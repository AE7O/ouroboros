"""
Reliability Manager for Ouroboros Protocol.

Handles ACK/NACK, retransmission, and delivery guarantees.
"""

import time
import threading
from typing import Dict, Optional, Callable, Tuple
from dataclasses import dataclass
from ..protocol.packet import OuroborosPacket, PacketType


class DeliveryError(Exception):
    """Raised when delivery operations fail."""
    pass


@dataclass
class PendingMessage:
    """Represents a message awaiting acknowledgment."""
    packet: OuroborosPacket
    destination: Tuple[str, int]  # (host, port)
    send_time: float
    retry_count: int = 0
    max_retries: int = 3
    retry_interval: float = 1.0  # seconds


class ReliabilityManager:
    """
    Manages reliable delivery of Ouroboros messages.
    
    Implements CoAP-style reliability with exponential backoff.
    """
    
    def __init__(self, 
                 max_retries: int = 3,
                 base_retry_interval: float = 1.0,
                 ack_timeout: float = 5.0,
                 max_backoff: float = 16.0):
        """
        Initialize reliability manager.
        
        Args:
            max_retries: Maximum number of retransmission attempts
            base_retry_interval: Initial retry interval in seconds
            ack_timeout: Total timeout for receiving ACK
            max_backoff: Maximum backoff interval
        """
        self.max_retries = max_retries
        self.base_retry_interval = base_retry_interval
        self.ack_timeout = ack_timeout
        self.max_backoff = max_backoff
        
        # Pending messages awaiting ACK
        self._pending_messages: Dict[int, PendingMessage] = {}
        
        # Callbacks for sending packets and handling failures
        self._send_callback: Optional[Callable[[OuroborosPacket, Tuple[str, int]], None]] = None
        self._failure_callback: Optional[Callable[[OuroborosPacket, str], None]] = None
        
        # Threading for retry management
        self._lock = threading.Lock()
        self._retry_thread: Optional[threading.Thread] = None
        self._stop_retry_thread = False
        
        # Statistics
        self._stats = {
            'messages_sent': 0,
            'acks_received': 0,
            'retransmissions': 0,
            'failures': 0
        }
    
    def set_send_callback(self, callback: Callable[[OuroborosPacket, Tuple[str, int]], None]) -> None:
        """
        Set callback function for sending packets.
        
        Args:
            callback: Function to call for sending packets
        """
        self._send_callback = callback
    
    def set_failure_callback(self, callback: Callable[[OuroborosPacket, str], None]) -> None:
        """
        Set callback function for handling delivery failures.
        
        Args:
            callback: Function to call when delivery fails
        """
        self._failure_callback = callback
    
    def send_reliable(self, packet: OuroborosPacket, destination: Tuple[str, int]) -> None:
        """
        Send a packet with reliability guarantees.
        
        Args:
            packet: Packet to send reliably
            destination: Destination address (host, port)
            
        Raises:
            DeliveryError: If reliability manager is not properly configured
        """
        if not self._send_callback:
            raise DeliveryError("Send callback not set")
        
        if not packet.is_data_packet():
            # Control packets (ACK, NACK, etc.) are sent unreliably
            self._send_callback(packet, destination)
            return
        
        with self._lock:
            # Create pending message entry
            pending = PendingMessage(
                packet=packet,
                destination=destination,
                send_time=time.time(),
                max_retries=self.max_retries,
                retry_interval=self.base_retry_interval
            )
            
            self._pending_messages[packet.counter] = pending
            self._stats['messages_sent'] += 1
        
        # Send initial packet
        self._send_callback(packet, destination)
        
        # Start retry thread if not running
        self._ensure_retry_thread()
    
    def handle_ack(self, ack_packet: OuroborosPacket) -> bool:
        """
        Handle received ACK packet.
        
        Args:
            ack_packet: Received ACK packet
            
        Returns:
            True if ACK was for a pending message, False otherwise
        """
        if not ack_packet.is_ack_packet():
            return False
        
        with self._lock:
            counter = ack_packet.counter
            if counter in self._pending_messages:
                del self._pending_messages[counter]
                self._stats['acks_received'] += 1
                return True
        
        return False
    
    def handle_nack(self, nack_packet: OuroborosPacket) -> bool:
        """
        Handle received NACK packet.
        
        Args:
            nack_packet: Received NACK packet
            
        Returns:
            True if NACK was for a pending message, False otherwise
        """
        if not (nack_packet.packet_type == PacketType.NACK):
            return False
        
        with self._lock:
            counter = nack_packet.counter
            if counter in self._pending_messages:
                pending = self._pending_messages[counter]
                # Immediate retry on NACK
                self._retry_message(pending)
                return True
        
        return False
    
    def _ensure_retry_thread(self) -> None:
        """Ensure the retry thread is running."""
        if self._retry_thread is None or not self._retry_thread.is_alive():
            self._stop_retry_thread = False
            self._retry_thread = threading.Thread(target=self._retry_loop, daemon=True)
            self._retry_thread.start()
    
    def _retry_loop(self) -> None:
        """Main retry loop running in background thread."""
        while not self._stop_retry_thread:
            try:
                current_time = time.time()
                messages_to_retry = []
                messages_to_fail = []
                
                with self._lock:
                    for counter, pending in list(self._pending_messages.items()):
                        elapsed = current_time - pending.send_time
                        
                        # Check if message should be retried
                        next_retry_time = pending.retry_interval * (2 ** pending.retry_count)
                        next_retry_time = min(next_retry_time, self.max_backoff)
                        
                        if elapsed >= next_retry_time:
                            if pending.retry_count < pending.max_retries:
                                messages_to_retry.append(pending)
                            else:
                                messages_to_fail.append(pending)
                                del self._pending_messages[counter]
                
                # Process retries outside of lock
                for pending in messages_to_retry:
                    self._retry_message(pending)
                
                # Process failures
                for pending in messages_to_fail:
                    self._handle_failure(pending, "Max retries exceeded")
                
                # Sleep before next check
                time.sleep(0.1)
                
            except Exception as e:
                # Log error but continue retry loop
                print(f"Error in retry loop: {e}")
    
    def _retry_message(self, pending: PendingMessage) -> None:
        """
        Retry sending a pending message.
        
        Args:
            pending: Pending message to retry
        """
        pending.retry_count += 1
        pending.send_time = time.time()
        
        self._stats['retransmissions'] += 1
        
        if self._send_callback:
            self._send_callback(pending.packet, pending.destination)
    
    def _handle_failure(self, pending: PendingMessage, reason: str) -> None:
        """
        Handle delivery failure.
        
        Args:
            pending: Failed message
            reason: Failure reason
        """
        self._stats['failures'] += 1
        
        if self._failure_callback:
            self._failure_callback(pending.packet, reason)
    
    def get_stats(self) -> dict:
        """
        Get reliability statistics.
        
        Returns:
            Dictionary with reliability statistics
        """
        with self._lock:
            return {
                **self._stats,
                'pending_messages': len(self._pending_messages)
            }
    
    def get_pending_count(self) -> int:
        """Get number of pending messages."""
        with self._lock:
            return len(self._pending_messages)
    
    def stop(self) -> None:
        """Stop the reliability manager and cleanup resources."""
        self._stop_retry_thread = True
        if self._retry_thread and self._retry_thread.is_alive():
            self._retry_thread.join(timeout=1.0)
    
    def __del__(self):
        """Cleanup on destruction."""
        self.stop()
