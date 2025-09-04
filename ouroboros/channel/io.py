"""
Socket I/O and framing for Ouroboros Protocol.

This module provides UDP socket management, packet framing, and multiplexing
for the Ouroboros secure communication protocol.
"""

import socket
import threading
import time
from typing import Callable, Optional, Tuple, Dict, Set
from queue import Queue, Empty
import logging

from ..protocol.packet import parse_packet, PacketFormatError, HEADER_SIZE


class SocketManager:
    """
    Manages UDP socket operations for Ouroboros protocol.
    """
    
    def __init__(self, bind_port: int = 0, bind_address: str = "0.0.0.0"):
        """
        Initialize socket manager.
        
        Args:
            bind_port: Port to bind to (0 for random port)
            bind_address: Address to bind to (default: all interfaces)
        """
        self.bind_address = bind_address
        self.bind_port = bind_port
        self.socket: Optional[socket.socket] = None
        self.actual_port: Optional[int] = None
        self.running = False
        self.receive_thread: Optional[threading.Thread] = None
        self.packet_handlers: Dict[int, Callable[[bytes, Tuple[str, int]], None]] = {}
        self.default_handler: Optional[Callable[[bytes, Tuple[str, int]], None]] = None
        self.receive_queue = Queue()
        self.logger = logging.getLogger(__name__)
    
    def start(self) -> int:
        """
        Start the socket manager.
        
        Returns:
            Actual port number being used
            
        Raises:
            IOError: If socket cannot be created or bound
        """
        if self.running:
            return self.actual_port
        
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to address
            self.socket.bind((self.bind_address, self.bind_port))
            self.actual_port = self.socket.getsockname()[1]
            
            # Start receive thread
            self.running = True
            self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receive_thread.start()
            
            self.logger.info(f"Socket manager started on {self.bind_address}:{self.actual_port}")
            return self.actual_port
            
        except Exception as e:
            self.stop()
            raise IOError(f"Failed to start socket manager: {e}") from e
    
    def stop(self):
        """Stop the socket manager."""
        self.running = False
        
        if self.socket:
            self.socket.close()
            self.socket = None
        
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=1.0)
        
        self.logger.info("Socket manager stopped")
    
    def send_packet(self, packet_bytes: bytes, destination: Tuple[str, int]) -> bool:
        """
        Send a packet to a destination.
        
        Args:
            packet_bytes: Raw packet data
            destination: (host, port) tuple
            
        Returns:
            True if packet was sent successfully
        """
        if not self.running or not self.socket:
            return False
        
        try:
            self.socket.sendto(packet_bytes, destination)
            return True
        except Exception as e:
            self.logger.error(f"Failed to send packet to {destination}: {e}")
            return False
    
    def register_handler(self, channel_id: int, 
                        handler: Callable[[bytes, Tuple[str, int]], None]):
        """
        Register a handler for packets from a specific channel.
        
        Args:
            channel_id: Channel ID to handle
            handler: Function to call with (packet_bytes, source_address)
        """
        self.packet_handlers[channel_id] = handler
    
    def set_default_handler(self, handler: Callable[[bytes, Tuple[str, int]], None]):
        """
        Set default handler for packets without specific handlers.
        
        Args:
            handler: Function to call with (packet_bytes, source_address)
        """
        self.default_handler = handler
    
    def get_received_packets(self, timeout: float = 0.1) -> list:
        """
        Get received packets from the queue.
        
        Args:
            timeout: Timeout for waiting for packets
            
        Returns:
            List of (packet_bytes, source_address) tuples
        """
        packets = []
        deadline = time.time() + timeout
        
        while time.time() < deadline:
            try:
                remaining_time = deadline - time.time()
                if remaining_time <= 0:
                    break
                
                packet_data = self.receive_queue.get(timeout=remaining_time)
                packets.append(packet_data)
            except Empty:
                break
        
        return packets
    
    def _receive_loop(self):
        """Main receive loop (runs in background thread)."""
        while self.running:
            try:
                if not self.socket:
                    break
                
                # Set socket timeout to avoid blocking indefinitely
                self.socket.settimeout(1.0)
                
                try:
                    data, source = self.socket.recvfrom(65536)
                except socket.timeout:
                    continue
                
                # Basic packet validation
                if len(data) < HEADER_SIZE:
                    self.logger.warning(f"Received undersized packet from {source}")
                    continue
                
                # Try to extract channel ID for routing
                try:
                    packet = parse_packet(data)
                    channel_id = packet.header.channel_id
                    
                    # Route to specific handler or default
                    if channel_id in self.packet_handlers:
                        self.packet_handlers[channel_id](data, source)
                    elif self.default_handler:
                        self.default_handler(data, source)
                    else:
                        # No handler - put in queue
                        self.receive_queue.put((data, source))
                        
                except PacketFormatError:
                    self.logger.warning(f"Received malformed packet from {source}")
                    continue
                
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error in receive loop: {e}")
                    time.sleep(0.1)  # Brief pause to avoid tight error loop
    
    def get_local_address(self) -> Optional[Tuple[str, int]]:
        """
        Get local socket address.
        
        Returns:
            (host, port) tuple or None if not running
        """
        if self.socket:
            return self.socket.getsockname()
        return None
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


class PacketFramer:
    """
    Handles packet framing and multiplexing for multiple channels.
    """
    
    def __init__(self, socket_manager: SocketManager):
        """
        Initialize packet framer.
        
        Args:
            socket_manager: SocketManager instance to use
        """
        self.socket_manager = socket_manager
        self.active_channels: Set[int] = set()
        self.logger = logging.getLogger(__name__)
    
    def send_to_channel(self, channel_id: int, packet_bytes: bytes, 
                       destination: Tuple[str, int]) -> bool:
        """
        Send a packet to a specific channel.
        
        Args:
            channel_id: Channel identifier
            packet_bytes: Raw packet data
            destination: Destination address
            
        Returns:
            True if packet was sent
        """
        self.active_channels.add(channel_id)
        return self.socket_manager.send_packet(packet_bytes, destination)
    
    def setup_channel_handler(self, channel_id: int, 
                            handler: Callable[[bytes, Tuple[str, int]], None]):
        """
        Set up a handler for a specific channel.
        
        Args:
            channel_id: Channel to handle
            handler: Handler function
        """
        self.active_channels.add(channel_id)
        self.socket_manager.register_handler(channel_id, handler)
    
    def get_channel_stats(self) -> dict:
        """
        Get statistics about active channels.
        
        Returns:
            Dictionary with channel statistics
        """
        return {
            'active_channels': list(self.active_channels),
            'total_channels': len(self.active_channels),
            'local_address': self.socket_manager.get_local_address()
        }


def create_udp_endpoint(port: int = 0, address: str = "0.0.0.0") -> SocketManager:
    """
    Create a UDP endpoint for Ouroboros communication.
    
    Args:
        port: Port to bind to (0 for random)
        address: Address to bind to
        
    Returns:
        Configured SocketManager
    """
    return SocketManager(bind_port=port, bind_address=address)


def test_socket_communication(port1: int = 0, port2: int = 0) -> dict:
    """
    Test basic socket communication between two endpoints.
    
    Args:
        port1: Port for first endpoint
        port2: Port for second endpoint
        
    Returns:
        Test results
    """
    from ..protocol.packet import create_test_packet
    
    results = {
        'success': False,
        'error': None,
        'endpoints': [],
        'packets_sent': 0,
        'packets_received': 0
    }
    
    try:
        # Create two endpoints
        endpoint1 = create_udp_endpoint(port1)
        endpoint2 = create_udp_endpoint(port2)
        
        with endpoint1, endpoint2:
            addr1 = endpoint1.get_local_address()
            addr2 = endpoint2.get_local_address()
            
            results['endpoints'] = [addr1, addr2]
            
            # Create test packet
            test_packet = create_test_packet(channel_id=1, counter=1, payload=b"Hello")
            packet_bytes = test_packet.to_bytes()
            
            # Send packet from endpoint1 to endpoint2
            if endpoint1.send_packet(packet_bytes, addr2):
                results['packets_sent'] += 1
            
            # Wait for reception
            time.sleep(0.1)
            received = endpoint2.get_received_packets(timeout=0.5)
            results['packets_received'] = len(received)
            
            # Verify packet content
            if received and received[0][0] == packet_bytes:
                results['success'] = True
            
    except Exception as e:
        results['error'] = str(e)
    
    return results
