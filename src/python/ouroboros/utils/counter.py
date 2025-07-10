"""
Message Counter Management for Ouroboros Protocol.

Handles counter increment, validation, and replay protection.
"""

from typing import Set
import threading


class CounterError(Exception):
    """Raised when counter operations fail."""
    pass


class CounterManager:
    """
    Thread-safe message counter manager with replay protection.
    
    Maintains send and receive counters, and tracks received message
    counters to prevent replay attacks.
    """
    
    def __init__(self, initial_send_counter: int = 0, window_size: int = 1000):
        """
        Initialize counter manager.
        
        Args:
            initial_send_counter: Starting value for send counter
            window_size: Size of replay protection window
        """
        self._send_counter = initial_send_counter
        self._last_received_counter = -1
        self._received_counters: Set[int] = set()
        self._window_size = window_size
        self._lock = threading.Lock()
    
    def get_next_send_counter(self) -> int:
        """
        Get the next counter value for sending a message.
        
        Returns:
            Next send counter value
            
        Raises:
            CounterError: If counter overflow would occur
        """
        with self._lock:
            if self._send_counter >= 2**64 - 1:
                raise CounterError("Send counter overflow")
            
            current = self._send_counter
            self._send_counter += 1
            return current
    
    def get_current_send_counter(self) -> int:
        """
        Get the current send counter value without incrementing.
        
        Returns:
            Current send counter value
        """
        with self._lock:
            return self._send_counter
    
    def validate_received_counter(self, counter: int) -> bool:
        """
        Validate a received message counter for replay protection.
        
        Args:
            counter: Received counter value
            
        Returns:
            True if counter is valid (not a replay), False otherwise
        """
        with self._lock:
            # Check if this is a replay
            if counter in self._received_counters:
                return False
            
            # Check if counter is too old (outside window)
            if counter < self._last_received_counter - self._window_size:
                return False
            
            # Accept the counter
            self._received_counters.add(counter)
            
            # Update last received if this is newer
            if counter > self._last_received_counter:
                self._last_received_counter = counter
            
            # Clean up old counters outside the window
            self._cleanup_old_counters()
            
            return True
    
    def _cleanup_old_counters(self):
        """Remove old counters that are outside the replay window."""
        cutoff = self._last_received_counter - self._window_size
        self._received_counters = {c for c in self._received_counters if c > cutoff}
    
    def reset_send_counter(self, value: int = 0):
        """
        Reset the send counter to a specific value.
        
        Args:
            value: New counter value
            
        Raises:
            CounterError: If value is invalid
        """
        if not (0 <= value < 2**64):
            raise CounterError("Counter value must be 64-bit")
        
        with self._lock:
            self._send_counter = value
    
    def reset_receive_state(self):
        """Reset the receive counter state and replay protection."""
        with self._lock:
            self._last_received_counter = -1
            self._received_counters.clear()
    
    def get_stats(self) -> dict:
        """
        Get counter statistics.
        
        Returns:
            Dictionary with counter statistics
        """
        with self._lock:
            return {
                'send_counter': self._send_counter,
                'last_received_counter': self._last_received_counter,
                'replay_window_size': len(self._received_counters),
                'window_limit': self._window_size
            }
