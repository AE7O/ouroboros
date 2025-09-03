"""
Sliding Window Replay Protection for Ouroboros Protocol.

Implements a sliding window with bitmap tracking to prevent replay attacks
while allowing out-of-order message delivery within the window.
"""

import threading
from typing import Set, Dict, Optional


class WindowError(Exception):
    """Raised when window operations fail."""
    pass


class SlidingWindow:
    """
    Sliding window implementation for replay protection.
    
    Uses a sliding window with bitmap tracking to efficiently handle
    out-of-order packets while preventing replay attacks.
    """
    
    def __init__(self, window_size: int = 1000):
        """
        Initialize sliding window.
        
        Args:
            window_size: Size of the replay protection window
            
        Raises:
            WindowError: If window size is invalid
        """
        if window_size <= 0:
            raise WindowError("Window size must be positive")
        
        self._window_size = window_size
        self._last_accepted_counter = -1
        self._received_counters: Set[int] = set()
        self._lock = threading.RLock()
    
    def is_valid_counter(self, counter: int) -> bool:
        """
        Check if a counter value is valid (not a replay and within window).
        
        Args:
            counter: Counter value to check
            
        Returns:
            True if counter is valid, False otherwise
        """
        with self._lock:
            # Check if this is a replay
            if counter in self._received_counters:
                return False
            
            # Check if counter is too old (outside window)
            # Counter must be > last_accepted - window_size to be valid
            if self._last_accepted_counter >= 0 and counter <= self._last_accepted_counter - self._window_size:
                return False
            
            return True
    
    def accept_counter(self, counter: int) -> bool:
        """
        Accept a counter value and update window state.
        
        Args:
            counter: Counter value to accept
            
        Returns:
            True if counter was accepted, False if it was a replay
        """
        with self._lock:
            # Validate the counter first
            if not self.is_valid_counter(counter):
                return False
            
            # Accept the counter
            self._received_counters.add(counter)
            
            # Update last accepted if this is newer
            if counter > self._last_accepted_counter:
                self._last_accepted_counter = counter
            
            # Clean up old counters outside the window
            self._cleanup_old_counters()
            
            return True
    
    def _cleanup_old_counters(self):
        """Remove old counters that are outside the replay window."""
        cutoff = self._last_accepted_counter - self._window_size
        self._received_counters = {c for c in self._received_counters if c > cutoff}
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get window statistics.
        
        Returns:
            Dictionary with window statistics
        """
        with self._lock:
            return {
                'last_accepted_counter': self._last_accepted_counter,
                'window_size': self._window_size,
                'tracked_counters': len(self._received_counters),
                'window_utilization': len(self._received_counters) / self._window_size
            }
    
    def reset(self):
        """Reset the window to initial state."""
        with self._lock:
            self._last_accepted_counter = -1
            self._received_counters.clear()
    
    def get_window_bounds(self) -> tuple:
        """
        Get the current window bounds.
        
        Returns:
            Tuple of (lower_bound, upper_bound)
        """
        with self._lock:
            lower_bound = max(0, self._last_accepted_counter - self._window_size)
            upper_bound = self._last_accepted_counter
            return lower_bound, upper_bound
    
    def get_missing_counters(self, start: int, end: int) -> Set[int]:
        """
        Get counters that are missing in the specified range.
        
        Args:
            start: Start of range (inclusive)
            end: End of range (inclusive)
            
        Returns:
            Set of missing counter values
        """
        with self._lock:
            expected = set(range(start, end + 1))
            received = self._received_counters.intersection(expected)
            return expected - received


class ChannelWindow:
    """
    Per-channel sliding window manager.
    
    Manages separate sliding windows for multiple channels.
    """
    
    def __init__(self, default_window_size: int = 1000):
        """
        Initialize channel window manager.
        
        Args:
            default_window_size: Default window size for new channels
        """
        self._default_window_size = default_window_size
        self._windows: Dict[int, SlidingWindow] = {}
        self._lock = threading.RLock()
    
    def get_window(self, channel_id: int) -> SlidingWindow:
        """
        Get sliding window for a specific channel.
        
        Args:
            channel_id: Channel identifier
            
        Returns:
            SlidingWindow instance for the channel
        """
        with self._lock:
            if channel_id not in self._windows:
                self._windows[channel_id] = SlidingWindow(self._default_window_size)
            return self._windows[channel_id]
    
    def is_valid_counter(self, channel_id: int, counter: int) -> bool:
        """
        Check if a counter is valid for a specific channel.
        
        Args:
            channel_id: Channel identifier
            counter: Counter value to check
            
        Returns:
            True if counter is valid, False otherwise
        """
        window = self.get_window(channel_id)
        return window.is_valid_counter(counter)
    
    def accept_counter(self, channel_id: int, counter: int) -> bool:
        """
        Accept a counter for a specific channel.
        
        Args:
            channel_id: Channel identifier
            counter: Counter value to accept
            
        Returns:
            True if counter was accepted, False if it was a replay
        """
        window = self.get_window(channel_id)
        return window.accept_counter(counter)
    
    def get_channel_stats(self, channel_id: int) -> Dict[str, int]:
        """
        Get statistics for a specific channel.
        
        Args:
            channel_id: Channel identifier
            
        Returns:
            Dictionary with channel statistics
        """
        if channel_id in self._windows:
            return self._windows[channel_id].get_stats()
        else:
            return {
                'last_accepted_counter': -1,
                'window_size': self._default_window_size,
                'tracked_counters': 0,
                'window_utilization': 0.0
            }
    
    def get_all_stats(self) -> Dict[int, Dict[str, int]]:
        """
        Get statistics for all channels.
        
        Returns:
            Dictionary mapping channel_id to statistics
        """
        with self._lock:
            return {
                channel_id: window.get_stats()
                for channel_id, window in self._windows.items()
            }
    
    def reset_channel(self, channel_id: int):
        """Reset a specific channel's window."""
        if channel_id in self._windows:
            self._windows[channel_id].reset()
    
    def reset_all(self):
        """Reset all channel windows."""
        with self._lock:
            for window in self._windows.values():
                window.reset()
    
    def remove_channel(self, channel_id: int):
        """Remove a channel's window."""
        with self._lock:
            if channel_id in self._windows:
                del self._windows[channel_id]
    
    def get_active_channels(self) -> Set[int]:
        """Get set of active channel IDs."""
        with self._lock:
            return set(self._windows.keys())


# Global channel window manager instance
_global_channel_window = None
_global_lock = threading.Lock()


def get_global_channel_window() -> ChannelWindow:
    """
    Get the global channel window manager instance.
    
    Returns:
        Global ChannelWindow instance
    """
    global _global_channel_window
    
    with _global_lock:
        if _global_channel_window is None:
            _global_channel_window = ChannelWindow()
        return _global_channel_window


def reset_global_channel_window():
    """Reset the global channel window manager."""
    global _global_channel_window
    
    with _global_lock:
        if _global_channel_window is not None:
            _global_channel_window.reset_all()