"""
Sliding window management for replay protection.

This module implements a sliding window to track received message counters
and prevent replay attacks while allowing for out-of-order delivery.
"""

from typing import Set, Optional


class SlidingWindow:
    """
    Sliding window for replay protection.
    
    Tracks received message counters within a window to prevent replay attacks
    while allowing reasonable out-of-order delivery.
    """
    
    def __init__(self, window_size: int = 32):
        """
        Initialize sliding window.
        
        Args:
            window_size: Size of the replay protection window (default: 32)
        """
        if window_size <= 0 or window_size > 64:
            raise ValueError("Window size must be between 1 and 64")
        
        self.window_size = window_size
        self.seen = -1  # Highest successfully processed counter (start with -1 to accept counter 0)
        self.seen_map = 0  # Bitmap of received messages within window
    
    def is_valid_counter(self, counter: int) -> bool:
        """
        Check if a counter value is valid (not a replay).
        
        Args:
            counter: Message counter to check
            
        Returns:
            True if counter is valid and should be accepted
        """
        if counter < 0:
            return False
        
        # Counter is ahead of window - always valid
        if counter > self.seen:
            return True
        
        # Counter is at the highest seen - replay
        if counter == self.seen:
            return False
        
        # Check if counter is within window
        diff = self.seen - counter
        if diff >= self.window_size:
            # Counter is too old (outside window)
            return False
        
        # Check if we've already seen this counter
        bit_position = diff
        return not bool(self.seen_map & (1 << bit_position))
    
    def mark_received(self, counter: int) -> bool:
        """
        Mark a counter as received if it's valid.
        
        Args:
            counter: Message counter to mark
            
        Returns:
            True if counter was marked (was valid), False if rejected
        """
        if not self.is_valid_counter(counter):
            return False
        
        if counter > self.seen:
            # Counter is ahead - shift window forward
            shift = counter - self.seen
            
            if shift >= self.window_size:
                # Complete window shift - clear all bits
                self.seen_map = 0
            else:
                # Partial shift - move existing bits
                self.seen_map = (self.seen_map << shift) & ((1 << self.window_size) - 1)
            
            # Update highest seen counter
            self.seen = counter
            # Mark this counter as seen at position 0 (most recent)
            self.seen_map |= 1
        else:
            # Counter is within current window - set bit
            diff = self.seen - counter
            bit_position = diff
            self.seen_map |= (1 << bit_position)
        
        return True
    
    def get_window_info(self) -> dict:
        """
        Get current window state information.
        
        Returns:
            Dictionary with window state details
        """
        return {
            'window_size': self.window_size,
            'highest_seen': self.seen,
            'seen_bitmap': f"0b{self.seen_map:0{self.window_size}b}",
            'seen_bitmap_hex': f"0x{self.seen_map:x}",
            'received_count': bin(self.seen_map).count('1') + (1 if self.seen > 0 else 0)
        }
    
    def reset(self):
        """Reset window state."""
        self.seen = 0
        self.seen_map = 0
    
    def __repr__(self) -> str:
        """String representation of window state."""
        return (
            f"SlidingWindow(size={self.window_size}, "
            f"seen={self.seen}, "
            f"bitmap=0x{self.seen_map:x})"
        )


class ReplayProtection:
    """
    High-level replay protection manager for multiple channels.
    """
    
    def __init__(self, default_window_size: int = 32):
        """
        Initialize replay protection.
        
        Args:
            default_window_size: Default window size for new channels
        """
        self.default_window_size = default_window_size
        self.windows = {}  # channel_id -> SlidingWindow
    
    def check_and_update(self, channel_id: int, counter: int) -> bool:
        """
        Check counter validity and update window if valid.
        
        Args:
            channel_id: Channel identifier
            counter: Message counter
            
        Returns:
            True if message should be accepted, False if replay
        """
        # Get or create window for channel
        if channel_id not in self.windows:
            self.windows[channel_id] = SlidingWindow(self.default_window_size)
        
        window = self.windows[channel_id]
        return window.mark_received(counter)
    
    def is_valid_message(self, channel_id: int, counter: int) -> bool:
        """
        Check if message counter is valid without updating state.
        
        Args:
            channel_id: Channel identifier
            counter: Message counter
            
        Returns:
            True if message would be accepted
        """
        if channel_id not in self.windows:
            # New channel - any positive counter is valid
            return counter >= 0
        
        window = self.windows[channel_id]
        return window.is_valid_counter(counter)
    
    def get_channel_info(self, channel_id: int) -> Optional[dict]:
        """
        Get window information for a channel.
        
        Args:
            channel_id: Channel identifier
            
        Returns:
            Window info dict or None if channel doesn't exist
        """
        if channel_id not in self.windows:
            return None
        
        return self.windows[channel_id].get_window_info()
    
    def reset_channel(self, channel_id: int):
        """
        Reset replay protection for a channel.
        
        Args:
            channel_id: Channel identifier
        """
        if channel_id in self.windows:
            self.windows[channel_id].reset()
    
    def remove_channel(self, channel_id: int):
        """
        Remove replay protection for a channel.
        
        Args:
            channel_id: Channel identifier
        """
        if channel_id in self.windows:
            del self.windows[channel_id]
    
    def get_all_channels(self) -> Set[int]:
        """
        Get set of all tracked channel IDs.
        
        Returns:
            Set of channel IDs
        """
        return set(self.windows.keys())
    
    def get_stats(self) -> dict:
        """
        Get statistics for all channels.
        
        Returns:
            Dictionary with overall statistics
        """
        total_channels = len(self.windows)
        total_received = sum(
            window.get_window_info()['received_count'] 
            for window in self.windows.values()
        )
        
        return {
            'total_channels': total_channels,
            'total_messages_received': total_received,
            'default_window_size': self.default_window_size,
            'channels': {
                channel_id: window.get_window_info()
                for channel_id, window in self.windows.items()
            }
        }


def test_window_sequence(counters: list, window_size: int = 32) -> list:
    """
    Test a sequence of counters against a sliding window.
    
    Args:
        counters: List of counter values to test
        window_size: Window size to use
        
    Returns:
        List of (counter, accepted) tuples
    """
    window = SlidingWindow(window_size)
    results = []
    
    for counter in counters:
        accepted = window.mark_received(counter)
        results.append((counter, accepted))
    
    return results
