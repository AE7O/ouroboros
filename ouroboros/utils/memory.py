"""
Secure Memory Operations for Ouroboros Protocol.

Provides utilities for secure handling of cryptographic material.
"""

import os
import ctypes
from typing import Union


def secure_zero(data: Union[bytearray, memoryview]) -> None:
    """
    Securely zero out memory containing sensitive data.
    
    Args:
        data: Memory to zero (must be mutable)
    """
    if isinstance(data, bytearray):
        # Zero the bytearray
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, memoryview):
        # Zero the underlying buffer
        for i in range(len(data)):
            data[i] = 0
    else:
        raise TypeError("Data must be bytearray or memoryview")


class SecureBytes:
    """
    A container for sensitive byte data that zeros itself on deletion.
    
    Use this for storing cryptographic keys and other sensitive data
    to ensure they are properly cleared from memory.
    """
    
    def __init__(self, data: bytes):
        """
        Initialize with sensitive data.
        
        Args:
            data: Sensitive bytes to store
        """
        self._data = bytearray(data)
        self._is_valid = True
    
    def __len__(self) -> int:
        """Get length of stored data."""
        if not self._is_valid:
            raise ValueError("SecureBytes has been cleared")
        return len(self._data)
    
    def __bytes__(self) -> bytes:
        """Get a copy of the stored data as bytes."""
        if not self._is_valid:
            raise ValueError("SecureBytes has been cleared")
        return bytes(self._data)
    
    def __getitem__(self, key):
        """Get item(s) from stored data."""
        if not self._is_valid:
            raise ValueError("SecureBytes has been cleared")
        return self._data[key]
    
    def __del__(self):
        """Securely clear data when object is destroyed."""
        self.clear()
    
    def clear(self) -> None:
        """Explicitly clear the stored data."""
        if self._is_valid:
            secure_zero(self._data)
            self._is_valid = False
    
    def copy(self) -> bytes:
        """
        Get a copy of the data.
        
        Returns:
            Copy of the stored bytes
        """
        return bytes(self)
    
    def is_valid(self) -> bool:
        """Check if the SecureBytes is still valid (not cleared)."""
        return self._is_valid
    
    def is_cleared(self) -> bool:
        """Check if the SecureBytes has been cleared."""
        return not self._is_valid
    
    @classmethod
    def generate_random(cls, length: int) -> 'SecureBytes':
        """
        Generate random secure bytes.
        
        Args:
            length: Number of random bytes to generate
            
        Returns:
            SecureBytes containing random data
        """
        return cls(os.urandom(length))


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0
