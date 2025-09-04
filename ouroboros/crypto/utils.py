"""
Cryptographic utilities for secure memory operations and random number generation.

This module provides utilities for secure memory handling, random number generation,
and byte operations used throughout the Ouroboros protocol.
"""

import os
import secrets
from typing import Union


def secure_zero(data: Union[bytes, bytearray, memoryview]) -> None:
    """
    Securely zero out sensitive data in memory.
    
    This function attempts to overwrite sensitive data with zeros to prevent
    it from being recovered from memory after deallocation.
    
    Args:
        data: Bytes, bytearray, or memoryview to zero out
    """
    if isinstance(data, (bytearray, memoryview)):
        # For mutable types, overwrite in place
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        # For immutable bytes, we can't actually zero them out
        # This is a limitation of Python's memory model
        # The caller should use bytearray for truly sensitive data
        pass
    else:
        raise TypeError("Data must be bytes, bytearray, or memoryview")


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of random bytes to generate
        
    Returns:
        Cryptographically secure random bytes
    """
    return secrets.token_bytes(length)


def generate_message_random() -> bytes:
    """
    Generate 4-byte random value for message scrambling.
    
    Returns:
        4 bytes of cryptographically secure random data
    """
    return generate_random_bytes(4)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time.
    
    This prevents timing attacks when comparing sensitive data like
    authentication tags or keys.
    
    Args:
        a: First byte sequence
        b: Second byte sequence
        
    Returns:
        True if sequences are equal, False otherwise
    """
    return secrets.compare_digest(a, b)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte sequences of equal length.
    
    Args:
        a: First byte sequence
        b: Second byte sequence
        
    Returns:
        XOR result as bytes
        
    Raises:
        ValueError: If sequences have different lengths
    """
    if len(a) != len(b):
        raise ValueError("Byte sequences must have equal length")
    
    return bytes(x ^ y for x, y in zip(a, b))


def bytes_to_int(data: bytes) -> int:
    """
    Convert bytes to integer (big-endian).
    
    Args:
        data: Bytes to convert
        
    Returns:
        Integer representation
    """
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(value: int, length: int) -> bytes:
    """
    Convert integer to bytes (big-endian).
    
    Args:
        value: Integer to convert
        length: Number of bytes in output
        
    Returns:
        Bytes representation
    """
    return value.to_bytes(length, byteorder='big')


class SecureBytes:
    """
    A wrapper for sensitive byte data that attempts secure cleanup.
    
    This class provides a context manager and destructor that attempts
    to securely zero out sensitive data when it's no longer needed.
    """
    
    def __init__(self, data: bytes):
        """
        Initialize with sensitive byte data.
        
        Args:
            data: Sensitive bytes to protect
        """
        self._data = bytearray(data)
    
    @property
    def data(self) -> bytes:
        """Get the protected data as bytes."""
        return bytes(self._data)
    
    def clear(self) -> None:
        """Securely clear the protected data."""
        secure_zero(self._data)
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - clear data."""
        self.clear()
    
    def __del__(self):
        """Destructor - attempt to clear data."""
        if hasattr(self, '_data'):
            self.clear()
    
    def __len__(self) -> int:
        """Return length of protected data."""
        return len(self._data)


def derive_channel_id(peer_a: bytes, peer_b: bytes) -> int:
    """
    Derive a channel ID from two peer identifiers.
    
    Args:
        peer_a: First peer identifier
        peer_b: Second peer identifier
        
    Returns:
        1-byte channel ID (0-255)
    """
    import hashlib
    
    # Sort peer IDs for consistent ordering
    peers = sorted([peer_a, peer_b])
    combined = peers[0] + peers[1]
    
    # Hash and take first byte as channel ID
    hash_result = hashlib.sha256(combined).digest()
    return hash_result[0]


def format_hex(data: bytes, separator: str = " ") -> str:
    """
    Format bytes as hexadecimal string.
    
    Args:
        data: Bytes to format
        separator: Separator between hex bytes
        
    Returns:
        Formatted hex string
    """
    return separator.join(f"{b:02x}" for b in data)


def parse_hex(hex_string: str) -> bytes:
    """
    Parse hexadecimal string to bytes.
    
    Args:
        hex_string: Hex string (with or without separators)
        
    Returns:
        Parsed bytes
    """
    # Remove common separators
    cleaned = hex_string.replace(" ", "").replace(":", "").replace("-", "")
    return bytes.fromhex(cleaned)
