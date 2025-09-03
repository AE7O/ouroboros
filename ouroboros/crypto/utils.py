"""
Cryptographic utilities for Ouroboros Protocol.

Provides secure memory handling, random number generation, and byte operations.
"""

import os
import secrets
import ctypes
from typing import Optional


class CryptoError(Exception):
    """Raised when cryptographic utility operations fail."""
    pass


def zeroize(data: bytearray):
    """
    Securely zero out sensitive data in memory.
    
    Args:
        data: Bytearray to zero out
    """
    if not isinstance(data, bytearray):
        raise CryptoError("Can only zeroize bytearray objects")
    
    # Overwrite with zeros
    for i in range(len(data)):
        data[i] = 0
    
    # Try to prevent compiler optimizations from removing the zeroing
    # This is a best-effort approach
    ctypes.memset(id(data) + 24, 0, len(data))


def secure_random(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Secure random bytes
    """
    if length < 0:
        raise CryptoError("Length must be non-negative")
    
    return secrets.token_bytes(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time.
    
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
        XOR result
        
    Raises:
        CryptoError: If sequences have different lengths
    """
    if len(a) != len(b):
        raise CryptoError("Byte sequences must have equal length for XOR")
    
    return bytes(x ^ y for x, y in zip(a, b))


def bytes_to_int(data: bytes, byteorder: str = 'big') -> int:
    """
    Convert bytes to integer.
    
    Args:
        data: Bytes to convert
        byteorder: Byte order ('big' or 'little')
        
    Returns:
        Integer representation
    """
    return int.from_bytes(data, byteorder)


def int_to_bytes(value: int, length: int, byteorder: str = 'big') -> bytes:
    """
    Convert integer to bytes with specified length.
    
    Args:
        value: Integer to convert
        length: Target byte length
        byteorder: Byte order ('big' or 'little')
        
    Returns:
        Bytes representation
        
    Raises:
        CryptoError: If value doesn't fit in specified length
    """
    try:
        return value.to_bytes(length, byteorder)
    except OverflowError:
        raise CryptoError(f"Value {value} doesn't fit in {length} bytes")


def pad_data(data: bytes, block_size: int, padding_char: int = 0) -> bytes:
    """
    Pad data to a multiple of block_size.
    
    Args:
        data: Data to pad
        block_size: Target block size
        padding_char: Byte value to use for padding
        
    Returns:
        Padded data
    """
    if block_size <= 0:
        raise CryptoError("Block size must be positive")
    
    padding_needed = block_size - (len(data) % block_size)
    if padding_needed == block_size:
        padding_needed = 0
    
    return data + bytes([padding_char] * padding_needed)


def unpad_data(data: bytes, padding_char: int = 0) -> bytes:
    """
    Remove padding from data.
    
    Args:
        data: Padded data
        padding_char: Padding byte value
        
    Returns:
        Unpadded data
    """
    if not data:
        return data
    
    # Find the last non-padding byte
    for i in range(len(data) - 1, -1, -1):
        if data[i] != padding_char:
            return data[:i + 1]
    
    # All bytes are padding
    return b""


class SecureBuffer:
    """
    A buffer that attempts to securely manage sensitive data in memory.
    """
    
    def __init__(self, size: int):
        """
        Initialize secure buffer.
        
        Args:
            size: Buffer size in bytes
        """
        if size < 0:
            raise CryptoError("Buffer size must be non-negative")
        
        self._data = bytearray(size)
        self._size = size
    
    def write(self, data: bytes, offset: int = 0):
        """
        Write data to buffer.
        
        Args:
            data: Data to write
            offset: Offset in buffer
            
        Raises:
            CryptoError: If data doesn't fit
        """
        if offset < 0 or offset >= self._size:
            raise CryptoError("Invalid offset")
        
        if len(data) + offset > self._size:
            raise CryptoError("Data doesn't fit in buffer")
        
        self._data[offset:offset + len(data)] = data
    
    def read(self, length: int, offset: int = 0) -> bytes:
        """
        Read data from buffer.
        
        Args:
            length: Number of bytes to read
            offset: Offset in buffer
            
        Returns:
            Data from buffer
            
        Raises:
            CryptoError: If read goes beyond buffer
        """
        if offset < 0 or offset >= self._size:
            raise CryptoError("Invalid offset")
        
        if length < 0 or offset + length > self._size:
            raise CryptoError("Read beyond buffer")
        
        return bytes(self._data[offset:offset + length])
    
    def clear(self):
        """Clear buffer contents securely."""
        zeroize(self._data)
    
    def __len__(self) -> int:
        """Get buffer size."""
        return self._size
    
    def __del__(self):
        """Clear buffer on destruction."""
        if hasattr(self, '_data'):
            zeroize(self._data)


def generate_nonce(length: int) -> bytes:
    """
    Generate a cryptographically secure nonce.
    
    Args:
        length: Nonce length in bytes
        
    Returns:
        Random nonce
    """
    return secure_random(length)


def derive_key_from_password(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    Derive a key from password using PBKDF2.
    
    Args:
        password: Password string
        salt: Salt bytes
        iterations: Number of iterations
        
    Returns:
        Derived 32-byte key
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode('utf-8'))


def validate_key_length(key: bytes, expected_length: int, name: str = "key"):
    """
    Validate that a key has the expected length.
    
    Args:
        key: Key to validate
        expected_length: Expected length in bytes
        name: Key name for error messages
        
    Raises:
        CryptoError: If key length is invalid
    """
    if len(key) != expected_length:
        raise CryptoError(f"{name} must be {expected_length} bytes, got {len(key)}")


def split_bytes(data: bytes, *lengths: int) -> tuple:
    """
    Split bytes into multiple parts of specified lengths.
    
    Args:
        data: Bytes to split
        lengths: Lengths of each part
        
    Returns:
        Tuple of byte parts
        
    Raises:
        CryptoError: If total length doesn't match data length
    """
    if sum(lengths) != len(data):
        raise CryptoError(f"Split lengths {lengths} don't match data length {len(data)}")
    
    parts = []
    offset = 0
    for length in lengths:
        parts.append(data[offset:offset + length])
        offset += length
    
    return tuple(parts)