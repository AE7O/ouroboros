"""
Data Scrambling for Ouroboros Protocol.

Provides an additional layer of obfuscation by scrambling encrypted data
using ChaCha20-seeded Fisher-Yates shuffle for traffic obfuscation.
"""

import hashlib
import struct
from typing import List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class ScramblingError(Exception):
    """Raised when scrambling or unscrambling fails."""
    pass


class ChaCha20PRNG:
    """
    ChaCha20-based pseudo-random number generator for deterministic scrambling.
    """
    
    def __init__(self, key: bytes, nonce: bytes = None):
        """
        Initialize ChaCha20 PRNG with key.
        
        Args:
            key: 32-byte key for ChaCha20
            nonce: 16-byte nonce (generated if None)
        """
        if len(key) != 32:
            raise ScramblingError("ChaCha20 key must be 32 bytes")
        
        self.key = key
        self.nonce = nonce if nonce else b'\x00' * 16  # ChaCha20 needs 16-byte nonce
        self.counter = 0
        self._buffer = b""
        self._buffer_pos = 0
    
    def random_bytes(self, length: int) -> bytes:
        """
        Generate pseudo-random bytes using ChaCha20.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Pseudo-random bytes
        """
        result = b""
        
        while len(result) < length:
            if self._buffer_pos >= len(self._buffer):
                # Generate new block
                cipher = Cipher(
                    algorithms.ChaCha20(self.key, self.nonce),
                    mode=None
                )
                encryptor = cipher.encryptor()
                # Encrypt block of zeros to get keystream
                self._buffer = encryptor.update(b'\x00' * 64)
                self._buffer_pos = 0
                
                # Increment nonce to get different keystream for next block
                nonce_int = int.from_bytes(self.nonce, 'little')
                nonce_int = (nonce_int + 1) % (2**128)  # 128-bit nonce
                self.nonce = nonce_int.to_bytes(16, 'little')
            
            # Take bytes from buffer
            available = len(self._buffer) - self._buffer_pos
            needed = length - len(result)
            take = min(available, needed)
            
            result += self._buffer[self._buffer_pos:self._buffer_pos + take]
            self._buffer_pos += take
        
        return result
    
    def random_uint32(self) -> int:
        """Generate a pseudo-random 32-bit unsigned integer."""
        return struct.unpack('<I', self.random_bytes(4))[0]


def _generate_permutation(key: bytes, length: int) -> List[int]:
    """
    Generate a deterministic permutation using ChaCha20-seeded Fisher-Yates shuffle.
    
    Args:
        key: Scrambling key (32 bytes)
        length: Length of the permutation
        
    Returns:
        List representing the permutation
    """
    if len(key) != 32:
        raise ScramblingError("Scrambling key must be 32 bytes")
    
    if length == 0:
        return []
    
    # Create initial array [0, 1, 2, ..., length-1]
    permutation = list(range(length))
    
    # Initialize ChaCha20 PRNG with the key
    prng = ChaCha20PRNG(key)
    
    # Fisher-Yates shuffle using ChaCha20 for randomness
    for i in range(length - 1, 0, -1):
        # Generate random index in range [0, i]
        rand_val = prng.random_uint32()
        j = rand_val % (i + 1)
        
        # Swap elements i and j
        permutation[i], permutation[j] = permutation[j], permutation[i]
    
    return permutation


def _invert_permutation(permutation: List[int]) -> List[int]:
    """
    Generate the inverse of a permutation.
    
    Args:
        permutation: Original permutation
        
    Returns:
        Inverse permutation
    """
    inverse = [0] * len(permutation)
    for i, j in enumerate(permutation):
        inverse[j] = i
    return inverse


def scramble_data(key: bytes, data: bytes) -> bytes:
    """
    Scramble data using a key-derived permutation.
    
    Args:
        key: 32-byte scrambling key
        data: Data to scramble
        
    Returns:
        Scrambled data
        
    Raises:
        ScramblingError: If scrambling fails
    """
    try:
        if len(key) != 32:
            raise ScramblingError("Scrambling key must be 32 bytes")
            
        if len(data) == 0:
            return data
            
        # Generate permutation for this data length
        permutation = _generate_permutation(key, len(data))
        
        # Apply permutation to scramble data
        data_array = bytearray(data)
        scrambled = bytearray(len(data))
        
        for i, j in enumerate(permutation):
            scrambled[j] = data_array[i]
            
        return bytes(scrambled)
        
    except Exception as e:
        raise ScramblingError(f"Scrambling failed: {str(e)}")


def unscramble_data(key: bytes, scrambled_data: bytes) -> bytes:
    """
    Unscramble data using a key-derived permutation.
    
    Args:
        key: 32-byte scrambling key (same as used for scrambling)
        scrambled_data: Data to unscramble
        
    Returns:
        Original unscrambled data
        
    Raises:
        ScramblingError: If unscrambling fails
    """
    try:
        if len(key) != 32:
            raise ScramblingError("Scrambling key must be 32 bytes")
            
        if len(scrambled_data) == 0:
            return scrambled_data
            
        # Generate same permutation as used for scrambling
        permutation = _generate_permutation(key, len(scrambled_data))
        
        # Generate inverse permutation
        inverse_permutation = _invert_permutation(permutation)
        
        # Apply inverse permutation to unscramble data
        scrambled_array = bytearray(scrambled_data)
        unscrambled = bytearray(len(scrambled_data))
        
        for i, j in enumerate(inverse_permutation):
            unscrambled[j] = scrambled_array[i]
            
        return bytes(unscrambled)
        
    except Exception as e:
        raise ScramblingError(f"Unscrambling failed: {str(e)}")


def test_scrambling_roundtrip(key: bytes, data: bytes) -> bool:
    """
    Test that scrambling and unscrambling returns original data.
    
    Args:
        key: Scrambling key to test
        data: Test data
        
    Returns:
        True if roundtrip is successful, False otherwise
    """
    try:
        scrambled = scramble_data(key, data)
        unscrambled = unscramble_data(key, scrambled)
        return data == unscrambled
    except Exception:
        return False
