"""
Data Scrambling for Ouroboros Protocol.

Provides an additional layer of obfuscation by scrambling encrypted data
using a cryptographic permutation seeded by the scrambling key.
"""

import hashlib
from typing import List


class ScramblingError(Exception):
    """Raised when scrambling or unscrambling fails."""
    pass


def _generate_permutation(key: bytes, length: int) -> List[int]:
    """
    Generate a cryptographic permutation based on the scrambling key.
    
    Args:
        key: 32-byte scrambling key
        length: Length of data to permute
        
    Returns:
        List representing the permutation indices
    """
    if length == 0:
        return []
    
    # Use key to seed deterministic permutation generation
    indices = list(range(length))
    
    # Generate deterministic "random" sequence from key
    seed = hashlib.sha256(key + length.to_bytes(4, 'big')).digest()
    
    # Fisher-Yates shuffle with deterministic randomness
    for i in range(length - 1, 0, -1):
        # Generate deterministic "random" index
        hash_input = seed + i.to_bytes(4, 'big')
        hash_output = hashlib.sha256(hash_input).digest()
        j = int.from_bytes(hash_output[:4], 'big') % (i + 1)
        
        # Swap elements
        indices[i], indices[j] = indices[j], indices[i]
        
        # Update seed for next iteration
        seed = hashlib.sha256(seed + hash_output[:8]).digest()
    
    return indices


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
