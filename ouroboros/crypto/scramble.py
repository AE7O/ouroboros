"""
Data scrambling and unscrambling using Fisher-Yates shuffle with ChaCha20 PRNG.

This module implements content-dependent permutation scrambling for traffic obfuscation.
The scrambling is reversible and uses a ChaCha20 stream cipher as a PRNG source.
"""

import struct
from typing import List

# ChaCha20 implementation
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.backends import default_backend
    CHACHA20_AVAILABLE = True
except ImportError:
    CHACHA20_AVAILABLE = False

from .utils import SecureBytes


class ChaCha20PRNG:
    """
    ChaCha20-based pseudo-random number generator for scrambling.
    
    This provides a cryptographically secure PRNG seeded with the scrambling key
    derived from the AEAD tag and other message-specific data.
    """
    
    def __init__(self, seed: bytes):
        """
        Initialize ChaCha20 PRNG with seed.
        
        Args:
            seed: 32-byte seed for ChaCha20
        """
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes")
        
        if not CHACHA20_AVAILABLE:
            # Fallback to simple PRNG if ChaCha20 not available
            import hashlib
            self._fallback = True
            self._state = hashlib.sha256(seed).digest()
            self._counter = 0
        else:
            self._fallback = False
            self._key = seed
            self._nonce = b'\x00' * 16  # Fixed nonce for PRNG use (ChaCha20 needs 16 bytes)
            self._counter = 0
            self._buffer = b''
            self._buffer_pos = 0
    
    def next_uint32(self) -> int:
        """Generate next 32-bit unsigned integer."""
        if self._fallback:
            return self._next_uint32_fallback()
        else:
            return self._next_uint32_chacha20()
    
    def _next_uint32_chacha20(self) -> int:
        """Generate using ChaCha20."""
        if self._buffer_pos >= len(self._buffer):
            # Generate new block of random data
            cipher = Cipher(
                algorithms.ChaCha20(self._key, self._nonce),
                mode=None,
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt 64 bytes of zeros to get random stream
            self._buffer = encryptor.update(b'\x00' * 64)
            self._buffer_pos = 0
            
            # Increment counter for next block
            self._counter += 1
            # Update nonce with counter (little-endian) - ChaCha20 needs 16 bytes
            self._nonce = struct.pack('<Q', self._counter) + b'\x00' * 8
        
        # Extract 4 bytes and convert to uint32
        value_bytes = self._buffer[self._buffer_pos:self._buffer_pos + 4]
        self._buffer_pos += 4
        
        return struct.unpack('<I', value_bytes)[0]
    
    def _next_uint32_fallback(self) -> int:
        """Fallback PRNG using SHA256."""
        import hashlib
        
        # Hash state with counter to get next value
        input_data = self._state + struct.pack('<Q', self._counter)
        hash_result = hashlib.sha256(input_data).digest()
        
        # Update state and counter
        self._state = hash_result
        self._counter += 1
        
        # Return first 4 bytes as uint32
        return struct.unpack('<I', hash_result[:4])[0]


def fisher_yates_shuffle(data: bytearray, prng: ChaCha20PRNG) -> None:
    """
    In-place Fisher-Yates shuffle using ChaCha20 PRNG.
    
    Args:
        data: Bytearray to shuffle in place
        prng: ChaCha20PRNG instance for random numbers
    """
    n = len(data)
    for i in range(n - 1, 0, -1):
        # Generate random index j where 0 <= j <= i
        j = prng.next_uint32() % (i + 1)
        
        # Swap elements at positions i and j
        data[i], data[j] = data[j], data[i]


def fisher_yates_unshuffle(data: bytearray, prng: ChaCha20PRNG) -> None:
    """
    Reverse Fisher-Yates shuffle to unscramble data.
    
    Args:
        data: Bytearray to unshuffle in place
        prng: ChaCha20PRNG instance (same seed as used for shuffling)
    """
    n = len(data)
    
    # Generate all the random indices that were used
    indices = []
    for i in range(n - 1, 0, -1):
        j = prng.next_uint32() % (i + 1)
        indices.append(j)
    
    # Reverse the shuffle by applying swaps in reverse order
    for i, j in enumerate(reversed(indices)):
        pos = i + 1  # Position in original shuffle
        data[pos], data[j] = data[j], data[pos]


class DataScrambler:
    """
    Data scrambling using chunked Fisher-Yates shuffle for IoT-friendly operation.
    
    Processes data in small chunks (64-128 bytes) to bound memory usage and 
    computational cost on constrained devices while maintaining security properties.
    """
    
    def __init__(self, use_chacha20: bool = True, chunk_size: int = 64):
        """
        Initialize the data scrambler.
        
        Args:
            use_chacha20: Use ChaCha20 if available, otherwise SHA256
            chunk_size: Size of chunks for permutation (64-128 bytes recommended)
        """
        self.use_chacha20 = use_chacha20 and CHACHA20_AVAILABLE
        self.chunk_size = min(max(chunk_size, 32), 128)  # Clamp to reasonable range
    
    def scramble(self, data: bytes, seed: bytes) -> bytes:
        """
        Scramble data using chunked Fisher-Yates permutation.
        
        Args:
            data: Input data to scramble
            seed: 32-byte seed for permutation
            
        Returns:
            Scrambled data with same length as input
        """
        if len(data) == 0:
            return data
            
        # Process data in chunks
        scrambled_chunks = []
        
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i:i + self.chunk_size]
            
            # Create chunk-specific seed by mixing original seed with chunk index
            chunk_seed = self._derive_chunk_seed(seed, i // self.chunk_size)
            
            # Scramble this chunk
            scrambled_chunk = self._scramble_chunk(chunk, chunk_seed)
            scrambled_chunks.append(scrambled_chunk)
        
        return b''.join(scrambled_chunks)
    
    def unscramble(self, scrambled_data: bytes, seed: bytes) -> bytes:
        """
        Unscramble data using chunked Fisher-Yates permutation.
        
        Args:
            scrambled_data: Previously scrambled data
            seed: Same 32-byte seed used for scrambling
            
        Returns:
            Original unscrambled data
        """
        if len(scrambled_data) == 0:
            return scrambled_data
            
        # Process data in chunks
        unscrambled_chunks = []
        
        for i in range(0, len(scrambled_data), self.chunk_size):
            chunk = scrambled_data[i:i + self.chunk_size]
            
            # Create chunk-specific seed by mixing original seed with chunk index
            chunk_seed = self._derive_chunk_seed(seed, i // self.chunk_size)
            
            # Unscramble this chunk
            unscrambled_chunk = self._unscramble_chunk(chunk, chunk_seed)
            unscrambled_chunks.append(unscrambled_chunk)
        
        return b''.join(unscrambled_chunks)
    
    def _derive_chunk_seed(self, base_seed: bytes, chunk_index: int) -> bytes:
        """
        Derive a chunk-specific seed from the base seed and chunk index.
        
        Args:
            base_seed: Base 32-byte seed
            chunk_index: Index of the chunk being processed
            
        Returns:
            32-byte chunk-specific seed
        """
        import hashlib
        
        # Mix base seed with chunk index
        hasher = hashlib.sha256()
        hasher.update(base_seed)
        hasher.update(chunk_index.to_bytes(4, byteorder='big'))
        
        return hasher.digest()
    
    def _scramble_chunk(self, data: bytes, seed: bytes) -> bytes:
        """
        Scramble a single chunk using Fisher-Yates shuffle.
        
        Args:
            data: Chunk data to scramble (≤ chunk_size bytes)
            seed: 32-byte seed for this chunk
            
        Returns:
            Scrambled chunk data
        """
        if len(data) <= 1:
            return data
            
        # Convert to mutable array
        data_array = bytearray(data)
        
        # Initialize PRNG for this chunk
        prng = ChaCha20PRNG(seed)
        
        # Apply Fisher-Yates shuffle to chunk
        fisher_yates_shuffle(data_array, prng)
        
        return bytes(data_array)
    
    def _unscramble_chunk(self, scrambled_data: bytes, seed: bytes) -> bytes:
        """
        Unscramble a single chunk using reverse Fisher-Yates shuffle.
        
        Args:
            scrambled_data: Chunk data to unscramble (≤ chunk_size bytes)
            seed: Same 32-byte seed used for scrambling this chunk
            
        Returns:
            Original chunk data
        """
        if len(scrambled_data) <= 1:
            return scrambled_data
            
        # Convert to mutable array
        data = bytearray(scrambled_data)
        
        # Initialize PRNG for this chunk (same as scrambling)
        prng = ChaCha20PRNG(seed)
        
        # Reverse the Fisher-Yates shuffle
        fisher_yates_unshuffle(data, prng)
        
        return bytes(data)

    @property
    def algorithm_name(self) -> str:
        """Get the name of the scrambling algorithm."""
        prng_name = "ChaCha20" if self.use_chacha20 else "SHA256-fallback"
        return f"Chunked Fisher-Yates ({self.chunk_size}B) + {prng_name}"


def scramble_data(data: bytes, permutation_key: bytes, tag: bytes, r: bytes) -> bytes:
    """
    Convenience function to scramble data with message-specific parameters.
    Uses optimized 64-byte chunks for IoT-friendly performance.
    
    Args:
        data: Data to scramble
        permutation_key: 32-byte permutation key from ratchet
        tag: 16-byte AEAD authentication tag
        r: 4-byte per-message random value
        
    Returns:
        Scrambled data
    """
    from .ratchet import compute_permutation_seed
    
    # Compute scrambling seed from all inputs
    seed = compute_permutation_seed(permutation_key, tag, r)
    
    # Scramble using chunked scrambler optimized for IoT devices
    scrambler = DataScrambler(chunk_size=64)  # 64-byte chunks for optimal performance
    return scrambler.scramble(data, seed)


def unscramble_data(scrambled_data: bytes, permutation_key: bytes, 
                   tag: bytes, r: bytes) -> bytes:
    """
    Convenience function to unscramble data with message-specific parameters.
    Uses optimized 64-byte chunks for IoT-friendly performance.
    
    Args:
        scrambled_data: Previously scrambled data
        permutation_key: Same 32-byte permutation key used for scrambling
        tag: Same 16-byte AEAD tag used for scrambling
        r: Same 4-byte random value used for scrambling
        
    Returns:
        Original unscrambled data
    """
    from .ratchet import compute_permutation_seed
    
    # Compute scrambling seed from all inputs
    seed = compute_permutation_seed(permutation_key, tag, r)
    
    # Unscramble using chunked scrambler optimized for IoT devices
    scrambler = DataScrambler(chunk_size=64)  # Same 64-byte chunks as scrambling
    return scrambler.unscramble(scrambled_data, seed)
    """
    Convenience function to unscramble data with message-specific parameters.
    
    Args:
        scrambled_data: Previously scrambled data
        permutation_key: Same 32-byte permutation key used for scrambling
        tag: Same 16-byte AEAD tag used for scrambling
        r: Same 4-byte random value used for scrambling
        
    Returns:
        Original unscrambled data
    """
    from .ratchet import compute_permutation_seed
    
    # Compute scrambling seed from all inputs
    seed = compute_permutation_seed(permutation_key, tag, r)
    
    # Unscramble using chunked scrambler optimized for IoT devices
    scrambler = DataScrambler(chunk_size=64)  # Same 64-byte chunks as scrambling
    return scrambler.unscramble(scrambled_data, seed)


def test_scrambling_roundtrip(data: bytes, seed: bytes) -> bool:
    """
    Test that scrambling and unscrambling produces original data.
    
    Args:
        data: Test data
        seed: Test seed
        
    Returns:
        True if roundtrip successful
    """
    scrambler = DataScrambler()
    
    # Scramble then unscramble
    scrambled = scrambler.scramble(data, seed)
    unscrambled = scrambler.unscramble(scrambled, seed)
    
    # Check if we got back original data
    return unscrambled == data
