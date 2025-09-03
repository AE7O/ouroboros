"""
Encryption Pipeline for Ouroboros Protocol.

Implements the complete encryption pipeline:
Ratchet derivation → AEAD encrypt → Scramble → Packet construction
"""

import os
import struct
from typing import Tuple, Optional
from ..crypto.ratchet import HashRatchet, derive_keys_hkdf
from ..crypto.aead import AEADCipher, encrypt_aes_gcm
from ..crypto.scramble import scramble_data
from ..crypto.utils import secure_random, validate_key_length
from .packet import OuroborosPacket, PacketType


class EncryptionError(Exception):
    """Raised when encryption operations fail."""
    pass


class OuroborosEncryptor:
    """
    Complete encryption pipeline for Ouroboros protocol.
    
    Handles key ratcheting, AEAD encryption, scrambling, and packet construction
    according to the new symmetric protocol specification.
    """
    
    def __init__(self, root_key: bytes, channel_id: int = 0, 
                 algorithm: str = AEADCipher.AES_GCM, use_ratcheting: bool = True):
        """
        Initialize encryptor with root key.
        
        Args:
            root_key: 32-byte root key material
            channel_id: Channel identifier (0-255)
            algorithm: AEAD algorithm to use
            use_ratcheting: Whether to use hash ratcheting (vs. HKDF)
            
        Raises:
            EncryptionError: If initialization fails
        """
        validate_key_length(root_key, 32, "root key")
        
        if not (0 <= channel_id <= 255):
            raise EncryptionError("Channel ID must be 0-255")
        
        self.channel_id = channel_id
        self.algorithm = algorithm
        self.use_ratcheting = use_ratcheting
        
        # Initialize AEAD cipher
        self.aead = AEADCipher(algorithm)
        
        # Initialize key ratchet if using ratcheting
        if use_ratcheting:
            self.ratchet = HashRatchet(root_key)
        else:
            self.root_key = root_key
        
        self._counter = 0
    
    def encrypt_message(self, plaintext: bytes, 
                       associated_data: bytes = b"") -> OuroborosPacket:
        """
        Encrypt a message using the complete Ouroboros pipeline.
        
        Pipeline: Ratchet derivation → AEAD encrypt → Scramble → Packet construction
        
        Args:
            plaintext: Message to encrypt
            associated_data: Additional authenticated data
            
        Returns:
            Ouroboros packet ready for transmission
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Step 1: Get next counter and derive keys
            counter = self._get_next_counter()
            enc_key, scr_key = self._derive_keys(counter)
            
            # Step 2: Generate random value r for this message
            r = struct.unpack('>I', secure_random(4))[0]
            
            # Step 3: Construct associated data for AEAD
            # Include channel_id, counter, and r in authentication
            header_data = struct.pack('>BII', self.channel_id, counter, r)
            full_associated_data = header_data + associated_data
            
            # Step 4: Generate deterministic nonce from counter and r
            # This ensures the decryptor can derive the same nonce
            nonce = self._derive_nonce(counter, r)
            
            # Step 5: AEAD encryption
            ciphertext_with_tag = self.aead.encrypt(
                enc_key, nonce, plaintext, full_associated_data
            )
            
            # Step 5: Extract ciphertext and auth tag
            ciphertext = ciphertext_with_tag[:-self.aead.tag_length]
            auth_tag = ciphertext_with_tag[-self.aead.tag_length:]
            
            # Step 6: Scramble the ciphertext
            scrambled_ciphertext = scramble_data(scr_key, ciphertext)
            
            # Step 7: Construct packet
            packet = OuroborosPacket(
                channel_id=self.channel_id,
                counter=counter,
                r=r,
                auth_tag=auth_tag,
                scrambled_data=scrambled_ciphertext,
                packet_type=PacketType.DATA
            )
            
            # Store nonce for potential debugging (not transmitted)
            packet._nonce = nonce
            
            return packet
            
        except Exception as e:
            raise EncryptionError(f"Message encryption failed: {e}")
    
    def _get_next_counter(self) -> int:
        """
        Get the next message counter.
        
        Returns:
            Next counter value
        """
        counter = self._counter
        self._counter += 1
        
        # Ensure counter doesn't overflow 32-bit space
        if self._counter >= 2**32:
            raise EncryptionError("Counter overflow - session must be reinitialized")
        
        return counter
    
    def _derive_keys(self, counter: int) -> Tuple[bytes, bytes]:
        """
        Derive encryption and scrambling keys for the given counter.
        
        Args:
            counter: Message counter
            
        Returns:
            Tuple of (encryption_key, scrambling_key)
        """
        if self.use_ratcheting:
            return self.ratchet.derive_keys(counter)
        else:
            return derive_keys_hkdf(self.root_key, counter)
    
    def _derive_nonce(self, counter: int, r: int) -> bytes:
        """
        Derive nonce deterministically from counter and r value.
        
        Args:
            counter: Message counter
            r: Random value
            
        Returns:
            Nonce for AEAD encryption
        """
        import hashlib
        
        if self.use_ratcheting:
            nonce_input = struct.pack('>II', counter, r) + self.ratchet.get_state()
        else:
            nonce_input = struct.pack('>II', counter, r) + self.root_key
        
        nonce_hash = hashlib.sha256(nonce_input).digest()
        return nonce_hash[:self.aead.nonce_length]
    
    def get_counter(self) -> int:
        """
        Get current counter value.
        
        Returns:
            Current counter
        """
        return self._counter
    
    def reset_counter(self, value: int = 0):
        """
        Reset counter to specified value.
        
        Args:
            value: New counter value
            
        Raises:
            EncryptionError: If value is invalid
        """
        if not (0 <= value < 2**32):
            raise EncryptionError("Counter must be 32-bit value")
        
        self._counter = value
    
    def get_stats(self) -> dict:
        """
        Get encryptor statistics.
        
        Returns:
            Dictionary with encryptor statistics
        """
        stats = {
            'channel_id': self.channel_id,
            'algorithm': self.algorithm,
            'use_ratcheting': self.use_ratcheting,
            'current_counter': self._counter,
            'key_length': self.aead.key_length,
            'nonce_length': self.aead.nonce_length,
            'tag_length': self.aead.tag_length
        }
        
        if hasattr(self, 'ratchet'):
            stats['ratchet_state'] = self.ratchet.get_state().hex()
        
        return stats


def encrypt_data(root_key: bytes, plaintext: bytes, channel_id: int = 0,
                counter: Optional[int] = None, algorithm: str = AEADCipher.AES_GCM) -> OuroborosPacket:
    """
    Convenience function to encrypt data with a single call.
    
    Args:
        root_key: 32-byte root key
        plaintext: Data to encrypt
        channel_id: Channel identifier
        counter: Specific counter to use (auto-generated if None)
        algorithm: AEAD algorithm to use
        
    Returns:
        Encrypted Ouroboros packet
    """
    encryptor = OuroborosEncryptor(root_key, channel_id, algorithm, use_ratcheting=False)
    
    if counter is not None:
        encryptor.reset_counter(counter)
    
    return encryptor.encrypt_message(plaintext)


def create_test_packet(plaintext: bytes = b"Hello, Ouroboros!") -> Tuple[OuroborosPacket, bytes]:
    """
    Create a test packet for debugging and testing.
    
    Args:
        plaintext: Test message to encrypt
        
    Returns:
        Tuple of (packet, root_key) for testing
    """
    root_key = secure_random(32)
    packet = encrypt_data(root_key, plaintext)
    return packet, root_key