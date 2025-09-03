"""
Decryption Pipeline for Ouroboros Protocol.

Implements the complete decryption pipeline:
Parse header → Unscramble → AEAD decrypt → Sliding window validation
"""

import struct
from typing import Tuple, Optional, Dict
from ..crypto.ratchet import HashRatchet, derive_keys_hkdf
from ..crypto.aead import AEADCipher, decrypt_aes_gcm
from ..crypto.scramble import unscramble_data
from ..crypto.utils import validate_key_length
from .packet import OuroborosPacket
from .window import ChannelWindow, get_global_channel_window


class DecryptionError(Exception):
    """Raised when decryption operations fail."""
    pass


class OuroborosDecryptor:
    """
    Complete decryption pipeline for Ouroboros protocol.
    
    Handles packet parsing, unscrambling, AEAD decryption, and sliding window
    replay protection according to the new symmetric protocol specification.
    """
    
    def __init__(self, root_key: bytes, channel_id: int = 0,
                 algorithm: str = AEADCipher.AES_GCM, use_ratcheting: bool = True,
                 window_size: int = 1000):
        """
        Initialize decryptor with root key.
        
        Args:
            root_key: 32-byte root key material
            channel_id: Expected channel identifier
            algorithm: AEAD algorithm to use
            use_ratcheting: Whether to use hash ratcheting (vs. HKDF)
            window_size: Sliding window size for replay protection
            
        Raises:
            DecryptionError: If initialization fails
        """
        validate_key_length(root_key, 32, "root key")
        
        if not (0 <= channel_id <= 255):
            raise DecryptionError("Channel ID must be 0-255")
        
        self.channel_id = channel_id
        self.algorithm = algorithm
        self.use_ratcheting = use_ratcheting
        self.window_size = window_size
        
        # Initialize AEAD cipher
        self.aead = AEADCipher(algorithm)
        
        # Initialize key derivation
        if use_ratcheting:
            # For decryption, we need to maintain multiple ratchet states
            # This is a simplified approach - a full implementation would
            # need more sophisticated state management
            self.root_key = root_key
            self._ratchet_states: Dict[int, HashRatchet] = {}
        else:
            self.root_key = root_key
        
        # Initialize replay protection window
        self.window = ChannelWindow(window_size)
    
    def decrypt_packet(self, packet: OuroborosPacket,
                      associated_data: bytes = b"") -> bytes:
        """
        Decrypt an Ouroboros packet using the complete pipeline.
        
        Pipeline: Parse header → Unscramble → AEAD decrypt → Sliding window validation
        
        Args:
            packet: Packet to decrypt
            associated_data: Additional authenticated data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            DecryptionError: If decryption or validation fails
        """
        try:
            # Step 1: Validate packet structure
            if not packet.is_valid():
                raise DecryptionError("Invalid packet structure")
            
            # Step 2: Check channel ID
            if packet.channel_id != self.channel_id:
                raise DecryptionError(f"Channel ID mismatch: expected {self.channel_id}, got {packet.channel_id}")
            
            # Step 3: Check replay protection
            if not self.window.is_valid_counter(packet.channel_id, packet.counter):
                raise DecryptionError(f"Replay attack detected: counter {packet.counter}")
            
            # Step 4: Derive keys for this counter
            enc_key, scr_key = self._derive_keys(packet.counter)
            
            # Step 5: Unscramble the ciphertext
            try:
                ciphertext = unscramble_data(scr_key, packet.scrambled_data)
            except Exception as e:
                raise DecryptionError(f"Unscrambling failed: {e}")
            
            # Step 6: Reconstruct ciphertext with auth tag for AEAD
            ciphertext_with_tag = ciphertext + packet.auth_tag
            
            # Step 7: Construct associated data for AEAD verification
            header_data = struct.pack('>BII', packet.channel_id, packet.counter, packet.r)
            full_associated_data = header_data + associated_data
            
            # Step 8: AEAD decryption (we need to reconstruct the nonce)
            # Note: In a real implementation, nonce derivation would be deterministic
            # For now, we'll assume nonce is stored or derived deterministically
            nonce = self._derive_nonce(packet.counter, packet.r)
            
            try:
                plaintext = self.aead.decrypt(
                    enc_key, nonce, ciphertext_with_tag, full_associated_data
                )
            except Exception as e:
                raise DecryptionError(f"AEAD decryption failed: {e}")
            
            # Step 9: Accept counter in sliding window (only after successful decryption)
            if not self.window.accept_counter(packet.channel_id, packet.counter):
                # This shouldn't happen since we checked earlier, but be defensive
                raise DecryptionError(f"Failed to accept counter {packet.counter}")
            
            return plaintext
            
        except DecryptionError:
            raise
        except Exception as e:
            raise DecryptionError(f"Packet decryption failed: {e}")
    
    def decrypt_bytes(self, packet_bytes: bytes,
                     associated_data: bytes = b"") -> bytes:
        """
        Decrypt packet from raw bytes.
        
        Args:
            packet_bytes: Raw packet data
            associated_data: Additional authenticated data
            
        Returns:
            Decrypted plaintext
        """
        packet = OuroborosPacket.from_bytes(packet_bytes)
        return self.decrypt_packet(packet, associated_data)
    
    def _derive_keys(self, counter: int) -> Tuple[bytes, bytes]:
        """
        Derive encryption and scrambling keys for the given counter.
        
        Args:
            counter: Message counter
            
        Returns:
            Tuple of (encryption_key, scrambling_key)
        """
        if self.use_ratcheting:
            # For ratcheting, we need to be able to derive keys for any counter
            # This is a simplified approach - create a fresh ratchet for each counter
            # A more efficient implementation would maintain ratchet state more carefully
            ratchet = HashRatchet(self.root_key)
            return ratchet.derive_keys(counter)
        else:
            return derive_keys_hkdf(self.root_key, counter)
    
    def _derive_nonce(self, counter: int, r: int) -> bytes:
        """
        Derive nonce deterministically from counter and r value.
        
        Args:
            counter: Message counter
            r: Random value from packet
            
        Returns:
            Nonce for AEAD decryption
        """
        import hashlib
        
        if self.use_ratcheting:
            # For ratcheting, we need the same state as encryptor had
            # This is simplified - derive it from root key and counter
            nonce_input = struct.pack('>II', counter, r) + self.root_key
        else:
            nonce_input = struct.pack('>II', counter, r) + self.root_key
        
        nonce_hash = hashlib.sha256(nonce_input).digest()
        return nonce_hash[:self.aead.nonce_length]
    
    def is_valid_packet(self, packet: OuroborosPacket) -> bool:
        """
        Check if a packet is valid for decryption.
        
        Args:
            packet: Packet to validate
            
        Returns:
            True if packet is valid, False otherwise
        """
        try:
            # Check packet structure
            if not packet.is_valid():
                return False
            
            # Check channel ID
            if packet.channel_id != self.channel_id:
                return False
            
            # Check replay protection
            if not self.window.is_valid_counter(packet.channel_id, packet.counter):
                return False
            
            return True
            
        except Exception:
            return False
    
    def get_window_stats(self) -> dict:
        """
        Get sliding window statistics.
        
        Returns:
            Dictionary with window statistics
        """
        return self.window.get_channel_stats(self.channel_id)
    
    def reset_window(self):
        """Reset the sliding window state."""
        self.window.reset_channel(self.channel_id)
    
    def get_stats(self) -> dict:
        """
        Get decryptor statistics.
        
        Returns:
            Dictionary with decryptor statistics
        """
        stats = {
            'channel_id': self.channel_id,
            'algorithm': self.algorithm,
            'use_ratcheting': self.use_ratcheting,
            'window_size': self.window_size,
            'key_length': self.aead.key_length,
            'nonce_length': self.aead.nonce_length,
            'tag_length': self.aead.tag_length
        }
        
        # Add window statistics
        stats.update(self.get_window_stats())
        
        return stats


def decrypt_data(root_key: bytes, packet: OuroborosPacket,
                channel_id: int = 0, algorithm: str = AEADCipher.AES_GCM) -> bytes:
    """
    Convenience function to decrypt data with a single call.
    
    Args:
        root_key: 32-byte root key
        packet: Packet to decrypt
        channel_id: Expected channel identifier
        algorithm: AEAD algorithm to use
        
    Returns:
        Decrypted plaintext
    """
    decryptor = OuroborosDecryptor(root_key, channel_id, algorithm, use_ratcheting=False)
    return decryptor.decrypt_packet(packet)


def test_decryption(packet_bytes: bytes, root_key: bytes) -> bytes:
    """
    Test decryption function for debugging.
    
    Args:
        packet_bytes: Raw packet data
        root_key: Root key used for encryption
        
    Returns:
        Decrypted plaintext
    """
    packet = OuroborosPacket.from_bytes(packet_bytes)
    return decrypt_data(root_key, packet, packet.channel_id)