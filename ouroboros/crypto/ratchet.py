"""
Hash-based Key Ratcheting for Ouroboros Protocol.

Implements forward-secure key derivation using hash-based ratcheting
where each message uses a unique key derived from the previous state.
"""

import hashlib
import os
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class RatchetError(Exception):
    """Raised when ratchet operations fail."""
    pass


# Protocol constants
OUROBOROS_ENC_CONTEXT = b"OUROBOROS_ENC_V2"
OUROBOROS_SCR_CONTEXT = b"OUROBOROS_SCR_V2"
OUROBOROS_RATCHET_CONTEXT = b"OUROBOROS_RATCHET_V2"
KEY_LENGTH = 32  # 256-bit keys


class HashRatchet:
    """
    Hash-based key ratcheting implementation.
    
    Provides forward secrecy through one-way hash-based key evolution.
    Each ratchet step produces new encryption and scrambling keys while
    advancing the internal state irreversibly.
    """
    
    def __init__(self, root_key: bytes):
        """
        Initialize ratchet with root key.
        
        Args:
            root_key: 32-byte root key material
            
        Raises:
            RatchetError: If root key is invalid
        """
        if len(root_key) != KEY_LENGTH:
            raise RatchetError(f"Root key must be {KEY_LENGTH} bytes")
        
        # Initialize ratchet state with root key
        self._state = root_key
    
    def derive_keys(self, counter: int) -> Tuple[bytes, bytes]:
        """
        Derive encryption and scrambling keys for a specific counter.
        
        Args:
            counter: Message counter (4 bytes when packed)
            
        Returns:
            Tuple of (encryption_key, scrambling_key)
            
        Raises:
            RatchetError: If derivation fails
        """
        try:
            # Convert counter to bytes for derivation context
            counter_bytes = counter.to_bytes(4, byteorder='big')
            
            # Derive new ratchet state
            hkdf_state = HKDF(
                algorithm=hashes.SHA256(),
                length=KEY_LENGTH,
                salt=counter_bytes,
                info=OUROBOROS_RATCHET_CONTEXT,
            )
            new_state = hkdf_state.derive(self._state)
            
            # Derive encryption key from new state
            hkdf_enc = HKDF(
                algorithm=hashes.SHA256(),
                length=KEY_LENGTH,
                salt=counter_bytes,
                info=OUROBOROS_ENC_CONTEXT,
            )
            encryption_key = hkdf_enc.derive(new_state)
            
            # Derive scrambling key from new state (separate derivation)
            hkdf_scr = HKDF(
                algorithm=hashes.SHA256(),
                length=KEY_LENGTH,
                salt=counter_bytes,
                info=OUROBOROS_SCR_CONTEXT,
            )
            scrambling_key = hkdf_scr.derive(new_state)
            
            # Update internal state for forward secrecy
            self._state = new_state
            
            return encryption_key, scrambling_key
            
        except Exception as e:
            raise RatchetError(f"Key derivation failed: {str(e)}")
    
    def get_state(self) -> bytes:
        """
        Get current ratchet state (for testing/debugging only).
        
        Returns:
            Current internal state
        """
        return self._state
    
    def reset(self, root_key: bytes):
        """
        Reset ratchet to initial state with new root key.
        
        Args:
            root_key: New 32-byte root key
            
        Raises:
            RatchetError: If root key is invalid
        """
        if len(root_key) != KEY_LENGTH:
            raise RatchetError(f"Root key must be {KEY_LENGTH} bytes")
        
        self._state = root_key


def generate_root_key() -> bytes:
    """Generate a cryptographically secure 32-byte root key."""
    return os.urandom(32)


def derive_keys_hkdf(root_key: bytes, counter: int) -> Tuple[bytes, bytes]:
    """
    Direct key derivation using HKDF (alternative to ratcheting).
    
    Args:
        root_key: 32-byte root key
        counter: Message counter
        
    Returns:
        Tuple of (encryption_key, scrambling_key)
    """
    if len(root_key) != KEY_LENGTH:
        raise RatchetError(f"Root key must be {KEY_LENGTH} bytes")
    
    counter_bytes = counter.to_bytes(4, byteorder='big')
    
    # Derive encryption key
    hkdf_enc = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=counter_bytes,
        info=OUROBOROS_ENC_CONTEXT,
    )
    encryption_key = hkdf_enc.derive(root_key)
    
    # Derive scrambling key (separate instance required)
    hkdf_scr = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=counter_bytes,
        info=OUROBOROS_SCR_CONTEXT,
    )
    scrambling_key = hkdf_scr.derive(root_key)
    
    return encryption_key, scrambling_key


def derive_keys_ascon(root_key: bytes, counter: int) -> Tuple[bytes, bytes]:
    """
    Key derivation using ASCON-Hash256 (placeholder implementation).
    
    Note: This is a placeholder. Full ASCON implementation would require
    the ASCON library or custom implementation.
    
    Args:
        root_key: 32-byte root key
        counter: Message counter
        
    Returns:
        Tuple of (encryption_key, scrambling_key)
    """
    # For now, fall back to HKDF-SHA256
    # TODO: Implement actual ASCON-Hash256 when library is available
    return derive_keys_hkdf(root_key, counter)