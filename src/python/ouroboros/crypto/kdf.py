"""
Key Derivation Functions for Ouroboros Protocol.

Implements the forward-secure key derivation chain where:
- Root key remains constant
- Session keys are derived from previous keys in the chain
- Uses HKDF with protocol-specific context strings
"""

import hashlib
import hmac
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyDerivationError(Exception):
    """Raised when key derivation fails."""
    pass


# Protocol constants
OUROBOROS_ENC_CONTEXT = b"OUROBOROS_ENC_V1"
OUROBOROS_SCR_CONTEXT = b"OUROBOROS_SCR_V1"
KEY_LENGTH = 32  # 256-bit keys


def derive_session_keys(
    root_key: bytes, 
    counter: int,
    previous_enc_key: Optional[bytes] = None,
    previous_scr_key: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Derive encryption and scrambling keys for a message.
    
    For the first message (counter=0), derives from root_key.
    For subsequent messages, derives from previous keys in the chain.
    
    Args:
        root_key: The permanent root key (32 bytes)
        counter: Message counter (incremented for each message)
        previous_enc_key: Previous encryption key (for counter > 0)
        previous_scr_key: Previous scrambling key (for counter > 0)
        
    Returns:
        Tuple of (encryption_key, scrambling_key) as 32-byte values
        
    Raises:
        KeyDerivationError: If derivation fails or invalid parameters
    """
    try:
        if len(root_key) != KEY_LENGTH:
            raise KeyDerivationError(f"Root key must be {KEY_LENGTH} bytes")
            
        if counter < 0:
            raise KeyDerivationError("Counter must be non-negative")
            
        # Convert counter to bytes for use in derivation
        counter_bytes = counter.to_bytes(8, byteorder='big')
        
        if counter == 0:
            # First message: derive from root key
            base_key_enc = root_key
            base_key_scr = root_key
        else:
            # Subsequent messages: derive from previous keys
            if previous_enc_key is None or previous_scr_key is None:
                raise KeyDerivationError("Previous keys required for counter > 0")
            if len(previous_enc_key) != KEY_LENGTH or len(previous_scr_key) != KEY_LENGTH:
                raise KeyDerivationError(f"Previous keys must be {KEY_LENGTH} bytes")
            base_key_enc = previous_enc_key
            base_key_scr = previous_scr_key
        
        # Derive encryption key
        hkdf_enc = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=counter_bytes,
            info=OUROBOROS_ENC_CONTEXT,
        )
        encryption_key = hkdf_enc.derive(base_key_enc)
        
        # Derive scrambling key
        hkdf_scr = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=counter_bytes,
            info=OUROBOROS_SCR_CONTEXT,
        )
        scrambling_key = hkdf_scr.derive(base_key_scr)
        
        return encryption_key, scrambling_key
        
    except Exception as e:
        raise KeyDerivationError(f"Key derivation failed: {str(e)}")


def generate_root_key() -> bytes:
    """
    Generate a cryptographically secure root key.
    
    Returns:
        32-byte root key for use in the protocol
    """
    import os
    return os.urandom(KEY_LENGTH)


def verify_key_chain_integrity(
    root_key: bytes,
    key_chain: list,
    max_counter: int
) -> bool:
    """
    Verify the integrity of a key derivation chain.
    
    Args:
        root_key: The root key used for derivation
        key_chain: List of (enc_key, scr_key) tuples
        max_counter: Maximum counter value to verify
        
    Returns:
        True if the chain is valid, False otherwise
    """
    try:
        current_enc, current_scr = None, None
        
        for counter in range(max_counter + 1):
            expected_enc, expected_scr = derive_session_keys(
                root_key, counter, current_enc, current_scr
            )
            
            if counter < len(key_chain):
                actual_enc, actual_scr = key_chain[counter]
                if actual_enc != expected_enc or actual_scr != expected_scr:
                    return False
            
            current_enc, current_scr = expected_enc, expected_scr
            
        return True
        
    except Exception:
        return False
