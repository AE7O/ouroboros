"""
Key Derivation Functions for Ouroboros Protocol.

Implements the forward-secure key derivation chain where:
- Root key remains constant
- Session keys are derived from previous keys in the chain
- Uses HKDF with protocol-specific context strings
"""

import os
import hashlib
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
        if counter < 0:
            raise KeyDerivationError("Counter must be non-negative")
            
        # Convert counter to bytes for use in derivation
        counter_bytes = counter.to_bytes(8, byteorder='big')
        
        if counter == 0:
            # First message: derive from root key
            if root_key is None or len(root_key) != KEY_LENGTH:
                raise KeyDerivationError(f"Root key must be {KEY_LENGTH} bytes for counter 0")
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


def load_root_key(key_file_path: str) -> bytes:
    """
    Load the root key/master secret from a file.
    
    Args:
        key_file_path: Path to the file containing the root key
        
    Returns:
        bytes: The 32-byte root key
        
    Raises:
        FileNotFoundError: If the key file doesn't exist
        ValueError: If the key file format is invalid
    """
    if not os.path.exists(key_file_path):
        raise FileNotFoundError(f"Root key file not found: {key_file_path}")
    
    with open(key_file_path, 'rb') as f:
        key_data = f.read()
    
    # Support different formats
    if len(key_data) == 32:
        # Raw binary key (32 bytes)
        return key_data
    elif len(key_data) == 64:
        # Hex-encoded key (64 hex chars = 32 bytes)
        try:
            return bytes.fromhex(key_data.decode('ascii'))
        except (ValueError, UnicodeDecodeError):
            pass
    elif len(key_data) == 65 and key_data.endswith(b'\n'):
        # Hex-encoded key with newline
        try:
            return bytes.fromhex(key_data[:-1].decode('ascii'))
        except (ValueError, UnicodeDecodeError):
            pass
    
    # If we get here, the format is not recognized
    raise ValueError(f"Invalid root key format. Expected 32 raw bytes or 64 hex characters, got {len(key_data)} bytes")


def create_root_key_file(key_file_path: str, root_key: bytes = None) -> bytes:
    """
    Create a root key file with either a provided key or a generated one.
    
    Args:
        key_file_path: Path where to save the key file
        root_key: Optional pre-existing key. If None, generates a new one.
        
    Returns:
        bytes: The root key that was saved
    """
    if root_key is None:
        root_key = generate_root_key()
    
    # Save as hex for human readability
    with open(key_file_path, 'w') as f:
        f.write(root_key.hex())
    
    # Set restrictive permissions (Unix/Linux)
    try:
        os.chmod(key_file_path, 0o600)  # rw-------
    except (OSError, AttributeError):
        # Windows or permission error - warn but continue
        print(f"Warning: Could not set restrictive permissions on {key_file_path}")
    
    return root_key


def generate_root_key() -> bytes:
    """Generate a cryptographically secure 32-byte root key."""
    return os.urandom(32)


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
