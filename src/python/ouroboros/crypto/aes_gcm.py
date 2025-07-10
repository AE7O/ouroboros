"""
AES-GCM Authenticated Encryption for Ouroboros Protocol.

Provides secure encryption and authentication of message data using AES-GCM.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""
    pass


def encrypt_message(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Encrypt a message using AES-GCM.
    
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
        associated_data: Additional data to authenticate (not encrypted)
        
    Returns:
        Tuple of (nonce, ciphertext_with_tag)
        
    Raises:
        EncryptionError: If encryption fails
    """
    try:
        if len(key) != 32:
            raise EncryptionError("Encryption key must be 32 bytes")
            
        # Generate random 96-bit nonce for GCM
        nonce = os.urandom(12)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Encrypt and authenticate
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        return nonce, ciphertext_with_tag
        
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {str(e)}")


def decrypt_message(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt a message using AES-GCM.
    
    Args:
        key: 32-byte encryption key
        nonce: 12-byte nonce used for encryption
        ciphertext_with_tag: Encrypted data with authentication tag
        associated_data: Additional authenticated data
        
    Returns:
        Decrypted plaintext
        
    Raises:
        EncryptionError: If decryption or authentication fails
    """
    try:
        if len(key) != 32:
            raise EncryptionError("Encryption key must be 32 bytes")
            
        if len(nonce) != 12:
            raise EncryptionError("Nonce must be 12 bytes for GCM")
            
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Decrypt and verify authentication
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        
        return plaintext
        
    except InvalidTag:
        raise EncryptionError("Authentication verification failed - message may be tampered")
    except Exception as e:
        raise EncryptionError(f"Decryption failed: {str(e)}")


def get_auth_tag(ciphertext_with_tag: bytes) -> bytes:
    """
    Extract the GCM authentication tag from ciphertext.
    
    Args:
        ciphertext_with_tag: Encrypted data with 16-byte tag appended
        
    Returns:
        16-byte authentication tag
    """
    if len(ciphertext_with_tag) < 16:
        raise EncryptionError("Ciphertext too short to contain authentication tag")
    
    return ciphertext_with_tag[-16:]


def get_ciphertext_only(ciphertext_with_tag: bytes) -> bytes:
    """
    Extract just the ciphertext without the authentication tag.
    
    Args:
        ciphertext_with_tag: Encrypted data with 16-byte tag appended
        
    Returns:
        Ciphertext without the authentication tag
    """
    if len(ciphertext_with_tag) < 16:
        raise EncryptionError("Ciphertext too short to contain authentication tag")
    
    return ciphertext_with_tag[:-16]
