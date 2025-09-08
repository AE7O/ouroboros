"""
AEAD (Authenticated Encryption with Associated Data) implementation.

This module provides AEAD encryption and decryption using either AES-256-GCM
for hardware-accelerated environments or ASCON-AEAD128 for lightweight IoT devices.

Uses the official pyascon implementation aligned with NIST SP 800-232.
"""

import struct
from typing import Tuple, Optional

# Standard cryptography library for AES-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Try to import ASCON for lightweight environments
try:
    import pyascon as ascon
    ASCON_AVAILABLE = True
except ImportError:
    ASCON_AVAILABLE = False

from .utils import SecureBytes


class AEADCipher:
    """
    AEAD cipher interface supporting both AES-256-GCM and ASCON-AEAD128.
    """
    
    def __init__(self, use_ascon: bool = False):
        """
        Initialize AEAD cipher.
        
        Args:
            use_ascon: If True, use ASCON-AEAD128; otherwise use AES-256-GCM
        """
        self.use_ascon = use_ascon and ASCON_AVAILABLE
        
        if self.use_ascon and not ASCON_AVAILABLE:
            raise RuntimeError("ASCON not available, install ascon package or use AES-GCM")
    
    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, 
                associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with AEAD.
        
        Args:
            key: Encryption key (32 bytes for AES-256, 16 bytes for ASCON-AEAD128)
            nonce: Nonce (12 bytes for AES-GCM, 16 bytes for ASCON-AEAD128)
            plaintext: Data to encrypt
            associated_data: Additional authenticated data (optional)
            
        Returns:
            Tuple of (ciphertext, authentication_tag)
        """
        if self.use_ascon:
            return self._encrypt_ascon(key, nonce, plaintext, associated_data)
        else:
            return self._encrypt_aes_gcm(key, nonce, plaintext, associated_data)
    
    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext with AEAD.
        
        Args:
            key: Decryption key
            nonce: Nonce used for encryption
            ciphertext: Encrypted data
            tag: Authentication tag
            associated_data: Additional authenticated data (optional)
            
        Returns:
            Decrypted plaintext
            
        Raises:
            AEADDecryptionError: If authentication fails
        """
        if self.use_ascon:
            return self._decrypt_ascon(key, nonce, ciphertext, tag, associated_data)
        else:
            return self._decrypt_aes_gcm(key, nonce, ciphertext, tag, associated_data)
    
    def _encrypt_aes_gcm(self, key: bytes, nonce: bytes, plaintext: bytes,
                        associated_data: Optional[bytes]) -> Tuple[bytes, bytes]:
        """Encrypt using AES-256-GCM."""
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires 32-byte key")
        if len(nonce) != 12:
            raise ValueError("AES-GCM requires 12-byte nonce")
        
        aesgcm = AESGCM(key)
        
        # AES-GCM returns ciphertext with tag appended
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Split ciphertext and tag (tag is last 16 bytes)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        return ciphertext, tag
    
    def _decrypt_aes_gcm(self, key: bytes, nonce: bytes, ciphertext: bytes, 
                        tag: bytes, associated_data: Optional[bytes]) -> bytes:
        """Decrypt using AES-256-GCM."""
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires 32-byte key")
        if len(nonce) != 12:
            raise ValueError("AES-GCM requires 12-byte nonce")
        if len(tag) != 16:
            raise ValueError("AES-GCM requires 16-byte tag")
        
        aesgcm = AESGCM(key)
        
        # Reconstruct ciphertext with tag for decryption
        ciphertext_with_tag = ciphertext + tag
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
            return plaintext
        except Exception as e:
            raise AEADDecryptionError("AES-GCM decryption failed") from e
    
    def _encrypt_ascon(self, key: bytes, nonce: bytes, plaintext: bytes,
                      associated_data: Optional[bytes]) -> Tuple[bytes, bytes]:
        """Encrypt using ASCON-AEAD128."""
        if not ASCON_AVAILABLE:
            raise RuntimeError("ASCON not available")
        
        # ASCON-AEAD128 uses 16-byte key and 16-byte nonce
        if len(key) == 32:
            # Truncate 32-byte key to 16 bytes for ASCON
            key = key[:16]
        elif len(key) != 16:
            raise ValueError("ASCON-AEAD128 requires 16-byte key")
        
        if len(nonce) == 12:
            # Pad 12-byte nonce to 16 bytes for ASCON
            nonce = nonce + b'\x00' * 4
        elif len(nonce) != 16:
            raise ValueError("ASCON-AEAD128 requires 16-byte nonce")
        
        # pyascon.ascon_encrypt returns ciphertext with tag appended
        try:
            ciphertext_with_tag = ascon.ascon_encrypt(
                key, nonce, associated_data or b"", plaintext,
                variant="Ascon-AEAD128"
            )
            
            # Split ciphertext and tag (tag is last 16 bytes)
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]
            return ciphertext, tag
        except Exception as e:
            raise RuntimeError("ASCON-AEAD128 encryption failed") from e
    
    def _decrypt_ascon(self, key: bytes, nonce: bytes, ciphertext: bytes,
                      tag: bytes, associated_data: Optional[bytes]) -> bytes:
        """Decrypt using ASCON-AEAD128."""
        if not ASCON_AVAILABLE:
            raise RuntimeError("ASCON not available")
        
        # ASCON-AEAD128 uses 16-byte key and 16-byte nonce
        if len(key) == 32:
            # Truncate 32-byte key to 16 bytes for ASCON
            key = key[:16]
        elif len(key) != 16:
            raise ValueError("ASCON-AEAD128 requires 16-byte key")
        
        if len(nonce) == 12:
            # Pad 12-byte nonce to 16 bytes for ASCON
            nonce = nonce + b'\x00' * 4
        elif len(nonce) != 16:
            raise ValueError("ASCON-AEAD128 requires 16-byte nonce")
        
        if len(tag) != 16:
            raise ValueError("ASCON-AEAD128 requires 16-byte tag")
        
        try:
            # pyascon.ascon_decrypt expects ciphertext with tag appended
            ciphertext_with_tag = ciphertext + tag
            plaintext = ascon.ascon_decrypt(
                key, nonce, associated_data or b"", ciphertext_with_tag,
                variant="Ascon-AEAD128"
            )
            return plaintext
        except Exception as e:
            raise AEADDecryptionError("ASCON-AEAD128 decryption failed") from e
    
    @property
    def algorithm_name(self) -> str:
        """Get the name of the current algorithm."""
        return "ASCON-AEAD128" if self.use_ascon else "AES-256-GCM"
    
    @property
    def key_size(self) -> int:
        """Get the required key size in bytes."""
        return 16 if self.use_ascon else 32
    
    @property
    def nonce_size(self) -> int:
        """Get the required nonce size in bytes."""
        return 16 if self.use_ascon else 12
    
    @property
    def tag_size(self) -> int:
        """Get the authentication tag size in bytes."""
        return 16  # Both algorithms use 16-byte tags


class AEADDecryptionError(Exception):
    """Exception raised when AEAD decryption fails."""
    pass


def create_aead_cipher(use_ascon: bool = False) -> AEADCipher:
    """
    Create an AEAD cipher instance.
    
    Args:
        use_ascon: If True, use ASCON-AEAD128; otherwise use AES-256-GCM
        
    Returns:
        AEADCipher instance
    """
    return AEADCipher(use_ascon=use_ascon)


def quick_encrypt(key: bytes, nonce: bytes, plaintext: bytes, 
                 use_ascon: bool = False) -> Tuple[bytes, bytes]:
    """
    Quick encryption function for simple use cases.
    
    Args:
        key: Encryption key
        nonce: Nonce
        plaintext: Data to encrypt
        use_ascon: Whether to use ASCON instead of AES-GCM
        
    Returns:
        Tuple of (ciphertext, tag)
    """
    cipher = create_aead_cipher(use_ascon)
    return cipher.encrypt(key, nonce, plaintext)


def quick_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                 use_ascon: bool = False) -> bytes:
    """
    Quick decryption function for simple use cases.
    
    Args:
        key: Decryption key
        nonce: Nonce used for encryption
        ciphertext: Encrypted data
        tag: Authentication tag
        use_ascon: Whether to use ASCON instead of AES-GCM
        
    Returns:
        Decrypted plaintext
    """
    cipher = create_aead_cipher(use_ascon)
    return cipher.decrypt(key, nonce, ciphertext, tag)
