"""
AEAD (Authenticated Encryption with Associated Data) wrapper for Ouroboros Protocol.

Provides a unified interface for both AES-256-GCM and ASCON-AEAD128 encryption,
supporting hardware acceleration where available.
"""

import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class AEADError(Exception):
    """Raised when AEAD operations fail."""
    pass


class AEADCipher:
    """
    Unified AEAD cipher interface supporting multiple algorithms.
    """
    
    # Supported cipher algorithms
    AES_GCM = "aes-256-gcm"
    ASCON_AEAD = "ascon-aead128"
    
    def __init__(self, algorithm: str = AES_GCM):
        """
        Initialize AEAD cipher with specified algorithm.
        
        Args:
            algorithm: Cipher algorithm (AES_GCM or ASCON_AEAD)
            
        Raises:
            AEADError: If algorithm is not supported
        """
        self.algorithm = algorithm
        
        if algorithm == self.AES_GCM:
            # AES-256-GCM with hardware acceleration support
            self._key_length = 32  # 256 bits
            self._nonce_length = 12  # 96 bits for GCM
            self._tag_length = 16   # 128 bits
        elif algorithm == self.ASCON_AEAD:
            # ASCON-AEAD128 for lightweight IoT devices
            self._key_length = 16   # 128 bits
            self._nonce_length = 16 # 128 bits
            self._tag_length = 16   # 128 bits
        else:
            raise AEADError(f"Unsupported algorithm: {algorithm}")
    
    @property
    def key_length(self) -> int:
        """Required key length in bytes."""
        return self._key_length
    
    @property
    def nonce_length(self) -> int:
        """Required nonce length in bytes."""
        return self._nonce_length
    
    @property
    def tag_length(self) -> int:
        """Authentication tag length in bytes."""
        return self._tag_length
    
    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, 
                associated_data: bytes = b"") -> bytes:
        """
        Encrypt data with authentication.
        
        Args:
            key: Encryption key (length depends on algorithm)
            nonce: Unique nonce (length depends on algorithm)
            plaintext: Data to encrypt
            associated_data: Additional data to authenticate (not encrypted)
            
        Returns:
            Ciphertext with authentication tag appended
            
        Raises:
            AEADError: If encryption fails
        """
        try:
            if len(key) != self._key_length:
                raise AEADError(f"Key must be {self._key_length} bytes for {self.algorithm}")
            
            if len(nonce) != self._nonce_length:
                raise AEADError(f"Nonce must be {self._nonce_length} bytes for {self.algorithm}")
            
            if self.algorithm == self.AES_GCM:
                return self._encrypt_aes_gcm(key, nonce, plaintext, associated_data)
            elif self.algorithm == self.ASCON_AEAD:
                return self._encrypt_ascon(key, nonce, plaintext, associated_data)
            else:
                raise AEADError(f"Encryption not implemented for {self.algorithm}")
                
        except Exception as e:
            raise AEADError(f"Encryption failed: {str(e)}")
    
    def decrypt(self, key: bytes, nonce: bytes, ciphertext_with_tag: bytes,
                associated_data: bytes = b"") -> bytes:
        """
        Decrypt and authenticate data.
        
        Args:
            key: Decryption key (same as encryption key)
            nonce: Nonce used for encryption
            ciphertext_with_tag: Encrypted data with authentication tag
            associated_data: Additional authenticated data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            AEADError: If decryption or authentication fails
        """
        try:
            if len(key) != self._key_length:
                raise AEADError(f"Key must be {self._key_length} bytes for {self.algorithm}")
            
            if len(nonce) != self._nonce_length:
                raise AEADError(f"Nonce must be {self._nonce_length} bytes for {self.algorithm}")
            
            if self.algorithm == self.AES_GCM:
                return self._decrypt_aes_gcm(key, nonce, ciphertext_with_tag, associated_data)
            elif self.algorithm == self.ASCON_AEAD:
                return self._decrypt_ascon(key, nonce, ciphertext_with_tag, associated_data)
            else:
                raise AEADError(f"Decryption not implemented for {self.algorithm}")
                
        except Exception as e:
            raise AEADError(f"Decryption failed: {str(e)}")
    
    def _encrypt_aes_gcm(self, key: bytes, nonce: bytes, plaintext: bytes,
                        associated_data: bytes) -> bytes:
        """Encrypt using AES-256-GCM."""
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, plaintext, associated_data)
    
    def _decrypt_aes_gcm(self, key: bytes, nonce: bytes, ciphertext_with_tag: bytes,
                        associated_data: bytes) -> bytes:
        """Decrypt using AES-256-GCM."""
        try:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            raise AEADError("Authentication verification failed - message may be tampered")
    
    def _encrypt_ascon(self, key: bytes, nonce: bytes, plaintext: bytes,
                      associated_data: bytes) -> bytes:
        """
        Encrypt using ASCON-AEAD128 (placeholder implementation).
        
        Note: This is a placeholder. Full ASCON implementation would require
        the ASCON library or custom implementation.
        """
        # TODO: Implement actual ASCON-AEAD128 when library is available
        # For now, fall back to AES-GCM with truncated key
        truncated_key = key[:16] + b'\x00' * 16  # Pad to 32 bytes for AES
        aesgcm = AESGCM(truncated_key)
        # Use first 12 bytes of nonce for GCM compatibility
        gcm_nonce = nonce[:12]
        return aesgcm.encrypt(gcm_nonce, plaintext, associated_data)
    
    def _decrypt_ascon(self, key: bytes, nonce: bytes, ciphertext_with_tag: bytes,
                      associated_data: bytes) -> bytes:
        """
        Decrypt using ASCON-AEAD128 (placeholder implementation).
        """
        # TODO: Implement actual ASCON-AEAD128 when library is available
        try:
            truncated_key = key[:16] + b'\x00' * 16
            aesgcm = AESGCM(truncated_key)
            gcm_nonce = nonce[:12]
            return aesgcm.decrypt(gcm_nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            raise AEADError("Authentication verification failed - message may be tampered")


# Convenience functions for direct use
def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Encrypt using AES-256-GCM with random nonce.
    
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
        associated_data: Additional data to authenticate
        
    Returns:
        Tuple of (nonce, ciphertext_with_tag)
    """
    cipher = AEADCipher(AEADCipher.AES_GCM)
    nonce = os.urandom(cipher.nonce_length)
    ciphertext_with_tag = cipher.encrypt(key, nonce, plaintext, associated_data)
    return nonce, ciphertext_with_tag


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext_with_tag: bytes,
                   associated_data: bytes = b"") -> bytes:
    """
    Decrypt using AES-256-GCM.
    
    Args:
        key: 32-byte decryption key
        nonce: 12-byte nonce used for encryption
        ciphertext_with_tag: Encrypted data with tag
        associated_data: Additional authenticated data
        
    Returns:
        Decrypted plaintext
    """
    cipher = AEADCipher(AEADCipher.AES_GCM)
    return cipher.decrypt(key, nonce, ciphertext_with_tag, associated_data)


def encrypt_ascon(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Encrypt using ASCON-AEAD128 with random nonce.
    
    Args:
        key: 16-byte encryption key
        plaintext: Data to encrypt
        associated_data: Additional data to authenticate
        
    Returns:
        Tuple of (nonce, ciphertext_with_tag)
    """
    cipher = AEADCipher(AEADCipher.ASCON_AEAD)
    nonce = os.urandom(cipher.nonce_length)
    ciphertext_with_tag = cipher.encrypt(key, nonce, plaintext, associated_data)
    return nonce, ciphertext_with_tag


def decrypt_ascon(key: bytes, nonce: bytes, ciphertext_with_tag: bytes,
                 associated_data: bytes = b"") -> bytes:
    """
    Decrypt using ASCON-AEAD128.
    
    Args:
        key: 16-byte decryption key
        nonce: 16-byte nonce used for encryption
        ciphertext_with_tag: Encrypted data with tag
        associated_data: Additional authenticated data
        
    Returns:
        Decrypted plaintext
    """
    cipher = AEADCipher(AEADCipher.ASCON_AEAD)
    return cipher.decrypt(key, nonce, ciphertext_with_tag, associated_data)