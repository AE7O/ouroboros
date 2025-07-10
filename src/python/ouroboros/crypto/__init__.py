"""
Cryptographic primitives for the Ouroboros Protocol.

This module provides the core cryptographic functions including:
- Key derivation (HKDF)
- Authenticated encryption (AES-GCM)
- Data scrambling
"""

from .kdf import derive_session_keys, KeyDerivationError
from .aes_gcm import encrypt_message, decrypt_message, EncryptionError
from .scramble import scramble_data, unscramble_data, ScramblingError

__all__ = [
    'derive_session_keys',
    'encrypt_message', 
    'decrypt_message',
    'scramble_data',
    'unscramble_data',
    'KeyDerivationError',
    'EncryptionError', 
    'ScramblingError'
]
