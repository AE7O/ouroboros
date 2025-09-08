"""
Cryptographic primitives for the Ouroboros Protocol.

This module provides the core cryptographic functions including:
- Key derivation (HKDF)
- Authenticated encryption (AES-GCM)
- Data scrambling
"""

from .kdf import derive_session_keys, KeyDerivationError
from .aead import quick_encrypt as encrypt_message, quick_decrypt as decrypt_message, AEADDecryptionError as EncryptionError
from .scramble import scramble_data, unscramble_data

__all__ = [
    'derive_session_keys',
    'encrypt_message', 
    'decrypt_message',
    'scramble_data',
    'unscramble_data',
    'KeyDerivationError',
    'EncryptionError'
]
