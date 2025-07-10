"""
Test suite for Ouroboros Protocol cryptographic functions.
"""

import pytest
import os
from ouroboros.crypto.kdf import (
    derive_session_keys, 
    generate_root_key,
    verify_key_chain_integrity,
    KeyDerivationError,
    KEY_LENGTH
)


class TestKeyDerivation:
    """Test key derivation functions."""
    
    def test_generate_root_key(self):
        """Test root key generation."""
        key = generate_root_key()
        assert len(key) == KEY_LENGTH
        assert isinstance(key, bytes)
        
        # Generate another key and ensure they're different
        key2 = generate_root_key()
        assert key != key2
    
    def test_derive_first_session_keys(self):
        """Test deriving the first session keys from root key."""
        root_key = generate_root_key()
        
        enc_key, scr_key = derive_session_keys(root_key, 0)
        
        assert len(enc_key) == KEY_LENGTH
        assert len(scr_key) == KEY_LENGTH
        assert enc_key != scr_key  # Should be different
        assert isinstance(enc_key, bytes)
        assert isinstance(scr_key, bytes)
    
    def test_derive_subsequent_session_keys(self):
        """Test deriving subsequent session keys from previous keys."""
        root_key = generate_root_key()
        
        # First keys
        enc_key_0, scr_key_0 = derive_session_keys(root_key, 0)
        
        # Second keys
        enc_key_1, scr_key_1 = derive_session_keys(
            root_key, 1, enc_key_0, scr_key_0
        )
        
        assert len(enc_key_1) == KEY_LENGTH
        assert len(scr_key_1) == KEY_LENGTH
        assert enc_key_1 != enc_key_0  # Should be different from previous
        assert scr_key_1 != scr_key_0
        assert enc_key_1 != scr_key_1  # Should be different from each other
    
    def test_deterministic_derivation(self):
        """Test that key derivation is deterministic."""
        root_key = generate_root_key()
        
        # Derive same keys twice
        enc_key_1a, scr_key_1a = derive_session_keys(root_key, 0)
        enc_key_1b, scr_key_1b = derive_session_keys(root_key, 0)
        
        assert enc_key_1a == enc_key_1b
        assert scr_key_1a == scr_key_1b
    
    def test_key_chain_forward_secrecy(self):
        """Test that keys in chain are different."""
        root_key = generate_root_key()
        
        keys = []
        prev_enc, prev_scr = None, None
        
        for i in range(5):
            enc, scr = derive_session_keys(root_key, i, prev_enc, prev_scr)
            keys.append((enc, scr))
            prev_enc, prev_scr = enc, scr
        
        # All keys should be unique
        all_keys = [k for pair in keys for k in pair]
        assert len(set(all_keys)) == len(all_keys)
    
    def test_invalid_root_key_length(self):
        """Test error handling for invalid root key length."""
        with pytest.raises(KeyDerivationError):
            derive_session_keys(b"short", 0)
        
        with pytest.raises(KeyDerivationError):
            derive_session_keys(b"x" * 33, 0)  # Too long
    
    def test_negative_counter(self):
        """Test error handling for negative counter."""
        root_key = generate_root_key()
        
        with pytest.raises(KeyDerivationError):
            derive_session_keys(root_key, -1)
    
    def test_missing_previous_keys(self):
        """Test error handling when previous keys are missing."""
        root_key = generate_root_key()
        
        with pytest.raises(KeyDerivationError):
            derive_session_keys(root_key, 1)  # Missing previous keys
    
    def test_verify_key_chain_integrity(self):
        """Test key chain integrity verification."""
        root_key = generate_root_key()
        
        # Generate a valid key chain
        key_chain = []
        prev_enc, prev_scr = None, None
        
        for i in range(3):
            enc, scr = derive_session_keys(root_key, i, prev_enc, prev_scr)
            key_chain.append((enc, scr))
            prev_enc, prev_scr = enc, scr
        
        # Should verify as valid
        assert verify_key_chain_integrity(root_key, key_chain, 2)
        
        # Corrupt a key and check it fails
        corrupted_chain = key_chain.copy()
        corrupted_chain[1] = (os.urandom(32), os.urandom(32))
        assert not verify_key_chain_integrity(root_key, corrupted_chain, 2)
