#!/usr/bin/env python3
"""
AES-GCM Encryption Module - Example & Test

This demonstrates and tests the AES-GCM authenticated encryption functionality
including encryption, decryption, error handling, and edge cases.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ouroboros.crypto.aes_gcm import encrypt_message, decrypt_message, get_auth_tag, get_ciphertext_only, EncryptionError
from ouroboros.crypto.kdf import generate_root_key


def main():
    print("🔒 AES-GCM Encryption Module - Example & Test")
    print("=" * 50)
    
    try:
        # Test 1: Basic encryption/decryption
        print("1. Testing basic AES-GCM encryption/decryption...")
        key = generate_root_key()  # 32-byte key
        test_message = b"Hello, Ouroboros Protocol! This is a test message for AES-GCM encryption."
        
        nonce, ciphertext_with_tag = encrypt_message(key, test_message)
        
        # Validate encryption output
        assert len(nonce) == 12, "GCM nonce must be 12 bytes"
        assert len(ciphertext_with_tag) >= len(test_message) + 16, "Ciphertext must include auth tag"
        print(f"   ✅ Encrypted {len(test_message)} bytes to {len(ciphertext_with_tag)} bytes")
        print(f"   Nonce: {nonce.hex()}")
        print(f"   Ciphertext+Tag: {ciphertext_with_tag[:16].hex()}...")
        
        # Test decryption
        decrypted = decrypt_message(key, nonce, ciphertext_with_tag)
        assert decrypted == test_message, "Decryption must return original message"
        print(f"   ✅ Decrypted message: {decrypted[:30]}...")
        
        # Test 2: Authentication tag extraction
        print("\n2. Testing authentication tag operations...")
        auth_tag = get_auth_tag(ciphertext_with_tag)
        ciphertext_only = get_ciphertext_only(ciphertext_with_tag)
        
        assert len(auth_tag) == 16, "GCM auth tag must be 16 bytes"
        assert len(ciphertext_only) == len(test_message), "Ciphertext only must match plaintext length"
        assert ciphertext_only + auth_tag == ciphertext_with_tag, "Tag extraction must be consistent"
        print(f"   ✅ Auth tag: {auth_tag.hex()}")
        print(f"   ✅ Ciphertext length: {len(ciphertext_only)} bytes")
        
        # Test 3: Different message sizes
        print("\n3. Testing various message sizes...")
        test_sizes = [0, 1, 15, 16, 17, 64, 128, 1024]
        
        for size in test_sizes:
            test_data = b'X' * size
            nonce, encrypted = encrypt_message(key, test_data)
            decrypted = decrypt_message(key, nonce, encrypted)
            assert decrypted == test_data, f"Failed for size {size}"
            print(f"   ✅ Size {size:4d}: {len(test_data)} → {len(encrypted)} → {len(decrypted)}")
        
        # Test 4: Associated data
        print("\n4. Testing associated data (AAD)...")
        associated_data = b"message_counter=12345,session_id=abcdef"
        nonce, encrypted = encrypt_message(key, test_message, associated_data)
        decrypted = decrypt_message(key, nonce, encrypted, associated_data)
        assert decrypted == test_message, "AAD decryption must work correctly"
        print(f"   ✅ Associated data authenticated: {associated_data}")
        
        # Test wrong AAD should fail
        try:
            decrypt_message(key, nonce, encrypted, b"wrong_aad")
            assert False, "Wrong AAD should cause authentication failure"
        except EncryptionError:
            print("   ✅ Correctly rejects wrong associated data")
        
        # Test 5: Error handling
        print("\n5. Testing error handling...")
        
        # Wrong key length
        try:
            encrypt_message(b"short_key", test_message)
            assert False, "Should reject wrong key length"
        except EncryptionError:
            print("   ✅ Correctly rejects wrong key length")
        
        # Wrong nonce length
        try:
            decrypt_message(key, b"short_nonce", encrypted)
            assert False, "Should reject wrong nonce length"
        except EncryptionError:
            print("   ✅ Correctly rejects wrong nonce length")
        
        # Tampered ciphertext
        try:
            tampered = bytearray(encrypted)
            tampered[0] ^= 1  # Flip one bit
            decrypt_message(key, nonce, bytes(tampered))
            assert False, "Should reject tampered ciphertext"
        except EncryptionError:
            print("   ✅ Correctly rejects tampered ciphertext")
        
        # Test 6: Key independence
        print("\n6. Testing key independence...")
        key2 = generate_root_key()
        nonce1, encrypted1 = encrypt_message(key, test_message)
        nonce2, encrypted2 = encrypt_message(key2, test_message)
        
        assert encrypted1 != encrypted2, "Different keys must produce different ciphertext"
        
        # Wrong key should fail decryption
        try:
            decrypt_message(key2, nonce1, encrypted1)
            assert False, "Wrong key should fail decryption"
        except EncryptionError:
            print("   ✅ Correctly rejects wrong decryption key")
        
        print("\n🎉 All AES-GCM encryption tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ AES-GCM encryption test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
