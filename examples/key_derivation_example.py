#!/usr/bin/env python3
"""
Simple example demonstrating Ouroboros Protocol key derivation.

This example shows how to:
1. Generate a root key
2. Derive session keys for multiple messages
3. Verify the key chain integrity
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ouroboros.crypto.kdf import derive_session_keys, generate_root_key, verify_key_chain_integrity


def main():
    print("🔑 Key Derivation Module - Example & Test")
    print("=" * 50)
    
    try:
        # Test 1: Generate a root key
        print("1. Testing root key generation...")
        root_key = generate_root_key()
        assert len(root_key) == 32, "Root key must be 32 bytes"
        print(f"   ✅ Root key generated: {root_key.hex()}")
        
        # Test 2: Derive session keys for multiple messages
        print("\n2. Testing session key derivation chain...")
        key_chain = []
        prev_enc, prev_scr = None, None
        
        for i in range(5):
            enc_key, scr_key = derive_session_keys(root_key, i, prev_enc, prev_scr)
            
            # Validate key properties
            assert len(enc_key) == 32, f"Encryption key {i} must be 32 bytes"
            assert len(scr_key) == 32, f"Scrambling key {i} must be 32 bytes"
            assert enc_key != scr_key, f"Keys {i} must be different from each other"
            
            if i > 0:
                prev_enc_key, prev_scr_key = key_chain[i-1]
                assert enc_key != prev_enc_key, f"Encryption key {i} must differ from previous"
                assert scr_key != prev_scr_key, f"Scrambling key {i} must differ from previous"
            
            key_chain.append((enc_key, scr_key))
            
            print(f"   Message {i}:")
            print(f"     Encryption key: {enc_key[:8].hex()}...")
            print(f"     Scrambling key: {scr_key[:8].hex()}...")
            
            prev_enc, prev_scr = enc_key, scr_key
        
        print("   ✅ All session keys derived successfully")
        
        # Test 3: Verify key chain integrity
        print("\n3. Testing key chain integrity verification...")
        is_valid = verify_key_chain_integrity(root_key, key_chain, 4)
        assert is_valid, "Key chain integrity verification failed"
        print(f"   ✅ Key chain integrity verified: {is_valid}")
        
        # Test 4: Test deterministic derivation
        print("\n4. Testing deterministic key derivation...")
        enc_key_2a, scr_key_2a = derive_session_keys(root_key, 2, key_chain[1][0], key_chain[1][1])
        enc_key_2b, scr_key_2b = derive_session_keys(root_key, 2, key_chain[1][0], key_chain[1][1])
        
        assert enc_key_2a == enc_key_2b, "Encryption key derivation must be deterministic"
        assert scr_key_2a == scr_key_2b, "Scrambling key derivation must be deterministic"
        assert enc_key_2a == key_chain[2][0], "Derived key must match chain key"
        print("   ✅ Key derivation is deterministic")
        
        # Test 5: Test error handling
        print("\n5. Testing error handling...")
        try:
            derive_session_keys(b"short", 0)  # Invalid root key length
            assert False, "Should have raised error for short key"
        except Exception:
            print("   ✅ Correctly rejects invalid root key length")
        
        try:
            derive_session_keys(root_key, 1)  # Missing previous keys
            assert False, "Should have raised error for missing previous keys"
        except Exception:
            print("   ✅ Correctly requires previous keys for counter > 0")
        
        print("\n🎉 All key derivation tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Key derivation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
