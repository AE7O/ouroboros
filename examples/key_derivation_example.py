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

# Add the source directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

from ouroboros.crypto.kdf import derive_session_keys, generate_root_key, verify_key_chain_integrity


def main():
    print("Ouroboros Protocol - Key Derivation Example")
    print("=" * 50)
    
    # Generate a root key
    print("1. Generating root key...")
    root_key = generate_root_key()
    print(f"   Root key: {root_key.hex()}")
    
    # Derive keys for first 5 messages
    print("\n2. Deriving session keys for first 5 messages...")
    key_chain = []
    prev_enc, prev_scr = None, None
    
    for i in range(5):
        enc_key, scr_key = derive_session_keys(root_key, i, prev_enc, prev_scr)
        key_chain.append((enc_key, scr_key))
        
        print(f"   Message {i}:")
        print(f"     Encryption key: {enc_key.hex()}")
        print(f"     Scrambling key: {scr_key.hex()}")
        
        prev_enc, prev_scr = enc_key, scr_key
    
    # Verify key chain integrity
    print("\n3. Verifying key chain integrity...")
    is_valid = verify_key_chain_integrity(root_key, key_chain, 4)
    print(f"   Key chain is valid: {is_valid}")
    
    # Demonstrate forward secrecy
    print("\n4. Demonstrating forward secrecy...")
    print("   Each key is derived from the previous, ensuring forward secrecy.")
    print("   Compromise of any key doesn't reveal previous keys in the chain.")
    
    print("\nExample completed successfully!")


if __name__ == "__main__":
    main()
