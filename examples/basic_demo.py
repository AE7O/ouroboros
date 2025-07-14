#!/usr/bin/env python3
"""
Basic example demonstrating Ouroboros Protocol key derivation and cryptography.

This example shows:
1. Root key generation
2. Forward-secure key derivation chain
3. AES-GCM encryption/decryption
4. Data scrambling/unscrambling
5. Packet creation and parsing
"""

import sys
import os

# Add the ouroboros package to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ouroboros.crypto.kdf import generate_root_key, derive_session_keys
from ouroboros.crypto.aes_gcm import encrypt_message, decrypt_message
from ouroboros.crypto.scramble import scramble_data, unscramble_data
from ouroboros.protocol.packet import OuroborosPacket, PacketType
from ouroboros.utils.counter import CounterManager


def main():
    print("🐍 Ouroboros Protocol - Python Implementation Demo")
    print("=" * 60)
    
    # 1. Generate root key
    print("\n1. Generating root key...")
    root_key = generate_root_key()
    print(f"   Root key: {root_key.hex()[:32]}... ({len(root_key)} bytes)")
    
    # 2. Demonstrate key derivation chain
    print("\n2. Deriving session keys (forward-secure chain)...")
    counter_mgr = CounterManager()
    
    keys_chain = []
    prev_enc, prev_scr = None, None
    
    for i in range(3):
        counter = counter_mgr.get_next_send_counter()
        enc_key, scr_key = derive_session_keys(root_key, counter, prev_enc, prev_scr)
        keys_chain.append((enc_key, scr_key))
        
        print(f"   Message {counter}:")
        print(f"     Enc key: {enc_key.hex()[:16]}...")
        print(f"     Scr key: {scr_key.hex()[:16]}...")
        
        prev_enc, prev_scr = enc_key, scr_key
    
    # 3. Demonstrate encryption/decryption
    print("\n3. Testing AES-GCM encryption...")
    message = b"Hello from Ouroboros Protocol! This is a test message."
    print(f"   Original message: {message.decode()}")
    
    # Use first set of keys
    enc_key, scr_key = keys_chain[0]
    
    # Encrypt
    nonce, ciphertext_with_tag = encrypt_message(enc_key, message)
    print(f"   Nonce: {nonce.hex()}")
    print(f"   Ciphertext: {ciphertext_with_tag.hex()[:32]}... ({len(ciphertext_with_tag)} bytes)")
    
    # Decrypt
    decrypted = decrypt_message(enc_key, nonce, ciphertext_with_tag)
    print(f"   Decrypted: {decrypted.decode()}")
    print(f"   ✅ Encryption/decryption successful: {message == decrypted}")
    
    # 4. Demonstrate scrambling
    print("\n4. Testing data scrambling...")
    test_data = b"This data will be scrambled for additional obfuscation."
    print(f"   Original: {test_data.decode()}")
    
    # Scramble
    scrambled = scramble_data(scr_key, test_data)
    print(f"   Scrambled: {scrambled.hex()[:32]}...")
    
    # Unscramble
    unscrambled = unscramble_data(scr_key, scrambled)
    print(f"   Unscrambled: {unscrambled.decode()}")
    print(f"   ✅ Scrambling/unscrambling successful: {test_data == unscrambled}")
    
    # 5. Demonstrate packet creation
    print("\n5. Testing packet creation and parsing...")
    
    # Create a data packet
    packet = OuroborosPacket(
        packet_type=PacketType.DATA,
        counter=42,
        scrambled_data=scrambled,
        auth_tag=ciphertext_with_tag[-16:]  # Use last 16 bytes as mock auth tag
    )
    
    print(f"   Created packet:")
    print(f"     Type: {packet.packet_type.name}")
    print(f"     Counter: {packet.counter}")
    print(f"     Data length: {len(packet.scrambled_data)} bytes")
    print(f"     Auth tag: {packet.auth_tag.hex()[:16]}...")
    
    # Serialize packet
    packet_bytes = packet.to_bytes()
    print(f"   Serialized packet: {len(packet_bytes)} bytes")
    
    # Parse packet back
    parsed_packet = OuroborosPacket.from_bytes(packet_bytes)
    print(f"   Parsed packet:")
    print(f"     Type: {parsed_packet.packet_type.name}")
    print(f"     Counter: {parsed_packet.counter}")
    print(f"     Data length: {len(parsed_packet.scrambled_data)} bytes")
    
    print(f"   ✅ Packet serialization successful: {packet_bytes == parsed_packet.to_bytes()}")
    
    # 6. Test counter management
    print("\n6. Testing counter management...")
    print(f"   Current send counter: {counter_mgr.get_current_send_counter()}")
    
    # Test replay protection
    test_counters = [0, 1, 2, 1, 3, 0]  # 1 and 0 are replays
    for counter in test_counters:
        is_valid = counter_mgr.validate_received_counter(counter)
        status = "✅ VALID" if is_valid else "❌ REPLAY"
        print(f"   Counter {counter}: {status}")
    
    print(f"\n   Counter stats: {counter_mgr.get_stats()}")
    
    print("\n" + "=" * 60)
    print("🎉 All tests completed successfully!")
    print("The Ouroboros Protocol foundation is working correctly.")


if __name__ == "__main__":
    main()
