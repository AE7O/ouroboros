#!/usr/bin/env python3
"""
Simple test example to verify the Ouroboros crypto implementation.
"""

import sys
import os

# Add the current directory to Python path so we can import ouroboros
sys.path.insert(0, os.path.dirname(__file__))

from ouroboros.crypto.kdf import derive_session_keys, generate_root_key
from ouroboros.crypto.aes_gcm import encrypt_message, decrypt_message
from ouroboros.crypto.scramble import scramble_data, unscramble_data, test_scrambling_roundtrip
from ouroboros.protocol.packet import OuroborosPacket, PacketType
from ouroboros.utils.counter import CounterManager


def test_key_derivation():
    """Test the key derivation functionality."""
    print("🔑 Testing Key Derivation...")
    
    # Generate a root key
    root_key = generate_root_key()
    print(f"   Generated root key: {len(root_key)} bytes")
    
    # Derive first session keys
    enc_key_0, scr_key_0 = derive_session_keys(root_key, 0)
    print(f"   First encryption key: {enc_key_0[:8].hex()}...")
    print(f"   First scrambling key: {scr_key_0[:8].hex()}...")
    
    # Derive second session keys
    enc_key_1, scr_key_1 = derive_session_keys(root_key, 1, enc_key_0, scr_key_0)
    print(f"   Second encryption key: {enc_key_1[:8].hex()}...")
    print(f"   Second scrambling key: {scr_key_1[:8].hex()}...")
    
    # Verify they're all different
    assert enc_key_0 != enc_key_1, "Encryption keys should be different"
    assert scr_key_0 != scr_key_1, "Scrambling keys should be different"
    assert enc_key_0 != scr_key_0, "Enc and scr keys should be different"
    
    print("   ✅ Key derivation working correctly!")
    return root_key, enc_key_0, scr_key_0


def test_encryption():
    """Test the AES-GCM encryption functionality."""
    print("\n🔒 Testing AES-GCM Encryption...")
    
    # Generate a key and test data
    root_key = generate_root_key()
    enc_key, _ = derive_session_keys(root_key, 0)
    
    test_message = b"Hello, Ouroboros Protocol! This is a test message."
    print(f"   Original message: {test_message.decode()}")
    
    # Encrypt the message
    nonce, ciphertext_with_tag = encrypt_message(enc_key, test_message)
    print(f"   Encrypted {len(test_message)} bytes -> {len(ciphertext_with_tag)} bytes")
    print(f"   Nonce: {nonce.hex()}")
    print(f"   Ciphertext: {ciphertext_with_tag[:16].hex()}...")
    
    # Decrypt the message
    decrypted = decrypt_message(enc_key, nonce, ciphertext_with_tag)
    print(f"   Decrypted message: {decrypted.decode()}")
    
    assert decrypted == test_message, "Decryption should return original message"
    print("   ✅ Encryption/decryption working correctly!")
    
    return enc_key, test_message, nonce, ciphertext_with_tag


def test_scrambling():
    """Test the data scrambling functionality."""
    print("\n🔀 Testing Data Scrambling...")
    
    # Generate a scrambling key
    root_key = generate_root_key()
    _, scr_key = derive_session_keys(root_key, 0)
    
    test_data = b"This is some test data that will be scrambled and unscrambled."
    print(f"   Original data: {test_data[:20]}...")
    
    # Scramble the data
    scrambled = scramble_data(scr_key, test_data)
    print(f"   Scrambled data: {scrambled[:20].hex()}...")
    
    # Unscramble the data
    unscrambled = unscramble_data(scr_key, scrambled)
    print(f"   Unscrambled data: {unscrambled[:20]}...")
    
    assert unscrambled == test_data, "Unscrambling should return original data"
    assert scrambled != test_data, "Scrambled data should be different from original"
    
    # Test the roundtrip test function
    assert test_scrambling_roundtrip(scr_key, test_data), "Roundtrip test should pass"
    
    print("   ✅ Scrambling/unscrambling working correctly!")


def test_packet_handling():
    """Test packet creation and serialization."""
    print("\n📦 Testing Packet Handling...")
    
    # Create a test packet
    packet = OuroborosPacket(
        packet_type=PacketType.DATA,
        counter=12345,
        scrambled_data=b"This is scrambled payload data",
        auth_tag=b"X" * 16  # Dummy auth tag
    )
    
    print(f"   Created packet: type={packet.packet_type.name}, counter={packet.counter}")
    
    # Serialize to bytes
    packet_bytes = packet.to_bytes()
    print(f"   Serialized to {len(packet_bytes)} bytes")
    
    # Deserialize back
    packet2 = OuroborosPacket.from_bytes(packet_bytes)
    print(f"   Deserialized: type={packet2.packet_type.name}, counter={packet2.counter}")
    
    assert packet.packet_type == packet2.packet_type, "Packet type should match"
    assert packet.counter == packet2.counter, "Counter should match"
    assert packet.scrambled_data == packet2.scrambled_data, "Data should match"
    assert packet.auth_tag == packet2.auth_tag, "Auth tag should match"
    
    print("   ✅ Packet serialization/deserialization working correctly!")


def test_counter_management():
    """Test message counter functionality."""
    print("\n🔢 Testing Counter Management...")
    
    counter_mgr = CounterManager()
    
    # Test send counter
    counter1 = counter_mgr.get_next_send_counter()
    counter2 = counter_mgr.get_next_send_counter()
    print(f"   Send counters: {counter1}, {counter2}")
    
    assert counter2 == counter1 + 1, "Send counter should increment"
    
    # Test receive validation
    assert counter_mgr.validate_received_counter(100), "Should accept first received counter"
    assert not counter_mgr.validate_received_counter(100), "Should reject duplicate counter"
    assert counter_mgr.validate_received_counter(101), "Should accept newer counter"
    
    stats = counter_mgr.get_stats()
    print(f"   Counter stats: {stats}")
    
    print("   ✅ Counter management working correctly!")


def main():
    """Run all tests."""
    print("🧪 Testing Ouroboros Protocol Implementation")
    print("=" * 50)
    
    try:
        test_key_derivation()
        test_encryption()
        test_scrambling()
        test_packet_handling()
        test_counter_management()
        
        print("\n🎉 All tests passed successfully!")
        print("✅ Core crypto and protocol components are working correctly!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
