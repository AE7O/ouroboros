#!/usr/bin/env python3
"""
Test the new Ouroboros symmetric protocol implementation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from ouroboros.crypto.ratchet import HashRatchet, generate_root_key
from ouroboros.crypto.aead import AEADCipher
from ouroboros.protocol.packet import OuroborosPacket
from ouroboros.protocol.encryptor import OuroborosEncryptor
from ouroboros.protocol.decryptor import OuroborosDecryptor
from ouroboros.protocol.window import SlidingWindow


def test_new_packet_format():
    """Test the new packet format."""
    print("Testing new packet format...")
    
    # Create a test packet
    packet = OuroborosPacket(
        channel_id=42,
        counter=12345,
        r=67890,
        auth_tag=b'\x01' * 16,
        scrambled_data=b"Hello, World!"
    )
    
    # Serialize and deserialize
    packet_bytes = packet.to_bytes()
    packet2 = OuroborosPacket.from_bytes(packet_bytes)
    
    assert packet.channel_id == packet2.channel_id
    assert packet.counter == packet2.counter
    assert packet.r == packet2.r
    assert packet.auth_tag == packet2.auth_tag
    assert packet.scrambled_data == packet2.scrambled_data
    
    print(f"✓ Packet roundtrip successful: {len(packet_bytes)} bytes")


def test_hash_ratchet():
    """Test hash-based key ratcheting."""
    print("Testing hash ratchet...")
    
    root_key = generate_root_key()
    ratchet = HashRatchet(root_key)
    
    # Derive keys for multiple counters
    keys = []
    for i in range(5):
        enc_key, scr_key = ratchet.derive_keys(i)
        keys.append((enc_key, scr_key))
        assert len(enc_key) == 32
        assert len(scr_key) == 32
    
    # Ensure all keys are different
    for i in range(5):
        for j in range(i + 1, 5):
            assert keys[i][0] != keys[j][0], f"Encryption keys {i} and {j} are identical"
            assert keys[i][1] != keys[j][1], f"Scrambling keys {i} and {j} are identical"
    
    print("✓ Hash ratcheting working correctly")


def test_aead_cipher():
    """Test AEAD cipher interface."""
    print("Testing AEAD cipher...")
    
    cipher = AEADCipher(AEADCipher.AES_GCM)
    key = generate_root_key()
    nonce = os.urandom(cipher.nonce_length)
    plaintext = b"Secret message"
    
    ciphertext_with_tag = cipher.encrypt(key, nonce, plaintext)
    decrypted = cipher.decrypt(key, nonce, ciphertext_with_tag)
    
    assert decrypted == plaintext
    print("✓ AEAD encryption/decryption working")


def test_sliding_window():
    """Test sliding window replay protection."""
    print("Testing sliding window...")
    
    window = SlidingWindow(window_size=10)
    
    # Test in-order acceptance
    for i in range(5):
        assert window.accept_counter(i), f"Failed to accept counter {i}"
    
    # Test replay detection
    assert not window.accept_counter(2), "Replay not detected"
    
    # Test out-of-order within window
    assert window.accept_counter(8), "Failed to accept out-of-order counter"
    assert window.accept_counter(6), "Failed to accept back-fill counter"
    
    # Test window advancement
    assert window.accept_counter(15), "Failed to accept future counter"
    assert not window.accept_counter(5), "Old counter not rejected"
    
    print("✓ Sliding window working correctly")


def test_encryption_decryption_pipeline():
    """Test complete encryption/decryption pipeline."""
    print("Testing encryption/decryption pipeline...")
    
    root_key = generate_root_key()
    channel_id = 123
    plaintext = b"This is a test message for the new Ouroboros protocol!"
    
    # Create encryptor and decryptor
    encryptor = OuroborosEncryptor(root_key, channel_id, use_ratcheting=False)
    decryptor = OuroborosDecryptor(root_key, channel_id, use_ratcheting=False)
    
    # Encrypt message
    packet = encryptor.encrypt_message(plaintext)
    
    # Verify packet structure
    assert packet.channel_id == channel_id
    assert packet.counter == 0  # First message
    assert len(packet.auth_tag) == 16
    assert len(packet.scrambled_data) > 0
    
    # Decrypt message
    decrypted = decryptor.decrypt_packet(packet)
    assert decrypted == plaintext
    
    print("✓ Encryption/decryption pipeline working")


def test_multiple_messages():
    """Test multiple message encryption/decryption."""
    print("Testing multiple messages...")
    
    root_key = generate_root_key()
    channel_id = 42
    
    encryptor = OuroborosEncryptor(root_key, channel_id, use_ratcheting=False)
    decryptor = OuroborosDecryptor(root_key, channel_id, use_ratcheting=False)
    
    messages = [
        b"First message",
        b"Second message",
        b"Third message with more content",
        b"Fourth message",
        b"Final message"
    ]
    
    packets = []
    for i, msg in enumerate(messages):
        packet = encryptor.encrypt_message(msg)
        packets.append(packet)
        assert packet.counter == i
    
    # Decrypt in order
    for i, (packet, original_msg) in enumerate(zip(packets, messages)):
        decrypted = decryptor.decrypt_packet(packet)
        assert decrypted == original_msg, f"Message {i} mismatch"
    
    print("✓ Multiple messages working correctly")


def main():
    """Run all tests."""
    print("🧪 Testing New Ouroboros Symmetric Protocol Implementation")
    print("=" * 60)
    
    try:
        test_new_packet_format()
        test_hash_ratchet()
        test_aead_cipher()
        test_sliding_window()
        test_encryption_decryption_pipeline()
        test_multiple_messages()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed! New protocol implementation working correctly.")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)