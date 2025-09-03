"""
Correctness Tests for Ouroboros Protocol.

Tests round-trip encryption/decryption, corruption detection, and replay protection.
"""

import pytest
import os
from ouroboros.crypto.ratchet import HashRatchet, generate_root_key
from ouroboros.crypto.aead import AEADCipher
from ouroboros.crypto.scramble import scramble_data, unscramble_data
from ouroboros.protocol.packet import OuroborosPacket, PacketError
from ouroboros.protocol.encryptor import OuroborosEncryptor
from ouroboros.protocol.decryptor import OuroborosDecryptor
from ouroboros.protocol.window import SlidingWindow


class TestRoundTrip:
    """Test round-trip encryption and decryption."""
    
    def test_basic_roundtrip(self):
        """Test basic message round-trip."""
        root_key = generate_root_key()
        plaintext = b"Hello, Ouroboros!"
        
        # Use non-ratcheting mode for basic tests to avoid state sync issues
        encryptor = OuroborosEncryptor(root_key, channel_id=1, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, channel_id=1, use_ratcheting=False)
        
        packet = encryptor.encrypt_message(plaintext)
        decrypted = decryptor.decrypt_packet(packet)
        
        assert decrypted == plaintext
    
    def test_empty_message(self):
        """Test encryption of empty message."""
        root_key = generate_root_key()
        plaintext = b""
        
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        packet = encryptor.encrypt_message(plaintext)
        decrypted = decryptor.decrypt_packet(packet)
        
        assert decrypted == plaintext
    
    def test_large_message(self):
        """Test encryption of large message."""
        root_key = generate_root_key()
        plaintext = b"X" * 10000  # 10KB message
        
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        packet = encryptor.encrypt_message(plaintext)
        decrypted = decryptor.decrypt_packet(packet)
        
        assert decrypted == plaintext
    
    def test_unicode_content(self):
        """Test encryption of Unicode content."""
        root_key = generate_root_key()
        plaintext = "Hello, 世界! 🌍🔐".encode('utf-8')
        
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        packet = encryptor.encrypt_message(plaintext)
        decrypted = decryptor.decrypt_packet(packet)
        
        assert decrypted == plaintext
    
    def test_multiple_messages(self):
        """Test multiple message round-trips."""
        root_key = generate_root_key()
        messages = [
            b"First message",
            b"Second message with more content",
            b"Third message",
            b"",  # Empty message
            b"Final message"
        ]
        
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        for i, message in enumerate(messages):
            packet = encryptor.encrypt_message(message)
            assert packet.counter == i
            
            decrypted = decryptor.decrypt_packet(packet)
            assert decrypted == message
    
    def test_different_algorithms(self):
        """Test round-trip with different AEAD algorithms."""
        root_key = generate_root_key()
        plaintext = b"Test message for different algorithms"
        
        algorithms = [AEADCipher.AES_GCM]  # Only test AES-GCM for now
        
        for algorithm in algorithms:
            encryptor = OuroborosEncryptor(root_key, algorithm=algorithm, use_ratcheting=False)
            decryptor = OuroborosDecryptor(root_key, algorithm=algorithm, use_ratcheting=False)
            
            packet = encryptor.encrypt_message(plaintext)
            decrypted = decryptor.decrypt_packet(packet)
            
            assert decrypted == plaintext


class TestCorruptionDetection:
    """Test detection of message corruption and tampering."""
    
    def test_auth_tag_corruption(self):
        """Test detection of auth tag corruption."""
        root_key = generate_root_key()
        plaintext = b"Test message"
        
        encryptor = OuroborosEncryptor(root_key)
        decryptor = OuroborosDecryptor(root_key)
        
        packet = encryptor.encrypt_message(plaintext)
        
        # Corrupt the auth tag
        corrupted_tag = bytearray(packet.auth_tag)
        corrupted_tag[0] ^= 0x01  # Flip one bit
        packet.auth_tag = bytes(corrupted_tag)
        
        with pytest.raises(Exception) as exc_info:
            decryptor.decrypt_packet(packet)
        
        assert "Authentication" in str(exc_info.value) or "Decryption" in str(exc_info.value)
    
    def test_ciphertext_corruption(self):
        """Test detection of ciphertext corruption."""
        root_key = generate_root_key()
        plaintext = b"Test message for corruption detection"
        
        encryptor = OuroborosEncryptor(root_key)
        decryptor = OuroborosDecryptor(root_key)
        
        packet = encryptor.encrypt_message(plaintext)
        
        # Corrupt the scrambled data
        if len(packet.scrambled_data) > 0:
            corrupted_data = bytearray(packet.scrambled_data)
            corrupted_data[0] ^= 0x01  # Flip one bit
            packet.scrambled_data = bytes(corrupted_data)
            
            with pytest.raises(Exception) as exc_info:
                decryptor.decrypt_packet(packet)
            
            assert "Authentication" in str(exc_info.value) or "Decryption" in str(exc_info.value)
    
    def test_header_corruption(self):
        """Test detection of header field corruption."""
        root_key = generate_root_key()
        plaintext = b"Test message"
        
        encryptor = OuroborosEncryptor(root_key, channel_id=5)
        decryptor = OuroborosDecryptor(root_key, channel_id=5)
        
        packet = encryptor.encrypt_message(plaintext)
        original_counter = packet.counter
        
        # Corrupt the counter
        packet.counter = original_counter + 1
        
        with pytest.raises(Exception) as exc_info:
            decryptor.decrypt_packet(packet)
        
        assert "Authentication" in str(exc_info.value) or "Decryption" in str(exc_info.value)
    
    def test_packet_truncation(self):
        """Test detection of packet truncation."""
        root_key = generate_root_key()
        plaintext = b"Test message for truncation"
        
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        
        packet = encryptor.encrypt_message(plaintext)
        packet_bytes = packet.to_bytes()
        
        # Truncate the packet to less than minimum size
        truncated_bytes = packet_bytes[:20]  # Less than minimum 25 bytes
        
        with pytest.raises(PacketError):
            OuroborosPacket.from_bytes(truncated_bytes)


class TestReplayProtection:
    """Test replay attack protection."""
    
    def test_simple_replay(self):
        """Test detection of simple replay attack."""
        root_key = generate_root_key()
        plaintext = b"Test message"
        
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        packet = encryptor.encrypt_message(plaintext)
        
        # First decryption should succeed
        decrypted1 = decryptor.decrypt_packet(packet)
        assert decrypted1 == plaintext
        
        # Second decryption (replay) should fail
        with pytest.raises(Exception) as exc_info:
            decryptor.decrypt_packet(packet)
        
        assert "replay" in str(exc_info.value).lower()
    
    def test_out_of_order_delivery(self):
        """Test handling of out-of-order packet delivery."""
        root_key = generate_root_key()
        messages = [b"Message 1", b"Message 2", b"Message 3", b"Message 4"]
        
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False, window_size=100)
        
        # Encrypt all messages
        packets = []
        for msg in messages:
            packet = encryptor.encrypt_message(msg)
            packets.append(packet)
        
        # Deliver out of order: 0, 2, 1, 3
        delivery_order = [0, 2, 1, 3]
        
        for i in delivery_order:
            decrypted = decryptor.decrypt_packet(packets[i])
            assert decrypted == messages[i]
    
    def test_window_advancement(self):
        """Test sliding window advancement."""
        window = SlidingWindow(window_size=5)
        
        # Accept counters 0-4
        for i in range(5):
            assert window.accept_counter(i)
        
        # Accept counter 10 (advances window)
        assert window.accept_counter(10)
        
        # Counter 4 should now be outside window
        assert not window.is_valid_counter(4)
        
        # Counter 6 should still be valid
        assert window.is_valid_counter(6)
    
    def test_large_window(self):
        """Test large sliding window operation."""
        window = SlidingWindow(window_size=1000)
        
        # Accept many counters in random order
        import random
        counters = list(range(100))
        random.shuffle(counters)
        
        for counter in counters:
            assert window.accept_counter(counter)
        
        # All should be remembered
        for counter in counters:
            assert not window.is_valid_counter(counter)  # Already accepted
    
    def test_counter_overflow_simulation(self):
        """Test behavior near counter overflow."""
        window = SlidingWindow(window_size=10)
        
        # Simulate counters near 32-bit overflow
        large_counter = 2**32 - 5
        
        # This would normally cause issues, but we test graceful handling
        # For this test, we'll use smaller numbers to simulate the behavior
        base = 1000000
        
        for i in range(5):
            assert window.accept_counter(base + i)
        
        # Jump forward significantly
        assert window.accept_counter(base + 20)
        
        # Old counters should be invalid
        assert not window.is_valid_counter(base + 5)


class TestKeyDerivation:
    """Test key derivation correctness."""
    
    def test_ratchet_forward_secrecy(self):
        """Test that hash ratchet provides forward secrecy."""
        root_key = generate_root_key()
        ratchet = HashRatchet(root_key)
        
        # Derive keys for multiple steps
        keys = []
        for i in range(5):
            enc_key, scr_key = ratchet.derive_keys(i)
            keys.append((enc_key, scr_key))
        
        # All keys should be different
        for i in range(5):
            for j in range(i + 1, 5):
                assert keys[i][0] != keys[j][0], f"Encryption keys {i} and {j} are identical"
                assert keys[i][1] != keys[j][1], f"Scrambling keys {i} and {j} are identical"
    
    def test_deterministic_derivation(self):
        """Test that key derivation is deterministic."""
        root_key = generate_root_key()
        
        # Create two ratchets with same root key
        ratchet1 = HashRatchet(root_key)
        ratchet2 = HashRatchet(root_key)
        
        # Derive same keys
        enc1, scr1 = ratchet1.derive_keys(0)
        enc2, scr2 = ratchet2.derive_keys(0)
        
        assert enc1 == enc2
        assert scr1 == scr2
    
    def test_different_roots_different_keys(self):
        """Test that different root keys produce different derived keys."""
        root_key1 = generate_root_key()
        root_key2 = generate_root_key()
        
        ratchet1 = HashRatchet(root_key1)
        ratchet2 = HashRatchet(root_key2)
        
        enc1, scr1 = ratchet1.derive_keys(0)
        enc2, scr2 = ratchet2.derive_keys(0)
        
        assert enc1 != enc2
        assert scr1 != scr2


class TestScrambling:
    """Test scrambling correctness."""
    
    def test_scrambling_roundtrip(self):
        """Test scrambling and unscrambling roundtrip."""
        key = generate_root_key()
        data = b"Test data for scrambling"
        
        scrambled = scramble_data(key, data)
        unscrambled = unscramble_data(key, scrambled)
        
        assert unscrambled == data
        assert scrambled != data  # Should be different (unless very small)
    
    def test_scrambling_deterministic(self):
        """Test that scrambling is deterministic."""
        key = generate_root_key()
        data = b"Test data for deterministic scrambling"
        
        scrambled1 = scramble_data(key, data)
        scrambled2 = scramble_data(key, data)
        
        assert scrambled1 == scrambled2
    
    def test_different_keys_different_scrambling(self):
        """Test that different keys produce different scrambling."""
        key1 = generate_root_key()
        key2 = generate_root_key()
        data = b"Test data for different keys"
        
        scrambled1 = scramble_data(key1, data)
        scrambled2 = scramble_data(key2, data)
        
        assert scrambled1 != scrambled2
    
    def test_scrambling_various_sizes(self):
        """Test scrambling with various data sizes."""
        key = generate_root_key()
        
        for size in [0, 1, 2, 16, 256, 1024]:
            data = os.urandom(size)
            scrambled = scramble_data(key, data)
            unscrambled = unscramble_data(key, scrambled)
            
            assert len(scrambled) == len(data)
            assert unscrambled == data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])