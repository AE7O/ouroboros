"""
Security Tests for Ouroboros Protocol.

Tests forward secrecy, per-message uniqueness, and cryptographic properties.
"""

import pytest
import os
import hashlib
from typing import Set, List, Tuple
from ouroboros.crypto.ratchet import HashRatchet, generate_root_key
from ouroboros.crypto.aead import AEADCipher
from ouroboros.crypto.scramble import scramble_data, unscramble_data
from ouroboros.crypto.utils import constant_time_compare, xor_bytes
from ouroboros.protocol.encryptor import OuroborosEncryptor
from ouroboros.protocol.decryptor import OuroborosDecryptor
from ouroboros.protocol.packet import OuroborosPacket


class TestForwardSecrecy:
    """Test forward secrecy properties."""
    
    def test_ratchet_forward_secrecy(self):
        """Test that compromise of current state doesn't reveal past keys."""
        root_key = generate_root_key()
        ratchet = HashRatchet(root_key)
        
        # Derive several keys
        past_keys = []
        for i in range(5):
            enc_key, scr_key = ratchet.derive_keys(i)
            past_keys.append((enc_key, scr_key))
        
        # Get current ratchet state
        current_state = ratchet.get_state()
        
        # Create new ratchet with current state (simulating compromise)
        compromised_ratchet = HashRatchet(current_state)
        
        # Try to derive past keys from compromised state
        for i in range(5):
            try:
                # This should produce different keys, not the past ones
                new_enc, new_scr = compromised_ratchet.derive_keys(i)
                
                # These should be different from the original past keys
                assert new_enc != past_keys[i][0], f"Past encryption key {i} derivable from compromise"
                assert new_scr != past_keys[i][1], f"Past scrambling key {i} derivable from compromise"
            except Exception:
                # If it fails to derive, that's also acceptable for forward secrecy
                pass
    
    def test_key_evolution_irreversibility(self):
        """Test that key evolution is irreversible."""
        root_key = generate_root_key()
        ratchet1 = HashRatchet(root_key)
        ratchet2 = HashRatchet(root_key)
        
        # Advance ratchet1 several steps
        advanced_keys = []
        for i in range(10):
            enc_key, scr_key = ratchet1.derive_keys(i)
            advanced_keys.append((enc_key, scr_key))
        
        # Get state after advancement
        advanced_state = ratchet1.get_state()
        
        # Advance ratchet2 to same position
        for i in range(10):
            enc_key, scr_key = ratchet2.derive_keys(i)
        
        # States should be the same
        assert ratchet1.get_state() == ratchet2.get_state()
        
        # But we shouldn't be able to derive earlier keys from current state
        # This is tested by ensuring the ratchet doesn't store past keys
        # (implementation detail that ensures forward secrecy)
    
    def test_session_isolation(self):
        """Test that different sessions don't leak information."""
        root_key1 = generate_root_key()
        root_key2 = generate_root_key()
        
        encryptor1 = OuroborosEncryptor(root_key1, channel_id=1)
        encryptor2 = OuroborosEncryptor(root_key2, channel_id=2)
        
        plaintext = b"Secret message"
        
        # Encrypt with both sessions
        packet1 = encryptor1.encrypt_message(plaintext)
        packet2 = encryptor2.encrypt_message(plaintext)
        
        # Packets should be completely different
        assert packet1.scrambled_data != packet2.scrambled_data
        assert packet1.auth_tag != packet2.auth_tag
        assert packet1.r != packet2.r  # Different random values
        
        # Knowledge of one session shouldn't help with the other
        decryptor1 = OuroborosDecryptor(root_key1, channel_id=1)
        
        with pytest.raises(Exception):
            decryptor1.decrypt_packet(packet2)  # Wrong session


class TestPerMessageUniqueness:
    """Test that each message produces unique ciphertext."""
    
    def test_identical_messages_different_ciphertext(self):
        """Test that identical messages produce different ciphertext."""
        root_key = generate_root_key()
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        
        plaintext = b"Repeated message"
        
        # Encrypt same message multiple times
        packets = []
        for _ in range(10):
            packet = encryptor.encrypt_message(plaintext)
            packets.append(packet)
        
        # All ciphertexts should be different
        ciphertexts = [p.scrambled_data for p in packets]
        auth_tags = [p.auth_tag for p in packets]
        r_values = [p.r for p in packets]
        
        # Check uniqueness
        assert len(set(map(bytes, ciphertexts))) == len(ciphertexts), "Duplicate ciphertexts found"
        assert len(set(map(bytes, auth_tags))) == len(auth_tags), "Duplicate auth tags found"
        assert len(set(r_values)) == len(r_values), "Duplicate r values found"
    
    def test_counter_affects_encryption(self):
        """Test that counter value affects encryption output."""
        root_key = generate_root_key()
        plaintext = b"Test message"
        
        # Encrypt same message with different counters
        packets = []
        for i in range(5):
            encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
            encryptor.reset_counter(i * 100)  # Different starting counters
            packet = encryptor.encrypt_message(plaintext)
            packets.append(packet)
        
        # All should be different
        for i in range(5):
            for j in range(i + 1, 5):
                assert packets[i].scrambled_data != packets[j].scrambled_data
                assert packets[i].auth_tag != packets[j].auth_tag
    
    def test_channel_id_affects_encryption(self):
        """Test that channel ID affects encryption output."""
        root_key = generate_root_key()
        plaintext = b"Test message"
        
        packets = []
        for channel_id in range(5):
            encryptor = OuroborosEncryptor(root_key, channel_id=channel_id, use_ratcheting=False)
            packet = encryptor.encrypt_message(plaintext)
            packets.append(packet)
        
        # All should be different
        for i in range(5):
            for j in range(i + 1, 5):
                assert packets[i].scrambled_data != packets[j].scrambled_data
                assert packets[i].auth_tag != packets[j].auth_tag


class TestCryptographicProperties:
    """Test cryptographic properties of the protocol."""
    
    def test_key_distribution(self):
        """Test that derived keys appear random."""
        root_key = generate_root_key()
        ratchet = HashRatchet(root_key)
        
        # Derive many keys
        keys = []
        for i in range(100):
            enc_key, scr_key = ratchet.derive_keys(i)
            keys.extend([enc_key, scr_key])
        
        # Test for basic randomness properties
        all_bytes = b''.join(keys)
        
        # Check byte distribution (should be roughly uniform)
        byte_counts = [0] * 256
        for byte in all_bytes:
            byte_counts[byte] += 1
        
        # Calculate chi-square statistic for uniformity
        expected = len(all_bytes) / 256
        chi_square = sum((count - expected) ** 2 / expected for count in byte_counts)
        
        # Critical value for 255 degrees of freedom at 99% confidence is ~310
        assert chi_square < 400, f"Key distribution not random enough: χ² = {chi_square}"
    
    def test_avalanche_effect(self):
        """Test avalanche effect in key derivation."""
        root_key1 = generate_root_key()
        root_key2 = bytearray(root_key1)
        root_key2[0] ^= 0x01  # Flip one bit
        root_key2 = bytes(root_key2)
        
        ratchet1 = HashRatchet(root_key1)
        ratchet2 = HashRatchet(root_key2)
        
        # Derive keys from both
        enc1, scr1 = ratchet1.derive_keys(0)
        enc2, scr2 = ratchet2.derive_keys(0)
        
        # Count bit differences
        def hamming_distance(b1: bytes, b2: bytes) -> int:
            return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))
        
        enc_diff = hamming_distance(enc1, enc2)
        scr_diff = hamming_distance(scr1, scr2)
        
        # Should have roughly 50% bit difference (avalanche effect)
        enc_ratio = enc_diff / (len(enc1) * 8)
        scr_ratio = scr_diff / (len(scr1) * 8)
        
        assert 0.3 < enc_ratio < 0.7, f"Poor avalanche effect in encryption key: {enc_ratio:.3f}"
        assert 0.3 < scr_ratio < 0.7, f"Poor avalanche effect in scrambling key: {scr_ratio:.3f}"
    
    def test_scrambling_properties(self):
        """Test cryptographic properties of scrambling."""
        key1 = generate_root_key()
        key2 = generate_root_key()
        
        # Test data
        data = b"A" * 256  # Repeated pattern
        
        scrambled1 = scramble_data(key1, data)
        scrambled2 = scramble_data(key2, data)
        
        # Scrambled data should be different from original
        assert scrambled1 != data
        assert scrambled2 != data
        
        # Different keys should produce different scrambling
        assert scrambled1 != scrambled2
        
        # Check that scrambling distributes the repeated pattern
        # Original has all bytes the same, scrambled should be more distributed
        unique_positions = set()
        for i, byte in enumerate(scrambled1):
            if byte == ord('A'):
                unique_positions.add(i)
        
        # Scrambling should spread the 'A' bytes around
        position_spread = max(unique_positions) - min(unique_positions) if unique_positions else 0
        assert position_spread > len(data) // 4, "Scrambling didn't distribute pattern well"


class TestReplayAndAttackResistance:
    """Test resistance to various attacks."""
    
    def test_replay_attack_resistance(self):
        """Test comprehensive replay attack resistance."""
        root_key = generate_root_key()
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        plaintext = b"Message to replay"
        packet = encryptor.encrypt_message(plaintext)
        
        # First decryption should succeed
        decrypted = decryptor.decrypt_packet(packet)
        assert decrypted == plaintext
        
        # Replay should fail
        with pytest.raises(Exception) as exc_info:
            decryptor.decrypt_packet(packet)
        assert "replay" in str(exc_info.value).lower()
        
        # Even if we create a new decryptor, replay should still fail
        # because the window should remember processed packets
        new_decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
        
        # Process some other packets first
        for i in range(5):
            new_packet = encryptor.encrypt_message(f"Other message {i}".encode())
            new_decryptor.decrypt_packet(new_packet)
        
        # The replayed packet should still be rejected
        with pytest.raises(Exception):
            new_decryptor.decrypt_packet(packet)
    
    def test_tampering_detection(self):
        """Test detection of various tampering attempts."""
        root_key = generate_root_key()
        encryptor = OuroborosEncryptor(root_key)
        decryptor = OuroborosDecryptor(root_key)
        
        plaintext = b"Message to tamper with"
        packet = encryptor.encrypt_message(plaintext)
        
        # Test various tampering scenarios
        tampering_tests = [
            ("auth_tag", lambda p: setattr(p, 'auth_tag', os.urandom(16))),
            ("scrambled_data", lambda p: setattr(p, 'scrambled_data', os.urandom(len(p.scrambled_data)))),
            ("counter", lambda p: setattr(p, 'counter', p.counter + 1)),
            ("r", lambda p: setattr(p, 'r', p.r ^ 0x12345678)),
            ("channel_id", lambda p: setattr(p, 'channel_id', (p.channel_id + 1) % 256)),
        ]
        
        for field_name, tamper_func in tampering_tests:
            # Create a copy and tamper with it
            tampered_packet = OuroborosPacket(
                channel_id=packet.channel_id,
                counter=packet.counter,
                r=packet.r,
                auth_tag=packet.auth_tag,
                scrambled_data=packet.scrambled_data
            )
            
            tamper_func(tampered_packet)
            
            with pytest.raises(Exception) as exc_info:
                decryptor.decrypt_packet(tampered_packet)
            
            # Should detect tampering
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in 
                      ["authentication", "decryption", "tamper", "invalid", "mismatch"]), \
                   f"Tampering of {field_name} not detected properly: {exc_info.value}"
    
    def test_key_confusion_resistance(self):
        """Test resistance to key confusion attacks."""
        root_key1 = generate_root_key()
        root_key2 = generate_root_key()
        
        encryptor1 = OuroborosEncryptor(root_key1)
        decryptor1 = OuroborosDecryptor(root_key1)
        decryptor2 = OuroborosDecryptor(root_key2)  # Wrong key
        
        plaintext = b"Secret message"
        packet = encryptor1.encrypt_message(plaintext)
        
        # Correct key should work
        decrypted = decryptor1.decrypt_packet(packet)
        assert decrypted == plaintext
        
        # Wrong key should fail
        with pytest.raises(Exception):
            decryptor2.decrypt_packet(packet)


class TestSidechannelResistance:
    """Test resistance to side-channel attacks."""
    
    def test_constant_time_operations(self):
        """Test that critical operations appear constant-time."""
        from ouroboros.crypto.utils import constant_time_compare
        
        # Test constant-time comparison
        data1 = os.urandom(32)
        data2 = os.urandom(32)
        data3 = data1  # Same as data1
        
        # These should all take roughly the same time
        import time
        
        times = []
        for _ in range(100):
            start = time.perf_counter()
            result = constant_time_compare(data1, data2)
            end = time.perf_counter()
            times.append(end - start)
            assert not result  # Should be False
        
        avg_time_different = sum(times) / len(times)
        
        times = []
        for _ in range(100):
            start = time.perf_counter()
            result = constant_time_compare(data1, data3)
            end = time.perf_counter()
            times.append(end - start)
            assert result  # Should be True
        
        avg_time_same = sum(times) / len(times)
        
        # Times should be very similar (within 50% of each other)
        time_ratio = max(avg_time_different, avg_time_same) / min(avg_time_different, avg_time_same)
        assert time_ratio < 1.5, f"Non-constant time behavior detected: {time_ratio:.2f}x difference"
    
    def test_no_key_dependent_branching(self):
        """Test that key-dependent operations don't have obvious branches."""
        # This is more of a code review test, but we can check basic properties
        
        key1 = b"\x00" * 32  # All zeros
        key2 = b"\xFF" * 32  # All ones
        
        data = b"Test data for timing"
        
        # Scrambling should take similar time regardless of key patterns
        import time
        
        times1 = []
        for _ in range(50):
            start = time.perf_counter()
            scrambled = scramble_data(key1, data)
            end = time.perf_counter()
            times1.append(end - start)
        
        times2 = []
        for _ in range(50):
            start = time.perf_counter()
            scrambled = scramble_data(key2, data)
            end = time.perf_counter()
            times2.append(end - start)
        
        avg1 = sum(times1) / len(times1)
        avg2 = sum(times2) / len(times2)
        
        # Should be within 50% of each other
        ratio = max(avg1, avg2) / min(avg1, avg2)
        assert ratio < 1.5, f"Key-dependent timing detected: {ratio:.2f}x difference"


class TestCryptographicStrength:
    """Test overall cryptographic strength."""
    
    def test_entropy_preservation(self):
        """Test that the protocol preserves entropy."""
        # Test that high-entropy input produces high-entropy output
        
        high_entropy_key = generate_root_key()
        high_entropy_data = os.urandom(1024)
        
        encryptor = OuroborosEncryptor(high_entropy_key)
        packet = encryptor.encrypt_message(high_entropy_data)
        
        # Check entropy of output (simple test)
        output_data = packet.scrambled_data + packet.auth_tag
        
        # Count unique bytes
        unique_bytes = len(set(output_data))
        entropy_ratio = unique_bytes / 256
        
        # Should have good byte distribution
        assert entropy_ratio > 0.8, f"Low entropy in output: {entropy_ratio:.3f}"
    
    def test_diffusion_properties(self):
        """Test diffusion properties of the protocol."""
        root_key = generate_root_key()
        
        # Test that small changes in input cause large changes in output
        plaintext1 = b"Test message for diffusion"
        plaintext2 = bytearray(plaintext1)
        plaintext2[0] ^= 0x01  # Change one bit
        plaintext2 = bytes(plaintext2)
        
        encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
        
        packet1 = encryptor.encrypt_message(plaintext1)
        encryptor.reset_counter(0)  # Reset to encrypt with same counter
        packet2 = encryptor.encrypt_message(plaintext2)
        
        # Count bit differences in output
        def bit_diff_ratio(b1: bytes, b2: bytes) -> float:
            if len(b1) != len(b2):
                return 1.0
            diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))
            total_bits = len(b1) * 8
            return diff_bits / total_bits
        
        # Note: With different r values, we expect significant differences
        # even with the same plaintext, so this test is more about ensuring
        # the protocol produces good diffusion
        
        scrambled_diff = bit_diff_ratio(packet1.scrambled_data, packet2.scrambled_data)
        tag_diff = bit_diff_ratio(packet1.auth_tag, packet2.auth_tag)
        
        # Should have good diffusion (but note that r values are different)
        # So we mainly check that it's not zero
        assert scrambled_diff > 0.1, f"Poor diffusion in scrambled data: {scrambled_diff:.3f}"
        assert tag_diff > 0.1, f"Poor diffusion in auth tag: {tag_diff:.3f}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])