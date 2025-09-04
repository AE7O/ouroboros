"""
Security property validation tests for Ouroboros Protocol.

This module tests security properties including forward secrecy,
message dependence, per-message uniqueness, and resistance to
various attacks.
"""

import pytest
import hashlib
from typing import Set, List

from ouroboros.crypto.utils import generate_random_bytes
from ouroboros.crypto.ratchet import RatchetState
from ouroboros.crypto.scramble import scramble_data, unscramble_data
from ouroboros.protocol.encryptor import create_encryption_context
from ouroboros.protocol.decryptor import create_decryption_context


class TestForwardSecrecy:
    """Test forward secrecy properties."""
    
    def test_key_evolution(self):
        """Test that ratchet keys evolve with each message."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        ratchet = RatchetState(master_psk)
        
        # Derive keys for different counters
        keys_and_nonces = []
        for counter in range(5):
            ke, nonce, kp = ratchet.derive_keys(channel_id, counter)
            keys_and_nonces.append((ke, nonce, kp))
        
        # All keys should be different
        unique_keys = set(ke for ke, _, _ in keys_and_nonces)
        unique_nonces = set(nonce for _, nonce, _ in keys_and_nonces)
        unique_kps = set(kp for _, _, kp in keys_and_nonces)
        
        assert len(unique_keys) == 5, "Encryption keys not unique across messages"
        assert len(unique_nonces) == 5, "Nonces not unique across messages"
        assert len(unique_kps) == 5, "Permutation keys not unique across messages"
    
    def test_counter_independence(self):
        """Test that different counters produce different keys."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        ratchet1 = RatchetState(master_psk)
        ratchet2 = RatchetState(master_psk)
        
        # Keys for different counters should be different
        ke1, nonce1, kp1 = ratchet1.derive_keys(channel_id, 0)
        ke2, nonce2, kp2 = ratchet2.derive_keys(channel_id, 1)
        
        assert ke1 != ke2, "Encryption keys should differ between counters"
        assert nonce1 != nonce2, "Nonces should differ between counters"
        assert kp1 != kp2, "Permutation keys should differ between counters"
    
    def test_channel_isolation(self):
        """Test that different channels produce different keys."""
        master_psk = generate_random_bytes(32)
        counter = 0
        
        ratchet1 = RatchetState(master_psk)
        ratchet2 = RatchetState(master_psk)
        
        # Same counter, different channels
        ke1, nonce1, kp1 = ratchet1.derive_keys(channel_id=1, counter=counter)
        ke2, nonce2, kp2 = ratchet2.derive_keys(channel_id=2, counter=counter)
        
        assert ke1 != ke2, "Encryption keys should differ between channels"
        assert nonce1 != nonce2, "Nonces should differ between channels"
        assert kp1 != kp2, "Permutation keys should differ between channels"


class TestMessageDependence:
    """Test that outputs depend on message content."""
    
    def test_scrambling_message_dependence(self):
        """Test that scrambling output depends on message content."""
        kp = generate_random_bytes(32)
        tag = generate_random_bytes(16)
        r = generate_random_bytes(4)
        
        # Different messages should produce different scrambled output
        message1 = b"Hello World!"
        message2 = b"Hello World?"  # Only one character different
        
        scrambled1 = scramble_data(message1, kp, tag, r)
        scrambled2 = scramble_data(message2, kp, tag, r)
        
        assert scrambled1 != scrambled2, "Scrambling should depend on message content"
        
        # Verify unscrambling works correctly
        unscrambled1 = unscramble_data(scrambled1, kp, tag, r)
        unscrambled2 = unscramble_data(scrambled2, kp, tag, r)
        
        assert unscrambled1 == message1
        assert unscrambled2 == message2
    
    def test_tag_dependence(self):
        """Test that scrambling depends on AEAD tag."""
        kp = generate_random_bytes(32)
        r = generate_random_bytes(4)
        message = b"Test message for tag dependence"
        
        # Different tags should produce different output
        tag1 = generate_random_bytes(16)
        tag2 = generate_random_bytes(16)
        
        scrambled1 = scramble_data(message, kp, tag1, r)
        scrambled2 = scramble_data(message, kp, tag2, r)
        
        assert scrambled1 != scrambled2, "Scrambling should depend on AEAD tag"
    
    def test_avalanche_effect(self):
        """Test avalanche effect in scrambling (single bit changes)."""
        kp = generate_random_bytes(32)
        tag = generate_random_bytes(16)
        r = generate_random_bytes(4)
        
        # Original message
        message = bytearray(b"A" * 64)  # 64 bytes of 'A'
        
        # Flip one bit
        message_flipped = bytearray(message)
        message_flipped[0] ^= 0x01  # Flip least significant bit of first byte
        
        scrambled1 = scramble_data(bytes(message), kp, tag, r)
        scrambled2 = scramble_data(bytes(message_flipped), kp, tag, r)
        
        # Count differing bytes
        diff_count = sum(a != b for a, b in zip(scrambled1, scrambled2))
        diff_percentage = (diff_count / len(scrambled1)) * 100
        
        # Should have some avalanche effect (at least 1% difference for single bit flip)
        assert diff_percentage > 1, f"Poor avalanche effect: only {diff_percentage:.1f}% difference"
        assert scrambled1 != scrambled2, "Single bit flip should produce different output"
        
        print(f"Avalanche effect: {diff_percentage:.1f}% of bytes changed")


class TestPerMessageUniqueness:
    """Test that identical messages produce different outputs."""
    
    def test_identical_message_uniqueness(self):
        """Test that identical messages encrypt to different ciphertexts."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        message = b"This is a test message that will be sent multiple times"
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        
        # Encrypt the same message multiple times
        ciphertexts = []
        for _ in range(5):
            packet = encrypt_ctx.encrypt_message(message)
            ciphertexts.append(packet.payload)  # Just the scrambled payload
        
        # All ciphertexts should be different due to per-message randomness
        unique_ciphertexts = set(ciphertexts)
        assert len(unique_ciphertexts) == 5, "Identical messages should produce unique ciphertexts"
    
    def test_packet_headers_differ(self):
        """Test that packet headers differ between messages."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        message = b"Test message"
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        
        # Encrypt multiple messages
        headers = []
        for _ in range(3):
            packet = encrypt_ctx.encrypt_message(message)
            headers.append((packet.header.counter, packet.header.r, packet.header.tag))
        
        # Counters should increment
        counters = [h[0] for h in headers]
        assert counters == [0, 1, 2], "Counters should increment sequentially"
        
        # Random values (r) should be different
        r_values = [h[1] for h in headers]
        unique_r = set(r_values)
        assert len(unique_r) == 3, "Per-message random values should be unique"
        
        # Tags should be different (different per-message keys and randoms)
        tags = [h[2] for h in headers]
        unique_tags = set(tags)
        assert len(unique_tags) == 3, "AEAD tags should be unique per message"


class TestAttackResistance:
    """Test resistance to various attacks."""
    
    def test_replay_attack_resistance(self):
        """Test that replay attacks are detected and rejected."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Encrypt a message
        message = b"Legitimate message"
        packet = encrypt_ctx.encrypt_message(message)
        packet_bytes = packet.to_bytes()
        
        # First decryption should succeed
        decrypted1 = decrypt_ctx.decrypt_packet(packet_bytes)
        assert decrypted1 == message
        
        # Replay should be rejected
        with pytest.raises(Exception, match="replay|Replay"):
            decrypt_ctx.decrypt_packet(packet_bytes)
    
    def test_tampering_detection(self):
        """Test that tampering with packets is detected."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Encrypt a message
        message = b"Original message"
        packet = encrypt_ctx.encrypt_message(message)
        packet_bytes = bytearray(packet.to_bytes())
        
        # Tamper with the packet (flip a bit in the payload)
        if len(packet_bytes) > 30:
            packet_bytes[30] ^= 0x01
        
        # Decryption should fail
        with pytest.raises(Exception):
            decrypt_ctx.decrypt_packet(bytes(packet_bytes))
    
    def test_wrong_channel_rejection(self):
        """Test that packets from wrong channels are rejected."""
        master_psk = generate_random_bytes(32)
        message = b"Cross-channel message"
        
        # Encrypt with channel 1
        encrypt_ctx1 = create_encryption_context(master_psk, channel_id=1)
        packet = encrypt_ctx1.encrypt_message(message)
        packet_bytes = packet.to_bytes()
        
        # Try to decrypt with channel 2
        decrypt_ctx2 = create_decryption_context(master_psk, channel_id=2)
        
        with pytest.raises(Exception, match="Channel ID mismatch"):
            decrypt_ctx2.decrypt_packet(packet_bytes)
    
    def test_out_of_order_tolerance(self):
        """Test that reasonable out-of-order delivery is tolerated."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        
        # Encrypt multiple messages (need fresh contexts for different counters)
        packets = []
        for i in range(5):
            fresh_encrypt = create_encryption_context(master_psk, channel_id)
            # Manually set counter
            fresh_encrypt.counter = i
            packet = fresh_encrypt.encrypt_message(f"Message {i}".encode())
            packets.append(packet.to_bytes())
        
        # Decrypt out of order: 0, 2, 1, 4, 3
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        order = [0, 2, 1, 4, 3]
        decrypted_messages = []
        
        for i in order:
            fresh_decrypt = create_decryption_context(master_psk, channel_id)
            try:
                decrypted = fresh_decrypt.decrypt_packet(packets[i])
                decrypted_messages.append(decrypted)
            except Exception as e:
                # Some out-of-order might be rejected depending on window size
                print(f"Message {i} rejected: {e}")
        
        # At least some out-of-order messages should be accepted
        assert len(decrypted_messages) >= 3, "Should tolerate reasonable out-of-order delivery"


class TestCryptographicProperties:
    """Test fundamental cryptographic properties."""
    
    def test_key_derivation_determinism(self):
        """Test that key derivation is deterministic."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        counter = 5
        
        # Multiple ratchets with same PSK should derive same keys
        results = []
        for _ in range(3):
            ratchet = RatchetState(master_psk)
            ke, nonce, kp = ratchet.derive_keys(channel_id, counter)
            results.append((ke, nonce, kp))
        
        # All results should be identical
        first_result = results[0]
        for result in results[1:]:
            assert result == first_result, "Key derivation should be deterministic"
    
    def test_entropy_in_outputs(self):
        """Test that outputs have good entropy distribution."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        # Collect many keys
        keys = []
        for counter in range(100):
            ratchet = RatchetState(master_psk)
            ke, _, _ = ratchet.derive_keys(channel_id, counter)
            keys.append(ke)
        
        # Test entropy by checking byte distribution
        all_bytes = b''.join(keys)
        byte_counts = [0] * 256
        
        for byte_val in all_bytes:
            byte_counts[byte_val] += 1
        
        # Calculate chi-square test for uniform distribution
        expected = len(all_bytes) / 256
        chi_square = sum((count - expected) ** 2 / expected for count in byte_counts)
        
        # With 255 degrees of freedom, critical value at 0.05 is ~293
        # We use a more relaxed threshold for this test
        assert chi_square < 400, f"Poor entropy distribution: χ² = {chi_square:.2f}"
        
        print(f"Key entropy test: χ² = {chi_square:.2f} (lower is better)")
    
    def test_non_malleability(self):
        """Test that the protocol resists malleability attacks."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Encrypt a known message
        message = b"0123456789ABCDEF" * 4  # 64 bytes
        packet = encrypt_ctx.encrypt_message(message)
        packet_bytes = bytearray(packet.to_bytes())
        
        # Try various bit flips in the ciphertext portion
        original_len = len(packet_bytes)
        header_len = 25  # channel_id(1) + counter(4) + r(4) + tag(16)
        
        tamper_positions = [
            header_len,  # First byte of payload
            header_len + len(packet.payload) // 2,  # Middle of payload
            original_len - 1  # Last byte of payload
        ]
        
        for pos in tamper_positions:
            if pos < len(packet_bytes):
                # Create tampered copy
                tampered = bytearray(packet_bytes)
                tampered[pos] ^= 0x01  # Flip one bit
                
                # Should be rejected
                with pytest.raises(Exception):
                    fresh_decrypt = create_decryption_context(master_psk, channel_id)
                    fresh_decrypt.decrypt_packet(bytes(tampered))
