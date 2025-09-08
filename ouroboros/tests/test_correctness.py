"""
Correctness tests for Ouroboros Protocol.

Tests round-trip encryption/decryption, corruption rejection, and replay prevention.
"""

import pytest
from ..crypto.utils import generate_random_bytes
from ..crypto.ratchet import RatchetState
from ..protocol.encryptor import create_encryption_context
from ..protocol.decryptor import create_decryption_context, DecryptionError
from ..protocol.packet import create_test_packet, parse_packet


class TestCryptoCorrectness:
    """Test cryptographic correctness."""
    
    def test_ratchet_key_derivation(self):
        """Test that ratchet generates consistent keys."""
        master_psk = generate_random_bytes(32)
        
        # Create two ratchets with same PSK
        ratchet1 = RatchetState(master_psk)
        ratchet2 = RatchetState(master_psk)
        
        # They should derive the same keys for same inputs
        ke1, nonce1, kp1 = ratchet1.derive_keys(channel_id=1, counter=1)
        ke2, nonce2, kp2 = ratchet2.derive_keys(channel_id=1, counter=1)
        
        assert ke1 == ke2
        assert nonce1 == nonce2
        assert kp1 == kp2
    
    def test_ratchet_forward_secrecy(self):
        """Test that ratchet provides forward secrecy."""
        master_psk = generate_random_bytes(32)
        ratchet = RatchetState(master_psk)
        
        # Derive keys for different counters
        keys1 = ratchet.derive_keys(channel_id=1, counter=1)
        keys2 = ratchet.derive_keys(channel_id=1, counter=2)
        
        # Keys should be different
        assert keys1[0] != keys2[0]  # ke
        assert keys1[1] != keys2[1]  # nonce
        assert keys1[2] != keys2[2]  # kp
    
    def test_aead_roundtrip(self):
        """Test AEAD encryption/decryption roundtrip."""
        from ..crypto.aead import create_aead_cipher
        
        cipher = create_aead_cipher(use_ascon=False)
        
        key = generate_random_bytes(32)
        nonce = generate_random_bytes(12)
        plaintext = b"Hello, AEAD world!"
        
        # Encrypt
        ciphertext, tag = cipher.encrypt(key, nonce, plaintext)
        
        # Decrypt
        decrypted = cipher.decrypt(key, nonce, ciphertext, tag)
        
        assert decrypted == plaintext
    
    def test_scrambling_roundtrip(self):
        """Test data scrambling roundtrip."""
        from ..crypto.scramble import DataScrambler
        
        scrambler = DataScrambler()
        data = b"This is test data for scrambling"
        seed = generate_random_bytes(32)
        
        # Scramble and unscramble
        scrambled = scrambler.scramble(data, seed)
        unscrambled = scrambler.unscramble(scrambled, seed)
        
        assert unscrambled == data
        assert scrambled != data  # Should actually scramble


class TestProtocolCorrectness:
    """Test protocol-level correctness."""
    
    def test_packet_serialization(self):
        """Test packet serialization/deserialization."""
        packet = create_test_packet(
            channel_id=42,
            counter=123,
            payload=b"test payload"
        )
        
        # Serialize and deserialize
        packet_bytes = packet.to_bytes()
        parsed = parse_packet(packet_bytes)
        
        assert parsed.header.channel_id == packet.header.channel_id
        assert parsed.header.counter == packet.header.counter
        assert parsed.header.r == packet.header.r
        assert parsed.header.tag == packet.header.tag
        assert parsed.payload == packet.payload
    
    def test_encryption_decryption_roundtrip(self):
        """Test full encryption/decryption pipeline."""
        master_psk = generate_random_bytes(32)
        channel_id = 42
        plaintext = b"Hello, Ouroboros Protocol!"
        
        # Create encryption and decryption contexts
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Encrypt
        packet = encrypt_ctx.encrypt_message(plaintext)
        packet_bytes = packet.to_bytes()
        
        # Decrypt
        decrypted = decrypt_ctx.decrypt_packet(packet_bytes)
        
        assert decrypted == plaintext
    
    def test_multiple_message_roundtrip(self):
        """Test multiple messages with ratcheting."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        messages = [
            b"First message",
            b"Second message",
            b"Third message with more content"
        ]
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Encrypt all messages
        packets = []
        for msg in messages:
            packet = encrypt_ctx.encrypt_message(msg)
            packets.append(packet.to_bytes())
        
        # Decrypt all messages
        decrypted = []
        for packet_bytes in packets:
            plaintext = decrypt_ctx.decrypt_packet(packet_bytes)
            decrypted.append(plaintext)
        
        assert decrypted == messages
    
    def test_channel_isolation(self):
        """Test that different channels are isolated."""
        master_psk = generate_random_bytes(32)
        plaintext = b"Test message"
        
        # Create contexts for different channels
        encrypt_ctx1 = create_encryption_context(master_psk, channel_id=1)
        encrypt_ctx2 = create_encryption_context(master_psk, channel_id=2)
        decrypt_ctx1 = create_decryption_context(master_psk, channel_id=1)
        decrypt_ctx2 = create_decryption_context(master_psk, channel_id=2)
        
        # Encrypt with channel 1
        packet1 = encrypt_ctx1.encrypt_message(plaintext)
        packet1_bytes = packet1.to_bytes()
        
        # Should decrypt with channel 1
        decrypted1 = decrypt_ctx1.decrypt_packet(packet1_bytes)
        assert decrypted1 == plaintext
        
        # Should fail with channel 2
        with pytest.raises(DecryptionError):
            decrypt_ctx2.decrypt_packet(packet1_bytes)


class TestCorruptionRejection:
    """Test rejection of corrupted packets."""
    
    def test_header_corruption(self):
        """Test rejection of packets with corrupted headers."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Create valid packet
        packet = encrypt_ctx.encrypt_message(b"test")
        packet_bytes = bytearray(packet.to_bytes())
        
        # Corrupt header (flip bit in counter)
        packet_bytes[2] ^= 0x01
        
        # Should fail to decrypt
        with pytest.raises(DecryptionError):
            decrypt_ctx.decrypt_packet(bytes(packet_bytes))
    
    def test_payload_corruption(self):
        """Test rejection of packets with corrupted payload."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Create valid packet
        packet = encrypt_ctx.encrypt_message(b"test message")
        packet_bytes = bytearray(packet.to_bytes())
        
        # Corrupt payload (flip bit in scrambled ciphertext)
        packet_bytes[-1] ^= 0x01
        
        # Should fail to decrypt
        with pytest.raises(DecryptionError):
            decrypt_ctx.decrypt_packet(bytes(packet_bytes))
    
    def test_truncated_packet(self):
        """Test rejection of truncated packets."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Create valid packet
        packet = encrypt_ctx.encrypt_message(b"test")
        packet_bytes = packet.to_bytes()
        
        # Truncate packet
        truncated = packet_bytes[:-5]
        
        # Should fail to decrypt
        with pytest.raises(DecryptionError):
            decrypt_ctx.decrypt_packet(truncated)


class TestReplayProtection:
    """Test replay attack prevention."""
    
    def test_replay_attack_prevention(self):
        """Test that replay attacks are prevented."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Encrypt message
        packet = encrypt_ctx.encrypt_message(b"test message")
        packet_bytes = packet.to_bytes()
        
        # First decryption should succeed
        decrypted1 = decrypt_ctx.decrypt_packet(packet_bytes)
        assert decrypted1 == b"test message"
        
        # Second decryption (replay) should fail
        with pytest.raises(DecryptionError):
            decrypt_ctx.decrypt_packet(packet_bytes)
    
    def test_out_of_order_delivery(self):
        """Test that out-of-order delivery within window is allowed."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        encrypt_ctx = create_encryption_context(master_psk, channel_id)
        decrypt_ctx = create_decryption_context(master_psk, channel_id)
        
        # Encrypt multiple messages
        messages = [f"Message {i}".encode() for i in range(5)]
        packets = []
        for msg in messages:
            packet = encrypt_ctx.encrypt_message(msg)
            packets.append(packet.to_bytes())
        
        # Deliver out of order: 0, 2, 1, 4, 3
        order = [0, 2, 1, 4, 3]
        decrypted = []
        
        for i in order:
            plaintext = decrypt_ctx.decrypt_packet(packets[i])
            decrypted.append(plaintext)
        
        # Should succeed for all messages
        expected = [messages[i] for i in order]
        assert decrypted == expected
    
    def test_sliding_window_limits(self):
        """Test sliding window size limits."""
        from ..protocol.window import SlidingWindow
        
        window = SlidingWindow(window_size=4)
        
        # Fill window
        for i in range(1, 5):
            assert window.mark_received(i)
        
        # Message outside window should be rejected
        assert not window.mark_received(0)  # Too old
        
        # Advance window
        assert window.mark_received(8)  # Jump ahead
        
        # Old messages should now be rejected
        assert not window.mark_received(1)
        assert not window.mark_received(4)
        
        # Recent messages should still be accepted
        assert window.mark_received(7)
        assert window.mark_received(6)


@pytest.mark.parametrize("use_ascon", [False, True])
def test_algorithm_compatibility(use_ascon):
    """Test compatibility with both AES-GCM and ASCON."""
    master_psk = generate_random_bytes(32)
    channel_id = 1
    plaintext = b"Algorithm compatibility test"
    
    try:
        encrypt_ctx = create_encryption_context(master_psk, channel_id, use_ascon)
        decrypt_ctx = create_decryption_context(master_psk, channel_id, use_ascon)
        
        # Encrypt and decrypt
        packet = encrypt_ctx.encrypt_message(plaintext)
        packet_bytes = packet.to_bytes()
        decrypted = decrypt_ctx.decrypt_packet(packet_bytes)
        
        assert decrypted == plaintext
        
    except ImportError:
        # Skip if ASCON not available
        if use_ascon:
            pytest.skip("ASCON not available")
        else:
            raise
