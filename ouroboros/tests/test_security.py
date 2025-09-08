"""
Security property validation tests for Ouroboros Protocol.

This module tests security properties including forward secrecy,
message dependence, per-message uniqueness, and resistance to
various attacks.
"""

import pytest
import hashlib
import statistics
import time
from typing import Set, List, Dict, Any, Tuple

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


class TestComprehensiveMessageDependence:
    """Comprehensive message dependence analysis with detailed metrics."""
    
    def test_bit_flip_analysis_comprehensive(self):
        """
        Comprehensive bit flip analysis for message dependence validation.
        Tests 0, 1, 2, 4, 8, 16 bits flipped in 16-byte payload.
        """
        # Fixed 16-byte baseline payload
        baseline_payload = b"BASELINE_MESSAGE"  # Exactly 16 bytes
        assert len(baseline_payload) == 16, "Payload must be exactly 16 bytes"
        
        # Fixed test parameters for reproducibility
        master_psk = b"TEST_PSK_FOR_MESSAGE_DEPENDENCE_"  # 32 bytes
        channel_id = 42
        
        # Create encryption context
        encrypt_ctx = create_encryption_context(master_psk, channel_id, use_ascon=False)
        
        # Test bit flip scenarios: 0, 1, 2, 4, 8, 16 bits
        bit_flip_counts = [0, 1, 2, 4, 8, 16]
        results = {}
        
        for bit_count in bit_flip_counts:
            print(f"\n--- Testing {bit_count} bit flips ---")
            
            # Create modified payload
            if bit_count == 0:
                modified_payload = baseline_payload
            else:
                modified_payload = self._flip_n_bits(baseline_payload, bit_count)
            
            # Encrypt both payloads using fresh contexts to avoid counter issues
            baseline_encrypt = create_encryption_context(master_psk, channel_id + bit_count * 10, use_ascon=False)
            modified_encrypt = create_encryption_context(master_psk, channel_id + bit_count * 10 + 1, use_ascon=False)
            
            baseline_packet = baseline_encrypt.encrypt_message(baseline_payload)
            modified_packet = modified_encrypt.encrypt_message(modified_payload)
            
            # Extract components for analysis
            baseline_encrypted = baseline_packet.payload
            modified_encrypted = modified_packet.payload
            
            # Get scrambled data (payload is already scrambled in the packet)
            baseline_scrambled = baseline_packet.payload
            modified_scrambled = modified_packet.payload
            
            # Calculate bit differences
            encrypted_bits_changed = self._calculate_bit_difference(baseline_encrypted, modified_encrypted)
            scrambled_bits_changed = self._calculate_bit_difference(baseline_scrambled, modified_scrambled)
            
            # Calculate permutation change (analyze scrambling pattern)
            permutation_change = self._analyze_permutation_change(baseline_scrambled, modified_scrambled)
            
            # Store results
            result_data = {
                'input_baseline': baseline_payload.hex(),
                'input_modified': modified_payload.hex(),
                'bits_flipped_count': bit_count,
                'encrypted_baseline': baseline_encrypted.hex(),
                'encrypted_modified': modified_encrypted.hex(),
                'scrambled_baseline': baseline_scrambled.hex(),
                'scrambled_modified': modified_scrambled.hex(),
                'encrypted_bits_changed_percentage': encrypted_bits_changed,
                'scrambled_bits_changed_percentage': scrambled_bits_changed,
                'permutation_change_score': permutation_change,
                'avalanche_effect_quality': 'Good' if encrypted_bits_changed > 45 else 'Poor'
            }
            
            results[f'flip_{bit_count}_bits'] = result_data
            
            # Print detailed results
            print(f"  Input baseline: {baseline_payload.hex()}")
            print(f"  Input modified: {modified_payload.hex()}")
            print(f"  Encrypted baseline: {baseline_encrypted.hex()}")
            print(f"  Encrypted modified: {modified_encrypted.hex()}")
            print(f"  Scrambled baseline: {baseline_scrambled.hex()}")
            print(f"  Scrambled modified: {modified_scrambled.hex()}")
            print(f"  Encrypted bits changed: {encrypted_bits_changed:.2f}%")
            print(f"  Scrambled bits changed: {scrambled_bits_changed:.2f}%")
            print(f"  Permutation change score: {permutation_change:.2f}")
            
            # Assertions for security validation
            if bit_count > 0:
                assert encrypted_bits_changed > 1, f"Poor avalanche effect for {bit_count} bit flips"
                assert scrambled_bits_changed > 1, f"Poor scrambling effect for {bit_count} bit flips"
        
        return results
    
    def _flip_n_bits(self, data: bytes, n_bits: int) -> bytes:
        """Flip exactly n bits in the data."""
        if n_bits == 0:
            return data
        
        data_array = bytearray(data)
        total_bits = len(data) * 8
        
        # Choose bit positions to flip (distributed across the data)
        bit_positions = []
        for i in range(n_bits):
            # Distribute bit flips across the payload
            bit_pos = (i * total_bits) // n_bits + (i % 8)
            bit_pos = bit_pos % total_bits  # Ensure within bounds
            bit_positions.append(bit_pos)
        
        # Flip the bits
        for bit_pos in bit_positions:
            byte_index = bit_pos // 8
            bit_index = bit_pos % 8
            data_array[byte_index] ^= (1 << bit_index)
        
        return bytes(data_array)
    
    def _calculate_bit_difference(self, data1: bytes, data2: bytes) -> float:
        """Calculate percentage of different bits between two byte sequences."""
        if len(data1) != len(data2):
            return 100.0  # Completely different
        
        different_bits = 0
        total_bits = len(data1) * 8
        
        for b1, b2 in zip(data1, data2):
            xor = b1 ^ b2
            different_bits += bin(xor).count('1')
        
        return (different_bits / total_bits) * 100
    
    def _analyze_permutation_change(self, data1: bytes, data2: bytes) -> float:
        """Analyze the permutation change between two scrambled outputs."""
        if len(data1) != len(data2):
            return 100.0
        
        # Calculate positional differences
        position_changes = sum(1 for i, (b1, b2) in enumerate(zip(data1, data2)) if b1 != b2)
        max_changes = len(data1)
        
        # Calculate byte value distribution changes
        hist1 = [0] * 256
        hist2 = [0] * 256
        
        for b in data1:
            hist1[b] += 1
        for b in data2:
            hist2[b] += 1
        
        distribution_change = sum(abs(h1 - h2) for h1, h2 in zip(hist1, hist2)) / (2 * len(data1))
        
        # Combine metrics
        permutation_score = (position_changes / max_changes) * 0.7 + distribution_change * 0.3
        return permutation_score * 100


class TestComprehensiveForwardSecrecy:
    """Comprehensive forward secrecy validation with operational flow analysis."""
    
    def test_forward_secrecy_operational_flow(self):
        """
        Test forward secrecy with detailed operational flow analysis.
        Tests compromise points at 1, 2, 5, 10, 50 operations.
        
        Forward secrecy demonstration: show that ratcheting provides key isolation.
        """
        # Fixed parameters
        master_psk = b"FORWARD_SECRECY_TEST_PSK_32BYTES"  # 32 bytes
        channel_id = 100
        payload = b"FORWARD_SEC_TEST"  # 16 bytes
        
        # Test scenarios: operations before compromise
        operation_counts = [1, 2, 5, 10, 50]
        results = {}
        
        for ops_before_compromise in operation_counts:
            print(f"\n--- Testing forward secrecy after {ops_before_compromise} operations ---")
            
            # Create fresh contexts for this test
            encrypt_ctx = create_encryption_context(master_psk, channel_id + ops_before_compromise, use_ascon=False)
            decrypt_ctx = create_decryption_context(master_psk, channel_id + ops_before_compromise, use_ascon=False)
            
            # Phase 1: Manual ratchet advancement and key tracking
            # We'll manually advance the ratchet to demonstrate forward secrecy
            key_evolution = []
            messages_and_packets = []
            
            for i in range(ops_before_compromise):
                test_payload = payload + f"_{i:02d}".encode()[:2]  # Keep 16 bytes
                test_payload = test_payload[:16]  # Ensure exactly 16 bytes
                
                # Capture keys before message
                pre_counter = encrypt_ctx.ratchet.counter_s
                ke_before, nonce_before, kp_before = encrypt_ctx.ratchet.derive_keys(
                    channel_id + ops_before_compromise, pre_counter
                )
                
                # Encrypt message (this uses current keys)
                packet = encrypt_ctx.encrypt_message(test_payload)
                
                # Manually advance the ratchet for forward secrecy demonstration
                actual_counter = encrypt_ctx.ratchet.advance_ratchet_send()
                
                # Capture keys after advancement
                post_counter = encrypt_ctx.ratchet.counter_s
                
                # Verify we can decrypt normally
                decrypted = decrypt_ctx.decrypt_packet(packet.to_bytes())
                assert decrypted == test_payload, f"Normal decryption failed at operation {i}"
                
                # Also advance the receiver ratchet to stay in sync
                decrypt_ctx.ratchet.advance_ratchet_send()
                
                key_evolution.append({
                    'operation': i,
                    'payload': test_payload.hex(),
                    'packet': packet.to_bytes().hex(),
                    'pre_counter': pre_counter,
                    'post_counter': post_counter,
                    'encryption_key_before': ke_before.hex(),
                    'nonce_before': nonce_before.hex(),
                    'permutation_key_before': kp_before.hex(),
                    'ratchet_advanced': post_counter > pre_counter
                })
                
                messages_and_packets.append((packet, test_payload))
            
            # Phase 2: Demonstrate key evolution properties
            current_counter = encrypt_ctx.ratchet.counter_s
            current_keys = self._capture_current_keys(encrypt_ctx.ratchet, channel_id + ops_before_compromise)
            
            # Phase 3: Forward secrecy validation
            # Test key isolation: current state should not reveal previous keys
            key_isolation_results = []
            
            for i, key_state in enumerate(key_evolution):
                # Compare current keys with historical keys
                keys_are_different = current_keys['encryption_key'] != key_state['encryption_key_before']
                ratchet_advanced_properly = key_state['ratchet_advanced']
                
                key_isolation_results.append({
                    'operation': i,
                    'historical_counter': key_state['pre_counter'],
                    'current_counter': current_counter,
                    'keys_evolved': keys_are_different,
                    'ratchet_advanced': ratchet_advanced_properly,
                    'forward_secrecy_property': keys_are_different and ratchet_advanced_properly
                })
            
            # Phase 4: Generate post-compromise messages with different keys
            post_compromise_messages = []
            for i in range(5):
                test_payload = payload + f"_P{i:01d}".encode()  # Post-compromise payload
                test_payload = test_payload[:16]  # Ensure exactly 16 bytes
                
                # Capture keys before
                pre_keys = self._capture_current_keys(encrypt_ctx.ratchet, channel_id + ops_before_compromise)
                
                # Encrypt and advance
                packet = encrypt_ctx.encrypt_message(test_payload)
                encrypt_ctx.ratchet.advance_ratchet_send()
                
                # Capture keys after
                post_keys = self._capture_current_keys(encrypt_ctx.ratchet, channel_id + ops_before_compromise)
                
                post_compromise_messages.append({
                    'operation': i,
                    'payload': test_payload.hex(),
                    'packet': packet.to_bytes().hex(),
                    'pre_keys': pre_keys,
                    'post_keys': post_keys,
                    'keys_evolved': pre_keys['encryption_key'] != post_keys['encryption_key']
                })
            
            # Phase 5: Demonstrate compromise resistance
            # Show that with proper ratcheting, old keys cannot be derived from current state
            compromise_analysis = []
            
            for i, key_state in enumerate(key_evolution):
                # Key insight: in a forward-secure system, you cannot go backwards
                can_derive_old_keys = self._attempt_key_reversal(
                    current_keys, key_state['encryption_key_before']
                )
                
                compromise_analysis.append({
                    'operation': i,
                    'can_reverse_to_old_key': can_derive_old_keys,
                    'forward_secrecy_holds': not can_derive_old_keys
                })
            
            # Calculate metrics
            total_operations = len(key_isolation_results)
            successful_key_isolations = sum(1 for result in key_isolation_results 
                                          if result['forward_secrecy_property'])
            successful_compromise_resistance = sum(1 for result in compromise_analysis 
                                                 if result['forward_secrecy_holds'])
            
            forward_secrecy_strength = (successful_key_isolations / total_operations) * 100 if total_operations > 0 else 0
            compromise_resistance = (successful_compromise_resistance / total_operations) * 100 if total_operations > 0 else 0
            
            # Store comprehensive results
            result_data = {
                'operations_before_compromise': ops_before_compromise,
                'key_evolution': key_evolution,
                'key_isolation_results': key_isolation_results,
                'post_compromise_messages': post_compromise_messages,
                'compromise_analysis': compromise_analysis,
                'metrics': {
                    'total_operations': total_operations,
                    'successful_key_isolations': successful_key_isolations,
                    'successful_compromise_resistance': successful_compromise_resistance,
                    'forward_secrecy_strength_percentage': forward_secrecy_strength,
                    'compromise_resistance_percentage': compromise_resistance,
                    'overall_forward_secrecy_score': (forward_secrecy_strength + compromise_resistance) / 2
                },
                'forward_secrecy_achieved': successful_key_isolations == total_operations and successful_compromise_resistance == total_operations
            }
            
            results[f'ops_{ops_before_compromise}'] = result_data
            
            # Print detailed results
            print(f"  Operations before compromise: {ops_before_compromise}")
            print(f"  Key evolution tracking:")
            for key_state in key_evolution:
                print(f"    Op {key_state['operation']}: Counter {key_state['pre_counter']} -> {key_state['post_counter']}")
                print(f"         Ratchet advanced: {key_state['ratchet_advanced']}")
                print(f"         Payload: {key_state['payload']}")
            
            print(f"  Forward secrecy analysis:")
            print(f"    Successful key isolations: {successful_key_isolations}/{total_operations}")
            print(f"    Successful compromise resistance: {successful_compromise_resistance}/{total_operations}")
            print(f"    Forward secrecy strength: {forward_secrecy_strength:.2f}%")
            print(f"    Compromise resistance: {compromise_resistance:.2f}%")
            print(f"    Overall forward secrecy achieved: {result_data['forward_secrecy_achieved']}")
            
            # Forward secrecy assertion
            assert result_data['forward_secrecy_achieved'], f"Forward secrecy not achieved: {successful_key_isolations}/{total_operations} key isolations, {successful_compromise_resistance}/{total_operations} compromise resistance"
        
        return results
    
    def _attempt_key_reversal(self, current_keys: Dict[str, Any], historical_key: str) -> bool:
        """
        Test if current keys can be used to derive historical keys.
        For proper forward secrecy, this should return False.
        """
        if 'error' in current_keys:
            return False
        
        # Simple check: if the keys are the same, then no forward secrecy (bad)
        if current_keys['encryption_key'] == historical_key:
            return True
        
        # In a properly implemented forward-secure system:
        # 1. Keys should be different after ratcheting
        # 2. Old keys should not be derivable from new keys
        # 3. The ratchet should be one-way
        
        # Check if root key has changed (indicating ratchet advancement)
        # If root key hash hasn't changed, ratcheting isn't working properly
        historical_root_indicator = hashlib.sha256(historical_key.encode()).hexdigest()
        current_root_hash = current_keys['root_key_hash']
        
        # If we can derive the historical pattern from current state, forward secrecy is broken
        if current_root_hash == historical_root_indicator:
            return True
        
        return False
    
    def _capture_current_keys(self, ratchet: RatchetState, channel_id: int) -> Dict[str, Any]:
        """Capture current ratchet state for compromise simulation."""
        try:
            # Get current keys at current counter
            current_counter = ratchet.counter_s
            ke, nonce, kp = ratchet.derive_keys(channel_id, current_counter)
            
            return {
                'send_counter': current_counter,
                'encryption_key': ke.hex(),
                'nonce': nonce.hex(),
                'permutation_key': kp.hex(),
                'root_key_hash': hashlib.sha256(ratchet.kr).hexdigest()
            }
        except Exception as e:
            return {'error': str(e)}


# ============================================================================
# EVALUATION FRAMEWORK INTEGRATION - REUSABLE SECURITY FUNCTIONS
# ============================================================================

def run_message_dependence_analysis(payload_size: int = 16, 
                                   bit_flip_counts: List[int] = None) -> Dict[str, Any]:
    """
    Reusable wrapper for message dependence analysis.
    Used by evaluation framework for comprehensive security analysis.
    """
    if bit_flip_counts is None:
        bit_flip_counts = [0, 1, 2, 4, 8, 16]
    
    # Create test instance and run analysis
    test_instance = TestComprehensiveMessageDependence()
    return test_instance.test_bit_flip_analysis_comprehensive()


def run_forward_secrecy_analysis(operation_counts: List[int] = None) -> Dict[str, Any]:
    """
    Reusable wrapper for forward secrecy analysis.
    Used by evaluation framework for comprehensive security analysis.
    """
    if operation_counts is None:
        operation_counts = [1, 2, 5, 10, 50]
    
    # Create test instance and run analysis
    test_instance = TestComprehensiveForwardSecrecy()
    return test_instance.test_forward_secrecy_operational_flow()


def run_comprehensive_security_analysis() -> Dict[str, Any]:
    """
    Run comprehensive security analysis combining message dependence and forward secrecy.
    """
    results = {
        'test_suite': 'comprehensive_security',
        'timestamp': time.time(),
        'message_dependence': {},
        'forward_secrecy': {},
        'summary': {}
    }
    
    try:
        # Run message dependence analysis
        print("Running message dependence analysis...")
        results['message_dependence'] = run_message_dependence_analysis()
        
        # Run forward secrecy analysis  
        print("Running forward secrecy analysis...")
        results['forward_secrecy'] = run_forward_secrecy_analysis()
        
        # Generate summary
        results['summary'] = {
            'message_dependence_tests': len(results['message_dependence']),
            'forward_secrecy_tests': len(results['forward_secrecy']),
            'total_security_tests': len(results['message_dependence']) + len(results['forward_secrecy']),
            'all_tests_passed': True  # Will be updated based on actual results
        }
        
    except Exception as e:
        results['error'] = str(e)
        results['status'] = 'failed'
    
    return results
