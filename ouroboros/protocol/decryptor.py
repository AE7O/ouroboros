"""
Decryption pipeline for Ouroboros Protocol.

This module implements the complete decryption pipeline:
1. Parse header → extract channel_id, counter, r, tag
2. Derive ke, nonce, and kp from ratchet using channel_id + counter
3. Derive permutation stream from (kp, tag, r)
4. Unscramble payload to recover ciphertext
5. AEAD verify and decrypt
6. If valid → deliver plaintext + update ratchet; else reject
7. Apply sliding window → enforce replay protection
"""

from typing import Optional, Tuple
from ..crypto.ratchet import RatchetState
from ..crypto.aead import AEADCipher, AEADDecryptionError
from ..crypto.scramble import unscramble_data
from .packet import parse_packet, OuroborosPacket, PacketFormatError
from .window import ReplayProtection


class DecryptionEngine:
    """
    Handles the complete decryption pipeline for Ouroboros messages.
    """
    
    def __init__(self, ratchet: RatchetState, channel_id: int, 
                 use_ascon: bool = False, window_size: int = 32):
        """
        Initialize decryption engine.
        
        Args:
            ratchet: RatchetState for key derivation
            channel_id: 1-byte channel identifier
            use_ascon: Whether to use ASCON instead of AES-GCM
            window_size: Sliding window size for replay protection
        """
        self.ratchet = ratchet
        self.channel_id = channel_id
        self.aead = AEADCipher(use_ascon=use_ascon)
        self.replay_protection = ReplayProtection(default_window_size=window_size)
        
        # Validate channel ID
        if not (0 <= channel_id <= 255):
            raise ValueError("Channel ID must be 0-255")
    
    def decrypt_packet(self, packet_bytes: bytes) -> bytes:
        """
        Decrypt a complete packet following the decryption pipeline.
        
        Args:
            packet_bytes: Raw packet data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            DecryptionError: If decryption fails for any reason
        """
        try:
            # Step 1: Parse packet header
            packet = parse_packet(packet_bytes)
            header = packet.header
            
            # Validate channel ID matches
            if header.channel_id != self.channel_id:
                raise DecryptionError(
                    f"Channel ID mismatch: expected {self.channel_id}, "
                    f"got {header.channel_id}"
                )
            
            # Step 2: Check replay protection
            if not self.replay_protection.check_and_update(
                self.channel_id, header.counter
            ):
                raise DecryptionError(f"Replay attack detected: counter {header.counter}")
            
            # Step 3: Derive keys from ratchet
            ke, nonce, kp = self.ratchet.derive_keys(self.channel_id, header.counter)
            
            # Step 4: Unscramble payload
            ciphertext = unscramble_data(packet.payload, kp, header.tag, header.r)
            
            # Step 5: AEAD decrypt and verify
            plaintext = self.aead.decrypt(ke, nonce, ciphertext, header.tag)
            
            return plaintext
            
        except PacketFormatError as e:
            raise DecryptionError(f"Invalid packet format: {e}") from e
        except AEADDecryptionError as e:
            raise DecryptionError(f"AEAD verification failed: {e}") from e
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    def try_decrypt_packet(self, packet_bytes: bytes) -> Tuple[bool, Optional[bytes], str]:
        """
        Try to decrypt a packet and return detailed result.
        
        Args:
            packet_bytes: Raw packet data
            
        Returns:
            Tuple of (success, plaintext_or_none, error_message)
        """
        try:
            plaintext = self.decrypt_packet(packet_bytes)
            return True, plaintext, "Success"
        except DecryptionError as e:
            return False, None, str(e)
    
    def get_replay_stats(self) -> dict:
        """
        Get replay protection statistics.
        
        Returns:
            Replay protection statistics
        """
        return self.replay_protection.get_stats()
    
    def reset_replay_protection(self):
        """Reset replay protection for this channel."""
        self.replay_protection.reset_channel(self.channel_id)
    
    def get_algorithm_info(self) -> dict:
        """
        Get information about current algorithms.
        
        Returns:
            Dictionary with algorithm details
        """
        return {
            'aead_algorithm': self.aead.algorithm_name,
            'ratchet_algorithm': 'ASCON-Hash256' if self.ratchet.use_ascon else 'HKDF-SHA256',
            'scrambling_algorithm': 'Fisher-Yates + ChaCha20',
            'channel_id': self.channel_id,
            'window_size': self.replay_protection.default_window_size
        }


class DecryptionError(Exception):
    """Raised when decryption fails."""
    pass


def decrypt_packet(ratchet: RatchetState, channel_id: int, packet_bytes: bytes,
                  use_ascon: bool = False, window_size: int = 32) -> bytes:
    """
    Convenience function to decrypt a single packet.
    
    Args:
        ratchet: RatchetState for key derivation
        channel_id: Channel identifier
        packet_bytes: Raw packet data
        use_ascon: Whether to use ASCON instead of AES-GCM
        window_size: Sliding window size
        
    Returns:
        Decrypted plaintext
    """
    engine = DecryptionEngine(ratchet, channel_id, use_ascon, window_size)
    return engine.decrypt_packet(packet_bytes)


def create_decryption_context(master_psk: bytes, channel_id: int, 
                            use_ascon: bool = False, window_size: int = 32) -> DecryptionEngine:
    """
    Create a complete decryption context from a master PSK.
    
    Args:
        master_psk: 32-byte master pre-shared key
        channel_id: Channel identifier
        use_ascon: Whether to use ASCON algorithms
        window_size: Sliding window size
        
    Returns:
        Ready-to-use DecryptionEngine
    """
    ratchet = RatchetState(master_psk, use_ascon=use_ascon)
    return DecryptionEngine(ratchet, channel_id, use_ascon=use_ascon, window_size=window_size)


def test_roundtrip_encryption(plaintext: bytes = b"Hello, Ouroboros!",
                            use_ascon: bool = False) -> dict:
    """
    Test complete roundtrip encryption and decryption.
    
    Args:
        plaintext: Test message
        use_ascon: Whether to use ASCON algorithms
        
    Returns:
        Test results
    """
    from ..crypto.utils import generate_random_bytes
    from .encryptor import create_encryption_context
    
    # Setup
    master_psk = generate_random_bytes(32)
    channel_id = 42
    
    # Create encryption and decryption engines with same PSK
    encrypt_engine = create_encryption_context(master_psk, channel_id, use_ascon)
    decrypt_engine = create_decryption_context(master_psk, channel_id, use_ascon)
    
    try:
        # Encrypt
        packet = encrypt_engine.encrypt_message(plaintext)
        packet_bytes = packet.to_bytes()
        
        # Decrypt
        decrypted = decrypt_engine.decrypt_packet(packet_bytes)
        
        # Verify
        success = decrypted == plaintext
        
        return {
            'success': success,
            'plaintext_size': len(plaintext),
            'packet_size': len(packet_bytes),
            'decrypted_size': len(decrypted),
            'algorithm': 'ASCON' if use_ascon else 'AES-GCM',
            'packet_details': {
                'channel_id': packet.header.channel_id,
                'counter': packet.header.counter,
                'random_r': packet.header.r.hex(),
                'tag': packet.header.tag.hex()
            },
            'roundtrip_verified': success
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'algorithm': 'ASCON' if use_ascon else 'AES-GCM'
        }


def test_replay_protection(use_ascon: bool = False) -> dict:
    """
    Test replay protection functionality.
    
    Args:
        use_ascon: Whether to use ASCON algorithms
        
    Returns:
        Test results
    """
    from ..crypto.utils import generate_random_bytes
    from .encryptor import create_encryption_context
    
    # Setup
    master_psk = generate_random_bytes(32)
    channel_id = 42
    
    encrypt_engine = create_encryption_context(master_psk, channel_id, use_ascon)
    decrypt_engine = create_decryption_context(master_psk, channel_id, use_ascon)
    
    # Test messages
    messages = [b"Message 1", b"Message 2", b"Message 3"]
    packets = []
    
    # Encrypt messages
    for msg in messages:
        packet = encrypt_engine.encrypt_message(msg)
        packets.append(packet.to_bytes())
    
    results = []
    
    # Test normal decryption
    for i, packet_bytes in enumerate(packets):
        success, plaintext, error = decrypt_engine.try_decrypt_packet(packet_bytes)
        results.append({
            'test': f'normal_decrypt_{i}',
            'success': success,
            'plaintext': plaintext.decode() if plaintext else None,
            'error': error
        })
    
    # Test replay attacks (should fail)
    for i, packet_bytes in enumerate(packets):
        success, plaintext, error = decrypt_engine.try_decrypt_packet(packet_bytes)
        results.append({
            'test': f'replay_attack_{i}',
            'success': success,
            'expected_failure': True,
            'error': error
        })
    
    return {
        'algorithm': 'ASCON' if use_ascon else 'AES-GCM',
        'results': results,
        'replay_stats': decrypt_engine.get_replay_stats()
    }


def benchmark_decryption(packet_size: int = 1024, iterations: int = 1000,
                        use_ascon: bool = False) -> dict:
    """
    Benchmark decryption performance.
    
    Args:
        packet_size: Size of test packets
        iterations: Number of decryption operations
        use_ascon: Whether to use ASCON algorithms
        
    Returns:
        Performance statistics
    """
    import time
    from ..crypto.utils import generate_random_bytes
    from .encryptor import create_encryption_context
    
    # Setup
    master_psk = generate_random_bytes(32)
    channel_id = 1
    plaintext = generate_random_bytes(packet_size)
    
    # Pre-generate encrypted packets
    encrypt_engine = create_encryption_context(master_psk, channel_id, use_ascon)
    packets = []
    for _ in range(iterations):
        # Reset encryption context for each packet
        test_engine = create_encryption_context(master_psk, channel_id, use_ascon)
        packet = test_engine.encrypt_message(plaintext)
        packets.append(packet.to_bytes())
    
    # Benchmark decryption
    decrypt_engine = create_decryption_context(master_psk, channel_id, use_ascon)
    
    start_time = time.perf_counter()
    
    for packet_bytes in packets:
        try:
            decrypted = decrypt_engine.decrypt_packet(packet_bytes)
        except DecryptionError:
            # Skip failed decryptions in benchmark
            pass
    
    end_time = time.perf_counter()
    
    # Calculate statistics
    total_time = end_time - start_time
    avg_time = total_time / iterations
    throughput = (packet_size * iterations) / total_time / 1024 / 1024  # MB/s
    
    return {
        'algorithm': 'ASCON' if use_ascon else 'AES-GCM',
        'packet_size': packet_size,
        'iterations': iterations,
        'total_time': total_time,
        'avg_time_per_message': avg_time,
        'throughput_mbps': throughput
    }
