"""
Encryption pipeline for Ouroboros Protocol.

This module implements the complete encryption pipeline:
1. Derive keys (ke, nonce, kp) from ratchet using channel_id + counter_s
2. Generate per-message random r (4B)
3. AEAD encrypt → (ciphertext, tag)
4. Derive permutation stream from (kp, tag, r)
5. Scramble ciphertext with Fisher–Yates + ChaCha20 PRNG
6. Construct packet → header || scrambled_ciphertext
"""

from typing import Tuple
from ..crypto.ratchet import RatchetState
from ..crypto.aead import AEADCipher, AEADDecryptionError
from ..crypto.scramble import scramble_data
from ..crypto.utils import generate_message_random
from .packet import build_packet, OuroborosPacket


class EncryptionEngine:
    """
    Handles the complete encryption pipeline for Ouroboros messages.
    """
    
    def __init__(self, ratchet: RatchetState, channel_id: int, use_ascon: bool = False):
        """
        Initialize encryption engine.
        
        Args:
            ratchet: RatchetState for key derivation
            channel_id: 1-byte channel identifier
            use_ascon: Whether to use ASCON instead of AES-GCM
        """
        self.ratchet = ratchet
        self.channel_id = channel_id
        self.aead = AEADCipher(use_ascon=use_ascon)
        self.counter = 0  # Track counter locally without modifying ratchet
        
        # Validate channel ID
        if not (0 <= channel_id <= 255):
            raise ValueError("Channel ID must be 0-255")
    
    def encrypt_message(self, plaintext: bytes) -> OuroborosPacket:
        """
        Encrypt a plaintext message following the complete pipeline.
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            Complete encrypted OuroborosPacket
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Step 1: Get current counter and advance it
            counter = self.counter
            self.counter += 1
            
            # Step 2: Derive keys from ratchet using counter
            ke, nonce, kp = self.ratchet.derive_keys(self.channel_id, counter)
            
            # Step 3: Generate per-message random
            r = generate_message_random()
            
            # Step 4: AEAD encrypt
            ciphertext, tag = self.aead.encrypt(ke, nonce, plaintext)
            
            # Step 5: Scramble ciphertext
            scrambled_ciphertext = scramble_data(ciphertext, kp, tag, r)
            
            # Step 6: Build final packet
            packet = build_packet(
                channel_id=self.channel_id,
                counter=counter,
                r=r,
                tag=tag,
                scrambled_payload=scrambled_ciphertext
            )
            
            return packet
            
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e
    
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
            'current_counter': self.ratchet.get_current_counter()
        }


class EncryptionError(Exception):
    """Raised when encryption fails."""
    pass


def encrypt_message(ratchet: RatchetState, channel_id: int, plaintext: bytes,
                   use_ascon: bool = False) -> OuroborosPacket:
    """
    Convenience function to encrypt a single message.
    
    Args:
        ratchet: RatchetState for key derivation
        channel_id: Channel identifier
        plaintext: Message to encrypt
        use_ascon: Whether to use ASCON instead of AES-GCM
        
    Returns:
        Encrypted OuroborosPacket
    """
    engine = EncryptionEngine(ratchet, channel_id, use_ascon)
    return engine.encrypt_message(plaintext)


def create_encryption_context(master_psk: bytes, channel_id: int, 
                            use_ascon: bool = False) -> EncryptionEngine:
    """
    Create a complete encryption context from a master PSK.
    
    Args:
        master_psk: 32-byte master pre-shared key
        channel_id: Channel identifier
        use_ascon: Whether to use ASCON algorithms
        
    Returns:
        Ready-to-use EncryptionEngine
    """
    ratchet = RatchetState(master_psk, use_ascon=use_ascon)
    return EncryptionEngine(ratchet, channel_id, use_ascon=use_ascon)


def benchmark_encryption(plaintext_size: int = 1024, iterations: int = 1000,
                        use_ascon: bool = False) -> dict:
    """
    Benchmark encryption performance.
    
    Args:
        plaintext_size: Size of test plaintext in bytes
        iterations: Number of encryption operations
        use_ascon: Whether to use ASCON algorithms
        
    Returns:
        Performance statistics
    """
    import time
    from ..crypto.utils import generate_random_bytes
    
    # Setup
    master_psk = generate_random_bytes(32)
    plaintext = generate_random_bytes(plaintext_size)
    engine = create_encryption_context(master_psk, channel_id=1, use_ascon=use_ascon)
    
    # Benchmark encryption
    start_time = time.perf_counter()
    
    packets = []
    for _ in range(iterations):
        # Create new engine for each test to avoid ratchet progression affecting timing
        test_engine = create_encryption_context(master_psk, channel_id=1, use_ascon=use_ascon)
        packet = test_engine.encrypt_message(plaintext)
        packets.append(packet)
    
    end_time = time.perf_counter()
    
    # Calculate statistics
    total_time = end_time - start_time
    avg_time = total_time / iterations
    throughput = (plaintext_size * iterations) / total_time / 1024 / 1024  # MB/s
    
    # Analyze packet sizes
    packet_sizes = [len(packet.to_bytes()) for packet in packets]
    avg_packet_size = sum(packet_sizes) / len(packet_sizes)
    overhead = avg_packet_size - plaintext_size
    overhead_percent = (overhead / plaintext_size) * 100
    
    return {
        'algorithm': 'ASCON' if use_ascon else 'AES-GCM',
        'plaintext_size': plaintext_size,
        'iterations': iterations,
        'total_time': total_time,
        'avg_time_per_message': avg_time,
        'throughput_mbps': throughput,
        'avg_packet_size': avg_packet_size,
        'protocol_overhead': overhead,
        'overhead_percent': overhead_percent
    }


def test_encryption_pipeline(plaintext: bytes = b"Hello, Ouroboros!",
                           use_ascon: bool = False) -> dict:
    """
    Test the complete encryption pipeline with a sample message.
    
    Args:
        plaintext: Test message
        use_ascon: Whether to use ASCON algorithms
        
    Returns:
        Test results and packet details
    """
    from ..crypto.utils import generate_random_bytes
    
    # Setup
    master_psk = generate_random_bytes(32)
    channel_id = 42
    
    # Create encryption engine
    engine = create_encryption_context(master_psk, channel_id, use_ascon)
    
    # Encrypt message
    packet = engine.encrypt_message(plaintext)
    
    # Analyze results
    header = packet.header
    
    return {
        'algorithm_info': engine.get_algorithm_info(),
        'plaintext_size': len(plaintext),
        'packet_size': len(packet.to_bytes()),
        'header_size': header.size,
        'payload_size': len(packet.payload),
        'overhead': len(packet.to_bytes()) - len(plaintext),
        'packet_details': {
            'channel_id': header.channel_id,
            'counter': header.counter,
            'random_r': header.r.hex(),
            'tag': header.tag.hex(),
            'scrambled_payload_preview': packet.payload[:32].hex() + '...' if len(packet.payload) > 32 else packet.payload.hex()
        }
    }
