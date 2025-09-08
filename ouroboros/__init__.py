"""
Ouroboros Secure Overlay Protocol.

A lightweight, symmetric-only secure communication protocol for IoT environments.
Provides TLS-like security using only symmetric cryptography and hash functions.

Key Features:
- Forward secrecy via hash-based key ratcheting
- Replay protection with sliding window
- Traffic obfuscation through per-message scrambling
- Support for AES-256-GCM and ASCON-AEAD128
- Comprehensive evaluation suite for research

Basic Usage:
    >>> from ouroboros import create_peer_context
    >>> from ouroboros.crypto.utils import generate_random_bytes
    >>> 
    >>> # Create shared key and peer contexts
    >>> master_psk = generate_random_bytes(32)
    >>> alice = create_peer_context(master_psk, channel_id=1)
    >>> bob = create_peer_context(master_psk, channel_id=1)
    >>> 
    >>> # Encrypt message
    >>> packet = alice.encrypt_message(b"Hello, Bob!")
    >>> 
    >>> # Decrypt message
    >>> plaintext = bob.decrypt_packet(packet.to_bytes())
    >>> print(plaintext)  # b"Hello, Bob!"
"""

__version__ = "1.0.0"
__author__ = "Ouroboros Protocol Team"

# Core protocol components
from .protocol.encryptor import create_encryption_context
from .protocol.decryptor import create_decryption_context
from .protocol.packet import OuroborosPacket, PacketHeader, build_packet, parse_packet

# Cryptographic primitives
from .crypto.ratchet import RatchetState
from .crypto.aead import AEADCipher, create_aead_cipher
from .crypto.scramble import DataScrambler, scramble_data, unscramble_data
from .crypto.utils import generate_random_bytes, SecureBytes

# Protocol utilities
from .protocol.window import SlidingWindow, ReplayProtection

# Channel communication
from .channel.io import SocketManager, create_udp_endpoint

# Evaluation tools
from .evaluation.benchmark import PerformanceBenchmark, run_comprehensive_benchmark


class PeerContext:
    """
    High-level peer context for secure communication.
    
    Combines encryption and decryption engines for easy peer-to-peer communication.
    """
    
    def __init__(self, master_psk: bytes, channel_id: int, use_ascon: bool = False):
        """
        Initialize peer context.
        
        Args:
            master_psk: 32-byte master pre-shared key
            channel_id: Channel identifier (0-255)
            use_ascon: Whether to use ASCON algorithms instead of AES-GCM
        """
        self.channel_id = channel_id
        self.use_ascon = use_ascon
        
        # Create separate encryption and decryption contexts
        self.encrypt_engine = create_encryption_context(master_psk, channel_id, use_ascon)
        self.decrypt_engine = create_decryption_context(master_psk, channel_id, use_ascon)
    
    def encrypt_message(self, plaintext: bytes) -> OuroborosPacket:
        """
        Encrypt a message.
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            Encrypted packet
        """
        return self.encrypt_engine.encrypt_message(plaintext)
    
    def decrypt_packet(self, packet_bytes: bytes) -> bytes:
        """
        Decrypt a packet.
        
        Args:
            packet_bytes: Raw packet data
            
        Returns:
            Decrypted plaintext
        """
        return self.decrypt_engine.decrypt_packet(packet_bytes)
    
    def get_info(self) -> dict:
        """Get information about this peer context."""
        return {
            'channel_id': self.channel_id,
            'algorithm': 'ASCON' if self.use_ascon else 'AES-GCM',
            'encryption_info': self.encrypt_engine.get_algorithm_info(),
            'replay_stats': self.decrypt_engine.get_replay_stats()
        }


def create_peer_context(master_psk: bytes, channel_id: int, 
                       use_ascon: bool = False) -> PeerContext:
    """
    Create a peer context for secure communication.
    
    Args:
        master_psk: 32-byte master pre-shared key
        channel_id: Channel identifier (0-255)
        use_ascon: Whether to use ASCON algorithms instead of AES-GCM
        
    Returns:
        PeerContext ready for secure communication
    """
    return PeerContext(master_psk, channel_id, use_ascon)


def quick_benchmark(algorithm: str = "AES-GCM") -> dict:
    """
    Run a quick performance benchmark.
    
    Args:
        algorithm: "AES-GCM" or "ASCON"
        
    Returns:
        Benchmark results
    """
    use_ascon = algorithm.upper() == "ASCON"
    
    # Quick test with small dataset
    benchmark = PerformanceBenchmark()
    message_sizes = [64, 512, 1024]
    iterations = 100
    
    encrypt_results = benchmark.benchmark_encryption_performance(
        message_sizes, iterations, use_ascon
    )
    decrypt_results = benchmark.benchmark_decryption_performance(
        message_sizes, iterations, use_ascon
    )
    
    return {
        'algorithm': algorithm,
        'encryption': encrypt_results,
        'decryption': decrypt_results
    }


# Export key components for easy access
__all__ = [
    # Version info
    '__version__',
    
    # High-level interface
    'PeerContext',
    'create_peer_context',
    
    # Protocol components
    'create_encryption_context',
    'create_decryption_context',
    'OuroborosPacket',
    'PacketHeader',
    'build_packet',
    'parse_packet',
    
    # Cryptographic primitives
    'RatchetState',
    'AEADCipher',
    'create_aead_cipher',
    'DataScrambler',
    'scramble_data',
    'unscramble_data',
    'generate_random_bytes',
    'SecureBytes',
    
    # Protocol utilities
    'SlidingWindow',
    'ReplayProtection',
    
    # Channel communication
    'SocketManager',
    'create_udp_endpoint',
    
    # Evaluation
    'PerformanceBenchmark',
    'run_comprehensive_benchmark',
    'quick_benchmark',
]
