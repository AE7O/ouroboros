"""
Key derivation and ratcheting functions for Ouroboros Protocol.

This module implements the hash-based key ratcheting mechanism that provides
forward secrecy by evolving keys after each message. Uses ASCON-Hash256 when 
available (via official pyascon implementation aligned with NIST SP 800-232).
"""

import hashlib
import hmac
import struct
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Try to import ASCON for lightweight environments
try:
    import pyascon as ascon
    ASCON_AVAILABLE = True
except ImportError:
    ASCON_AVAILABLE = False

from .utils import secure_zero


class RatchetState:
    """Manages the key ratchet state for a peer connection."""
    
    def __init__(self, master_psk: bytes, use_ascon: bool = False):
        """Initialize ratchet with master pre-shared key."""
        if len(master_psk) != 32:
            raise ValueError("Master PSK must be 32 bytes")
        
        self.use_ascon = use_ascon and ASCON_AVAILABLE
        self.kr = bytearray(master_psk)  # Current ratchet key
        self.counter_s = 0  # Outbound message counter
        
        # Immediately derive initial ratchet key and zero master PSK
        self._advance_ratchet()
        secure_zero(master_psk)
    
    def derive_keys(self, channel_id: int, counter: int) -> Tuple[bytes, bytes, bytes]:
        """
        Derive encryption key (ke), nonce, and permutation key (kp) for a message.
        
        Args:
            channel_id: 1-byte channel identifier
            counter: 4-byte message counter
            
        Returns:
            Tuple of (ke, nonce, kp) - 32 bytes, 12 bytes, 32 bytes respectively
        """
        # Create derivation context
        context = struct.pack('!BI', channel_id, counter)
        
        if self.use_ascon:
            return self._derive_keys_ascon(context)
        else:
            return self._derive_keys_hkdf(context)
    
    def _derive_keys_hkdf(self, context: bytes) -> Tuple[bytes, bytes, bytes]:
        """Derive keys using HKDF-SHA256."""
        # Derive 76 bytes total: 32 (ke) + 12 (nonce) + 32 (kp)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=76,
            salt=None,
            info=b"ouroboros-v1" + context
        )
        derived = hkdf.derive(bytes(self.kr))
        
        ke = derived[:32]
        nonce = derived[32:44]
        kp = derived[44:76]
        
        return ke, nonce, kp
    
    def _derive_keys_ascon(self, context: bytes) -> Tuple[bytes, bytes, bytes]:
        """Derive keys using ASCON-Hash256 (lightweight option)."""
        if not ASCON_AVAILABLE:
            raise RuntimeError("ASCON not available, use HKDF instead")
        
        # Use ASCON hash as KDF
        input_data = bytes(self.kr) + b"ouroboros-v1" + context
        
        # Generate 76 bytes using multiple hash rounds
        derived = b""
        for i in range(3):  # 3 rounds * 32 bytes = 96 bytes (we'll take first 76)
            round_input = input_data + struct.pack('!B', i)
            derived += ascon.ascon_hash(round_input, variant="Ascon-Hash256", hashlength=32)
        
        ke = derived[:32]
        nonce = derived[32:44]
        kp = derived[44:76]
        
        return ke, nonce, kp
    
    def advance_ratchet_send(self) -> int:
        """Advance ratchet for sending a message. Returns counter value."""
        counter = self.counter_s
        self.counter_s += 1
        self._advance_ratchet()
        return counter
    
    def _advance_ratchet(self):
        """Advance the ratchet key using hash ratcheting."""
        if self.use_ascon and ASCON_AVAILABLE:
            # Use ASCON hash for ratcheting
            new_kr = ascon.ascon_hash(bytes(self.kr) + b"ratchet", variant="Ascon-Hash256", hashlength=32)
        else:
            # Use SHA256 for ratcheting
            new_kr = hashlib.sha256(bytes(self.kr) + b"ratchet").digest()
        
        # Securely update ratchet key
        secure_zero(self.kr)
        self.kr = bytearray(new_kr)
    
    def get_current_counter(self) -> int:
        """Get current outbound counter value."""
        return self.counter_s
    
    def __del__(self):
        """Securely clear ratchet key on destruction."""
        if hasattr(self, 'kr'):
            secure_zero(self.kr)


def derive_initial_keys(master_psk: bytes, peer_id: bytes) -> bytes:
    """
    Derive initial ratchet key from master PSK and peer identifier.
    
    Args:
        master_psk: 32-byte master pre-shared key
        peer_id: Peer identifier for key separation
        
    Returns:
        32-byte initial ratchet key
    """
    if len(master_psk) != 32:
        raise ValueError("Master PSK must be 32 bytes")
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ouroboros-init" + peer_id
    )
    return hkdf.derive(master_psk)


def compute_permutation_seed(kp: bytes, tag: bytes, r: bytes) -> bytes:
    """
    Compute seed for scrambling permutation.
    
    Args:
        kp: 32-byte permutation key from ratchet
        tag: 16-byte AEAD authentication tag
        r: 4-byte per-message random value
        
    Returns:
        32-byte seed for ChaCha20 PRNG
    """
    # Combine all inputs and hash to get final seed
    combined = kp + tag + r
    return hashlib.sha256(combined).digest()
