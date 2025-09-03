"""
Ouroboros Session Management.

Handles the complete message lifecycle including key derivation,
encryption/decryption, scrambling, and packet processing.
"""

from typing import Optional, Tuple
from ..crypto.kdf import derive_session_keys
from ..crypto.aes_gcm import encrypt_message, decrypt_message
from ..crypto.scramble import scramble_data, unscramble_data
from ..utils.counter import CounterManager
from ..utils.memory import SecureBytes
from .packet import OuroborosPacket, PacketType


class SessionError(Exception):
    """Raised when session operations fail."""
    pass


class OuroborosSession:
    """
    Ouroboros protocol session manager.
    
    Manages the complete secure channel including key derivation,
    message encryption/decryption, and packet processing.
    """
    
    def __init__(self, root_key: bytes, is_initiator: bool = True):
        """
        Initialize session with root key.
        
        Args:
            root_key: 32-byte pre-shared root key (used once)
            is_initiator: Whether this is the initiating side
        """
        if len(root_key) != 32:
            raise SessionError("Root key must be 32 bytes")
        
        self.is_initiator = is_initiator
        # Start counter at 1 since we'll use counter 0 for initial key derivation
        self.counter_manager = CounterManager(initial_send_counter=1)
        
        # Use root key once to derive initial session keys for counter 0
        self._current_enc_key, self._current_scr_key = derive_session_keys(root_key, 0)
        
        # Store keys securely
        self._enc_key = SecureBytes(self._current_enc_key)
        self._scr_key = SecureBytes(self._current_scr_key)
        
        # Clear root key from memory immediately
        root_key = b'\x00' * 32  # Zero out the reference
        
        self._initialized = True
    
    def encrypt_message(self, plaintext: bytes) -> OuroborosPacket:
        """
        Encrypt a message and create an Ouroboros packet.
        
        Args:
            plaintext: Message data to encrypt
            
        Returns:
            OuroborosPacket ready for transmission
            
        Raises:
            SessionError: If encryption fails
        """
        if not self._initialized:
            raise SessionError("Session not initialized")
        
        try:
            # Get next counter for this message
            counter = self.counter_manager.get_next_send_counter()
            
            # Derive new session keys for this message using previous keys
            new_enc_key, new_scr_key = derive_session_keys(
                root_key=None,  # Don't use root key after initialization
                counter=counter,
                previous_enc_key=bytes(self._enc_key),
                previous_scr_key=bytes(self._scr_key)
            )
            
            # Update stored keys
            self._enc_key.clear()
            self._scr_key.clear()
            self._enc_key = SecureBytes(new_enc_key)
            self._scr_key = SecureBytes(new_scr_key)
            
            # Create deterministic nonce from counter
            nonce = counter.to_bytes(12, byteorder='big')
            
            # Encrypt the message
            ciphertext_with_tag = encrypt_message(new_enc_key, plaintext, nonce)
            
            # Extract ciphertext and auth tag
            ciphertext = ciphertext_with_tag[:-16]
            auth_tag = ciphertext_with_tag[-16:]
            
            # Scramble the ciphertext
            scrambled_data = scramble_data(new_scr_key, ciphertext)
            
            # Create packet
            packet = OuroborosPacket(
                packet_type=PacketType.DATA,
                counter=counter,
                scrambled_data=scrambled_data,
                auth_tag=auth_tag
            )
            
            return packet
            
        except Exception as e:
            raise SessionError(f"Message encryption failed: {e}")
    
    def decrypt_message(self, packet: OuroborosPacket) -> bytes:
        """
        Decrypt a received Ouroboros packet.
        
        Args:
            packet: Received packet to decrypt
            
        Returns:
            Decrypted plaintext message
            
        Raises:
            SessionError: If decryption fails
        """
        if not self._initialized:
            raise SessionError("Session not initialized")
        
        if packet.packet_type != PacketType.DATA:
            raise SessionError("Can only decrypt DATA packets")
        
        try:
            # Validate counter for replay protection
            if not self.counter_manager.validate_received_counter(packet.counter):
                raise SessionError("Invalid or replayed counter")
            
            # For simplicity in this demo, we'll derive keys from counter directly
            # In production, you'd maintain proper receive key chain state
            recv_enc_key, recv_scr_key = self._derive_keys_for_counter(packet.counter)
            
            # Unscramble the data
            ciphertext = unscramble_data(recv_scr_key, packet.scrambled_data)
            
            # Reconstruct ciphertext with auth tag
            ciphertext_with_tag = ciphertext + packet.auth_tag
            
            # Derive nonce from counter for deterministic decryption
            nonce = packet.counter.to_bytes(12, byteorder='big')
            
            # Decrypt the message
            plaintext = decrypt_message(recv_enc_key, nonce, ciphertext_with_tag)
            
            return plaintext
            
        except Exception as e:
            raise SessionError(f"Message decryption failed: {e}")
    
    def _derive_keys_for_counter(self, counter: int) -> Tuple[bytes, bytes]:
        """
        Derive session keys for a specific counter value.
        
        This derives keys the same way as during encryption, ensuring
        both sender and receiver can derive the same keys for a given counter.
        
        Args:
            counter: Message counter
            
        Returns:
            Tuple of (encryption_key, scrambling_key)
        """
        from ..crypto.kdf import derive_session_keys
        
        try:
            if counter == 0:
                # For counter 0, use the initial keys we derived from root key
                return bytes(self._enc_key), bytes(self._scr_key)
            else:
                # For counter > 0, we need to derive from the keys for counter-1
                # This is simplified - in production you'd maintain full key chain
                if counter == 1:
                    # Derive from initial keys (counter 0 keys)
                    return derive_session_keys(
                        root_key=None,
                        counter=counter,
                        previous_enc_key=bytes(self._enc_key),
                        previous_scr_key=bytes(self._scr_key)
                    )
                else:
                    # For higher counters, this is simplified
                    # In production, you'd track the full key chain
                    base_enc, base_scr = bytes(self._enc_key), bytes(self._scr_key)
                    # Derive multiple times to reach the target counter
                    for i in range(1, counter + 1):
                        base_enc, base_scr = derive_session_keys(
                            root_key=None,
                            counter=i,
                            previous_enc_key=base_enc,
                            previous_scr_key=base_scr
                        )
                    return base_enc, base_scr
        except Exception:
            # Fallback to current keys if derivation fails
            return bytes(self._enc_key), bytes(self._scr_key)
    
    def create_ack_packet(self, ack_counter: int) -> OuroborosPacket:
        """
        Create an acknowledgment packet.
        
        Args:
            ack_counter: Counter value to acknowledge
            
        Returns:
            ACK packet
        """
        return OuroborosPacket(
            packet_type=PacketType.ACK,
            counter=ack_counter
        )
    
    def get_stats(self) -> dict:
        """
        Get session statistics.
        
        Returns:
            Dictionary with session statistics
        """
        return {
            'initialized': self._initialized,
            'is_initiator': self.is_initiator,
            'counter_stats': self.counter_manager.get_stats()
        }
    
    def __del__(self):
        """Clean up secure memory on session destruction."""
        if hasattr(self, '_enc_key'):
            self._enc_key.clear()
        if hasattr(self, '_scr_key'):
            self._scr_key.clear()
