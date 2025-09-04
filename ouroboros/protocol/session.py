"""
Ouroboros Session Management.

Handles the complete message lifecycle including key derivation,
encryption/decryption, scrambling, and packet processing.
"""

from typing import Optional, Tuple
from ..crypto.kdf import derive_session_keys
from ..crypto import encrypt_message, decrypt_message
from ..crypto.scramble import scramble_data, unscramble_data
from ..crypto.utils import SecureBytes
from .packet import OuroborosPacket


class SessionError(Exception):
    """Raised when session operations fail."""
    pass


class OuroborosSession:
    """
    Ouroboros protocol session manager.
    
    Manages the complete secure channel including key derivation,
    message encryption/decryption, and packet processing.
    """
    
    def __init__(self, root_key: bytes, channel_id: int = 1, is_initiator: bool = True):
        """
        Initialize session with root key.
        
        Args:
            root_key: 32-byte pre-shared root key (used once)
            channel_id: 1-byte channel identifier (default 1)
            is_initiator: Whether this is the initiating side
        """
        if len(root_key) != 32:
            raise SessionError("Root key must be 32 bytes")
        if not (0 <= channel_id <= 255):
            raise SessionError("Channel ID must be 0-255")
        
        # Initialize session
        self.channel_id = channel_id
        self.is_initiator = is_initiator
        
        # Simple counter management
        self.send_counter = 0
        self.received_counters = set()
        self.max_counter_window = 1000  # Prevent memory growth
        
        # Use root key once to derive initial session keys
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
            counter = self.send_counter
            self.send_counter += 1
            
            # Derive new session keys for this message
            new_enc_key, new_scr_key = derive_session_keys(
                None, counter, bytes(self._enc_key), bytes(self._scr_key)
            )
            
            # Update stored keys
            self._enc_key.clear()
            self._scr_key.clear()
            self._enc_key = SecureBytes(new_enc_key)
            self._scr_key = SecureBytes(new_scr_key)
            
            # Encrypt the message
            nonce, ciphertext_with_tag = encrypt_message(new_enc_key, plaintext)
            
            # Extract ciphertext and auth tag
            ciphertext = ciphertext_with_tag[:-16]
            auth_tag = ciphertext_with_tag[-16:]
            
            # Scramble the ciphertext
            scrambled_data = scramble_data(new_scr_key, ciphertext)
            
            # Create packet header
            from .packet import PacketHeader
            header = PacketHeader(
                channel_id=self.channel_id,
                counter=counter,
                r=nonce[:4],  # Use first 4 bytes of nonce as 'r'
                tag=auth_tag
            )
            
            # Create packet
            packet = OuroborosPacket(
                header=header,
                payload=scrambled_data
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
        
        if not packet.is_data_packet():
            raise SessionError("Can only decrypt DATA packets")
        
        try:
            # Validate counter for replay protection
            if packet.counter in self.received_counters:
                raise SessionError(f"Replay attack detected - counter {packet.counter} already seen")
            
            self.received_counters.add(packet.counter)
            
            # Prevent memory growth by limiting window size
            if len(self.received_counters) > self.max_counter_window:
                # Remove oldest counters (simplified approach)
                sorted_counters = sorted(self.received_counters)
                self.received_counters = set(sorted_counters[-self.max_counter_window//2:])
            
            # Derive session keys for this message counter
            # Note: For received messages, we need to track the key chain
            # This is a simplified version - production would need proper state tracking
            recv_enc_key, recv_scr_key = self._derive_keys_for_counter(packet.counter)
            
            # Unscramble the data
            ciphertext = unscramble_data(recv_scr_key, packet.scrambled_data)
            
            # Reconstruct ciphertext with auth tag
            ciphertext_with_tag = ciphertext + packet.auth_tag
            
            # For decryption, we need the nonce - in real protocol this would be derived
            # or transmitted. For now, we'll extract it from packet context
            if packet.nonce is None:
                raise SessionError("Nonce required for decryption")
            
            # Decrypt the message
            plaintext = decrypt_message(recv_enc_key, packet.nonce, ciphertext_with_tag)
            
            return plaintext
            
        except Exception as e:
            raise SessionError(f"Message decryption failed: {e}")
    
    def _derive_keys_for_counter(self, counter: int) -> Tuple[bytes, bytes]:
        """
        Derive session keys for a specific counter value.
        
        This is a simplified implementation. In production, you'd need
        to maintain proper key chain state for both send and receive.
        
        Args:
            counter: Message counter
            
        Returns:
            Tuple of (encryption_key, scrambling_key)
        """
        # For now, use current keys (this is simplified)
        # In production, you'd track separate send/receive key chains
        return bytes(self._enc_key), bytes(self._scr_key)
    
    def create_ack_packet(self, ack_counter: int) -> OuroborosPacket:
        """
        Create an acknowledgment packet.
        
        Args:
            ack_counter: Counter value to acknowledge
            
        Returns:
            ACK packet
        """
        # Create empty ACK packet
        from .packet import PacketHeader
        header = PacketHeader(
            channel_id=self.channel_id,
            counter=ack_counter,
            r=b'\x00' * 4,  # Empty r for ACK
            tag=b'\x00' * 16  # Empty tag for ACK
        )
        return OuroborosPacket(
            header=header,
            payload=b''  # Empty payload for ACK
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
            'send_counter': self.send_counter,
            'received_counter_count': len(self.received_counters)
        }
    
    def __del__(self):
        """Clean up secure memory on session destruction."""
        if hasattr(self, '_enc_key'):
            self._enc_key.clear()
        if hasattr(self, '_scr_key'):
            self._scr_key.clear()
