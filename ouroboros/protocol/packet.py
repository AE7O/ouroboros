"""
Ouroboros Protocol Packet Definition and Handling.

Defines the new packet structure and provides functions for encoding/decoding
protocol messages with the format:
channel_id (1B) || counter (4B) || r (4B) || tag (16B) || scrambled_ciphertext
"""

import struct
from enum import IntEnum
from typing import Optional, Tuple
from dataclasses import dataclass


class PacketType(IntEnum):
    """Ouroboros packet types."""
    DATA = 0x01      # Data message
    ACK = 0x02       # Acknowledgment
    NACK = 0x03      # Negative acknowledgment
    PING = 0x04      # Keep-alive ping
    PONG = 0x05      # Ping response


class PacketError(Exception):
    """Raised when packet operations fail."""
    pass


@dataclass
class OuroborosPacket:
    """
    Ouroboros protocol packet structure.
    
    New packet format:
    ┌─────────────┬─────────────┬─────────────┬──────────────┬─────────────────┐
    │ Channel ID  │  Counter    │      r      │   Auth Tag   │ Scrambled Data  │
    │   (1B)      │    (4B)     │    (4B)     │    (16B)     │   (variable)    │
    └─────────────┴─────────────┴─────────────┴──────────────┴─────────────────┘
    
    Total header: 25 bytes (1 + 4 + 4 + 16)
    """
    
    # Channel identifier (8 bits)
    channel_id: int = 0
    
    # Message counter (32 bits)
    counter: int = 0
    
    # Random value r (32 bits) 
    r: int = 0
    
    # GCM authentication tag (16 bytes)
    auth_tag: bytes = b""
    
    # Scrambled payload data
    scrambled_data: bytes = b""
    
    # Packet type (not transmitted, used for higher-level logic)
    packet_type: PacketType = PacketType.DATA
    
    def __post_init__(self):
        """Validate packet fields after initialization."""
        if not (0 <= self.channel_id <= 255):
            raise PacketError("Channel ID must be 0-255")
        if not (0 <= self.counter <= 2**32 - 1):
            raise PacketError("Counter must be 32-bit value")
        if not (0 <= self.r <= 2**32 - 1):
            raise PacketError("Random value r must be 32-bit value")
        if self.auth_tag and len(self.auth_tag) != 16:
            raise PacketError("Auth tag must be 16 bytes")
    
    def to_bytes(self) -> bytes:
        """
        Serialize packet to bytes for transmission.
        
        Returns:
            Serialized packet data
        """
        try:
            # Pack header: channel_id (1B) + counter (4B) + r (4B) + tag (16B)
            header = struct.pack('>BII', self.channel_id, self.counter, self.r)
            
            # Combine header + auth_tag + scrambled_data
            packet_data = header + self.auth_tag + self.scrambled_data
            
            return packet_data
            
        except struct.error as e:
            raise PacketError(f"Failed to serialize packet: {str(e)}")
    
    @classmethod 
    def from_bytes(cls, data: bytes) -> 'OuroborosPacket':
        """
        Deserialize packet from bytes.
        
        Args:
            data: Raw packet bytes
            
        Returns:
            OuroborosPacket instance
            
        Raises:
            PacketError: If packet is malformed
        """
        try:
            if len(data) < 25:  # Minimum packet size (1 + 4 + 4 + 16)
                raise PacketError("Packet too short")
            
            # Unpack header: channel_id (1B) + counter (4B) + r (4B)
            channel_id, counter, r = struct.unpack('>BII', data[:9])
            
            # Extract auth tag (16 bytes)
            auth_tag = data[9:25]
            
            # Everything after header is scrambled data
            scrambled_data = data[25:] if len(data) > 25 else b""
            
            return cls(
                channel_id=channel_id,
                counter=counter,
                r=r,
                auth_tag=auth_tag,
                scrambled_data=scrambled_data
            )
            
        except (struct.error, ValueError) as e:
            raise PacketError(f"Failed to deserialize packet: {str(e)}")
    
    def get_header_bytes(self) -> bytes:
        """
        Get just the header bytes (channel_id + counter + r).
        
        Returns:
            9-byte header
        """
        return struct.pack('>BII', self.channel_id, self.counter, self.r)
    
    def get_size(self) -> int:
        """
        Get total packet size in bytes.
        
        Returns:
            Total packet size
        """
        return 25 + len(self.scrambled_data)  # Header (9) + Tag (16) + Data
    
    def is_valid(self) -> bool:
        """
        Check if packet structure is valid.
        
        Returns:
            True if packet is valid, False otherwise
        """
        try:
            self.__post_init__()
            return True
        except PacketError:
            return False
    
    def is_data_packet(self) -> bool:
        """Check if this is a data packet."""
        return self.packet_type == PacketType.DATA
    
    def is_ack_packet(self) -> bool:
        """Check if this is an acknowledgment packet."""
        return self.packet_type == PacketType.ACK
    
    def is_control_packet(self) -> bool:
        """Check if this is a control packet (ACK, NACK, PING, PONG)."""
        return self.packet_type in [PacketType.ACK, PacketType.NACK, PacketType.PING, PacketType.PONG]


def create_ack_packet(channel_id: int, counter: int) -> OuroborosPacket:
    """
    Create an acknowledgment packet.
    
    Args:
        channel_id: Channel identifier
        counter: Counter value being acknowledged
        
    Returns:
        ACK packet
    """
    return OuroborosPacket(
        channel_id=channel_id,
        counter=counter,
        r=0,  # ACK packets don't need random value
        auth_tag=b'\x00' * 16,  # Placeholder tag
        scrambled_data=b"",
        packet_type=PacketType.ACK
    )


def create_nack_packet(channel_id: int, counter: int) -> OuroborosPacket:
    """
    Create a negative acknowledgment packet.
    
    Args:
        channel_id: Channel identifier
        counter: Counter value being rejected
        
    Returns:
        NACK packet
    """
    return OuroborosPacket(
        channel_id=channel_id,
        counter=counter,
        r=0,  # NACK packets don't need random value
        auth_tag=b'\x00' * 16,  # Placeholder tag
        scrambled_data=b"",
        packet_type=PacketType.NACK
    )


def create_ping_packet(channel_id: int) -> OuroborosPacket:
    """
    Create a ping packet for keep-alive.
    
    Args:
        channel_id: Channel identifier
        
    Returns:
        PING packet
    """
    return OuroborosPacket(
        channel_id=channel_id,
        counter=0,  # Ping uses counter 0
        r=0,
        auth_tag=b'\x00' * 16,
        scrambled_data=b"",
        packet_type=PacketType.PING
    )