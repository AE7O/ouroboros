"""
Ouroboros Protocol Packet Definition and Handling.

Defines the packet structure and provides functions for encoding/decoding
protocol messages.
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
    
    Packet format:
    ┌────────────────┬─────────────────┬─────────────────┬──────────────┐
    │   Header (8B)  │  Counter (8B)   │ Scrambled Data  │  Auth Tag    │
    ├────────────────┼─────────────────┼─────────────────┼──────────────┤
    │ Ver│Type│Flags │    MSG_COUNTER  │   CIPHERTEXT    │  GCM_TAG     │
    └────────────────┴─────────────────┴─────────────────┴──────────────┘
    """
    
    # Protocol version (4 bits)
    version: int = 1
    
    # Packet type (4 bits) 
    packet_type: PacketType = PacketType.DATA
    
    # Flags (8 bits)
    flags: int = 0
    
    # Reserved field (16 bits)
    reserved: int = 0
    
    # Message counter (64 bits)
    counter: int = 0
    
    # Scrambled payload data
    scrambled_data: bytes = b""
    
    # GCM authentication tag (16 bytes)
    auth_tag: bytes = b""
    
    # Original nonce used for encryption (not transmitted)
    nonce: Optional[bytes] = None
    
    def __post_init__(self):
        """Validate packet fields after initialization."""
        if not (0 <= self.version <= 15):
            raise PacketError("Version must be 0-15")
        if not isinstance(self.packet_type, PacketType):
            raise PacketError("Invalid packet type")
        if not (0 <= self.flags <= 255):
            raise PacketError("Flags must be 0-255")
        if not (0 <= self.counter <= 2**64 - 1):
            raise PacketError("Counter must be 64-bit value")
        if self.auth_tag and len(self.auth_tag) != 16:
            raise PacketError("Auth tag must be 16 bytes")
    
    def to_bytes(self) -> bytes:
        """
        Serialize packet to bytes for transmission.
        
        Returns:
            Serialized packet data
        """
        try:
            # Pack header (8 bytes total)
            # Byte 0: Version (4 bits) + Type (4 bits)
            version_type = (self.version << 4) | (self.packet_type & 0x0F)
            
            # Bytes 1-7: Flags (1 byte) + Reserved (2 bytes) + padding (4 bytes)
            header = struct.pack('>BBHI', version_type, self.flags, self.reserved, 0)
            
            # Counter (8 bytes)
            counter_bytes = struct.pack('>Q', self.counter)
            
            # Combine all parts
            packet_data = header + counter_bytes + self.scrambled_data + self.auth_tag
            
            return packet_data
            
        except Exception as e:
            raise PacketError(f"Failed to serialize packet: {str(e)}")
    
    @classmethod 
    def from_bytes(cls, data: bytes) -> 'OuroborosPacket':
        """
        Deserialize packet from bytes.
        
        Args:
            data: Raw packet data
            
        Returns:
            OuroborosPacket instance
            
        Raises:
            PacketError: If packet is malformed
        """
        try:
            if len(data) < 32:  # Minimum: 8 (header) + 8 (counter) + 16 (auth_tag)
                raise PacketError("Packet too short")
            
            # Unpack header
            version_type, flags, reserved, padding = struct.unpack('>BBHI', data[:8])
            
            # Extract version and type
            version = (version_type >> 4) & 0x0F
            packet_type = PacketType(version_type & 0x0F)
            
            # Unpack counter
            counter = struct.unpack('>Q', data[8:16])[0]
            
            # Extract auth tag (last 16 bytes)
            auth_tag = data[-16:]
            
            # Everything in between is scrambled data
            scrambled_data = data[16:-16] if len(data) > 32 else b""
            
            return cls(
                version=version,
                packet_type=packet_type,
                flags=flags,
                reserved=reserved,
                counter=counter,
                scrambled_data=scrambled_data,
                auth_tag=auth_tag
            )
            
        except (struct.error, ValueError) as e:
            raise PacketError(f"Failed to deserialize packet: {str(e)}")
    
    def get_header_bytes(self) -> bytes:
        """
        Get just the header portion for use in authentication.
        
        Returns:
            8-byte header
        """
        version_type = (self.version << 4) | (self.packet_type & 0x0F)
        return struct.pack('>BBHI', version_type, self.flags, self.reserved, 0)
    
    def is_data_packet(self) -> bool:
        """Check if this is a data packet."""
        return self.packet_type == PacketType.DATA
    
    def is_ack_packet(self) -> bool:
        """Check if this is an acknowledgment packet."""
        return self.packet_type == PacketType.ACK
    
    def is_control_packet(self) -> bool:
        """Check if this is a control packet (ACK, NACK, PING, PONG)."""
        return self.packet_type in [PacketType.ACK, PacketType.NACK, PacketType.PING, PacketType.PONG]


def create_ack_packet(counter: int) -> OuroborosPacket:
    """
    Create an acknowledgment packet for a given counter.
    
    Args:
        counter: Counter value to acknowledge
        
    Returns:
        ACK packet
    """
    return OuroborosPacket(
        packet_type=PacketType.ACK,
        counter=counter
    )


def create_nack_packet(counter: int) -> OuroborosPacket:
    """
    Create a negative acknowledgment packet.
    
    Args:
        counter: Counter value to negative acknowledge
        
    Returns:
        NACK packet
    """
    return OuroborosPacket(
        packet_type=PacketType.NACK,
        counter=counter
    )
