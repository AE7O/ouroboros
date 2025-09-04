"""
Packet structure and parsing for Ouroboros Protocol.

This module defines the packet format and provides functions to build and parse
protocol messages according to the specification:

header = channel_id (1B) || counter (4B) || r (4B) || tag (16B)
payload = scrambled_ciphertext
packet = header || payload
"""

import struct
from typing import Tuple, Optional
from dataclasses import dataclass


@dataclass
class PacketHeader:
    """
    Ouroboros packet header structure.
    
    Fields:
        channel_id: 1-byte channel identifier
        counter: 4-byte message counter (big-endian)
        r: 4-byte per-message random value
        tag: 16-byte AEAD authentication tag
    """
    channel_id: int
    counter: int
    r: bytes
    tag: bytes
    
    def __post_init__(self):
        """Validate header fields."""
        if not (0 <= self.channel_id <= 255):
            raise ValueError("Channel ID must be 0-255")
        if not (0 <= self.counter <= 0xFFFFFFFF):
            raise ValueError("Counter must be 32-bit unsigned integer")
        if len(self.r) != 4:
            raise ValueError("Random value 'r' must be 4 bytes")
        if len(self.tag) != 16:
            raise ValueError("Authentication tag must be 16 bytes")
    
    @property
    def size(self) -> int:
        """Get header size in bytes."""
        return HEADER_SIZE
    
    def to_bytes(self) -> bytes:
        """Serialize header to bytes."""
        return struct.pack('!BI4s16s', self.channel_id, self.counter, self.r, self.tag)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'PacketHeader':
        """Deserialize header from bytes."""
        if len(data) != HEADER_SIZE:
            raise PacketFormatError(f"Header must be {HEADER_SIZE} bytes, got {len(data)}")
        
        try:
            channel_id, counter, r, tag = struct.unpack('!BI4s16s', data)
            return cls(channel_id=channel_id, counter=counter, r=r, tag=tag)
        except struct.error as e:
            raise PacketFormatError("Invalid header format") from e


@dataclass
class OuroborosPacket:
    """
    Complete Ouroboros protocol packet.
    
    Fields:
        header: Packet header containing metadata
        payload: Scrambled ciphertext payload
    """
    header: PacketHeader
    payload: bytes
    
    @property
    def size(self) -> int:
        """Get total packet size in bytes."""
        return len(self.header.to_bytes()) + len(self.payload)
    
    def to_bytes(self) -> bytes:
        """Serialize complete packet to bytes."""
        return self.header.to_bytes() + self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'OuroborosPacket':
        """Deserialize complete packet from bytes."""
        if len(data) < HEADER_SIZE:
            raise PacketFormatError(f"Packet too short: {len(data)} bytes")
        
        # Parse header
        header_bytes = data[:HEADER_SIZE]
        header = PacketHeader.from_bytes(header_bytes)
        
        # Extract payload
        payload = data[HEADER_SIZE:]
        
        return cls(header=header, payload=payload)
    
    def __len__(self) -> int:
        """Get packet size."""
        return self.size


# Constants
HEADER_SIZE = 25  # 1 + 4 + 4 + 16 bytes
MAX_PAYLOAD_SIZE = 65535 - HEADER_SIZE  # Maximum UDP payload minus header


class PacketFormatError(Exception):
    """Raised when packet format is invalid."""
    pass


def build_packet(channel_id: int, counter: int, r: bytes, tag: bytes, 
                scrambled_payload: bytes) -> OuroborosPacket:
    """
    Build a complete Ouroboros packet.
    
    Args:
        channel_id: 1-byte channel identifier
        counter: 4-byte message counter
        r: 4-byte per-message random value
        tag: 16-byte AEAD authentication tag
        scrambled_payload: Scrambled ciphertext
        
    Returns:
        Complete OuroborosPacket
        
    Raises:
        PacketFormatError: If packet parameters are invalid
    """
    if len(scrambled_payload) > MAX_PAYLOAD_SIZE:
        raise PacketFormatError(f"Payload too large: {len(scrambled_payload)} bytes")
    
    header = PacketHeader(
        channel_id=channel_id,
        counter=counter,
        r=r,
        tag=tag
    )
    
    return OuroborosPacket(header=header, payload=scrambled_payload)


def parse_packet(packet_bytes: bytes) -> OuroborosPacket:
    """
    Parse raw bytes into an Ouroboros packet.
    
    Args:
        packet_bytes: Raw packet data
        
    Returns:
        Parsed OuroborosPacket
        
    Raises:
        PacketFormatError: If packet format is invalid
    """
    return OuroborosPacket.from_bytes(packet_bytes)


def extract_header(packet_bytes: bytes) -> PacketHeader:
    """
    Extract just the header from packet bytes without parsing payload.
    
    Args:
        packet_bytes: Raw packet data
        
    Returns:
        Parsed PacketHeader
        
    Raises:
        PacketFormatError: If header format is invalid
    """
    if len(packet_bytes) < HEADER_SIZE:
        raise PacketFormatError(f"Packet too short for header: {len(packet_bytes)} bytes")
    
    header_bytes = packet_bytes[:HEADER_SIZE]
    return PacketHeader.from_bytes(header_bytes)


def validate_packet_format(packet_bytes: bytes) -> bool:
    """
    Validate packet format without full parsing.
    
    Args:
        packet_bytes: Raw packet data
        
    Returns:
        True if packet format is valid
    """
    try:
        parse_packet(packet_bytes)
        return True
    except PacketFormatError:
        return False


def get_payload_slice(packet_bytes: bytes) -> bytes:
    """
    Extract payload bytes without header parsing.
    
    Args:
        packet_bytes: Raw packet data
        
    Returns:
        Payload bytes (scrambled ciphertext)
        
    Raises:
        PacketFormatError: If packet is too short
    """
    if len(packet_bytes) < HEADER_SIZE:
        raise PacketFormatError(f"Packet too short: {len(packet_bytes)} bytes")
    
    return packet_bytes[HEADER_SIZE:]


def create_test_packet(channel_id: int = 42, counter: int = 1, 
                      payload: bytes = b"test") -> OuroborosPacket:
    """
    Create a test packet with dummy values.
    
    Args:
        channel_id: Channel ID (default: 42)
        counter: Message counter (default: 1)
        payload: Test payload (default: b"test")
        
    Returns:
        Test OuroborosPacket
    """
    from ..crypto.utils import generate_random_bytes
    
    r = generate_random_bytes(4)
    tag = generate_random_bytes(16)
    
    return build_packet(channel_id, counter, r, tag, payload)


def packet_summary(packet: OuroborosPacket) -> str:
    """
    Create a human-readable summary of a packet.
    
    Args:
        packet: Packet to summarize
        
    Returns:
        Summary string
    """
    header = packet.header
    return (
        f"Ouroboros Packet:\n"
        f"  Channel ID: {header.channel_id}\n"
        f"  Counter: {header.counter}\n"
        f"  Random (r): {header.r.hex()}\n"
        f"  Tag: {header.tag.hex()}\n"
        f"  Payload size: {len(packet.payload)} bytes\n"
        f"  Total size: {packet.size} bytes"
    )
