"""
Channel layer components for Ouroboros Protocol.

This module provides networking and communication functionality including:
- UDP socket I/O operations
- Peer-to-peer connection management
- Interactive CLI interface for demos
"""

from .io import SocketManager, create_udp_endpoint
from .peer import PeerConnection, create_peer_connection
from .interactive import InteractiveChat

__all__ = [
    'SocketManager',
    'create_udp_endpoint',
    'PeerConnection',
    'create_peer_connection',
    'InteractiveChat'
]