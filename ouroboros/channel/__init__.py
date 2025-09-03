"""
Peer-to-peer communication channels for Ouroboros Protocol.

This module provides high-level communication abstractions including:
- Chat messaging
- File transfer
- Interactive demo channels
"""

from .chat import ChatChannel, ChatMessage
from .file_transfer import FileTransferChannel, FileTransfer
from .demo import InteractiveDemoChannel

__all__ = [
    'ChatChannel',
    'ChatMessage', 
    'FileTransferChannel',
    'FileTransfer',
    'InteractiveDemoChannel'
]