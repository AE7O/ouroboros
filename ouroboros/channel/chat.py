"""
Chat messaging channel for Ouroboros Protocol.

Provides secure peer-to-peer chat functionality with message history,
typing indicators, and user presence.
"""

import time
import json
from typing import List, Optional, Dict, Callable
from dataclasses import dataclass, asdict
from datetime import datetime

from ..protocol.session import OuroborosSession
from ..transport.udp import UDPTransport
from ..protocol.packet import PacketType


@dataclass
class ChatMessage:
    """Represents a chat message."""
    sender: str
    recipient: str
    content: str
    timestamp: float
    message_id: str
    message_type: str = "text"  # text, file, typing, presence
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ChatMessage':
        """Create from dictionary."""
        return cls(**data)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ChatMessage':
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


class ChatChannel:
    """
    Secure chat channel using Ouroboros Protocol.
    
    Provides real-time messaging with forward secrecy, replay protection,
    and optional features like typing indicators and file sharing.
    """
    
    def __init__(self, session: OuroborosSession, transport: UDPTransport, user_id: str):
        """
        Initialize chat channel.
        
        Args:
            session: Ouroboros session for encryption/decryption
            transport: UDP transport for network communication
            user_id: Unique identifier for this user
        """
        self.session = session
        self.transport = transport
        self.user_id = user_id
        
        # Message handling
        self.message_history: List[ChatMessage] = []
        self.message_handlers: List[Callable[[ChatMessage], None]] = []
        
        # Presence tracking
        self.online_users: Dict[str, float] = {}  # user_id -> last_seen_timestamp
        
        # Configuration
        self.auto_ack = True
        self.typing_timeout = 3.0  # seconds
        self.presence_interval = 30.0  # seconds
        
        # State
        self.is_running = False
        self._last_presence_broadcast = 0.0
    
    def add_message_handler(self, handler: Callable[[ChatMessage], None]) -> None:
        """Add a message handler callback."""
        self.message_handlers.append(handler)
    
    def remove_message_handler(self, handler: Callable[[ChatMessage], None]) -> None:
        """Remove a message handler callback."""
        if handler in self.message_handlers:
            self.message_handlers.remove(handler)
    
    def send_message(self, content: str, recipient: str) -> ChatMessage:
        """
        Send a chat message.
        
        Args:
            content: Message content
            recipient: Recipient user ID
            
        Returns:
            ChatMessage that was sent
        """
        # Create message
        message = ChatMessage(
            sender=self.user_id,
            recipient=recipient,
            content=content,
            timestamp=time.time(),
            message_id=f"{self.user_id}_{int(time.time()*1000000)}",
            message_type="text"
        )
        
        # Serialize and encrypt
        message_json = message.to_json()
        packet = self.session.encrypt_message(message_json.encode('utf-8'))
        
        # Send over transport
        # Note: In a real implementation, we'd need peer discovery
        # For demo purposes, we'll use a simplified approach
        self.transport.send_packet(packet, "127.0.0.1", 8000)  # Demo address
        
        # Store in history
        self.message_history.append(message)
        
        return message
    
    def send_typing_indicator(self, recipient: str, is_typing: bool = True) -> None:
        """
        Send typing indicator.
        
        Args:
            recipient: Recipient user ID
            is_typing: Whether user is currently typing
        """
        indicator = ChatMessage(
            sender=self.user_id,
            recipient=recipient,
            content="typing" if is_typing else "stopped_typing",
            timestamp=time.time(),
            message_id=f"{self.user_id}_typing_{int(time.time()*1000)}",
            message_type="typing"
        )
        
        # Serialize and send
        message_json = indicator.to_json()
        packet = self.session.encrypt_message(message_json.encode('utf-8'))
        self.transport.send_packet(packet, "127.0.0.1", 8000)  # Demo address
    
    def send_presence_update(self) -> None:
        """Send presence update to announce we're online."""
        presence = ChatMessage(
            sender=self.user_id,
            recipient="*",  # Broadcast
            content="online",
            timestamp=time.time(),
            message_id=f"{self.user_id}_presence_{int(time.time()*1000)}",
            message_type="presence"
        )
        
        # Serialize and send
        message_json = presence.to_json()
        packet = self.session.encrypt_message(message_json.encode('utf-8'))
        self.transport.send_packet(packet, "127.0.0.1", 8000)  # Demo address
        
        self._last_presence_broadcast = time.time()
    
    def receive_messages(self, timeout: float = 1.0) -> List[ChatMessage]:
        """
        Receive and process incoming messages.
        
        Args:
            timeout: Receive timeout in seconds
            
        Returns:
            List of received messages
        """
        received_messages = []
        
        try:
            while True:
                # Receive packet
                packet, sender_addr = self.transport.receive_packet(timeout)
                
                # Decrypt message
                decrypted_data = self.session.decrypt_message(packet)
                message_json = decrypted_data.decode('utf-8')
                message = ChatMessage.from_json(message_json)
                
                # Process based on message type
                if message.message_type == "text":
                    self.message_history.append(message)
                    received_messages.append(message)
                    
                    # Send ACK if enabled
                    if self.auto_ack:
                        ack_packet = self.session.create_ack_packet(packet.counter)
                        self.transport.send_packet(ack_packet, sender_addr[0], sender_addr[1])
                
                elif message.message_type == "typing":
                    # Handle typing indicator
                    received_messages.append(message)
                
                elif message.message_type == "presence":
                    # Update user presence
                    self.online_users[message.sender] = message.timestamp
                    received_messages.append(message)
                
                # Notify handlers
                for handler in self.message_handlers:
                    handler(message)
                
                # Reset timeout for continuous receiving
                timeout = 0.1
                
        except TimeoutError:
            # Normal timeout, return what we received
            pass
        except Exception as e:
            # Log error but don't crash
            print(f"Error receiving message: {e}")
        
        return received_messages
    
    def start_background_services(self) -> None:
        """Start background services like presence broadcasting."""
        self.is_running = True
        
        # Send initial presence
        self.send_presence_update()
    
    def stop_background_services(self) -> None:
        """Stop background services."""
        self.is_running = False
    
    def get_online_users(self) -> List[str]:
        """
        Get list of currently online users.
        
        Returns:
            List of user IDs that are currently online
        """
        current_time = time.time()
        online_threshold = current_time - (self.presence_interval * 2)
        
        online = []
        for user_id, last_seen in self.online_users.items():
            if last_seen > online_threshold:
                online.append(user_id)
        
        return online
    
    def get_message_history(self, with_user: Optional[str] = None, limit: Optional[int] = None) -> List[ChatMessage]:
        """
        Get message history.
        
        Args:
            with_user: Filter messages with specific user (None = all)
            limit: Maximum number of messages (None = all)
            
        Returns:
            List of chat messages
        """
        messages = self.message_history
        
        # Filter by user if specified
        if with_user:
            messages = [
                msg for msg in messages
                if msg.sender == with_user or msg.recipient == with_user
            ]
        
        # Sort by timestamp (most recent last)
        messages = sorted(messages, key=lambda m: m.timestamp)
        
        # Apply limit if specified
        if limit:
            messages = messages[-limit:]
        
        return messages
    
    def clear_history(self) -> None:
        """Clear message history."""
        self.message_history.clear()
    
    def get_stats(self) -> dict:
        """Get chat channel statistics."""
        return {
            'user_id': self.user_id,
            'messages_sent': len([m for m in self.message_history if m.sender == self.user_id]),
            'messages_received': len([m for m in self.message_history if m.sender != self.user_id]),
            'total_messages': len(self.message_history),
            'online_users': len(self.get_online_users()),
            'is_running': self.is_running
        }