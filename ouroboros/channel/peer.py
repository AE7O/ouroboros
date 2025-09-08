"""
Peer-to-peer communication logic for Ouroboros Protocol.

This module implements secure peer-to-peer communication including:
- Chat messaging
- File transfer capabilities
- Connection management
"""

import os
import time
import socket
from typing import Optional, Callable, Dict, Any
from pathlib import Path

from ..crypto.utils import generate_random_bytes
from ..protocol.encryptor import create_encryption_context
from ..protocol.decryptor import create_decryption_context
from .io import SocketManager, create_udp_endpoint

class SocketError(Exception):
    """Socket operation error."""
    pass


class PeerConnection:
    """
    Manages a secure peer-to-peer connection using Ouroboros Protocol.
    """
    
    def __init__(self, master_psk: bytes, channel_id: int, 
                 local_addr: tuple, remote_addr: tuple, use_ascon: bool = False):
        """
        Initialize peer connection.
        
        Args:
            master_psk: 32-byte pre-shared key
            channel_id: Channel identifier
            local_addr: (host, port) for local binding
            remote_addr: (host, port) for remote peer
            use_ascon: Whether to use ASCON algorithms
        """
        self.master_psk = master_psk
        self.channel_id = channel_id
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.use_ascon = use_ascon
        
        # Create encryption/decryption contexts
        self.encrypt_ctx = create_encryption_context(master_psk, channel_id, use_ascon)
        self.decrypt_ctx = create_decryption_context(master_psk, channel_id, use_ascon)
        
        # Initialize socket with local address
        self.socket = SocketManager(bind_port=local_addr[1], bind_address=local_addr[0])
        self.connected = False
        
        # Message handlers
        self.message_handler: Optional[Callable[[str], None]] = None
        self.file_handler: Optional[Callable[[str, bytes], None]] = None
        
    def connect(self) -> None:
        """Establish connection to remote peer."""
        try:
            self.socket.start()
            self.connected = True
            print(f"Socket started on port {self.socket.actual_port}, communicating with {self.remote_addr}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect: {e}")
    
    def disconnect(self) -> None:
        """Close connection."""
        if self.connected:
            self.socket.stop()
            self.connected = False
    
    def send_message(self, message: str) -> None:
        """
        Send a text message to the remote peer.
        
        Args:
            message: Text message to send
        """
        if not self.connected:
            raise ConnectionError("Not connected")
        
        # Prepare message with type prefix
        payload = b"MSG:" + message.encode('utf-8')
        
        # Encrypt and send
        packet = self.encrypt_ctx.encrypt_message(payload)
        packet_bytes = packet.to_bytes()
        
        success = self.socket.send_packet(packet_bytes, self.remote_addr)
        if not success:
            raise RuntimeError(f"Failed to send message to {self.remote_addr}")
    
    def send_file(self, file_path: str) -> None:
        """
        Send a file to the remote peer.
        
        Args:
            file_path: Path to file to send
        """
        if not self.connected:
            raise ConnectionError("Not connected")
        
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read file data
        with open(path, 'rb') as f:
            file_data = f.read()
        
        # Prepare file message with metadata
        file_name = path.name
        payload = f"FILE:{file_name}:".encode('utf-8') + file_data
        
        # Encrypt and send
        packet = self.encrypt_ctx.encrypt_message(payload)
        packet_bytes = packet.to_bytes()
        
        success = self.socket.send_packet(packet_bytes, self.remote_addr)
        if not success:
            raise RuntimeError(f"Failed to send file to {self.remote_addr}")
        print(f"Sent file: {file_name} ({len(file_data)} bytes)")
    
    def receive_messages(self, timeout: float = 1.0) -> None:
        """
        Receive and process incoming messages.
        
        Args:
            timeout: Receive timeout in seconds
        """
        if not self.connected:
            raise ConnectionError("Not connected")
        
        try:
            # Get received packets from the socket manager
            packets = self.socket.get_received_packets(timeout=timeout)
            
            for packet_bytes, addr in packets:
                # Verify sender (allow localhost/127.0.0.1 equivalence)
                expected_host, expected_port = self.remote_addr
                actual_host, actual_port = addr
                
                # Normalize localhost
                if expected_host == 'localhost':
                    expected_host = '127.0.0.1'
                if actual_host == 'localhost':
                    actual_host = '127.0.0.1'
                    
                if (actual_host, actual_port) != (expected_host, expected_port):
                    print(f"Warning: Received packet from unexpected address {addr}")
                    continue
                
                # Decrypt packet
                try:
                    payload = self.decrypt_ctx.decrypt_packet(packet_bytes)
                    self._process_payload(payload)
                except Exception as e:
                    print(f"Failed to decrypt packet: {e}")
                    
        except Exception:
            # Timeout or other socket error - normal in non-blocking mode
            pass
    
    def _process_payload(self, payload: bytes) -> None:
        """Process decrypted payload based on message type."""
        try:
            if payload.startswith(b"MSG:"):
                # Text message
                message = payload[4:].decode('utf-8')
                if self.message_handler:
                    self.message_handler(message)
                else:
                    print(f"Peer: {message}")
            
            elif payload.startswith(b"FILE:"):
                # File transfer
                content = payload[5:]
                # Find filename separator
                sep_idx = content.find(b':')
                if sep_idx > 0:
                    file_name = content[:sep_idx].decode('utf-8')
                    file_data = content[sep_idx + 1:]
                    
                    if self.file_handler:
                        self.file_handler(file_name, file_data)
                    else:
                        # Save file to current directory
                        with open(file_name, 'wb') as f:
                            f.write(file_data)
                        print(f"Received file: {file_name} ({len(file_data)} bytes)")
            
            else:
                print(f"Unknown message type: {payload[:10]}...")
                
        except Exception as e:
            print(f"Error processing payload: {e}")
    
    def set_message_handler(self, handler: Callable[[str], None]) -> None:
        """Set custom message handler."""
        self.message_handler = handler
    
    def set_file_handler(self, handler: Callable[[str, bytes], None]) -> None:
        """Set custom file handler."""
        self.file_handler = handler
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        return {
            'channel_id': self.channel_id,
            'algorithm': 'ASCON' if self.use_ascon else 'AES-GCM',
            'local_addr': self.local_addr,
            'remote_addr': self.remote_addr,
            'connected': self.connected,
            'packets_sent': getattr(self.encrypt_ctx, 'counter', 0),
        }


def create_peer_connection(master_psk: bytes, channel_id: int,
                          local_port: int, remote_host: str, remote_port: int,
                          use_ascon: bool = False) -> PeerConnection:
    """
    Create a peer connection with simplified addressing.
    
    Args:
        master_psk: 32-byte pre-shared key
        channel_id: Channel identifier
        local_port: Local port to bind to
        remote_host: Remote peer hostname/IP
        remote_port: Remote peer port
        use_ascon: Whether to use ASCON algorithms
        
    Returns:
        Configured PeerConnection
    """
    local_addr = ('localhost', local_port)
    remote_addr = (remote_host, remote_port)
    
    return PeerConnection(master_psk, channel_id, local_addr, remote_addr, use_ascon)


def demo_file_transfer():
    """Demo function showing file transfer capability."""
    # Generate shared key
    master_psk = generate_random_bytes(32)
    
    # Create test file
    test_data = b"Hello from Ouroboros file transfer!\nThis is a test file."
    with open('/tmp/test_file.txt', 'wb') as f:
        f.write(test_data)
    
    print("File transfer demo would require two processes.")
    print("Run this with two instances to test peer-to-peer file transfer.")


if __name__ == "__main__":
    demo_file_transfer()
