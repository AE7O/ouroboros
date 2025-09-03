"""
Peer-to-peer communication for Ouroboros Protocol.

Implements secure P2P chat and file transfer functionality.
"""

import threading
import time
import queue
from typing import Dict, List, Optional, Callable
from ..crypto.ratchet import generate_root_key
from ..protocol.encryptor import OuroborosEncryptor
from ..protocol.decryptor import OuroborosDecryptor
from ..protocol.packet import OuroborosPacket


class PeerError(Exception):
    """Raised when peer operations fail."""
    pass


class MessageHandler:
    """Handler for different types of messages."""
    
    def __init__(self):
        self.handlers: Dict[str, Callable] = {}
    
    def register(self, message_type: str, handler: Callable):
        """Register a handler for a message type."""
        self.handlers[message_type] = handler
    
    def handle(self, message_type: str, data: bytes, sender_id: str):
        """Handle a message of the given type."""
        if message_type in self.handlers:
            self.handlers[message_type](data, sender_id)


class SecurePeer:
    """
    A secure peer capable of P2P communication using Ouroboros protocol.
    
    Supports text chat, file transfer, and custom message handlers.
    """
    
    def __init__(self, peer_id: str, root_key: bytes, channel_id: int = 0):
        """
        Initialize secure peer.
        
        Args:
            peer_id: Unique identifier for this peer
            root_key: Shared root key for encryption
            channel_id: Communication channel ID
        """
        self.peer_id = peer_id
        self.channel_id = channel_id
        self.root_key = root_key
        
        # Crypto components
        self.encryptor = OuroborosEncryptor(root_key, channel_id, use_ratcheting=False)
        self.decryptor = OuroborosDecryptor(root_key, channel_id, use_ratcheting=False)
        
        # Communication
        self.connected_peers: Dict[str, 'SecurePeer'] = {}
        self.message_queue = queue.Queue()
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None
        
        # Message handling
        self.message_handler = MessageHandler()
        self._setup_default_handlers()
        
        # Statistics
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'encryption_errors': 0,
            'decryption_errors': 0,
            'connection_time': time.time()
        }
        
        # Chat and file transfer
        self.chat_messages: List[Dict] = []
        self.file_transfers: Dict[str, Dict] = {}
    
    def _setup_default_handlers(self):
        """Setup default message handlers."""
        self.message_handler.register('chat', self._handle_chat_message)
        self.message_handler.register('file_chunk', self._handle_file_chunk)
        self.message_handler.register('file_info', self._handle_file_info)
        self.message_handler.register('ping', self._handle_ping)
        self.message_handler.register('pong', self._handle_pong)
    
    def connect_to(self, peer: 'SecurePeer'):
        """Connect to another peer."""
        self.connected_peers[peer.peer_id] = peer
        peer.connected_peers[self.peer_id] = self
    
    def start(self):
        """Start the peer's message processing."""
        if self.running:
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._message_worker, daemon=True)
        self.worker_thread.start()
    
    def stop(self):
        """Stop the peer's message processing."""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=1.0)
    
    def process_received_messages(self):
        """Process all received messages synchronously."""
        while not self.message_queue.empty():
            try:
                message_data = self.message_queue.get_nowait()
                self._process_received_message(message_data)
                self.message_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error processing message: {e}")
    
    def _message_worker(self):
        """Background worker for processing messages."""
        while self.running:
            try:
                # Process messages from queue with timeout
                try:
                    message_data = self.message_queue.get(timeout=0.1)
                    self._process_received_message(message_data)
                    self.message_queue.task_done()
                except queue.Empty:
                    continue
            except Exception as e:
                print(f"Error in message worker for {self.peer_id}: {e}")
    
    def send_message(self, target_peer_id: str, message_type: str, data: bytes) -> bool:
        """
        Send a message to a specific peer.
        
        Args:
            target_peer_id: ID of target peer
            message_type: Type of message
            data: Message data
            
        Returns:
            True if message was sent successfully
        """
        if target_peer_id not in self.connected_peers:
            return False
        
        try:
            # Create message with type header
            full_message = f"{message_type}:".encode() + data
            
            # Encrypt message
            packet = self.encryptor.encrypt_message(full_message)
            
            # Send to target peer
            target_peer = self.connected_peers[target_peer_id]
            target_peer._receive_packet(packet, self.peer_id)
            
            self.stats['messages_sent'] += 1
            self.stats['bytes_sent'] += len(data)
            
            return True
            
        except Exception as e:
            self.stats['encryption_errors'] += 1
            return False
    
    def _receive_packet(self, packet: OuroborosPacket, sender_id: str):
        """Receive a packet from another peer."""
        self.message_queue.put((packet, sender_id))
    
    def _process_received_message(self, message_data):
        """Process a received message."""
        packet, sender_id = message_data
        
        try:
            # Decrypt message
            decrypted = self.decryptor.decrypt_packet(packet)
            
            # Parse message type
            if b':' in decrypted:
                message_type, data = decrypted.split(b':', 1)
                message_type = message_type.decode()
            else:
                message_type = 'raw'
                data = decrypted
            
            # Handle message
            self.message_handler.handle(message_type, data, sender_id)
            
            self.stats['messages_received'] += 1
            self.stats['bytes_received'] += len(data)
            
        except Exception as e:
            self.stats['decryption_errors'] += 1
    
    def send_chat_message(self, target_peer_id: str, message: str) -> bool:
        """Send a chat message to a peer."""
        return self.send_message(target_peer_id, 'chat', message.encode('utf-8'))
    
    def send_file(self, target_peer_id: str, filename: str, file_data: bytes, chunk_size: int = 1024) -> bool:
        """
        Send a file to a peer in chunks.
        
        Args:
            target_peer_id: Target peer ID
            filename: Name of the file
            file_data: File content
            chunk_size: Size of each chunk
            
        Returns:
            True if file transfer was initiated successfully
        """
        # Send file info first
        file_info = f"{filename}:{len(file_data)}".encode()
        if not self.send_message(target_peer_id, 'file_info', file_info):
            return False
        
        # Send file chunks
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i + chunk_size]
            chunk_header = f"{filename}:{i}:".encode()
            chunk_data = chunk_header + chunk
            
            if not self.send_message(target_peer_id, 'file_chunk', chunk_data):
                return False
        
        return True
    
    def ping_peer(self, target_peer_id: str) -> bool:
        """Send a ping to a peer."""
        ping_data = str(time.time()).encode()
        return self.send_message(target_peer_id, 'ping', ping_data)
    
    def _handle_chat_message(self, data: bytes, sender_id: str):
        """Handle received chat message."""
        try:
            message = data.decode('utf-8')
            chat_entry = {
                'sender': sender_id,
                'message': message,
                'timestamp': time.time()
            }
            self.chat_messages.append(chat_entry)
        except Exception as e:
            print(f"Error handling chat message: {e}")
    
    def _handle_file_info(self, data: bytes, sender_id: str):
        """Handle file transfer info."""
        try:
            info = data.decode('utf-8')
            filename, size_str = info.split(':', 1)
            size = int(size_str)
            
            # Initialize file transfer tracking
            transfer_id = f"{sender_id}:{filename}"
            self.file_transfers[transfer_id] = {
                'filename': filename,
                'total_size': size,
                'received_size': 0,
                'chunks': {},
                'sender': sender_id,
                'start_time': time.time()
            }
        except Exception as e:
            print(f"Error handling file info: {e}")
    
    def _handle_file_chunk(self, data: bytes, sender_id: str):
        """Handle file chunk."""
        try:
            # Parse chunk header
            header_end = data.find(b':', data.find(b':') + 1) + 1
            header = data[:header_end].decode('utf-8')
            chunk_data = data[header_end:]
            
            parts = header.split(':')
            filename = parts[0]
            offset = int(parts[1])
            
            transfer_id = f"{sender_id}:{filename}"
            
            if transfer_id in self.file_transfers:
                transfer = self.file_transfers[transfer_id]
                transfer['chunks'][offset] = chunk_data
                transfer['received_size'] += len(chunk_data)
                
                # Check if transfer is complete
                if transfer['received_size'] >= transfer['total_size']:
                    self._complete_file_transfer(transfer_id)
                    
        except Exception as e:
            print(f"Error handling file chunk: {e}")
    
    def _complete_file_transfer(self, transfer_id: str):
        """Complete a file transfer by reassembling chunks."""
        try:
            transfer = self.file_transfers[transfer_id]
            
            # Sort chunks by offset and reassemble
            sorted_offsets = sorted(transfer['chunks'].keys())
            file_data = b''.join(transfer['chunks'][offset] for offset in sorted_offsets)
            
            # Mark transfer as complete
            transfer['completed'] = True
            transfer['file_data'] = file_data
            transfer['completion_time'] = time.time()
            
        except Exception as e:
            print(f"Error completing file transfer: {e}")
    
    def _handle_ping(self, data: bytes, sender_id: str):
        """Handle ping message."""
        # Send pong response
        self.send_message(sender_id, 'pong', data)
    
    def _handle_pong(self, data: bytes, sender_id: str):
        """Handle pong message."""
        try:
            sent_time = float(data.decode())
            rtt = time.time() - sent_time
            print(f"Pong from {sender_id}: RTT = {rtt*1000:.1f} ms")
        except Exception:
            pass
    
    def get_chat_messages(self) -> List[Dict]:
        """Get all chat messages."""
        return self.chat_messages.copy()
    
    def get_completed_files(self) -> Dict[str, bytes]:
        """Get all completed file transfers."""
        completed = {}
        for transfer_id, transfer in self.file_transfers.items():
            if transfer.get('completed', False):
                completed[transfer['filename']] = transfer['file_data']
        return completed
    
    def get_stats(self) -> Dict:
        """Get peer statistics."""
        stats = self.stats.copy()
        stats['uptime'] = time.time() - stats['connection_time']
        stats['connected_peers'] = len(self.connected_peers)
        stats['active_transfers'] = len([t for t in self.file_transfers.values() if not t.get('completed', False)])
        return stats


class PeerNetwork:
    """A network of connected peers."""
    
    def __init__(self):
        self.peers: Dict[str, SecurePeer] = {}
        self.root_key = generate_root_key()
    
    def add_peer(self, peer_id: str, channel_id: int = 0) -> SecurePeer:
        """Add a new peer to the network."""
        peer = SecurePeer(peer_id, self.root_key, channel_id)
        self.peers[peer_id] = peer
        return peer
    
    def connect_peers(self, peer_id1: str, peer_id2: str):
        """Connect two peers in the network."""
        if peer_id1 in self.peers and peer_id2 in self.peers:
            self.peers[peer_id1].connect_to(self.peers[peer_id2])
    
    def start_all(self):
        """Start all peers in the network."""
        for peer in self.peers.values():
            peer.start()
    
    def stop_all(self):
        """Stop all peers in the network."""
        for peer in self.peers.values():
            peer.stop()
    
    def get_network_stats(self) -> Dict:
        """Get statistics for the entire network."""
        stats = {
            'total_peers': len(self.peers),
            'total_messages': sum(p.stats['messages_sent'] for p in self.peers.values()),
            'total_bytes': sum(p.stats['bytes_sent'] for p in self.peers.values()),
            'active_peers': sum(1 for p in self.peers.values() if p.running)
        }
        return stats