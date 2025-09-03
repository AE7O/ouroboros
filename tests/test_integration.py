"""
Integration Tests for Ouroboros Protocol.

Tests end-to-end peer communication, file transfer, and system integration.
"""

import pytest
import os
import tempfile
import threading
import time
import socket
from typing import List, Tuple
from ouroboros.crypto.ratchet import generate_root_key
from ouroboros.protocol.encryptor import OuroborosEncryptor
from ouroboros.protocol.decryptor import OuroborosDecryptor
from ouroboros.protocol.packet import OuroborosPacket


class MockNetworkChannel:
    """Mock network channel for testing peer communication."""
    
    def __init__(self):
        self.sent_packets = []
        self.received_packets = []
        self.connected_peer = None
        self.latency = 0.0  # Simulated network latency
        self.packet_loss_rate = 0.0  # Simulated packet loss
        self.corruption_rate = 0.0  # Simulated corruption
    
    def connect_to(self, peer: 'MockNetworkChannel'):
        """Connect this channel to a peer."""
        self.connected_peer = peer
        peer.connected_peer = self
    
    def send_packet(self, packet: OuroborosPacket) -> bool:
        """Send a packet to the connected peer."""
        if not self.connected_peer:
            return False
        
        self.sent_packets.append(packet)
        
        # Simulate packet loss
        import random
        if random.random() < self.packet_loss_rate:
            return False
        
        # Simulate corruption
        if random.random() < self.corruption_rate:
            # Corrupt a random byte in scrambled data
            if packet.scrambled_data:
                corrupted_data = bytearray(packet.scrambled_data)
                if corrupted_data:
                    corrupted_data[random.randint(0, len(corrupted_data) - 1)] ^= 0x01
                    packet.scrambled_data = bytes(corrupted_data)
        
        # Simulate latency
        if self.latency > 0:
            threading.Timer(self.latency, lambda: self.connected_peer._receive_packet(packet)).start()
        else:
            self.connected_peer._receive_packet(packet)
        
        return True
    
    def _receive_packet(self, packet: OuroborosPacket):
        """Receive a packet from a peer."""
        self.received_packets.append(packet)
    
    def get_received_packets(self) -> List[OuroborosPacket]:
        """Get all received packets."""
        packets = self.received_packets.copy()
        self.received_packets.clear()
        return packets


class SecurePeer:
    """A secure peer using Ouroboros protocol."""
    
    def __init__(self, peer_id: str, root_key: bytes, channel_id: int = 0):
        self.peer_id = peer_id
        self.channel_id = channel_id
        self.encryptor = OuroborosEncryptor(root_key, channel_id, use_ratcheting=False)
        self.decryptor = OuroborosDecryptor(root_key, channel_id, use_ratcheting=False)
        self.network = MockNetworkChannel()
        self.received_messages = []
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'encryption_errors': 0,
            'decryption_errors': 0
        }
    
    def connect_to(self, peer: 'SecurePeer'):
        """Connect to another peer."""
        self.network.connect_to(peer.network)
    
    def send_message(self, message: bytes) -> bool:
        """Send a secure message to the connected peer."""
        try:
            packet = self.encryptor.encrypt_message(message)
            success = self.network.send_packet(packet)
            if success:
                self.stats['messages_sent'] += 1
            return success
        except Exception:
            self.stats['encryption_errors'] += 1
            return False
    
    def process_received_packets(self):
        """Process all received packets and extract messages."""
        packets = self.network.get_received_packets()
        
        for packet in packets:
            try:
                message = self.decryptor.decrypt_packet(packet)
                self.received_messages.append(message)
                self.stats['messages_received'] += 1
            except Exception:
                self.stats['decryption_errors'] += 1
    
    def get_received_messages(self) -> List[bytes]:
        """Get all received messages."""
        self.process_received_packets()
        messages = self.received_messages.copy()
        self.received_messages.clear()
        return messages


class TestPeerToPeerCommunication:
    """Test peer-to-peer communication."""
    
    def test_basic_peer_communication(self):
        """Test basic message exchange between two peers."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key, channel_id=1)
        peer_b = SecurePeer("Bob", root_key, channel_id=1)
        
        peer_a.connect_to(peer_b)
        
        # Send message from A to B
        message = b"Hello, Bob!"
        assert peer_a.send_message(message)
        
        # Process received messages
        received = peer_b.get_received_messages()
        assert len(received) == 1
        assert received[0] == message
        
        # Send response from B to A
        response = b"Hello, Alice!"
        assert peer_b.send_message(response)
        
        received = peer_a.get_received_messages()
        assert len(received) == 1
        assert received[0] == response
    
    def test_multiple_message_exchange(self):
        """Test exchange of multiple messages."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key)
        peer_b = SecurePeer("Bob", root_key)
        
        peer_a.connect_to(peer_b)
        
        # Send multiple messages
        messages_a_to_b = [
            b"Message 1 from Alice",
            b"Message 2 from Alice",
            b"Message 3 from Alice"
        ]
        
        messages_b_to_a = [
            b"Response 1 from Bob",
            b"Response 2 from Bob"
        ]
        
        # Send messages from A to B
        for msg in messages_a_to_b:
            assert peer_a.send_message(msg)
        
        # Send messages from B to A
        for msg in messages_b_to_a:
            assert peer_b.send_message(msg)
        
        # Check received messages
        received_by_b = peer_b.get_received_messages()
        received_by_a = peer_a.get_received_messages()
        
        assert received_by_b == messages_a_to_b
        assert received_by_a == messages_b_to_a
    
    def test_bidirectional_communication(self):
        """Test simultaneous bidirectional communication."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key)
        peer_b = SecurePeer("Bob", root_key)
        
        peer_a.connect_to(peer_b)
        
        # Send messages simultaneously
        messages_count = 10
        
        for i in range(messages_count):
            peer_a.send_message(f"Message {i} from Alice".encode())
            peer_b.send_message(f"Message {i} from Bob".encode())
        
        # Process all messages
        received_by_a = peer_a.get_received_messages()
        received_by_b = peer_b.get_received_messages()
        
        assert len(received_by_a) == messages_count
        assert len(received_by_b) == messages_count
        
        # Check message ordering and content
        for i in range(messages_count):
            assert received_by_a[i] == f"Message {i} from Bob".encode()
            assert received_by_b[i] == f"Message {i} from Alice".encode()
    
    def test_different_channel_isolation(self):
        """Test that different channels are isolated."""
        root_key = generate_root_key()
        
        # Create peers on different channels
        peer_a1 = SecurePeer("Alice-Ch1", root_key, channel_id=1)
        peer_b1 = SecurePeer("Bob-Ch1", root_key, channel_id=1)
        peer_a2 = SecurePeer("Alice-Ch2", root_key, channel_id=2)
        peer_b2 = SecurePeer("Bob-Ch2", root_key, channel_id=2)
        
        # Connect same-channel peers
        peer_a1.connect_to(peer_b1)
        peer_a2.connect_to(peer_b2)
        
        # Send messages on both channels
        peer_a1.send_message(b"Channel 1 message")
        peer_a2.send_message(b"Channel 2 message")
        
        # Check isolation
        received_b1 = peer_b1.get_received_messages()
        received_b2 = peer_b2.get_received_messages()
        
        assert len(received_b1) == 1
        assert len(received_b2) == 1
        assert received_b1[0] == b"Channel 1 message"
        assert received_b2[0] == b"Channel 2 message"


class TestNetworkConditions:
    """Test protocol behavior under various network conditions."""
    
    def test_packet_loss_resilience(self):
        """Test resilience to packet loss."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key)
        peer_b = SecurePeer("Bob", root_key)
        
        peer_a.connect_to(peer_b)
        
        # Simulate 20% packet loss
        peer_a.network.packet_loss_rate = 0.2
        peer_b.network.packet_loss_rate = 0.2
        
        # Send many messages
        sent_count = 50
        messages_sent = []
        
        for i in range(sent_count):
            message = f"Message {i}".encode()
            messages_sent.append(message)
            peer_a.send_message(message)
        
        # Process received messages
        received = peer_b.get_received_messages()
        
        # Should receive some messages despite packet loss
        assert len(received) > 0
        assert len(received) < sent_count  # Some should be lost
        
        # Received messages should be correct
        for msg in received:
            assert msg in messages_sent
    
    def test_network_latency(self):
        """Test protocol behavior with network latency."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key)
        peer_b = SecurePeer("Bob", root_key)
        
        peer_a.connect_to(peer_b)
        
        # Simulate 100ms latency
        peer_a.network.latency = 0.1
        peer_b.network.latency = 0.1
        
        # Send message
        message = b"Delayed message"
        peer_a.send_message(message)
        
        # Should not be received immediately
        received = peer_b.get_received_messages()
        assert len(received) == 0
        
        # Wait for latency
        time.sleep(0.15)
        
        # Should be received now
        received = peer_b.get_received_messages()
        assert len(received) == 1
        assert received[0] == message
    
    def test_corruption_detection(self):
        """Test detection of corrupted packets."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key)
        peer_b = SecurePeer("Bob", root_key)
        
        peer_a.connect_to(peer_b)
        
        # Simulate 50% corruption rate
        peer_a.network.corruption_rate = 0.5
        
        # Send many messages
        sent_count = 20
        for i in range(sent_count):
            peer_a.send_message(f"Message {i}".encode())
        
        # Process received messages
        received = peer_b.get_received_messages()
        
        # Should receive fewer messages due to corruption detection
        assert len(received) < sent_count
        assert peer_b.stats['decryption_errors'] > 0


class TestFileTransfer:
    """Test file transfer functionality."""
    
    def test_small_file_transfer(self):
        """Test transfer of a small file."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key)
        peer_b = SecurePeer("Bob", root_key)
        
        peer_a.connect_to(peer_b)
        
        # Create test file content
        file_content = b"This is a test file content for secure transfer."
        
        # Send file content
        peer_a.send_message(file_content)
        
        # Receive and verify
        received = peer_b.get_received_messages()
        assert len(received) == 1
        assert received[0] == file_content
    
    def test_large_file_transfer(self):
        """Test transfer of a larger file in chunks."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key)
        peer_b = SecurePeer("Bob", root_key)
        
        peer_a.connect_to(peer_b)
        
        # Create large file content (10KB)
        file_content = os.urandom(10240)
        
        # Split into chunks
        chunk_size = 1024
        chunks = [file_content[i:i+chunk_size] for i in range(0, len(file_content), chunk_size)]
        
        # Send chunks
        for chunk in chunks:
            peer_a.send_message(chunk)
        
        # Receive and reassemble
        received_chunks = peer_b.get_received_messages()
        assert len(received_chunks) == len(chunks)
        
        reconstructed = b''.join(received_chunks)
        assert reconstructed == file_content
    
    def test_concurrent_file_transfers(self):
        """Test multiple concurrent file transfers."""
        root_key = generate_root_key()
        
        # Create multiple peer pairs
        peers = []
        for i in range(3):
            peer_a = SecurePeer(f"Sender-{i}", root_key, channel_id=i)
            peer_b = SecurePeer(f"Receiver-{i}", root_key, channel_id=i)
            peer_a.connect_to(peer_b)
            peers.append((peer_a, peer_b))
        
        # Create different file contents
        files = [
            b"File 1 content",
            b"File 2 has different content",
            b"File 3 is yet another file"
        ]
        
        # Send files concurrently
        for (sender, receiver), file_content in zip(peers, files):
            sender.send_message(file_content)
        
        # Verify all transfers
        for (sender, receiver), expected_content in zip(peers, files):
            received = receiver.get_received_messages()
            assert len(received) == 1
            assert received[0] == expected_content


class TestSystemIntegration:
    """Test system-level integration scenarios."""
    
    def test_multi_peer_network(self):
        """Test communication in a multi-peer network."""
        root_key = generate_root_key()
        
        # Create multiple peers
        peers = []
        for i in range(5):
            peer = SecurePeer(f"Peer-{i}", root_key, channel_id=0)
            peers.append(peer)
        
        # Connect in a mesh (each peer connects to next one in cycle)
        for i in range(len(peers)):
            next_peer = peers[(i + 1) % len(peers)]
            peers[i].connect_to(next_peer)
        
        # Each peer sends a message to its connected peer
        for i, peer in enumerate(peers):
            message = f"Message from Peer-{i}".encode()
            peer.send_message(message)
        
        # Verify message delivery
        for i, peer in enumerate(peers):
            received = peer.get_received_messages()
            expected_sender = (i - 1) % len(peers)
            expected_message = f"Message from Peer-{expected_sender}".encode()
            
            assert len(received) == 1
            assert received[0] == expected_message
    
    def test_session_statistics(self):
        """Test collection of session statistics."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key)
        peer_b = SecurePeer("Bob", root_key)
        
        peer_a.connect_to(peer_b)
        
        # Send several messages
        message_count = 10
        for i in range(message_count):
            peer_a.send_message(f"Message {i}".encode())
        
        # Process messages
        peer_b.get_received_messages()
        
        # Check statistics
        assert peer_a.stats['messages_sent'] == message_count
        assert peer_b.stats['messages_received'] == message_count
        assert peer_a.stats['encryption_errors'] == 0
        assert peer_b.stats['decryption_errors'] == 0
    
    def test_error_recovery(self):
        """Test error recovery and resilience."""
        root_key = generate_root_key()
        
        peer_a = SecurePeer("Alice", root_key)
        peer_b = SecurePeer("Bob", root_key)
        
        peer_a.connect_to(peer_b)
        
        # Send some normal messages
        peer_a.send_message(b"Normal message 1")
        peer_a.send_message(b"Normal message 2")
        
        # Introduce corruption
        peer_a.network.corruption_rate = 1.0  # 100% corruption
        
        # Try to send corrupted messages
        peer_a.send_message(b"Corrupted message 1")
        peer_a.send_message(b"Corrupted message 2")
        
        # Remove corruption
        peer_a.network.corruption_rate = 0.0
        
        # Send more normal messages
        peer_a.send_message(b"Normal message 3")
        peer_a.send_message(b"Normal message 4")
        
        # Check that only non-corrupted messages were received
        received = peer_b.get_received_messages()
        expected_messages = [
            b"Normal message 1",
            b"Normal message 2",
            b"Normal message 3",
            b"Normal message 4"
        ]
        
        assert received == expected_messages
        assert peer_b.stats['decryption_errors'] == 2  # Two corrupted messages


if __name__ == "__main__":
    pytest.main([__file__, "-v"])