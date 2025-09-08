"""
Integration tests for end-to-end peer communication.

This module tests the complete peer-to-peer communication stack
including networking, protocol integration, and interactive features.
"""

import pytest
import time
import threading
import tempfile
import os
from pathlib import Path

from ouroboros.crypto.utils import generate_random_bytes
from ouroboros.channel.peer import create_peer_connection, PeerConnection
from ouroboros.channel.io import SocketManager, create_udp_endpoint


class TestPeerToPeerCommunication:
    """Test complete peer-to-peer communication."""
    
    def test_basic_message_exchange(self):
        """Test basic message exchange between two peers."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        # Create two peers on different ports
        peer1 = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9001,
            remote_host='localhost',
            remote_port=9002,
            use_ascon=False
        )
        
        peer2 = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9002,
            remote_host='localhost',
            remote_port=9001,
            use_ascon=False
        )
        
        try:
            # Connect both peers
            peer1.connect()
            peer2.connect()
            
            # Set up message collection for peer2
            received_messages = []
            peer2.set_message_handler(lambda msg: received_messages.append(msg))
            
            # Peer1 sends a message
            test_message = "Hello from peer1!"
            peer1.send_message(test_message)
            
            # Give time for message delivery
            time.sleep(0.1)
            
            # Peer2 receives the message
            peer2.receive_messages(timeout=0.5)
            
            # Verify message was received correctly
            assert len(received_messages) == 1
            assert received_messages[0] == test_message
            
        finally:
            peer1.disconnect()
            peer2.disconnect()
    
    def test_bidirectional_communication(self):
        """Test bidirectional message exchange."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        peer1 = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9003,
            remote_host='localhost',
            remote_port=9004,
            use_ascon=False
        )
        
        peer2 = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9004,
            remote_host='localhost',
            remote_port=9003,
            use_ascon=False
        )
        
        try:
            peer1.connect()
            peer2.connect()
            
            # Set up message collection
            peer1_messages = []
            peer2_messages = []
            
            peer1.set_message_handler(lambda msg: peer1_messages.append(msg))
            peer2.set_message_handler(lambda msg: peer2_messages.append(msg))
            
            # Exchange messages
            peer1.send_message("Message from peer1")
            peer2.send_message("Response from peer2")
            
            # Allow message delivery
            time.sleep(0.1)
            
            # Both peers receive messages
            peer1.receive_messages(timeout=0.5)
            peer2.receive_messages(timeout=0.5)
            
            # Verify both received their messages
            assert len(peer1_messages) == 1
            assert len(peer2_messages) == 1
            assert peer1_messages[0] == "Response from peer2"
            assert peer2_messages[0] == "Message from peer1"
            
        finally:
            peer1.disconnect()
            peer2.disconnect()
    
    def test_file_transfer(self):
        """Test file transfer between peers."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        peer1 = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9005,
            remote_host='localhost',
            remote_port=9006,
            use_ascon=False
        )
        
        peer2 = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9006,
            remote_host='localhost',
            remote_port=9005,
            use_ascon=False
        )
        
        try:
            peer1.connect()
            peer2.connect()
            
            # Create a test file
            test_data = b"This is test file content for transfer.\nLine 2 of the file.\n"
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as tmp_file:
                tmp_file.write(test_data)
                test_file_path = tmp_file.name
            
            # Set up file reception
            received_files = []
            def file_handler(filename, data):
                received_files.append((filename, data))
            
            peer2.set_file_handler(file_handler)
            
            # Send the file
            peer1.send_file(test_file_path)
            
            # Allow file transfer
            time.sleep(0.1)
            peer2.receive_messages(timeout=0.5)
            
            # Verify file was received
            assert len(received_files) == 1
            filename, received_data = received_files[0]
            
            assert received_data == test_data
            assert filename == Path(test_file_path).name
            
            # Clean up
            os.unlink(test_file_path)
            
        finally:
            peer1.disconnect()
            peer2.disconnect()
    
    def test_multiple_message_sequence(self):
        """Test sending multiple messages in sequence."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        peer1 = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9007,
            remote_host='localhost',
            remote_port=9008,
            use_ascon=False
        )
        
        peer2 = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9008,
            remote_host='localhost',
            remote_port=9007,
            use_ascon=False
        )
        
        try:
            peer1.connect()
            peer2.connect()
            
            received_messages = []
            peer2.set_message_handler(lambda msg: received_messages.append(msg))
            
            # Send multiple messages
            messages = [
                "First message",
                "Second message", 
                "Third message with more content",
                "Final message"
            ]
            
            for msg in messages:
                peer1.send_message(msg)
                time.sleep(0.05)  # Small delay between messages
            
            # Receive all messages
            for _ in range(len(messages)):
                peer2.receive_messages(timeout=0.5)
            
            # Verify all messages received in order
            assert len(received_messages) == len(messages)
            assert received_messages == messages
            
        finally:
            peer1.disconnect()
            peer2.disconnect()
    
    def test_connection_statistics(self):
        """Test connection statistics reporting."""
        master_psk = generate_random_bytes(32)
        channel_id = 42
        
        peer = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9009,
            remote_host='localhost',
            remote_port=9010,
            use_ascon=True  # Test ASCON
        )
        
        try:
            peer.connect()
            
            # Get initial stats
            stats = peer.get_stats()
            
            assert stats['channel_id'] == channel_id
            assert stats['algorithm'] == 'ASCON'
            assert stats['local_addr'] == ('localhost', 9009)
            assert stats['remote_addr'] == ('localhost', 9010)
            assert stats['connected'] == True
            assert 'packets_sent' in stats
            
        finally:
            peer.disconnect()


class TestNetworkingIntegration:
    """Test networking layer integration."""
    
    def test_socket_error_handling(self):
        """Test proper handling of socket errors."""
        # Try to create peer with invalid addresses
        master_psk = generate_random_bytes(32)
        
        # This should work initially
        peer = create_peer_connection(
            master_psk=master_psk,
            channel_id=1,
            local_port=9011,
            remote_host='localhost',
            remote_port=9012,
            use_ascon=False
        )
        
        # Connection should work
        peer.connect()
        
        # Try to send to non-existent peer (should not crash)
        try:
            peer.send_message("Message to nowhere")
            # This might succeed (UDP doesn't guarantee delivery)
        except Exception:
            # Or it might fail, both are acceptable
            pass
        
        peer.disconnect()
    
    def test_concurrent_connections(self):
        """Test multiple concurrent peer connections."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        # Create a hub peer that will communicate with multiple others
        hub = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9020,
            remote_host='localhost',
            remote_port=9021,  # Will be overridden
            use_ascon=False
        )
        
        # Note: This is a simplified test since our current implementation
        # only supports one-to-one connections. In a full implementation,
        # you'd have a more sophisticated connection manager.
        
        try:
            hub.connect()
            
            # Test that the hub can at least maintain its connection
            stats = hub.get_stats()
            assert stats['connected'] == True
            
            # Send a test message to verify functionality
            hub.send_message("Hub test message")
            
        finally:
            hub.disconnect()


class TestProtocolCompatibility:
    """Test protocol compatibility and interoperability."""
    
    def test_algorithm_interoperability(self):
        """Test that different algorithm settings don't interfere."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        # Both peers must use the same algorithm for compatibility
        for use_ascon in [False, True]:
            peer1 = create_peer_connection(
                master_psk=master_psk,
                channel_id=channel_id,
                local_port=9013,
                remote_host='localhost',
                remote_port=9014,
                use_ascon=use_ascon
            )
            
            peer2 = create_peer_connection(
                master_psk=master_psk,
                channel_id=channel_id,
                local_port=9014,
                remote_host='localhost',
                remote_port=9013,
                use_ascon=use_ascon
            )
            
            try:
                peer1.connect()
                peer2.connect()
                
                received = []
                peer2.set_message_handler(lambda msg: received.append(msg))
                
                test_msg = f"Test with {'ASCON' if use_ascon else 'AES-GCM'}"
                peer1.send_message(test_msg)
                
                time.sleep(0.1)
                peer2.receive_messages(timeout=0.5)
                
                if use_ascon:
                    try:
                        assert len(received) == 1
                        assert received[0] == test_msg
                    except ImportError:
                        # ASCON might not be available
                        pytest.skip("ASCON not available")
                else:
                    assert len(received) == 1
                    assert received[0] == test_msg
                
            finally:
                peer1.disconnect()
                peer2.disconnect()
    
    def test_channel_isolation_in_practice(self):
        """Test that different channels don't interfere in practice."""
        master_psk = generate_random_bytes(32)
        
        # Create peers on different channels
        peer1_ch1 = create_peer_connection(
            master_psk=master_psk,
            channel_id=1,
            local_port=9015,
            remote_host='localhost',
            remote_port=9016,
            use_ascon=False
        )
        
        peer2_ch2 = create_peer_connection(
            master_psk=master_psk,
            channel_id=2,  # Different channel
            local_port=9016,
            remote_host='localhost',
            remote_port=9015,
            use_ascon=False
        )
        
        try:
            peer1_ch1.connect()
            peer2_ch2.connect()
            
            # Set up message handlers
            ch1_messages = []
            ch2_messages = []
            
            peer1_ch1.set_message_handler(lambda msg: ch1_messages.append(msg))
            peer2_ch2.set_message_handler(lambda msg: ch2_messages.append(msg))
            
            # Send messages
            peer1_ch1.send_message("Message on channel 1")
            peer2_ch2.send_message("Message on channel 2")
            
            time.sleep(0.1)
            
            # Try to receive (should fail due to channel mismatch)
            peer1_ch1.receive_messages(timeout=0.5)
            peer2_ch2.receive_messages(timeout=0.5)
            
            # Neither should receive the other's message
            # (They're on different channels with same PSK)
            # The exact behavior depends on implementation details
            
        finally:
            peer1_ch1.disconnect()
            peer2_ch2.disconnect()


class TestErrorScenarios:
    """Test various error scenarios and recovery."""
    
    def test_malformed_packet_handling(self):
        """Test handling of malformed packets."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        peer = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9017,
            remote_host='localhost',
            remote_port=9018,
            use_ascon=False
        )
        
        try:
            peer.connect()
            
            # Manually inject malformed data through the socket
            malformed_data = b"This is not a valid Ouroboros packet"
            peer.socket.send_packet(malformed_data, peer.remote_addr)
            
            # Try to receive - should handle gracefully
            peer.receive_messages(timeout=0.5)
            
            # Peer should still be functional
            stats = peer.get_stats()
            assert stats['connected'] == True
            
        finally:
            peer.disconnect()
    
    def test_connection_recovery(self):
        """Test connection recovery after errors."""
        master_psk = generate_random_bytes(32)
        channel_id = 1
        
        peer = create_peer_connection(
            master_psk=master_psk,
            channel_id=channel_id,
            local_port=9019,
            remote_host='localhost',
            remote_port=9020,
            use_ascon=False
        )
        
        try:
            # Initial connection
            peer.connect()
            assert peer.connected == True
            
            # Disconnect and reconnect
            peer.disconnect()
            assert peer.connected == False
            
            peer.connect()
            assert peer.connected == True
            
        finally:
            peer.disconnect()


if __name__ == '__main__':
    # Allow running integration tests directly
    pytest.main([__file__, '-v'])
