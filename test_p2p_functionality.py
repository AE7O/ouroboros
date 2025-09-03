"""
Comprehensive test suite for Ouroboros Protocol peer-to-peer functionality.

Tests the chat channel, file transfer channel, and interactive demo components
to ensure complete protocol operation.
"""

import os
import sys
import tempfile
import threading
import time
import pytest
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ouroboros.crypto.kdf import generate_root_key
from ouroboros.protocol.session import OuroborosSession
from ouroboros.transport.udp import UDPTransport
from ouroboros.channel.chat import ChatChannel, ChatMessage
from ouroboros.channel.file_transfer import FileTransferChannel, FileTransfer
from ouroboros.channel.demo import InteractiveDemoChannel


class TestPeerToPeerCommunication:
    """Test peer-to-peer communication functionality."""
    
    def setup_method(self):
        """Setup test environment."""
        # Generate shared root key
        self.root_key = generate_root_key()
        
        # Create two nodes for testing
        self.alice_session = OuroborosSession(self.root_key, is_initiator=True)
        self.bob_session = OuroborosSession(self.root_key, is_initiator=False)
        
        # Create transports (using different ports for testing)
        self.alice_transport = UDPTransport("127.0.0.1", 0)  # Auto-assign port
        self.bob_transport = UDPTransport("127.0.0.1", 0)    # Auto-assign port
        
        # Bind transports
        self.alice_transport.bind()
        self.bob_transport.bind()
        
        self.alice_addr = self.alice_transport.get_local_address()
        self.bob_addr = self.bob_transport.get_local_address()
    
    def teardown_method(self):
        """Cleanup test environment."""
        if hasattr(self, 'alice_transport'):
            self.alice_transport.close()
        if hasattr(self, 'bob_transport'):
            self.bob_transport.close()
    
    def test_session_encrypt_decrypt_roundtrip(self):
        """Test basic session encryption/decryption."""
        # Alice encrypts a message
        test_message = b"Hello from Alice to Bob!"
        encrypted_packet = self.alice_session.encrypt_message(test_message)
        
        # Verify packet structure
        assert encrypted_packet.packet_type.value == 1  # DATA packet
        assert encrypted_packet.counter > 0
        assert len(encrypted_packet.scrambled_data) > 0
        assert len(encrypted_packet.auth_tag) == 16
        
        # Bob decrypts the message
        decrypted_message = self.bob_session.decrypt_message(encrypted_packet)
        
        # Verify message content
        assert decrypted_message == test_message
        print(f"✅ Session roundtrip: {test_message.decode()} -> {decrypted_message.decode()}")
    
    def test_chat_channel_basic_messaging(self):
        """Test basic chat channel functionality."""
        # Create chat channels
        alice_chat = ChatChannel(self.alice_session, self.alice_transport, "Alice")
        bob_chat = ChatChannel(self.bob_session, self.bob_transport, "Bob")
        
        # Test message creation
        test_content = "Hello Bob, this is Alice!"
        message = alice_chat.send_message(test_content, "Bob")
        
        # Verify message structure
        assert message.sender == "Alice"
        assert message.recipient == "Bob"
        assert message.content == test_content
        assert message.message_type == "text"
        assert message.timestamp > 0
        
        # Verify message is in Alice's history
        alice_history = alice_chat.get_message_history()
        assert len(alice_history) == 1
        assert alice_history[0].content == test_content
        
        print(f"✅ Chat message created: {message.content}")
    
    def test_chat_message_serialization(self):
        """Test chat message JSON serialization/deserialization."""
        # Create test message
        original_message = ChatMessage(
            sender="Alice",
            recipient="Bob", 
            content="Test serialization",
            timestamp=time.time(),
            message_id="test_123",
            message_type="text"
        )
        
        # Serialize to JSON
        json_str = original_message.to_json()
        assert isinstance(json_str, str)
        assert "Alice" in json_str
        assert "Test serialization" in json_str
        
        # Deserialize from JSON
        restored_message = ChatMessage.from_json(json_str)
        
        # Verify all fields match
        assert restored_message.sender == original_message.sender
        assert restored_message.recipient == original_message.recipient
        assert restored_message.content == original_message.content
        assert restored_message.timestamp == original_message.timestamp
        assert restored_message.message_id == original_message.message_id
        assert restored_message.message_type == original_message.message_type
        
        print(f"✅ Message serialization successful")
    
    def test_file_transfer_initialization(self):
        """Test file transfer initialization."""
        # Create file transfer channels
        alice_ft = FileTransferChannel(self.alice_session, self.alice_transport, "Alice")
        bob_ft = FileTransferChannel(self.bob_session, self.bob_transport, "Bob")
        
        # Create a test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            test_content = "This is a test file for Ouroboros file transfer."
            f.write(test_content)
            test_file_path = f.name
        
        try:
            # Initialize file transfer
            transfer = alice_ft.send_file(test_file_path, "Bob")
            
            # Verify transfer object
            assert transfer.sender == "Alice"
            assert transfer.recipient == "Bob"
            assert transfer.filename == Path(test_file_path).name
            assert transfer.file_size > 0
            assert transfer.status == "pending"
            assert transfer.chunks_total > 0
            assert len(transfer.file_hash) == 64  # SHA256 hex
            
            # Verify transfer is tracked
            active_transfers = alice_ft.get_active_transfers()
            assert transfer.transfer_id in active_transfers
            
            print(f"✅ File transfer initialized: {transfer.filename} ({transfer.file_size} bytes)")
            
        finally:
            # Cleanup
            os.unlink(test_file_path)
    
    def test_file_transfer_progress_calculation(self):
        """Test file transfer progress calculations."""
        # Create test transfer
        transfer = FileTransfer(
            transfer_id="test_123",
            filename="test.txt",
            file_size=1000,
            file_hash="dummy_hash",
            sender="Alice",
            recipient="Bob",
            chunk_size=100
        )
        
        # Test initial state
        assert transfer.chunks_total == 10  # 1000 / 100
        assert transfer.get_progress() == 0.0
        
        # Simulate partial progress
        transfer.chunks_sent = 5
        transfer.chunks_received = 3
        assert transfer.get_progress() == 0.3  # min(5, 3) / 10
        
        # Simulate completion
        transfer.chunks_sent = 10
        transfer.chunks_received = 10
        assert transfer.get_progress() == 1.0
        
        print(f"✅ Progress calculation working correctly")
    
    def test_demo_channel_initialization(self):
        """Test interactive demo channel initialization."""
        # Create demo channel
        demo = InteractiveDemoChannel("TestUser", port=0, root_key=self.root_key)
        
        # Verify initialization
        assert demo.user_id == "TestUser"
        assert demo.session is not None
        assert demo.transport is not None
        assert demo.chat is not None
        assert demo.file_transfer is not None
        
        # Verify commands are setup
        assert 'help' in demo.commands
        assert 'status' in demo.commands
        assert 'msg' in demo.commands
        assert 'send_file' in demo.commands
        
        # Test command execution (help command)
        import io
        import contextlib
        
        # Capture stdout to test help command
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            demo._cmd_help([])
        
        help_output = stdout_capture.getvalue()
        assert "Available commands:" in help_output
        assert "help" in help_output
        assert "status" in help_output
        
        print(f"✅ Demo channel initialized with {len(demo.commands)} commands")
    
    def test_multiple_message_sequence(self):
        """Test sending multiple messages in sequence."""
        messages = [
            "First message from Alice",
            "Second message with more content",
            "Third message to test sequence",
            "Fourth message with special chars: !@#$%^&*()",
            "Final message to complete the test"
        ]
        
        decrypted_messages = []
        
        for original_msg in messages:
            # Alice encrypts message
            packet = self.alice_session.encrypt_message(original_msg.encode('utf-8'))
            
            # Bob decrypts message
            decrypted = self.bob_session.decrypt_message(packet)
            decrypted_messages.append(decrypted.decode('utf-8'))
        
        # Verify all messages were transmitted correctly
        assert len(decrypted_messages) == len(messages)
        for i, (original, decrypted) in enumerate(zip(messages, decrypted_messages)):
            assert original == decrypted, f"Message {i+1} mismatch: {original} != {decrypted}"
        
        print(f"✅ {len(messages)} messages transmitted successfully")
    
    def test_session_statistics(self):
        """Test session statistics tracking."""
        # Create fresh sessions for this test to ensure isolation
        fresh_alice = OuroborosSession(self.root_key, is_initiator=True)
        fresh_bob = OuroborosSession(self.root_key, is_initiator=False)
        
        # Send a few messages to generate stats
        for i in range(5):
            msg = f"Test message {i+1}"
            packet = fresh_alice.encrypt_message(msg.encode('utf-8'))
            fresh_bob.decrypt_message(packet)
        
        # Check Alice's stats (sender)
        alice_stats = fresh_alice.get_stats()
        bob_stats = fresh_bob.get_stats()
        
        assert alice_stats['initialized'] == True
        assert alice_stats['is_initiator'] == True
        # Counter starts at 1, after 5 messages (1,2,3,4,5) the next counter is 6
        assert alice_stats['counter_stats']['send_counter'] == 6
        
        # Check Bob's stats (receiver)
        assert bob_stats['initialized'] == True
        assert bob_stats['is_initiator'] == False
        # Last received should be the 5th message, which has counter 5
        assert bob_stats['counter_stats']['last_received_counter'] == 5
        
        print(f"✅ Session statistics: Alice sent 5 messages (counter at {alice_stats['counter_stats']['send_counter']}), Bob received up to counter {bob_stats['counter_stats']['last_received_counter']}")
    
    def test_error_handling(self):
        """Test error handling in various scenarios."""
        # Test decrypting invalid packet type
        ack_packet = self.alice_session.create_ack_packet(1)
        
        try:
            self.bob_session.decrypt_message(ack_packet)
            assert False, "Should have raised error for non-data packet"
        except Exception as e:
            assert "Can only decrypt DATA packets" in str(e)
        
        # Test invalid root key length
        try:
            OuroborosSession(b"too_short", is_initiator=True)
            assert False, "Should have raised error for short root key"
        except Exception as e:
            assert "Root key must be 32 bytes" in str(e)
        
        print(f"✅ Error handling working correctly")


def main():
    """Run all tests."""
    print("🧪 Testing Ouroboros Protocol Peer-to-Peer Communication")
    print("=" * 60)
    
    test_suite = TestPeerToPeerCommunication()
    
    try:
        # Setup
        test_suite.setup_method()
        
        # Run tests
        tests = [
            ("Session Encrypt/Decrypt", test_suite.test_session_encrypt_decrypt_roundtrip),
            ("Chat Channel Messaging", test_suite.test_chat_channel_basic_messaging),
            ("Message Serialization", test_suite.test_chat_message_serialization),
            ("File Transfer Init", test_suite.test_file_transfer_initialization),
            ("Transfer Progress", test_suite.test_file_transfer_progress_calculation),
            ("Demo Channel Init", test_suite.test_demo_channel_initialization),
            ("Message Sequence", test_suite.test_multiple_message_sequence),
            ("Session Statistics", test_suite.test_session_statistics),
            ("Error Handling", test_suite.test_error_handling),
        ]
        
        passed = 0
        failed = 0
        
        for test_name, test_func in tests:
            try:
                print(f"\n🔍 Testing {test_name}...")
                test_func()
                print(f"✅ {test_name} passed")
                passed += 1
            except Exception as e:
                print(f"❌ {test_name} failed: {e}")
                import traceback
                traceback.print_exc()
                failed += 1
        
        # Cleanup
        test_suite.teardown_method()
        
        print(f"\n📊 Test Results:")
        print(f"   Passed: {passed}")
        print(f"   Failed: {failed}")
        print(f"   Total:  {len(tests)}")
        
        if failed == 0:
            print(f"\n🎉 All peer-to-peer communication tests passed!")
            return True
        else:
            print(f"\n💔 {failed} test(s) failed")
            return False
            
    except Exception as e:
        print(f"\n❌ Test setup failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)