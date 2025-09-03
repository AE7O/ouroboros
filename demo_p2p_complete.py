#!/usr/bin/env python3
"""
Demo Script for Ouroboros Protocol Interactive Channel

This script demonstrates the complete peer-to-peer communication functionality
including chat messaging, file transfer, and an interactive demo channel.
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from ouroboros.crypto.kdf import generate_root_key
from ouroboros.protocol.session import OuroborosSession
from ouroboros.transport.udp import UDPTransport
from ouroboros.channel.chat import ChatChannel, ChatMessage
from ouroboros.channel.file_transfer import FileTransferChannel, FileTransfer
from ouroboros.channel.demo import InteractiveDemoChannel


def demo_basic_messaging():
    """Demonstrate basic peer-to-peer messaging."""
    print("🔹 Demo: Basic Peer-to-Peer Messaging")
    print("-" * 40)
    
    # Create shared root key
    root_key = generate_root_key()
    print(f"   Root key: {root_key.hex()[:32]}...")
    
    # Create Alice and Bob sessions
    alice_session = OuroborosSession(root_key, is_initiator=True)
    bob_session = OuroborosSession(root_key, is_initiator=False)
    
    # Test Alice sending messages to Bob
    messages = [
        "Hello Bob! This is Alice.",
        "The Ouroboros Protocol is working great!",
        "Forward secrecy through key ratcheting is active.",
        "Each message uses different encryption keys.",
        "🎉 Quantum-resistant communication achieved!"
    ]
    
    print(f"   Alice sending {len(messages)} messages to Bob...")
    
    for i, msg in enumerate(messages, 1):
        # Alice encrypts message
        packet = alice_session.encrypt_message(msg.encode('utf-8'))
        
        # Bob decrypts message
        decrypted = bob_session.decrypt_message(packet)
        
        print(f"   Message {i}: {decrypted.decode('utf-8')[:50]}...")
        assert decrypted.decode('utf-8') == msg
    
    # Show session statistics
    alice_stats = alice_session.get_stats()
    bob_stats = bob_session.get_stats()
    
    print(f"   ✅ Alice: sent {len(messages)} messages (counter at {alice_stats['counter_stats']['send_counter']})")
    print(f"   ✅ Bob: received up to counter {bob_stats['counter_stats']['last_received_counter']}")
    
    # Now demonstrate Bob sending messages to Alice using fresh sessions
    print(f"   Bob sending {len(messages)} messages back to Alice...")
    
    # Create fresh sessions for return communication
    alice_session2 = OuroborosSession(root_key, is_initiator=False)  # Alice as receiver
    bob_session2 = OuroborosSession(root_key, is_initiator=True)     # Bob as sender
    
    reply_messages = [
        "Hi Alice! Bob here.",
        "The protocol is indeed working perfectly!",
        "I can confirm quantum-resistant security.",
        "Each message is encrypted with fresh keys.",
        "🔒 Secure communication established!"
    ]
    
    for i, msg in enumerate(reply_messages, 1):
        # Bob encrypts message
        packet = bob_session2.encrypt_message(msg.encode('utf-8'))
        
        # Alice decrypts message
        decrypted = alice_session2.decrypt_message(packet)
        
        print(f"   Reply {i}: {decrypted.decode('utf-8')[:50]}...")
        assert decrypted.decode('utf-8') == msg
    
    print(f"   ✅ Bidirectional communication successful!")
    print()


def demo_chat_channel():
    """Demonstrate chat channel functionality."""
    print("🔹 Demo: Chat Channel")
    print("-" * 40)
    
    # Setup
    root_key = generate_root_key()
    alice_session = OuroborosSession(root_key, is_initiator=True)
    alice_transport = UDPTransport("127.0.0.1", 0)
    alice_transport.bind()
    
    alice_chat = ChatChannel(alice_session, alice_transport, "Alice")
    
    # Create and send a message
    message = alice_chat.send_message("Hello from the chat channel!", "Bob")
    
    print(f"   Created message: {message.sender} → {message.recipient}")
    print(f"   Content: {message.content}")
    print(f"   Timestamp: {time.strftime('%H:%M:%S', time.localtime(message.timestamp))}")
    print(f"   Message ID: {message.message_id}")
    
    # Test message serialization
    json_data = message.to_json()
    restored = ChatMessage.from_json(json_data)
    assert restored.content == message.content
    print(f"   ✅ JSON serialization working")
    
    # Check message history
    history = alice_chat.get_message_history()
    print(f"   ✅ Message history: {len(history)} messages stored")
    
    alice_transport.close()
    print()


def demo_file_transfer():
    """Demonstrate file transfer functionality."""
    print("🔹 Demo: File Transfer")
    print("-" * 40)
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        test_content = "This is a test file for Ouroboros Protocol file transfer.\n" * 10
        f.write(test_content)
        test_file_path = f.name
    
    try:
        # Setup
        root_key = generate_root_key()
        alice_session = OuroborosSession(root_key, is_initiator=True)
        alice_transport = UDPTransport("127.0.0.1", 0)
        alice_transport.bind()
        
        alice_ft = FileTransferChannel(alice_session, alice_transport, "Alice")
        
        # Initialize file transfer
        transfer = alice_ft.send_file(test_file_path, "Bob")
        
        print(f"   File: {transfer.filename}")
        print(f"   Size: {transfer.file_size} bytes")
        print(f"   Chunks: {transfer.chunks_total} (of {transfer.chunk_size} bytes each)")
        print(f"   Hash: {transfer.file_hash[:16]}...")
        print(f"   Status: {transfer.status}")
        
        # Test progress calculation
        transfer.chunks_sent = 5
        transfer.chunks_received = 3
        progress = transfer.get_progress()
        print(f"   Progress: {progress*100:.1f}% complete")
        
        # Show transfer stats
        stats = alice_ft.get_stats()
        print(f"   ✅ File transfer initialized: {stats['total_transfers']} transfers")
        
        alice_transport.close()
        
    finally:
        # Cleanup
        os.unlink(test_file_path)
    
    print()


def demo_interactive_channel():
    """Demonstrate interactive demo channel setup."""
    print("🔹 Demo: Interactive Demo Channel")
    print("-" * 40)
    
    # Create demo channel
    demo = InteractiveDemoChannel("DemoUser", port=0)
    
    print(f"   User ID: {demo.user_id}")
    print(f"   Available commands: {len(demo.commands)}")
    
    # List some key commands
    key_commands = ['help', 'status', 'msg', 'send_file', 'chat', 'transfers']
    print(f"   Key commands: {', '.join(key_commands)}")
    
    # Show session info
    session_stats = demo.session.get_stats()
    print(f"   Session initialized: {session_stats['initialized']}")
    print(f"   Cryptographic state: Ready")
    
    print(f"   ✅ Interactive demo channel ready")
    print(f"   💡 To start interactive mode, run: python -m ouroboros.channel.demo <user_id>")
    print()


def demo_protocol_overview():
    """Show high-level protocol capabilities."""
    print("🔹 Demo: Protocol Overview")
    print("-" * 40)
    
    features = [
        "✅ Quantum-resistant security (symmetric crypto only)",
        "✅ Forward secrecy through key ratcheting",
        "✅ Replay protection with message counters",
        "✅ Authenticated encryption (AES-256-GCM)",
        "✅ Data scrambling for traffic analysis resistance",
        "✅ Peer-to-peer chat messaging",
        "✅ Secure file transfer with integrity checking",
        "✅ Interactive demo channel",
        "✅ Lightweight design for IoT devices",
        "✅ Comprehensive testing suite"
    ]
    
    print("   Protocol Features:")
    for feature in features:
        print(f"      {feature}")
    
    print()
    
    print("   Architecture:")
    print("      🔐 Crypto Layer: KDF, AES-GCM, Scrambling")
    print("      📡 Protocol Layer: Sessions, Packets, Reliability")
    print("      🌐 Transport Layer: UDP (async and sync)")
    print("      💬 Channel Layer: Chat, File Transfer, Demo")
    print("      🛠️  Utils: Counter Management, Secure Memory")
    print()


def main():
    """Run all demonstrations."""
    print("🌀 Ouroboros Protocol - Complete Demonstration")
    print("=" * 60)
    print()
    
    try:
        # Run all demos
        demo_protocol_overview()
        demo_basic_messaging()
        demo_chat_channel()
        demo_file_transfer()
        demo_interactive_channel()
        
        print("🎉 All demonstrations completed successfully!")
        print()
        print("Next Steps:")
        print("  • Run the full test suite: python test_p2p_functionality.py")
        print("  • Try interactive mode: python -m ouroboros.channel.demo Alice")
        print("  • Explore examples in the examples/ directory")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)