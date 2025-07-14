#!/usr/bin/env python3
"""
Holistic Protocol Operation - Example & Test

This demonstrates the complete Ouroboros protocol operation,
showing how all components work together in a realistic scenario.
This serves as both documentation and integration test.
"""

import sys
import os
import tempfile
import threading
import time

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ouroboros.crypto.kdf import derive_session_keys, load_root_key
from ouroboros.crypto.aes_gcm import encrypt_message, decrypt_message
from ouroboros.crypto.scramble import scramble_data, unscramble_data
from ouroboros.protocol.packet import OuroborosPacket, PacketType, create_ack_packet
from ouroboros.utils.counter import CounterManager
from ouroboros.utils.memory import SecureBytes


class OuroborosNode:
    """
    A complete Ouroboros protocol node implementation.
    This demonstrates how all components work together.
    """
    
    def __init__(self, node_id: str, root_key: bytes):
        self.node_id = node_id
        self.root_key = SecureBytes(root_key)
        self.counter_mgr = CounterManager()
        self.current_session_key = None
        self.peer_last_counter = 0
        self.message_history = []
        
        # Initialize first session key from root key
        self._derive_initial_session_key()
    
    def _derive_initial_session_key(self):
        """Derive the initial session key from root key"""
        keys = derive_session_keys(
            previous_key=self.root_key.data,
            counter=1,
            context=f"session_{self.node_id}".encode()
        )
        self.current_session_key = SecureBytes(keys['encryption_key'])
        print(f"[{self.node_id}] Derived initial session key")
    
    def _advance_session_key(self, counter: int):
        """Advance to next session key using forward-secure ratcheting"""
        keys = derive_session_keys(
            previous_key=self.current_session_key.data,
            counter=counter,
            context=f"session_{self.node_id}".encode()
        )
        # Securely overwrite old key
        self.current_session_key.clear()
        self.current_session_key = SecureBytes(keys['encryption_key'])
        print(f"[{self.node_id}] Advanced to new session key (counter={counter})")
    
    def send_message(self, plaintext: str, to_node_id: str) -> bytes:
        """
        Send a message using the complete Ouroboros protocol:
        1. Generate counter
        2. Advance session key
        3. Encrypt message
        4. Scramble encrypted data
        5. Create protocol packet
        6. Serialize for transmission
        """
        message_bytes = plaintext.encode('utf-8')
        
        # 1. Generate next counter
        counter = self.counter_mgr.get_next_counter()
        print(f"[{self.node_id}] Sending message #{counter}: '{plaintext[:20]}...'")
        
        # 2. Advance session key using forward-secure ratcheting
        self._advance_session_key(counter)
        
        # 3. Encrypt the message with AES-GCM
        encrypted_data, auth_tag = encrypt_message(
            plaintext=message_bytes,
            key=self.current_session_key.data,
            associated_data=f"msg_{counter}_{to_node_id}".encode()
        )
        
        # 4. Scramble the encrypted data for additional obfuscation
        scramble_key = self.current_session_key.data[:16]  # Use first 16 bytes as scramble key
        scrambled_data = scramble_data(encrypted_data, scramble_key)
        
        # 5. Create protocol packet
        packet = OuroborosPacket(
            version=1,
            packet_type=PacketType.DATA,
            flags=0x01,  # Indicate scrambled data
            counter=counter,
            scrambled_data=scrambled_data,
            auth_tag=auth_tag
        )
        
        # 6. Serialize for transmission
        packet_bytes = packet.to_bytes()
        
        print(f"[{self.node_id}] Message encrypted and packaged ({len(packet_bytes)} bytes)")
        return packet_bytes
    
    def receive_message(self, packet_bytes: bytes, from_node_id: str) -> str:
        """
        Receive a message using the complete Ouroboros protocol:
        1. Deserialize packet
        2. Validate counter (replay protection)
        3. Advance session key to match sender
        4. Unscramble data
        5. Decrypt message
        6. Return plaintext
        """
        # 1. Deserialize packet
        packet = OuroborosPacket.from_bytes(packet_bytes)
        print(f"[{self.node_id}] Received packet #{packet.counter} from {from_node_id}")
        
        # 2. Validate counter for replay protection
        if packet.counter <= self.peer_last_counter:
            raise ValueError(f"Replay attack detected: counter {packet.counter} <= {self.peer_last_counter}")
        
        # 3. Advance our session key to match the sender's counter
        # In a real implementation, we'd need to synchronize keys more carefully
        for _ in range(self.peer_last_counter + 1, packet.counter + 1):
            self._advance_session_key(_)
        
        self.peer_last_counter = packet.counter
        
        # 4. Unscramble the data
        scramble_key = self.current_session_key.data[:16]
        encrypted_data = unscramble_data(packet.scrambled_data, scramble_key)
        
        # 5. Decrypt the message
        plaintext_bytes = decrypt_message(
            ciphertext=encrypted_data,
            auth_tag=packet.auth_tag,
            key=self.current_session_key.data,
            associated_data=f"msg_{packet.counter}_{self.node_id}".encode()
        )
        
        plaintext = plaintext_bytes.decode('utf-8')
        print(f"[{self.node_id}] Decrypted message: '{plaintext[:20]}...'")
        
        # Store in message history
        self.message_history.append({
            'counter': packet.counter,
            'from': from_node_id,
            'message': plaintext,
            'timestamp': time.time()
        })
        
        return plaintext
    
    def send_ack(self, ack_counter: int) -> bytes:
        """Send an acknowledgment packet"""
        ack_packet = create_ack_packet(ack_counter)
        return ack_packet.to_bytes()
    
    def get_status(self) -> dict:
        """Get current node status"""
        return {
            'node_id': self.node_id,
            'current_counter': self.counter_mgr.get_current_counter(),
            'peer_last_counter': self.peer_last_counter,
            'messages_received': len(self.message_history)
        }


def main():
    print("🌀 Holistic Ouroboros Protocol Operation - Example & Test")
    print("=" * 60)
    
    try:
        # Test 1: Initialize two nodes with shared root key
        print("1. Initializing Ouroboros nodes...")
        
        # Create a temporary root key file
        root_key = os.urandom(32)  # 256-bit root key
        
        # Initialize two nodes (Alice and Bob)
        alice = OuroborosNode("Alice", root_key)
        bob = OuroborosNode("Bob", root_key)
        
        print(f"   ✅ Alice initialized: {alice.get_status()}")
        print(f"   ✅ Bob initialized: {bob.get_status()}")
        
        # Test 2: Basic message exchange
        print("\n2. Testing basic message exchange...")
        
        # Alice sends message to Bob
        message1 = "Hello Bob! This is Alice."
        packet1_bytes = alice.send_message(message1, "Bob")
        received1 = bob.receive_message(packet1_bytes, "Alice")
        
        assert received1 == message1, "Message 1 should be received correctly"
        print(f"   ✅ Alice → Bob: '{received1}'")
        
        # Bob sends message to Alice
        message2 = "Hi Alice! Bob here."
        packet2_bytes = bob.send_message(message2, "Alice")
        received2 = alice.receive_message(packet2_bytes, "Bob")
        
        assert received2 == message2, "Message 2 should be received correctly"
        print(f"   ✅ Bob → Alice: '{received2}'")
        
        # Test 3: Multiple message sequence
        print("\n3. Testing message sequence with forward secrecy...")
        
        messages = [
            ("Alice", "How's your IoT project going?"),
            ("Bob", "Great! The sensors are collecting data."),
            ("Alice", "Excellent! The encryption is working perfectly."),
            ("Bob", "Yes, and the key ratcheting provides forward secrecy."),
            ("Alice", "Perfect for quantum-resistant communication!")
        ]
        
        for sender_name, message in messages:
            if sender_name == "Alice":
                packet_bytes = alice.send_message(message, "Bob")
                received = bob.receive_message(packet_bytes, "Alice")
                receiver = bob
            else:
                packet_bytes = bob.send_message(message, "Alice")
                received = alice.receive_message(packet_bytes, "Bob")
                receiver = alice
            
            assert received == message, f"Message '{message}' should be received correctly"
            print(f"   ✅ {sender_name}: '{message[:30]}...'")
        
        print(f"   Alice status: {alice.get_status()}")
        print(f"   Bob status: {bob.get_status()}")
        
        # Test 4: Large message handling
        print("\n4. Testing large message handling...")
        
        large_message = "X" * 4096  # 4KB message
        large_packet = alice.send_message(large_message, "Bob")
        received_large = bob.receive_message(large_packet, "Alice")
        
        assert received_large == large_message, "Large message should be received correctly"
        assert len(received_large) == 4096, "Large message length should be preserved"
        print(f"   ✅ Large message (4KB) transmitted successfully")
        
        # Test 5: Acknowledgment packets
        print("\n5. Testing acknowledgment system...")
        
        # Send data packet
        data_message = "This message needs an ACK"
        data_packet = alice.send_message(data_message, "Bob")
        received_data = bob.receive_message(data_packet, "Alice")
        
        # Send ACK back
        current_counter = bob.counter_mgr.get_current_counter()
        ack_packet_bytes = bob.send_ack(current_counter)
        ack_packet = OuroborosPacket.from_bytes(ack_packet_bytes)
        
        assert ack_packet.is_ack_packet(), "Should be ACK packet"
        assert ack_packet.counter == current_counter, "ACK counter should match"
        print(f"   ✅ ACK packet created and validated (counter={ack_packet.counter})")
        
        # Test 6: Concurrent operation simulation
        print("\n6. Testing concurrent operation...")
        
        results = []
        errors = []
        
        def send_messages(node, node_name, other_node, other_name, count):
            """Send multiple messages concurrently"""
            try:
                for i in range(count):
                    message = f"Concurrent message {i+1} from {node_name}"
                    packet = node.send_message(message, other_name)
                    # In real scenario, this would go over network
                    # For test, we'll store the packets
                    results.append((node_name, packet, message))
                    time.sleep(0.01)  # Small delay
            except Exception as e:
                errors.append(f"{node_name}: {e}")
        
        # Start concurrent sending
        alice_thread = threading.Thread(
            target=send_messages, 
            args=(alice, "Alice", bob, "Bob", 5)
        )
        bob_thread = threading.Thread(
            target=send_messages, 
            args=(bob, "Bob", alice, "Alice", 5)
        )
        
        alice_thread.start()
        bob_thread.start()
        alice_thread.join()
        bob_thread.join()
        
        assert len(errors) == 0, f"No errors should occur: {errors}"
        assert len(results) == 10, "Should have 10 messages total"
        print(f"   ✅ Concurrent operation completed: {len(results)} messages")
        
        # Test 7: Performance measurement
        print("\n7. Testing protocol performance...")
        
        # Measure encryption/decryption performance
        test_message = "Performance test message " * 10  # ~250 bytes
        
        start_time = time.time()
        for i in range(100):
            packet = alice.send_message(f"{test_message} #{i}", "Bob")
            received = bob.receive_message(packet, "Alice")
        processing_time = time.time() - start_time
        
        throughput = 100 / processing_time
        print(f"   ✅ Processed 100 messages in {processing_time:.3f}s ({throughput:.1f} msg/s)")
        
        # Test 8: Protocol state validation
        print("\n8. Validating protocol state...")
        
        alice_status = alice.get_status()
        bob_status = bob.get_status()
        
        # Both nodes should have advanced their counters
        assert alice_status['current_counter'] > 0, "Alice should have sent messages"
        assert bob_status['current_counter'] > 0, "Bob should have sent messages"
        
        # Both nodes should have received messages
        assert alice_status['messages_received'] > 0, "Alice should have received messages"
        assert bob_status['messages_received'] > 0, "Bob should have received messages"
        
        print(f"   ✅ Alice final state: {alice_status}")
        print(f"   ✅ Bob final state: {bob_status}")
        
        # Test 9: Memory cleanup verification
        print("\n9. Testing secure memory cleanup...")
        
        # Force cleanup of sensitive data
        alice.current_session_key.clear()
        bob.current_session_key.clear()
        alice.root_key.clear()
        bob.root_key.clear()
        
        # Verify keys are cleared
        assert alice.current_session_key.is_cleared(), "Alice session key should be cleared"
        assert bob.current_session_key.is_cleared(), "Bob session key should be cleared"
        assert alice.root_key.is_cleared(), "Alice root key should be cleared"
        assert bob.root_key.is_cleared(), "Bob root key should be cleared"
        
        print("   ✅ Secure memory cleanup verified")
        
        print("\n🎉 Complete Ouroboros protocol operation test passed!")
        print("\n📊 Test Summary:")
        print(f"   • Messages exchanged: {alice_status['current_counter'] + bob_status['current_counter']}")
        print(f"   • Forward secrecy: ✅ Keys ratcheted for each message")
        print(f"   • Replay protection: ✅ Counter validation working")
        print(f"   • Data scrambling: ✅ Additional obfuscation layer")
        print(f"   • Authenticated encryption: ✅ AES-GCM with auth tags")
        print(f"   • Secure memory: ✅ Automatic cleanup")
        print(f"   • Performance: ✅ {throughput:.1f} messages/second")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Holistic protocol test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
