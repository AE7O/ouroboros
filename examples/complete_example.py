#!/usr/bin/env python3
"""
Complete Ouroboros Protocol Example - Client and Server.

Demonstrates the full protocol stack working together.
"""

import sys
import os
import time
import threading

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from ouroboros.config import OuroborosConfig
from ouroboros.protocol.session import OuroborosSession
from ouroboros.transport.udp import UDPTransport
from ouroboros.protocol.reliability import ReliabilityManager
from ouroboros.protocol.packet import PacketType


class OuroborosClient:
    """Simple Ouroboros client implementation."""
    
    def __init__(self, root_key: bytes, server_host: str = "localhost", server_port: int = 8888):
        """Initialize client with root key and server address."""
        self.session = OuroborosSession(root_key, is_initiator=True)
        self.transport = UDPTransport()
        self.reliability = ReliabilityManager()
        self.server_address = (server_host, server_port)
        
        # Set up reliability callbacks
        self.reliability.set_send_callback(self._send_packet)
        self.reliability.set_failure_callback(self._handle_failure)
        
        # Start transport
        self.transport.bind()
        print(f"Client bound to {self.transport.get_local_address()}")
    
    def send_message(self, message: str) -> None:
        """Send a message to the server."""
        print(f"Sending: '{message}'")
        
        # Encrypt message into packet
        packet = self.session.encrypt_message(message.encode())
        
        # Send reliably
        self.reliability.send_reliable(packet, self.server_address)
    
    def _send_packet(self, packet, destination):
        """Callback for sending packets via transport."""
        self.transport.send_packet(packet, destination[0], destination[1])
    
    def _handle_failure(self, packet, reason):
        """Callback for handling delivery failures."""
        print(f"Message delivery failed: {reason}")
    
    def listen_for_responses(self, timeout: float = 10.0):
        """Listen for server responses."""
        end_time = time.time() + timeout
        
        while time.time() < end_time:
            try:
                packet, addr = self.transport.receive_packet(timeout=1.0)
                
                if packet.is_ack_packet():
                    if self.reliability.handle_ack(packet):
                        print(f"Received ACK for message {packet.counter}")
                elif packet.is_data_packet():
                    # Echo response from server
                    try:
                        response = self.session.decrypt_message(packet)
                        print(f"Server response: '{response.decode()}'")
                        
                        # Send ACK
                        ack = self.session.create_ack_packet(packet.counter)
                        self.transport.send_packet(ack, addr[0], addr[1])
                        
                    except Exception as e:
                        print(f"Failed to decrypt server response: {e}")
                
            except TimeoutError:
                continue
            except Exception as e:
                print(f"Error receiving: {e}")
                break
    
    def close(self):
        """Close client resources."""
        self.reliability.stop()
        self.transport.close()


class OuroborosServer:
    """Simple Ouroboros server implementation."""
    
    def __init__(self, root_key: bytes, port: int = 8888):
        """Initialize server with root key and port."""
        self.session = OuroborosSession(root_key, is_initiator=False)
        self.transport = UDPTransport("0.0.0.0", port)
        self.reliability = ReliabilityManager()
        self.running = False
        
        # Set up reliability callbacks
        self.reliability.set_send_callback(self._send_packet)
        
        # Start transport
        self.transport.bind()
        print(f"Server listening on {self.transport.get_local_address()}")
    
    def start(self):
        """Start the server."""
        self.running = True
        print("Server started, waiting for messages...")
        
        while self.running:
            try:
                packet, addr = self.transport.receive_packet(timeout=1.0)
                self._handle_packet(packet, addr)
                
            except TimeoutError:
                continue
            except Exception as e:
                print(f"Server error: {e}")
                break
    
    def _handle_packet(self, packet, addr):
        """Handle received packet."""
        if packet.is_data_packet():
            try:
                # Decrypt message
                message = self.session.decrypt_message(packet)
                print(f"Received from {addr}: '{message.decode()}'")
                
                # Send ACK
                ack = self.session.create_ack_packet(packet.counter)
                self.transport.send_packet(ack, addr[0], addr[1])
                
                # Send echo response
                response = f"Echo: {message.decode()}"
                response_packet = self.session.encrypt_message(response.encode())
                self.reliability.send_reliable(response_packet, addr)
                
            except Exception as e:
                print(f"Failed to process message: {e}")
        
        elif packet.is_ack_packet():
            self.reliability.handle_ack(packet)
    
    def _send_packet(self, packet, destination):
        """Callback for sending packets via transport."""
        self.transport.send_packet(packet, destination[0], destination[1])
    
    def stop(self):
        """Stop the server."""
        self.running = False
        self.reliability.stop()
        self.transport.close()


def test_full_protocol():
    """Test the complete protocol with client and server."""
    print("🚀 Testing Complete Ouroboros Protocol")
    print("=" * 50)
    
    # Create test configuration
    config = OuroborosConfig("/tmp/ouroboros_test")
    test_key = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
    config.set_root_key(test_key)
    
    # Get root key for both client and server
    root_key = config.get_root_key()
    
    # Start server in background thread
    server = OuroborosServer(root_key, port=9999)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    # Give server time to start
    time.sleep(0.5)
    
    try:
        # Create client
        client = OuroborosClient(root_key, "localhost", 9999)
        
        # Send test messages
        messages = [
            "Hello, Ouroboros!",
            "This is a test message.",
            "Protocol working correctly!"
        ]
        
        for msg in messages:
            client.send_message(msg)
            time.sleep(0.5)
        
        # Listen for responses
        print("\nListening for server responses...")
        client.listen_for_responses(timeout=5.0)
        
        # Show statistics
        print(f"\nClient reliability stats: {client.reliability.get_stats()}")
        print(f"Server reliability stats: {server.reliability.get_stats()}")
        print(f"Client session stats: {client.session.get_stats()}")
        
        client.close()
        
    finally:
        server.stop()
    
    print("\n✅ Full protocol test completed!")


if __name__ == "__main__":
    test_full_protocol()
