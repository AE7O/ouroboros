"""
Interactive CLI interface for live demonstration of Ouroboros Protocol.

This module provides a command-line interface for secure peer-to-peer
communication, similar to secure netcat but with the Ouroboros protocol.
"""

import sys
import threading
import time
import argparse
from pathlib import Path
from typing import Optional

from ..crypto.utils import generate_random_bytes, format_hex
from .peer import create_peer_connection, PeerConnection


class InteractiveChat:
    """
    Interactive chat session using Ouroboros Protocol.
    """
    
    def __init__(self, peer: PeerConnection, peer_name: str):
        """
        Initialize interactive chat.
        
        Args:
            peer: PeerConnection instance
            peer_name: Display name for this peer
        """
        self.peer = peer
        self.peer_name = peer_name
        self.running = False
        self.receive_thread: Optional[threading.Thread] = None
        
        # Set up message handler
        self.peer.set_message_handler(self._handle_message)
        self.peer.set_file_handler(self._handle_file)
    
    def start(self) -> None:
        """Start the interactive chat session."""
        print(f"=== {self.peer_name} - Ouroboros Secure Chat ===")
        
        try:
            self.peer.connect()
            
            # Start receive thread
            self.running = True
            self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receive_thread.start()
            
            self._print_help()
            self._input_loop()
            
        except KeyboardInterrupt:
            print("\nShutting down...")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the chat session."""
        self.running = False
        if self.receive_thread:
            self.receive_thread.join(timeout=1.0)
        self.peer.disconnect()
    
    def _receive_loop(self) -> None:
        """Background thread for receiving messages."""
        while self.running:
            try:
                self.peer.receive_messages(timeout=0.1)
            except Exception as e:
                if self.running:  # Only print errors if we're still running
                    print(f"\nReceive error: {e}")
                break
    
    def _input_loop(self) -> None:
        """Main input loop for user commands."""
        while self.running:
            try:
                user_input = input(f"{self.peer_name}> ").strip()
                
                if not user_input:
                    continue
                
                if user_input.startswith('/'):
                    self._handle_command(user_input)
                else:
                    # Send as regular message
                    self.peer.send_message(user_input)
                    
            except KeyboardInterrupt:
                break
            except EOFError:
                break
            except Exception as e:
                print(f"Input error: {e}")
    
    def _handle_command(self, command: str) -> None:
        """Handle chat commands."""
        parts = command.split(' ', 1)
        cmd = parts[0].lower()
        
        if cmd == '/help' or cmd == '/h':
            self._print_help()
        
        elif cmd == '/quit' or cmd == '/q':
            self.running = False
        
        elif cmd == '/stats' or cmd == '/s':
            stats = self.peer.get_stats()
            print(f"\nConnection Stats:")
            print(f"  Channel ID: {stats['channel_id']}")
            print(f"  Algorithm: {stats['algorithm']}")
            print(f"  Local: {stats['local_addr']}")
            print(f"  Remote: {stats['remote_addr']}")
            print(f"  Packets sent: {stats['packets_sent']}")
        
        elif cmd == '/send' or cmd == '/file':
            if len(parts) > 1:
                file_path = parts[1].strip()
                try:
                    self.peer.send_file(file_path)
                except Exception as e:
                    print(f"File send error: {e}")
            else:
                print("Usage: /send <file_path>")
        
        elif cmd == '/test':
            # Send test message with performance info
            test_msg = "Test message for performance measurement"
            start_time = time.time()
            self.peer.send_message(test_msg)
            elapsed = (time.time() - start_time) * 1000
            print(f"Test message sent (took {elapsed:.2f}ms)")
        
        else:
            print(f"Unknown command: {cmd}")
    
    def _handle_message(self, message: str) -> None:
        """Handle received text message."""
        print(f"\nPeer: {message}")
        print(f"{self.peer_name}> ", end='', flush=True)
    
    def _handle_file(self, filename: str, data: bytes) -> None:
        """Handle received file."""
        try:
            # Save with timestamp to avoid conflicts
            timestamp = int(time.time())
            safe_filename = f"received_{timestamp}_{filename}"
            
            with open(safe_filename, 'wb') as f:
                f.write(data)
            
            print(f"\nFile received: {safe_filename} ({len(data)} bytes)")
            print(f"{self.peer_name}> ", end='', flush=True)
            
        except Exception as e:
            print(f"\nFile save error: {e}")
            print(f"{self.peer_name}> ", end='', flush=True)
    
    def _print_help(self) -> None:
        """Print help message."""
        print("\nCommands:")
        print("  /help, /h      - Show this help")
        print("  /quit, /q      - Quit the chat")
        print("  /stats, /s     - Show connection statistics")
        print("  /send <file>   - Send a file")
        print("  /test          - Send test message with timing")
        print("  <message>      - Send regular text message")
        print()


def main():
    """Main entry point for interactive CLI."""
    parser = argparse.ArgumentParser(
        description="Ouroboros Protocol Interactive Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Peer A (listener):
  python -m ouroboros.channel.interactive --listen 5000 --remote-port 5001

  # Peer B (connector):
  python -m ouroboros.channel.interactive --connect localhost 5001 --local-port 5000
        """
    )
    
    # Connection mode
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--listen', type=int, metavar='PORT',
                      help='Listen mode: bind to PORT and wait for peer')
    group.add_argument('--connect', nargs=2, metavar=('HOST', 'PORT'),
                      help='Connect mode: connect to HOST:PORT')
    
    # Additional options
    parser.add_argument('--local-port', type=int, 
                       help='Local port to bind (for connect mode)')
    parser.add_argument('--remote-port', type=int,
                       help='Remote port to connect to (for listen mode)')
    parser.add_argument('--channel', type=int, default=1,
                       help='Channel ID (default: 1)')
    parser.add_argument('--key', type=str,
                       help='Hex-encoded PSK (generates random if not provided)')
    parser.add_argument('--ascon', action='store_true',
                       help='Use ASCON instead of AES-GCM')
    parser.add_argument('--name', type=str, default='User',
                       help='Display name (default: User)')
    
    args = parser.parse_args()
    
    # Generate or parse PSK
    if args.key:
        try:
            master_psk = bytes.fromhex(args.key.replace(':', '').replace(' ', ''))
            if len(master_psk) != 32:
                raise ValueError("PSK must be 32 bytes (64 hex characters)")
        except ValueError as e:
            print(f"Invalid PSK: {e}")
            return 1
    else:
        master_psk = generate_random_bytes(32)
        print(f"Generated PSK: {format_hex(master_psk)}")
        print("Share this key with the other peer!\n")
    
    # Determine addresses
    if args.listen:
        local_port = args.listen
        remote_port = args.remote_port or (args.listen + 1)
        remote_host = 'localhost'
        print(f"Listening on port {local_port}, expecting peer on port {remote_port}")
    else:
        remote_host, remote_port_str = args.connect
        remote_port = int(remote_port_str)
        local_port = args.local_port or (remote_port + 1)
        print(f"Connecting to {remote_host}:{remote_port} from local port {local_port}")
    
    # Create peer connection
    try:
        peer = create_peer_connection(
            master_psk=master_psk,
            channel_id=args.channel,
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
            use_ascon=args.ascon
        )
        
        # Start interactive chat
        chat = InteractiveChat(peer, args.name)
        chat.start()
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
