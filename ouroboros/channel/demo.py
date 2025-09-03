"""
Interactive demo channel for Ouroboros Protocol.

Provides an interactive command-line interface demonstrating
the complete Ouroboros protocol functionality including
chat messaging, file transfer, and protocol diagnostics.
"""

import os
import sys
import time
import threading
from typing import Optional, Dict, List
from pathlib import Path

from ..protocol.session import OuroborosSession
from ..transport.udp import UDPTransport
from ..crypto.kdf import generate_root_key
from .chat import ChatChannel, ChatMessage
from .file_transfer import FileTransferChannel, FileTransfer


class InteractiveDemoChannel:
    """
    Interactive demonstration of Ouroboros Protocol capabilities.
    
    Provides a command-line interface for testing chat, file transfer,
    and protocol features in real-time.
    """
    
    def __init__(self, user_id: str, port: int = 0, root_key: Optional[bytes] = None):
        """
        Initialize interactive demo channel.
        
        Args:
            user_id: Unique identifier for this user
            port: Local port to bind to (0 = auto-assign)
            root_key: Pre-shared root key (None = generate new)
        """
        self.user_id = user_id
        self.port = port
        
        # Generate or use provided root key
        if root_key is None:
            root_key = generate_root_key()
        
        # Initialize protocol components
        self.session = OuroborosSession(root_key, is_initiator=True)
        self.transport = UDPTransport("127.0.0.1", port)
        
        # Initialize communication channels
        self.chat = ChatChannel(self.session, self.transport, user_id)
        self.file_transfer = FileTransferChannel(self.session, self.transport, user_id)
        
        # Demo state
        self.is_running = False
        self.receive_thread: Optional[threading.Thread] = None
        self.commands: Dict[str, callable] = {}
        self.connected_peers: Dict[str, tuple] = {}  # peer_id -> (host, port)
        
        # Setup command handlers
        self._setup_commands()
        
        # Setup message handlers
        self.chat.add_message_handler(self._handle_chat_message)
        self.file_transfer.add_handler("init", self._handle_file_transfer_init)
        self.file_transfer.add_handler("complete", self._handle_file_transfer_complete)
    
    def _setup_commands(self) -> None:
        """Setup available commands."""
        self.commands = {
            'help': self._cmd_help,
            'status': self._cmd_status,
            'connect': self._cmd_connect,
            'disconnect': self._cmd_disconnect,
            'peers': self._cmd_peers,
            'msg': self._cmd_send_message,
            'chat': self._cmd_chat_mode,
            'send_file': self._cmd_send_file,
            'accept_file': self._cmd_accept_file,
            'transfers': self._cmd_list_transfers,
            'history': self._cmd_message_history,
            'clear': self._cmd_clear_screen,
            'quit': self._cmd_quit,
            'exit': self._cmd_quit,
        }
    
    def start(self) -> None:
        """Start the interactive demo."""
        print(f"🌀 Ouroboros Protocol Interactive Demo")
        print(f"=" * 50)
        print(f"User ID: {self.user_id}")
        
        try:
            # Bind transport
            self.transport.bind()
            local_addr = self.transport.get_local_address()
            print(f"Listening on: {local_addr[0]}:{local_addr[1]}")
            print(f"Root key: {bytes(self.session._enc_key).hex()[:32]}...")
            
            # Start background services
            self.is_running = True
            self.chat.start_background_services()
            
            # Start receive thread
            self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receive_thread.start()
            
            print(f"\nDemo started! Type 'help' for available commands.")
            print(f"Type 'quit' to exit.\n")
            
            # Main command loop
            self._command_loop()
            
        except KeyboardInterrupt:
            print(f"\n\nShutting down...")
        except Exception as e:
            print(f"Error starting demo: {e}")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the demo."""
        self.is_running = False
        
        if self.chat:
            self.chat.stop_background_services()
        
        if self.transport:
            self.transport.close()
        
        print(f"Demo stopped.")
    
    def _command_loop(self) -> None:
        """Main command processing loop."""
        while self.is_running:
            try:
                # Display prompt
                online_count = len(self.chat.get_online_users())
                prompt = f"[{self.user_id}|{online_count} online] > "
                
                user_input = input(prompt).strip()
                if not user_input:
                    continue
                
                # Parse command and arguments
                parts = user_input.split()
                command = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                # Execute command
                if command in self.commands:
                    try:
                        self.commands[command](args)
                    except Exception as e:
                        print(f"Error executing command '{command}': {e}")
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
                
            except (EOFError, KeyboardInterrupt):
                self.is_running = False
                break
            except Exception as e:
                print(f"Command loop error: {e}")
    
    def _receive_loop(self) -> None:
        """Background loop for receiving messages."""
        while self.is_running:
            try:
                # Process chat messages
                self.chat.receive_messages(timeout=0.5)
                
                # Process file transfer messages
                self.file_transfer.process_incoming_messages(timeout=0.1)
                
            except Exception as e:
                if self.is_running:  # Only log if we're still supposed to be running
                    print(f"Receive error: {e}")
                time.sleep(0.1)
    
    def _handle_chat_message(self, message: ChatMessage) -> None:
        """Handle incoming chat message."""
        if message.message_type == "text" and message.sender != self.user_id:
            timestamp = time.strftime("%H:%M:%S", time.localtime(message.timestamp))
            print(f"\n[{timestamp}] {message.sender}: {message.content}")
        elif message.message_type == "typing" and message.sender != self.user_id:
            if message.content == "typing":
                print(f"\n{message.sender} is typing...")
        elif message.message_type == "presence":
            if message.sender != self.user_id:
                print(f"\n{message.sender} is now online")
    
    def _handle_file_transfer_init(self, transfer: FileTransfer) -> None:
        """Handle incoming file transfer request."""
        print(f"\n📁 File transfer request from {transfer.sender}:")
        print(f"   File: {transfer.filename} ({transfer.file_size} bytes)")
        print(f"   Transfer ID: {transfer.transfer_id}")
        print(f"   Use 'accept_file {transfer.transfer_id} <save_path>' to accept")
    
    def _handle_file_transfer_complete(self, transfer: FileTransfer) -> None:
        """Handle completed file transfer."""
        if transfer.sender == self.user_id:
            print(f"\n✅ File sent successfully: {transfer.filename}")
        else:
            print(f"\n✅ File received successfully: {transfer.filename}")
    
    # Command implementations
    def _cmd_help(self, args: List[str]) -> None:
        """Display help information."""
        print("Available commands:")
        print("  help                     - Show this help")
        print("  status                   - Show protocol status")
        print("  connect <peer_id> <host> <port> - Connect to peer") 
        print("  disconnect <peer_id>     - Disconnect from peer")
        print("  peers                    - List connected peers")
        print("  msg <peer_id> <message>  - Send message to peer")
        print("  chat <peer_id>           - Enter chat mode with peer")
        print("  send_file <peer_id> <file_path> - Send file to peer")
        print("  accept_file <transfer_id> <save_path> - Accept file transfer")
        print("  transfers                - List active file transfers")
        print("  history [peer_id] [limit] - Show message history")
        print("  clear                    - Clear screen")
        print("  quit/exit                - Exit demo")
    
    def _cmd_status(self, args: List[str]) -> None:
        """Show protocol status."""
        session_stats = self.session.get_stats()
        chat_stats = self.chat.get_stats()
        transfer_stats = self.file_transfer.get_stats()
        local_addr = self.transport.get_local_address()
        
        print(f"Protocol Status:")
        print(f"  Local address: {local_addr[0]}:{local_addr[1]}")
        print(f"  Session initialized: {session_stats['initialized']}")
        print(f"  Is initiator: {session_stats['is_initiator']}")
        print(f"  Send counter: {session_stats['counter_stats']['send_counter']}")
        print(f"  Last received: {session_stats['counter_stats']['last_received_counter']}")
        print(f"  Chat messages: {chat_stats['total_messages']}")
        print(f"  Online users: {chat_stats['online_users']}")
        print(f"  File transfers: {transfer_stats['total_transfers']}")
    
    def _cmd_connect(self, args: List[str]) -> None:
        """Connect to a peer."""
        if len(args) < 3:
            print("Usage: connect <peer_id> <host> <port>")
            return
        
        peer_id, host, port_str = args[0], args[1], args[2]
        try:
            port = int(port_str)
            self.connected_peers[peer_id] = (host, port)
            print(f"Connected to {peer_id} at {host}:{port}")
        except ValueError:
            print("Invalid port number")
    
    def _cmd_disconnect(self, args: List[str]) -> None:
        """Disconnect from a peer."""
        if len(args) < 1:
            print("Usage: disconnect <peer_id>")
            return
        
        peer_id = args[0]
        if peer_id in self.connected_peers:
            del self.connected_peers[peer_id]
            print(f"Disconnected from {peer_id}")
        else:
            print(f"Not connected to {peer_id}")
    
    def _cmd_peers(self, args: List[str]) -> None:
        """List connected peers."""
        if not self.connected_peers:
            print("No connected peers")
            return
        
        print("Connected peers:")
        for peer_id, (host, port) in self.connected_peers.items():
            status = "online" if peer_id in self.chat.get_online_users() else "offline"
            print(f"  {peer_id}: {host}:{port} ({status})")
    
    def _cmd_send_message(self, args: List[str]) -> None:
        """Send a message to a peer."""
        if len(args) < 2:
            print("Usage: msg <peer_id> <message>")
            return
        
        peer_id = args[0]
        message = " ".join(args[1:])
        
        try:
            sent_message = self.chat.send_message(message, peer_id)
            timestamp = time.strftime("%H:%M:%S", time.localtime(sent_message.timestamp))
            print(f"[{timestamp}] You -> {peer_id}: {message}")
        except Exception as e:
            print(f"Failed to send message: {e}")
    
    def _cmd_chat_mode(self, args: List[str]) -> None:
        """Enter chat mode with a specific peer."""
        if len(args) < 1:
            print("Usage: chat <peer_id>")
            return
        
        peer_id = args[0]
        print(f"Entering chat mode with {peer_id}. Type '/exit' to return to command mode.")
        
        while True:
            try:
                message = input(f"[{peer_id}] > ").strip()
                if message == "/exit":
                    break
                elif message:
                    self.chat.send_message(message, peer_id)
            except (EOFError, KeyboardInterrupt):
                break
        
        print("Exited chat mode.")
    
    def _cmd_send_file(self, args: List[str]) -> None:
        """Send a file to a peer."""
        if len(args) < 2:
            print("Usage: send_file <peer_id> <file_path>")
            return
        
        peer_id = args[0]
        file_path = " ".join(args[1:])  # Handle file paths with spaces
        
        try:
            transfer = self.file_transfer.send_file(file_path, peer_id)
            print(f"File transfer initiated: {transfer.transfer_id}")
            print(f"Sending {transfer.filename} ({transfer.file_size} bytes) to {peer_id}")
        except Exception as e:
            print(f"Failed to initiate file transfer: {e}")
    
    def _cmd_accept_file(self, args: List[str]) -> None:
        """Accept a file transfer."""
        if len(args) < 2:
            print("Usage: accept_file <transfer_id> <save_path>")
            return
        
        transfer_id = args[0]
        save_path = " ".join(args[1:])
        
        if self.file_transfer.accept_file_transfer(transfer_id, save_path):
            print(f"File transfer accepted: {transfer_id}")
        else:
            print(f"Transfer not found: {transfer_id}")
    
    def _cmd_list_transfers(self, args: List[str]) -> None:
        """List active file transfers."""
        transfers = self.file_transfer.get_active_transfers()
        
        if not transfers:
            print("No active file transfers")
            return
        
        print("Active file transfers:")
        for transfer_id, transfer in transfers.items():
            progress = transfer.get_progress() * 100
            status_icon = {"pending": "⏳", "active": "🔄", "completed": "✅", "failed": "❌"}.get(transfer.status, "❓")
            print(f"  {status_icon} {transfer.filename} ({transfer.sender} -> {transfer.recipient})")
            print(f"     Progress: {progress:.1f}% | Status: {transfer.status}")
            if transfer.status == "active":
                speed = transfer.get_speed_mbps()
                eta = transfer.get_eta_seconds()
                print(f"     Speed: {speed:.2f} MB/s | ETA: {eta:.1f}s" if eta else f"     Speed: {speed:.2f} MB/s")
    
    def _cmd_message_history(self, args: List[str]) -> None:
        """Show message history."""
        peer_id = args[0] if len(args) > 0 else None
        limit = int(args[1]) if len(args) > 1 else 20
        
        messages = self.chat.get_message_history(with_user=peer_id, limit=limit)
        
        if not messages:
            print("No message history")
            return
        
        print(f"Message history" + (f" with {peer_id}" if peer_id else "") + f" (last {len(messages)} messages):")
        for msg in messages:
            timestamp = time.strftime("%H:%M:%S", time.localtime(msg.timestamp))
            direction = "You" if msg.sender == self.user_id else msg.sender
            recipient = "You" if msg.recipient == self.user_id else msg.recipient
            print(f"  [{timestamp}] {direction} -> {recipient}: {msg.content}")
    
    def _cmd_clear_screen(self, args: List[str]) -> None:
        """Clear the screen."""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def _cmd_quit(self, args: List[str]) -> None:
        """Quit the demo."""
        self.is_running = False


def run_demo(user_id: str = None, port: int = 0, root_key: bytes = None) -> None:
    """
    Run the interactive demo.
    
    Args:
        user_id: User identifier (None = prompt for input)
        port: Local port (0 = auto-assign)
        root_key: Pre-shared root key (None = generate)
    """
    if user_id is None:
        user_id = input("Enter your user ID: ").strip()
        if not user_id:
            user_id = f"user_{int(time.time())}"
    
    demo = InteractiveDemoChannel(user_id, port, root_key)
    demo.start()


if __name__ == "__main__":
    # Allow running as standalone script
    import sys
    
    user_id = sys.argv[1] if len(sys.argv) > 1 else None
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    
    run_demo(user_id, port)