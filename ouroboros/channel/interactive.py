"""
Interactive Command-Line Interface for Ouroboros Protocol.

Provides a CLI interface for live demonstration of the protocol features.
"""

import cmd
import threading
import time
import os
from typing import Dict, List
from ..crypto.ratchet import generate_root_key
from .peer import SecurePeer, PeerNetwork


class OuroborosCLI(cmd.Cmd):
    """Interactive CLI for Ouroboros protocol demonstration."""
    
    intro = """
🐍 Welcome to Ouroboros Protocol Interactive CLI! 🔐
===================================================

This demonstrates the new symmetric-only Ouroboros protocol with:
- Hash-based key ratcheting for forward secrecy
- ChaCha20-seeded Fisher-Yates scrambling for traffic obfuscation  
- Sliding window replay protection
- Secure P2P communication

Type 'help' or '?' to list commands.
"""
    
    prompt = 'ouroboros> '
    
    def __init__(self):
        super().__init__()
        self.network = PeerNetwork()
        self.current_peer: str = None
        self.running_peers: Dict[str, SecurePeer] = {}
    
    def do_create_peer(self, line):
        """Create a new peer: create_peer <peer_id> [channel_id]"""
        args = line.split()
        if not args:
            print("Usage: create_peer <peer_id> [channel_id]")
            return
        
        peer_id = args[0]
        channel_id = int(args[1]) if len(args) > 1 else 0
        
        if peer_id in self.network.peers:
            print(f"Peer {peer_id} already exists")
            return
        
        peer = self.network.add_peer(peer_id, channel_id)
        peer.start()
        self.running_peers[peer_id] = peer
        
        print(f"✅ Created peer '{peer_id}' on channel {channel_id}")
        
        if self.current_peer is None:
            self.current_peer = peer_id
            print(f"🎯 Set '{peer_id}' as current peer")
    
    def do_connect(self, line):
        """Connect two peers: connect <peer1> <peer2>"""
        args = line.split()
        if len(args) != 2:
            print("Usage: connect <peer1> <peer2>")
            return
        
        peer1_id, peer2_id = args
        
        if peer1_id not in self.network.peers or peer2_id not in self.network.peers:
            print("Both peers must exist. Use 'list_peers' to see available peers.")
            return
        
        self.network.connect_peers(peer1_id, peer2_id)
        print(f"🔗 Connected '{peer1_id}' ↔ '{peer2_id}'")
    
    def do_switch(self, line):
        """Switch to a different peer: switch <peer_id>"""
        if not line.strip():
            print("Usage: switch <peer_id>")
            return
        
        peer_id = line.strip()
        if peer_id not in self.network.peers:
            print(f"Peer '{peer_id}' does not exist")
            return
        
        self.current_peer = peer_id
        print(f"🎯 Switched to peer '{peer_id}'")
    
    def do_send(self, line):
        """Send a message: send <target_peer> <message>"""
        if not self.current_peer:
            print("No current peer. Use 'create_peer' or 'switch' first.")
            return
        
        args = line.split(None, 1)
        if len(args) != 2:
            print("Usage: send <target_peer> <message>")
            return
        
        target_peer, message = args
        peer = self.running_peers[self.current_peer]
        
        if peer.send_chat_message(target_peer, message):
            print(f"📤 [{self.current_peer}] → [{target_peer}]: {message}")
        else:
            print(f"❌ Failed to send message to {target_peer}")
    
    def do_read(self, line):
        """Read received messages for current peer"""
        if not self.current_peer:
            print("No current peer. Use 'create_peer' or 'switch' first.")
            return
        
        peer = self.running_peers[self.current_peer]
        
        # Process any pending messages
        peer.process_received_messages()
        
        messages = peer.get_chat_messages()
        if not messages:
            print("📭 No messages")
            return
        
        print(f"📨 Messages for '{self.current_peer}':")
        for msg in messages[-10:]:  # Show last 10 messages
            timestamp = time.strftime("%H:%M:%S", time.localtime(msg['timestamp']))
            print(f"  [{timestamp}] {msg['sender']}: {msg['message']}")
        
        # Clear messages after reading
        peer.chat_messages.clear()
    
    def do_sendfile(self, line):
        """Send a file: sendfile <target_peer> <filename> [content]"""
        if not self.current_peer:
            print("No current peer. Use 'create_peer' or 'switch' first.")
            return
        
        args = line.split(None, 2)
        if len(args) < 2:
            print("Usage: sendfile <target_peer> <filename> [content]")
            return
        
        target_peer = args[0]
        filename = args[1]
        
        # Use provided content or read from file
        if len(args) > 2:
            content = args[2].encode('utf-8')
        else:
            try:
                with open(filename, 'rb') as f:
                    content = f.read()
            except FileNotFoundError:
                print(f"File '{filename}' not found")
                return
        
        peer = self.running_peers[self.current_peer]
        
        if peer.send_file(target_peer, filename, content):
            print(f"📎 [{self.current_peer}] → [{target_peer}]: File '{filename}' ({len(content)} bytes)")
        else:
            print(f"❌ Failed to send file to {target_peer}")
    
    def do_listfiles(self, line):
        """List received files for current peer"""
        if not self.current_peer:
            print("No current peer. Use 'create_peer' or 'switch' first.")
            return
        
        peer = self.running_peers[self.current_peer]
        files = peer.get_completed_files()
        
        if not files:
            print("📁 No files received")
            return
        
        print(f"📁 Files received by '{self.current_peer}':")
        for filename, content in files.items():
            print(f"  {filename} ({len(content)} bytes)")
    
    def do_ping(self, line):
        """Ping a peer: ping <target_peer>"""
        if not self.current_peer:
            print("No current peer. Use 'create_peer' or 'switch' first.")
            return
        
        if not line.strip():
            print("Usage: ping <target_peer>")
            return
        
        target_peer = line.strip()
        peer = self.running_peers[self.current_peer]
        
        if peer.ping_peer(target_peer):
            print(f"🏓 Ping sent to {target_peer}")
        else:
            print(f"❌ Failed to ping {target_peer}")
    
    def do_stats(self, line):
        """Show statistics for current peer or all peers"""
        if line.strip() == 'all':
            print("📊 Network Statistics:")
            network_stats = self.network.get_network_stats()
            for key, value in network_stats.items():
                print(f"  {key}: {value}")
            
            print("\n📊 Individual Peer Statistics:")
            for peer_id, peer in self.running_peers.items():
                stats = peer.get_stats()
                print(f"  {peer_id}: {stats['messages_sent']} sent, {stats['messages_received']} received")
        else:
            if not self.current_peer:
                print("No current peer. Use 'create_peer' or 'switch' first.")
                return
            
            peer = self.running_peers[self.current_peer]
            stats = peer.get_stats()
            
            print(f"📊 Statistics for '{self.current_peer}':")
            for key, value in stats.items():
                if key == 'uptime':
                    print(f"  {key}: {value:.1f} seconds")
                elif key == 'connection_time':
                    print(f"  {key}: {time.strftime('%H:%M:%S', time.localtime(value))}")
                else:
                    print(f"  {key}: {value}")
    
    def do_list_peers(self, line):
        """List all peers and their connections"""
        if not self.network.peers:
            print("No peers created yet")
            return
        
        print("👥 Peers:")
        for peer_id, peer in self.network.peers.items():
            status = "🟢" if peer.running else "🔴"
            current_marker = " 👈" if peer_id == self.current_peer else ""
            connections = list(peer.connected_peers.keys())
            connections_str = f" → {connections}" if connections else " (not connected)"
            
            print(f"  {status} {peer_id} (ch:{peer.channel_id}){connections_str}{current_marker}")
    
    def do_demo(self, line):
        """Run a quick demonstration"""
        print("🎬 Running Ouroboros Protocol Demo...")
        
        # Create peers
        print("Creating peers Alice and Bob...")
        self.onecmd("create_peer Alice 1")
        self.onecmd("create_peer Bob 1")
        
        # Connect them
        print("Connecting peers...")
        self.onecmd("connect Alice Bob")
        
        # Send some messages
        print("Sending messages...")
        self.onecmd("switch Alice")
        self.onecmd("send Bob Hello Bob, this is Alice!")
        
        self.onecmd("switch Bob")
        time.sleep(0.1)  # Allow message processing
        self.onecmd("read")
        self.onecmd("send Alice Hi Alice! Bob here.")
        
        self.onecmd("switch Alice")
        time.sleep(0.1)
        self.onecmd("read")
        
        # Send a file
        print("Sending a file...")
        self.onecmd("sendfile Bob test.txt This is a test file content!")
        
        self.onecmd("switch Bob")
        time.sleep(0.1)
        self.onecmd("listfiles")
        
        # Show stats
        print("Final statistics:")
        self.onecmd("stats all")
        
        print("🎉 Demo complete!")
    
    def do_benchmark(self, line):
        """Run a simple performance benchmark"""
        print("🚀 Running simple benchmark...")
        
        # Create test peers
        self.onecmd("create_peer Sender")
        self.onecmd("create_peer Receiver")
        self.onecmd("connect Sender Receiver")
        self.onecmd("switch Sender")
        
        # Send many messages and measure time
        message_count = 100
        start_time = time.time()
        
        for i in range(message_count):
            self.onecmd(f"send Receiver Message {i}")
        
        end_time = time.time()
        
        # Get stats
        sender = self.running_peers['Sender']
        receiver = self.running_peers['Receiver']
        
        # Allow time for message processing
        time.sleep(0.5)
        self.onecmd("switch Receiver")
        receiver._message_worker()  # Process messages
        
        duration = end_time - start_time
        throughput = message_count / duration
        
        print(f"📈 Benchmark Results:")
        print(f"  Messages sent: {message_count}")
        print(f"  Time taken: {duration:.3f} seconds")
        print(f"  Throughput: {throughput:.1f} messages/second")
        print(f"  Sender stats: {sender.stats}")
        print(f"  Receiver stats: {receiver.stats}")
    
    def do_clear(self, line):
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def do_exit(self, line):
        """Exit the CLI"""
        print("🛑 Shutting down...")
        self.network.stop_all()
        print("👋 Goodbye!")
        return True
    
    def do_quit(self, line):
        """Exit the CLI"""
        return self.do_exit(line)
    
    def emptyline(self):
        """Don't repeat last command on empty line"""
        pass
    
    def cmdloop(self, intro=None):
        """Enhanced command loop with error handling"""
        try:
            super().cmdloop(intro)
        except KeyboardInterrupt:
            print("\n🛑 Interrupted")
            self.do_exit("")
        except Exception as e:
            print(f"❌ Error: {e}")


def main():
    """Main entry point for the interactive CLI."""
    cli = OuroborosCLI()
    cli.cmdloop()


if __name__ == "__main__":
    main()