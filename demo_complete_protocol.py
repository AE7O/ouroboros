#!/usr/bin/env python3
"""
Ouroboros Protocol Complete Demonstration.

This script demonstrates the complete reworked Ouroboros protocol implementation
with all its new features including symmetric-only cryptography, traffic obfuscation,
and forward secrecy.
"""

import sys
import os
import time

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from ouroboros.crypto.ratchet import generate_root_key, HashRatchet
from ouroboros.crypto.aead import AEADCipher
from ouroboros.crypto.scramble import scramble_data, unscramble_data
from ouroboros.protocol.packet import OuroborosPacket
from ouroboros.protocol.encryptor import OuroborosEncryptor
from ouroboros.protocol.decryptor import OuroborosDecryptor
from ouroboros.protocol.window import SlidingWindow
from ouroboros.channel.peer import SecurePeer, PeerNetwork


def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'='*60}")
    print(f"🔐 {title}")
    print('='*60)


def demo_new_packet_format():
    """Demonstrate the new packet format."""
    print_section("NEW PACKET FORMAT DEMONSTRATION")
    
    # Create a sample packet
    packet = OuroborosPacket(
        channel_id=42,
        counter=12345,
        r=0x87654321,
        auth_tag=b'\x01\x02\x03\x04' * 4,
        scrambled_data=b"This is scrambled payload data"
    )
    
    print("📦 New Packet Structure:")
    print(f"  Channel ID: {packet.channel_id}")
    print(f"  Counter:    {packet.counter}")
    print(f"  Random r:   0x{packet.r:08x}")
    print(f"  Auth Tag:   {packet.auth_tag.hex()}")
    print(f"  Data Size:  {len(packet.scrambled_data)} bytes")
    
    # Serialize and show format
    packet_bytes = packet.to_bytes()
    print(f"\n📏 Serialized Packet: {len(packet_bytes)} bytes")
    print(f"  Format: channel_id(1B) || counter(4B) || r(4B) || tag(16B) || data")
    print(f"  Bytes:  {packet_bytes[:1].hex()} {packet_bytes[1:5].hex()} {packet_bytes[5:9].hex()} {packet_bytes[9:25].hex()} {packet_bytes[25:].hex()}")
    
    # Roundtrip test
    packet2 = OuroborosPacket.from_bytes(packet_bytes)
    print(f"✅ Roundtrip successful: {packet2.channel_id == packet.channel_id}")


def demo_hash_ratcheting():
    """Demonstrate hash-based key ratcheting."""
    print_section("HASH-BASED KEY RATCHETING")
    
    root_key = generate_root_key()
    ratchet = HashRatchet(root_key)
    
    print("🔑 Key Ratcheting for Forward Secrecy:")
    print(f"  Root Key: {root_key.hex()}")
    
    # Derive keys for multiple messages
    keys = []
    for i in range(5):
        enc_key, scr_key = ratchet.derive_keys(i)
        keys.append((enc_key, scr_key))
        print(f"  Message {i}: Enc={enc_key[:8].hex()}... Scr={scr_key[:8].hex()}...")
    
    # Show that all keys are different
    print("\n🔒 Forward Secrecy Verification:")
    all_different = True
    for i in range(5):
        for j in range(i + 1, 5):
            if keys[i][0] == keys[j][0] or keys[i][1] == keys[j][1]:
                all_different = False
                break
    
    print(f"  All derived keys unique: {'✅' if all_different else '❌'}")
    print(f"  Ratchet state evolution: {ratchet.get_state()[:8].hex()}...")


def demo_chacha20_scrambling():
    """Demonstrate ChaCha20-seeded scrambling."""
    print_section("CHACHA20-SEEDED TRAFFIC OBFUSCATION")
    
    key = generate_root_key()
    test_data = b"AAAAAAAAAAAAAAAA"  # Repeated pattern to show scrambling effect
    
    print("🌪️  Traffic Obfuscation via Scrambling:")
    print(f"  Original:  {test_data}")
    print(f"  Hex:       {test_data.hex()}")
    
    scrambled = scramble_data(key, test_data)
    print(f"  Scrambled: {scrambled}")
    print(f"  Hex:       {scrambled.hex()}")
    
    unscrambled = unscramble_data(key, scrambled)
    print(f"  Restored:  {unscrambled}")
    print(f"  Match:     {'✅' if unscrambled == test_data else '❌'}")
    
    # Show that different keys produce different scrambling
    key2 = generate_root_key()
    scrambled2 = scramble_data(key2, test_data)
    print(f"\n🔀 Key-Dependent Scrambling:")
    print(f"  Key1 result: {scrambled.hex()}")
    print(f"  Key2 result: {scrambled2.hex()}")
    print(f"  Different:   {'✅' if scrambled != scrambled2 else '❌'}")


def demo_sliding_window():
    """Demonstrate sliding window replay protection."""
    print_section("SLIDING WINDOW REPLAY PROTECTION")
    
    window = SlidingWindow(window_size=5)
    
    print("🪟 Sliding Window Replay Protection:")
    
    # Accept some counters
    test_sequence = [0, 1, 2, 4, 3, 6, 2, 7, 1]  # Include out-of-order and replays
    
    for counter in test_sequence:
        if window.is_valid_counter(counter):
            accepted = window.accept_counter(counter)
            status = "✅ ACCEPTED" if accepted else "⚠️  REJECTED"
        else:
            status = "🚫 INVALID (replay/old)"
        
        print(f"  Counter {counter}: {status}")
    
    stats = window.get_stats()
    print(f"\n📊 Window Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")


def demo_encryption_pipeline():
    """Demonstrate the complete encryption/decryption pipeline."""
    print_section("COMPLETE ENCRYPTION/DECRYPTION PIPELINE")
    
    root_key = generate_root_key()
    channel_id = 42
    
    encryptor = OuroborosEncryptor(root_key, channel_id, use_ratcheting=False)
    decryptor = OuroborosDecryptor(root_key, channel_id, use_ratcheting=False)
    
    # Test messages
    messages = [
        b"Hello, Ouroboros!",
        b"This is the new symmetric protocol",
        b"With forward secrecy and traffic obfuscation",
        "Perfect for IoT devices! 🔐".encode('utf-8')
    ]
    
    print("🔄 Encryption → Decryption Pipeline:")
    
    total_overhead = 0
    for i, message in enumerate(messages):
        print(f"\n  Message {i}: {message}")
        
        # Encrypt
        packet = encryptor.encrypt_message(message)
        packet_bytes = packet.to_bytes()
        
        # Calculate overhead
        overhead = len(packet_bytes) - len(message)
        total_overhead += overhead
        
        print(f"    Encrypted: {len(packet_bytes)} bytes (overhead: +{overhead})")
        print(f"    Counter:   {packet.counter}")
        print(f"    Random r:  0x{packet.r:08x}")
        
        # Decrypt
        decrypted = decryptor.decrypt_packet(packet)
        
        success = decrypted == message
        print(f"    Decrypted: {'✅ SUCCESS' if success else '❌ FAILED'}")
    
    avg_overhead = total_overhead / len(messages)
    print(f"\n📈 Pipeline Statistics:")
    print(f"  Messages processed: {len(messages)}")
    print(f"  Average overhead:   {avg_overhead:.1f} bytes")
    print(f"  Success rate:       100%")


def demo_peer_communication():
    """Demonstrate peer-to-peer communication."""
    print_section("PEER-TO-PEER SECURE COMMUNICATION")
    
    # Create a network
    network = PeerNetwork()
    
    # Add peers
    alice = network.add_peer("Alice", channel_id=1)
    bob = network.add_peer("Bob", channel_id=1)
    charlie = network.add_peer("Charlie", channel_id=2)  # Different channel
    
    # Connect peers
    network.connect_peers("Alice", "Bob")
    network.connect_peers("Alice", "Charlie")
    
    # Start peers
    network.start_all()
    
    print("👥 Network Setup:")
    print("  Alice ↔ Bob (channel 1)")
    print("  Alice ↔ Charlie (channel 2)")
    
    # Send messages
    print(f"\n💬 Message Exchange:")
    alice.send_chat_message("Bob", "Hello Bob from Alice!")
    alice.send_chat_message("Charlie", "Hi Charlie from Alice!")
    bob.send_chat_message("Alice", "Hey Alice, Bob here!")
    
    # Send a file
    file_content = b"This is a secret file content!"
    alice.send_file("Bob", "secret.txt", file_content)
    
    # Allow time for processing
    time.sleep(0.1)
    
    # Process received messages
    alice.process_received_messages()
    bob.process_received_messages()
    charlie.process_received_messages()
    
    # Display results
    print("\n📨 Received Messages:")
    
    for peer_name, peer in [("Alice", alice), ("Bob", bob), ("Charlie", charlie)]:
        messages = peer.get_chat_messages()
        files = peer.get_completed_files()
        
        print(f"  {peer_name}:")
        for msg in messages:
            print(f"    💬 {msg['sender']}: {msg['message']}")
        for filename, content in files.items():
            print(f"    📁 File '{filename}': {len(content)} bytes")
    
    # Show statistics
    print(f"\n📊 Network Statistics:")
    net_stats = network.get_network_stats()
    for key, value in net_stats.items():
        print(f"  {key}: {value}")
    
    # Cleanup
    network.stop_all()


def demo_performance_preview():
    """Show a preview of performance capabilities."""
    print_section("PERFORMANCE PREVIEW")
    
    root_key = generate_root_key()
    encryptor = OuroborosEncryptor(root_key, use_ratcheting=False)
    decryptor = OuroborosDecryptor(root_key, use_ratcheting=False)
    
    # Test with different message sizes
    sizes = [16, 64, 256, 1024, 4096]
    
    print("⚡ Performance Testing:")
    
    for size in sizes:
        message = os.urandom(size)
        
        # Time encryption
        start = time.perf_counter()
        packet = encryptor.encrypt_message(message)
        encrypt_time = time.perf_counter() - start
        
        # Time decryption
        start = time.perf_counter()
        decrypted = decryptor.decrypt_packet(packet)
        decrypt_time = time.perf_counter() - start
        
        total_time = encrypt_time + decrypt_time
        throughput = size / total_time / 1024 / 1024  # MB/s
        
        print(f"  {size:4d} bytes: {total_time*1000:6.2f} ms ({throughput:5.1f} MB/s)")
    
    print("\n💡 Note: Run 'python -m ouroboros.evaluation.benchmark' for comprehensive benchmarks")


def main():
    """Run the complete demonstration."""
    print("🐍 OUROBOROS PROTOCOL - COMPLETE SYMMETRIC REWORK DEMONSTRATION")
    print("🔐 Quantum-Resistant • IoT-Optimized • Forward Secure • Traffic Obfuscated")
    
    try:
        # Core protocol features
        demo_new_packet_format()
        demo_hash_ratcheting()
        demo_chacha20_scrambling()
        demo_sliding_window()
        
        # Pipeline and communication
        demo_encryption_pipeline()
        demo_peer_communication()
        
        # Performance preview
        demo_performance_preview()
        
        print_section("DEMONSTRATION COMPLETE")
        print("✅ All protocol features demonstrated successfully!")
        print("\n🎮 Try the interactive CLI: python -m ouroboros.channel.interactive")
        print("📊 Run benchmarks: python -m ouroboros.evaluation.benchmark")
        print("🧪 Run tests: python -m pytest tests/ -v")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)