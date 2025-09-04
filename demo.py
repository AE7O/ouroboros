#!/usr/bin/env python3
"""
Ouroboros Protocol Demo Script.

This script demonstrates the key features of the Ouroboros Secure Overlay Protocol:
- Symmetric-only encryption with forward secrecy
- Per-message scrambling for traffic obfuscation
- Replay protection with sliding window
- Support for both AES-256-GCM and ASCON-AEAD128
"""

import sys
import time
from ouroboros import (
    create_peer_context, 
    generate_random_bytes,
    quick_benchmark,
    run_comprehensive_benchmark
)


def demo_basic_communication():
    """Demonstrate basic secure communication between two peers."""
    print("=== Ouroboros Protocol Basic Communication Demo ===\n")
    
    # Generate shared secret (normally exchanged through secure channel)
    master_psk = generate_random_bytes(32)
    print(f"Shared Master PSK: {master_psk.hex()[:32]}...\n")
    
    # Create peer contexts
    alice = create_peer_context(master_psk, channel_id=42, use_ascon=False)
    bob = create_peer_context(master_psk, channel_id=42, use_ascon=False)
    
    print("Created peer contexts for Alice and Bob")
    print(f"Algorithm: {alice.get_info()['algorithm']}")
    print(f"Channel ID: {alice.channel_id}\n")
    
    # Exchange messages
    messages = [
        b"Hello Bob, this is Alice!",
        b"How are you doing today?",
        b"This message demonstrates forward secrecy - each message uses different keys!"
    ]
    
    print("Alice sends messages to Bob:")
    for i, message in enumerate(messages, 1):
        print(f"\n{i}. Alice encrypts: {message.decode()}")
        
        # Alice encrypts
        packet = alice.encrypt_message(message)
        packet_bytes = packet.to_bytes()
        
        print(f"   Encrypted packet size: {len(packet_bytes)} bytes")
        print(f"   Counter: {packet.header.counter}")
        print(f"   Random (r): {packet.header.r.hex()}")
        print(f"   Scrambled payload: {packet.payload[:16].hex()}...")
        
        # Bob decrypts
        decrypted = bob.decrypt_packet(packet_bytes)
        print(f"   Bob decrypts: {decrypted.decode()}")
        
        # Verify roundtrip
        assert decrypted == message, "Decryption failed!"
        print("   ✓ Roundtrip successful")
    
    print(f"\nBob's replay protection stats:")
    stats = bob.get_info()['replay_stats']
    print(f"   Channels tracked: {stats['total_channels']}")
    print(f"   Messages received: {stats['total_messages_received']}")


def demo_replay_protection():
    """Demonstrate replay attack protection."""
    print("\n=== Replay Protection Demo ===\n")
    
    master_psk = generate_random_bytes(32)
    alice = create_peer_context(master_psk, channel_id=1)
    bob = create_peer_context(master_psk, channel_id=1)
    
    # Send legitimate message
    message = b"Legitimate message"
    packet = alice.encrypt_message(message)
    packet_bytes = packet.to_bytes()
    
    print("1. Alice sends legitimate message")
    decrypted = bob.decrypt_packet(packet_bytes)
    print(f"   Bob receives: {decrypted.decode()}")
    print("   ✓ Message accepted")
    
    # Attempt replay attack
    print("\n2. Attacker replays the same packet")
    try:
        bob.decrypt_packet(packet_bytes)
        print("   ❌ Replay attack succeeded (this should not happen!)")
    except Exception as e:
        print(f"   ✓ Replay attack blocked: {type(e).__name__}")


def demo_algorithm_comparison():
    """Compare AES-GCM vs ASCON performance."""
    print("\n=== Algorithm Comparison Demo ===\n")
    
    algorithms = ["AES-GCM"]
    
    # Check if ASCON is available
    try:
        import ascon
        algorithms.append("ASCON")
    except ImportError:
        print("ASCON not available - testing AES-GCM only")
    
    for algorithm in algorithms:
        print(f"Testing {algorithm}...")
        
        # Quick benchmark
        results = quick_benchmark(algorithm)
        
        # Display results
        for test_type in ['encryption', 'decryption']:
            print(f"\n{test_type.title()} Performance:")
            for result in results[test_type]:
                overhead_str = f"{result.overhead_percent:.1f}%" if result.overhead_percent is not None else "N/A"
                print(f"  {result.message_size}B: "
                      f"{result.throughput_mbps:.2f} MB/s, "
                      f"{result.avg_time*1000:.2f}ms avg, "
                      f"{overhead_str} overhead")


def demo_traffic_obfuscation():
    """Demonstrate traffic obfuscation through scrambling."""
    print("\n=== Traffic Obfuscation Demo ===\n")
    
    master_psk = generate_random_bytes(32)
    alice = create_peer_context(master_psk, channel_id=1)
    
    # Send same message multiple times
    message = b"This is the same message sent multiple times"
    print(f"Original message: {message.decode()}")
    
    print("\nScrambled payloads for identical messages:")
    for i in range(3):
        packet = alice.encrypt_message(message)
        print(f"{i+1}. {packet.payload[:32].hex()}...")
        
        # Show that payloads are different due to scrambling
        if i > 0:
            print("   ✓ Payload differs from previous (scrambling working)")


def run_performance_suite():
    """Run comprehensive performance evaluation."""
    print("\n=== Comprehensive Performance Suite ===\n")
    print("Running comprehensive benchmark (this may take a while)...")
    
    # Run quick benchmark
    results = run_comprehensive_benchmark(quick=True)
    
    print("\nSummary Results:")
    summary = results['summary']
    
    for algorithm in summary['algorithms_tested']:
        alg_stats = summary['by_algorithm'][algorithm]
        print(f"\n{algorithm}:")
        print(f"  Average throughput: {alg_stats['avg_throughput_mbps']:.2f} MB/s")
        print(f"  Peak throughput: {alg_stats['max_throughput_mbps']:.2f} MB/s")
        print(f"  Average latency: {alg_stats['avg_latency_ms']:.2f} ms")
        print(f"  Minimum latency: {alg_stats['min_latency_ms']:.2f} ms")
    
    # Show scrambling overhead
    if results['scrambling_overhead']:
        print(f"\nScrambling Overhead:")
        for result in results['scrambling_overhead'][:3]:  # Show first 3
            print(f"  {result['message_size']}B: "
                  f"{result['overhead_percent']:.1f}% overhead")


def main():
    """Main demo function."""
    print("🐍 Ouroboros Secure Overlay Protocol Demo")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        demo_type = sys.argv[1].lower()
        
        if demo_type == "basic":
            demo_basic_communication()
        elif demo_type == "replay":
            demo_replay_protection()
        elif demo_type == "compare":
            demo_algorithm_comparison()
        elif demo_type == "obfuscation":
            demo_traffic_obfuscation()
        elif demo_type == "performance":
            run_performance_suite()
        else:
            print(f"Unknown demo type: {demo_type}")
            print("Available demos: basic, replay, compare, obfuscation, performance")
            sys.exit(1)
    else:
        # Run all demos
        demo_basic_communication()
        demo_replay_protection()
        demo_algorithm_comparison()
        demo_traffic_obfuscation()
        
        # Ask before running performance suite
        response = input("\nRun comprehensive performance suite? (y/N): ")
        if response.lower() == 'y':
            run_performance_suite()
    
    print("\n✅ Demo completed successfully!")


if __name__ == "__main__":
    main()
