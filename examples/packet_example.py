#!/usr/bin/env python3
"""
Packet Handling Module - Example & Test

This demonstrates and tests the Ouroboros packet structure,
serialization, deserialization, and packet type handling.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ouroboros.protocol.packet import (
    OuroborosPacket, PacketType, PacketError,
    create_ack_packet, create_nack_packet
)


def main():
    print("📦 Packet Handling Module - Example & Test")
    print("=" * 50)
    
    try:
        # Test 1: Basic packet creation and properties
        print("1. Testing basic packet creation...")
        
        packet = OuroborosPacket(
            version=1,
            packet_type=PacketType.DATA,
            flags=0x42,
            counter=12345,
            scrambled_data=b"This is test scrambled data payload",
            auth_tag=b"1234567890abcdef"  # 16 bytes
        )
        
        assert packet.version == 1, "Version should be set correctly"
        assert packet.packet_type == PacketType.DATA, "Packet type should be DATA"
        assert packet.flags == 0x42, "Flags should be set correctly"
        assert packet.counter == 12345, "Counter should be set correctly"
        assert packet.is_data_packet(), "Should identify as data packet"
        assert not packet.is_ack_packet(), "Should not identify as ACK packet"
        assert not packet.is_control_packet(), "Should not identify as control packet"
        
        print(f"   ✅ Created packet: type={packet.packet_type.name}, counter={packet.counter}")
        
        # Test 2: Packet serialization
        print("\n2. Testing packet serialization...")
        
        packet_bytes = packet.to_bytes()
        expected_length = 8 + 8 + len(packet.scrambled_data) + 16  # header + counter + data + auth_tag
        
        assert len(packet_bytes) == expected_length, f"Packet length should be {expected_length}"
        print(f"   ✅ Serialized to {len(packet_bytes)} bytes")
        print(f"   Header: {packet_bytes[:8].hex()}")
        print(f"   Counter: {packet_bytes[8:16].hex()}")
        
        # Test 3: Packet deserialization
        print("\n3. Testing packet deserialization...")
        
        deserialized_packet = OuroborosPacket.from_bytes(packet_bytes)
        
        assert deserialized_packet.version == packet.version, "Version should match after deserialization"
        assert deserialized_packet.packet_type == packet.packet_type, "Type should match"
        assert deserialized_packet.flags == packet.flags, "Flags should match"
        assert deserialized_packet.counter == packet.counter, "Counter should match"
        assert deserialized_packet.scrambled_data == packet.scrambled_data, "Data should match"
        assert deserialized_packet.auth_tag == packet.auth_tag, "Auth tag should match"
        
        print(f"   ✅ Deserialized: type={deserialized_packet.packet_type.name}, counter={deserialized_packet.counter}")
        
        # Test 4: Different packet types
        print("\n4. Testing different packet types...")
        
        test_packets = [
            (PacketType.DATA, "DATA packet"),
            (PacketType.ACK, "ACK packet"),
            (PacketType.NACK, "NACK packet"),
            (PacketType.PING, "PING packet"),
            (PacketType.PONG, "PONG packet"),
        ]
        
        for ptype, description in test_packets:
            test_packet = OuroborosPacket(
                packet_type=ptype,
                counter=100 + ptype.value,
                auth_tag=b"x" * 16
            )
            
            # Test packet identification methods
            if ptype == PacketType.DATA:
                assert test_packet.is_data_packet(), f"{description} identification failed"
                assert not test_packet.is_control_packet(), f"{description} should not be control"
            elif ptype == PacketType.ACK:
                assert test_packet.is_ack_packet(), f"{description} identification failed"
                assert test_packet.is_control_packet(), f"{description} should be control"
            else:
                assert test_packet.is_control_packet(), f"{description} should be control"
                assert not test_packet.is_data_packet(), f"{description} should not be data"
            
            # Test serialization roundtrip
            serialized = test_packet.to_bytes()
            deserialized = OuroborosPacket.from_bytes(serialized)
            assert deserialized.packet_type == ptype, f"{description} roundtrip failed"
            
            print(f"   ✅ {description}: serialization and identification work")
        
        # Test 5: Helper functions
        print("\n5. Testing packet helper functions...")
        
        ack_packet = create_ack_packet(54321)
        assert ack_packet.packet_type == PacketType.ACK, "ACK packet type should be set"
        assert ack_packet.counter == 54321, "ACK counter should be set"
        assert ack_packet.is_ack_packet(), "Should identify as ACK"
        print(f"   ✅ ACK packet created: counter={ack_packet.counter}")
        
        nack_packet = create_nack_packet(98765)
        assert nack_packet.packet_type == PacketType.NACK, "NACK packet type should be set"
        assert nack_packet.counter == 98765, "NACK counter should be set"
        assert nack_packet.is_control_packet(), "Should identify as control packet"
        print(f"   ✅ NACK packet created: counter={nack_packet.counter}")
        
        # Test 6: Various payload sizes
        print("\n6. Testing various payload sizes...")
        
        test_sizes = [0, 1, 16, 64, 256, 1024, 4096]
        
        for size in test_sizes:
            test_data = b"X" * size
            test_packet = OuroborosPacket(
                packet_type=PacketType.DATA,
                counter=size,
                scrambled_data=test_data,
                auth_tag=b"Y" * 16
            )
            
            serialized = test_packet.to_bytes()
            deserialized = OuroborosPacket.from_bytes(serialized)
            
            assert len(deserialized.scrambled_data) == size, f"Payload size {size} roundtrip failed"
            assert deserialized.scrambled_data == test_data, f"Payload data {size} roundtrip failed"
            
            print(f"   ✅ Payload size {size:4d}: serialization roundtrip successful")
        
        # Test 7: Edge cases and validation
        print("\n7. Testing edge cases and validation...")
        
        # Maximum counter value
        max_packet = OuroborosPacket(
            counter=2**64 - 1,
            auth_tag=b"Z" * 16
        )
        max_serialized = max_packet.to_bytes()
        max_deserialized = OuroborosPacket.from_bytes(max_serialized)
        assert max_deserialized.counter == 2**64 - 1, "Maximum counter should work"
        print("   ✅ Maximum counter value handled correctly")
        
        # Header extraction
        header_bytes = packet.get_header_bytes()
        assert len(header_bytes) == 8, "Header should be 8 bytes"
        print(f"   ✅ Header extraction: {header_bytes.hex()}")
        
        # Test 8: Error handling
        print("\n8. Testing error handling...")
        
        # Invalid packet data
        try:
            OuroborosPacket.from_bytes(b"too_short")
            assert False, "Should reject packet that's too short"
        except PacketError:
            print("   ✅ Correctly rejects packet that's too short")
        
        # Invalid version
        try:
            OuroborosPacket(version=16)  # > 15
            assert False, "Should reject invalid version"
        except PacketError:
            print("   ✅ Correctly rejects invalid version")
        
        # Invalid auth tag length
        try:
            OuroborosPacket(auth_tag=b"short_tag")
            assert False, "Should reject invalid auth tag length"
        except PacketError:
            print("   ✅ Correctly rejects invalid auth tag length")
        
        print("\n🎉 All packet handling tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Packet handling test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
