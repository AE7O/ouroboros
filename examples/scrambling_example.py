#!/usr/bin/env python3
"""
Data Scrambling Module - Example & Test

This demonstrates and tests the data scrambling functionality
including scrambling, unscrambling, and various data sizes.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ouroboros.crypto.scramble import scramble_data, unscramble_data, test_scrambling_roundtrip, ScramblingError
from ouroboros.crypto.kdf import generate_root_key


def main():
    print("🔀 Data Scrambling Module - Example & Test")
    print("=" * 50)
    
    try:
        # Test 1: Basic scrambling/unscrambling
        print("1. Testing basic data scrambling...")
        key = generate_root_key()  # 32-byte key
        test_data = b"This is a test message that will be scrambled and unscrambled to verify functionality."
        
        scrambled = scramble_data(key, test_data)
        assert len(scrambled) == len(test_data), "Scrambled data must be same length as original"
        assert scrambled != test_data, "Scrambled data must be different from original"
        print(f"   Original:  {test_data[:20]}...")
        print(f"   Scrambled: {scrambled[:20].hex()}...")
        
        unscrambled = unscramble_data(key, scrambled)
        assert unscrambled == test_data, "Unscrambling must return original data"
        print(f"   ✅ Roundtrip successful: {len(test_data)} bytes")
        
        # Test 2: Built-in roundtrip test
        print("\n2. Testing built-in roundtrip verification...")
        assert test_scrambling_roundtrip(key, test_data), "Built-in roundtrip test should pass"
        print("   ✅ Built-in roundtrip test passed")
        
        # Test 3: Various data sizes
        print("\n3. Testing various data sizes...")
        test_sizes = [0, 1, 2, 15, 16, 17, 32, 64, 128, 255, 256, 1024]
        
        for size in test_sizes:
            # Generate test data of the correct size
            if size <= 256:
                test_bytes = bytes(range(size))  # Unique byte pattern
            else:
                # For larger sizes, repeat the pattern
                pattern = bytes(range(256))
                test_bytes = (pattern * ((size // 256) + 1))[:size]
            
            scrambled = scramble_data(key, test_bytes)
            unscrambled = unscramble_data(key, scrambled)
            
            assert len(scrambled) == size, f"Scrambled size mismatch for {size} bytes"
            assert unscrambled == test_bytes, f"Roundtrip failed for {size} bytes"
            
            # For size > 1 with diverse data, scrambling should usually change the order
            # (size 0 and 1 cannot be meaningfully scrambled)
            # For very small sizes (2-3), the permutation might occasionally be identical
            # so we only enforce this for larger sizes where it's statistically unlikely
            if size > 3:
                assert scrambled != test_bytes, f"Scrambling had no effect for {size} bytes"
            
            print(f"   ✅ Size {size:4d}: Original→Scrambled→Original")
        
        # Test 4: Key sensitivity
        print("\n4. Testing key sensitivity...")
        key2 = generate_root_key()
        
        scrambled1 = scramble_data(key, test_data)
        scrambled2 = scramble_data(key2, test_data)
        
        assert scrambled1 != scrambled2, "Different keys must produce different scrambled output"
        
        # Wrong key should produce wrong result
        wrong_unscrambled = unscramble_data(key2, scrambled1)
        assert wrong_unscrambled != test_data, "Wrong key should not unscramble correctly"
        print("   ✅ Different keys produce different scrambling")
        
        # Test 5: Deterministic behavior
        print("\n5. Testing deterministic behavior...")
        scrambled_a = scramble_data(key, test_data)
        scrambled_b = scramble_data(key, test_data)
        
        assert scrambled_a == scrambled_b, "Scrambling with same key must be deterministic"
        print("   ✅ Scrambling is deterministic")
        
        # Test 6: Data patterns
        print("\n6. Testing various data patterns...")
        
        # All zeros
        zeros = b'\\x00' * 100
        scrambled_zeros = scramble_data(key, zeros)
        assert unscramble_data(key, scrambled_zeros) == zeros
        assert scrambled_zeros != zeros  # Should not leave zeros unchanged
        print("   ✅ All-zeros pattern scrambled correctly")
        
        # All same byte
        ones = b'\\xff' * 100
        scrambled_ones = scramble_data(key, ones)
        assert unscramble_data(key, scrambled_ones) == ones
        assert scrambled_ones != ones
        print("   ✅ All-ones pattern scrambled correctly")
        
        # Sequential bytes
        sequential = bytes(range(256))
        scrambled_seq = scramble_data(key, sequential)
        assert unscramble_data(key, scrambled_seq) == sequential
        assert scrambled_seq != sequential
        print("   ✅ Sequential pattern scrambled correctly")
        
        # Test 7: Error handling
        print("\n7. Testing error handling...")
        
        # Wrong key length
        try:
            scramble_data(b"short_key", test_data)
            assert False, "Should reject wrong key length"
        except ScramblingError:
            print("   ✅ Correctly rejects wrong key length")
        
        try:
            unscramble_data(b"another_short_key", scrambled)
            assert False, "Should reject wrong key length for unscrambling"
        except ScramblingError:
            print("   ✅ Correctly rejects wrong key length for unscrambling")
        
        # Test 8: Empty data edge case
        print("\n8. Testing empty data edge case...")
        empty_scrambled = scramble_data(key, b"")
        empty_unscrambled = unscramble_data(key, empty_scrambled)
        
        assert empty_scrambled == b"", "Empty data should remain empty when scrambled"
        assert empty_unscrambled == b"", "Empty scrambled data should unscramble to empty"
        print("   ✅ Empty data handled correctly")
        
        print("\n🎉 All data scrambling tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Data scrambling test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
