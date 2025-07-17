#!/usr/bin/env python3
"""
Data Scrambling Demonstration - Step-by-Step Explanation

This example shows exactly how the Ouroboros scrambling works:
1. How the permutation is generated from a key
2. How data is scrambled using the permutation
3. How data is unscrambled using the inverse permutation
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from ouroboros.crypto.scramble import scramble_data, unscramble_data, _generate_permutation, _invert_permutation


def visualize_scrambling_process():
    """Demonstrate scrambling with visual step-by-step explanation."""
    
    print("🔀 Ouroboros Data Scrambling - Step-by-Step Demonstration")
    print("=" * 60)
    
    # Step 1: Setup key and data
    print("\n1️⃣ SETUP")
    print("-" * 30)
    
    # Use a simple key for demonstration
    key = b"my_secret_scrambling_key_32bytes"  # Exactly 32 bytes
    print(f"Scrambling Key: {key}")
    print(f"Key Length: {len(key)} bytes")
    print(f"Key (hex): {key.hex()}")
    
    # Use simple text data
    original_data = b"HELLO_WORLD!"
    print(f"\nOriginal Data: {original_data}")
    print(f"Data Length: {len(original_data)} bytes")
    print(f"Data (hex): {original_data.hex()}")
    
    # Step 2: Show the data as individual bytes with positions
    print("\n2️⃣ DATA BREAKDOWN")
    print("-" * 30)
    print("Position:  ", end="")
    for i in range(len(original_data)):
        print(f"{i:2d} ", end="")
    print()
    
    print("Character: ", end="")
    for byte in original_data:
        print(f"{chr(byte):2s} ", end="")
    print()
    
    print("Hex Value: ", end="")
    for byte in original_data:
        print(f"{byte:02x} ", end="")
    print()
    
    # Step 3: Generate the permutation
    print("\n3️⃣ PERMUTATION GENERATION")
    print("-" * 30)
    
    permutation = _generate_permutation(key, len(original_data))
    print(f"Generated Permutation: {permutation}")
    print("\nPermutation Explanation:")
    print("- This permutation tells us where each byte should go")
    print("- permutation[i] = j means: byte at position i goes to position j")
    print()
    
    for i, j in enumerate(permutation):
        char = chr(original_data[i])
        print(f"  Position {i} ('{char}') → Position {j}")
    
    # Step 4: Apply scrambling manually to show the process
    print("\n4️⃣ SCRAMBLING PROCESS")
    print("-" * 30)
    
    print("Creating scrambled array...")
    scrambled_array = bytearray(len(original_data))
    
    print("\nScrambling steps:")
    for i, j in enumerate(permutation):
        original_byte = original_data[i]
        original_char = chr(original_byte)
        scrambled_array[j] = original_byte
        print(f"  Step {i+1}: Take '{original_char}' from position {i} → put at position {j}")
    
    scrambled_data = bytes(scrambled_array)
    
    # Step 5: Show the result
    print("\n5️⃣ SCRAMBLING RESULT")
    print("-" * 30)
    
    print("BEFORE (Original):")
    print("Position:  ", end="")
    for i in range(len(original_data)):
        print(f"{i:2d} ", end="")
    print()
    print("Character: ", end="")
    for byte in original_data:
        print(f"{chr(byte):2s} ", end="")
    print()
    
    print("\nAFTER (Scrambled):")
    print("Position:  ", end="")
    for i in range(len(scrambled_data)):
        print(f"{i:2d} ", end="")
    print()
    print("Character: ", end="")
    for byte in scrambled_data:
        print(f"{chr(byte):2s} ", end="")
    print()
    
    print(f"\nOriginal:  {original_data}")
    print(f"Scrambled: {scrambled_data}")
    print(f"Scrambled (hex): {scrambled_data.hex()}")
    
    # Verify our manual scrambling matches the function
    function_scrambled = scramble_data(key, original_data)
    print(f"\n✅ Manual scrambling matches function: {scrambled_data == function_scrambled}")
    
    # Step 6: Generate inverse permutation
    print("\n6️⃣ INVERSE PERMUTATION")
    print("-" * 30)
    
    inverse_permutation = _invert_permutation(permutation)
    print(f"Original Permutation: {permutation}")
    print(f"Inverse Permutation:  {inverse_permutation}")
    print("\nInverse Permutation Explanation:")
    print("- This tells us where to find each byte in the scrambled data")
    print("- inverse[i] = j means: to get byte for position i, look at position j")
    print()
    
    for i, j in enumerate(inverse_permutation):
        scrambled_char = chr(scrambled_data[j])
        print(f"  Position {i} ← Position {j} ('{scrambled_char}')")
    
    # Step 7: Apply unscrambling manually
    print("\n7️⃣ UNSCRAMBLING PROCESS")
    print("-" * 30)
    
    print("Creating unscrambled array...")
    unscrambled_array = bytearray(len(scrambled_data))
    
    print("\nUnscrambling steps:")
    for i, j in enumerate(inverse_permutation):
        scrambled_byte = scrambled_data[j]
        scrambled_char = chr(scrambled_byte)
        unscrambled_array[i] = scrambled_byte
        print(f"  Step {i+1}: Take '{scrambled_char}' from position {j} → put at position {i}")
    
    unscrambled_data = bytes(unscrambled_array)
    
    # Step 8: Show final result
    print("\n8️⃣ UNSCRAMBLING RESULT")
    print("-" * 30)
    
    print("BEFORE (Scrambled):")
    print("Position:  ", end="")
    for i in range(len(scrambled_data)):
        print(f"{i:2d} ", end="")
    print()
    print("Character: ", end="")
    for byte in scrambled_data:
        print(f"{chr(byte):2s} ", end="")
    print()
    
    print("\nAFTER (Unscrambled):")
    print("Position:  ", end="")
    for i in range(len(unscrambled_data)):
        print(f"{i:2d} ", end="")
    print()
    print("Character: ", end="")
    for byte in unscrambled_data:
        print(f"{chr(byte):2s} ", end="")
    print()
    
    print(f"\nScrambled:   {scrambled_data}")
    print(f"Unscrambled: {unscrambled_data}")
    print(f"Original:    {original_data}")
    
    # Verify our manual unscrambling matches the function
    function_unscrambled = unscramble_data(key, scrambled_data)
    print(f"\n✅ Manual unscrambling matches function: {unscrambled_data == function_unscrambled}")
    print(f"✅ Roundtrip successful: {original_data == unscrambled_data}")


def demonstrate_key_sensitivity():
    """Show how different keys produce different scrambling."""
    
    print("\n\n🔑 KEY SENSITIVITY DEMONSTRATION")
    print("=" * 60)
    
    original_data = b"SECRET_MESSAGE"
    
    # Two similar keys that differ by just one byte
    key1 = b"key_number_1_for_scrambling_test" 
    key2 = b"key_number_2_for_scrambling_test"  # Only differs in one character
    
    print(f"Original Data: {original_data}")
    print(f"Key 1: {key1}")
    print(f"Key 2: {key2}")
    print(f"Keys differ by: 1 character (position 11: '1' vs '2')")
    
    # Scramble with both keys
    scrambled1 = scramble_data(key1, original_data)
    scrambled2 = scramble_data(key2, original_data)
    
    print(f"\nScrambled with Key 1: {scrambled1}")
    print(f"Scrambled with Key 2: {scrambled2}")
    print(f"Results are different: {scrambled1 != scrambled2}")
    
    # Show the permutations are different
    perm1 = _generate_permutation(key1, len(original_data))
    perm2 = _generate_permutation(key2, len(original_data))
    
    print(f"\nPermutation with Key 1: {perm1}")
    print(f"Permutation with Key 2: {perm2}")
    print(f"Permutations differ: {perm1 != perm2}")


def demonstrate_data_length_impact():
    """Show how data length affects the permutation."""
    
    print("\n\n📏 DATA LENGTH IMPACT DEMONSTRATION")
    print("=" * 60)
    
    key = b"same_key_for_all_length_tests_32"
    
    # Different length data
    data_lengths = [5, 10, 15]
    
    for length in data_lengths:
        data = bytes(range(length))  # [0, 1, 2, 3, 4] for length 5
        permutation = _generate_permutation(key, length)
        scrambled = scramble_data(key, data)
        
        print(f"\nData Length: {length}")
        print(f"Original:    {list(data)}")
        print(f"Permutation: {permutation}")
        print(f"Scrambled:   {list(scrambled)}")


def main():
    """Run all demonstrations."""
    
    try:
        # Main demonstration
        visualize_scrambling_process()
        
        # Additional demonstrations
        demonstrate_key_sensitivity()
        demonstrate_data_length_impact()
        
        print("\n\n🎉 All scrambling demonstrations completed successfully!")
        print("\n💡 KEY INSIGHTS:")
        print("   • Scrambling uses a deterministic permutation based on the key")
        print("   • The same key always produces the same permutation for same-length data")
        print("   • Different keys produce completely different permutations")
        print("   • The process is reversible using the inverse permutation")
        print("   • Data length affects the permutation (longer data = more complex scrambling)")
        
    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
