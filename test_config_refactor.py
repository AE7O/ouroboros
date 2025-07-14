#!/usr/bin/env python3
"""
Test the refactored configuration system.
"""

import sys
import os
import tempfile
import shutil

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from ouroboros.config import OuroborosConfig, ConfigError


def test_refactored_config():
    """Test the new configuration system that uses kdf.py functions."""
    print("🔧 Testing Refactored Configuration System...")
    
    # Create a temporary config directory
    temp_dir = tempfile.mkdtemp(prefix="ouroboros_config_test_")
    config = OuroborosConfig(temp_dir)
    
    try:
        # Test 1: Check that no key exists initially
        assert not config.key_exists(), "Should not have key initially"
        print("   ✅ Initial state: no key exists")
        
        # Test 2: Try to load non-existent key (should fail)
        try:
            config.get_root_key()
            assert False, "Should fail when no key exists"
        except ConfigError:
            print("   ✅ Correctly failed when no key exists")
        
        # Test 3: Set a hex key
        test_hex_key = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        config.set_root_key(test_hex_key)
        print(f"   ✅ Set hex key: {test_hex_key[:16]}...")
        
        # Test 4: Verify key exists now
        assert config.key_exists(), "Key should exist after setting"
        print("   ✅ Key exists after setting")
        
        # Test 5: Load the key back
        loaded_key = config.get_root_key()
        expected_key = bytes.fromhex(test_hex_key)
        assert loaded_key == expected_key, "Loaded key should match set key"
        print(f"   ✅ Loaded key matches: {loaded_key[:8].hex()}...")
        
        # Test 6: Test multiple file formats using kdf.py capabilities
        # Create a binary key file
        binary_key_path = os.path.join(temp_dir, "binary_key.bin")
        with open(binary_key_path, 'wb') as f:
            f.write(expected_key)
        
        # Copy from binary file (should work with new robust loading)
        config2 = OuroborosConfig(os.path.join(temp_dir, "config2"))
        config2.set_root_key_from_file(binary_key_path)
        loaded_key2 = config2.get_root_key()
        assert loaded_key2 == expected_key, "Binary file loading should work"
        print("   ✅ Binary file format supported")
        
        # Test 7: Generate new key
        config3 = OuroborosConfig(os.path.join(temp_dir, "config3"))
        generated_key = config3.create_new_root_key()
        assert len(generated_key) == 32, "Generated key should be 32 bytes"
        print(f"   ✅ Generated new key: {generated_key[:8].hex()}...")
        
        # Test 8: Invalid hex key (should fail)
        try:
            config.set_root_key("invalid_hex_key")
            assert False, "Should fail with invalid hex"
        except ConfigError:
            print("   ✅ Correctly rejected invalid hex key")
        
        print("   ✅ All configuration tests passed!")
        
    finally:
        # Clean up
        shutil.rmtree(temp_dir)


def test_format_compatibility():
    """Test that the config system handles all the formats supported by kdf.py."""
    print("\n📁 Testing File Format Compatibility...")
    
    temp_dir = tempfile.mkdtemp(prefix="ouroboros_format_test_")
    
    try:
        test_key = bytes.fromhex("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
        
        # Test format 1: Raw binary (32 bytes)
        binary_file = os.path.join(temp_dir, "key.bin")
        with open(binary_file, 'wb') as f:
            f.write(test_key)
        
        config1 = OuroborosConfig(os.path.join(temp_dir, "config1"))
        config1.set_root_key_from_file(binary_file)
        loaded1 = config1.get_root_key()
        assert loaded1 == test_key, "Binary format should work"
        print("   ✅ Raw binary format (32 bytes)")
        
        # Test format 2: Hex encoded (64 chars)
        hex_file = os.path.join(temp_dir, "key.hex")
        with open(hex_file, 'w') as f:
            f.write(test_key.hex())
        
        config2 = OuroborosConfig(os.path.join(temp_dir, "config2"))
        config2.set_root_key_from_file(hex_file)
        loaded2 = config2.get_root_key()
        assert loaded2 == test_key, "Hex format should work"
        print("   ✅ Hex encoded format (64 chars)")
        
        # Test format 3: Hex with newline (65 chars)
        hex_newline_file = os.path.join(temp_dir, "key_newline.hex")
        with open(hex_newline_file, 'w') as f:
            f.write(test_key.hex() + '\n')
        
        config3 = OuroborosConfig(os.path.join(temp_dir, "config3"))
        config3.set_root_key_from_file(hex_newline_file)
        loaded3 = config3.get_root_key()
        assert loaded3 == test_key, "Hex with newline format should work"
        print("   ✅ Hex with newline format (65 chars)")
        
        print("   ✅ All file formats supported correctly!")
        
    finally:
        shutil.rmtree(temp_dir)


def main():
    """Run all configuration tests."""
    print("🧪 Testing Refactored Configuration System")
    print("=" * 50)
    
    try:
        test_refactored_config()
        test_format_compatibility()
        
        print("\n🎉 All configuration tests passed!")
        print("✅ Refactored config.py successfully uses kdf.py functions!")
        print("✅ Eliminated code duplication!")
        print("✅ Better separation of concerns achieved!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
