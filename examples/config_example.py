#!/usr/bin/env python3
"""
Configuration Management Example & Test

This demonstrates Ouroboros configuration handling,
including root key management, protocol parameters,
and secure configuration practices.
"""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ouroboros.crypto.kdf import save_root_key, load_root_key, generate_root_key


class OuroborosConfig:
    """
    Configuration manager for Ouroboros protocol.
    Handles root keys, protocol parameters, and security settings.
    """
    
    DEFAULT_CONFIG = {
        'protocol': {
            'version': 1,
            'max_packet_size': 8192,
            'default_window_size': 1000,
            'session_timeout': 3600,  # 1 hour
            'max_retries': 3
        },
        'crypto': {
            'key_size': 32,  # 256 bits
            'auth_tag_size': 16,  # 128 bits
            'scramble_enabled': True,
            'forward_secrecy': True
        },
        'network': {
            'default_port': 8998,
            'bind_address': '0.0.0.0',
            'timeout': 30,
            'keepalive': True
        },
        'security': {
            'strict_counter_validation': True,
            'require_authentication': True,
            'log_security_events': True,
            'secure_memory': True
        }
    }
    
    def __init__(self, config_dir: str = None):
        if config_dir is None:
            config_dir = os.path.expanduser('~/.ouroboros')
        
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / 'config.json'
        self.keys_dir = self.config_dir / 'keys'
        
        # Ensure directories exist
        self.config_dir.mkdir(mode=0o700, exist_ok=True)
        self.keys_dir.mkdir(mode=0o700, exist_ok=True)
        
        # Load or create configuration
        self.config = self._load_config()
    
    def _load_config(self) -> dict:
        """Load configuration from file or create default"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults for missing keys
                return self._merge_configs(self.DEFAULT_CONFIG, config)
        else:
            # Create default configuration
            self.save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()
    
    def _merge_configs(self, default: dict, user: dict) -> dict:
        """Recursively merge user config with defaults"""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def save_config(self, config: dict = None):
        """Save configuration to file"""
        if config is not None:
            self.config = config
        
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
        
        # Secure the config file
        os.chmod(self.config_file, 0o600)
    
    def get(self, key_path: str, default=None):
        """Get configuration value using dot notation (e.g., 'crypto.key_size')"""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value):
        """Set configuration value using dot notation"""
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
        self.save_config()
    
    def create_root_key(self, key_id: str = 'default') -> str:
        """Create and save a new root key"""
        root_key = generate_root_key()
        key_file = self.keys_dir / f'{key_id}.key'
        save_root_key(root_key, str(key_file))
        return str(key_file)
    
    def get_root_key_path(self, key_id: str = 'default') -> str:
        """Get path to root key file"""
        return str(self.keys_dir / f'{key_id}.key')
    
    def load_root_key(self, key_id: str = 'default') -> bytes:
        """Load root key from file"""
        key_file = self.get_root_key_path(key_id)
        return load_root_key(key_file)
    
    def list_root_keys(self) -> list:
        """List available root key IDs"""
        keys = []
        for key_file in self.keys_dir.glob('*.key'):
            keys.append(key_file.stem)
        return sorted(keys)
    
    def validate_config(self) -> list:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Check required sections
        required_sections = ['protocol', 'crypto', 'network', 'security']
        for section in required_sections:
            if section not in self.config:
                issues.append(f"Missing required section: {section}")
        
        # Validate specific values
        if self.get('crypto.key_size') not in [16, 24, 32]:
            issues.append("crypto.key_size must be 16, 24, or 32")
        
        if self.get('protocol.version') != 1:
            issues.append("Only protocol version 1 is supported")
        
        if self.get('protocol.max_packet_size') > 65535:
            issues.append("max_packet_size cannot exceed 65535")
        
        if self.get('network.default_port') not in range(1, 65536):
            issues.append("default_port must be between 1 and 65535")
        
        return issues


def main():
    print("⚙️  Configuration Management - Example & Test")
    print("=" * 50)
    
    try:
        # Test 1: Basic configuration creation
        print("1. Testing configuration creation...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config = OuroborosConfig(temp_dir)
            
            # Check default values
            assert config.get('protocol.version') == 1, "Default protocol version should be 1"
            assert config.get('crypto.key_size') == 32, "Default key size should be 32"
            assert config.get('network.default_port') == 8998, "Default port should be 8998"
            
            print("   ✅ Configuration created with defaults")
            
            # Test 2: Configuration file persistence
            print("\n2. Testing configuration persistence...")
            
            # Modify configuration
            config.set('network.default_port', 9999)
            config.set('protocol.max_packet_size', 4096)
            
            # Create new config instance (should load from file)
            config2 = OuroborosConfig(temp_dir)
            
            assert config2.get('network.default_port') == 9999, "Port should be persisted"
            assert config2.get('protocol.max_packet_size') == 4096, "Packet size should be persisted"
            assert config2.get('crypto.key_size') == 32, "Other defaults should remain"
            
            print("   ✅ Configuration persistence working")
            
            # Test 3: Root key management
            print("\n3. Testing root key management...")
            
            # Create root key
            key_file = config.create_root_key('test_key')
            assert os.path.exists(key_file), "Root key file should be created"
            
            # Load root key
            loaded_key = config.load_root_key('test_key')
            assert len(loaded_key) == 32, "Root key should be 32 bytes"
            
            # List keys
            keys = config.list_root_keys()
            assert 'test_key' in keys, "Test key should be listed"
            
            print(f"   ✅ Root key created and loaded: {len(keys)} keys available")
            
            # Test 4: Multiple root keys
            print("\n4. Testing multiple root keys...")
            
            # Create additional keys
            config.create_root_key('alice_key')
            config.create_root_key('bob_key')
            config.create_root_key('iot_device_001')
            
            keys = config.list_root_keys()
            expected_keys = ['alice_key', 'bob_key', 'iot_device_001', 'test_key']
            
            for expected_key in expected_keys:
                assert expected_key in keys, f"Key {expected_key} should exist"
                loaded = config.load_root_key(expected_key)
                assert len(loaded) == 32, f"Key {expected_key} should be 32 bytes"
            
            print(f"   ✅ Multiple keys managed: {len(keys)} total")
            
            # Test 5: Configuration validation
            print("\n5. Testing configuration validation...")
            
            # Valid configuration
            issues = config.validate_config()
            assert len(issues) == 0, f"Valid config should have no issues: {issues}"
            
            # Invalid configuration
            config.set('crypto.key_size', 15)  # Invalid key size
            config.set('protocol.version', 2)   # Unsupported version
            config.set('network.default_port', 70000)  # Invalid port
            
            issues = config.validate_config()
            assert len(issues) >= 3, "Invalid config should have issues"
            
            print(f"   ✅ Validation found {len(issues)} issues as expected")
            
            # Test 6: Nested configuration access
            print("\n6. Testing nested configuration access...")
            
            # Deep nesting
            config.set('advanced.encryption.algorithms.primary', 'AES-GCM')
            config.set('advanced.encryption.algorithms.fallback', 'ChaCha20-Poly1305')
            
            primary = config.get('advanced.encryption.algorithms.primary')
            fallback = config.get('advanced.encryption.algorithms.fallback')
            
            assert primary == 'AES-GCM', "Primary algorithm should be set"
            assert fallback == 'ChaCha20-Poly1305', "Fallback algorithm should be set"
            
            # Non-existent path with default
            missing = config.get('non.existent.path', 'default_value')
            assert missing == 'default_value', "Should return default for missing path"
            
            print("   ✅ Nested configuration access working")
            
            # Test 7: Configuration merging
            print("\n7. Testing configuration merging...")
            
            # Create partial configuration
            partial_config = {
                'protocol': {
                    'max_packet_size': 16384  # Override default
                },
                'custom': {
                    'feature_enabled': True,
                    'debug_mode': False
                }
            }
            
            # Create new config with partial overrides
            config3 = OuroborosConfig(temp_dir)
            config3.save_config(partial_config)
            
            # Reload to test merging
            config4 = OuroborosConfig(temp_dir)
            
            # Should have merged values
            assert config4.get('protocol.max_packet_size') == 16384, "Should use override"
            assert config4.get('protocol.version') == 1, "Should keep defaults"
            assert config4.get('custom.feature_enabled') == True, "Should have custom config"
            
            print("   ✅ Configuration merging working")
            
            # Test 8: Secure file permissions
            print("\n8. Testing secure file permissions...")
            
            # Check config file permissions
            config_stat = os.stat(config.config_file)
            config_perms = oct(config_stat.st_mode)[-3:]
            assert config_perms == '600', f"Config file should be 600, got {config_perms}"
            
            # Check key directory permissions
            keys_stat = os.stat(config.keys_dir)
            keys_perms = oct(keys_stat.st_mode)[-3:]
            assert keys_perms == '700', f"Keys directory should be 700, got {keys_perms}"
            
            print("   ✅ File permissions are secure")
            
            # Test 9: Environment-specific configurations
            print("\n9. Testing environment-specific configurations...")
            
            # IoT device configuration
            iot_config = {
                'protocol': {'max_packet_size': 1024},  # Smaller for IoT
                'crypto': {'scramble_enabled': True},
                'network': {'timeout': 10},  # Shorter timeout
                'security': {'strict_counter_validation': True}
            }
            
            config.save_config(iot_config)
            
            # Verify IoT-specific settings
            assert config.get('protocol.max_packet_size') == 1024, "IoT packet size"
            assert config.get('network.timeout') == 10, "IoT timeout"
            assert config.get('crypto.scramble_enabled') == True, "IoT scrambling"
            
            print("   ✅ Environment-specific configuration working")
            
            # Test 10: Configuration export/import
            print("\n10. Testing configuration export/import...")
            
            # Export current configuration
            exported = config.config.copy()
            
            # Modify and import
            exported['protocol']['version'] = 1
            exported['custom']['exported'] = True
            
            config.save_config(exported)
            
            # Verify import
            assert config.get('custom.exported') == True, "Exported flag should be set"
            
            print("   ✅ Configuration export/import working")
        
        print("\n🎉 All configuration management tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Configuration management test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
