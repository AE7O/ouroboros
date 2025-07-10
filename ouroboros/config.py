"""
Configuration management for Ouroboros Protocol.

Simplified approach: Root key is loaded once and used to bootstrap
the session key chain. No complex tracking needed since root key
is inherently one-time use.
"""

import os
from typing import Optional


class ConfigError(Exception):
    """Raised when configuration operations fail."""
    pass


class OuroborosConfig:
    """
    Simple configuration manager for Ouroboros Protocol.
    
    Handles loading the pre-provisioned root key for one-time use.
    """
    
    def __init__(self, config_dir: str = None):
        """
        Initialize configuration.
        
        Args:
            config_dir: Directory for configuration files. Defaults to ~/.ouroboros/
        """
        if config_dir is None:
            config_dir = os.path.expanduser("~/.ouroboros")
        
        self.config_dir = config_dir
        self.key_file_path = os.path.join(config_dir, "root_key.hex")
        
        # Create config directory if it doesn't exist
        os.makedirs(config_dir, exist_ok=True)
    
    def get_root_key(self) -> bytes:
        """
        Load the pre-provisioned root key.
        
        Returns:
            bytes: The 32-byte root key
            
        Raises:
            ConfigError: If root key cannot be loaded
        """
        if not os.path.exists(self.key_file_path):
            raise ConfigError(f"Root key file not found: {self.key_file_path}")
        
        try:
            with open(self.key_file_path, 'r') as f:
                hex_key = f.read().strip()
            
            if len(hex_key) != 64:
                raise ConfigError("Root key must be 64 hex characters (32 bytes)")
            
            root_key = bytes.fromhex(hex_key)
            return root_key
            
        except (ValueError, IOError) as e:
            raise ConfigError(f"Failed to load root key: {e}")
    
    def set_root_key(self, hex_key: str) -> None:
        """
        Set the root key from hex string (for setup/testing).
        
        Args:
            hex_key: 64-character hex string
        """
        if len(hex_key) != 64:
            raise ConfigError("Root key must be 64 hex characters (32 bytes)")
        
        try:
            # Validate hex format
            bytes.fromhex(hex_key)
        except ValueError:
            raise ConfigError("Invalid hex characters in root key")
        
        with open(self.key_file_path, 'w') as f:
            f.write(hex_key)
        
        # Set restrictive permissions
        try:
            os.chmod(self.key_file_path, 0o600)
        except (OSError, AttributeError):
            pass  # Windows or permission error
        
        print(f"Root key saved to: {self.key_file_path}")
    
    def key_exists(self) -> bool:
        """Check if a root key file exists."""
        return os.path.exists(self.key_file_path)