"""
Configuration management for Ouroboros Protocol.

Simplified approach: Root key is loaded once and used to bootstrap
the session key chain. No complex tracking needed since root key
is inherently one-time use.

This module handles application-level configuration while delegating
cryptographic file operations to the kdf module.
"""

import os
from typing import Optional
from .crypto.kdf import load_root_key, create_root_key_file


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
        Load the pre-provisioned root key using kdf module.
        
        Supports multiple file formats:
        - Raw binary (32 bytes)
        - Hex encoded (64 characters)
        - Hex encoded with newline (65 characters)
        
        Returns:
            bytes: The 32-byte root key
            
        Raises:
            ConfigError: If root key cannot be loaded
        """
        if not os.path.exists(self.key_file_path):
            raise ConfigError(f"Root key file not found: {self.key_file_path}")
        
        try:
            # Use kdf module for robust file format handling
            return load_root_key(self.key_file_path)
        except FileNotFoundError:
            raise ConfigError(f"Root key file not found: {self.key_file_path}")
        except ValueError as e:
            raise ConfigError(f"Invalid root key format: {e}")
        except Exception as e:
            raise ConfigError(f"Failed to load root key: {e}")
    
    def set_root_key(self, hex_key: str) -> None:
        """
        Set the root key from hex string (for setup/testing).
        
        Args:
            hex_key: 64-character hex string
            
        Raises:
            ConfigError: If key format is invalid
        """
        if len(hex_key) != 64:
            raise ConfigError("Root key must be 64 hex characters (32 bytes)")
        
        try:
            # Validate hex format by converting to bytes
            root_key_bytes = bytes.fromhex(hex_key)
        except ValueError:
            raise ConfigError("Invalid hex characters in root key")
        
        try:
            # Use kdf module for consistent file creation
            create_root_key_file(self.key_file_path, root_key_bytes)
            print(f"Root key saved to: {self.key_file_path}")
        except Exception as e:
            raise ConfigError(f"Failed to save root key: {e}")
    
    def set_root_key_from_file(self, source_file: str) -> None:
        """
        Copy root key from another file.
        
        Args:
            source_file: Path to existing root key file
            
        Raises:
            ConfigError: If source file cannot be read or key is invalid
        """
        try:
            # Load from source using robust kdf function
            root_key = load_root_key(source_file)
            
            # Save to config location
            create_root_key_file(self.key_file_path, root_key)
            print(f"Root key copied to: {self.key_file_path}")
            
        except FileNotFoundError:
            raise ConfigError(f"Source key file not found: {source_file}")
        except ValueError as e:
            raise ConfigError(f"Invalid source key format: {e}")
        except Exception as e:
            raise ConfigError(f"Failed to copy root key: {e}")
    
    def create_new_root_key(self) -> bytes:
        """
        Generate a new root key for testing/development.
        
        Returns:
            bytes: The generated 32-byte root key
            
        Raises:
            ConfigError: If key generation or saving fails
        """
        try:
            # Use kdf module to generate and save new key
            root_key = create_root_key_file(self.key_file_path)
            print(f"Generated new root key: {root_key.hex()}")
            print(f"Saved to: {self.key_file_path}")
            return root_key
        except Exception as e:
            raise ConfigError(f"Failed to create new root key: {e}")
    
    def key_exists(self) -> bool:
        """Check if a root key file exists."""
        return os.path.exists(self.key_file_path)