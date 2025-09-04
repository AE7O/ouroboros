#!/usr/bin/env python3
"""
Installer script for pyascon - the official ASCON implementation.

This script downloads the official pyascon implementation from:
https://github.com/meichlseder/pyascon

The pyascon module provides NIST SP 800-232 compliant ASCON-AEAD128 
and ASCON-Hash256 implementations for lightweight IoT cryptography.
"""

import os
import urllib.request

def install_pyascon():
    """Download and install pyascon.py to the current directory."""
    
    print("🔄 Installing pyascon (official ASCON implementation)...")
    
    url = "https://raw.githubusercontent.com/meichlseder/pyascon/master/ascon.py"
    target_file = "pyascon.py"
    
    try:
        # Download the file
        print(f"📥 Downloading from {url}")
        urllib.request.urlretrieve(url, target_file)
        
        # Verify the file exists and has content
        if os.path.exists(target_file) and os.path.getsize(target_file) > 0:
            size_kb = os.path.getsize(target_file) // 1024
            print(f"✅ Successfully installed pyascon.py ({size_kb} KB)")
            print("📖 ASCON-AEAD128 and ASCON-Hash256 are now available!")
            return True
        else:
            print("❌ Download failed - file is missing or empty")
            return False
            
    except Exception as e:
        print(f"❌ Installation failed: {e}")
        return False

if __name__ == "__main__":
    success = install_pyascon()
    if success:
        print("\n🎉 pyascon installation complete!")
        print("You can now use ASCON algorithms in Ouroboros Protocol.")
    else:
        print("\n💡 You can also manually download ascon.py from:")
        print("   https://github.com/meichlseder/pyascon")
        print("   and rename it to pyascon.py")
