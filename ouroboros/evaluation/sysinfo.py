"""
System information capture for reproducible evaluation results.
"""

import platform
import sys
import json
from typing import Dict, Any, Optional


def capture_system_info() -> Dict[str, Any]:
    """Capture comprehensive system information for evaluation reproducibility."""
    sysinfo = {
        "timestamp": get_timestamp(),
        "system": get_system_info(),
        "python": get_python_info(),
        "hardware": get_hardware_info(),
        "libraries": get_library_versions()
    }
    return sysinfo


def get_timestamp() -> str:
    """Get current timestamp."""
    from datetime import datetime
    return datetime.now().isoformat()


def get_system_info() -> Dict[str, Any]:
    """Get operating system information."""
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor()
    }


def get_python_info() -> Dict[str, Any]:
    """Get Python interpreter information."""
    return {
        "version": sys.version,
        "version_info": {
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
            "micro": sys.version_info.micro
        },
        "executable": sys.executable,
        "implementation": platform.python_implementation()
    }


def get_hardware_info() -> Dict[str, Any]:
    """Get hardware information where available."""
    hardware = {}
    
    try:
        import psutil
        
        # CPU information
        cpu_freq = psutil.cpu_freq()
        hardware["cpu"] = {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "max_frequency_mhz": cpu_freq.max if cpu_freq else None,
            "current_frequency_mhz": cpu_freq.current if cpu_freq else None
        }
        
        # Memory information
        memory = psutil.virtual_memory()
        hardware["memory"] = {
            "total_gb": round(memory.total / (1024**3), 2),
            "available_gb": round(memory.available / (1024**3), 2),
            "used_percent": memory.percent
        }
        
    except ImportError:
        hardware["note"] = "psutil not available - hardware info limited"
    
    # Try to get CPU model from /proc/cpuinfo on Linux
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if 'model name' in line:
                    hardware["cpu_model"] = line.split(':')[1].strip()
                    break
    except (FileNotFoundError, PermissionError):
        # Not Linux or no access
        pass
    
    return hardware


def get_library_versions() -> Dict[str, Any]:
    """Get versions of relevant libraries."""
    versions = {}
    
    # Core crypto libraries
    try:
        import cryptography
        versions["cryptography"] = cryptography.__version__
    except ImportError:
        versions["cryptography"] = "not available"
    
    try:
        # Check for our local pyascon copy
        import pyascon
        versions["pyascon"] = "local implementation"
    except ImportError:
        versions["pyascon"] = "not available"
    
    # Evaluation libraries
    try:
        import psutil
        versions["psutil"] = psutil.__version__
    except ImportError:
        versions["psutil"] = "not available"
    
    try:
        import matplotlib
        versions["matplotlib"] = matplotlib.__version__
    except ImportError:
        versions["matplotlib"] = "not available"
    
    try:
        import pandas
        versions["pandas"] = pandas.__version__
    except ImportError:
        versions["pandas"] = "not available"
    
    try:
        import numpy
        versions["numpy"] = numpy.__version__
    except ImportError:
        versions["numpy"] = "not available"
    
    # Check for OQS (PQC library)
    try:
        import oqs
        versions["oqs"] = getattr(oqs, 'oqs_version', lambda: 'unknown')()
    except ImportError:
        versions["oqs"] = "not available"
    except:
        versions["oqs"] = "available but version unknown"
    
    return versions
