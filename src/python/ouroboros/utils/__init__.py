"""
Utility functions and helpers for Ouroboros Protocol.
"""

from .counter import CounterManager, CounterError
from .memory import secure_zero, SecureBytes

__all__ = [
    'CounterManager',
    'CounterError', 
    'secure_zero',
    'SecureBytes'
]
