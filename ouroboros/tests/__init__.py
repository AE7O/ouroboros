"""
Test suite for Ouroboros Protocol.

This package contains comprehensive tests for all components:
- test_correctness.py: Round-trip, corruption, replay protection
- test_performance.py: Timing, memory, scrambling overhead  
- test_security.py: Forward secrecy, per-message uniqueness
- test_integration.py: End-to-end peer communication
"""

__all__ = [
    'test_correctness',
    'test_performance',
    'test_security',
    'test_integration'
]
