"""
Ouroboros Protocol - Quantum-Resistant Secure Channel for IoT

A lightweight, symmetric-crypto-only protocol designed for secure communication
between IoT devices, providing forward secrecy and quantum resistance.
"""

__version__ = "0.1.0"
__author__ = "Ouroboros Project"
__description__ = "Quantum-resistant secure channel protocol for IoT devices"

# Core protocol components
from .protocol.session import OuroborosSession
from .transport.udp import UDPTransport

# Main API exports
__all__ = [
    'OuroborosSession',
    'UDPTransport',
    '__version__'
]
