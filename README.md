# 🐍 Ouroboros Secure Overlay Protocol

A **lightweight, symmetric-only secure communication protocol** for IoT environments. Ouroboros provides TLS-like security using only symmetric cryptography and hash functions, with no asymmetric operations required.

## 🔹 Key Features

- **Symmetric-Only Cryptography**: No public key operations - perfect for resource-constrained devices
- **Forward Secrecy**: Hash-based key ratcheting ensures past messages remain secure
- **Replay Protection**: Sliding window mechanism prevents replay attacks
- **Traffic Obfuscation**: Per-message scrambling provides protocol-level traffic analysis resistance
- **Dual Algorithm Support**: Choose between AES-256-GCM (hardware accelerated) or ASCON-AEAD128 (lightweight)
- **IoT Optimized**: Minimal overhead and memory footprint

## 🔹 Protocol Overview

### Message Format
```
header = channel_id (1B) || counter (4B) || r (4B) || tag (16B)
payload = scrambled_ciphertext
packet  = header || payload
```

### Encryption Pipeline
1. **Derive Keys**: Extract `ke`, `nonce`, and `kp` from ratchet using `channel_id` + `counter`
2. **Generate Random**: Create per-message random `r` (4 bytes)
3. **AEAD Encrypt**: Produce `(ciphertext, tag)` using AES-256-GCM or ASCON-AEAD128
4. **Scramble**: Apply Fisher-Yates shuffle with ChaCha20 PRNG seeded from `(kp, tag, r)`
5. **Build Packet**: Construct final packet with visible header and scrambled payload

### Security Guarantees
- **Confidentiality & Integrity**: AEAD encryption
- **Forward Secrecy**: Hash-based key ratcheting  
- **Replay Protection**: Sliding window with bitmap tracking
- **Traffic Obfuscation**: Content-dependent per-message scrambling

## 🚀 Quick Start

### Installation
```bash
# Clone repository
git clone https://github.com/AE7O/ouroboros.git
cd ouroboros

# Install dependencies
pip install -r requirements.txt

# Install package
pip install -e .
```

### Basic Usage
```python
from ouroboros import create_peer_context, generate_random_bytes

# Create shared secret (normally exchanged securely)
master_psk = generate_random_bytes(32)

# Create peer contexts
alice = create_peer_context(master_psk, channel_id=42)
bob = create_peer_context(master_psk, channel_id=42)

# Alice encrypts message
packet = alice.encrypt_message(b"Hello, Bob!")

# Bob decrypts message  
plaintext = bob.decrypt_packet(packet.to_bytes())
print(plaintext)  # b"Hello, Bob!"
```

### Advanced Configuration
```python
# Use ASCON for lightweight environments
alice = create_peer_context(master_psk, channel_id=1, use_ascon=True)

# Access low-level components
from ouroboros.crypto.ratchet import RatchetState
from ouroboros.protocol.encryptor import EncryptionEngine

ratchet = RatchetState(master_psk, use_ascon=True)
encryptor = EncryptionEngine(ratchet, channel_id=1, use_ascon=True)
```

## 🔬 Demonstrations

### Run Interactive Demo
```bash
# Basic communication demo
python demo.py basic

# Replay protection demo  
python demo.py replay

# Algorithm comparison
python demo.py compare

# Traffic obfuscation demo
python demo.py obfuscation

# Performance evaluation
python demo.py performance

# Run all demos
python demo.py
```

### Example Output
```
=== Ouroboros Protocol Basic Communication Demo ===

Created peer contexts for Alice and Bob
Algorithm: AES-256-GCM
Channel ID: 42

Alice sends messages to Bob:

1. Alice encrypts: Hello Bob, this is Alice!
   Encrypted packet size: 67 bytes
   Counter: 0
   Random (r): a1b2c3d4
   Scrambled payload: 8f2e1a9c4b7d3e8f...
   Bob decrypts: Hello Bob, this is Alice!
   ✓ Roundtrip successful
```

## 📊 Performance

### Benchmark Results (Example)
| Algorithm   | Message Size | Throughput | Latency | Overhead |
|-------------|--------------|------------|---------|----------|
| AES-256-GCM | 1024B       | 45.2 MB/s  | 0.022ms | 2.4%     |
| ASCON-AEAD  | 1024B       | 12.8 MB/s  | 0.078ms | 2.4%     |

### Run Benchmarks
```python
from ouroboros import quick_benchmark, run_comprehensive_benchmark

# Quick benchmark
results = quick_benchmark("AES-GCM")

# Comprehensive evaluation
full_results = run_comprehensive_benchmark(quick=False)
```

## 🏗️ Architecture

### Module Structure
```
ouroboros/
├── crypto/                 # Cryptographic primitives
│   ├── ratchet.py         # Key derivation & ratcheting
│   ├── aead.py            # AEAD encrypt/decrypt wrappers  
│   ├── scramble.py        # Data scrambling with Fisher-Yates
│   └── utils.py           # Secure memory & utilities
├── protocol/              # Protocol implementation
│   ├── packet.py          # Packet structure & parsing
│   ├── encryptor.py       # Encryption pipeline
│   ├── decryptor.py       # Decryption pipeline  
│   └── window.py          # Sliding window replay protection
├── channel/               # Communication layer
│   ├── io.py              # Socket I/O & framing
│   ├── peer.py            # Peer-to-peer logic
│   └── interactive.py     # CLI interface
├── tests/                 # Test suite
│   ├── test_correctness.py # Round-trip & corruption tests
│   ├── test_performance.py # Performance benchmarks
│   ├── test_security.py   # Security property validation
│   └── test_integration.py # End-to-end testing
└── evaluation/            # Research evaluation tools
    ├── benchmark.py       # Performance measurement
    ├── charts.py          # Visualization
    └── report.py          # Academic reporting
```

## 🧪 Testing

### Run Test Suite
```bash
# Install test dependencies
pip install pytest pytest-cov

# Run correctness tests
python -m pytest ouroboros/tests/test_correctness.py -v

# Run with coverage
python -m pytest ouroboros/tests/ --cov=ouroboros --cov-report=html

# Run specific test
python -m pytest ouroboros/tests/test_correctness.py::TestCryptoCorrectness::test_ratchet_key_derivation
```

### Test Categories
- **Correctness**: Round-trip encryption, corruption rejection, replay prevention
- **Performance**: Throughput, latency, memory usage benchmarks  
- **Security**: Forward secrecy, message uniqueness, key isolation
- **Integration**: End-to-end peer communication scenarios

## 🔧 Development

### Dependencies
- **Core**: `cryptography>=41.0.0` (AES-GCM implementation)
- **Optional**: `ascon>=1.0.0` (lightweight AEAD for IoT)
- **Testing**: `pytest>=7.0.0`, `pytest-cov>=4.0.0`
- **Evaluation**: `matplotlib>=3.5.0`, `numpy>=1.21.0`

### Code Quality
```bash
# Format code
black ouroboros/

# Type checking  
mypy ouroboros/

# Linting
flake8 ouroboros/
```

## 📚 Research & Academic Use

This implementation is designed for academic research and includes:

- **Comprehensive benchmarking** with statistical analysis
- **Visualization tools** for performance charts and graphs
- **Evaluation suite** producing dissertation-ready outputs
- **Configurable parameters** for research experimentation
- **Detailed logging** and profiling capabilities

### Citation
If you use Ouroboros in academic work, please cite:
```bibtex
@software{ouroboros_protocol,
  title={Ouroboros: Symmetric-Only Secure Overlay Protocol},
  author={Your Name},
  year={2025},
  url={https://github.com/AE7O/ouroboros}
}
```

## 🛡️ Security Considerations

- **Pre-shared keys** must be exchanged through a secure channel
- **Key derivation** uses HKDF-SHA256 or ASCON-Hash256
- **Replay protection** requires synchronized counter state
- **Forward secrecy** is achieved through hash-based ratcheting
- **Traffic analysis resistance** via per-message scrambling

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/AE7O/ouroboros/issues)
- **Discussions**: [GitHub Discussions](https://github.com/AE7O/ouroboros/discussions)
- **Documentation**: [Wiki](https://github.com/AE7O/ouroboros/wiki)

---

**Ouroboros Protocol** - Secure, Lightweight, Symmetric-Only Communication for the IoT Era 🔒
