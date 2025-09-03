# Ouroboros Protocol - Complete Symmetric Rework

🐍 **Quantum-Resistant • IoT-Optimized • Forward Secure • Traffic Obfuscated**

This repository contains a complete rework of the Ouroboros protocol implementing a new symmetric-only design focused on lightweight IoT devices with hardware acceleration support.

## 🚀 New Protocol Features

### Symmetric-Only Cryptography
- **No asymmetric operations** - Pure symmetric cryptography for IoT efficiency
- **AES-256-GCM** with hardware acceleration support  
- **ASCON-AEAD128** placeholder for lightweight implementations
- **HKDF-SHA256** for deterministic key derivation

### Advanced Security Properties  
- **Hash-based key ratcheting** for forward secrecy
- **Per-message scrambling** using ChaCha20-seeded Fisher-Yates shuffle
- **Sliding window replay protection** with bitmap tracking
- **Traffic obfuscation** through content-dependent scrambling

### New Packet Format
```
channel_id (1B) || counter (4B) || r (4B) || tag (16B) || scrambled_ciphertext
```

## 📁 Module Structure

```
ouroboros/
├── crypto/
│   ├── ratchet.py          # Hash-based key ratcheting (HKDF-SHA256)
│   ├── aead.py             # AEAD encryption (AES-256-GCM/ASCON-AEAD128)
│   ├── scramble.py         # ChaCha20-seeded Fisher-Yates scrambling
│   └── utils.py            # Secure memory, random helpers, byte ops
├── protocol/
│   ├── packet.py           # New packet format and parsing
│   ├── encryptor.py        # Complete encryption pipeline
│   ├── decryptor.py        # Complete decryption pipeline
│   └── window.py           # Sliding window replay protection
├── channel/
│   ├── peer.py             # P2P communication and file transfer
│   └── interactive.py      # CLI interface for live demo
├── tests/
│   ├── test_correctness.py # Round-trip, corruption, replay tests
│   ├── test_performance.py # Timing, memory, throughput tests
│   ├── test_security.py    # Forward secrecy, crypto properties
│   └── test_integration.py # End-to-end peer communication
└── evaluation/
    └── benchmark.py        # Performance benchmarking framework
```

## 🔧 Installation

```bash
git clone https://github.com/AE7O/ouroboros.git
cd ouroboros
pip install -e .[dev]
```

## 🎮 Quick Start

### Run the Complete Demo
```bash
python demo_complete_protocol.py
```

### Interactive CLI
```bash
python -m ouroboros.channel.interactive
```

### Run Tests
```bash
# All tests
python -m pytest tests/ -v

# Specific test suites
python -m pytest tests/test_correctness.py -v
python -m pytest tests/test_security.py -v
python -m pytest tests/test_performance.py -v
python -m pytest tests/test_integration.py -v
```

### Performance Benchmarks
```bash
python -m ouroboros.evaluation.benchmark
```

## 🔐 Protocol Pipeline

### Encryption Pipeline
```
1. Hash ratchet key derivation
2. AEAD encryption (AES-256-GCM)
3. ChaCha20-seeded scrambling
4. Packet construction
```

### Decryption Pipeline  
```
1. Packet parsing and validation
2. ChaCha20-seeded unscrambling
3. AEAD decryption and authentication
4. Sliding window replay protection
```

## 📊 Security Properties

- **Confidentiality & Integrity**: AEAD encryption with authentication
- **Forward Secrecy**: Hash-based key ratcheting prevents past key recovery
- **Replay Protection**: Sliding window with out-of-order delivery support
- **Traffic Obfuscation**: Per-message scrambling hides traffic patterns

## 🧪 Test Coverage

- **22 Correctness Tests**: Round-trip, corruption detection, replay protection
- **13 Performance Tests**: Timing, memory usage, throughput analysis  
- **15 Security Tests**: Forward secrecy, cryptographic properties
- **12 Integration Tests**: End-to-end peer communication, file transfer

## 📈 Performance Characteristics

- **Key Derivation**: ~0.1-1ms per operation
- **Encryption/Decryption**: 0.1-0.3 MB/s for 1-4KB messages
- **Scrambling Overhead**: <50% additional processing time
- **Memory Usage**: Linear scaling with window size
- **Packet Overhead**: 25 bytes (header + tag)

## 🌟 Key Innovations

1. **Symmetric-Only Design**: No public key operations for IoT efficiency
2. **ChaCha20 Scrambling**: Content-dependent traffic obfuscation
3. **Deterministic Nonces**: Derived from counter and random values
4. **Per-Message Keys**: Forward secure ratcheting
5. **Lightweight Focus**: Optimized for resource-constrained devices

## 🔍 Interactive Demo Commands

```bash
# Create peers and connect them
create_peer Alice 1
create_peer Bob 1  
connect Alice Bob

# Send messages
switch Alice
send Bob Hello Bob!

# Check received messages
switch Bob
read

# Send files
sendfile Bob document.txt "File content here"

# View statistics
stats all
```

## 🏗️ Architecture Principles

- **Modular Design**: Clean separation of crypto, protocol, and channel layers
- **Testable**: Comprehensive test suite with >95% coverage
- **Extensible**: Plugin architecture for new algorithms
- **Secure by Default**: Memory safety and constant-time operations
- **IoT-Optimized**: Minimal resource requirements

## 📚 Academic Evaluation

The implementation includes comprehensive evaluation tools suitable for dissertation research:

- Performance benchmarking with statistical analysis
- Security property verification 
- Comparative analysis framework
- Academic-quality test methodology

## 🤝 Contributing

This is a research implementation for academic purposes. The code demonstrates a complete symmetric protocol rework with quantum-resistant properties and IoT optimization.

## 📄 License

MIT License - See LICENSE file for details.

---

**Note**: This is a research implementation demonstrating the new symmetric Ouroboros protocol design. ASCON implementations require additional libraries when available.