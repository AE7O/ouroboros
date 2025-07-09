# Ouroboros: Quantum-Resistant Symmetric-Key Protocol for IoT

A lightweight, stateful cryptographic protocol designed for secure communication in closed IoT ecosystems, with particular focus on resource-constrained devices like Raspberry Pi.

## Project Overview

Ouroboros is a novel quantum-resistant symmetric-key protocol specifically designed for secure IoT communications. Unlike traditional approaches that rely on asymmetric cryptography vulnerable to quantum attacks, Ouroboros uses only symmetric-key primitives and hash functions to achieve quantum resistance while maintaining lightweight operation suitable for embedded devices.

The protocol addresses the unique challenges of IoT environments: limited computational resources, intermittent connectivity, and the need for long-term security in a post-quantum world. By implementing a stateful ratcheting mechanism with robust state synchronization, Ouroboros provides forward secrecy and resilience against device compromise.

**Primary Use Cases:**
- Industrial IoT sensor networks
- Smart meter deployments
- Medical device communications
- Any closed ecosystem where devices communicate with a central server

## Key Features

### 🔐 Quantum Resistance
- **No asymmetric cryptography**: Completely avoids number theory-based algorithms vulnerable to Shor's algorithm
- **Symmetric primitives only**: Built entirely on AES, SHA-3, and HKDF
- **Future-proof security**: Resistant to both classical and quantum attacks

### 🪶 Lightweight Operation
- **Raspberry Pi optimized**: Designed for resource-constrained devices
- **Minimal computational overhead**: Fast symmetric operations only
- **Low memory footprint**: Efficient state management

### 🔄 Forward Secrecy
- **Key ratcheting mechanism**: Automatic key evolution after each message
- **Compromise resilience**: Past messages remain secure even if current key is compromised
- **Perfect forward secrecy**: Each session key is cryptographically independent

### 🔗 Robust State Management
- **Synchronization handling**: Automatic recovery from lost messages
- **Counter-based tracking**: Message ordering and gap detection
- **Device reboot resilience**: State persistence across power cycles

## Protocol Outline

### 1. Initial Provisioning
- **Pre-shared key (PSK) distribution**: Master secret embedded during manufacturing/provisioning
- **Device registration**: Each device receives unique PSK with central server
- **Secure bootstrapping**: Initial state establishment

### 2. Key Derivation
- **HKDF-based expansion**: Master PSK stretched into key chain using HMAC-SHA256
- **Deterministic generation**: Both parties derive identical key sequences
- **Key isolation**: Each session key cryptographically independent

### 3. Ratcheting Mechanism
- **Hash-based evolution**: State updated after each message using SHA-3
- **Bidirectional ratcheting**: Both sender and receiver advance state
- **Forward secrecy guarantee**: Previous keys cannot be recovered

### 4. State Synchronization
- **Counter inclusion**: Each message contains sequence number
- **Gap detection**: Receiver identifies missing messages
- **Catch-up mechanism**: Automatic ratcheting to synchronize states
- **Bounded recovery**: Configurable maximum synchronization window

### 5. Message Processing
- **Encrypt-then-MAC**: AES-GCM for authenticated encryption
- **Replay protection**: Counter-based message ordering
- **Integrity verification**: HMAC validation of all messages

## Getting Started

### Prerequisites
- Raspberry Pi 3B+ or newer (or compatible ARM device)
- Python 3.8+ or C compiler (GCC)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/AE7O/ouroboros.git
   cd ouroboros
   ```

2. **Set up Python environment** (Python implementation)
   ```bash
   python3 -m venv ouroboros-env
   source ouroboros-env/bin/activate
   pip install -r requirements.txt
   ```

3. **Build C implementation** (C implementation)
   ```bash
   make clean
   make
   ```

### Basic Usage

1. **Initialize device**
   ```bash
   # Generate and provision pre-shared key
   python3 provision.py --device-id sensor-01 --output device.key
   ```

2. **Start server**
   ```bash
   # Launch central server
   python3 server.py --config server.conf
   ```

3. **Run client**
   ```bash
   # Start IoT device client
   python3 client.py --key device.key --server-addr 192.168.1.100:8080
   ```

### Configuration

Edit `config.yaml` to customize:
- Key derivation parameters
- Ratcheting intervals
- Synchronization windows
- Network timeouts

### Example Applications

See the `examples/` directory for:
- Temperature sensor simulation
- Smart meter data collection
- Medical device telemetry
- Industrial monitoring system

## Roadmap

### Current Phase (v0.1)
- [x] Core protocol specification
- [x] Python reference implementation
- [ ] Basic state synchronization
- [ ] Raspberry Pi optimization

### Phase 2 (v0.2)
- [ ] C implementation for embedded systems
- [ ] Advanced synchronization algorithms
- [ ] Performance benchmarking suite
- [ ] Memory optimization

### Phase 3 (v0.3)
- [ ] Example IoT applications
- [ ] Deployment automation scripts
- [ ] Security analysis tools
- [ ] Documentation website

### Phase 4 (v1.0)
- [ ] Production hardening
- [ ] Formal security verification
- [ ] Multi-platform support
- [ ] Performance optimization

### Future Enhancements
- [ ] Group communication support
- [ ] Hardware security module (HSM) integration
- [ ] Mesh networking capabilities
- [ ] Real-time analytics dashboard

## Development

### Contributing
We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) for details on:
- Code style and standards
- Testing requirements
- Pull request process
- Security considerations

### Testing
```bash
# Run test suite
python3 -m pytest tests/

# Performance benchmarks
python3 benchmarks/performance.py

# Security analysis
python3 tools/security_analysis.py
```

### Documentation
- [Protocol Specification](docs/protocol.md)
- [API Reference](docs/api.md)
- [Security Analysis](docs/security.md)
- [Performance Guide](docs/performance.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Attribution

This project is part of a Master's dissertation research on cryptography, focusing on quantum-resistant protocols for IoT systems. The work explores novel approaches to symmetric-key cryptography and stateful protocol design.

**Academic Context:**
- *Title*: "A Stateful, Symmetric-Key Protocol for Quantum-Resistant Communication in Closed IoT Ecosystems"
- *Focus*: Novel cryptographic protocol design for post-quantum IoT security
- *Institution*: [University Name]
- *Year*: 2024

## Contact

For questions, suggestions, or collaboration opportunities:

- **Issues**: [GitHub Issues](https://github.com/AE7O/ouroboros/issues)
- **Discussions**: [GitHub Discussions](https://github.com/AE7O/ouroboros/discussions)
- **Email**: [Contact Email]

### Research Collaboration
If you're interested in academic collaboration or have research questions about the protocol design, please reach out through the contact methods above.

---

*"In cryptography, as in mythology, the ouroboros represents the cycle of renewal - each key derived from the last, each message securing the next, in an endless chain of protection."*
