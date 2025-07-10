# Ouroboros Protocol

Ouroboros is a lightweight, quantum-resistant secure channel protocol purpose-built for IoT. It combines high efficiency with robust modern security guarantees, making it ideal for resource-constrained devices such as Raspberry Pi and embedded sensors.

## Core Philosophy

Ouroboros achieves robust, future-proof security using only symmetric cryptography. It’s designed for closed ecosystems where a master root secret can be pre-installed on each device and its server. This approach eliminates the need for slow, complex public-key operations while delivering exceptional performance and security.

## Secure Message Lifecycle

**1. Provisioning:**  
Each device is initialised with the same master key, securely loaded at setup.

**2. Session Key Derivation:**  
For every message, the protocol uses the current Root Key and a message counter to derive two single-use session keys:
- One for authenticated encryption
- One for data scrambling

**3. Authenticated Encryption:**  
The data is encrypted with AES-GCM (or similar), producing ciphertext and an authentication tag (tamper-proof seal).

**4. Scrambling:**  
The ciphertext and tag are scrambled using a cryptographic permutation seeded by the second session key. This makes every packet unique and further obfuscates traffic patterns.

**5. Reliable Delivery:**  
The device sends the scrambled packet and waits for an acknowledgement (ACK). If no ACK is received in time, the packet is retransmitted. Using a similar approach to the CoAP protocol.

**6. Decoding:**  
Upon receipt, the server uses the same session keys to unscramble and then decrypt the data, verifying the authentication tag for integrity.

**7. Ratcheting:**  
After a successful exchange, both sides update their Root Key by hashing the old key with the authentication tag from the confirmed message. This irreversible process ensures that even if a key is compromised, past and future messages remain secure.

## Why Ouroboros?

- **Quantum-Resistant:** No reliance on public-key crypto—immune to quantum attacks targeting number-theoretic algorithms.
- **Forward Secrecy:** Each message uses its own cryptographic state; keys are never reused.
- **Layered Security:** Data is both encrypted and scrambled, maximising confidentiality and resisting traffic analysis.
- **Resilient:** Reliable delivery and replay protection by design.
- **Lightweight:** Suitable for microcontrollers, Raspberry Pi, and any low-power device.

## Usage and Implementation

- See the repository for a proof-of-concept implementation in Python (or C).
- Designed for easy integration into IoT projects or secure communication between trusted endpoints.

---

This protocol is part of ongoing research for a Master's dissertation on cryptography and welcomes feedback and collaboration.
