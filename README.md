Concept: Two systems are synchronized. They share an initial secret seed. Over time, they both generate a long, identical sequence of random-looking values. To communicate at time T, they both use a public value (like a hash of T) to agree on which value from the sequence to use as the session key.
Analysis: This is your most promising path to a novel dissertation. It avoids classical asymmetric cryptography entirely and is based on principles that are known to be quantum-resistant. Your intuition here is spot on. This idea is closely related to Hash-Based Cryptography.
Strengths:
It relies only on symmetric-key primitives (the initial secret) and hash functions (for generating the sequence). Hash functions and symmetric ciphers are considered quantum-resistant.
It is extremely fast and lightweight once the initial secret is in place.
Challenges (This is where your dissertation's novelty lies):
The Initial Seed: How do the two systems agree on the very first secret seed? This is the Achilles' heel. If you use RSA/ECC to exchange it, the whole system is broken.
State Management: What happens if a message is lost and one device generates a new key but the other doesn't? They become out of sync. Managing this "state" is a major challenge.
A Feasible Dissertation Path: The "Pre-Shared Key" Model for IoT
Scenario: An organization is deploying a set of IoT devices that will only ever talk to the organization's central server (e.g., sensors in a factory, smart meters for a utility, medical devices in a hospital).
Your Dissertation Proposal:
Title: A Stateful, Symmetric-Key Protocol for Quantum-Resistant Communication in Closed IoT Ecosystems
Methodology:
The Foundation (Solving the Seed Problem): Assume a pre-shared key (PSK) model. A single master secret key is securely embedded into each IoT device and the server during the manufacturing or provisioning process. This is your "initial seed." This is a realistic and common practice for closed systems.
The Core Protocol (Your Novel Contribution): Design a protocol built on this PSK. This is where your novelty comes from, not from inventing a new hash function, but from inventing the rules of communication.
Key Derivation: Use a standard Key Derivation Function (like HKDF, based on HMAC-SHA256) to stretch the master PSK into a long chain of future session keys.
Key Ratcheting: Design a "ratchet" mechanism. After each message, both sides use a hash function to update their state and derive the next key. This provides forward secrecy—if an attacker compromises a device and finds the current session key, they cannot use it to decrypt past messages. This is a highly desirable property.
State Synchronization: This is the hardest part and a great research challenge. Design a mechanism to handle lost messages or device reboots. For example, each message could include a counter. If the server receives a message with a future counter, it knows it missed some and can perform a defined number of ratchet steps to catch up.
Why this meets your goals:
It is Novel: You are not just implementing Kyber. You are designing a complete communication protocol with a ratchet, state management, and key derivation rules tailored for IoT. This is a significant piece of engineering and research.
It Avoids Mainstream PQC: It sidesteps the need for PQC asymmetric algorithms like Kyber/Dilithium and instead relies entirely on symmetric primitives (AES, SHA-3, HKDF), which are part of a different branch of quantum-safe cryptography.
It's Genuinely Quantum-Resistant: Because it never uses number theory-based asymmetric crypto, Shor's algorithm is completely irrelevant. Its security rests on the strength of the underlying hash functions and symmetric ciphers.
This approach allows you to satisfy your desire for novelty while grounding your work in established cryptographic principles, giving you a clear and achievable path to a successful Master's dissertation.
