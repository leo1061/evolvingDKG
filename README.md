# evolvingDKG

A zero-knowledge ElGamal encryption/decryption implementation using Circom circuits and the Baby Jubjub elliptic curve.

## 🔍 Overview

This project implements ElGamal encryption and decryption using zero-knowledge proofs:

- **Encryption Circuit** (`circuits/encryption.circom`): Encrypts messages on the Baby Jubjub curve
- **Decryption Circuit** (`circuits/decryption.circom`): Decrypts ciphertext while proving knowledge of the private key

> **Note**: The Rust key generation component (`rust-keygen/`) is deprecated and will be removed in a future update. Key generation functionality will be integrated directly into the main codebase.

## 🏗️ Architecture

```
┌──────────────────┐    ┌─────────────────┐
│   Encryption     │    │   Decryption    │
│   (Circom)       │───▶│   (Circom)      │
│                  │    │                 │
│ • Encode message │    │ • Prove sk      │
│ • ElGamal encrypt│    │ • Decrypt C2    │
└──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- [Node.js](https://nodejs.org/) (v16+)
- [Circom](https://docs.circom.io/getting-started/installation/)

### Installation

1. **Clone and setup**:

   ```bash
   git clone https://github.com/yourusername/evolvingDKG.git
   cd evolvingDKG
   npm install
   npm run install-circom
   ```

2. **Compile circuits**:
   ```bash
   npm run compile-all
   ```

## 📁 Project Structure

```
evolvingDKG/
├── circuits/           # Circom circuit files
│   ├── encryption.circom
│   └── decryption.circom
├── scripts/            # Utility scripts
├── examples/           # Usage examples
├── tests/              # Test files
├── docs/               # Documentation
├── build/             # Compiled circuit outputs
├── bjj_sk.txt         # Generated private key
├── bjj_pk.txt         # Generated public key
├── package.json       # Node.js dependencies
└── README.md
```

## 🔐 Cryptographic Details

### ElGamal Encryption

The implementation uses the Baby Jubjub elliptic curve with the following parameters:

- **Base Point G**: `(5299619240641551281634865583518297030282874472190772894086521144482721001553, 16950150798460657717958625567821834550301663161624707787222815936182638968203)`
- **Field**: BN254 scalar field
- **Key Size**: 253 bits

### Encryption Process

1. **Message Encoding**: `M = plaintext * G`
2. **Key Generation**: `pk = sk * G`
3. **Encryption**:
   - `C1 = r * G` (ephemeral key)
   - `C2 = M + r * pk` (encrypted message)

### Decryption Process

1. **Shared Secret**: `S = sk * C1`
2. **Message Recovery**: `M = C2 - S`

## 🧪 Usage Examples

### Encryption (Circom)

```javascript
// Inputs
signal input message[2];      // Encoded message point
signal input nonceKey;        // Random nonce
signal input publicKey[2];    // Recipient's public key

// Outputs
signal output ephemeralKey[2];     // C1
signal output encryptedMessage[2]; // C2
```

### Decryption (Circom)

```javascript
// Inputs
signal input sk;    // Private key
signal input c2x;   // C2.x coordinate
signal input c2y;   // C2.y coordinate

// Outputs
signal output mx;   // Decrypted message x
signal output my;   // Decrypted message y
```

## 🛠️ Development

### Building Circuits

```bash
# Compile encryption circuit
npm run compile-encrypt

# Compile decryption circuit
npm run compile-decrypt

# Compile both
npm run compile-all
```

> **Note**: The Rust key generation component (`rust-keygen/`) is deprecated and will be removed. Key generation functionality will be integrated directly into the main codebase in a future update.

## 🔒 Security Considerations

- Uses cryptographically secure random number generation
- Implements curve point validation to prevent invalid curve attacks
- Protects against identity point attacks
- All operations performed in the BN254 scalar field

## 📚 Dependencies

### Node.js

- `circomlib`: ^2.0.0 - Circom circuit library
- `circomlibjs`: ^0.1.2 - JavaScript utilities for Circom

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
