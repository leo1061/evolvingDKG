# evolvingDKG

A zero-knowledge ElGamal encryption/decryption implementation using Circom circuits and the Baby Jubjub elliptic curve.

## 🔍 Overview

This project implements ElGamal encryption and decryption using zero-knowledge proofs:

- **Encryption Circuit** (`circuits/encryption.circom`): Encrypts messages on the Baby Jubjub curve
- **Decryption Circuit** (`circuits/decryption.circom`): Decrypts ciphertext while proving knowledge of the private key
- **Key Generation** (`rust-keygen/main.rs`): Generates cryptographic key pairs using arkworks

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Key Gen       │    │   Encryption     │    │   Decryption    │
│   (Rust)        │───▶│   (Circom)       │───▶│   (Circom)      │
│                 │    │                  │    │                 │
│ • Generate sk   │    │ • Encode message │    │ • Prove sk      │
│ • Compute pk    │    │ • ElGamal encrypt│    │ • Decrypt C2    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- [Node.js](https://nodejs.org/) (v16+)
- [Rust](https://rustup.rs/) (latest stable)
- [Circom](https://docs.circom.io/getting-started/installation/)

### Installation

1. **Clone and setup**:
   ```bash
   git clone https://github.com/yourusername/evolvingDKG.git
   cd evolvingDKG
   npm install
   ```

2. **Generate keys**:
   ```bash
   cd rust-keygen
   cargo run --bin keygen
   cd ..
   ```

3. **Compile circuits**:
   ```bash
   npm run compile-all
   ```

## 📁 Project Structure

```
evolvingDKG/
├── circuits/           # Circom circuit files
│   ├── encryption.circom
│   └── decryption.circom
├── rust-keygen/        # Rust key generation
│   ├── Cargo.toml
│   └── main.rs
├── scripts/            # Utility scripts
├── examples/           # Usage examples
├── tests/              # Test files
├── docs/               # Documentation
├── package.json        # Node.js dependencies
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

### Key Generation
```rust
// Generate random private key
let sk: Fr = Fr::rand(&mut rng);

// Compute public key
let pk = G * sk;
```

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

### Key Generation
```bash
cd rust-keygen
cargo run --bin keygen
```

This generates:
- `sk.txt`: Private key (scalar)
- `pk.txt`: Public key (x, y coordinates)

## 🔒 Security Considerations

- Uses cryptographically secure random number generation
- Implements curve point validation to prevent invalid curve attacks
- Protects against identity point attacks
- All operations performed in the BN254 scalar field

## 📚 Dependencies

### Node.js
- `circomlib`: Circom circuit library
- `circom`: Circuit compiler

### Rust
- `ark-bn254`: BN254 curve implementation
- `ark-ec`: Elliptic curve operations
- `ark-ff`: Finite field arithmetic
- `rand`: Secure random number generation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Circom](https://circom.io/) for the zero-knowledge circuit framework
- [arkworks](https://arkworks.rs/) for elliptic curve cryptography
- [Baby Jubjub](https://eips.ethereum.org/EIPS/eip-2494) curve specification

## 📞 Support

If you have questions or need help:

1. Check the [documentation](docs/)
2. Open an issue on GitHub
3. Join our discussions

---

Built with ❤️ for the zero-knowledge community
