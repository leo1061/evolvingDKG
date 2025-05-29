# Cryptographic Implementation Details

## ElGamal on Elliptic Curves

This implementation uses ElGamal encryption adapted for elliptic curves, specifically the Baby Jubjub curve used in zero-knowledge applications.

### Mathematical Foundation

**Elliptic Curve**: Baby Jubjub
- Equation: `ax² + y² = 1 + dx²y²`
- Field: BN254 scalar field
- Base point G with order n

**Key Generation**:
- Private key: `sk ∈ᴿ Fₙ`
- Public key: `pk = sk × G`

**Encryption**:
- Message encoding: `M = m × G`
- Choose random `r ∈ᴿ Fₙ`
- Ciphertext: `(C₁, C₂) = (r × G, M + r × pk)`

**Decryption**:
- Compute: `S = sk × C₁`
- Recover: `M = C₂ - S`

### Security Properties

1. **IND-CPA Security**: Based on ECDH assumption
2. **Malleability**: Homomorphic properties preserved
3. **Zero-Knowledge**: Decryption proves key knowledge without revealing it

### Implementation Notes

- All scalar multiplications use windowed methods for efficiency
- Point validation prevents invalid curve attacks
- Constant-time operations where possible
