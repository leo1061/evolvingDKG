use anyhow::Result;
use dusk_jubjub::{JubJubScalar, JubJubExtended, GENERATOR_EXTENDED};
use ff::Field;
use sha2::{Sha256, Digest};
use num_bigint::BigUint;
use crate::{BabyJubJubPK, BabyJubJubSK, biguint_to_scalar};

// Sigma Protocol for Discrete Log Knowledge
// Proves knowledge of secret key x such that PK = x * G
// This is the Schnorr identification protocol made non-interactive via Fiat-Shamir

#[derive(Debug, Clone)]
pub struct Commitment {
    pub r: BabyJubJubPK,  // First message: R = k * G (commitment)
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub c: JubJubScalar,  // Second message: c = H(R || PK || m) (challenge)
}

#[derive(Debug, Clone)]
pub struct Response {
    pub s: BigUint,       // Third message: s = k + c * x (response)
}

#[derive(Debug, Clone)]
pub struct SigmaProof {
    pub commitment: Commitment,
    pub response: Response,
    // Note: Challenge is not stored as it's computed via Fiat-Shamir
}

// Legacy alias for backward compatibility
pub type SchnorrSignature = SigmaProof;

impl SigmaProof {
    /// Create a non-interactive proof using the Fiat-Shamir heuristic
    /// This collapses the interactive sigma protocol into a single proof
    pub fn prove(message: &[u8], private_key: &BabyJubJubSK) -> Result<Self> {
        // COMMIT PHASE: Generate random nonce and compute commitment
        let k = generate_random_scalar()?;
        let r_point = GENERATOR_EXTENDED * &k;
        let commitment = Commitment {
            r: r_point.into(),
        };
        
        // CHALLENGE PHASE: Compute challenge via Fiat-Shamir heuristic
        let public_key = private_key.get_public_key();
        let challenge = fiat_shamir_challenge(&commitment.r, &public_key, message)?;
        
        // RESPONSE PHASE: Compute response
        let sk_scalar = biguint_to_scalar(&private_key.value)?;
        let s_scalar = k + (challenge.c * sk_scalar);
        let response = Response {
            s: BigUint::from_bytes_le(&s_scalar.to_bytes()),
        };
        
        Ok(SigmaProof {
            commitment,
            response,
        })
    }
    
    /// Verify the non-interactive proof
    pub fn verify(&self, message: &[u8], public_key: &BabyJubJubPK) -> Result<bool> {
        // CHALLENGE PHASE: Recompute challenge via Fiat-Shamir heuristic
        let challenge = fiat_shamir_challenge(&self.commitment.r, public_key, message)?;
        
        // VERIFICATION: Check the sigma protocol equation
        let s_scalar = biguint_to_scalar(&self.response.s)?;
        let r_point: JubJubExtended = self.commitment.r.clone().into();
        let pk_point: JubJubExtended = public_key.clone().into();
        
        // Verify: s * G = R + c * PK
        // This is equivalent to checking: s * G - c * PK = R
        let left_side = GENERATOR_EXTENDED * &s_scalar;
        let right_side = r_point + (pk_point * &challenge.c);
        
        Ok(left_side == right_side)
    }
}

// Legacy methods for backward compatibility (implemented as associated functions)
impl SchnorrSignature {
    pub fn sign(message: &[u8], private_key: &BabyJubJubSK) -> Result<Self> {
        SigmaProof::prove(message, private_key)
    }
}

fn generate_random_scalar() -> Result<JubJubScalar> {
    use rand::rngs::OsRng;
    
    let mut rng = OsRng;
    Ok(JubJubScalar::random(&mut rng))
}

/// Fiat-Shamir heuristic: Convert interactive challenge to non-interactive
/// In an interactive protocol, the verifier would send a random challenge
/// Here we replace the verifier with a cryptographic hash function
pub fn fiat_shamir_challenge(r: &BabyJubJubPK, pk: &BabyJubJubPK, message: &[u8]) -> Result<Challenge> {
    let c = compute_challenge_scalar(r, pk, message)?;
    Ok(Challenge { c })
}

/// Compute the challenge scalar using cryptographic hash
fn compute_challenge_scalar(r: &BabyJubJubPK, pk: &BabyJubJubPK, message: &[u8]) -> Result<JubJubScalar> {
    let mut hasher = Sha256::new();
    
    // Hash R point coordinates
    hasher.update(r.x.to_bytes_le());
    hasher.update(r.y.to_bytes_le());
    
    // Hash public key coordinates
    hasher.update(pk.x.to_bytes_le());
    hasher.update(pk.y.to_bytes_le());
    
    // Hash message
    hasher.update(message);
    
    let hash = hasher.finalize();
    
    // Convert hash to scalar - expand 32 bytes to 64 bytes for wide reduction
    let mut wide_bytes = [0u8; 64];
    wide_bytes[0..32].copy_from_slice(&hash);
    
    Ok(JubJubScalar::from_bytes_wide(&wide_bytes))
}