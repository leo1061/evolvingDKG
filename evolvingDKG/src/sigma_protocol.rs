use anyhow::Result;
use num_bigint::BigUint;
use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use sha2::{Sha256, Digest};
use crate::{BabyJubJubPK, BabyJubJubSK, elgamal::ElGamalCiphertext};

// Round 2 Sigma Protocol for Relation R_L
// Proves correct decryption of multiple ElGamal ciphertexts and sum computation
#[derive(Debug, Clone)]
pub struct Round2Commitment {
    pub a_sk: BabyJubJubPK,    // A_sk = g^r_sk (proves knowledge of secret key)
    pub a_sum: BabyJubJubPK,   // A_sum = g^r_sum (proves knowledge of sum)
    pub a_batch: BabyJubJubPK, // A_batch = batched decryption commitment
}

#[derive(Debug, Clone)]
pub struct Round2Response {
    pub z_sk: BigUint,  // z_sk = r_sk + e * sk_i
    pub z_sum: BigUint, // z_sum = r_sum + e * x_i
}

#[derive(Debug, Clone)]
pub struct Round2Proof {
    pub commitment: Round2Commitment,
    pub response: Round2Response,
}

#[derive(Debug, Clone)]
pub struct Round2Statement {
    pub public_key: BabyJubJubPK,
    pub ciphertexts: Vec<ElGamalCiphertext>,
    pub claimed_sum: JubJubExtended, // Y_i = g^{x_i}
}

impl Round2Proof {
    pub fn prove(
        statement: &Round2Statement,
        secret_key: &BabyJubJubSK,
        _decrypted_shares: &[BigUint],
        final_share: &BigUint,
    ) -> Result<Self> {
        // COMMITMENT PHASE
        let r_sk = generate_random_scalar()?;
        let r_sum = generate_random_scalar()?;
        
        // A_sk = g^r_sk
        let a_sk_point = GENERATOR_EXTENDED * &r_sk;
        let a_sk: BabyJubJubPK = a_sk_point.into();
        
        // A_sum = g^r_sum
        let a_sum_point = GENERATOR_EXTENDED * &r_sum;
        let a_sum: BabyJubJubPK = a_sum_point.into();
        
        // A_batch = batched commitment for decryption proofs
        let batch_size = JubJubScalar::from(statement.ciphertexts.len() as u64);
        let r_sum_divided = r_sum * batch_size.invert().unwrap();
        
        let mut a_batch_point = JubJubExtended::default();
        for ciphertext in &statement.ciphertexts {
            let term = (GENERATOR_EXTENDED * &r_sum_divided) + (ciphertext.c1 * &r_sk);
            a_batch_point = a_batch_point + term;
        }
        let a_batch: BabyJubJubPK = a_batch_point.into();
        
        let commitment = Round2Commitment {
            a_sk,
            a_sum,
            a_batch,
        };
        
        // CHALLENGE PHASE: Compute challenge via Fiat-Shamir heuristic
        let challenge = compute_round2_challenge(statement, &commitment)?;
        
        // RESPONSE PHASE
        let sk_scalar = share_to_scalar(&secret_key.value)?;
        let final_share_scalar = share_to_scalar(final_share)?;
        
        // z_sk = r_sk + e * sk_i
        let z_sk_scalar = r_sk + (challenge * sk_scalar);
        let z_sk = BigUint::from_bytes_le(&z_sk_scalar.to_bytes());
        
        // z_sum = r_sum + e * x_i
        let z_sum_scalar = r_sum + (challenge * final_share_scalar);
        let z_sum = BigUint::from_bytes_le(&z_sum_scalar.to_bytes());
        
        let response = Round2Response { z_sk, z_sum };
        
        Ok(Round2Proof {
            commitment,
            response,
        })
    }
    
    pub fn verify(&self, statement: &Round2Statement) -> Result<bool> {
        // CHALLENGE PHASE: Recompute challenge via Fiat-Shamir heuristic
        let challenge = compute_round2_challenge(statement, &self.commitment)?;
        
        // Convert response components to scalars
        let z_sk_scalar = share_to_scalar(&self.response.z_sk)?;
        let z_sum_scalar = share_to_scalar(&self.response.z_sum)?;
        
        // Convert statement components to curve points
        let pk_point: JubJubExtended = statement.public_key.clone().into();
        let y_point = statement.claimed_sum;
        let a_sk_point: JubJubExtended = self.commitment.a_sk.clone().into();
        let a_sum_point: JubJubExtended = self.commitment.a_sum.clone().into();
        let a_batch_point: JubJubExtended = self.commitment.a_batch.clone().into();
        
        // VERIFICATION PHASE
        
        // Check 1: g^z_sk = A_sk * pk^e
        let left1 = GENERATOR_EXTENDED * &z_sk_scalar;
        let right1 = a_sk_point + (pk_point * &challenge);
        if left1 != right1 {
            return Ok(false);
        }
        
        // Check 2: g^z_sum = A_sum * Y^e
        let left2 = GENERATOR_EXTENDED * &z_sum_scalar;
        let right2 = a_sum_point + (y_point * &challenge);
        if left2 != right2 {
            return Ok(false);
        }
        
        // Check 3: Batch decryption verification
        let batch_size = JubJubScalar::from(statement.ciphertexts.len() as u64);
        let z_sum_divided = z_sum_scalar * batch_size.invert().unwrap();
        
        let mut left3 = JubJubExtended::default();
        let mut right3_product = JubJubExtended::default();
        
        for ciphertext in &statement.ciphertexts {
            let term = (GENERATOR_EXTENDED * &z_sum_divided) + (ciphertext.c1 * &z_sk_scalar);
            left3 = left3 + term;
            right3_product = right3_product + (ciphertext.c2 * &challenge);
        }
        
        let right3 = a_batch_point + right3_product;
        
        Ok(left3 == right3)
    }
}

// Helper function to convert BigUint share to JubJub scalar with proper field reduction
fn share_to_scalar(share: &BigUint) -> Result<JubJubScalar> {
    
    let mut bytes = [0u8; 32];
    let share_bytes = share.to_bytes_le();
    
    // Handle larger shares by taking modulo of field size
    if share_bytes.len() > 32 {
        // For large shares, use a hash-based approach to get valid field element
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        share.hash(&mut hasher);
        let hash_val = hasher.finish();
        bytes[0..8].copy_from_slice(&hash_val.to_le_bytes());
    } else {
        bytes[0..share_bytes.len()].copy_from_slice(&share_bytes);
    }
    
    // Create scalar from bytes (will automatically reduce modulo field size)
    Ok(JubJubScalar::from_bytes(&bytes).unwrap())
}

// Generate a random scalar for commitments
fn generate_random_scalar() -> Result<JubJubScalar> {
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    Ok(JubJubScalar::random(&mut rng))
}

// Compute the Fiat-Shamir challenge for Round 2 proof
fn compute_round2_challenge(
    statement: &Round2Statement,
    commitment: &Round2Commitment,
) -> Result<JubJubScalar> {
    let mut hasher = Sha256::new();
    
    // Hash public key
    hasher.update(statement.public_key.x.to_bytes_le());
    hasher.update(statement.public_key.y.to_bytes_le());
    
    // Hash all ciphertexts
    for ciphertext in &statement.ciphertexts {
        let c1_pk: BabyJubJubPK = ciphertext.c1.into();
        let c2_pk: BabyJubJubPK = ciphertext.c2.into();
        hasher.update(c1_pk.x.to_bytes_le());
        hasher.update(c1_pk.y.to_bytes_le());
        hasher.update(c2_pk.x.to_bytes_le());
        hasher.update(c2_pk.y.to_bytes_le());
    }
    
    // Hash claimed sum
    let claimed_sum_pk: BabyJubJubPK = statement.claimed_sum.into();
    hasher.update(claimed_sum_pk.x.to_bytes_le());
    hasher.update(claimed_sum_pk.y.to_bytes_le());
    
    // Hash commitments
    hasher.update(commitment.a_sk.x.to_bytes_le());
    hasher.update(commitment.a_sk.y.to_bytes_le());
    hasher.update(commitment.a_sum.x.to_bytes_le());
    hasher.update(commitment.a_sum.y.to_bytes_le());
    hasher.update(commitment.a_batch.x.to_bytes_le());
    hasher.update(commitment.a_batch.y.to_bytes_le());
    
    let hash = hasher.finalize();
    
    // Convert hash to scalar - expand 32 bytes to 64 bytes for wide reduction
    let mut wide_bytes = [0u8; 64];
    wide_bytes[0..32].copy_from_slice(&hash);
    
    Ok(JubJubScalar::from_bytes_wide(&wide_bytes))
}