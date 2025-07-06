use anyhow::Result;
use evolvingDKG::elgamal::{ElGamalCiphertext, generate_keypair};
use evolvingDKG::{BabyJubJubPK, BabyJubJubSK, biguint_to_scalar};
use dusk_jubjub::{JubJubScalar, JubJubExtended, GENERATOR_EXTENDED};
use ff::Field;
use sha2::{Sha256, Digest};
use num_bigint::BigUint;
use rand::rngs::StdRng;
use rand::SeedableRng;

// Sigma Protocol for Proving Correct Decryption Relation (Batch Version)
// Relation: R'_L = {((pk, {c_j}_{j∈I'}, Y), sk) | sk is valid secret key for pk; Y = g^(Σ aHPKE.Dec(sk,c_i))}

#[derive(Debug, Clone)]
pub struct DecryptionCommitment {
    pub a_pk: BabyJubJubPK,     // A_pk = g^r_sk
    pub a_sum: BabyJubJubPK,    // A_sum = g^r_sum  
    pub a_batch: BabyJubJubPK,  // A_batch = ∏(g^(r_sum/|I'|) · c_i,1^r_sk)
}

#[derive(Debug, Clone)]
pub struct DecryptionResponse {
    pub z_sk: BigUint,    // z_sk = r_sk + e · sk mod p
    pub z_sum: BigUint,   // z_sum = r_sum + e · (Σm_i) mod p
}

#[derive(Debug, Clone)]
pub struct DecryptionProof {
    pub commitment: DecryptionCommitment,
    pub response: DecryptionResponse,
}

#[derive(Debug, Clone)]
pub struct BatchDecryptionStatement {
    pub public_key: BabyJubJubPK,           // pk = g^sk
    pub ciphertexts: Vec<ElGamalCiphertext>, // {c_i} = {(g^r_i, g^m_i · pk^r_i)}
    pub claimed_sum: BabyJubJubPK,          // Y = g^(Σm_i)
}

impl DecryptionProof {
    /// Create a non-interactive proof using batched Fiat-Shamir heuristic
    /// Proves knowledge of secret key and correct decryption of multiple ciphertexts
    pub fn prove_batch(
        statement: &BatchDecryptionStatement,
        secret_key: &BabyJubJubSK,
        messages: &[JubJubScalar], // The actual decrypted scalar values
    ) -> Result<Self> {
        if statement.ciphertexts.len() != messages.len() {
            anyhow::bail!("Number of ciphertexts must match number of messages");
        }
        
        if statement.ciphertexts.is_empty() {
            anyhow::bail!("Cannot create proof for empty ciphertext set");
        }

        // COMMITMENT PHASE
        let r_sk = generate_random_scalar()?;
        let r_sum = generate_random_scalar()?;
        
        // A_pk = g^r_sk
        let a_pk_point = GENERATOR_EXTENDED * &r_sk;
        let a_pk: BabyJubJubPK = a_pk_point.into();
        
        // A_sum = g^r_sum
        let a_sum_point = GENERATOR_EXTENDED * &r_sum;
        let a_sum: BabyJubJubPK = a_sum_point.into();
        
        // A_batch = ∏_{i∈I'} (g^(r_sum/|I'|) · c_i,1^r_sk)
        let batch_size = JubJubScalar::from(statement.ciphertexts.len() as u64);
        let r_sum_divided = r_sum * batch_size.invert().unwrap(); // r_sum / |I'|
        
        let mut a_batch_point = JubJubExtended::default(); // Identity element
        for ciphertext in &statement.ciphertexts {
            // g^(r_sum/|I'|) · c_i,1^r_sk
            let term = (GENERATOR_EXTENDED * &r_sum_divided) + (ciphertext.c1 * &r_sk);
            a_batch_point = a_batch_point + term;
        }
        let a_batch: BabyJubJubPK = a_batch_point.into();
        
        let commitment = DecryptionCommitment {
            a_pk,
            a_sum,
            a_batch,
        };
        
        // CHALLENGE PHASE: Compute challenge via Fiat-Shamir heuristic
        let challenge = compute_batch_challenge(statement, &commitment)?;
        
        // RESPONSE PHASE
        let sk_scalar = biguint_to_scalar(&secret_key.value)?;
        
        // z_sk = r_sk + e · sk mod p
        let z_sk_scalar = r_sk + (challenge * sk_scalar);
        let z_sk = BigUint::from_bytes_le(&z_sk_scalar.to_bytes());
        
        // z_sum = r_sum + e · (Σm_i) mod p
        let sum_messages: JubJubScalar = messages.iter().fold(JubJubScalar::zero(), |acc, m| acc + m);
        let z_sum_scalar = r_sum + (challenge * sum_messages);
        let z_sum = BigUint::from_bytes_le(&z_sum_scalar.to_bytes());
        
        let response = DecryptionResponse { z_sk, z_sum };
        
        Ok(DecryptionProof {
            commitment,
            response,
        })
    }
    
    /// Verify the batched non-interactive proof
    pub fn verify_batch(&self, statement: &BatchDecryptionStatement) -> Result<bool> {
        if statement.ciphertexts.is_empty() {
            return Ok(false);
        }
        
        // CHALLENGE PHASE: Recompute challenge via Fiat-Shamir heuristic
        let challenge = compute_batch_challenge(statement, &self.commitment)?;
        
        // Convert response components to scalars
        let z_sk_scalar = biguint_to_scalar(&self.response.z_sk)?;
        let z_sum_scalar = biguint_to_scalar(&self.response.z_sum)?;
        
        // Convert statement components to curve points
        let pk_point: JubJubExtended = statement.public_key.clone().into();
        let y_point: JubJubExtended = statement.claimed_sum.clone().into();
        let a_pk_point: JubJubExtended = self.commitment.a_pk.clone().into();
        let a_sum_point: JubJubExtended = self.commitment.a_sum.clone().into();
        let a_batch_point: JubJubExtended = self.commitment.a_batch.clone().into();
        
        // VERIFICATION PHASE
        
        // Check 1: g^z_sk = A_pk · pk^e
        let left1 = GENERATOR_EXTENDED * &z_sk_scalar;
        let right1 = a_pk_point + (pk_point * &challenge);
        if left1 != right1 {
            return Ok(false);
        }
        
        // Check 2: g^z_sum = A_sum · Y^e
        let left2 = GENERATOR_EXTENDED * &z_sum_scalar;
        let right2 = a_sum_point + (y_point * &challenge);
        if left2 != right2 {
            return Ok(false);
        }
        
        // Check 3: ∏_{i∈I'} (g^(z_sum/|I'|) · c_i,1^z_sk) = A_batch · ∏_{i∈I'} c_i,2^e
        let batch_size = JubJubScalar::from(statement.ciphertexts.len() as u64);
        let z_sum_divided = z_sum_scalar * batch_size.invert().unwrap(); // z_sum / |I'|
        
        let mut left3 = JubJubExtended::default();
        let mut right3_product = JubJubExtended::default();
        
        for ciphertext in &statement.ciphertexts {
            // Left side: g^(z_sum/|I'|) · c_i,1^z_sk
            let term = (GENERATOR_EXTENDED * &z_sum_divided) + (ciphertext.c1 * &z_sk_scalar);
            left3 = left3 + term;
            
            // Right side product: ∏_{i∈I'} c_i,2^e
            right3_product = right3_product + (ciphertext.c2 * &challenge);
        }
        
        let right3 = a_batch_point + right3_product;
        
        Ok(left3 == right3)
    }
}

/// Generate a random scalar for commitments
fn generate_random_scalar() -> Result<JubJubScalar> {
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    Ok(JubJubScalar::random(&mut rng))
}

/// Compute the Fiat-Shamir challenge for the batch decryption proof
fn compute_batch_challenge(
    statement: &BatchDecryptionStatement,
    commitment: &DecryptionCommitment,
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
    hasher.update(statement.claimed_sum.x.to_bytes_le());
    hasher.update(statement.claimed_sum.y.to_bytes_le());
    
    // Hash commitments
    hasher.update(commitment.a_pk.x.to_bytes_le());
    hasher.update(commitment.a_pk.y.to_bytes_le());
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

fn main() -> Result<()> {
    println!("🔐 Batch Decryption Proof Example");
    println!("=================================");
    println!();
    
    println!("📚 PROTOCOL EXPLANATION:");
    println!("------------------------");
    println!("Goal: Prove correct decryption of multiple ElGamal ciphertexts");
    println!("Relation: Given pk, ciphertexts {{c_i}}, and claimed sum Y,");
    println!("          prove knowledge of sk such that:");
    println!("          - pk = g^sk");
    println!("          - Y = g^(Σ decrypt(sk, c_i))");
    println!();
    println!("Batch optimization: Instead of proving each decryption individually,");
    println!("                   prove the sum relation efficiently in one go!");
    println!();
    
    // Setup: Generate keys and test data
    let mut rng = StdRng::seed_from_u64(0x1337);
    let (jubjub_sk, jubjub_pk) = generate_keypair(&mut rng);
    
    // Convert to our key format
    let secret_key: BabyJubJubSK = jubjub_sk.into();
    let public_key: BabyJubJubPK = jubjub_pk.into();
    
    println!("🔑 SETUP:");
    println!("----------");
    println!("Secret Key: {}", secret_key.value);
    println!("Public Key: {}", public_key);
    println!();
    
    // Create some test messages and encrypt them
    let test_messages = vec![
        JubJubScalar::from(100u64),
        JubJubScalar::from(200u64), 
        JubJubScalar::from(300u64),
        JubJubScalar::from(150u64),
    ];
    
    println!("📝 MESSAGES TO ENCRYPT:");
    println!("-----------------------");
    for (i, msg) in test_messages.iter().enumerate() {
        println!("Message {}: {}", i + 1, msg.to_string()[..20].to_string() + "...");
    }
    
    // Encrypt each message
    let mut ciphertexts = Vec::new();
    let mut encrypted_messages = Vec::new();
    
    for &message_scalar in &test_messages {
        let message_point = GENERATOR_EXTENDED * &message_scalar;
        let ciphertext = evolvingDKG::elgamal::encrypt(&jubjub_pk, &message_point, &mut rng)?;
        ciphertexts.push(ciphertext);
        encrypted_messages.push(message_point);
    }
    
    println!();
    println!("🔒 ENCRYPTED {} MESSAGES", ciphertexts.len());
    println!();
    
    // Compute the claimed sum Y = g^(Σm_i)
    let sum_scalar: JubJubScalar = test_messages.iter().fold(JubJubScalar::zero(), |acc, m| acc + m);
    let claimed_sum_point = GENERATOR_EXTENDED * &sum_scalar;
    let claimed_sum: BabyJubJubPK = claimed_sum_point.into();
    
    println!("📊 CLAIMED SUM:");
    println!("---------------");
    println!("Sum of messages: {} + {} + {} + {} = {}", 
             100, 200, 300, 150, 100 + 200 + 300 + 150);
    println!("Y = g^(sum) = {}", claimed_sum);
    println!();
    
    // Create the statement to prove
    let statement = BatchDecryptionStatement {
        public_key,
        ciphertexts,
        claimed_sum,
    };
    
    // Create the proof
    println!("🔐 CREATING BATCH PROOF:");
    println!("-------------------------");
    println!("✓ COMMIT phase: Generate A_pk, A_sum, A_batch");
    let proof = DecryptionProof::prove_batch(&statement, &secret_key, &test_messages)?;
    println!("  A_pk = {}", proof.commitment.a_pk);
    println!("  A_sum = {}", proof.commitment.a_sum);
    println!("  A_batch = {}", proof.commitment.a_batch);
    println!();
    
    println!("✓ CHALLENGE phase: e = H(pk || ciphertexts || Y || commitments) [Fiat-Shamir]");
    let challenge = compute_batch_challenge(&statement, &proof.commitment)?;
    println!("  e = {}...", &challenge.to_string()[..30]);
    println!();
    
    println!("✓ RESPONSE phase: z_sk, z_sum");
    println!("  z_sk = {}", proof.response.z_sk);
    println!("  z_sum = {}", proof.response.z_sum);
    println!();
    
    // Verify the proof
    println!("🔍 VERIFICATION:");
    println!("----------------");
    println!("Checking batch equations:");
    println!("  1. g^z_sk = A_pk · pk^e");
    println!("  2. g^z_sum = A_sum · Y^e");
    println!("  3. ∏(g^(z_sum/n) · c_i,1^z_sk) = A_batch · ∏c_i,2^e");
    
    let is_valid = proof.verify_batch(&statement)?;
    println!("✓ Batch proof valid: {}", is_valid);
    println!();
    
    // Security tests
    println!("🛡️ SECURITY TESTS:");
    println!("-------------------");
    
    // Test 1: Wrong claimed sum
    let wrong_sum_scalar = sum_scalar + JubJubScalar::from(1u64);
    let wrong_sum_point = GENERATOR_EXTENDED * &wrong_sum_scalar;
    let wrong_statement = BatchDecryptionStatement {
        public_key: statement.public_key.clone(),
        ciphertexts: statement.ciphertexts.clone(),
        claimed_sum: wrong_sum_point.into(),
    };
    
    let wrong_sum_valid = proof.verify_batch(&wrong_statement)?;
    println!("Test 1 - Wrong claimed sum: {} (should be false)", wrong_sum_valid);
    
    // Test 2: Wrong public key
    let (_wrong_sk, wrong_pk) = generate_keypair(&mut rng);
    let wrong_statement2 = BatchDecryptionStatement {
        public_key: wrong_pk.into(),
        ciphertexts: statement.ciphertexts.clone(),
        claimed_sum: statement.claimed_sum.clone(),
    };
    
    let wrong_pk_valid = proof.verify_batch(&wrong_statement2)?;
    println!("Test 2 - Wrong public key: {} (should be false)", wrong_pk_valid);
    
    // Test 3: Proof with different message set
    let different_messages = vec![
        JubJubScalar::from(50u64),
        JubJubScalar::from(100u64),
        JubJubScalar::from(150u64),
        JubJubScalar::from(200u64),
    ];
    
    let different_proof = DecryptionProof::prove_batch(&statement, &secret_key, &different_messages);
    match different_proof {
        Ok(diff_proof) => {
            let diff_valid = diff_proof.verify_batch(&statement)?;
            println!("Test 3 - Different message set: {} (should be false)", diff_valid);
        }
        Err(_) => {
            println!("Test 3 - Different message set: proof creation failed as expected");
        }
    }
    
    println!();
    println!("🎉 Batch Decryption Proof demonstration complete!");
    println!("This shows efficient zero-knowledge proof of correct ElGamal decryption.");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_decryption_proof_valid() {
        let mut rng = StdRng::seed_from_u64(0x123);
        let (jubjub_sk, jubjub_pk) = generate_keypair(&mut rng);
        let secret_key: BabyJubJubSK = jubjub_sk.into();
        let public_key: BabyJubJubPK = jubjub_pk.into();
        
        let messages = vec![
            JubJubScalar::from(10u64),
            JubJubScalar::from(20u64),
            JubJubScalar::from(30u64),
        ];
        
        // Encrypt messages
        let mut ciphertexts = Vec::new();
        for &msg_scalar in &messages {
            let msg_point = GENERATOR_EXTENDED * &msg_scalar;
            let ciphertext = evolvingDKG::elgamal::encrypt(&jubjub_pk, &msg_point, &mut rng).unwrap();
            ciphertexts.push(ciphertext);
        }
        
        // Compute claimed sum
        let sum_scalar: JubJubScalar = messages.iter().fold(JubJubScalar::zero(), |acc, m| acc + m);
        let claimed_sum: BabyJubJubPK = (GENERATOR_EXTENDED * &sum_scalar).into();
        
        let statement = BatchDecryptionStatement {
            public_key,
            ciphertexts,
            claimed_sum,
        };
        
        let proof = DecryptionProof::prove_batch(&statement, &secret_key, &messages).unwrap();
        assert!(proof.verify_batch(&statement).unwrap());
    }

    #[test]
    fn test_batch_decryption_proof_wrong_sum() {
        let mut rng = StdRng::seed_from_u64(0x456);
        let (jubjub_sk, jubjub_pk) = generate_keypair(&mut rng);
        let secret_key: BabyJubJubSK = jubjub_sk.into();
        let public_key: BabyJubJubPK = jubjub_pk.into();
        
        let messages = vec![JubJubScalar::from(100u64), JubJubScalar::from(200u64)];
        
        // Encrypt messages
        let mut ciphertexts = Vec::new();
        for &msg_scalar in &messages {
            let msg_point = GENERATOR_EXTENDED * &msg_scalar;
            let ciphertext = evolvingDKG::elgamal::encrypt(&jubjub_pk, &msg_point, &mut rng).unwrap();
            ciphertexts.push(ciphertext);
        }
        
        // Wrong claimed sum
        let wrong_sum_scalar = JubJubScalar::from(999u64);
        let wrong_claimed_sum: BabyJubJubPK = (GENERATOR_EXTENDED * &wrong_sum_scalar).into();
        
        let statement = BatchDecryptionStatement {
            public_key,
            ciphertexts,
            claimed_sum: wrong_claimed_sum,
        };
        
        let proof = DecryptionProof::prove_batch(&statement, &secret_key, &messages).unwrap();
        assert!(!proof.verify_batch(&statement).unwrap());
    }

    #[test]
    fn test_batch_decryption_proof_single_ciphertext() {
        let mut rng = StdRng::seed_from_u64(0x789);
        let (jubjub_sk, jubjub_pk) = generate_keypair(&mut rng);
        let secret_key: BabyJubJubSK = jubjub_sk.into();
        let public_key: BabyJubJubPK = jubjub_pk.into();
        
        let messages = vec![JubJubScalar::from(42u64)];
        
        let msg_point = GENERATOR_EXTENDED * &messages[0];
        let ciphertext = evolvingDKG::elgamal::encrypt(&jubjub_pk, &msg_point, &mut rng).unwrap();
        
        let claimed_sum: BabyJubJubPK = msg_point.into();
        
        let statement = BatchDecryptionStatement {
            public_key,
            ciphertexts: vec![ciphertext],
            claimed_sum,
        };
        
        let proof = DecryptionProof::prove_batch(&statement, &secret_key, &messages).unwrap();
        assert!(proof.verify_batch(&statement).unwrap());
    }

    #[test]
    fn test_batch_decryption_proof_empty_set() {
        let mut rng = StdRng::seed_from_u64(0xabc);
        let (jubjub_sk, _) = generate_keypair(&mut rng);
        let secret_key: BabyJubJubSK = jubjub_sk.into();
        
        let messages: Vec<JubJubScalar> = vec![];
        let statement = BatchDecryptionStatement {
            public_key: GENERATOR_EXTENDED.into(),
            ciphertexts: vec![],
            claimed_sum: GENERATOR_EXTENDED.into(),
        };
        
        assert!(DecryptionProof::prove_batch(&statement, &secret_key, &messages).is_err());
    }

    #[test]
    fn test_batch_decryption_proof_mismatched_lengths() {
        let mut rng = StdRng::seed_from_u64(0xdef);
        let (jubjub_sk, jubjub_pk) = generate_keypair(&mut rng);
        let secret_key: BabyJubJubSK = jubjub_sk.into();
        
        // Create 2 ciphertexts but provide 3 messages
        let ciphertexts = vec![
            evolvingDKG::elgamal::encrypt(&jubjub_pk, &GENERATOR_EXTENDED, &mut rng).unwrap(),
            evolvingDKG::elgamal::encrypt(&jubjub_pk, &GENERATOR_EXTENDED, &mut rng).unwrap(),
        ];
        
        let messages = vec![
            JubJubScalar::from(1u64),
            JubJubScalar::from(2u64),
            JubJubScalar::from(3u64), // Extra message
        ];
        
        let statement = BatchDecryptionStatement {
            public_key: jubjub_pk.into(),
            ciphertexts,
            claimed_sum: GENERATOR_EXTENDED.into(),
        };
        
        assert!(DecryptionProof::prove_batch(&statement, &secret_key, &messages).is_err());
    }
}