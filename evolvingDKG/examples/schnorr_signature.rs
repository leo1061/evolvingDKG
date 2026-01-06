use anyhow::Result;
use evolvingDKG::schnorr_lib::*;
use evolvingDKG::{BabyJubJubSK, BabyJubJubPK};
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;

fn main() -> Result<()> {
    println!("sigma protocol example: non-interactive schnorr proof");
    println!("======================================================");
    println!();
    
    // explain the sigma protocol structure
    println!("📚 sigma protocol explanation:");
    println!("------------------------------");
    println!("goal: prove knowledge of secret key x such that pk = x * g");
    println!();
    println!("interactive version (3 rounds):");
    println!("  1. commit:    prover → verifier: r = k * g (random k)");
    println!("  2. challenge: verifier → prover: c (random challenge)");
    println!("  3. response:  prover → verifier: s = k + c * x");
    println!("  4. verify:    verifier checks: s * g = r + c * pk");
    println!();
    println!("non-interactive version (fiat-shamir):");
    println!("  - replace step 2 with: c = h(r || pk || message)");
    println!("  - this removes the need for interaction!");
    println!();
    
    // generate a keypair
    let mut rng = rand::rngs::OsRng;
    let sk_scalar = JubJubScalar::random(&mut rng);
    let private_key: BabyJubJubSK = sk_scalar.into();
    let public_key = private_key.get_public_key();
    
    println!("🔑 setup:");
    println!("---------");
    println!("secret key (x): {}", private_key.value);
    println!("public key (pk = x * g): {}", public_key);
    println!();
    
    // message to prove knowledge about
    let message = b"i know the discrete log of this public key!";
    println!("📝 message: {:?}", std::str::from_utf8(message).unwrap());
    println!();
    
    // create the non-interactive proof
    println!("🔐 creating non-interactive proof:");
    println!("-----------------------------------");
    let proof = SigmaProof::prove(message, &private_key)?;
    
    println!("✓ commit phase: r = k * g");
    println!("    r = {}", proof.commitment.r);
    println!();
    
    println!("✓ challenge phase: c = h(r || pk || message) [fiat-shamir]");
    let challenge = fiat_shamir_challenge(&proof.commitment.r, &public_key, message)?;
    println!("    c = {} (first 20 chars)", &challenge.c.to_string()[..20]);
    println!();
    
    println!("✓ response phase: s = k + c * x");
    println!("    s = {}", proof.response.s);
    println!();
    
    // verify the proof
    println!("🔍 verification:");
    println!("----------------");
    println!("checking: s * g = r + c * pk");
    let is_valid = proof.verify(message, &public_key)?;
    println!("✓ proof valid: {}", is_valid);
    println!();
    
    // demonstrate security properties
    println!("🛡️  security tests:");
    println!("-------------------");
    
    // test 1: wrong message
    let wrong_message = b"i know something else";
    println!("test 1 - wrong message: {:?}", std::str::from_utf8(wrong_message).unwrap());
    let is_valid_wrong = proof.verify(wrong_message, &public_key)?;
    println!("  result: {} (should be false)", is_valid_wrong);
    println!();
    
    // test 2: wrong public key
    let wrong_sk_scalar = JubJubScalar::random(&mut rng);
    let wrong_private_key: BabyJubJubSK = wrong_sk_scalar.into();
    let wrong_public_key = wrong_private_key.get_public_key();
    println!("test 2 - wrong public key");
    let is_valid_wrong_pk = proof.verify(message, &wrong_public_key)?;
    println!("  result: {} (should be false)", is_valid_wrong_pk);
    println!();
    
    // test 3: proof uniqueness (different random nonces)
    println!("test 3 - multiple proofs for same statement:");
    for i in 1..=3 {
        let proof_i = SigmaProof::prove(message, &private_key)?;
        let valid_i = proof_i.verify(message, &public_key)?;
        println!("  proof {}: valid = {}, r = {}...", i, valid_i, &proof_i.commitment.r.to_string()[..40]);
    }
    
    println!();
    println!("🎉 sigma protocol demonstration complete!");
    println!("this shows how fiat-shamir transforms interactive proofs to non-interactive ones.");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_sigma_protocol_valid_proof() {
        let mut rng = StdRng::seed_from_u64(0x123);
        let sk_scalar = JubJubScalar::random(&mut rng);
        let private_key: BabyJubJubSK = sk_scalar.into();
        let public_key = private_key.get_public_key();
        
        let message = b"test message";
        let proof = SigmaProof::prove(message, &private_key).unwrap();
        
        assert!(proof.verify(message, &public_key).unwrap());
    }

    #[test]
    fn test_sigma_protocol_invalid_message() {
        let mut rng = StdRng::seed_from_u64(0x456);
        let sk_scalar = JubJubScalar::random(&mut rng);
        let private_key: BabyJubJubSK = sk_scalar.into();
        let public_key = private_key.get_public_key();
        
        let message = b"test message";
        let wrong_message = b"wrong message";
        let proof = SigmaProof::prove(message, &private_key).unwrap();
        
        // Fiat-Shamir challenge depends on message, so wrong message should fail
        assert!(!proof.verify(wrong_message, &public_key).unwrap());
    }

    #[test]
    fn test_sigma_protocol_invalid_public_key() {
        let mut rng = StdRng::seed_from_u64(0x789);
        let sk_scalar = JubJubScalar::random(&mut rng);
        let private_key: BabyJubJubSK = sk_scalar.into();
        
        let wrong_sk_scalar = JubJubScalar::random(&mut rng);
        let wrong_private_key: BabyJubJubSK = wrong_sk_scalar.into();
        let wrong_public_key = wrong_private_key.get_public_key();
        
        let message = b"test message";
        let proof = SigmaProof::prove(message, &private_key).unwrap();
        
        // Proof was created for different public key, so should fail
        assert!(!proof.verify(message, &wrong_public_key).unwrap());
    }

    #[test]
    fn test_multiple_proofs_same_statement() {
        let mut rng = StdRng::seed_from_u64(0xabc);
        let sk_scalar = JubJubScalar::random(&mut rng);
        let private_key: BabyJubJubSK = sk_scalar.into();
        let public_key = private_key.get_public_key();
        
        // Test multiple proofs of the same statement (different random nonces)
        let message = b"test message";
        for _ in 0..5 {
            let proof = SigmaProof::prove(message, &private_key).unwrap();
            assert!(proof.verify(message, &public_key).unwrap());
        }
    }

    #[test]
    fn test_fiat_shamir_deterministic() {
        let mut rng = StdRng::seed_from_u64(0xdef);
        let sk_scalar = JubJubScalar::random(&mut rng);
        let private_key: BabyJubJubSK = sk_scalar.into();
        let public_key = private_key.get_public_key();
        
        // Create a commitment point
        let k = JubJubScalar::random(&mut rng);
        let r_point = GENERATOR_EXTENDED * &k;
        let r_pk: BabyJubJubPK = r_point.into();
        
        let message = b"test message";
        
        // Fiat-Shamir should be deterministic for same inputs
        let challenge1 = fiat_shamir_challenge(&r_pk, &public_key, message).unwrap();
        let challenge2 = fiat_shamir_challenge(&r_pk, &public_key, message).unwrap();
        
        assert_eq!(challenge1.c, challenge2.c);
    }

    #[test]
    fn test_sigma_protocol_completeness() {
        // Completeness: honest prover with correct secret should always convince verifier
        let mut rng = StdRng::seed_from_u64(0x111);
        
        for _ in 0..10 {
            let sk_scalar = JubJubScalar::random(&mut rng);
            let private_key: BabyJubJubSK = sk_scalar.into();
            let public_key = private_key.get_public_key();
            
            let message = b"completeness test";
            let proof = SigmaProof::prove(message, &private_key).unwrap();
            
            assert!(proof.verify(message, &public_key).unwrap());
        }
    }

    #[test]
    fn test_sigma_protocol_soundness() {
        // Soundness: prover without correct secret should not convince verifier
        let mut rng = StdRng::seed_from_u64(0x222);
        
        let sk_scalar = JubJubScalar::random(&mut rng);
        let private_key: BabyJubJubSK = sk_scalar.into();
        let public_key = private_key.get_public_key();
        
        // Create proof for correct key
        let message = b"soundness test";
        let proof = SigmaProof::prove(message, &private_key).unwrap();
        
        // Try to verify with different public keys (should all fail)
        for _ in 0..5 {
            let wrong_sk = JubJubScalar::random(&mut rng);
            let wrong_private_key: BabyJubJubSK = wrong_sk.into();
            let wrong_public_key = wrong_private_key.get_public_key();
            
            assert!(!proof.verify(message, &wrong_public_key).unwrap());
        }
    }

    // Legacy tests for backward compatibility
    #[test]
    fn test_schnorr_signature_legacy_compatibility() {
        let mut rng = StdRng::seed_from_u64(0x333);
        let sk_scalar = JubJubScalar::random(&mut rng);
        let private_key: BabyJubJubSK = sk_scalar.into();
        let public_key = private_key.get_public_key();
        
        let message = b"legacy test";
        let signature = SchnorrSignature::sign(message, &private_key).unwrap();
        
        assert!(signature.verify(message, &public_key).unwrap());
    }
}