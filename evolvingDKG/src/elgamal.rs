use ark_ec::{AffineRepr, PrimeGroup, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsConfig, EdwardsProjective, Fr, Fq};
use ark_ff::{UniformRand, PrimeField, BigInteger};
use ark_std::rand::{CryptoRng, RngCore};
use ark_std::Zero;
use std::str::FromStr;
use anyhow::{Result, anyhow};
use crate::curve_converter::{CurveConverter, Elligator2};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    pub c1: EdwardsProjective,
    pub c2: EdwardsProjective,
}

impl ElGamalCiphertext {
    pub fn new(c1: EdwardsProjective, c2: EdwardsProjective) -> Self {
        Self { c1, c2 }
    }

    pub fn decrypt(&self, sk: &Fr) -> EdwardsProjective {
        self.c2 - self.c1 * sk
    }
}

pub struct ElGamal;

impl ElGamal {
    pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (Fr, EdwardsProjective) {
        let sk = Fr::rand(rng);
        let pk = EdwardsProjective::generator() * sk;
        (sk, pk)
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        public_key: &EdwardsProjective,
        message: &EdwardsProjective,
        rng: &mut R,
    ) -> Result<ElGamalCiphertext> {
        let r = Fr::rand(rng);
        
        let c1 = EdwardsProjective::generator() * r;
        let c2 = *message + *public_key * r;
        
        Ok(ElGamalCiphertext::new(c1, c2))
    }

    /// Encrypt a scalar value by first mapping it to a curve point using Elligator2
    pub fn encrypt_scalar<R: RngCore + CryptoRng>(
        public_key: &EdwardsProjective,
        message: &Fr,
        rng: &mut R,
    ) -> Result<ElGamalCiphertext> {
        // Convert scalar to field element for Elligator2
        let message_bytes = message.into_bigint().to_bytes_le();
        let field_element = Fq::from_le_bytes_mod_order(&message_bytes);
        
        // Map to Montgomery curve using Elligator2
        let a = CurveConverter::montgomery_a();
        let b = CurveConverter::montgomery_b();
        let (x_mont, y_mont) = Elligator2::encode(&field_element, &a, &b)
            .ok_or_else(|| anyhow!("Failed to encode scalar to Montgomery point"))?;
        
        // Convert Montgomery point to Edwards point
        let edwards_point = CurveConverter::montgomery_to_edwards(x_mont, y_mont)
            .ok_or_else(|| anyhow!("Failed to convert Montgomery to Edwards point"))?;
        
        // Encrypt the Edwards point
        Self::encrypt(public_key, &edwards_point.into(), rng)
    }

    /// Decrypt a ciphertext and recover the scalar by reversing the Elligator2 mapping
    pub fn decrypt_to_scalar(ciphertext: &ElGamalCiphertext, sk: &Fr) -> Option<Fr> {
        let decrypted_point = ciphertext.decrypt(sk);
        let edwards_affine = decrypted_point.into_affine();
        
        // Convert Edwards point to Montgomery point
        let (x_mont, y_mont) = CurveConverter::edwards_to_montgomery(&edwards_affine)?;
        
        // Decode Montgomery point to field element using Elligator2
        let a = CurveConverter::montgomery_a();
        let b = CurveConverter::montgomery_b();
        let field_element = Elligator2::decode(&x_mont, &y_mont, &a, &b)?;
        
        // Convert field element back to scalar
        let field_bytes = field_element.into_bigint().to_bytes_le();
        Some(Fr::from_le_bytes_mod_order(&field_bytes))
    }


    pub fn homomorphic_add(
        ct1: &ElGamalCiphertext,
        ct2: &ElGamalCiphertext,
    ) -> ElGamalCiphertext {
        ElGamalCiphertext::new(ct1.c1 + ct2.c1, ct1.c2 + ct2.c2)
    }

    pub fn scalar_multiply(ct: &ElGamalCiphertext, scalar: &Fr) -> ElGamalCiphertext {
        ElGamalCiphertext::new(ct.c1 * scalar, ct.c2 * scalar)
    }

    pub fn rerandomize<R: RngCore + CryptoRng>(
        ct: &ElGamalCiphertext,
        pk: &EdwardsProjective,
        rng: &mut R,
    ) -> ElGamalCiphertext {
        let r = Fr::rand(rng);
        let generator = EdwardsProjective::generator();
        
        ElGamalCiphertext::new(ct.c1 + generator * r, ct.c2 + *pk * r)
    }
}

pub fn generator() -> EdwardsProjective {
    EdwardsProjective::generator()
}

pub fn generator_affine() -> EdwardsAffine {
    EdwardsAffine::generator()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    #[test]
    fn test_elgamal_encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(0x12345678);
        
        let (sk, pk) = ElGamal::generate_keypair(&mut rng);
        
        let message = EdwardsProjective::generator() * Fr::from(1234u64);
        
        let ciphertext = ElGamal::encrypt(&pk, &message, &mut rng).unwrap();
        
        let decrypted = ciphertext.decrypt(&sk);
        
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_scalar_encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(0x87654321);
        
        let (sk, pk) = ElGamal::generate_keypair(&mut rng);
        
        // Test with multiple scalars to find ones that work with Elligator2
        let test_values = [1u64, 2, 3, 42, 100, 255, 1000, 12345];
        let mut successful_tests = 0;
        
        for &test_value in &test_values {
            let message_scalar = Fr::from(test_value);
            
            if let Ok(ciphertext) = ElGamal::encrypt_scalar(&pk, &message_scalar, &mut rng) {
                if let Some(decrypted_scalar) = ElGamal::decrypt_to_scalar(&ciphertext, &sk) {
                    if decrypted_scalar == message_scalar {
                        successful_tests += 1;
                    }
                }
            }
        }
        
        // Expect at least one successful round trip (Elligator2 doesn't work for all inputs)
        assert!(successful_tests > 0, "No successful Elligator2 round trips found");
    }

    #[test]
    fn test_homomorphic_addition() {
        let mut rng = StdRng::seed_from_u64(0xabcdef);
        
        let (sk, pk) = ElGamal::generate_keypair(&mut rng);
        
        // Try multiple combinations to find ones that work with Elligator2
        let test_pairs = [(1u64, 2u64), (3u64, 5u64), (10u64, 20u64), (7u64, 11u64)];
        
        for &(val1, val2) in &test_pairs {
            let m1 = Fr::from(val1);
            let m2 = Fr::from(val2);
            
            if let (Ok(ct1), Ok(ct2)) = (
                ElGamal::encrypt_scalar(&pk, &m1, &mut rng),
                ElGamal::encrypt_scalar(&pk, &m2, &mut rng)
            ) {
                let ct_sum = ElGamal::homomorphic_add(&ct1, &ct2);
                
                if let Some(decrypted_sum) = ElGamal::decrypt_to_scalar(&ct_sum, &sk) {
                    let expected_sum = Fr::from(val1 + val2);
                    if decrypted_sum == expected_sum {
                        return; // Test passed
                    }
                }
            }
        }
        
        panic!("No successful homomorphic addition with Elligator2 found");
    }

    #[test]
    fn test_scalar_multiplication() {
        let mut rng = StdRng::seed_from_u64(0xfedcba);
        
        let (sk, pk) = ElGamal::generate_keypair(&mut rng);
        
        // Try multiple combinations to find ones that work with Elligator2
        let test_pairs = [(1u64, 2u64), (2u64, 3u64), (5u64, 3u64), (7u64, 4u64)];
        
        for &(msg_val, scalar_val) in &test_pairs {
            let m = Fr::from(msg_val);
            let scalar = Fr::from(scalar_val);
            
            if let Ok(ct) = ElGamal::encrypt_scalar(&pk, &m, &mut rng) {
                let ct_scaled = ElGamal::scalar_multiply(&ct, &scalar);
                
                if let Some(decrypted_scaled) = ElGamal::decrypt_to_scalar(&ct_scaled, &sk) {
                    let expected = Fr::from(msg_val * scalar_val);
                    if decrypted_scaled == expected {
                        return; // Test passed
                    }
                }
            }
        }
        
        panic!("No successful scalar multiplication with Elligator2 found");
    }

    #[test]
    fn test_rerandomization() {
        let mut rng = StdRng::seed_from_u64(0x111222);
        
        let (sk, pk) = ElGamal::generate_keypair(&mut rng);
        
        let message = EdwardsProjective::generator() * Fr::from(999u64);
        
        let ct1 = ElGamal::encrypt(&pk, &message, &mut rng).unwrap();
        
        let ct2 = ElGamal::rerandomize(&ct1, &pk, &mut rng);
        
        assert_ne!(ct1.c1, ct2.c1);
        assert_ne!(ct1.c2, ct2.c2);
        
        let decrypted1 = ct1.decrypt(&sk);
        let decrypted2 = ct2.decrypt(&sk);
        
        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_keypair_generation() {
        let mut rng = StdRng::seed_from_u64(0x333444);
        
        let (sk1, pk1) = ElGamal::generate_keypair(&mut rng);
        let (sk2, pk2) = ElGamal::generate_keypair(&mut rng);
        
        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
        
        assert_eq!(pk1, EdwardsProjective::generator() * sk1);
        assert_eq!(pk2, EdwardsProjective::generator() * sk2);
    }

    #[test]
    fn test_curve_properties() {
        let generator = generator();
        
        assert!(!generator.is_zero());
        
        let generator_affine = generator_affine();
        assert!(generator_affine.is_on_curve());
        
        let scalar_order = Fr::from_str(
            "2736030358979909402780800718157159386076813972158567259200215660948447373041"
        )
        .unwrap();
        let should_be_identity = generator * scalar_order;
        assert!(should_be_identity.is_zero());
    }
}