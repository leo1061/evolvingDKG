use ark_ec::{AffineRepr, PrimeGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsConfig, EdwardsProjective, Fr};
use ark_ff::UniformRand;
use ark_std::rand::{CryptoRng, RngCore};
use ark_std::Zero;
use std::str::FromStr;
use anyhow::Result;

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

    // FIX: must use the mapping elligator2
    pub fn encrypt_scalar<R: RngCore + CryptoRng>(
        public_key: &EdwardsProjective,
        message: &Fr,
        rng: &mut R,
    ) -> Result<ElGamalCiphertext> {
        let message_point = EdwardsProjective::generator() * message;
        Self::encrypt(public_key, &message_point, rng)
    }

    // FIX: must use the mapping elligator2
    pub fn decrypt_to_scalar(ciphertext: &ElGamalCiphertext, sk: &Fr) -> Option<Fr> {
        let decrypted_point = ciphertext.decrypt(sk);
        Self::discrete_log(&decrypted_point, 32)
    }

    // FIX: remove
    fn discrete_log(point: &EdwardsProjective, max_bits: u32) -> Option<Fr> {
        let generator = EdwardsProjective::generator();
        let max_value = 1u64 << max_bits;
        
        let mut current = EdwardsProjective::zero();
        for i in 0..max_value {
            if current == *point {
                return Some(Fr::from(i));
            }
            current += generator;
        }
        
        None
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
        
        let message_scalar = Fr::from(42u64);
        
        let ciphertext = ElGamal::encrypt_scalar(&pk, &message_scalar, &mut rng).unwrap();
        
        let decrypted_scalar = ElGamal::decrypt_to_scalar(&ciphertext, &sk);
        
        assert_eq!(decrypted_scalar, Some(message_scalar));
    }

    #[test]
    fn test_homomorphic_addition() {
        let mut rng = StdRng::seed_from_u64(0xabcdef);
        
        let (sk, pk) = ElGamal::generate_keypair(&mut rng);
        
        let m1 = Fr::from(10u64);
        let m2 = Fr::from(20u64);
        
        let ct1 = ElGamal::encrypt_scalar(&pk, &m1, &mut rng).unwrap();
        let ct2 = ElGamal::encrypt_scalar(&pk, &m2, &mut rng).unwrap();
        
        let ct_sum = ElGamal::homomorphic_add(&ct1, &ct2);
        
        let decrypted_sum = ElGamal::decrypt_to_scalar(&ct_sum, &sk);
        
        assert_eq!(decrypted_sum, Some(Fr::from(30u64)));
    }

    #[test]
    fn test_scalar_multiplication() {
        let mut rng = StdRng::seed_from_u64(0xfedcba);
        
        let (sk, pk) = ElGamal::generate_keypair(&mut rng);
        
        let m = Fr::from(5u64);
        let scalar = Fr::from(3u64);
        
        let ct = ElGamal::encrypt_scalar(&pk, &m, &mut rng).unwrap();
        
        let ct_scaled = ElGamal::scalar_multiply(&ct, &scalar);
        
        let decrypted_scaled = ElGamal::decrypt_to_scalar(&ct_scaled, &sk);
        
        assert_eq!(decrypted_scaled, Some(Fr::from(15u64)));
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