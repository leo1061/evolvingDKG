use anyhow::Result;
use jubjub_elgamal::{Encryption, DecryptFrom};
use dusk_jubjub::{JubJubScalar, JubJubExtended, GENERATOR_EXTENDED};
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Represents an ElGamal ciphertext using JubJub curve
#[derive(Debug, Clone)]
pub struct ElGamalCiphertext {
    pub c1: JubJubExtended,  // rG
    pub c2: JubJubExtended,  // m + rPK
}

impl ElGamalCiphertext {
    /// Create a new ElGamal ciphertext
    pub fn new(c1: JubJubExtended, c2: JubJubExtended) -> Self {
        Self { c1, c2 }
    }

    /// Decrypt the ciphertext using a secret key
    pub fn decrypt(&self, sk: &JubJubScalar) -> JubJubExtended {
        // c2 - sk * c1 = m + rPK - sk * rG = m + rPK - rPK = m
        self.c2 - (self.c1 * sk)
    }
}

/// Encrypt a message using ElGamal with JubJub curve
pub fn encrypt(
    public_key: &JubJubExtended,
    message: &JubJubExtended,
    rng: &mut StdRng,
) -> Result<ElGamalCiphertext> {
    // Generate a random scalar for the encryption
    let r = JubJubScalar::random(rng);
    
    // Compute c1 = rG
    let c1 = GENERATOR_EXTENDED * &r;
    
    // Compute c2 = m + rPK
    let c2 = message + (public_key * &r);
    
    Ok(ElGamalCiphertext::new(c1, c2))
}

/// Generate a new ElGamal key pair
pub fn generate_keypair(rng: &mut StdRng) -> (JubJubScalar, JubJubExtended) {
    // Generate private key
    let sk = JubJubScalar::random(rng);
    
    // Compute public key
    let pk = GENERATOR_EXTENDED * &sk;
    
    (sk, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_elgamal_encryption_decryption() {
        let mut rng = StdRng::seed_from_u64(0xc0b);
        
        // Generate key pair
        let (sk, pk) = generate_keypair(&mut rng);
        
        // Create a test message
        let message = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);
        
        // Encrypt the message
        let ciphertext = encrypt(&pk, &message, &mut rng).unwrap();
        
        // Decrypt the message
        let decrypted = ciphertext.decrypt(&sk);
        
        // Verify the decryption
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_keypair_generation() {
        let mut rng = StdRng::seed_from_u64(0x123);
        
        // Generate two different key pairs
        let (sk1, pk1) = generate_keypair(&mut rng);
        let (sk2, pk2) = generate_keypair(&mut rng);
        
        // Verify that different key pairs are generated
        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
        
        // Verify that public key is derived correctly from private key
        assert_eq!(pk1, GENERATOR_EXTENDED * &sk1);
        assert_eq!(pk2, GENERATOR_EXTENDED * &sk2);
    }

    #[test]
    fn test_multiple_encryptions() {
        let mut rng = StdRng::seed_from_u64(0x456);
        let (sk, pk) = generate_keypair(&mut rng);
        
        // Test multiple messages
        let messages = vec![
            GENERATOR_EXTENDED * JubJubScalar::from(1u64),
            GENERATOR_EXTENDED * JubJubScalar::from(42u64),
            GENERATOR_EXTENDED * JubJubScalar::from(999u64),
        ];
        
        for message in messages {
            let ciphertext = encrypt(&pk, &message, &mut rng).unwrap();
            let decrypted = ciphertext.decrypt(&sk);
            assert_eq!(message, decrypted);
        }
    }

    #[test]
    fn test_ciphertext_creation() {
        let mut rng = StdRng::seed_from_u64(0x789);
        let (_, pk) = generate_keypair(&mut rng);
        let message = GENERATOR_EXTENDED * JubJubScalar::from(100u64);
        
        let ciphertext = encrypt(&pk, &message, &mut rng).unwrap();
        
        // Verify ciphertext components are not zero
        assert_ne!(ciphertext.c1, JubJubExtended::default());
        assert_ne!(ciphertext.c2, JubJubExtended::default());
    }
} 