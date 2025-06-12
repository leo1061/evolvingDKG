use std::{fs, path::Path, process::Command, str::FromStr, fmt};
use anyhow::Result;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json;
use dusk_jubjub::{JubJubScalar, JubJubExtended};
use group::GroupEncoding;

pub mod elgamal;
use elgamal::ElGamalCiphertext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BabyJubJubPK {
    pub x: BigUint,
    pub y: BigUint,
}

impl From<JubJubExtended> for BabyJubJubPK {
    fn from(pk: JubJubExtended) -> Self {
        let bytes = pk.to_bytes();
        // The bytes represent the x-coordinate in compressed format
        Self {
            x: BigUint::from_bytes_le(&bytes),
            y: BigUint::from(0u32), // We can't recover y from compressed format
        }
    }
}

impl From<BabyJubJubPK> for JubJubExtended {
    fn from(pk: BabyJubJubPK) -> Self {
        let mut bytes = [0u8; 32];
        let x_bytes = pk.x.to_bytes_le();
        bytes[0..x_bytes.len()].copy_from_slice(&x_bytes);
        JubJubExtended::from_bytes(&bytes).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct BabyJubJubSK {
    pub value: BigUint,
}

impl From<JubJubScalar> for BabyJubJubSK {
    fn from(sk: JubJubScalar) -> Self {
        Self {
            value: BigUint::from_bytes_le(&sk.to_bytes()),
        }
    }
}

impl From<BabyJubJubSK> for JubJubScalar {
    fn from(sk: BabyJubJubSK) -> Self {
        let mut bytes = [0u8; 32];
        let sk_bytes = sk.value.to_bytes_le();
        bytes[0..sk_bytes.len()].copy_from_slice(&sk_bytes);
        JubJubScalar::from_bytes(&bytes).unwrap()
    }
}

#[derive(Debug)]
pub struct Share {
    pub sk: BabyJubJubSK,
    pub pk: BabyJubJubPK,
    pub share: BigUint,
    pub encr_share: Option<ElGamalCiphertext>,  // Encrypted share using ElGamal
}

impl Share {
    pub fn new(sk: BabyJubJubSK, pk: BabyJubJubPK) -> Self {
        Self {
            sk,
            pk,
            share: BigUint::from(0u32),
            encr_share: None,
        }
    }

    pub fn set_share(&mut self, share: BigUint) {
        self.share = share;
    }

    pub fn set_encrypted_share(&mut self, encr_share: ElGamalCiphertext) {
        self.encr_share = Some(encr_share);
    }
}

impl fmt::Display for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  Secret Key: {}", self.sk.value)?;
        writeln!(f, "  Public Key: ({}, {})", self.pk.x, self.pk.y)?;
        writeln!(f, "  Share: {}", self.share)
    }
}

#[derive(Debug)]
pub struct Party {
    pub index: u32,
    pub share: Share,   
}

impl Party {
    pub fn new(i: u32, sk: BabyJubJubSK, pk: BabyJubJubPK) -> Result<Self> {
        Ok(Self {
            index: i,
            share: Share::new(sk, pk),
        })
    }

    pub fn set_share(&mut self, share: BigUint) {
        self.share.set_share(share);
    }
}

impl fmt::Display for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Party {}:", self.index)?;
        write!(f, "{}", self.share)
    }
}

// Wrapper type for Vec<Party>
pub struct PartyList(pub Vec<Party>);

impl fmt::Display for PartyList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\nAll Parties:")?;
        writeln!(f, "{}", "=".repeat(50))?;
        for party in &self.0 {
            writeln!(f, "{}", party)?;
            writeln!(f, "{}", "-".repeat(50))?;
        }
        Ok(())
    }
}

pub fn key_gen(i: u32) -> Result<()> {
    // Get the parent directory path
    let parent_dir = Path::new("..");
    
    // Execute the Node.js script with the correct path
    let output = Command::new("node")
        .current_dir(parent_dir)  // Set working directory to parent
        .arg("scripts/gen_bjj_keys.js")
        .arg(i.to_string())
        .output()?;

    // Check if the command was successful
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to generate keys: {}", error);
    }

    Ok(())
}

pub fn read_keys(i: u32) -> (BabyJubJubSK, BabyJubJubPK) {
    let sk_file_path = format!("../bjj_sk_{}.txt", i);
    let sk_contents = fs::read_to_string(sk_file_path)
        .expect("Should have been able to read the file");
    let sk = BabyJubJubSK {
        value: BigUint::from_str(&sk_contents).unwrap()
    };

    let pk_file_path = format!("../bjj_pk_{}.txt", i);
    let pk_contents = fs::read_to_string(pk_file_path)
        .expect("Should have been able to read the file");
    
    let pk_array: Vec<String> = serde_json::from_str(&pk_contents)
        .expect("Failed to parse public key array");
    
    let pk = BabyJubJubPK {
        x: BigUint::from_str(&pk_array[0]).unwrap(),
        y: BigUint::from_str(&pk_array[1]).unwrap()
    };

    (sk, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_jubjub::GENERATOR_EXTENDED;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use ff::Field;

    #[test]
    fn test_pk_conversion_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0x123);
        
        // Generate a random JubJub public key
        let sk = JubJubScalar::random(&mut rng);
        let jubjub_pk = GENERATOR_EXTENDED * &sk;
        
        // Convert to BabyJubJub and back
        let babyjub_pk: BabyJubJubPK = jubjub_pk.into();
        let jubjub_pk_again: JubJubExtended = babyjub_pk.into();
        
        // Verify the roundtrip conversion
        assert_eq!(jubjub_pk, jubjub_pk_again);
    }

    #[test]
    fn test_sk_conversion_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0x456);
        
        // Generate a random JubJub scalar
        let jubjub_sk = JubJubScalar::random(&mut rng);
        
        // Convert to BabyJubJub and back
        let babyjub_sk: BabyJubJubSK = jubjub_sk.into();
        let jubjub_sk_again: JubJubScalar = babyjub_sk.into();
        
        // Verify the roundtrip conversion
        assert_eq!(jubjub_sk, jubjub_sk_again);
    }

    #[test]
    fn test_keypair_consistency() {
        let mut rng = StdRng::seed_from_u64(0x789);
        
        // Generate a keypair using JubJub
        let jubjub_sk = JubJubScalar::random(&mut rng);
        let jubjub_pk = GENERATOR_EXTENDED * &jubjub_sk;
        
        // Convert to BabyJubJub format
        let babyjub_sk: BabyJubJubSK = jubjub_sk.into();
        let babyjub_pk: BabyJubJubPK = jubjub_pk.into();
        
        // Convert back to JubJub
        let jubjub_sk_again: JubJubScalar = babyjub_sk.into();
        let jubjub_pk_again: JubJubExtended = babyjub_pk.into();
        
        // Verify the keypair relationship is maintained
        let expected_pk = GENERATOR_EXTENDED * &jubjub_sk_again;
        assert_eq!(jubjub_pk_again, expected_pk);
    }

    #[test]
    fn test_multiple_conversions() {
        let mut rng = StdRng::seed_from_u64(0xabc);
        
        // Test multiple random keypairs
        for _ in 0..10 {
            let jubjub_sk = JubJubScalar::random(&mut rng);
            let jubjub_pk = GENERATOR_EXTENDED * &jubjub_sk;
            
            let babyjub_sk: BabyJubJubSK = jubjub_sk.into();
            let babyjub_pk: BabyJubJubPK = jubjub_pk.into();
            
            let jubjub_sk_again: JubJubScalar = babyjub_sk.into();
            let jubjub_pk_again: JubJubExtended = babyjub_pk.into();
            
            assert_eq!(jubjub_sk, jubjub_sk_again);
            assert_eq!(jubjub_pk, jubjub_pk_again);
            
            // Verify the keypair relationship
            let expected_pk = GENERATOR_EXTENDED * &jubjub_sk_again;
            assert_eq!(jubjub_pk_again, expected_pk);
        }
    }

    #[test]
    fn test_edge_cases() {
        // Test zero scalar
        let zero_scalar = JubJubScalar::zero();
        let babyjub_sk: BabyJubJubSK = zero_scalar.into();
        let jubjub_sk_again: JubJubScalar = babyjub_sk.into();
        assert_eq!(zero_scalar, jubjub_sk_again);
        
        // Test identity point
        let identity = JubJubExtended::default();
        let babyjub_pk: BabyJubJubPK = identity.into();
        let jubjub_pk_again: JubJubExtended = babyjub_pk.into();
        assert_eq!(identity, jubjub_pk_again);
    }
} 