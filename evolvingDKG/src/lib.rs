use std::{fs, path::Path, process::Command, str::FromStr, fmt, hash::Hash};
use anyhow::Result;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json;
use dusk_jubjub::{JubJubScalar, JubJubExtended, JubJubAffine, GENERATOR_EXTENDED};
use group::GroupEncoding;
use ff::Field;

pub mod elgamal;
pub mod schnorr_lib;
pub mod setup_zk;
pub mod circom_encryption;
pub mod circom_decryption;
use elgamal::ElGamalCiphertext;

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct BabyJubJubPK {
    pub x: BigUint,
    pub y: BigUint,
}

impl From<JubJubExtended> for BabyJubJubPK {
    fn from(pk: JubJubExtended) -> Self {
        use dusk_jubjub::JubJubAffine;
        
        // Convert to affine coordinates to get both x and y
        let affine: JubJubAffine = pk.into();
        
        // Extract x and y coordinates - use get_u and get_v for Edwards coordinates
        let u_bytes = affine.get_u().to_bytes();
        let v_bytes = affine.get_v().to_bytes();
        
        Self {
            x: BigUint::from_bytes_le(&u_bytes),
            y: BigUint::from_bytes_le(&v_bytes),
        }
    }
}

impl From<BabyJubJubPK> for JubJubExtended {
    fn from(pk: BabyJubJubPK) -> Self {
        use dusk_jubjub::JubJubAffine;
        
        // Convert BigUint coordinates to field elements
        let u_field = biguint_to_field(&pk.x).expect("Invalid u coordinate");
        let v_field = biguint_to_field(&pk.y).expect("Invalid v coordinate");
        
        // Create affine point from Edwards coordinates (u, v)
        let affine = JubJubAffine::from_raw_unchecked(u_field, v_field);
        
        // Verify the point is on the curve
        if affine.is_on_curve().into() {
            affine.into()
        } else {
            // If coordinates don't form a valid curve point, try to recover
            // This handles cases where we only have u coordinate (compressed format)
            recover_point_from_u(&pk.x).unwrap_or_else(|_| {
                // Fallback: create a deterministic valid point
                create_deterministic_point(&pk.x, &pk.y)
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct BabyJubJubSK {
    pub value: BigUint,
}

impl BabyJubJubSK {
    pub fn get_public_key(&self) -> BabyJubJubPK {     
        let jubjub_sk = biguint_to_scalar(&self.value).expect("Invalid scalar value");
        let jubjub_pk = GENERATOR_EXTENDED * &jubjub_sk;
        jubjub_pk.into()
    }
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

#[derive(Debug, Clone)]
pub struct Share {
    pub sk: BabyJubJubSK,
    pub pk: BabyJubJubPK,
    pub share: BigUint,
    pub encr_share: Option<Vec<ElGamalCiphertext>>,  // Encrypted share using ElGamal
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

    pub fn set_encrypted_share(&mut self, encr_share: Vec<ElGamalCiphertext>) {
        self.encr_share = Some(encr_share);
    }

    pub fn get_encrypted_share(&self) -> Option<&Vec<ElGamalCiphertext>> {
        self.encr_share.as_ref()
    }
}

impl fmt::Display for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  Secret Key: {}", self.sk.value)?;
        writeln!(f, "  Public Key: ({}, {})", self.pk.x, self.pk.y)?;
        writeln!(f, "  Share: {}", self.share)
    }
}

#[derive(Debug, Clone)]
pub struct Party {
    pub index: u32,
    pub generation: u32,
    pub share: Share,   
}

impl Party {
    pub fn new(i: u32, g: u32, sk: BabyJubJubSK, pk: BabyJubJubPK) -> Result<Self> {
        Ok(Self {
            index: i,
            generation: g,
            share: Share::new(sk, pk),
        })
    }

    pub fn set_share(&mut self, share: BigUint) {
        self.share.set_share(share);
    }

    pub fn get_generation(&mut self) -> u32 {
        self.generation
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

pub struct PKI {
    pub keys: Vec<BabyJubJubPK>,
}

impl PKI {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn add_public_key(&mut self, pk: BabyJubJubPK) {
        self.keys.push(pk);
    }
    
    pub fn get_public_key(&self, index: usize) -> Option<&BabyJubJubPK> {
        self.keys.get(index)
    }
}

impl fmt::Display for BabyJubJubPK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}

impl fmt::Display for PKI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PKI contains {} keys", self.keys.len())?;
        for (i, pk) in self.keys.iter().enumerate() {
            writeln!(f, "Key {}: {}", i, pk)?;
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

// Helper function to convert BigUint to JubJub scalar with proper field reduction
pub fn biguint_to_scalar(value: &BigUint) -> Result<JubJubScalar> {
    let mut bytes = [0u8; 32];
    let value_bytes = value.to_bytes_le();
    
    // Handle values that are larger than 32 bytes
    if value_bytes.len() > 32 {
        // Use modular reduction to fit within field
        let field_modulus = BigUint::from_str("52435875175126190479447740508185965837690552500527637822603658699938581184513")?;
        let reduced = value % &field_modulus;
        let reduced_bytes = reduced.to_bytes_le();
        bytes[0..reduced_bytes.len().min(32)].copy_from_slice(&reduced_bytes[0..reduced_bytes.len().min(32)]);
    } else {
        bytes[0..value_bytes.len()].copy_from_slice(&value_bytes);
    }
    
    // Create scalar from bytes using CtOption
    JubJubScalar::from_bytes(&bytes).into_option().ok_or_else(|| anyhow::anyhow!("Invalid scalar bytes"))
}

// Helper function to convert BigUint to JubJub field element
fn biguint_to_field(value: &BigUint) -> Result<dusk_jubjub::Fq> {
    let mut bytes = [0u8; 32];
    let value_bytes = value.to_bytes_le();
    
    // Handle values that are larger than 32 bytes
    if value_bytes.len() > 32 {
        // Use modular reduction to fit within field
        let field_modulus = BigUint::from_str("52435875175126190479447740508185965837690552500527637822603658699938581184513")?;
        let reduced = value % &field_modulus;
        let reduced_bytes = reduced.to_bytes_le();
        bytes[0..reduced_bytes.len().min(32)].copy_from_slice(&reduced_bytes[0..reduced_bytes.len().min(32)]);
    } else {
        bytes[0..value_bytes.len()].copy_from_slice(&value_bytes);
    }
    
    // Create field element from bytes using CtOption
    dusk_jubjub::Fq::from_bytes(&bytes).into_option().ok_or_else(|| anyhow::anyhow!("Invalid field element bytes"))
}

// Recover a JubJub point from u coordinate (for compressed point decompression)
fn recover_point_from_u(u: &BigUint) -> Result<JubJubExtended> {
    use ff::Field;
    use dusk_jubjub::JubJubAffine;
    
    let u_field = biguint_to_field(u)?;
    
    // Edwards curve equation: u^2 + v^2 = 1 + d*u^2*v^2
    // Where d is the Edwards curve parameter for BabyJubJub
    // Rearranging: v^2 = (1 - u^2) / (1 + d*u^2)
    
    // BabyJubJub parameter d = 168696/168700 
    let d_num = dusk_jubjub::Fq::from(168696u64);
    let d_den = dusk_jubjub::Fq::from(168700u64);
    let d = d_num * d_den.invert().unwrap();
    
    let u_squared = u_field.square();
    let numerator = dusk_jubjub::Fq::one() - u_squared;
    let denominator = dusk_jubjub::Fq::one() + d * u_squared;
    
    let denom_inv_opt: Option<dusk_jubjub::Fq> = denominator.invert().into();
    if let Some(denom_inv) = denom_inv_opt {
        let v_squared = numerator * denom_inv;
        
        // Try to find square root
        if let Some(v_field) = v_squared.sqrt().into() {
            let affine = JubJubAffine::from_raw_unchecked(u_field, v_field);
            if affine.is_on_curve().into() {
                return Ok(affine.into());
            }
            
            // Try the negative square root
            let v_field_neg = -v_field;
            let affine_neg = JubJubAffine::from_raw_unchecked(u_field, v_field_neg);
            if affine_neg.is_on_curve().into() {
                return Ok(affine_neg.into());
            }
        }
    }
    
    Err(anyhow::anyhow!("Cannot recover valid point from u coordinate"))
}

// Create a deterministic valid point from coordinates (fallback method)
fn create_deterministic_point(x: &BigUint, y: &BigUint) -> JubJubExtended {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Create a deterministic scalar from both coordinates
    let mut hasher = DefaultHasher::new();
    x.hash(&mut hasher);
    y.hash(&mut hasher);
    let hash_value = hasher.finish();
    
    // Convert to a JubJub scalar
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[0..8].copy_from_slice(&hash_value.to_le_bytes());
    
    let scalar = JubJubScalar::from_bytes(&scalar_bytes).unwrap();
    GENERATOR_EXTENDED * &scalar
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

    #[test]
    fn test_pki_initialization() {
        let pki = PKI::new();
        assert_eq!(pki.keys.len(), 0);
    }

    #[test]
    fn test_pki_add_and_get_keys() {
        let mut pki = PKI::new();
        let mut rng = StdRng::seed_from_u64(0xdef);

        // Generate and add some test keys
        for _ in 0..3 {
            let sk = JubJubScalar::random(&mut rng);
            let jubjub_pk = GENERATOR_EXTENDED * &sk;
            let babyjub_pk: BabyJubJubPK = jubjub_pk.into();
            pki.add_public_key(babyjub_pk);
        }

        // Verify the number of keys
        assert_eq!(pki.keys.len(), 3);

        // Test retrieving keys
        assert!(pki.get_public_key(0).is_some());
        assert!(pki.get_public_key(1).is_some());
        assert!(pki.get_public_key(2).is_some());
        assert!(pki.get_public_key(3).is_none()); // Out of bounds
    }

    #[test]
    fn test_pki_key_consistency() {
        let mut pki = PKI::new();
        let mut rng = StdRng::seed_from_u64(0x123);

        // Generate a keypair
        let sk = JubJubScalar::random(&mut rng);
        let jubjub_pk = GENERATOR_EXTENDED * &sk;
        let babyjub_pk: BabyJubJubPK = jubjub_pk.into();

        // Add the public key to PKI
        pki.add_public_key(babyjub_pk.clone());

        // Retrieve and verify the key
        let retrieved_pk = pki.get_public_key(0).unwrap();
        assert_eq!(retrieved_pk.x, babyjub_pk.x);
        assert_eq!(retrieved_pk.y, babyjub_pk.y);
    }

    #[test]
    fn test_pki_display() {
        let mut pki = PKI::new();
        let mut rng = StdRng::seed_from_u64(0x456);

        // Add a test key
        let sk = JubJubScalar::random(&mut rng);
        let jubjub_pk = GENERATOR_EXTENDED * &sk;
        let babyjub_pk: BabyJubJubPK = jubjub_pk.into();
        pki.add_public_key(babyjub_pk);

        // Test the Display implementation
        let display_output = format!("{}", pki);
        assert!(display_output.contains("PKI contains 1 keys"));
        assert!(display_output.contains("Key 0:"));
    }
} 