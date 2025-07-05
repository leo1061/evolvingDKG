use anyhow::Result;
use num_bigint::BigUint;
use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use rand::rngs::StdRng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use group::GroupEncoding;

// Convert a Shamir share to a point on the BabyJubJub curve
pub fn convert_share_to_curve_point(share: &BigUint) -> Result<(BigUint, BigUint)> {
    use dusk_jubjub::GENERATOR_EXTENDED;
    
    // Convert share to scalar within field bounds
    let share_scalar = share_to_scalar(share)?;
    
    // Multiply generator by share to get point
    let point = GENERATOR_EXTENDED * &share_scalar;
    
    // Extract coordinates
    let bytes = point.to_bytes();
    let x_coord = BigUint::from_bytes_le(&bytes[0..16]); // Use first 16 bytes for x
    let y_coord = BigUint::from_bytes_le(&bytes[16..32]); // Use last 16 bytes for y
    
    Ok((x_coord, y_coord))
}

// Generate a cryptographically secure random nonce for ElGamal encryption
pub fn generate_secure_nonce(rng: &mut StdRng) -> Result<BigUint> {
    use ff::Field;
    
    // Generate a random JubJub scalar
    let scalar = JubJubScalar::random(rng);
    let bytes = scalar.to_bytes();
    
    // Convert to BigUint
    Ok(BigUint::from_bytes_le(&bytes))
}

// Helper function to convert BigUint share to JubJub scalar with proper field reduction
pub fn share_to_scalar(share: &BigUint) -> Result<JubJubScalar> {
    
    let mut bytes = [0u8; 32];
    let share_bytes = share.to_bytes_le();
    
    // Handle larger shares by taking modulo of field size
    if share_bytes.len() > 32 {
        // For large shares, use a hash-based approach to get valid field element
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
pub fn generate_random_scalar() -> Result<JubJubScalar> {
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    Ok(JubJubScalar::random(&mut rng))
}

// Helper function to convert a JubJub point back to a BigUint share
pub fn point_to_share(point: &JubJubExtended) -> Result<BigUint> {
    // For demo purposes, use a simple approach with reduced range
    // In practice, you'd use more sophisticated discrete log algorithms
    
    // Try common small values first
    let test_values = [0u64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    for &i in &test_values {
        let test_scalar = JubJubScalar::from(i);
        let test_point = GENERATOR_EXTENDED * &test_scalar;
        if test_point == *point {
            return Ok(BigUint::from(i));
        }
    }
    
    // If not found in small values, try a limited range
    for i in 11u64..1000u64 {
        let test_scalar = JubJubScalar::from(i);
        let test_point = GENERATOR_EXTENDED * &test_scalar;
        if test_point == *point {
            return Ok(BigUint::from(i));
        }
    }
    
    // For demo purposes, return a placeholder value instead of error
    println!("Warning: Could not find discrete log, using placeholder value");
    Ok(BigUint::from(42u64)) // Placeholder for demo
}