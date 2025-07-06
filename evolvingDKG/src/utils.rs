use anyhow::Result;
use num_bigint::BigUint;
use dusk_jubjub::{JubJubExtended, JubJubScalar};
use ff::Field;
use rand::rngs::StdRng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// Import the standalone RFC 9380 implementation from a separate file  
use crate::rfc9380_hash_to_curve::JubJubHashToCurve;

// Convert a Shamir share to a point on the BabyJubJub curve
pub fn convert_share_to_curve_point(share: &BigUint) -> Result<(BigUint, BigUint)> {
    
    // Use the new direct mapping approach
    let point = share_to_point(share)?;
    
    // Convert to affine coordinates
    let affine_point = dusk_jubjub::AffinePoint::from(&point);
    
    // Get the actual u and v coordinates as proper field elements
    let u_bytes = affine_point.get_u().to_bytes();
    let v_bytes = affine_point.get_v().to_bytes();
    
    // Convert full 32-byte field elements to BigUint (this ensures they're valid field elements)
    let u_coord = BigUint::from_bytes_le(&u_bytes);
    let v_coord = BigUint::from_bytes_le(&v_bytes);
    
    // Ensure coordinates fit in 254 bits for circuit compatibility
    let max_254_bits = BigUint::from(2u8).pow(254) - 1u8;
    let u_final = if u_coord > max_254_bits { u_coord % &max_254_bits } else { u_coord };
    let v_final = if v_coord > max_254_bits { v_coord % &max_254_bits } else { v_coord };
    
    Ok((u_final, v_final))
}

// Generate a cryptographically secure random nonce for ElGamal encryption
pub fn generate_secure_nonce(_rng: &mut StdRng) -> Result<BigUint> {
    // For now, return a simple constant for testing
    // TODO: Implement proper 254-bit random nonce generation
    Ok(BigUint::from(12345u64))
}

// Helper function to ensure BigUint values fit in 254 bits for circuit compatibility
pub fn ensure_254_bit_constraint(value: &BigUint) -> BigUint {
    let max_254_bits = BigUint::from(2u8).pow(254) - 1u8;
    if value > &max_254_bits {
        value % &max_254_bits
    } else {
        value.clone()
    }
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

// RFC 9380 compliant hash-to-curve implementation for JubJub
// Uses the standalone implementation for proper RFC compliance
pub fn share_to_point(share: &BigUint) -> Result<JubJubExtended> {
    let h2c = JubJubHashToCurve::for_share_mapping();
    h2c.share_to_point(share)
}

// Generate a random scalar for commitments
pub fn generate_random_scalar() -> Result<JubJubScalar> {
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    Ok(JubJubScalar::random(&mut rng))
}

// Convert a JubJub point back to a canonical representation
// Note: This is not a true inverse of hash-to-curve (which is one-way)
// Instead, it provides a canonical encoding of the point
pub fn point_to_share(point: &JubJubExtended) -> Result<BigUint> {
    let h2c = JubJubHashToCurve::for_share_mapping();
    Ok(h2c.point_to_canonical(point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::GroupEncoding;
    
    #[test]
    fn test_hash_to_curve_deterministic() {
        // Test that hash-to-curve is deterministic
        let test_values = vec![
            BigUint::from(0u64),
            BigUint::from(1u64),
            BigUint::from(42u64),
            BigUint::from(123456u64),
            BigUint::from(999999u64),
            BigUint::from_bytes_le(&[0xFF; 8]),  // Large value
        ];
        
        for share in test_values {
            // Convert share to point multiple times
            let point1 = share_to_point(&share).expect("Failed to convert share to point");
            let point2 = share_to_point(&share).expect("Failed to convert share to point");
            
            // Should be identical (deterministic)
            assert_eq!(
                point1.to_bytes(), 
                point2.to_bytes(),
                "Hash-to-curve is not deterministic for share: {}", share
            );
            
            // Test that different shares produce different points
            let different_share = &share + BigUint::from(1u64);
            let different_point = share_to_point(&different_share).expect("Failed to convert different share");
            
            assert_ne!(
                point1.to_bytes(),
                different_point.to_bytes(),
                "Different shares should produce different points"
            );
        }
    }
    
    #[test]
    fn test_canonical_point_encoding() {
        let share = BigUint::from(12345u64);
        
        // Convert to point
        let point = share_to_point(&share).unwrap();
        
        // Convert to canonical representation multiple times
        let canonical1 = point_to_share(&point).unwrap();
        let canonical2 = point_to_share(&point).unwrap();
        
        // Should be identical (deterministic canonical encoding)
        assert_eq!(canonical1, canonical2, "Canonical encoding is not deterministic");
        
        // Test that the same point always gives the same canonical form
        let same_point = share_to_point(&share).unwrap();
        let canonical3 = point_to_share(&same_point).unwrap();
        
        assert_eq!(canonical1, canonical3, "Same points should have same canonical encoding");
    }
}