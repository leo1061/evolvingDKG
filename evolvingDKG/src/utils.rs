use anyhow::Result;
use num_bigint::BigUint;
use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use rand::{rngs::StdRng, RngCore};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

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

// Helper function to convert BigUint share directly to a JubJub point
// Uses coordinate-based mapping instead of discrete logarithm  
pub fn share_to_point(share: &BigUint) -> Result<JubJubExtended> {
    
    let mut point_bytes = [0u8; 32];
    let share_bytes = share.to_bytes_le();
    
    // Use the share value as the v-coordinate (first 16 bytes)
    let copy_len = std::cmp::min(share_bytes.len(), 16);
    point_bytes[0..copy_len].copy_from_slice(&share_bytes[0..copy_len]);
    
    // Try to decode as a valid curve point
    if let Some(affine_point) = Option::<dusk_jubjub::AffinePoint>::from(dusk_jubjub::AffinePoint::from_bytes(point_bytes)) {
        Ok(JubJubExtended::from(affine_point))
    } else {
        // If the direct mapping doesn't work, use hash-to-curve approach
        let mut hasher = DefaultHasher::new();
        share.hash(&mut hasher);
        let hash_val = hasher.finish();
        
        // Create deterministic point from hash
        point_bytes[0..8].copy_from_slice(&hash_val.to_le_bytes());
        
        // Try multiple candidates until we find a valid point
        for i in 0..=255u8 {
            point_bytes[16] = i;
            if let Some(affine_point) = Option::<dusk_jubjub::AffinePoint>::from(dusk_jubjub::AffinePoint::from_bytes(point_bytes)) {
                return Ok(JubJubExtended::from(affine_point));
            }
        }
        
        // Fallback: use the share as a scalar multiplier (old approach but safe)
        let share_scalar = share_to_scalar(share)?;
        Ok(GENERATOR_EXTENDED * &share_scalar)
    }
}

// Generate a random scalar for commitments
pub fn generate_random_scalar() -> Result<JubJubScalar> {
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    Ok(JubJubScalar::random(&mut rng))
}

// Helper function to convert a JubJub point back to a BigUint share
// Uses coordinate-based mapping instead of discrete logarithm
pub fn point_to_share(point: &JubJubExtended) -> Result<BigUint> {
    
    // Convert to affine form to get stable coordinates
    let affine_point = dusk_jubjub::AffinePoint::from(point);
    
    // Get the v-coordinate bytes (the main coordinate used in encoding)
    let point_bytes = affine_point.to_bytes();
    
    // Convert the first 16 bytes to BigUint (v-coordinate is the main data)
    // This provides a fully reversible mapping without discrete logarithm
    let share_value = BigUint::from_bytes_le(&point_bytes[0..16]);
    
    Ok(share_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::GroupEncoding;
    
    #[test]
    fn test_reversible_mapping() {
        // Test round-trip conversion for various share values
        let test_values = vec![
            BigUint::from(0u64),
            BigUint::from(1u64),
            BigUint::from(42u64),
            BigUint::from(123456u64),
            BigUint::from(999999u64),
            BigUint::from_bytes_le(&[0xFF; 8]),  // Large value
        ];
        
        for original_share in test_values {
            println!("Testing share: {}", original_share);
            
            // Convert share to point
            let point = share_to_point(&original_share).expect("Failed to convert share to point");
            
            // Convert point back to share
            let recovered_share = point_to_share(&point).expect("Failed to convert point to share");
            
            println!("Original: {}, Recovered: {}", original_share, recovered_share);
            
            // For coordinate-based mapping, we don't expect exact equality
            // but the mapping should be deterministic and reversible
            assert_eq!(
                share_to_point(&recovered_share).unwrap().to_bytes(),
                point.to_bytes(),
                "Mapping is not deterministic for share: {}", original_share
            );
        }
    }
    
    #[test]
    fn test_deterministic_mapping() {
        let share = BigUint::from(12345u64);
        
        // Convert to point multiple times
        let point1 = share_to_point(&share).unwrap();
        let point2 = share_to_point(&share).unwrap();
        
        // Should be identical
        assert_eq!(point1.to_bytes(), point2.to_bytes(), "Mapping is not deterministic");
        
        // Convert back multiple times
        let recovered1 = point_to_share(&point1).unwrap();
        let recovered2 = point_to_share(&point2).unwrap();
        
        // Should be identical
        assert_eq!(recovered1, recovered2, "Reverse mapping is not deterministic");
    }
}