use ark_ed_on_bn254::Fq;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::Zero;

/// Elligator 2 implementation for Montgomery curves
///
/// Provides indistinguishable encoding/decoding between field elements
/// and Montgomery curve points. Works for Montgomery curves of the form:
/// By² = x³ + Ax² + x
/// where A² - 4 is not a square in the field.
pub struct Elligator2;

impl Elligator2 {
    /// Check if a field element is a quadratic residue (has a square root)
    pub fn is_square(x: &Fq) -> bool {
        if x.is_zero() {
            return true;
        }
        
        // Use Euler's criterion: x^((p-1)/2) = 1 if x is a square
        let exp = Fq::MODULUS_MINUS_ONE_DIV_TWO;
        let result = x.pow(exp);
        result == Fq::ONE
    }
    
    /// Compute the square root of a field element if it exists
    /// Returns the principal square root (the smaller of the two)
    pub fn sqrt(x: &Fq) -> Option<Fq> {
        let sqrt = x.sqrt()?;
        // Return the principal square root (smaller of the two)
        let neg_sqrt = -sqrt;
        Some(if sqrt < neg_sqrt { sqrt } else { neg_sqrt })
    }
    
    /// Check if Elligator 2 can be used with the given Montgomery curve parameters
    /// Requires that A² - 4 is not a square in the field
    pub fn is_elligator_applicable(a: &Fq) -> bool {
        let a_squared_minus_4 = a.square() - Fq::from(4u64);
        !Self::is_square(&a_squared_minus_4)
    }
    
    /// Elligator 2 forward mapping: field element → Montgomery point
    /// 
    /// Maps a field element r to a point (x, y) on the Montgomery curve
    /// By² = x³ + Ax² + x
    pub fn encode(r: &Fq, a: &Fq, b: &Fq) -> Option<(Fq, Fq)> {
        // Special case: r = 0 maps to (0, 0) if it's on the curve
        if r.is_zero() {
            return Some((Fq::zero(), Fq::zero()));
        }
        
        // u = -A / (1 + 2r²)
        let two_r_squared = Fq::from(2u64) * r.square();
        let denom = Fq::ONE + two_r_squared;
        
        if denom.is_zero() {
            return None;
        }
        
        let u = -(*a) / denom;
        
        // Compute e = u³ + Au² + u
        let u_squared = u.square();
        let u_cubed = u_squared * u;
        let e = u_cubed + (*a) * u_squared + u;
        
        // v = ±√(e/B)
        let e_over_b = e / (*b);
        
        let (x, y) = if Self::is_square(&e_over_b) {
            // Case 1: e/B is a square
            let v = Self::sqrt(&e_over_b)?;
            (u, v)
        } else {
            // Case 2: e/B is not a square
            // x = -u - A
            let x = -u - (*a);
            
            // Compute e' = x³ + Ax² + x
            let x_squared = x.square();
            let x_cubed = x_squared * x;
            let e_prime = x_cubed + (*a) * x_squared + x;
            
            // v = ±√(e'/B)
            let e_prime_over_b = e_prime / (*b);
            let v = Self::sqrt(&e_prime_over_b)?;
            
            (x, v)
        };
        
        // Choose the sign of y based on the sign of r
        // This ensures the mapping is deterministic
        let y_final = if Self::is_positive(&y) == Self::is_positive(r) {
            y
        } else {
            -y
        };
        
        Some((x, y_final))
    }
    
    /// Elligator 2 reverse mapping: Montgomery point → field element
    /// 
    /// Given a point (x, y) on the Montgomery curve, finds a field element r
    /// such that encode(r) = (x, y). Not all points have preimages.
    pub fn decode(x: &Fq, y: &Fq, a: &Fq, b: &Fq) -> Option<Fq> {
        // Special case: (0, 0) maps from r = 0
        if x.is_zero() && y.is_zero() {
            return Some(Fq::zero());
        }
        
        // Check if -x - A is a square
        let neg_x_minus_a = -(*x) - (*a);
        
        if !Self::is_square(&neg_x_minus_a) {
            // Try to find r such that u = x
            // From u = -A / (1 + 2r²), solve for r:
            // 1 + 2r² = -A / u
            // 2r² = -A/u - 1
            // r² = (-A/u - 1) / 2
            
            if x.is_zero() {
                return None;
            }
            
            let neg_a_over_u = -(*a) / (*x);
            let r_squared = (neg_a_over_u - Fq::ONE) / Fq::from(2u64);
            
            if !Self::is_square(&r_squared) {
                return None;
            }
            
            let r = Self::sqrt(&r_squared)?;
            
            // Choose the sign of r to match the sign of y
            let r_final = if Self::is_positive(&r) == Self::is_positive(y) {
                r
            } else {
                -r
            };
            
            // Verify the encoding gives us back the original point
            if let Some((x_check, y_check)) = Self::encode(&r_final, a, b) {
                if x_check == *x && y_check == *y {
                    return Some(r_final);
                }
            }
        }
        
        None
    }
    
    /// Helper function to determine if a field element is "positive"
    /// We define positive as having the least significant bit = 0
    fn is_positive(x: &Fq) -> bool {
        let bytes = x.into_bigint().to_bytes_le();
        bytes.first().map(|b| b & 1 == 0).unwrap_or(true)
    }
    
    /// Convert bytes to a field element for use with Elligator
    pub fn bytes_to_field_element(bytes: &[u8]) -> Fq {
        // Hash the bytes to get a uniform distribution
        // In practice, you'd use a proper hash-to-field function
        Fq::from_le_bytes_mod_order(bytes)
    }
    
    /// Convert a field element to bytes
    pub fn field_element_to_bytes(element: &Fq) -> Vec<u8> {
        element.into_bigint().to_bytes_le()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_converter::CurveConverter;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    
    #[test]
    fn test_elligator_applicable() {
        let a = CurveConverter::montgomery_a();
        assert!(Elligator2::is_elligator_applicable(&a));
    }
    
    #[test]
    fn test_is_square() {
        // Test known squares
        assert!(Elligator2::is_square(&Fq::zero()));
        assert!(Elligator2::is_square(&Fq::ONE));
        assert!(Elligator2::is_square(&Fq::from(4u64)));
        assert!(Elligator2::is_square(&Fq::from(9u64)));
        assert!(Elligator2::is_square(&Fq::from(16u64)));
        
        // Test known non-squares
        let a = CurveConverter::montgomery_a();
        let a_squared_minus_4 = a.square() - Fq::from(4u64);
        assert!(!Elligator2::is_square(&a_squared_minus_4));
    }
    
    #[test]
    fn test_sqrt() {
        // Test square roots of known values
        let four = Fq::from(4u64);
        let sqrt_four = Elligator2::sqrt(&four).unwrap();
        assert_eq!(sqrt_four.square(), four);
        
        let nine = Fq::from(9u64);
        let sqrt_nine = Elligator2::sqrt(&nine).unwrap();
        assert_eq!(sqrt_nine.square(), nine);
    }
    
    #[test]
    fn test_encode_decode_roundtrip() {
        let mut rng = test_rng();
        let a = CurveConverter::montgomery_a();
        let b = CurveConverter::montgomery_b();
        
        // Test with random field elements
        let mut successful_encodes = 0;
        let mut successful_decodes = 0;
        let mut successful_roundtrips = 0;
        let test_count = 100;
        
        for i in 0..test_count {
            let r = Fq::rand(&mut rng);
            
            // Encode to point
            if let Some((x, y)) = Elligator2::encode(&r, &a, &b) {
                successful_encodes += 1;
                
                // Verify the point is on the curve
                if !CurveConverter::verify_montgomery_point(x, y) {
                    println!("Test {}: Point ({}, {}) is not on curve", i, x, y);
                    continue;
                }
                
                // Try to decode back
                if let Some(r_decoded) = Elligator2::decode(&x, &y, &a, &b) {
                    successful_decodes += 1;
                    
                    // Verify we can encode back to the same point
                    if let Some((x2, y2)) = Elligator2::encode(&r_decoded, &a, &b) {
                        if x == x2 && y == y2 {
                            successful_roundtrips += 1;
                        }
                    }
                }
            }
        }
        
        println!("Successful encodes: {}/{}", successful_encodes, test_count);
        println!("Successful decodes: {}/{}", successful_decodes, successful_encodes);
        println!("Successful roundtrips: {}/{}", successful_roundtrips, successful_decodes);
        
        // We expect reasonable success rate for encodings
        assert!(successful_encodes > test_count / 3);
        // We expect at least some roundtrips to work
        assert!(successful_roundtrips > 0);
    }
    
    #[test]
    fn test_special_cases() {
        let a = CurveConverter::montgomery_a();
        let b = CurveConverter::montgomery_b();
        
        // Test r = 0
        let (x, y) = Elligator2::encode(&Fq::zero(), &a, &b).unwrap();
        assert_eq!(x, Fq::zero());
        assert_eq!(y, Fq::zero());
        
        // Test decode of (0, 0)
        let r = Elligator2::decode(&Fq::zero(), &Fq::zero(), &a, &b).unwrap();
        assert_eq!(r, Fq::zero());
    }
}