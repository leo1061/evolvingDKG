use num_bigint::BigUint;
use num_traits::{Zero, One};

/// Represents a point (x, y) for polynomial interpolation
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
}

impl Point {
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Point { x, y }
    }
}

/// Polynomial operations over finite fields
pub struct Polynomial {
    pub modulus: BigUint,
}

impl Polynomial {
    /// Create a new polynomial handler with the given field modulus
    pub fn new(modulus: BigUint) -> Self {
        Polynomial { modulus }
    }

    /// Compute modular inverse using Extended Euclidean Algorithm
    /// Returns None if the inverse doesn't exist (gcd != 1)
    pub fn mod_inverse(&self, a: &BigUint) -> Option<BigUint> {
        if a.is_zero() {
            return None;
        }

        let mut old_r = a.clone();
        let mut r = self.modulus.clone();
        let mut old_s = BigUint::one();
        let mut s = BigUint::zero();

        while !r.is_zero() {
            let quotient = &old_r / &r;
            
            let temp_r = r.clone();
            r = if &old_r >= &(&quotient * &r) {
                &old_r - &quotient * &r
            } else {
                &self.modulus - (&quotient * &r - &old_r) % &self.modulus
            };
            old_r = temp_r;

            let temp_s = s.clone();
            s = if &old_s >= &(&quotient * &s) {
                (&old_s - &quotient * &s) % &self.modulus
            } else {
                &self.modulus - (&quotient * &s - &old_s) % &self.modulus
            };
            old_s = temp_s;
        }

        if old_r == BigUint::one() {
            Some(old_s % &self.modulus)
        } else {
            None
        }
    }

    /// Modular subtraction: (a - b) mod p
    pub fn mod_sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        if a >= b {
            (a - b) % &self.modulus
        } else {
            (&self.modulus - ((b - a) % &self.modulus)) % &self.modulus
        }
    }

    /// Modular multiplication: (a * b) mod p
    pub fn mod_mul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.modulus
    }

    /// Modular addition: (a + b) mod p
    pub fn mod_add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + b) % &self.modulus
    }

    /// Evaluate polynomial at point x using Lagrange interpolation
    /// Given points (x_i, y_i), compute the polynomial value at x
    pub fn lagrange_interpolate(&self, points: &[Point], x: &BigUint) -> Option<BigUint> {
        if points.is_empty() {
            return Some(BigUint::zero());
        }

        let mut result = BigUint::zero();

        for i in 0..points.len() {
            let mut numerator = BigUint::one();
            let mut denominator = BigUint::one();

            // Compute Lagrange basis polynomial L_i(x)
            for j in 0..points.len() {
                if i != j {
                    // numerator *= (x - x_j)
                    numerator = self.mod_mul(&numerator, &self.mod_sub(x, &points[j].x));
                    
                    // denominator *= (x_i - x_j)
                    denominator = self.mod_mul(&denominator, &self.mod_sub(&points[i].x, &points[j].x));
                }
            }

            // Compute L_i(x) = numerator / denominator
            let denominator_inv = self.mod_inverse(&denominator)?;
            let basis_value = self.mod_mul(&numerator, &denominator_inv);

            // Add y_i * L_i(x) to result
            let term = self.mod_mul(&points[i].y, &basis_value);
            result = self.mod_add(&result, &term);
        }

        Some(result)
    }

    /// Evaluate polynomial at x = 0 using Lagrange interpolation
    /// This is often used to recover the secret (constant term) from shares
    pub fn lagrange_interpolate_at_zero(&self, points: &[Point]) -> Option<BigUint> {
        self.lagrange_interpolate(points, &BigUint::zero())
    }

    /// Convert Shamir shares to Points for interpolation
    /// Assumes share.index is the share index (1-based) and share.value is the y-coordinate
    pub fn shares_to_points(&self, shares: &[shamir_rs::Share]) -> Vec<Point> {
        shares.iter().map(|share| {
            Point::new(BigUint::from(share.index), share.value.clone())
        }).collect()
    }

    /// Compute Lagrange coefficients for a given set of x-coordinates at evaluation point x
    /// Returns the coefficients λ_i such that f(x) = Σ λ_i * y_i
    pub fn lagrange_coefficients(&self, x_coords: &[BigUint], eval_x: &BigUint) -> Option<Vec<BigUint>> {
        let mut coefficients = Vec::new();

        for i in 0..x_coords.len() {
            let mut numerator = BigUint::one();
            let mut denominator = BigUint::one();

            for j in 0..x_coords.len() {
                if i != j {
                    // numerator *= (eval_x - x_j)
                    numerator = self.mod_mul(&numerator, &self.mod_sub(eval_x, &x_coords[j]));
                    
                    // denominator *= (x_i - x_j)
                    denominator = self.mod_mul(&denominator, &self.mod_sub(&x_coords[i], &x_coords[j]));
                }
            }

            let denominator_inv = self.mod_inverse(&denominator)?;
            let coefficient = self.mod_mul(&numerator, &denominator_inv);
            coefficients.push(coefficient);
        }

        Some(coefficients)
    }

    /// Batch evaluate polynomial at multiple points
    pub fn batch_evaluate(&self, points: &[Point], eval_points: &[BigUint]) -> Option<Vec<BigUint>> {
        eval_points.iter()
            .map(|x| self.lagrange_interpolate(points, x))
            .collect()
    }

    /// Verify that a point lies on the polynomial defined by the given shares
    pub fn verify_point_on_polynomial(&self, shares: &[Point], test_point: &Point) -> Option<bool> {
        let expected_y = self.lagrange_interpolate(shares, &test_point.x)?;
        Some(expected_y == test_point.y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_mod_inverse() {
        let prime = BigUint::from_str("2736030358979909402780800718157159386076813972158567259200215660948447373041").unwrap();
        let poly = Polynomial::new(prime.clone());
        
        let a = BigUint::from(5u32);
        let inv = poly.mod_inverse(&a).unwrap();
        let product = poly.mod_mul(&a, &inv);
        
        assert_eq!(product, BigUint::one());
    }

    #[test]
    fn test_basic_interpolation() {
        let prime = BigUint::from(17u32); // Small prime for testing
        let poly = Polynomial::new(prime);
        
        // Test polynomial f(x) = 3x + 2 mod 17
        // f(1) = 5, f(2) = 8
        let points = vec![
            Point::new(BigUint::one(), BigUint::from(5u32)),
            Point::new(BigUint::from(2u32), BigUint::from(8u32)),
        ];
        
        // Evaluate at x = 0 (should give constant term = 2)
        let result = poly.lagrange_interpolate_at_zero(&points).unwrap();
        assert_eq!(result, BigUint::from(2u32));
        
        // Evaluate at x = 3 (should give f(3) = 3*3 + 2 = 11)
        let result_at_3 = poly.lagrange_interpolate(&points, &BigUint::from(3u32)).unwrap();
        assert_eq!(result_at_3, BigUint::from(11u32));
    }

    #[test]
    fn test_lagrange_coefficients() {
        let prime = BigUint::from(17u32);
        let poly = Polynomial::new(prime);
        
        let x_coords = vec![BigUint::one(), BigUint::from(2u32)];
        let coeffs = poly.lagrange_coefficients(&x_coords, &BigUint::zero()).unwrap();
        
        // For evaluation at x=0 with points at x=1,2:
        // λ_0 = (0-2)/(1-2) = -2/-1 = 2
        // λ_1 = (0-1)/(2-1) = -1/1 = -1 = 16 mod 17
        assert_eq!(coeffs[0], BigUint::from(2u32));
        assert_eq!(coeffs[1], BigUint::from(16u32));
    }
}   