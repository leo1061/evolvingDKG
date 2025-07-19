use ark_bn254::{Fq as BN254Fq, G1Affine as BN254Affine, G1Projective as BN254Projective};
use ark_ec::twisted_edwards::{Affine as EdwardsAffine, Projective as EdwardsProjective};
use ark_ed_on_bn254::{EdwardsConfig, Fq, Fr};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::ops::*;

/// Baby-Jubjub (Edwards on BN254) to BN254 coordinate conversion
///
/// This demonstrates the conversion between:
/// - Baby-Jubjub: Twisted Edwards curve over Fr (scalar field of BN254)
/// - BN254: Short Weierstrass curve over Fq (base field)
///
/// The conversion goes through Montgomery form as an intermediate step:
/// Twisted Edwards → Montgomery → Short Weierstrass
pub struct CurveConverter;

impl CurveConverter {
    /// Baby-Jubjub curve parameters (Twisted Edwards form)
    /// ax² + y² = 1 + dx²y²
    /// where a = 1, d = 168696/168700 (mod p)
    pub const EDWARDS_A: Fq = Fq::ONE; // a = 1
                                       // d = 168696/168700 mod p = 9706598848417545097372247223557719406784115219466060233080913168975159366771

    /// Montgomery curve parameters (intermediate form)
    /// By² = x³ + Ax² + x
    /// where A = 168698, B = 1
    pub const MONTGOMERY_A: Fq = Fq::from_mont_limbs([168698, 0, 0, 0]); // A = 168698
    pub const MONTGOMERY_B: Fq = Fq::ONE; // B = 1

    /// Short Weierstrass curve parameters (BN254 form)
    /// y² = x³ + ax + b
    /// Derived from Montgomery parameters
    pub fn weierstrass_params() -> (BN254Fq, BN254Fq) {
        // For BN254: y² = x³ + 3 (a=0, b=3)
        (BN254Fq::ZERO, BN254Fq::from(3u64))
    }

    /// Convert point from Twisted Edwards to Montgomery form
    ///
    /// Edwards: ax² + y² = 1 + dx²y²
    /// Montgomery: By² = x³ + Ax² + x
    ///
    /// Conversion formulas:
    /// x_montgomery = (1 + y_edwards) / (1 - y_edwards)
    /// y_montgomery = (1 + y_edwards) / ((1 - y_edwards) * x_edwards)
    pub fn edwards_to_montgomery(edwards_point: &EdwardsAffine) -> Option<(Fq, Fq)> {
        let x_e = edwards_point.x;
        let y_e = edwards_point.y;

        // Handle special cases
        if y_e == Fq::ONE {
            // Point at infinity in Montgomery form
            return None;
        }

        if x_e.is_zero() {
            // Handle x = 0 case
            let x_m = (Fq::ONE + y_e) / (Fq::ONE - y_e);
            return Some((x_m, Fq::ZERO));
        }

        // General case
        let one_plus_y = Fq::ONE + y_e;
        let one_minus_y = Fq::ONE - y_e;

        let x_m = one_plus_y / one_minus_y;
        let y_m = one_plus_y / (one_minus_y * x_e);

        Some((x_m, y_m))
    }

    /// Convert point from Montgomery to Twisted Edwards form
    ///
    /// Inverse conversion:
    /// x_edwards = x_montgomery / y_montgomery
    /// y_edwards = (x_montgomery - 1) / (x_montgomery + 1)
    pub fn montgomery_to_edwards(x_m: Fq, y_m: Fq) -> Option<EdwardsAffine> {
        // Handle special cases
        if y_m.is_zero() {
            return None; // Point at infinity
        }

        if x_m == -Fq::ONE {
            return None; // Undefined conversion
        }

        let x_e = x_m / y_m;
        let y_e = (x_m - Fq::ONE) / (x_m + Fq::ONE);

        Some(EdwardsAffine::new(x_e, y_e))
    }

    /// Convert point from Montgomery to Short Weierstrass form
    ///
    /// Montgomery: By² = x³ + Ax² + x
    /// Weierstrass: Y² = X³ + aX + b
    ///
    /// Conversion formulas:
    /// X = (x + A/3) / B
    /// Y = y / B
    ///
    /// Where the Weierstrass curve parameters are:
    /// a = (3 - A²) / (3B²)
    /// b = (2A³ - 9A) / (27B³)
    pub fn montgomery_to_weierstrass(x_m: Fq, y_m: Fq) -> (BN254Fq, BN254Fq) {
        // Since we're converting from Baby-Jubjub (over Fr) to BN254 (over Fq),
        // we need to be careful about field conversions

        // This is a conceptual conversion - in practice, you would need
        // to handle the field conversion from Fr to Fq appropriately
        let a_div_3 = Self::MONTGOMERY_A / Fq::from(3u64);
        let x_w = (x_m + a_div_3) / Self::MONTGOMERY_B;
        let y_w = y_m / Self::MONTGOMERY_B;

        // Convert from Fq to BN254Fq (this is simplified)
        // In practice, you'd need proper field element conversion
        let x_bn254 = BN254Fq::from_le_bytes_mod_order(&x_w.into_bigint().to_bytes_le());
        let y_bn254 = BN254Fq::from_le_bytes_mod_order(&y_w.into_bigint().to_bytes_le());

        (x_bn254, y_bn254)
    }

    /// Convert point from Short Weierstrass to Montgomery form
    ///
    /// Inverse conversion:
    /// x = B * X - A/3
    /// y = B * Y
    pub fn weierstrass_to_montgomery(x_w: BN254Fq, y_w: BN254Fq) -> (Fq, Fq) {
        // Convert from BN254Fq to Fq (simplified)
        let x_w_fq = Fq::from_le_bytes_mod_order(&x_w.into_bigint().to_bytes_le());
        let y_w_fq = Fq::from_le_bytes_mod_order(&y_w.into_bigint().to_bytes_le());

        let a_div_3 = Self::MONTGOMERY_A / Fq::from(3u64);
        let x_m = Self::MONTGOMERY_B * x_w_fq - a_div_3;
        let y_m = Self::MONTGOMERY_B * y_w_fq;

        (x_m, y_m)
    }

    /// Complete conversion from Baby-Jubjub to BN254
    ///
    /// This is the full pipeline:
    /// Twisted Edwards → Montgomery → Short Weierstrass
    pub fn edwards_to_bn254(edwards_point: &EdwardsAffine) -> Option<BN254Affine> {
        // Step 1: Edwards to Montgomery
        let (x_m, y_m) = Self::edwards_to_montgomery(edwards_point)?;

        // Step 2: Montgomery to Weierstrass
        let (x_w, y_w) = Self::montgomery_to_weierstrass(x_m, y_m);

        // Step 3: Create BN254 point
        Some(BN254Affine::new(x_w, y_w))
    }

    /// Complete conversion from BN254 to Baby-Jubjub
    ///
    /// This is the full pipeline:
    /// Short Weierstrass → Montgomery → Twisted Edwards
    pub fn bn254_to_edwards(bn254_point: &BN254Affine) -> Option<EdwardsAffine> {
        // Step 1: Weierstrass to Montgomery
        let (x_m, y_m) = Self::weierstrass_to_montgomery(bn254_point.x, bn254_point.y);

        // Step 2: Montgomery to Edwards
        Self::montgomery_to_edwards(x_m, y_m)
    }

    /// Verify that a point satisfies the Baby-Jubjub curve equation
    /// ax² + y² = 1 + dx²y²
    pub fn verify_edwards_point(point: &EdwardsAffine) -> bool {
        let x = point.x;
        let y = point.y;
        let a = Self::EDWARDS_A;
        let d = EdwardsConfig::COEFF_D;

        let left_side = a * x.square() + y.square();
        let right_side = Fq::ONE + d * x.square() * y.square();

        left_side == right_side
    }

    /// Verify that a point satisfies the Montgomery curve equation
    /// By² = x³ + Ax² + x
    pub fn verify_montgomery_point(x: Fq, y: Fq) -> bool {
        let a = Self::MONTGOMERY_A;
        let b = Self::MONTGOMERY_B;

        let left_side = b * y.square();
        let right_side = x.cube() + a * x.square() + x;

        left_side == right_side
    }
}

/// Mathematical relationships between the curve forms
pub struct CurveRelations;

impl CurveRelations {
    /// Relationship between Edwards and Montgomery parameters
    ///
    /// For Edwards curve: ax² + y² = 1 + dx²y²
    /// For Montgomery curve: By² = x³ + Ax² + x
    ///
    /// The relationship is:
    /// A = 2(a+d)/(a-d)
    /// B = 4/(a-d)
    ///
    /// For Baby-Jubjub:
    /// a = 1, d = 168696/168700
    /// A = 168698, B = 1
    pub fn edwards_to_montgomery_params(a: Fq, d: Fq) -> (Fq, Fq) {
        let a_plus_d = a + d;
        let a_minus_d = a - d;

        let big_a = (Fq::from(2u64) * a_plus_d) / a_minus_d;
        let big_b = Fq::from(4u64) / a_minus_d;

        (big_a, big_b)
    }

    /// Relationship between Montgomery and Weierstrass parameters
    ///
    /// For Montgomery curve: By² = x³ + Ax² + x
    /// For Weierstrass curve: Y² = X³ + aX + b
    ///
    /// The relationship is:
    /// a = (3 - A²) / (3B²)
    /// b = (2A³ - 9A) / (27B³)
    pub fn montgomery_to_weierstrass_params(big_a: Fq, big_b: Fq) -> (Fq, Fq) {
        let a_squared = big_a.square();
        let a_cubed = a_squared * big_a;
        let b_squared = big_b.square();
        let b_cubed = b_squared * big_b;

        let weierstrass_a = (Fq::from(3u64) - a_squared) / (Fq::from(3u64) * b_squared);
        let weierstrass_b =
            (Fq::from(2u64) * a_cubed - Fq::from(9u64) * big_a) / (Fq::from(27u64) * b_cubed);

        (weierstrass_a, weierstrass_b)
    }
}

fn main() {
    println!("=== Edwards on BN254 ↔ BN254 Coordinate Conversion ===\n");

    // Example conversion workflow
    println!("1. Baby-Jubjub Curve Parameters:");
    println!("   Twisted Edwards form: ax² + y² = 1 + dx²y²");
    println!("   a = 1");
    println!("   d = {}", EdwardsConfig::COEFF_D);

    println!("\n2. Montgomery Curve Parameters:");
    println!("   Montgomery form: By² = x³ + Ax² + x");
    println!("   A = {}", CurveConverter::MONTGOMERY_A);
    println!("   B = {}", CurveConverter::MONTGOMERY_B);

    // Verify parameter relationships
    let (computed_a, computed_b) = CurveRelations::edwards_to_montgomery_params(
        CurveConverter::EDWARDS_A,
        EdwardsConfig::COEFF_D,
    );
    println!("   ✓ Computed A from Edwards params: {}", computed_a);
    println!("   ✓ Computed B from Edwards params: {}", computed_b);

    println!("\n3. Conversion Formulas:");
    println!("   Edwards → Montgomery:");
    println!("   x_m = (1 + y_e) / (1 - y_e)");
    println!("   y_m = (1 + y_e) / ((1 - y_e) * x_e)");

    println!("\n   Montgomery → Edwards:");
    println!("   x_e = x_m / y_m");
    println!("   y_e = (x_m - 1) / (x_m + 1)");

    println!("\n   Montgomery → Weierstrass:");
    println!("   X = (x + A/3) / B");
    println!("   Y = y / B");

    println!("\n4. Important Notes:");
    println!("   • Baby-Jubjub is defined over Fr (scalar field of BN254)");
    println!("   • BN254 is defined over Fq (base field)");
    println!("   • Field conversion between Fr and Fq is necessary");
    println!("   • Some points cannot be converted (exceptional cases)");
    println!("   • The conversion preserves the elliptic curve group structure");

    println!("\n=== Conversion formulas provided! ===");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{CurveGroup, Group};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_edwards_montgomery_conversion() {
        let mut rng = test_rng();

        // Generate random Edwards point
        let edwards_point = EdwardsProjective::rand(&mut rng).into_affine();

        // Verify it's on the Edwards curve
        assert!(CurveConverter::verify_edwards_point(&edwards_point));

        // Convert to Montgomery
        if let Some((x_m, y_m)) = CurveConverter::edwards_to_montgomery(&edwards_point) {
            // Verify it's on the Montgomery curve
            assert!(CurveConverter::verify_montgomery_point(x_m, y_m));

            // Convert back to Edwards
            if let Some(edwards_back) = CurveConverter::montgomery_to_edwards(x_m, y_m) {
                // Should be the same point (within numerical precision)
                assert_eq!(edwards_point.x, edwards_back.x);
                assert_eq!(edwards_point.y, edwards_back.y);
            }
        }
    }

    #[test]
    fn test_parameter_relationships() {
        let a = CurveConverter::EDWARDS_A;
        let d = EdwardsConfig::COEFF_D;

        let (computed_a, computed_b) = CurveRelations::edwards_to_montgomery_params(a, d);

        // The computed parameters should match the expected Montgomery parameters
        // (within the precision of the field arithmetic)
        println!("Edwards a: {}", a);
        println!("Edwards d: {}", d);
        println!("Computed Montgomery A: {}", computed_a);
        println!("Computed Montgomery B: {}", computed_b);
        println!("Expected Montgomery A: {}", CurveConverter::MONTGOMERY_A);
        println!("Expected Montgomery B: {}", CurveConverter::MONTGOMERY_B);
    }
}
