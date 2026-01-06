use num_bigint::BigUint;
use num_traits::{Zero, One};
use rand::Rng;
use std::collections::HashMap;
use std::str::FromStr;

// Import the polynomial module
use evolvingDKG::polynomial::{Polynomial, Point};

// Prime modulus for the finite field (BN254 scalar field)
const PRIME: &str = "2736030358979909402780800718157159386076813972158567259200215660948447373041";

fn main() {
    println!("=== Two-Phase DKG Example (Corrected) ===\n");
    
    let prime = BigUint::from_str(PRIME).unwrap();
    let poly = Polynomial::new(prime.clone());
    
    // Phase 1: 5 parties with threshold 3
    let phase1_key = phase1(&poly, &prime);
    
    println!("\n");
    
    // Phase 2: 4 new parties with threshold 4, reusing shares from Phase 1
    phase2(&poly, &prime, phase1_key);
}

fn phase1(poly: &Polynomial, prime: &BigUint) -> BigUint {
    println!("=== PHASE 1 ===");
    println!("Creating 5 parties (P1...P5) with threshold 3 (polynomial degree 2)");
    
    let mut rng = rand::thread_rng();
    let num_parties = 5;
    let threshold = 3;
    
    // Step 1: Each party Pi creates a secret polynomial fi(x) of degree t-1
    // where fi(0) = si is their secret
    let mut party_polynomials = Vec::new();
    
    println!("\nStep 1: Each party creates a random polynomial of degree {}:", threshold - 1);
    for i in 1..=num_parties {
        // Create random polynomial coefficients
        let mut coeffs = Vec::new();
        for j in 0..threshold {
            let coeff = BigUint::from(rng.gen_range(1..1000000u64));
            coeffs.push(coeff.clone());
            if j == 0 {
                println!("  P{} secret (f{}(0)) = {}", i, i, coeff);
            }
        }
        party_polynomials.push(coeffs);
    }
    
    // Step 2: Each party Pi evaluates their polynomial at j to create shares sij = fi(j)
    let mut shares: HashMap<(usize, usize), BigUint> = HashMap::new();
    
    println!("\nStep 2: Each party evaluates their polynomial at points 1..{}:", num_parties);
    for i in 1..=num_parties {
        let coeffs = &party_polynomials[i-1];
        
        for j in 1..=num_parties {
            // Evaluate polynomial at point j
            let mut value = BigUint::zero();
            let mut x_power = BigUint::one();
            let x = BigUint::from(j as u32);
            
            for coeff in coeffs {
                value = poly.mod_add(&value, &poly.mod_mul(coeff, &x_power));
                x_power = poly.mod_mul(&x_power, &x);
            }
            
            shares.insert((i, j), value.clone());
            if j <= 3 || j == num_parties { // Show first few and last
                println!("  s{}{} = f{}({}) = {}", i, j, i, j, value);
            }
        }
    }
    
    // Step 3: Each party Pj receives sij from all Pi and computes Sj = sum_i(sij)
    let mut aggregated_shares = Vec::new();
    
    println!("\nStep 3: Each party aggregates received shares:");
    for j in 1..=num_parties {
        let mut sum_j = BigUint::zero();
        
        for i in 1..=num_parties {
            let share_ij = shares.get(&(i, j)).unwrap();
            sum_j = poly.mod_add(&sum_j, share_ij);
        }
        
        println!("  P{}: S{} = sum(s_i{}) = {}", j, j, j, sum_j);
        aggregated_shares.push(sum_j);
    }
    
    // Step 4: Use shares from P2, P3, P5 to reconstruct the secret
    let selected_parties = vec![2, 3, 5];
    let mut points = Vec::new();
    
    println!("\nStep 4: Using shares from parties {:?} for reconstruction:", selected_parties);
    for &party in &selected_parties {
        let point = Point::new(
            BigUint::from(party as u32),
            aggregated_shares[party-1].clone()
        );
        points.push(point);
    }
    
    let aggregated_key = poly.lagrange_interpolate_at_zero(&points).unwrap();
    println!("\nAggregated private key (f(0)) = {}", aggregated_key);
    
    // Verify: The aggregated key should equal the sum of all original secrets
    let expected_sum = party_polynomials.iter()
        .map(|coeffs| coeffs[0].clone())
        .fold(BigUint::zero(), |acc, s| poly.mod_add(&acc, &s));
    println!("Expected sum of all secrets = {}", expected_sum);
    println!("Verification: {} (should be true)", aggregated_key == expected_sum);
    
    // Store aggregated shares for Phase 2 demonstration
    std::fs::write("phase1_shares.json", serde_json::to_string(&vec![
        aggregated_shares[0].to_string(),
        aggregated_shares[2].to_string(), 
        aggregated_shares[3].to_string()
    ]).unwrap()).unwrap();
    
    aggregated_key
}

fn phase2(poly: &Polynomial, _prime: &BigUint, expected_key: BigUint) {
    println!("=== PHASE 2 ===");
    println!("Resharing to 4 new parties (P6...P9) with threshold 4 (polynomial degree 3)");
    
    // Read shares from Phase 1
    let phase1_data: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string("phase1_shares.json").unwrap()
    ).unwrap();
    
    let s1 = BigUint::from_str(&phase1_data[0]).unwrap();
    let s3 = BigUint::from_str(&phase1_data[1]).unwrap();
    let s4 = BigUint::from_str(&phase1_data[2]).unwrap();
    
    println!("\nRetrieved shares from Phase 1:");
    println!("  S1 = {}", s1);
    println!("  S3 = {}", s3);
    println!("  S4 = {}", s4);
    
    // First verify we can reconstruct the original secret from these shares
    let old_points = vec![
        Point::new(BigUint::from(1u32), s1.clone()),
        Point::new(BigUint::from(3u32), s3.clone()),
        Point::new(BigUint::from(4u32), s4.clone()),
    ];
    
    let reconstructed = poly.lagrange_interpolate_at_zero(&old_points).unwrap();
    println!("\nVerifying reconstruction from old shares: {}", reconstructed);
    println!("Matches expected: {}", reconstructed == expected_key);
    
    // Now each old party creates new Shamir shares for parties 6-9
    println!("\nPhase 2 resharing process:");
    
    let mut rng = rand::thread_rng();
    let new_threshold = 4;
    let new_parties = vec![6, 7, 8, 9];
    let old_parties = vec![(1, s1.clone()), (3, s3.clone()), (4, s4.clone())];
    
    // Store shares that each new party receives
    let mut new_party_shares: HashMap<usize, Vec<BigUint>> = HashMap::new();
    for &party_id in &new_parties {
        new_party_shares.insert(party_id, Vec::new());
    }
    
    // Each old party creates a polynomial with their share as the constant term
    for (old_party_id, old_share) in &old_parties {
        println!("\nP{} creates new polynomial with S{} as secret:", old_party_id, old_party_id);
        
        // Create polynomial of degree 3 (threshold-1) with old_share as constant term
        let mut coeffs = vec![old_share.clone()];
        for _ in 1..new_threshold {
            coeffs.push(BigUint::from(rng.gen_range(1..1000000u64)));
        }
        
        // Evaluate at points 6, 7, 8, 9 for new parties
        for &new_party_id in &new_parties {
            let x = BigUint::from(new_party_id as u32);
            let mut value = BigUint::zero();
            let mut x_power = BigUint::one();
            
            for coeff in &coeffs {
                value = poly.mod_add(&value, &poly.mod_mul(coeff, &x_power));
                x_power = poly.mod_mul(&x_power, &x);
            }
            
            println!("  S{}{} = {}", old_party_id, new_party_id, value);
            new_party_shares.get_mut(&new_party_id).unwrap().push(value);
        }
    }
    
    // Each new party sums the shares they received
    println!("\nNew parties aggregate their received shares:");
    let mut new_aggregated_shares = Vec::new();
    
    for &party_id in &new_parties {
        let shares = new_party_shares.get(&party_id).unwrap();
        let sum = shares.iter().fold(BigUint::zero(), |acc, s| poly.mod_add(&acc, s));
        println!("  P{}: S{} = sum of received shares = {}", party_id, party_id, sum);
        new_aggregated_shares.push((party_id, sum));
    }
    
    // Now use all 4 new shares to reconstruct
    println!("\nUsing all 4 new shares for reconstruction:");
    let new_points: Vec<Point> = new_aggregated_shares.iter()
        .map(|(party_id, share)| Point::new(BigUint::from(*party_id as u32), share.clone()))
        .collect();
    
    let new_aggregated_key = poly.lagrange_interpolate_at_zero(&new_points).unwrap();
    println!("\nNew aggregated private key (f(0)) = {}", new_aggregated_key);
    
    // The new key should equal the sum of the old shares used for resharing
    let old_shares_sum = vec![&s1, &s3, &s4].iter()
        .fold(BigUint::zero(), |acc, s| poly.mod_add(&acc, s));
    println!("Sum of old shares (S1 + S3 + S4) = {}", old_shares_sum);
    println!("Original aggregated key = {}", expected_key);
    
    println!("\nVerification: new key matches sum of old shares: {}", new_aggregated_key == old_shares_sum);

    
    // Clean up
    std::fs::remove_file("phase1_shares.json").ok();
}