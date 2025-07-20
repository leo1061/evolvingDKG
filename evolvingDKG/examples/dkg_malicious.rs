use num_bigint::BigUint;
use num_traits::{Zero, One};
use rand::Rng;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::str::FromStr;
use ark_ed_on_bn254::Fq;
use ark_ff::PrimeField;

// Import the polynomial module and Elligator
use evolvingDKG::polynomial::{Polynomial, Point};
use evolvingDKG::curve_converter::{CurveConverter, Elligator2};

// Prime modulus for the finite field (BN254 scalar field)
const PRIME: &str = "2736030358979909402780800718157159386076813972158567259200215660948447373041";

// Configuration parameters
const PHASE1_PARTIES: usize = 5;
const PHASE1_THRESHOLD: usize = 3;
const PHASE2_PARTIES: usize = 6;
const PHASE2_THRESHOLD: usize = 4;
const MAX_ELLIGATOR_ATTEMPTS: usize = 20_000;

fn main() {
    println!("=== Malicious-Secure DKG Example (Step 1: Elligator-Compatible Shares) ===\n");
    println!("Phase 1: {} parties, threshold {}", PHASE1_PARTIES, PHASE1_THRESHOLD);
    println!("Phase 2: {} new parties, threshold {}", PHASE2_PARTIES, PHASE2_THRESHOLD);
    
    let prime = BigUint::from_str(PRIME).unwrap();
    let poly = Polynomial::new(prime.clone());
    
    // Get Montgomery curve parameters for Elligator
    let mont_a = CurveConverter::montgomery_a();
    let mont_b = CurveConverter::montgomery_b();
    
    // Verify Elligator is applicable
    if !Elligator2::is_elligator_applicable(&mont_a) {
        panic!("Elligator2 is not applicable to this curve!");
    }
    
    println!("\nElligator2 is applicable to the Montgomery curve");
    
    // Phase 1: Initial DKG with Elligator-compatible shares
    let (phase1_key, all_shares) = phase1(&poly, &prime, &mont_a, &mont_b);
    
    println!("\n{}\n", "=".repeat(60));
    
    // Phase 2: Resharing with Elligator-compatible shares
    phase2(&poly, &prime, phase1_key, all_shares, &mont_a, &mont_b);
}

/// Generate Elligator-compatible Shamir shares
/// Returns None if unable to generate compatible shares within MAX_ELLIGATOR_ATTEMPTS
fn generate_elligator_compatible_shares(
    poly: &Polynomial,
    secret: &BigUint,
    num_shares: usize,
    threshold: usize,
    mont_a: &Fq,
    mont_b: &Fq,
    prime: &BigUint,
) -> Option<Vec<(usize, BigUint)>> {
    let mut rng = rand::thread_rng();
    let mut attempts = 0;
    
    while attempts < MAX_ELLIGATOR_ATTEMPTS {
        attempts += 1;
        
        // Generate polynomial coefficients
        let mut coeffs = vec![secret.clone()];
        for _ in 1..threshold {
            coeffs.push(BigUint::from(rng.gen_range(1..1000000u64)));
        }
        
        // Evaluate polynomial at each point to create shares
        let mut shares = Vec::new();
        let mut all_elligator_compatible = true;
        
        for j in 1..=num_shares {
            let mut value = BigUint::zero();
            let mut x_power = BigUint::one();
            let x = BigUint::from(j as u32);
            
            for coeff in &coeffs {
                value = poly.mod_add(&value, &poly.mod_mul(coeff, &x_power));
                x_power = poly.mod_mul(&x_power, &x);
            }
            
            // Check if this share is Elligator-compatible
            if !is_elligator_compatible(&value, mont_a, mont_b, prime) {
                all_elligator_compatible = false;
                break;
            }
            
            shares.push((j, value));
        }
        
        if all_elligator_compatible {
            if attempts > 1 {
                println!("  Found Elligator-compatible shares after {} attempts", attempts);
            }
            return Some(shares);
        }
    }
    
    None
}

/// Check if a BigUint value is Elligator-compatible
fn is_elligator_compatible(value: &BigUint, mont_a: &Fq, mont_b: &Fq, _prime: &BigUint) -> bool {
    // Convert BigUint to Fq
    let value_bytes = value.to_bytes_le();
    let fq_value = Fq::from_le_bytes_mod_order(&value_bytes);
    
    // Try to encode and decode with Elligator2
    if let Some((x, y)) = Elligator2::encode(&fq_value, mont_a, mont_b) {
        // Verify the point is on the Montgomery curve
        if CurveConverter::verify_montgomery_point(x, y) {
            // Try to decode back
            if let Some(_decoded) = Elligator2::decode(&x, &y, mont_a, mont_b) {
                return true;
            }
        }
    }
    
    false
}

fn phase1(
    poly: &Polynomial, 
    prime: &BigUint,
    mont_a: &Fq,
    mont_b: &Fq,
) -> (BigUint, Vec<(usize, BigUint)>) {
    println!("\n=== PHASE 1 ===");
    println!("Creating {} parties with threshold {} (polynomial degree {})", 
             PHASE1_PARTIES, PHASE1_THRESHOLD, PHASE1_THRESHOLD - 1);
    
    let mut rng = rand::thread_rng();
    
    // Step 1: Each party creates a secret
    let mut party_secrets = Vec::new();
    let mut total_secret = BigUint::zero();
    
    println!("\nStep 1: Each party creates a secret:");
    for i in 1..=PHASE1_PARTIES {
        let secret = BigUint::from(rng.gen_range(1..1000000u64));
        println!("  P{} secret = {}", i, secret);
        total_secret = poly.mod_add(&total_secret, &secret);
        party_secrets.push(secret);
    }
    
    // Step 2: Generate Elligator-compatible shares
    let mut all_shares: HashMap<(usize, usize), BigUint> = HashMap::new();
    
    println!("\nStep 2: Generating Elligator-compatible Shamir shares...");
    for i in 1..=PHASE1_PARTIES {
        let secret = &party_secrets[i-1];
        
        print!("  P{} generating shares...", i);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        match generate_elligator_compatible_shares(poly, secret, PHASE1_PARTIES, PHASE1_THRESHOLD, mont_a, mont_b, prime) {
            Some(shares) => {
                println!(" ✓");
                for (j, value) in shares {
                    all_shares.insert((i, j), value);
                }
            }
            None => {
                println!(" ✗ Failed after {} attempts!", MAX_ELLIGATOR_ATTEMPTS);
                panic!("Unable to generate Elligator-compatible shares for party {}", i);
            }
        }
    }
    
    // Step 3: Aggregate shares
    let mut aggregated_shares = Vec::new();
    
    println!("\nStep 3: Each party aggregates received shares:");
    for j in 1..=PHASE1_PARTIES {
        let mut sum_j = BigUint::zero();
        
        for i in 1..=PHASE1_PARTIES {
            let share_ij = all_shares.get(&(i, j)).unwrap();
            sum_j = poly.mod_add(&sum_j, share_ij);
        }
        
        // Verify aggregated share is still Elligator-compatible
        let is_compatible = is_elligator_compatible(&sum_j, mont_a, mont_b, prime);
        println!("  P{}: S{} = {} (Elligator: {})", j, j, sum_j, 
                 if is_compatible { "✓" } else { "✗" });
        
        aggregated_shares.push((j, sum_j));
    }
    
    // Step 4: Verify reconstruction
    let mut selected_indices: Vec<usize> = (1..=PHASE1_PARTIES).collect();
    selected_indices.shuffle(&mut rng);
    selected_indices.truncate(PHASE1_THRESHOLD);
    selected_indices.sort();
    
    println!("\nStep 4: Reconstructing with subset {:?}:", selected_indices);
    let mut points = Vec::new();
    
    for &idx in &selected_indices {
        let share = &aggregated_shares[idx-1].1;
        points.push(Point::new(BigUint::from(idx as u32), share.clone()));
    }
    
    let aggregated_key = poly.lagrange_interpolate_at_zero(&points).unwrap();
    println!("\nAggregated private key = {}", aggregated_key);
    println!("Expected (sum of secrets) = {}", total_secret);
    println!("Verification: {}", aggregated_key == total_secret);
    
    (aggregated_key, aggregated_shares)
}

fn phase2(
    poly: &Polynomial,
    prime: &BigUint,
    _original_key: BigUint,
    all_shares: Vec<(usize, BigUint)>,
    mont_a: &Fq,
    mont_b: &Fq,
) {
    println!("=== PHASE 2 ===");
    println!("Resharing to {} new parties with threshold {}", PHASE2_PARTIES, PHASE2_THRESHOLD);
    
    let mut rng = rand::thread_rng();
    
    // Randomly select old parties
    let mut old_party_indices: Vec<usize> = (1..=PHASE1_PARTIES).collect();
    old_party_indices.shuffle(&mut rng);
    old_party_indices.truncate(PHASE1_THRESHOLD);
    old_party_indices.sort();
    
    println!("\nRandomly selected old parties: {:?}", old_party_indices);
    
    // Collect shares from selected parties
    let mut old_parties = Vec::new();
    let mut selected_shares_sum = BigUint::zero();
    
    for &idx in &old_party_indices {
        let share = &all_shares[idx-1].1;
        old_parties.push((idx, share.clone()));
        selected_shares_sum = poly.mod_add(&selected_shares_sum, share);
        
        let is_compatible = is_elligator_compatible(share, mont_a, mont_b, prime);
        println!("  P{} contributes S{} = {} (Elligator: {})", 
                 idx, idx, share, if is_compatible { "✓" } else { "✗" });
    }
    
    // Create new party IDs
    let new_party_start = PHASE1_PARTIES + 1;
    let new_parties: Vec<usize> = (new_party_start..new_party_start + PHASE2_PARTIES).collect();
    
    println!("\nNew parties: P{} through P{}", new_parties[0], new_parties[new_parties.len()-1]);
    
    // Each selected old party creates new Elligator-compatible shares
    let mut new_party_shares: HashMap<usize, Vec<BigUint>> = HashMap::new();
    for &party_id in &new_parties {
        new_party_shares.insert(party_id, Vec::new());
    }
    
    println!("\nPhase 2 resharing with Elligator-compatible shares:");
    for (old_party_id, old_share) in &old_parties {
        print!("  P{} generating new shares...", old_party_id);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        // Generate shares but need to evaluate at correct indices for new parties
        let mut attempts = 0;
        let mut found = false;
        
        while attempts < MAX_ELLIGATOR_ATTEMPTS && !found {
            attempts += 1;
            
            // Generate polynomial coefficients
            let mut coeffs = vec![old_share.clone()];
            for _ in 1..PHASE2_THRESHOLD {
                coeffs.push(BigUint::from(rng.gen_range(1..1000000u64)));
            }
            
            // Evaluate polynomial at new party indices
            let mut shares = Vec::new();
            let mut all_compatible = true;
            
            for &new_party_id in &new_parties {
                let x = BigUint::from(new_party_id as u32);
                let mut value = BigUint::zero();
                let mut x_power = BigUint::one();
                
                for coeff in &coeffs {
                    value = poly.mod_add(&value, &poly.mod_mul(coeff, &x_power));
                    x_power = poly.mod_mul(&x_power, &x);
                }
                
                if !is_elligator_compatible(&value, mont_a, mont_b, prime) {
                    all_compatible = false;
                    break;
                }
                
                shares.push((new_party_id, value));
            }
            
            if all_compatible {
                if attempts > 1 {
                    println!(" ✓ Found Elligator-compatible shares after {} attempts", attempts);
                } else {
                    println!(" ✓");
                }
                
                for (party_id, value) in shares {
                    new_party_shares.get_mut(&party_id).unwrap().push(value);
                }
                found = true;
            }
        }
        
        if !found {
            println!(" ✗ Failed after {} attempts!", MAX_ELLIGATOR_ATTEMPTS);
            panic!("Unable to generate Elligator-compatible shares for party {}", old_party_id);
        }
    }
    
    // New parties aggregate their received shares
    println!("\nNew parties aggregate their received shares:");
    let mut new_aggregated_shares = Vec::new();
    
    for &party_id in &new_parties {
        let shares = new_party_shares.get(&party_id).unwrap();
        let sum = shares.iter().fold(BigUint::zero(), |acc, s| poly.mod_add(&acc, s));
        
        let is_compatible = is_elligator_compatible(&sum, mont_a, mont_b, prime);
        println!("  P{}: S{} = {} (Elligator: {})", 
                 party_id, party_id, sum, if is_compatible { "✓" } else { "✗" });
        
        new_aggregated_shares.push((party_id, sum));
    }
    
    // Reconstruct using random subset of new shares
    let mut selected_new: Vec<usize> = (0..PHASE2_PARTIES).collect();
    selected_new.shuffle(&mut rng);
    selected_new.truncate(PHASE2_THRESHOLD);
    
    println!("\nReconstructing from new parties {:?}:", 
             selected_new.iter().map(|&i| new_parties[i]).collect::<Vec<_>>());
    
    let new_points: Vec<Point> = selected_new.iter()
        .map(|&i| {
            let (party_id, share) = &new_aggregated_shares[i];
            Point::new(BigUint::from(*party_id as u32), share.clone())
        })
        .collect();
    
    let new_aggregated_key = poly.lagrange_interpolate_at_zero(&new_points).unwrap();
    
    println!("\nNew aggregated private key = {}", new_aggregated_key);
    println!("Sum of selected old shares = {}", selected_shares_sum);
    println!("Verification: new key matches sum of selected old shares: {}", 
             new_aggregated_key == selected_shares_sum);
    
    // Count how many shares are Elligator-compatible
    let total_shares = new_aggregated_shares.len();
    let compatible_shares = new_aggregated_shares.iter()
        .filter(|(_, share)| is_elligator_compatible(share, mont_a, mont_b, prime))
        .count();
    
    println!("\nElligator compatibility summary:");
    println!("  Compatible shares: {}/{}", compatible_shares, total_shares);
}