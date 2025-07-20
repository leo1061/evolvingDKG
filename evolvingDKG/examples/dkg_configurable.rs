use num_bigint::BigUint;
use num_traits::{Zero, One};
use rand::Rng;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::str::FromStr;
use std::env;

// Import the polynomial module
use evolvingDKG::polynomial::{Polynomial, Point};

// Prime modulus for the finite field (BN254 scalar field)
const PRIME: &str = "2736030358979909402780800718157159386076813972158567259200215660948447373041";

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Parse command line arguments with defaults
    let phase1_parties = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let phase1_threshold = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let phase2_parties = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(4);
    let phase2_threshold = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(3);
    
    // Validate parameters
    if phase1_threshold > phase1_parties {
        eprintln!("Error: Phase 1 threshold cannot exceed number of parties");
        std::process::exit(1);
    }
    if phase2_threshold > phase2_parties {
        eprintln!("Error: Phase 2 threshold cannot exceed number of parties");
        std::process::exit(1);
    }
    
    println!("=== Configurable DKG Example ===");
    println!("\nUsage: {} [phase1_parties] [phase1_threshold] [phase2_parties] [phase2_threshold]", args[0]);
    println!("\nConfiguration:");
    println!("  Phase 1: {} parties, threshold {}", phase1_parties, phase1_threshold);
    println!("  Phase 2: {} new parties, threshold {}", phase2_parties, phase2_threshold);
    
    let prime = BigUint::from_str(PRIME).unwrap();
    let poly = Polynomial::new(prime.clone());
    
    // Run the protocol
    let (phase1_key, all_shares) = phase1(&poly, phase1_parties, phase1_threshold);
    println!("\n{}\n", "=".repeat(60));
    phase2(&poly, phase1_key, all_shares, phase1_parties, phase1_threshold, phase2_parties, phase2_threshold);
}

fn phase1(poly: &Polynomial, num_parties: usize, threshold: usize) -> (BigUint, Vec<(usize, BigUint)>) {
    println!("=== PHASE 1: Initial DKG ===");
    println!("Setting up {} parties with threshold {} (degree {} polynomial)", 
             num_parties, threshold, threshold - 1);
    
    let mut rng = rand::thread_rng();
    
    // Each party creates a polynomial
    let mut party_polynomials = Vec::new();
    let mut total_secret = BigUint::zero();
    
    println!("\nParty secrets:");
    for i in 1..=num_parties {
        let mut coeffs = Vec::new();
        for j in 0..threshold {
            let coeff = BigUint::from(rng.gen_range(1..1000000u64));
            coeffs.push(coeff.clone());
            if j == 0 {
                println!("  P{}: {}", i, coeff);
                total_secret = poly.mod_add(&total_secret, &coeff);
            }
        }
        party_polynomials.push(coeffs);
    }
    println!("Total secret: {}", total_secret);
    
    // Distribute shares
    let mut shares: HashMap<(usize, usize), BigUint> = HashMap::new();
    
    for i in 1..=num_parties {
        let coeffs = &party_polynomials[i-1];
        
        for j in 1..=num_parties {
            let mut value = BigUint::zero();
            let mut x_power = BigUint::one();
            let x = BigUint::from(j as u32);
            
            for coeff in coeffs {
                value = poly.mod_add(&value, &poly.mod_mul(coeff, &x_power));
                x_power = poly.mod_mul(&x_power, &x);
            }
            
            shares.insert((i, j), value);
        }
    }
    
    // Aggregate shares
    let mut aggregated_shares = Vec::new();
    
    println!("\nAggregated shares:");
    for j in 1..=num_parties {
        let mut sum_j = BigUint::zero();
        
        for i in 1..=num_parties {
            let share_ij = shares.get(&(i, j)).unwrap();
            sum_j = poly.mod_add(&sum_j, share_ij);
        }
        
        println!("  S{} = {}", j, sum_j);
        aggregated_shares.push((j, sum_j));
    }
    
    // Verify with random subset
    let mut indices: Vec<usize> = (1..=num_parties).collect();
    indices.shuffle(&mut rng);
    indices.truncate(threshold);
    indices.sort();
    
    println!("\nVerifying with subset {:?}:", indices);
    let points: Vec<Point> = indices.iter()
        .map(|&idx| Point::new(
            BigUint::from(idx as u32), 
            aggregated_shares[idx-1].1.clone()
        ))
        .collect();
    
    let reconstructed = poly.lagrange_interpolate_at_zero(&points).unwrap();
    println!("Reconstructed: {}", reconstructed);
    println!("Verification: {}", reconstructed == total_secret);
    
    (reconstructed, aggregated_shares)
}

fn phase2(
    poly: &Polynomial,
    original_key: BigUint,
    old_shares: Vec<(usize, BigUint)>,
    old_parties: usize,
    old_threshold: usize,
    new_parties: usize,
    new_threshold: usize,
) {
    println!("=== PHASE 2: Resharing Protocol ===");
    
    let mut rng = rand::thread_rng();
    
    // Select exactly threshold number of old parties
    let mut selected_old: Vec<usize> = (1..=old_parties).collect();
    selected_old.shuffle(&mut rng);
    selected_old.truncate(old_threshold);
    selected_old.sort();
    
    println!("Selected {} old parties: {:?}", old_threshold, selected_old);
    
    // Collect their shares
    let mut contributing_parties = Vec::new();
    let mut sum_of_shares = BigUint::zero();
    
    println!("\nContributing shares:");
    for &idx in &selected_old {
        let share = &old_shares[idx-1].1;
        contributing_parties.push((idx, share.clone()));
        sum_of_shares = poly.mod_add(&sum_of_shares, share);
        println!("  P{}: S{} = {}", idx, idx, share);
    }
    println!("Sum of contributing shares: {}", sum_of_shares);
    
    // Verify we can reconstruct the original key
    let points: Vec<Point> = contributing_parties.iter()
        .map(|(idx, share)| Point::new(BigUint::from(*idx as u32), share.clone()))
        .collect();
    
    let verify = poly.lagrange_interpolate_at_zero(&points).unwrap();
    println!("Verification: {} (should equal original key: {})", verify, original_key);
    
    // Create new party IDs
    let new_party_start = old_parties + 1;
    let new_party_ids: Vec<usize> = (new_party_start..new_party_start + new_parties).collect();
    
    println!("\nNew parties: P{} through P{}", new_party_ids[0], new_party_ids[new_party_ids.len()-1]);
    println!("New threshold: {} (degree {} polynomial)", new_threshold, new_threshold - 1);
    
    // Each contributing party creates shares for new parties
    let mut shares_for_new: HashMap<usize, Vec<BigUint>> = HashMap::new();
    for &id in &new_party_ids {
        shares_for_new.insert(id, Vec::new());
    }
    
    println!("\nResharing process:");
    for (old_id, old_share) in &contributing_parties {
        println!("\nP{} shares S{}:", old_id, old_id);
        
        // Create degree (new_threshold-1) polynomial
        let mut coeffs = vec![old_share.clone()];
        for _ in 1..new_threshold {
            coeffs.push(BigUint::from(rng.gen_range(1..1000000u64)));
        }
        
        // Evaluate for each new party
        for &new_id in &new_party_ids {
            let x = BigUint::from(new_id as u32);
            let mut value = BigUint::zero();
            let mut x_power = BigUint::one();
            
            for coeff in &coeffs {
                value = poly.mod_add(&value, &poly.mod_mul(coeff, &x_power));
                x_power = poly.mod_mul(&x_power, &x);
            }
            
            if new_id <= new_party_ids[0] + 2 || new_id == *new_party_ids.last().unwrap() {
                println!("  → P{}: {}", new_id, value);
            } else if new_id == new_party_ids[0] + 3 {
                println!("  → ...");
            }
            
            shares_for_new.get_mut(&new_id).unwrap().push(value);
        }
    }
    
    // New parties aggregate
    let mut new_aggregated = Vec::new();
    
    println!("\nNew party aggregated shares:");
    for &id in &new_party_ids {
        let shares = shares_for_new.get(&id).unwrap();
        let sum = shares.iter().fold(BigUint::zero(), |acc, s| poly.mod_add(&acc, s));
        println!("  S{} = {}", id, sum);
        new_aggregated.push((id, sum));
    }
    
    // Final reconstruction with random subset
    let mut selected_new: Vec<usize> = (0..new_parties).collect();
    selected_new.shuffle(&mut rng);
    selected_new.truncate(new_threshold);
    
    let selected_ids: Vec<usize> = selected_new.iter()
        .map(|&i| new_party_ids[i])
        .collect();
    
    println!("\nFinal reconstruction with new parties {:?}:", selected_ids);
    
    let final_points: Vec<Point> = selected_new.iter()
        .map(|&i| {
            let (id, share) = &new_aggregated[i];
            Point::new(BigUint::from(*id as u32), share.clone())
        })
        .collect();
    
    let final_key = poly.lagrange_interpolate_at_zero(&final_points).unwrap();
    
    println!("\nFinal reconstructed key: {}", final_key);
    println!("Expected (sum of contributing shares): {}", sum_of_shares);
    println!("Success: {}", final_key == sum_of_shares);
    
    println!("\nSummary:");
    println!("- Original key was shared among {} parties", old_parties);
    println!("- {} parties contributed to resharing", old_threshold);
    println!("- New key shared among {} parties with threshold {}", new_parties, new_threshold);
    println!("- New key represents {}/{} of the original parties' contributions", old_threshold, old_parties);
}