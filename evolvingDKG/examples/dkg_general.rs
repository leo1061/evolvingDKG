use num_bigint::BigUint;
use num_traits::{Zero, One};
use rand::Rng;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::str::FromStr;

// Import the polynomial module and encryption
use evolvingDKG::polynomial::{Polynomial, Point};
use evolvingDKG::{PKI, BabyJubJubPK, BabyJubJubSK, key_gen, read_keys};
use evolvingDKG::elgamal::{ElGamal, ElGamalCiphertext};
use ark_ed_on_bn254::{EdwardsProjective, Fr};
use ark_ff::{PrimeField, BigInteger};

// Prime modulus for the finite field (BN254 scalar field)
const PRIME: &str = "2736030358979909402780800718157159386076813972158567259200215660948447373041";

// Configuration parameters
const PHASE1_PARTIES: usize = 5;
const PHASE1_THRESHOLD: usize = 3;
const PHASE2_PARTIES: usize = 6;  // Number of new parties
const PHASE2_THRESHOLD: usize = 4;

// Utility functions for BigUint/Fr conversion
fn biguint_to_fr(big: &BigUint) -> Fr {
    let bytes = big.to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

fn fr_to_biguint(fr: &Fr) -> BigUint {
    let bytes = fr.into_bigint().to_bytes_le();
    BigUint::from_bytes_le(&bytes)
}

// Setup PKI with BabyJubJub keys for all parties
fn setup_pki(num_parties: usize) -> PKI {
    let mut pki = PKI::new();
    
    println!("\nGenerating BabyJubJub keypairs:");
    for i in 1..=num_parties {
        print!("  Generating keys for party {}...", i);
        
        // Generate keypair using external script
        if let Err(e) = key_gen(i as u32) {
            println!(" Failed: {}", e);
            continue;
        }
        
        // Read the generated keys
        let (_sk, pk) = read_keys(i as u32);
        pki.add_public_key(pk);
        println!(" ✓");
    }
    
    pki
}

// Setup ElGamal keys for all parties
fn setup_elgamal_keys(num_parties: usize) -> Vec<(Fr, EdwardsProjective)> {
    let mut rng = rand::thread_rng();
    let mut keys = Vec::new();
    
    println!("\nGenerating ElGamal keypairs:");
    for i in 1..=num_parties {
        let (sk, pk) = ElGamal::generate_keypair(&mut rng);
        keys.push((sk, pk));
        println!("  Party {}: ElGamal keys ✓", i);
    }
    
    keys
}

fn main() {
    println!("=== General Two-Phase DKG Example with PKI and Encryption ===\n");
    println!("Phase 1: {} parties, threshold {}", PHASE1_PARTIES, PHASE1_THRESHOLD);
    println!("Phase 2: {} new parties, threshold {}", PHASE2_PARTIES, PHASE2_THRESHOLD);
    
    let prime = BigUint::from_str(PRIME).unwrap();
    let poly = Polynomial::new(prime.clone());
    
    // Setup PKI for all parties (phase 1 + phase 2)
    let total_parties = PHASE1_PARTIES + PHASE2_PARTIES;
    let mut pki = setup_pki(total_parties);
    let elgamal_keys = setup_elgamal_keys(total_parties);
    
    println!("\nPKI Setup Complete:");
    println!("  BabyJubJub keys: {} parties", pki.keys.len());
    println!("  ElGamal keys: {} parties", elgamal_keys.len());
    
    // Phase 1: Initial DKG with encryption
    let (phase1_key, all_shares) = phase1(&poly, &prime, &mut pki, &elgamal_keys);
    
    println!("\n{}", "=".repeat(60));
    
    // Phase 2: Resharing with encryption
    phase2(&poly, &prime, phase1_key, all_shares, &pki, &elgamal_keys);
}

fn phase1(poly: &Polynomial, _prime: &BigUint) -> (BigUint, Vec<(usize, BigUint)>) {
    println!("\n=== PHASE 1 ===");
    println!("Creating {} parties with threshold {} (polynomial degree {})", 
             PHASE1_PARTIES, PHASE1_THRESHOLD, PHASE1_THRESHOLD - 1);
    
    let mut rng = rand::thread_rng();
    
    // Step 1: Each party creates a secret polynomial
    let mut party_polynomials = Vec::new();
    let mut total_secret = BigUint::zero();
    
    println!("\nStep 1: Each party creates a random polynomial:");
    for i in 1..=PHASE1_PARTIES {
        let mut coeffs = Vec::new();
        for j in 0..PHASE1_THRESHOLD {
            let coeff = BigUint::from(rng.gen_range(1..1000000u64));
            coeffs.push(coeff.clone());
            if j == 0 {
                println!("  P{} secret (f{}(0)) = {}", i, i, coeff);
                total_secret = poly.mod_add(&total_secret, &coeff);
            }
        }
        party_polynomials.push(coeffs);
    }
    
    // Step 2: Evaluate and distribute shares
    let mut shares: HashMap<(usize, usize), BigUint> = HashMap::new();
    
    println!("\nStep 2: Distributing shares...");
    for i in 1..=PHASE1_PARTIES {
        let coeffs = &party_polynomials[i-1];
        
        for j in 1..=PHASE1_PARTIES {
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
    
    // Step 3: Aggregate shares
    let mut aggregated_shares = Vec::new();
    
    println!("\nStep 3: Each party aggregates received shares:");
    for j in 1..=PHASE1_PARTIES {
        let mut sum_j = BigUint::zero();
        
        for i in 1..=PHASE1_PARTIES {
            let share_ij = shares.get(&(i, j)).unwrap();
            sum_j = poly.mod_add(&sum_j, share_ij);
        }
        
        println!("  P{}: S{} = {}", j, j, sum_j);
        aggregated_shares.push((j, sum_j));
    }
    
    // Step 4: Verify reconstruction with random subset
    let mut selected_indices: Vec<usize> = (1..=PHASE1_PARTIES).collect();
    selected_indices.shuffle(&mut rng);
    selected_indices.truncate(PHASE1_THRESHOLD);
    selected_indices.sort();
    
    println!("\nStep 4: Reconstructing with random subset {:?}:", selected_indices);
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

fn phase2(poly: &Polynomial, _prime: &BigUint, original_key: BigUint, all_shares: Vec<(usize, BigUint)>) {
    println!("=== PHASE 2 ===");
    println!("Resharing to {} new parties with threshold {}", PHASE2_PARTIES, PHASE2_THRESHOLD);
    
    let mut rng = rand::thread_rng();
    
    // Randomly select old parties (exactly threshold number)
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
        println!("  P{} contributes S{} = {}", idx, idx, share);
    }
    
    // Create new party IDs starting after the old parties
    let new_party_start = PHASE1_PARTIES + 1;
    let new_parties: Vec<usize> = (new_party_start..new_party_start + PHASE2_PARTIES).collect();
    
    println!("\nNew parties: P{} through P{}", new_parties[0], new_parties[new_parties.len()-1]);
    
    // Verify we can reconstruct from selected old shares
    let old_points: Vec<Point> = old_parties.iter()
        .map(|(idx, share)| Point::new(BigUint::from(*idx as u32), share.clone()))
        .collect();
    
    let reconstructed = poly.lagrange_interpolate_at_zero(&old_points).unwrap();
    println!("\nReconstructed from selected shares: {}", reconstructed);
    println!("Original key: {}", original_key);
    println!("Matches: {}", reconstructed == original_key);
    
    // Each selected old party creates new shares
    let mut new_party_shares: HashMap<usize, Vec<BigUint>> = HashMap::new();
    for &party_id in &new_parties {
        new_party_shares.insert(party_id, Vec::new());
    }
    
    println!("\nPhase 2 resharing process:");
    for (old_party_id, old_share) in &old_parties {
        println!("\nP{} creates new polynomial with S{} as secret:", old_party_id, old_party_id);
        
        // Create polynomial of degree (new_threshold - 1)
        let mut coeffs = vec![old_share.clone()];
        for _ in 1..PHASE2_THRESHOLD {
            coeffs.push(BigUint::from(rng.gen_range(1..1000000u64)));
        }
        
        // Evaluate at new party points
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
    
    // New parties aggregate their received shares
    println!("\nNew parties aggregate their received shares:");
    let mut new_aggregated_shares = Vec::new();
    
    for &party_id in &new_parties {
        let shares = new_party_shares.get(&party_id).unwrap();
        
        // Create points from the shares received from old parties
        let share_points: Vec<Point> = old_party_indices.iter().zip(shares.iter())
            .map(|(&old_id, share)| Point::new(BigUint::from(old_id as u32), share.clone()))
            .collect();
        
        // Compute aggregated share as interpolation at zero
        let aggregated_share = poly.lagrange_interpolate_at_zero(&share_points).unwrap();
        println!("  P{}: S{} = {}", party_id, party_id, aggregated_share);
        new_aggregated_shares.push((party_id, aggregated_share));
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
    
    println!("\nNote: The new key represents contributions from {} out of {} original parties",
             old_party_indices.len(), PHASE1_PARTIES);
}