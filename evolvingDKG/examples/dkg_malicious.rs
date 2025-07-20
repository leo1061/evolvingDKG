use num_bigint::BigUint;
use num_traits::{Zero, One};
use rand::Rng;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::str::FromStr;
use ark_ed_on_bn254::Fq;
use ark_ff::{PrimeField, BigInteger};

// Import the polynomial module and Elligator
use evolvingDKG::polynomial::{Polynomial, Point};
use evolvingDKG::curve_converter::{CurveConverter, Elligator2};
use evolvingDKG::{PKI, key_gen, read_keys};
use evolvingDKG::elgamal::{ElGamal, ElGamalCiphertext};
use ark_ed_on_bn254::{EdwardsProjective, Fr};

// Prime modulus for the finite field (BN254 scalar field)
const PRIME: &str = "2736030358979909402780800718157159386076813972158567259200215660948447373041";

// Configuration parameters
const PHASE1_PARTIES: usize = 5;
const PHASE1_THRESHOLD: usize = 3;
const PHASE2_PARTIES: usize = 6;
const PHASE2_THRESHOLD: usize = 4;
const MAX_ELLIGATOR_ATTEMPTS: usize = 25_000;

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
    println!("=== Malicious-Secure DKG with PKI and Encryption ===\n");
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
    
    // Setup PKI for all parties (phase 1 + phase 2)
    let total_parties = PHASE1_PARTIES + PHASE2_PARTIES;
    let mut pki = setup_pki(total_parties);
    let elgamal_keys = setup_elgamal_keys(total_parties);
    
    println!("\nPKI Setup Complete:");
    println!("  BabyJubJub keys: {} parties", pki.keys.len());
    println!("  ElGamal keys: {} parties", elgamal_keys.len());
    
    // Phase 1: Initial DKG with Elligator-compatible shares and encryption
    let (phase1_key, all_shares) = phase1(&poly, &prime, &mont_a, &mont_b, &mut pki, &elgamal_keys);
    
    println!("\n{}\n", "=".repeat(60));
    
    // Phase 2: Resharing with Elligator-compatible shares and encryption
    phase2(&poly, &prime, phase1_key, all_shares, &mont_a, &mont_b, &pki, &elgamal_keys);
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
    _pki: &mut PKI,
    elgamal_keys: &[(Fr, EdwardsProjective)],
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
    
    // Step 2: Generate Elligator-compatible shares and encrypt them
    let mut all_shares: HashMap<(usize, usize), BigUint> = HashMap::new();
    let mut encrypted_shares: HashMap<(usize, usize), ElGamalCiphertext> = HashMap::new();
    let mut rng = rand::thread_rng();
    
    println!("\nStep 2: Generating Elligator-compatible Shamir shares and encrypting...");
    for i in 1..=PHASE1_PARTIES {
        let secret = &party_secrets[i-1];
        
        print!("  P{} generating shares...", i);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        match generate_elligator_compatible_shares(poly, secret, PHASE1_PARTIES, PHASE1_THRESHOLD, mont_a, mont_b, prime) {
            Some(shares) => {
                print!(" ✓ Encrypting...");
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                
                for (j, value) in shares {
                    // Store the share
                    all_shares.insert((i, j), value.clone());
                    
                    // Encrypt the share using the recipient's ElGamal public key
                    let recipient_pk = &elgamal_keys[j-1].1; // j-1 because arrays are 0-indexed
                    let share_fr = biguint_to_fr(&value);
                    
                    match ElGamal::encrypt_scalar(recipient_pk, &share_fr, &mut rng) {
                        Ok(ciphertext) => {
                            encrypted_shares.insert((i, j), ciphertext);
                        }
                        Err(e) => {
                            println!(" ✗ Encryption failed: {}", e);
                            panic!("Unable to encrypt share for party {}", j);
                        }
                    }
                }
                println!(" ✓");
            }
            None => {
                println!(" ✗ Failed after {} attempts!", MAX_ELLIGATOR_ATTEMPTS);
                panic!("Unable to generate Elligator-compatible shares for party {}", i);
            }
        }
    }
    
    println!("\nStep 2.5: Verifying encryption/decryption...");
    let mut successful_decryptions = 0;
    let mut total_encryptions = 0;
    
    for ((i, j), ciphertext) in &encrypted_shares {
        total_encryptions += 1;
        let recipient_sk = &elgamal_keys[j-1].0; // j-1 because arrays are 0-indexed
        
        if let Some(decrypted_fr) = ElGamal::decrypt_to_scalar(ciphertext, recipient_sk) {
            let decrypted_biguint = fr_to_biguint(&decrypted_fr);
            let original_share = all_shares.get(&(*i, *j)).unwrap();
            
            if &decrypted_biguint == original_share {
                successful_decryptions += 1;
            }
        }
    }
    
    println!("  Successful decryptions: {}/{}", successful_decryptions, total_encryptions);
    
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
        // let is_compatible = is_elligator_compatible(&sum_j, mont_a, mont_b, prime);
        println!("  P{}: S{} = {} ", j, j, sum_j);
        
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
    _pki: &PKI,
    elgamal_keys: &[(Fr, EdwardsProjective)],
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
        
        // let is_compatible = is_elligator_compatible(share, mont_a, mont_b, prime);
        println!("  P{} contributes S{} = {}", 
                 idx, idx, share);
    }
    
    // Create new party IDs
    let new_party_start = PHASE1_PARTIES + 1;
    let new_parties: Vec<usize> = (new_party_start..new_party_start + PHASE2_PARTIES).collect();
    
    println!("\nNew parties: P{} through P{}", new_parties[0], new_parties[new_parties.len()-1]);
    
    // Each selected old party creates new Elligator-compatible shares and encrypts them
    let mut new_party_shares: HashMap<usize, Vec<BigUint>> = HashMap::new();
    let mut encrypted_new_shares: HashMap<(usize, usize), ElGamalCiphertext> = HashMap::new();
    
    for &party_id in &new_parties {
        new_party_shares.insert(party_id, Vec::new());
    }
    
    println!("\nPhase 2 resharing with Elligator-compatible shares and encryption:");
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
                print!(" ✓ Encrypting...");
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
                
                for (party_id, value) in shares {
                    // Store the share
                    new_party_shares.get_mut(&party_id).unwrap().push(value.clone());
                    
                    // Encrypt the share using the new party's ElGamal public key
                    let recipient_pk = &elgamal_keys[party_id - 1].1; // party_id - 1 for 0-indexing
                    let share_fr = biguint_to_fr(&value);
                    
                    match ElGamal::encrypt_scalar(recipient_pk, &share_fr, &mut rng) {
                        Ok(ciphertext) => {
                            encrypted_new_shares.insert((*old_party_id, party_id), ciphertext);
                        }
                        Err(e) => {
                            println!(" ✗ Encryption failed: {}", e);
                            panic!("Unable to encrypt share for new party {}", party_id);
                        }
                    }
                }
                
                if attempts > 1 {
                    println!(" ✓ Complete after {} attempts", attempts);
                } else {
                    println!(" ✓ Complete");
                }
                found = true;
            }
        }
        
        if !found {
            println!(" ✗ Failed after {} attempts!", MAX_ELLIGATOR_ATTEMPTS);
            panic!("Unable to generate Elligator-compatible shares for party {}", old_party_id);
        }
    }
    
    println!("\nPhase 2 encryption verification:");
    let mut successful_new_decryptions = 0;
    let mut total_new_encryptions = 0;
    
    for ((old_id, new_id), ciphertext) in &encrypted_new_shares {
        total_new_encryptions += 1;
        let recipient_sk = &elgamal_keys[new_id - 1].0; // new_id - 1 for 0-indexing
        
        if let Some(decrypted_fr) = ElGamal::decrypt_to_scalar(ciphertext, recipient_sk) {
            let decrypted_biguint = fr_to_biguint(&decrypted_fr);
            // Find the original share in new_party_shares
            let shares_for_party = new_party_shares.get(new_id).unwrap();
            let old_party_index = old_party_indices.iter().position(|&x| x == *old_id).unwrap();
            let original_share = &shares_for_party[old_party_index];
            
            if &decrypted_biguint == original_share {
                successful_new_decryptions += 1;
            }
        }
    }
    
    println!("  Phase 2 successful decryptions: {}/{}", successful_new_decryptions, total_new_encryptions);
    
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
        
        // let is_compatible = is_elligator_compatible(&aggregated_share, mont_a, mont_b, prime);
        println!("  P{}: S{} = {}", 
                 party_id, party_id, aggregated_share);
        
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
    println!("Verification: new key matches old key: {}", 
             new_aggregated_key == _original_key);
    

}