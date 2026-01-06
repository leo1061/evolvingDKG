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
use ark_ec::{PrimeGroup, CurveGroup};

// Prime modulus for the finite field (BN254 scalar field)
const PRIME: &str = "2736030358979909402780800718157159386076813972158567259200215660948447373041";

// Configuration parameters
const PHASE1_PARTIES: usize = 5;
const PHASE1_THRESHOLD: usize = 3;
const PHASE2_PARTIES: usize = 5;
const PHASE2_THRESHOLD: usize = 3;
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

fn fq_to_biguint(fq: &Fq) -> BigUint {
    let bytes = fq.into_bigint().to_bytes_le();
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

/// Finalize the distribute/output phase: reconstruct combined shares using
/// ciphertexts of Lagrange-weighted shares (λ_k * s_{k->j}) and verify them.
fn finalize_distribute(
    poly: &Polynomial,
    old_party_indices: &[usize],
    new_parties: &[usize],
    encrypted_new_shares: &HashMap<(usize, usize), ElGamalCiphertext>,
    new_party_shares: &HashMap<usize, Vec<BigUint>>,
    new_aggregated_shares: &[(usize, BigUint)],
    new_commitments: &[(usize, EdwardsProjective)],
    elgamal_keys: &[(Fr, EdwardsProjective)],
    expected_pk: EdwardsProjective,
) {
    println!("\n=== DISTRIBUTE: finalize / output phase ===");

    // Coefficienti di Lagrange servono più sotto per l'aggregazione della PK
    let old_x_coords: Vec<BigUint> = old_party_indices
        .iter()
        .map(|&idx| BigUint::from(idx as u32))
        .collect();

    let lagrange_coeffs = match poly.lagrange_coefficients(&old_x_coords, &BigUint::zero()) {
        Some(l) => l,
        None => {
            println!("  ✗ Failed to compute Lagrange coefficients for old parties");
            println!("  ✗ Cannot verify decrypted aggregated shares");
            return;
        }
    };

    let mut all_ok = true;

    // Per ogni nuovo party, sommiamo le share λ_k * s_{k->j} decriptate
    for (idx, &(party_id, ref aggregated_share)) in new_aggregated_shares.iter().enumerate() {
        println!("\n-- New party P{} verification --", party_id);

        let recipient_sk = &elgamal_keys[party_id - 1].0;
        let mut accumulated_share_fr = Fr::zero();
        let mut any_ciphertext = false;

        for &old_id in old_party_indices.iter() {
            if let Some(ct) = encrypted_new_shares.get(&(old_id, party_id)) {
                any_ciphertext = true;

                if let Some(decrypted_fr) = ElGamal::decrypt_to_scalar(ct, recipient_sk) {
                    // decrypted_fr = Fr( λ_k * s_{k->j} ), già pesata in Phase 2
                    accumulated_share_fr += decrypted_fr;
                } else {
                    println!(
                        "  ✗ Decryption failed for share from old party P{} to P{}",
                        old_id, party_id
                    );
                    all_ok = false;
                }
            } else {
                println!(
                    "  Warning: missing ciphertext from old party P{} -> P{} (skipping this contribution)",
                    old_id, party_id
                );
            }
        }

        if !any_ciphertext {
            println!(
                "  ✗ No ciphertexts found to reconstruct aggregated share for P{}",
                party_id
            );
            all_ok = false;
            continue;
        }

        // Valore atteso nel campo scalare (mod r)
        let expected_share_fr = biguint_to_fr(aggregated_share);

        // Logging (rappresentanti in BigUint, entrambi mod r)
        let decrypted_aggregated_biguint = fr_to_biguint(&accumulated_share_fr);
        let expected_share_biguint = fr_to_biguint(&expected_share_fr);

        println!(
            "  Decrypted combined (Lagrange-weighted) share (mod r) = {}",
            decrypted_aggregated_biguint
        );
        println!(
            "  Expected aggregated share              (mod r) = {}",
            expected_share_biguint
        );

        if accumulated_share_fr == expected_share_fr {
            println!("  ✓ Decryption matches aggregated share for P{}", party_id);
        } else {
            println!(
                "  ✗ Decryption DOES NOT match aggregated share for P{}",
                party_id
            );
            all_ok = false;
        }

        // verify commitment corresponds to generator * aggregated_share_fr
        let aggregated_share_fr = biguint_to_fr(aggregated_share);
        let expected_commitment = EdwardsProjective::generator() * aggregated_share_fr;

        let commitment = &new_commitments[idx].1;
        if *commitment == expected_commitment {
            println!("  ✓ Commitment matches generator * share for P{}", party_id);
        } else {
            println!("  ✗ Commitment mismatch for P{}", party_id);
            all_ok = false;
        }
    }

    // --- Parte aggregazione PK dai nuovi commitment: la tua logica era già corretta ---

    let selected_count = std::cmp::min(PHASE2_THRESHOLD, new_parties.len());
    if selected_count == 0 {
        println!("  ✗ No new parties available to check aggregated public key");
        return;
    }

    let selected_indices: Vec<usize> = (0..selected_count).collect();
    let new_x_coords: Vec<BigUint> = selected_indices
        .iter()
        .map(|&i| BigUint::from(new_parties[i] as u32))
        .collect();

    let new_lagrange_coeffs = match poly.lagrange_coefficients(&new_x_coords, &BigUint::zero()) {
        Some(v) => v,
        None => {
            println!("  ✗ Failed to compute new Lagrange coeffs for public key aggregation");
            return;
        }
    };

    let mut aggregated_pk = EdwardsProjective::zero();
    for (i, &sel_i) in selected_indices.iter().enumerate() {
        let (party_id, _) = new_aggregated_shares[sel_i];
        let commit = new_commitments
            .iter()
            .find(|(pid, _)| *pid == party_id)
            .map(|(_, c)| *c)
            .expect("commitment missing for selected new party");

        let coeff_fr = biguint_to_fr(&new_lagrange_coeffs[i]);
        aggregated_pk = aggregated_pk + commit * coeff_fr;
    }

    println!("\nAggregated public key (from commitments) computed.");
    println!(
        "Expected public key matches aggregated: {}",
        aggregated_pk == expected_pk
    );

    if all_ok && aggregated_pk == expected_pk {
        println!("\nDISTRIBUTE finalize: all checks passed ✅");
    } else {
        println!("\nDISTRIBUTE finalize: some checks failed ❌");
    }
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
    
    // First, compute the Lagrange coefficients for the selected old parties at x=0
    let old_x_coords: Vec<BigUint> = old_party_indices.iter()
        .map(|&idx| BigUint::from(idx as u32))
        .collect();
    let lagrange_coeffs = poly.lagrange_coefficients(&old_x_coords, &BigUint::zero())
        .expect("Failed to compute Lagrange coefficients");
    
    for (i, (old_party_id, old_share)) in old_parties.iter().enumerate() {
        print!("  P{} generating new shares...", old_party_id);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        // Get the Lagrange coefficient for this old party
        let lagrange_coeff = &lagrange_coeffs[i];
        
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
                
                // Multiply by Lagrange coefficient
                let value_with_lagrange = poly.mod_mul(&value, lagrange_coeff);
                
                if !is_elligator_compatible(&value_with_lagrange, mont_a, mont_b, prime) {
                    all_compatible = false;
                    break;
                }
                
                shares.push((new_party_id, value_with_lagrange));
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
    let mut new_commitments = Vec::new();
    
    for &party_id in &new_parties {
        let shares = new_party_shares.get(&party_id).unwrap();
        
        // Since shares already include Lagrange coefficients, we just sum them
        let mut aggregated_share = BigUint::zero();
        for share in shares {
            aggregated_share = poly.mod_add(&aggregated_share, share);
        }
        
        // Create commitment of aggregated_share i.e. the related BabyJubJubPK
        let aggregated_share_fr = biguint_to_fr(&aggregated_share);

        let commitment = EdwardsProjective::generator() * aggregated_share_fr;

        // let is_compatible = is_elligator_compatible(&aggregated_share, mont_a, mont_b, prime);
        println!("  P{}: S{} = {}", 
                 party_id, party_id, aggregated_share);
        
        new_aggregated_shares.push((party_id, aggregated_share));
    

        // Add the commitment to new_commitments
        new_commitments.push((party_id, commitment));
    }

    // Generate zero knowledge proof for each new party
    println!("\nGenerating ZK proofs for each new party...");
    generate_zk_proofs_for_new_parties(
        &new_parties,
        &new_aggregated_shares,
        &new_commitments,
        &encrypted_new_shares,
        &elgamal_keys,
        &old_party_indices,
        &new_party_shares,
    );

        // expected_pk calcolato come prima (usa la chiave aggregata originale)
    let expected_pk = EdwardsProjective::generator() * biguint_to_fr(&_original_key);

    // finalize distribute: ricostruisce ciphertext aggregati, li decripta e verifica commit / pk aggregata
    finalize_distribute(
        poly,
        &old_party_indices,
        &new_parties,
        &encrypted_new_shares,
        &new_party_shares,
        &new_aggregated_shares,
        &new_commitments,
        &elgamal_keys,
        expected_pk,
    );

    
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
    
    // Verify that the commitments are consistent with the aggregated key
    println!("\nVerifying commitments:");
    
    // Compute the aggregated public key from new parties' commitments
    let selected_commitments: Vec<_> = selected_new.iter()
        .map(|&i| new_commitments[i].1)
        .collect();
    
    // Compute Lagrange coefficients for the selected new parties
    let new_x_coords: Vec<BigUint> = selected_new.iter()
        .map(|&i| BigUint::from(new_parties[i] as u32))
        .collect();
    let new_lagrange_coeffs = poly.lagrange_coefficients(&new_x_coords, &BigUint::zero())
        .expect("Failed to compute Lagrange coefficients for verification");
    
    // Compute aggregated public key
    let mut aggregated_pk = EdwardsProjective::zero();
    for (i, &commitment) in selected_commitments.iter().enumerate() {
        let coeff_fr = biguint_to_fr(&new_lagrange_coeffs[i]);
        aggregated_pk = aggregated_pk + commitment * coeff_fr;
    }
    
    // Verify against the original key
    let expected_pk = EdwardsProjective::generator() * biguint_to_fr(&_original_key);
    println!("  Aggregated public key matches expected: {}", aggregated_pk == expected_pk);

}

/// Generate ZK proofs for each new party
fn generate_zk_proofs_for_new_parties(
    new_parties: &[usize],
    new_aggregated_shares: &[(usize, BigUint)],
    new_commitments: &[(usize, EdwardsProjective)],
    encrypted_new_shares: &HashMap<(usize, usize), ElGamalCiphertext>,
    elgamal_keys: &[(Fr, EdwardsProjective)],
    old_party_indices: &[usize],
    new_party_shares: &HashMap<usize, Vec<BigUint>>,
) {
    use std::process::Command;
    use std::fs;
    
    // Change to scripts directory for running the ZK proof generation
    let scripts_dir = std::path::Path::new("../scripts");
    
    for (i, &party_id) in new_parties.iter().enumerate() {
        let (_, _aggregated_share) = &new_aggregated_shares[i];
        let (_, commitment) = &new_commitments[i];
        
        // Get ElGamal keys for this party
        let (el_gamal_sk, el_gamal_pk) = &elgamal_keys[party_id - 1]; // party_id - 1 for 0-indexing
        
        // Extract ElGamal public key coordinates
        let pk_affine = el_gamal_pk.into_affine();
        let pk_x = fq_to_biguint(&pk_affine.x);
        let pk_y = fq_to_biguint(&pk_affine.y);
        
        // The Y point should be the sum of the individual shares as points
        // Each share should be converted to generator * share, then summed
        // This matches what the circuit expects: Base8^(sum of messages)
        let mut y_point = EdwardsProjective::zero();
        
        // Collect the individual shares from old parties (before aggregation)
        for &old_party_id in old_party_indices {
            if let Some(_ciphertext) = encrypted_new_shares.get(&(old_party_id, party_id)) {
                // Find the original share from new_party_shares
                let shares_for_party = new_party_shares.get(&party_id).unwrap();
                let old_party_index = old_party_indices.iter().position(|&x| x == old_party_id).unwrap();
                let individual_share = &shares_for_party[old_party_index];
                
                // Convert share to point: generator * share
                let share_fr = biguint_to_fr(individual_share);
                let share_point = EdwardsProjective::generator() * share_fr;
                y_point = y_point + share_point;
            }
        }
        
        let y_point_affine = y_point.into_affine();
        let y_x = fq_to_biguint(&y_point_affine.x);
        let y_y = fq_to_biguint(&y_point_affine.y);
        
        // Collect encrypted shares for this party from the old parties that participated
        let mut ciphertexts = Vec::new();
        for &old_party_id in old_party_indices {
            if let Some(ciphertext) = encrypted_new_shares.get(&(old_party_id, party_id)) {
                // Extract ciphertext coordinates (c1 = ephemeral key, c2 = encrypted message)
                let ephemeral_key_affine = ciphertext.c1.into_affine();
                let encrypted_message_affine = ciphertext.c2.into_affine();
                
                let ek_x = fq_to_biguint(&ephemeral_key_affine.x);
                let ek_y = fq_to_biguint(&ephemeral_key_affine.y);
                let em_x = fq_to_biguint(&encrypted_message_affine.x);
                let em_y = fq_to_biguint(&encrypted_message_affine.y);
                
                ciphertexts.push(serde_json::json!([
                    [ek_x.to_string(), ek_y.to_string()],
                    [em_x.to_string(), em_y.to_string()]
                ]));
            }
        }
        
        let n = ciphertexts.len();
        
        // Collect preimages (original shares) for Elligator2 circuit
        let mut preimages = Vec::new();
        for &old_party_id in old_party_indices {
            if let Some(_ciphertext) = encrypted_new_shares.get(&(old_party_id, party_id)) {
                let shares_for_party = new_party_shares.get(&party_id).unwrap();
                let old_party_index = old_party_indices.iter().position(|&x| x == old_party_id).unwrap();
                let individual_share = &shares_for_party[old_party_index];
                let share_fr = biguint_to_fr(individual_share);
                preimages.push(fr_to_biguint(&share_fr).to_string());
            }
        }
        
        // Extract ephemeral keys and encrypted messages separately for elgamal_elligator2 circuit
        let mut ephemeral_keys = Vec::new();
        let mut encrypted_messages = Vec::new();
        
        for &old_party_id in old_party_indices {
            if let Some(ciphertext) = encrypted_new_shares.get(&(old_party_id, party_id)) {
                let ephemeral_key_affine = ciphertext.c1.into_affine();
                let encrypted_message_affine = ciphertext.c2.into_affine();
                
                let ek_x = fq_to_biguint(&ephemeral_key_affine.x);
                let ek_y = fq_to_biguint(&ephemeral_key_affine.y);
                let em_x = fq_to_biguint(&encrypted_message_affine.x);
                let em_y = fq_to_biguint(&encrypted_message_affine.y);
                
                ephemeral_keys.push([ek_x.to_string(), ek_y.to_string()]);
                encrypted_messages.push([em_x.to_string(), em_y.to_string()]);
            }
        }
        
        // Generator point
        let generator_affine = EdwardsProjective::generator().into_affine();
        let gen_x = fq_to_biguint(&generator_affine.x);
        let gen_y = fq_to_biguint(&generator_affine.y);
        
        // Create JSON file for elgamal_elligator2 circuit
        let json_data = serde_json::json!({
            "ephemeralKeys": ephemeral_keys,
            "encryptedMessages": encrypted_messages,
            "privateKey": fr_to_biguint(el_gamal_sk).to_string(),
            "preimages": preimages,
            "Y": [y_x.to_string(), y_y.to_string()],
            "generator": [gen_x.to_string(), gen_y.to_string()]
        });
        
        let json_filename = format!("elligator2_{}.json", party_id);
        let json_path = scripts_dir.join(&json_filename);
        
        // Write JSON file
        if let Err(e) = fs::write(&json_path, serde_json::to_string_pretty(&json_data).unwrap()) {
            println!("  P{}: ✗ Failed to write JSON file: {}", party_id, e);
            continue;
        }
        
        println!("  P{}: Created {}", party_id, json_filename);
        
        println!("  P{}: Generating ZK proof...", party_id);
        
        // Use snarkjs directly with elgamal_elligator2 circuit
        let witness_file = format!("witness_{}.wtns", party_id);
        let wasm_path = "../circuits/elgamal_elligator2_js/elgamal_elligator2.wasm";
        let r1cs_path = "../circuits/elgamal_elligator2.r1cs";
        
        let output = Command::new("snarkjs")
            .arg("wtns")
            .arg("calculate")
            .arg(wasm_path)
            .arg(&json_filename)
            .arg(&witness_file)
            .current_dir(&scripts_dir)
            .output();
            
        match output {
            Ok(result) => {
                if result.status.success() {
                    println!("  P{}: ✓ Witness calculated successfully", party_id);
                    
                    // Now check constraints
                    let check_output = Command::new("snarkjs")
                        .arg("wtns")
                        .arg("check")
                        .arg(r1cs_path)
                        .arg(&witness_file)
                        .current_dir(&scripts_dir)
                        .output();
                    
                    match check_output {
                        Ok(check_result) => {
                            if check_result.status.success() {
                                println!("  P{}: ✓ ZK proof verification successful", party_id);
                            } else {
                                println!("  P{}: ✗ ZK proof verification failed", party_id);
                                println!("    stderr: {}", String::from_utf8_lossy(&check_result.stderr));
                            }
                        }
                        Err(e) => {
                            println!("  P{}: ✗ Failed to check constraints: {}", party_id, e);
                        }
                    }
                    
                    // Clean up witness file
                    let _ = fs::remove_file(scripts_dir.join(&witness_file));
                } else {
                    println!("  P{}: ✗ Witness calculation failed", party_id);
                    println!("    stdout: {}", String::from_utf8_lossy(&result.stdout));
                    println!("    stderr: {}", String::from_utf8_lossy(&result.stderr));
                }
            }
            Err(e) => {
                println!("  P{}: ✗ Failed to execute witness calculation: {}", party_id, e);
            }
        }
    }
}