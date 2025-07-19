// use anyhow::Result;
use num_bigint::BigUint;
use shamir_rs::{Scheme, ;
use shamir_rs::Share as SsShare;
// use evolvingDKG::{key_gen, read_keys, Party, PartyList, PKI, BabyJubJubPK, BabyJubJubSK, setup_zk::CircuitSetup, circom_encryption::EncryptionCircuit, elgamal::{self, ElGamalCiphertext}};
use evolvingDKG::{key_gen, read_keys, SigmaTilde, Party, PKI, elgamal::ElGamalCiphertext};
use ark_ed_on_bn254::{EdwardsProjective, Fr, Fq};
use ark_ec::{PrimeGroup, CurveGroup};
use ark_ff::{PrimeField, UniformRand, BigInteger, One, Zero};
use std::str::FromStr;
use rand::{rngs::StdRng, SeedableRng, Rng};
// use serde_json::Value;
// use group::GroupEncoding;
use rayon::prelude::*;
use anyhow::Result;

fn debug_print(debug: bool, message: &str) {
    if debug {
        println!("{}", message);
    }
}

const MAX_ATTEMPTS: usize = 20_000; //need to have percentage based number

/// Generate a random field element that is compatible with Elligator2
/// This function tries random field elements until it finds one that can be encoded/decoded
fn generate_elligator2_compatible_fr(rng: &mut StdRng) -> Fr {
    let a = evolvingDKG::curve_converter::CurveConverter::montgomery_a();
    let b = evolvingDKG::curve_converter::CurveConverter::montgomery_b();
    
    loop {
        // Generate a random Fr
        let random_fr = Fr::rand(rng);
        
        // Convert to Fq for Elligator2 testing
        let fr_bytes = random_fr.into_bigint().to_bytes_le();
        let field_element = Fq::from_le_bytes_mod_order(&fr_bytes);
        
        // Try to encode with Elligator2
        if let Some((x_mont, y_mont)) = evolvingDKG::curve_converter::Elligator2::encode(&field_element, &a, &b) {
            // Try to decode back
            if let Some(decoded_element) = evolvingDKG::curve_converter::Elligator2::decode(&x_mont, &y_mont, &a, &b) {
                // Convert back to Fr and verify round-trip
                let decoded_bytes = decoded_element.into_bigint().to_bytes_le();
                let decoded_fr = Fr::from_le_bytes_mod_order(&decoded_bytes);
                
                if decoded_fr == random_fr {
                    return random_fr;
                }
            }
        }
        // If we get here, this random_fr is not compatible, try another one
    }
}

/// Convert an Elligator2-compatible Fr to BigUint for use with Shamir scheme
fn fr_to_biguint(fr: &Fr) -> BigUint {
    let bytes = fr.into_bigint().to_bytes_le();
    BigUint::from_bytes_le(&bytes)
}

/// Convert BigUint back to Fr (for checking Elligator2 compatibility)
fn biguint_to_fr(big: &BigUint) -> Fr {
    let bytes = big.to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Check if a BigUint (when converted to Fr) is Elligator2-compatible
fn is_elligator2_compatible(big: &BigUint) -> bool {
    let fr = biguint_to_fr(big);
    let a = evolvingDKG::curve_converter::CurveConverter::montgomery_a();
    let b = evolvingDKG::curve_converter::CurveConverter::montgomery_b();
    
    // Convert to Fq for Elligator2 testing
    let fr_bytes = fr.into_bigint().to_bytes_le();
    let field_element = Fq::from_le_bytes_mod_order(&fr_bytes);
    
    // Try to encode with Elligator2
    if let Some((x_mont, y_mont)) = evolvingDKG::curve_converter::Elligator2::encode(&field_element, &a, &b) {
        // Try to decode back
        if let Some(decoded_element) = evolvingDKG::curve_converter::Elligator2::decode(&x_mont, &y_mont, &a, &b) {
            // Convert back to Fr and verify round-trip
            let decoded_bytes = decoded_element.into_bigint().to_bytes_le();
            let decoded_fr = Fr::from_le_bytes_mod_order(&decoded_bytes);
            
            return decoded_fr == fr;
        }
    }
    false
}

/// Check if all shares in a vector are Elligator2-compatible
fn are_all_shares_elligator2_compatible(shares: &[shamir_rs::Share]) -> bool {
    shares.iter().all(|share| is_elligator2_compatible(&share.value))
}

/// Generate Shamir shares that are all Elligator2-compatible
/// Retries the secret sharing until all resulting shares are compatible
fn generate_elligator2_compatible_shares(
    secret: &BigUint,
    scheme: &Scheme,
    max_attempts: usize,
    debug: bool,
) -> Vec<shamir_rs::Share> {
    let mut best_shares = Vec::new();
    let mut best_compatible_count = 0;
    
    for attempt in 1..=max_attempts {
        let shares = scheme.split_secret(secret);
        let compatible_count = shares.iter()
            .filter(|share| is_elligator2_compatible(&share.value))
            .count();
        
        if compatible_count > best_compatible_count {
            best_compatible_count = compatible_count;
            best_shares = shares.clone();
        }
        
        if are_all_shares_elligator2_compatible(&shares) {
            if debug && attempt > 1 {
                println!("  ✓ Found ALL {}/{} Elligator2-compatible shares after {} attempts", 
                         shares.len(), shares.len(), attempt);
            }
            return shares;
        } else if debug && attempt <= 10 {
            println!("  Attempt {}: {}/{} shares are Elligator2-compatible", 
                     attempt, compatible_count, shares.len());
        } else if debug && attempt % 100 == 0 {
            println!("  Attempt {}: Best so far {}/{} compatible shares", 
                     attempt, best_compatible_count, best_shares.len());
        }
    }
    
    // If we couldn't find all compatible, return the best we found
    println!("  ⚠ Using best result: {}/{} Elligator2-compatible shares after {} attempts", 
             best_compatible_count, best_shares.len(), max_attempts);
    best_shares
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Debug flag
    let debug = false;

    println!("================Pre initialization=================");

    // Protocol parameters
    let ng_array = [3,3,4]; // number of NEW parties in each generation
    let t_array = [2,2,2]; // threshold for each generation
    let g_max = 2; // total generations after initialization

    let mut g = 0; // current generation
    let mut ng = ng_array[0]; // number of new parties in current generation
    let mut n = ng; // total number of parties (initially n = ng for generation 0)
    let mut t = t_array[0]; // threshold for reconstruction
    
    // Use the actual Fr field modulus for compatibility
    let prime = BigUint::from_str("2736030358979909402780800718157159386076813972158567259200215660948447373041")?; // Fr modulus
    println!("\nUsing Fr field modulus: {}", prime);
    
    // Create the Shamir scheme
    let scheme = Scheme::new(t as usize, ng as usize, prime.clone())?;
    // Initialize RNG for generating random secrets
    let mut rng = StdRng::seed_from_u64(0x12345678);
    
    // crerate zk SRS
    // let setup = CircuitSetup::new("build");
    // setup.setup_all()?;



    println!("================Initialization=================");
    // Generate keys for each party
    println!("\n--- Step0: Initialize parties ---");
    
    // Create all key generation tasks for parallel execution
    let key_tasks: Vec<usize> = (0..ng).collect();
    
    // Generate keys in parallel
    let key_results: Result<Vec<Party>> = key_tasks
        .par_iter()
        .map(|&i| -> Result<Party> {
            println!("Generating keys for party {}", i);
            let party_id = i as u32;
            key_gen(party_id)?;
            let (sk, pk) = read_keys(party_id);
            let party = Party::new(party_id, g, sk, pk)?;
            Ok(party)
        })
        .collect();
    
    let mut parties = key_results?;

    // Add all public keys to a PKI. 
    let mut pki = PKI::new();
    for party in &parties {
        pki.add_public_key(party.share.pk.clone());
    }

    println!("Current state of PKI: {}", pki);
    
    println!("\n--- Step1: Each party creates a random secret ---");
    let mut party_secrets: Vec<BigUint> = Vec::new();
    for i in 0..ng {
        // Generate Elligator2-compatible secret
        let elligator2_compatible_fr = generate_elligator2_compatible_fr(&mut rng);
        let secret = fr_to_biguint(&elligator2_compatible_fr);
        party_secrets.push(secret.clone());
        debug_print(debug, &format!("Party {} generated Elligator2-compatible secret: {}", i, secret));
    }
    
    println!("\n--- Step 2: Creating secret shares (ensuring Elligator2 compatibility) ---");
    let mut all_shares: Vec<Vec<shamir_rs::Share>> = Vec::new();
    for i in 0..ng {
        println!("Party {} generating Elligator2-compatible shares...", i);
        let shares = generate_elligator2_compatible_shares(
            &party_secrets[i as usize], 
            &scheme, 
            MAX_ATTEMPTS, // max attempts
            false // reduced debug output
        );
        debug_print(debug, &format!("Party {} has those shares: {:?}", i, shares));
        all_shares.push(shares.clone());
        println!("Party {} created {} Elligator2-compatible shares", i, shares.len());
    }
    // create keys for each party

    // println!("All Shares: {:?}", all_shares);

    // Create received_shares: transpose of all_shares
    // received_shares[j] contains all shares that party j receives
    let mut received_shares: Vec<Vec<shamir_rs::Share>> = vec![Vec::new(); ng as usize];
    for i in 0..ng {
        for j in 0..ng {
            // Party j receives the j-th share from party i
            received_shares[j as usize].push(all_shares[i as usize][j as usize].clone());
        }
    }
    
    debug_print(debug, "\n--- Received shares (transpose) ---");
    for j in 0..ng {
        debug_print(debug, &format!("Party {} received shares: {:?}", j, received_shares[j as usize]));
    }

    // Create final_shares: sum of shares for each party
    let mut final_shares: Vec<BigUint> = Vec::new();
    for j in 0..ng {
        let mut sum = BigUint::from(0u32);
        for share in &received_shares[j as usize] {
            sum = (sum + &share.value) % &prime;
        }
        final_shares.push(sum.clone());
        parties[j as usize].set_share(sum.clone());

        println!("Party {} final share: {}", j, sum);
    }

    debug_print(debug, &format!("{:?}", parties));

    // Create an aggregated private key as a sum of the final_shares components
    let mut aggregated_private_key = BigUint::from(0u32);
    for share in &final_shares {
        aggregated_private_key = (aggregated_private_key + share) % &prime;
    }
    println!("\nAggregated private key: {}", aggregated_private_key);
    
    // From that aggregated private key compute an aggregated public key which basically is a point on the baby jubjub curve
    let aggregated_private_key_fr = Fr::from_str(&aggregated_private_key.to_string()).unwrap();
    let aggregated_public_key = EdwardsProjective::generator() * aggregated_private_key_fr;
    let aggregated_public_key_affine = aggregated_public_key.into_affine();
    
    println!("Aggregated public key: ({}, {})", 
             aggregated_public_key_affine.x, 
             aggregated_public_key_affine.y);
    
    
    
    println!("\n================Round 1=================");

    // Update generation and party counts for Round 1
    g = 1;
    let old_n = n;
    let old_t = t;
    ng = ng_array[g as usize];
    n = old_n + ng;
    t = t_array[g as usize];
    
    println!("Round 1 parameters: old_n={}, old_t={}, new ng={}, total n={}, new t={}", 
             old_n, old_t, ng, n, t);
    
    // Generate keys for new parties (indices old_n to n-1) and add to PKI
    println!("\n--- Generating keys for new parties ---");
    let mut new_parties: Vec<Party> = Vec::new();
    
    // Generate keys in parallel for new parties
    let new_party_tasks: Vec<usize> = (old_n..n).map(|i| i as usize).collect();
    let new_party_results: Result<Vec<Party>> = new_party_tasks
        .par_iter()
        .map(|&i| -> Result<Party> {
            println!("Generating keys for new party {}", i);
            let party_id = i as u32;
            key_gen(party_id)?;
            let (sk, pk) = read_keys(party_id);
            let party = Party::new(party_id, g, sk, pk)?;
            Ok(party)
        })
        .collect();
    
    new_parties = new_party_results?;
    
    // Add new parties' public keys to PKI
    for party in &new_parties {
        pki.add_public_key(party.share.pk.clone());
    }
    
    println!("Added {} new parties to PKI", new_parties.len());
    println!("PKI now contains {} total keys", pki.keys.len());

    // Select exactly `old_t` parties to be online (instead of all old parties)
    let online_old_parties: Vec<usize> = (0..old_t as usize).collect();
    println!("Online old parties: {:?}", online_old_parties);
    
    
    // Create variable to store all sigma_tilde
    let mut all_sigma_tilde: Vec<SigmaTilde> = Vec::new();
    
    // Get the generator of BabyJubJub curve
    let generator = EdwardsProjective::generator();
    
    // Create new Shamir scheme for the new total number of parties
    let new_scheme = Scheme::new(t as usize, n as usize, prime.clone())?;
    
    // For each old party i among those online
    for &i in &online_old_parties {
        let old_party_share = &parties[i].share.share;
        
        // Create commitment of share as share*G
        let share_scalar = Fr::from_str(&old_party_share.to_string()).unwrap();
        let commitment = generator * share_scalar;
        
        // Shamir split old party share to get x_{i,k} for k = {1..n} (ensuring Elligator2 compatibility)
        println!("Old party {} generating Elligator2-compatible shares for new scheme...", i);
        let shares = generate_elligator2_compatible_shares(
            old_party_share, 
            &new_scheme, 
            MAX_ATTEMPTS, // max attempts
            false // reduced debug output
        );
        
        // For each new party j (new parties have indices from old_n to n-1)
        for j in old_n..n {
            let j_idx = j as usize;
            
            // Get party j's public key from PKI for encryption
            let new_party = &new_parties[j_idx - old_n as usize]; // j_idx is in range [old_n, n)
            let elgamal_sk_bigint = &new_party.share.sk.value;
            let elgamal_sk = Fr::from_str(&elgamal_sk_bigint.to_string()).unwrap();
            let elgamal_pk = EdwardsProjective::generator() * elgamal_sk;
            
            // Collect all shares, encrypting them with party j's public key
            let mut encrypted_shares_for_others = Vec::new();

            for (idx, share) in shares.iter().enumerate() {
                if idx != j_idx {  // Don't include the share for party j itself
                    // Convert share to Fr for ElGamal encryption
                    let share_as_fr = Fr::from_str(&share.value.to_string()).unwrap();
                    
                    // Check if this share is Elligator2-compatible
                    let is_compatible = is_elligator2_compatible(&share.value);
                    debug_print(debug, &format!(
                        "Share idx={} for new_party={} is Elligator2-compatible: {}", 
                        idx, j_idx, is_compatible
                    ));
                    
                    // Encrypt the share using party j's public key
                    let mut rng = StdRng::seed_from_u64(0x12345678 + (i * 1000 + j_idx * 100 + idx) as u64);
                    
                    if let Ok(encrypted_share) = evolvingDKG::elgamal::ElGamal::encrypt_scalar(&elgamal_pk, &share_as_fr, &mut rng) {
                        // Test round-trip to verify encryption works
                        if let Some(decrypted_share) = evolvingDKG::elgamal::ElGamal::decrypt_to_scalar(&encrypted_share, &elgamal_sk) {
                            // Assert equality for round-trip verification
                            assert_eq!(share_as_fr, decrypted_share, 
                                "ElGamal round-trip failed for old_party={}, new_party={}, share_idx={}", i, j_idx, idx);
                            
                            debug_print(debug, &format!(
                                "✓ ElGamal round-trip successful for old_party={}, new_party={}, share_idx={}", i, j_idx, idx
                            ));
                            
                            encrypted_shares_for_others.push((idx, encrypted_share));
                        } else {
                            debug_print(debug, &format!(
                                "⚠ ElGamal decryption failed for old_party={}, new_party={}, share_idx={} (Elligator2 limitation)", i, j_idx, idx
                            ));
                        }
                    } else {
                        debug_print(debug, &format!(
                            "⚠ ElGamal encryption failed for old_party={}, new_party={}, share_idx={} (Elligator2 limitation)", i, j_idx, idx
                        ));
                    }
                }
            }
            
            // Create sigma_tilde with encrypted shares
            let sigma_tilde = SigmaTilde {
                old_party_index: i,
                new_party_index: j_idx,
                commitment: commitment.clone(),
                encrypted_shares: encrypted_shares_for_others
            };
            
            // Add to all_sigma_tilde
            all_sigma_tilde.push(sigma_tilde);

        }
    }
    
    // Debug print all_sigma_tilde
    debug_print(debug, &format!("all_sigma_tilde length: {}", all_sigma_tilde.len()));
    for sigma in &all_sigma_tilde {
        debug_print(debug, &format!(
            "SigmaTilde: old_party={}, new_party={}, encrypted_shares_count={}", 
            sigma.old_party_index, sigma.new_party_index, sigma.encrypted_shares.len()
        ));
    }
    
    println!("Created {} sigma_tilde entries", all_sigma_tilde.len());
    println!("================Round 2=================");

    // Process shares for each new party
    let mut new_party_final_shares: Vec<BigUint> = Vec::new();
    
    // For each new party j
    for j in old_n..n {
        let j_idx = j as usize;
        let new_party = &new_parties[j_idx - old_n as usize];
        
        println!("\n--- Processing shares for new party {} ---", j);
        
        // Collect all shares that party j receives from old parties
        let mut shares_from_old_parties: Vec<BigUint> = Vec::new();
        let mut decryption_count = 0;
        let mut j_final_share = BigUint::from(0u32);
        
        // Find all sigma_tilde entries for this new party
        for sigma_tilde in &all_sigma_tilde {
            if sigma_tilde.new_party_index == j_idx {
                // Decrypt the shares using party j's secret key
                let elgamal_sk = Fr::from_str(&new_party.share.sk.value.to_string()).unwrap();
                // Find the encrypted share for party j
                let encrypted_share = &sigma_tilde.encrypted_shares[0].1; // Assuming we want the first encrypted share
                
                
                // Also decrypt the shares that were encrypted for party j
                // (these are shares intended for other parties but encrypted with j's key) 
                if let Some(decrypted_fr) = evolvingDKG::elgamal::ElGamal::decrypt_to_scalar(encrypted_share, &elgamal_sk) {
                    decryption_count += 1;
                    debug_print(debug, &format!("  Decrypted share from old party {}", sigma_tilde.old_party_index));
                    j_final_share = (j_final_share + fr_to_biguint(&decrypted_fr)) % &prime;
                }
            }
        
        }
        
        println!("  Received {} shares from old parties", shares_from_old_parties.len());
        println!("  Successfully decrypted {} encrypted shares", decryption_count);
        

        
        new_party_final_shares.push(j_final_share.clone());
        println!("  New party {} final share: {}", j, j_final_share);
        
        // Create commitment for verification
        let share_scalar = Fr::from_str(&j_final_share.to_string()).unwrap();
        let commitment = EdwardsProjective::generator() * share_scalar;
        debug_print(debug, &format!("  New party {} commitment: {:?}", j, commitment));
    }
    
    // Combine all parties' shares (old + new) to verify the aggregate keys
    println!("\n--- Verifying aggregate keys ---");
    
    // Collect all final shares
    let mut all_final_shares: Vec<BigUint> = Vec::new();
    
    // Add old parties' shares (only the online ones that participated)
    // for &i in &online_old_parties {
    //     all_final_shares.push(parties[i].share.share.clone());
    // }
    
    // Add new parties' shares
    all_final_shares.extend(new_party_final_shares.clone());
    
    // Calculate the new aggregated private key
    let mut new_aggregated_private_key = BigUint::from(0u32);
    for share in &all_final_shares {
        new_aggregated_private_key = (new_aggregated_private_key + share) % &prime;
    }
    
    println!("\nNew aggregated private key: {}", new_aggregated_private_key);
    
    // Calculate the new aggregated public key
    let new_aggregated_private_key_fr = Fr::from_str(&new_aggregated_private_key.to_string()).unwrap();
    let new_aggregated_public_key = EdwardsProjective::generator() * new_aggregated_private_key_fr;
    let new_aggregated_public_key_affine = new_aggregated_public_key.into_affine();
    
    println!("New aggregated public key: ({}, {})", 
             new_aggregated_public_key_affine.x, 
             new_aggregated_public_key_affine.y);
    
    // Verify that the aggregate keys match
    if aggregated_private_key == new_aggregated_private_key {
        println!("\n✓ SUCCESS: Aggregate private keys match!");
    } else {
        println!("\n✗ ERROR: Aggregate private keys do NOT match!");
        println!("  Original: {}", aggregated_private_key);
        println!("  New:      {}", new_aggregated_private_key);
    }
    
    if aggregated_public_key_affine == new_aggregated_public_key_affine {
        println!("✓ SUCCESS: Aggregate public keys match!");
    } else {
        println!("✗ ERROR: Aggregate public keys do NOT match!");
        println!("  Original: ({}, {})", aggregated_public_key_affine.x, aggregated_public_key_affine.y);
        println!("  New:      ({}, {})", new_aggregated_public_key_affine.x, new_aggregated_public_key_affine.y);
    }

    Ok(())
}
