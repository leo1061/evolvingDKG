// use anyhow::Result;
use num_bigint::BigUint;
use shamir_rs::Scheme;
// use evolvingDKG::{key_gen, read_keys, Party, PartyList, PKI, BabyJubJubPK, BabyJubJubSK, setup_zk::CircuitSetup, circom_encryption::EncryptionCircuit, elgamal::{self, ElGamalCiphertext}};
use evolvingDKG::{key_gen, read_keys, SigmaTilde, Party, PKI};
use ark_ed_on_bn254::{EdwardsProjective, Fr};
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
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


fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Debug flag
    let debug = true;

    println!("================Pre initialization=================");

    // Protocol parameters
    let ng_array = [3,3,4]; // number of NEW parties in each generation
    let t_array = [2,2,2]; // threshold for each generation
    let g_max = 2; // total generations after initialization

    let mut g = 0; // current generation
    let mut ng = ng_array[0]; // number of new parties in current generation
    let mut n = ng; // total number of parties (initially n = ng for generation 0)
    let mut t = t_array[0]; // threshold for reconstruction
    
    // Choose a large prime for the field
    let prime = BigUint::from_str("340282366920938463463374607431768211297")?;
    println!("\nUsing prime field of size: {}", prime);
    
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
        let secret = BigUint::from(rng.gen::<u64>()) % &prime; // Random secret for demo
        party_secrets.push(secret.clone());
        debug_print(debug, &format!("Party {} generated secret: {}", i, secret));
    }
    
    println!("\n--- Step 2: Creating secret shares ---");
    let mut all_shares: Vec<Vec<shamir_rs::Share>> = Vec::new();
    for i in 0..ng {
        let shares = scheme.split_secret(&party_secrets[i as usize]);
        debug_print(debug, &format!("Party {} has those shares: {:?}", i, shares));
        all_shares.push(shares.clone());
        println!("Party {} created {} shares of their secret", i, shares.len());
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
    println!("================Round 1=================");

    // Update generation and party counts for Round 1
    g = 1;
    let old_n = n;
    let old_t = t;
    ng = ng_array[g as usize];
    n = old_n + ng;
    t = t_array[g as usize];
    
    println!("Round 1 parameters: old_n={}, old_t={}, new ng={}, total n={}, new t={}", 
             old_n, old_t, ng, n, t);
    
    // Decide which parties of old t are online (for demo, assume all old parties are online)
    let online_old_parties: Vec<usize> = (0..old_n as usize).collect();
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
        
        // Shamir split old party share to get x_{i,k} for k = {1..n}
        let shares = new_scheme.split_secret(old_party_share);
        
        // For each new party j (new parties have indices from old_n to n-1)
        for j in old_n..n {
            let j_idx = j as usize;
            
            // Collect all shares except the one for party j
            let mut shares_for_others = Vec::new();
            for (idx, share) in shares.iter().enumerate() {
                if idx != j_idx {
                    shares_for_others.push((idx, share.value.clone()));
                }
            }
            
            // Create sigma_tilde
            let sigma_tilde = SigmaTilde {
                old_party_index: i,
                new_party_index: j_idx,
                commitment: commitment.clone(),
                shares_for_others,
                share_for_recipient: shares[j_idx].value.clone(),
            };
            
            // Add to all_sigma_tilde
            all_sigma_tilde.push(sigma_tilde);
        }
    }
    
    // Debug print all_sigma_tilde
    debug_print(debug, &format!("all_sigma_tilde length: {}", all_sigma_tilde.len()));
    for sigma in &all_sigma_tilde {
        debug_print(debug, &format!(
            "SigmaTilde: old_party={}, new_party={}, share_for_recipient={}", 
            sigma.old_party_index, sigma.new_party_index, sigma.share_for_recipient
        ));
    }
    
    println!("Created {} sigma_tilde entries", all_sigma_tilde.len());
    println!("================Round 2=================");



    // at the end of round 2, check that everything is working 
    // i.e.: aggregate priv and pub keys are the same as in the init phase


    Ok(())
}
