// use anyhow::Result;
use num_bigint::BigUint;
use shamir_rs::Scheme;
// use evolvingDKG::{key_gen, read_keys, Party, PartyList, PKI, BabyJubJubPK, BabyJubJubSK, setup_zk::CircuitSetup, circom_encryption::EncryptionCircuit, elgamal::{self, ElGamalCiphertext}};
use evolvingDKG::{key_gen, read_keys, Party, PartyList ,PKI, BabyJubJubPK, BabyJubJubSK, };
use std::str::FromStr;
use rand::{rngs::StdRng, SeedableRng, Rng};
// use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
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

    // for each old party
    // for each new party
        // split old party share

    println!("================Round 2=================");




    Ok(())
}