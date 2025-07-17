use anyhow::Result;
use evolvingDKG::{protocol_init::ProtocolInitializer, round1::Round1Executor, round2::Round2Executor, elgamal_numeric};
use rand::{rngs::StdRng, SeedableRng};
use num_bigint::{BigUint, BigInt, Sign};
use std::str::FromStr;

fn main() -> Result<()> {
    // Protocol parameters
    let n_array = [5, 3, 4]; // number of parties in each generation
    let t_array = [3, 2, 2]; // threshold for each generation
    let _g_max = 2; // total generations after initialization

    let mut g = 0; // current generation
    let mut total_parties = 0; // total number of parties accumulated
    let mut t = t_array[0]; // threshold for reconstruction

    // Generation 0 (Initialization)
    let new_parties_current_gen = n_array[0]; // Number of new parties in this generation
    total_parties += new_parties_current_gen; // Update total parties

    // ======================================================================
    // ElGamal Key Generation and Encryption Demo
    // ======================================================================
    
    println!("=== ElGamal Key Generation and Encryption Demo ===");
    
    // Generate ElGamal keypair
    let elgamal_keypair = elgamal_numeric::generate_keypair(512);
    println!("Generated ElGamal keypair with {} bit prime", 512);
    
    // Test message encryption/decryption
    let test_message = BigInt::from(42);
    println!("Original message: {}", test_message);
    
    let ciphertext = elgamal_keypair.encrypt(&test_message);
    println!("Encrypted ciphertext: c1={}, c2={}", ciphertext.c1, ciphertext.c2);
    
    let decrypted = elgamal_keypair.decrypt(&ciphertext);
    println!("Decrypted message: {}", decrypted);
    
    if decrypted == test_message {
        println!("✅ ElGamal encryption/decryption test: SUCCESS");
    } else {
        println!("❌ ElGamal encryption/decryption test: FAILED");
    }
    
    // ======================================================================
    // DKG Protocol Initialization
    // ======================================================================
    
    println!("\n=== DKG Protocol Initialization ===");
    
    // Initialize the protocol
    let mut initializer = ProtocolInitializer::new(total_parties, t, g)?;
    initializer.initialize_protocol()?;

    // Increment generation for Round 1
    g += 1;
    let new_parties_current_gen = n_array[g as usize]; // Number of new parties in this generation
    t = t_array[g as usize]; // Threshold for this generation

    // ======================================================================
    // Round 1 of Evolving DKG Protocol
    // ======================================================================
    
    // Round 1 - Let I be a set of parties in generation g-1 such that |I| = t_array[g]
    let prev_threshold = t_array[g as usize - 1]; // threshold for current generation determines how many parties from previous generation participate
    println!("Selecting {} parties from previous generation to participate", prev_threshold);
    
    // Select the first t parties from the previous generation (parties vector)
    let participating_parties: Vec<_> = initializer.parties.iter().take(prev_threshold as usize).cloned().collect();
    println!("Selected parties: {:?}", participating_parties.iter().map(|p| p.index).collect::<Vec<_>>());
    
    // Create new RNG for Round 1
    let rng = StdRng::seed_from_u64(0x12345678);
    
    // Execute Round 1
    let prev_generation_total = total_parties; // Total parties from previous generation
    let mut round1_executor = Round1Executor::new(
        participating_parties.clone(),
        initializer.pki.clone(),
        t,
        new_parties_current_gen, // n in Round1Executor is the number of new parties
        g,
        prev_generation_total,
        rng,
    )?;
    
    let evolving_messages = round1_executor.execute_round1()?;

    // Update total parties after Round 1 (new parties are added)
    total_parties += new_parties_current_gen;

    // ======================================================================
    // Round 2 of Evolving DKG Protocol
    // ======================================================================
    
    // Simulate network broadcast - collect received messages for each new party
    // The size of received_evolving_messages should be based on the number of *new* parties
    let mut received_evolving_messages: Vec<Vec<_>> = vec![Vec::new(); new_parties_current_gen as usize];
    
    for (_j, messages_from_j) in evolving_messages.iter().enumerate() {
        for (k_relative, message) in messages_from_j.iter().enumerate() {
            // Broadcast σ̃_{j,k} to new party k. k_relative is the index within the new parties.
            received_evolving_messages[k_relative].push(message.clone());
        }
    }
    
    // Execute Round 2
    let mut round2_executor = Round2Executor::new(
        round1_executor.new_parties,
        received_evolving_messages,
        total_parties, // n in Round2Executor is the total number of parties
        new_parties_current_gen, // ng in Round2Executor is the number of new parties
    );
    
    round2_executor.execute_round2()?;

    // ======================================================================
    // ElGamal Share Encryption Demo
    // ======================================================================
    
    println!("\n=== ElGamal Share Encryption Demo ===");
    
    // Encrypt shares using ElGamal
    let encrypted_shares: Vec<_> = participating_parties.iter()
        .map(|party| {
            let share_as_bigint = BigInt::from_bytes_be(Sign::Plus, &party.share.share.to_bytes_be());
            let encrypted_share = elgamal_keypair.encrypt(&share_as_bigint);
            println!("Party {}: share={}, encrypted to c1={}, c2={}", 
                     party.index, party.share.share, encrypted_share.c1, encrypted_share.c2);
            encrypted_share
        })
        .collect();
    
    // Decrypt and verify shares
    let decrypted_shares: Vec<_> = encrypted_shares.iter()
        .enumerate()
        .map(|(i, ciphertext)| {
            let decrypted = elgamal_keypair.decrypt(ciphertext);
            let original_share = BigInt::from_bytes_be(Sign::Plus, &participating_parties[i].share.share.to_bytes_be());
            if decrypted == original_share {
                println!("✅ Party {} share encryption/decryption: SUCCESS", participating_parties[i].index);
            } else {
                println!("❌ Party {} share encryption/decryption: FAILED", participating_parties[i].index);
            }
            decrypted
        })
        .collect();
    
    println!("Encrypted {} shares successfully", encrypted_shares.len());
    
    // ======================================================================
    // Secret Reconstruction Verification
    // ======================================================================
    
    println!("\n=== Verifying Secret Reconstruction ===");
    
    // Get the original secret from the initialization phase
    if let Some(original_secret) = initializer.get_original_secret() {
        println!("Original secret from initialization: {}", original_secret);
        
        // Debug: Let's also verify that the original parties can still reconstruct the secret
        println!("\n--- Verifying original parties can still reconstruct ---");
        let mut original_shares = Vec::new();
        for (i, party) in participating_parties.iter().enumerate() {
            println!("Original party {}: index={}, share={}", 
                     i, party.index, party.share.share);
            let share = shamir_rs::Share {
                index: party.index as u32 + 1, // Use the actual party index
                value: party.share.share.clone(),
            };
            original_shares.push(share);
        }
        
        if let Ok(original_reconstructed) = initializer.scheme.reconstruct_secret(&original_shares) {
            println!("Secret reconstructed from original parties: {}", original_reconstructed);
            if &original_reconstructed == original_secret {
                println!("✅ Original parties reconstruction: SUCCESS");
            } else {
                println!("❌ Original parties reconstruction: FAILED");
            }
        } else {
            println!("❌ Failed to reconstruct from original parties");
        }
        
        // Reconstruct the secret using the new parties after Round 2  
        // Create a new scheme that matches the current generation's parameters
        let current_threshold = t_array[g as usize];
        // The current_n here refers to the number of *new* parties in this generation
        let new_parties_in_current_gen = n_array[g as usize];
        println!("Attempting to reconstruct secret using {} new parties (current threshold: {})", 
                 round2_executor.get_final_shares().len(), current_threshold);
        
        // Debug: Show the party indices and their shares
        for (i, share_tuple) in round2_executor.get_final_shares().iter().enumerate() {
            println!("New party {}: index={}, share={}", 
                     i, 
                     round2_executor.new_parties[i].index, 
                     share_tuple.x_i);
        }
        
        // Create a new scheme for the current generation  
        // The scheme needs to support the actual party indices (e.g., 5, 6, 7), so we need n >= max_index
        let max_party_index = round2_executor.new_parties.iter().map(|p| p.index).max().unwrap_or(new_parties_in_current_gen);
        // The scheme_n should be the total number of parties to cover all possible indices
        let scheme_n = std::cmp::max(total_parties, max_party_index) as usize;
        let prime = BigUint::from_str("340282366920938463463374607431768211297")?;
        let current_scheme = shamir_rs::Scheme::new(current_threshold as usize, scheme_n, prime)?;
        println!("Created scheme with threshold={}, n={} to support party indices up to {}", 
                 current_threshold, scheme_n, max_party_index);
        
        let new_party_indices: Vec<u32> = round2_executor.new_parties.iter().map(|p| p.index).collect();
        
        match round2_executor.reconstruct_secret_from_new_parties(&current_scheme, current_threshold as usize, &new_party_indices) {
            Ok(reconstructed_secret) => {
                // Apply modular reduction to the reconstructed secret
                let prime = BigUint::from_str("340282366920938463463374607431768211297")?;
                let reconstructed_secret_reduced = &reconstructed_secret % &prime;
                
                println!("Reconstructed secret from new parties: {} (reduced from {})", reconstructed_secret_reduced, reconstructed_secret);
                
                if &reconstructed_secret_reduced == original_secret {
                    println!("\n✅ SUCCESS: Reconstructed secret matches original secret!");
                    println!("The evolving DKG protocol correctly preserved the secret through the evolution process.");
                } else {
                    println!("\n❌ FAILURE: Reconstructed secret does not match original secret!");
                    println!("Expected: {}", original_secret);
                    println!("Got:      {}", reconstructed_secret_reduced);
                }
            }
            Err(e) => {
                println!("\n❌ ERROR: Failed to reconstruct secret from new parties: {}", e);
            }
        }
    } else {
        println!("❌ No original secret available for comparison");
    }

    Ok(())
}
