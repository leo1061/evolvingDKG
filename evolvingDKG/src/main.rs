use anyhow::Result;
use evolvingDKG::{protocol_init::ProtocolInitializer, round1::Round1Executor, round2::Round2Executor};
use rand::{rngs::StdRng, SeedableRng};
use num_bigint::BigUint;
use std::str::FromStr;

fn main() -> Result<()> {
    // Protocol parameters
    let n_array = [5, 3, 4]; // number of parties in each generation
    let t_array = [3, 2, 2]; // threshold for each generation
    let _g_max = 2; // total generations after initialization

    let mut g = 0; // current generation
    let mut n = n_array[0]; // total number of parties
    let mut t = t_array[0]; // threshold for reconstruction

    // Initialize the protocol
    let mut initializer = ProtocolInitializer::new(n, t, g)?;
    initializer.initialize_protocol()?;

    // Increment generation for Round 1
    g += 1;
    n = n_array[g as usize];
    t = t_array[g as usize];

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
    let prev_generation_total = n_array[0]; // Total parties from generation 0 (5 parties)
    let mut round1_executor = Round1Executor::new(
        participating_parties.clone(),
        initializer.pki.clone(),
        t,
        n,
        g,
        prev_generation_total,
        rng,
    )?;
    
    let evolving_messages = round1_executor.execute_round1()?;

    // ======================================================================
    // Round 2 of Evolving DKG Protocol
    // ======================================================================
    
    // Simulate network broadcast - collect received messages for each new party
    let mut received_evolving_messages: Vec<Vec<_>> = vec![Vec::new(); n as usize];
    
    for (_j, messages_from_j) in evolving_messages.iter().enumerate() {
        for (k, message) in messages_from_j.iter().enumerate() {
            // Broadcast σ̃_{j,k} to new party k
            received_evolving_messages[k].push(message.clone());
        }
    }
    
    // Execute Round 2
    let mut round2_executor = Round2Executor::new(
        round1_executor.new_parties,
        received_evolving_messages,
        n,
        n, // ng = n for this example
    );
    
    round2_executor.execute_round2()?;

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
                index: (i + 1) as u32, // Convert to 1-based indexing for Shamir
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
        let current_n = n_array[g as usize];
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
        // The scheme needs to support the actual party indices (5, 6, 7), so we need n >= max_index
        let max_party_index = round2_executor.new_parties.iter().map(|p| p.index).max().unwrap_or(current_n);
        let scheme_n = std::cmp::max(current_n, max_party_index) as usize;
        let prime = BigUint::from_str("340282366920938463463374607431768211297")?;
        let current_scheme = shamir_rs::Scheme::new(current_threshold as usize, scheme_n, prime)?;
        println!("Created scheme with threshold={}, n={} to support party indices up to {}", 
                 current_threshold, scheme_n, max_party_index);
        
        match round2_executor.reconstruct_secret_from_new_parties(&current_scheme, current_threshold as usize) {
            Ok(reconstructed_secret) => {
                println!("Reconstructed secret from new parties: {}", reconstructed_secret);
                
                if &reconstructed_secret == original_secret {
                    println!("\n✅ SUCCESS: Reconstructed secret matches original secret!");
                    println!("The evolving DKG protocol correctly preserved the secret through the evolution process.");
                } else {
                    println!("\n❌ FAILURE: Reconstructed secret does not match original secret!");
                    println!("Expected: {}", original_secret);
                    println!("Got:      {}", reconstructed_secret);
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
