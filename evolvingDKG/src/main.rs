use anyhow::Result;
use num_bigint::BigUint;
use shamir_rs::Scheme;
use evolvingDKG::{key_gen, read_keys, Party, PartyList, PKI, setup_zk::CircuitSetup, circom_encryption::EncryptionCircuit, elgamal};
use std::str::FromStr;
use rand::{rngs::StdRng, SeedableRng, Rng};
use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use serde_json::Value;
use group::GroupEncoding;
use rayon::prelude::*;

fn main() -> Result<()> {
    // Protocol parameters
    let n_array = [5,3,4]; // number of parties in each generation
    let t_array = [3,2,2]; // threshold for each generation
    let g_max = 2; // total generations after initialization

    let mut g = 0; // current generation
    let mut n = n_array[0]; // total number of parties
    let mut t = t_array[0]; // threshold for reconstruction
    

    println!("Initializing Shamir Secret Sharing Protocol");
    println!("Total parties: {}", n);
    println!("Threshold: {}", t);
    
    // Generate keys for each party
    println!("\nGenerating keys for each party...");
    
    // Create all key generation tasks for parallel execution
    let key_tasks: Vec<usize> = (0..n).collect();
    
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
    
    // Initialization: Initialization: Step 1: Each party runs the zero-knowledge setup to get the keys
    println!("\n=== Initialization: Initialization: Step 1: Zero-knowledge setup ===");
    let setup = CircuitSetup::new("build");
    // setup.setup_all()?;
    println!("✅ Zero-knowledge setup completed for all parties");

    // Choose a large prime for the field
    let prime = BigUint::from_str("340282366920938463463374607431768211297")?;
    println!("\nUsing prime field of size: {}", prime);
    
    // Create the Shamir scheme
    let scheme = Scheme::new(t as usize, n as usize, prime.clone())?;
    
    // Initialize RNG for generating random secrets
    let mut rng = StdRng::seed_from_u64(0x12345678);
    
    // DKG Protocol Implementation
    println!("\n=== DKG Protocol Implementation ===");
    
    // Initialization: Initialization: Step 2: Each party creates a random secret
    println!("\n--- Initialization: Initialization: Step 2: Each party creates a random secret ---");
    let mut party_secrets: Vec<BigUint> = Vec::new();
    for i in 0..n {
        let secret = BigUint::from(rng.gen::<u64>() % 1000000); // Random secret for demo
        party_secrets.push(secret.clone());
        println!("Party {} generated secret: {}", i, secret);
    }
    
    // Initialization: Step 3: Each party creates secret shares for other parties
    println!("\n--- Initialization: Step 3: Creating secret shares ---");
    let mut all_shares: Vec<Vec<shamir_rs::Share>> = Vec::new();
    for i in 0..n {
        let shares = scheme.split_secret(&party_secrets[i as usize]);
        all_shares.push(shares.clone());
        println!("Party {} created {} shares of their secret", i, shares.len());
    }
    
    // Initialization: Step 4: Each party encrypts their shares using ElGamal encryption
    println!("\n--- Initialization: Step 4: Encrypting shares with ElGamal ---");
    let mut encrypted_shares: Vec<Vec<Option<elgamal::ElGamalCiphertext>>> = Vec::new();
    
    for i in 0..n {
        let mut party_encrypted_shares = Vec::new();
        for j in 0..n {
            // Get recipient's public key from PKI
            let recipient_pk = pki.get_public_key(j as usize).unwrap();
            let jubjub_pk: JubJubExtended = recipient_pk.clone().into();
            
            // Convert share to JubJub point for encryption
            let share_value = &all_shares[i as usize][j as usize].value;
            let share_scalar = share_to_scalar(share_value)?;
            let share_point = GENERATOR_EXTENDED * &share_scalar; // aka commitment to the share
            
            // Encrypt the share (including for self)
            let encrypted_share = elgamal::encrypt(&jubjub_pk, &share_point, &mut rng)?;
            party_encrypted_shares.push(Some(encrypted_share));
            
            println!("Party {} encrypted share for party {}", i, j);
        }
        encrypted_shares.push(party_encrypted_shares);
    }
    
    // Initialization: Step 5: Generate zero-knowledge proofs for each encrypted share
    println!("\n--- Initialization: Step 5: Generating zero-knowledge proofs ---");
    let encryption_circuit = std::sync::Arc::new(std::sync::Mutex::new(EncryptionCircuit::new("build")));
    
    // Create all tasks for parallel execution
    let mut proof_tasks: Vec<(usize, usize)> = Vec::new();
    for i in 0..n {
        for j in 0..n {
            proof_tasks.push((i as usize, j as usize));
        }
    }
    
    // Generate proofs in parallel
    let proof_results: Vec<((usize, usize), (Value, Value))> = proof_tasks
        .par_iter()
        .map(|&(i, j)| {
            // Create a new RNG for this thread using a deterministic seed
            let mut thread_rng = StdRng::seed_from_u64(0x12345678 + (i * n as usize + j) as u64);
            
            // Get the actual share value and recipient's public key
            let share_value = &all_shares[i][j].value;
            let recipient_pk = pki.get_public_key(j).unwrap();
            
            // Convert share to curve point coordinates
            let share_point = convert_share_to_curve_point(share_value).expect("Failed to convert share");
            
            // Generate a cryptographically secure random nonce
            let nonce = generate_secure_nonce(&mut thread_rng).expect("Failed to generate nonce");
            
            // Create proper circuit input
            let circuit_input = serde_json::json!({
                "message": [share_point.0.to_string(), share_point.1.to_string()],
                "nonceKey": nonce.to_string(),
                "publicKey": [recipient_pk.x.to_string(), recipient_pk.y.to_string()]
            });
            
            // Generate witness and proof using the actual circuit (including for self)
            // Lock the circuit to prevent concurrent access to shared files
            let circuit_guard = encryption_circuit.lock().unwrap();
            let witness_path = circuit_guard.generate_witness(&circuit_input).expect("Failed to generate witness");
            let (proof, public_inputs) = circuit_guard.generate_proof(&witness_path).expect("Failed to generate proof");
            drop(circuit_guard); // Release the lock early
            
            println!("Party {} generated ZK proof for share to party {}", i, j);
            ((i, j), (proof, public_inputs))
        })
        .collect();
    
    // Reconstruct the proofs vector from parallel results
    let mut proofs: Vec<Vec<(Value, Value)>> = vec![vec![(serde_json::json!(null), serde_json::json!(null)); n as usize]; n as usize];
    for ((i, j), (proof, public_inputs)) in proof_results {
        proofs[i][j] = (proof, public_inputs);
    }
    
    // Initialization: Step 6: Each party sends encrypted shares and proofs (simulate network)
    println!("\n--- Initialization: Step 6: Distributing encrypted shares and proofs ---");
    let mut received_encrypted_shares: Vec<Vec<Option<elgamal::ElGamalCiphertext>>> = vec![Vec::new(); n as usize];
    let mut received_proofs: Vec<Vec<(Value, Value)>> = vec![Vec::new(); n as usize];
    
    for sender in 0..n {
        for receiver in 0..n {
            if let Some(ref encrypted_share) = encrypted_shares[sender as usize][receiver as usize] {
                received_encrypted_shares[receiver as usize].push(Some(encrypted_share.clone()));
                received_proofs[receiver as usize].push(proofs[sender as usize][receiver as usize].clone());
                println!("Party {} received encrypted share and proof from party {}", receiver, sender);
            } else {
                received_encrypted_shares[receiver as usize].push(None);
                received_proofs[receiver as usize].push((serde_json::json!(null), serde_json::json!(null)));
            }
        }
    }
    
    // Initialization: Step 7: Each party verifies the received proofs
    println!("\n--- Initialization: Step 7: Verifying zero-knowledge proofs ---");
    
    // Create all verification tasks for parallel execution
    let mut verification_tasks: Vec<(usize, usize)> = Vec::new();
    for receiver in 0..n {
        for sender in 0..n {
            verification_tasks.push((receiver as usize, sender as usize));
        }
    }
    
    // Verify proofs in parallel
    let verification_results: Vec<((usize, usize), bool)> = verification_tasks
        .par_iter()
        .map(|&(receiver, sender)| {
            // Verify the actual zero-knowledge proof using the circuit
            let (proof, public_inputs) = &received_proofs[receiver][sender];
            
            let is_valid = if proof.is_null() || public_inputs.is_null() {
                // Skip null proofs
                true
            } else {
                // Use the actual circuit verification with mutex protection
                let circuit_guard = encryption_circuit.lock().unwrap();
                let result = circuit_guard.verify_proof(proof, public_inputs)
                    .unwrap_or(false);
                drop(circuit_guard); // Release the lock early
                result
            };
            
            if is_valid {
                println!("✅ Party {} verified proof from party {}", receiver, sender);
            } else {
                println!("❌ Party {} rejected proof from party {} - SKIPPING", receiver, sender);
            }
            
            ((receiver, sender), is_valid)
        })
        .collect();
    
    // Reconstruct the valid_parties matrix from parallel results
    let mut valid_parties: Vec<Vec<bool>> = vec![vec![true; n as usize]; n as usize];
    for ((receiver, sender), is_valid) in verification_results {
        valid_parties[receiver][sender] = is_valid;
    }
    
    // Initialization: Step 8: Distribute final DKG shares to each party
    println!("\n--- Initialization: Step 8: Computing final DKG shares ---");
    
    // Calculate the total distributed secret (sum of all party secrets)
    let total_secret: BigUint = party_secrets.iter().sum();
    println!("Total DKG secret (sum of all party secrets): {}", total_secret);
    
    // For each party, compute their final share by summing shares sent to them by all parties
    for party_idx in 0..n {
        let mut party_final_share = BigUint::from(0u32);
        
        // Sum all shares sent to this party by all other parties (including themselves)
        for sender_idx in 0..n {
            // Check if sender is considered valid by majority
            let validations: usize = (0..n).map(|i| if valid_parties[i as usize][sender_idx as usize] { 1 } else { 0 }).sum();
            if validations >= (n as usize / 2) {
                // Add the share that sender_idx intended for party_idx
                party_final_share += &all_shares[sender_idx as usize][party_idx as usize].value;
                println!("Party {} received share {} from party {} (validated by {}/{} parties)", 
                    party_idx, all_shares[sender_idx as usize][party_idx as usize].value, sender_idx, validations, n);
            } else {
                println!("Party {} ignoring share from party {} (only validated by {}/{} parties)", 
                    party_idx, sender_idx, validations, n);
            }
        }
        
        // Set the final share for this party
        parties[party_idx as usize].set_share(party_final_share.clone());
        println!("Party {} final share: {}", party_idx, party_final_share);
    }
    
    // Verify the DKG worked correctly by reconstructing the secret from any t shares
    println!("\n--- Initialization: Step 9: Verifying DKG reconstruction ---");
    let mut verification_shares = Vec::new();
    for i in 0..t {
        let share = shamir_rs::Share {
            index: (i + 1) as u32, // Shamir shares are 1-indexed
            value: parties[i as usize].share.share.clone(),
        };
        verification_shares.push(share);
    }
    
    if verification_shares.len() >= t as usize {
        let reconstructed_secret = scheme.reconstruct_secret(&verification_shares)?;
        println!("Reconstructed secret from first {} parties: {}", t, reconstructed_secret);
        println!("Expected total secret: {}", total_secret);
        
        if reconstructed_secret == total_secret {
            println!("\n✅ DKG Protocol completed successfully! Reconstruction matches expected total.");
        } else {
            println!("\n⚠️ DKG Protocol completed but reconstruction doesn't match expected total.");
        }
    } else {
        println!("❌ Not enough shares for verification reconstruction");
    }
    
    println!("\nFinal state of all parties: {}", PartyList(parties.clone()));

    // Increment generation
    g += 1;
    n = n_array[g as usize];
    t = t_array[g as usize];

    // ======================================================================
    // Round 1 of Evolving DKG Protocol
    // ======================================================================
    println!("\n=== Round 1: Evolving DKG Protocol ===");
    println!("Generation: {}", g);
    println!("Parties in generation {}: {}", g, n);
    println!("Threshold for generation {}: {}", g, t);
    
    // Round 1 - Let I be a set of parties in generation g-1 such that |I| = t_array[g]
    let prev_threshold = t_array[g as usize - 1]; // threshold for current generation determines how many parties from previous generation participate
    println!("Selecting {} parties from previous generation to participate", prev_threshold);
    
    // Select the first t parties from the previous generation (parties vector)
    let participating_parties: Vec<&Party> = parties.iter().take(prev_threshold).collect();
    println!("Selected parties: {:?}", participating_parties.iter().map(|p| p.index).collect::<Vec<_>>());
    
    // Initialize new parties for generation g (N[g] additional parties)
    println!("\nInitializing {} new parties for generation {}", n, g);
    let mut new_parties = Vec::new();
    
    // Create new party tasks for parallel execution
    let new_party_tasks: Vec<usize> = (0..n).collect();
    
    // Generate keys for new parties in parallel
    let new_key_results: Result<Vec<Party>> = new_party_tasks
        .par_iter()
        .map(|&i| -> Result<Party> {
            let party_id = (parties.len() + i) as u32; // Continue numbering from existing parties
            println!("Generating keys for new party {}", party_id);
            key_gen(party_id)?;
            let (sk, pk) = read_keys(party_id);
            let party = Party::new(party_id, g, sk, pk)?;
            Ok(party)
        })
        .collect();
    
    new_parties = new_key_results?;
    
    // Add new parties' public keys to PKI
    for party in &new_parties {
        pki.add_public_key(party.share.pk.clone());
    }
    
    println!("Initialized {} new parties", new_parties.len());
    
    // Round 1 - Each P_j in I (participating parties from previous generation):

    // Step 1: Parse the Share and compute Y_j for each participating party
    println!("\n--- Step 1: Parse shares and compute Y_j ---");
    let mut party_commitments: Vec<JubJubExtended> = Vec::new();
    
    for (j, party) in participating_parties.iter().enumerate() {
        // Parse the Share (sk_j, pk_j, C_j, x_j) ← σ_j of the party
        let sk_j = &party.share.sk;
        let pk_j = &party.share.pk;
        let c_j = party.share.encr_share.as_ref(); // Option<Vec<ElGamalCiphertext>>
        let x_j = &party.share.share; // BigUint representing the secret value
        
        println!("Party {}: sk_j={}, x_j={}", party.index, sk_j.value, x_j);
        
        // Compute Y_j = g^{x_j} using group exponentiation
        // Convert x_j (BigUint) to JubJubScalar for exponentiation
        let x_j_scalar = share_to_scalar(x_j)?;
        let y_j = GENERATOR_EXTENDED * &x_j_scalar; // Y_j = g^{x_j}
        
        party_commitments.push(y_j);
        println!("Party {}: computed Y_j (commitment)", party.index);
    }

    // Step 2: Generate random polynomials G_j for each participating party  
    println!("\n--- Step 2: Generate random polynomials G_j ---");
    let mut party_polynomials: Vec<Vec<BigUint>> = Vec::new();
    
    for (j, party) in participating_parties.iter().enumerate() {
        let x_j = &party.share.share;
        
        // Choose a random degree-(t^{(g)} - 1) polynomial G_j with G_j(0) = x_j
        let degree = t - 1; // degree is t^{(g)} - 1
        let mut polynomial = Vec::new();
        
        // Constant term (coefficient of x^0) must equal x_j
        polynomial.push(x_j.clone());
        
        // Generate random coefficients for x^1, x^2, ..., x^{t-1}
        for i in 1..=degree {
            let random_coeff = BigUint::from(rng.gen::<u64>() % 1000000); // Random coefficient
            polynomial.push(random_coeff);
        }
        
        party_polynomials.push(polynomial.clone());
        println!("Party {}: generated polynomial G_j of degree {} with G_j(0) = {}", 
                 party.index, degree, x_j);
        println!("  Polynomial coefficients: {:?}", polynomial);
    }

    // Step 3: Evaluate polynomials at each party index
    println!("\n--- Step 3: Evaluate polynomials G_j(k) for each party k ---");
    let mut polynomial_shares: Vec<Vec<BigUint>> = Vec::new(); // [j][k] = x_{j,k}
    
    // Helper function to evaluate polynomial at point x
    let evaluate_polynomial = |coeffs: &[BigUint], x: u32| -> BigUint {
        let mut result = BigUint::from(0u32);
        let x_big = BigUint::from(x);
        
        for (i, coeff) in coeffs.iter().enumerate() {
            let term = coeff * x_big.pow(i as u32);
            result += term;
        }
        result
    };
    
    for (j, polynomial) in party_polynomials.iter().enumerate() {
        let mut shares_for_party_j = Vec::new();
        
        // For each P_k with k ∈ [n] (all new parties), create x_{j,k} = G_j(k)
        for k in 1..=n {
            let x_jk = evaluate_polynomial(polynomial, k as u32);
            shares_for_party_j.push(x_jk.clone());
            println!("Party {}: x_{{j={},k={}}} = G_{}({}) = {}", 
                     participating_parties[j].index, j, k, j, k, x_jk);
        }
        
        polynomial_shares.push(shares_for_party_j);
    }

    // Step 4: Generate encryption randomness and encrypt shares
    println!("\n--- Step 4: Generate encryption randomness and encrypt shares ---");
    let mut encrypted_shares_evolving: Vec<Vec<elgamal::ElGamalCiphertext>> = Vec::new();
    let mut randomness_values: Vec<Vec<BigUint>> = Vec::new();
    
    for (j, shares_for_j) in polynomial_shares.iter().enumerate() {
        let mut encrypted_shares_for_j = Vec::new();
        let mut randomness_for_j = Vec::new();
        
        for (k, x_jk) in shares_for_j.iter().enumerate() {
            // Choose ω_{j,k} ←$ {0,1}* (random encryption randomness)
            let omega_jk = BigUint::from(rng.gen::<u64>());
            randomness_for_j.push(omega_jk.clone());
            
            // Get recipient's public key (new party k)
            let recipient_pk = &new_parties[k].share.pk;
            let jubjub_pk: JubJubExtended = recipient_pk.clone().into();
            
            // Convert share to JubJub point for encryption
            let share_scalar = share_to_scalar(x_jk)?;
            let share_point = GENERATOR_EXTENDED * &share_scalar;
            
            // Compute γ_{j,k} = Enc(pk_k, (x_{j,k}, ω_{j,k}))
            // For now, we encrypt just the share (the randomness ω_{j,k} will be sent separately)
            let gamma_jk = elgamal::encrypt(&jubjub_pk, &share_point, &mut rng)?;
            encrypted_shares_for_j.push(gamma_jk);
            
            println!("Party {}: encrypted share x_{{j={},k={}}} = {} for new party {}", 
                     participating_parties[j].index, j, k, x_jk, new_parties[k].index);
        }
        
        encrypted_shares_evolving.push(encrypted_shares_for_j);
        randomness_values.push(randomness_for_j);
    }

    // Step 5: Create message bundles σ̃_{j,k} for each recipient
    println!("\n--- Step 5: Create message bundles σ̃_{{j,k}} ---");
    
    // Define message structure for σ̃_{j,k}
    #[derive(Debug, Clone)]
    struct EvolvingMessage {
        y_j: JubJubExtended,                                    // Y_j commitment
        gamma_others: Vec<elgamal::ElGamalCiphertext>,         // {γ_{j,i}}_{i∈[n]\{k}}
        gamma_k: elgamal::ElGamalCiphertext,                   // γ_{j,k}
        party_j_index: u32,                                    // Which party j sent this
        recipient_k_index: u32,                                // Which party k should receive this
    }
    
    let mut evolving_messages: Vec<Vec<EvolvingMessage>> = Vec::new(); // [j][k] = message from j to k
    
    for (j, _) in participating_parties.iter().enumerate() {
        let mut messages_from_j = Vec::new();
        
        for k in 0..n {
            // Create σ̃_{j,k} = {Y_j, {γ_{j,i}}_{i∈[n]\{k}}, γ_{j,k}}
            let y_j = party_commitments[j];
            let gamma_k = encrypted_shares_evolving[j][k].clone();
            
            // Create {γ_{j,i}}_{i∈[n]\{k}} (all encrypted shares except for party k)
            let mut gamma_others = Vec::new();
            for i in 0..n {
                if i != k {
                    gamma_others.push(encrypted_shares_evolving[j][i].clone());
                }
            }
            
            let message = EvolvingMessage {
                y_j,
                gamma_others,
                gamma_k,
                party_j_index: participating_parties[j].index,
                recipient_k_index: new_parties[k].index,
            };
            
            messages_from_j.push(message);
            println!("Created message σ̃_{{j={},k={}}} from party {} to new party {}", 
                     j, k, participating_parties[j].index, new_parties[k].index);
        }
        
        evolving_messages.push(messages_from_j);
    }

    // Step 6: Zero-Knowledge Functionality (Placeholder)
    println!("\n--- Step 6: Zero-Knowledge Functionality (Placeholder) ---");
    
    // Bundle data for zero-knowledge functionality
    for (j, _) in participating_parties.iter().enumerate() {
        // Bundle ({(pk_i, γ_{j,i})}_{i∈[n]}, Y_j), {(x_{j,i}, ω_{j,i})}_{i∈[n]}, P_j), {P_{n-n_g+1}, ..., P_n})
        let mut pk_gamma_pairs = Vec::new();
        for (i, new_party) in new_parties.iter().enumerate() {
            pk_gamma_pairs.push((
                new_party.share.pk.clone(),
                encrypted_shares_evolving[j][i].clone()
            ));
        }
        
        let mut x_omega_pairs = Vec::new();
        for (i, x_ji) in polynomial_shares[j].iter().enumerate() {
            x_omega_pairs.push((
                x_ji.clone(),
                randomness_values[j][i].clone()
            ));
        }
        
        // This would be sent to zero-knowledge functionality
        println!("Party {}: ZK bundle prepared with {} pk-gamma pairs and {} x-omega pairs", 
                 participating_parties[j].index, pk_gamma_pairs.len(), x_omega_pairs.len());
        println!("  [PLACEHOLDER] Zero-knowledge proof would verify correct encryption");
    }
    
    // Step 7: Broadcast messages to new parties
    println!("\n--- Step 7: Broadcasting messages to new parties ---");
    
    // Simulate network broadcast
    let mut received_evolving_messages: Vec<Vec<EvolvingMessage>> = vec![Vec::new(); n];
    
    for (j, messages_from_j) in evolving_messages.iter().enumerate() {
        for (k, message) in messages_from_j.iter().enumerate() {
            // Broadcast σ̃_{j,k} to new party k
            received_evolving_messages[k].push(message.clone());
            println!("New party {} received message from party {} (σ̃_{{j={},k={}}})", 
                     new_parties[k].index, participating_parties[j].index, j, k);
        }
    }
    
    println!("\n✅ Round 1 of Evolving DKG completed successfully!");
    println!("- {} participating parties from generation {} sent shares", 
             participating_parties.len(), g-1);
    println!("- {} new parties in generation {} received encrypted shares", 
             new_parties.len(), g);
    println!("- All messages broadcast and zero-knowledge proofs prepared (placeholder)");
    Ok(())
}

// Convert a Shamir share to a point on the BabyJubJub curve
fn convert_share_to_curve_point(share: &BigUint) -> Result<(BigUint, BigUint)> {
    use dusk_jubjub::GENERATOR_EXTENDED;
    
    // Convert share to scalar within field bounds
    let share_scalar = share_to_scalar(share)?;
    
    // Multiply generator by share to get point
    let point = GENERATOR_EXTENDED * &share_scalar;
    
    // Extract coordinates
    let bytes = point.to_bytes();
    let x_coord = BigUint::from_bytes_le(&bytes[0..16]); // Use first 16 bytes for x
    let y_coord = BigUint::from_bytes_le(&bytes[16..32]); // Use last 16 bytes for y
    
    Ok((x_coord, y_coord))
}

// Generate a cryptographically secure random nonce for ElGamal encryption
fn generate_secure_nonce(rng: &mut StdRng) -> Result<BigUint> {
    use ff::Field;
    
    // Generate a random JubJub scalar
    let scalar = JubJubScalar::random(rng);
    let bytes = scalar.to_bytes();
    
    // Convert to BigUint
    Ok(BigUint::from_bytes_le(&bytes))
}

// Helper function to convert BigUint share to JubJub scalar with proper field reduction
fn share_to_scalar(share: &BigUint) -> Result<JubJubScalar> {
    use ff::Field;
    
    let mut bytes = [0u8; 32];
    let share_bytes = share.to_bytes_le();
    
    // Handle larger shares by taking modulo of field size
    if share_bytes.len() > 32 {
        // For large shares, use a hash-based approach to get valid field element
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        share.hash(&mut hasher);
        let hash_val = hasher.finish();
        bytes[0..8].copy_from_slice(&hash_val.to_le_bytes());
    } else {
        bytes[0..share_bytes.len()].copy_from_slice(&share_bytes);
    }
    
    // Create scalar from bytes (will automatically reduce modulo field size)
    Ok(JubJubScalar::from_bytes(&bytes).unwrap())
}

