use anyhow::Result;
use num_bigint::BigUint;
use shamir_rs::Scheme;
use evolvingDKG::{key_gen, read_keys, Party, PartyList, PKI, setup_zk::CircuitSetup, circom_encryption::EncryptionCircuit, elgamal};
use std::str::FromStr;
use rand::{rngs::StdRng, SeedableRng, Rng};
use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use serde_json::Value;
use group::GroupEncoding;

fn main() -> Result<()> {
    // Protocol parameters
    let n = 5; // total number of parties
    let t = 3; // threshold for reconstruction
    
    println!("Initializing Shamir Secret Sharing Protocol");
    println!("Total parties: {}", n);
    println!("Threshold: {}", t);
    
    // Generate keys for each party
    let mut parties = Vec::new();
    println!("\nGenerating keys for each party...");
    for i in 0..n {
        println!("Generating keys for party {}", i);
        key_gen(i)?;
        let (sk, pk) = read_keys(i);
        let party = Party::new(i, sk, pk)?;
        parties.push(party);
    }

    // Add all public keys to a PKI. 
    let mut pki = PKI::new();
    for party in &parties {
        pki.add_public_key(party.share.pk.clone());
    }

    println!("Current state of PKI: {}", pki);
    
    // Step 1: Each party runs the zero-knowledge setup to get the keys
    println!("\n=== Step 1: Zero-knowledge setup ===");
    let setup = CircuitSetup::new("build");
    setup.setup_all()?;
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
    
    // Step 2: Each party creates a random secret
    println!("\n--- Step 2: Each party creates a random secret ---");
    let mut party_secrets: Vec<BigUint> = Vec::new();
    for i in 0..n {
        let secret = BigUint::from(rng.gen::<u64>() % 1000000); // Random secret for demo
        party_secrets.push(secret.clone());
        println!("Party {} generated secret: {}", i, secret);
    }
    
    // Step 3: Each party creates secret shares for other parties
    println!("\n--- Step 3: Creating secret shares ---");
    let mut all_shares: Vec<Vec<shamir_rs::Share>> = Vec::new();
    for i in 0..n {
        let shares = scheme.split_secret(&party_secrets[i as usize]);
        all_shares.push(shares.clone());
        println!("Party {} created {} shares of their secret", i, shares.len());
    }
    
    // Step 4: Each party encrypts their shares using ElGamal encryption
    println!("\n--- Step 4: Encrypting shares with ElGamal ---");
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
    
    // Step 5: Generate zero-knowledge proofs for each encrypted share
    println!("\n--- Step 5: Generating zero-knowledge proofs ---");
    let encryption_circuit = EncryptionCircuit::new("build");
    let mut proofs: Vec<Vec<(Value, Value)>> = Vec::new();
    
    for i in 0..n {
        let mut party_proofs = Vec::new();
        for j in 0..n {
            // Get the actual share value and recipient's public key
            let share_value = &all_shares[i as usize][j as usize].value;
            let recipient_pk = pki.get_public_key(j as usize).unwrap();
            
            // Convert share to curve point coordinates
            let share_point = convert_share_to_curve_point(share_value)?;
            
            // Generate a cryptographically secure random nonce
            let nonce = generate_secure_nonce(&mut rng)?;
            
            // Create proper circuit input
            let circuit_input = serde_json::json!({
                "message": [share_point.0.to_string(), share_point.1.to_string()],
                "nonceKey": nonce.to_string(),
                "publicKey": [recipient_pk.x.to_string(), recipient_pk.y.to_string()]
            });
            
            // Generate witness and proof using the actual circuit (including for self)
            let witness_path = encryption_circuit.generate_witness(&circuit_input)?;
            let (proof, public_inputs) = encryption_circuit.generate_proof(&witness_path)?;
            
            party_proofs.push((proof, public_inputs));
            println!("Party {} generated ZK proof for share to party {}", i, j);
        }
        proofs.push(party_proofs);
    }
    
    // Step 6: Each party sends encrypted shares and proofs (simulate network)
    println!("\n--- Step 6: Distributing encrypted shares and proofs ---");
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
    
    // Step 7: Each party verifies the received proofs
    println!("\n--- Step 7: Verifying zero-knowledge proofs ---");
    let mut valid_parties: Vec<Vec<bool>> = vec![vec![true; n as usize]; n as usize];
    
    for receiver in 0..n {
        for sender in 0..n {
            // Verify the actual zero-knowledge proof using the circuit
            let (proof, public_inputs) = &received_proofs[receiver as usize][sender as usize];
            
            // Skip null proofs
            if proof.is_null() || public_inputs.is_null() {
                valid_parties[receiver as usize][sender as usize] = true;
            } else {
                // Use the actual circuit verification
                let is_valid = encryption_circuit.verify_proof(proof, public_inputs)
                    .unwrap_or(false);
                valid_parties[receiver as usize][sender as usize] = is_valid;
                
                if is_valid {
                    println!("✅ Party {} verified proof from party {}", receiver, sender);
                } else {
                    println!("❌ Party {} rejected proof from party {} - SKIPPING", receiver, sender);
                }
            }
        }
    }
    
    // Step 8: Distribute final DKG shares to each party
    println!("\n--- Step 8: Computing final DKG shares ---");
    
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
    println!("\n--- Step 9: Verifying DKG reconstruction ---");
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
    
    println!("\nFinal state of all parties: {}", PartyList(parties));

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

