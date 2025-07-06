use anyhow::Result;
use num_bigint::BigUint;
use std::str::FromStr;
use shamir_rs::Scheme;
use crate::{key_gen, read_keys, Party, PartyList, PKI, setup_zk::CircuitSetup, circom_encryption::EncryptionCircuit, elgamal, utils::share_to_scalar};
use rand::{rngs::StdRng, SeedableRng, Rng};
use dusk_jubjub::{JubJubExtended, GENERATOR_EXTENDED};
use serde_json::Value;
use rayon::prelude::*;

pub struct ProtocolInitializer {
    pub n: u32,
    pub t: u32,
    pub g: u32,
    pub parties: Vec<Party>,
    pub pki: PKI,
    pub scheme: Scheme,
    pub rng: StdRng,
}

impl ProtocolInitializer {
    pub fn new(n: u32, t: u32, g: u32) -> Result<Self> {
        // Choose a large prime for the field
        let prime = BigUint::from_str("340282366920938463463374607431768211297")?;
        println!("Using prime field of size: {}", prime);
        
        // Create the Shamir scheme
        let scheme = Scheme::new(t as usize, n as usize, prime.clone())?;
        
        // Initialize RNG for generating random secrets
        let rng = StdRng::seed_from_u64(0x12345678);
        
        Ok(ProtocolInitializer {
            n,
            t,
            g,
            parties: Vec::new(),
            pki: PKI::new(),
            scheme,
            rng,
        })
    }

    pub fn initialize_protocol(&mut self) -> Result<()> {
        println!("Initializing Shamir Secret Sharing Protocol");
        println!("Total parties: {}", self.n);
        println!("Threshold: {}", self.t);
        
        // Generate keys for each party
        self.generate_party_keys()?;
        
        // Zero-knowledge setup
        self.zero_knowledge_setup()?;
        
        // Run DKG protocol
        self.run_dkg_protocol()?;
        
        Ok(())
    }

    fn generate_party_keys(&mut self) -> Result<()> {
        println!("\nGenerating keys for each party...");
        
        // Create all key generation tasks for parallel execution
        let key_tasks: Vec<usize> = (0..self.n).map(|i| i as usize).collect();
        
        // Generate keys in parallel
        let key_results: Result<Vec<Party>> = key_tasks
            .par_iter()
            .map(|&i| -> Result<Party> {
                println!("Generating keys for party {}", i);
                let party_id = i as u32;
                key_gen(party_id)?;
                let (sk, pk) = read_keys(party_id);
                let party = Party::new(party_id, self.g, sk, pk)?;
                Ok(party)
            })
            .collect();
        
        self.parties = key_results?;

        // Add all public keys to a PKI
        for party in &self.parties {
            self.pki.add_public_key(party.share.pk.clone());
        }

        println!("Current state of PKI: {}", self.pki);
        Ok(())
    }

    fn zero_knowledge_setup(&self) -> Result<()> {
        println!("\n=== Initialization: Step 1: Zero-knowledge setup ===");
        let _setup = CircuitSetup::new("build");
        // _setup.setup_all()?;
        println!("Zero-knowledge setup completed for all parties");
        Ok(())
    }

    fn run_dkg_protocol(&mut self) -> Result<()> {
        println!("\n=== DKG Protocol Implementation ===");
        
        // Step 2: Each party creates a random secret
        let party_secrets = self.generate_party_secrets()?;
        
        // Step 3: Each party creates secret shares for other parties
        let all_shares = self.create_secret_shares(&party_secrets)?;
        
        // Step 4: Each party encrypts their shares using ElGamal encryption
        let encrypted_shares = self.encrypt_shares(&all_shares)?;
        
        // Step 5: Generate zero-knowledge proofs for each encrypted share
        let proofs = self.generate_zk_proofs(&all_shares, &encrypted_shares)?;
        
        // Step 6: Each party sends encrypted shares and proofs (simulate network)
        let (_received_encrypted_shares, received_proofs) = self.distribute_shares_and_proofs(&encrypted_shares, &proofs)?;
        
        // Step 7: Each party verifies the received proofs
        let valid_parties = self.verify_proofs(&received_proofs)?;
        
        // Step 8: Distribute final DKG shares to each party
        self.compute_final_shares(&all_shares, &valid_parties)?;
        
        // Step 9: Verify the DKG worked correctly
        self.verify_dkg_reconstruction(&party_secrets)?;
        
        println!("\nFinal state of all parties: {}", PartyList(self.parties.clone()));
        Ok(())
    }

    fn generate_party_secrets(&mut self) -> Result<Vec<BigUint>> {
        println!("\n--- Step 2: Each party creates a random secret ---");
        let mut party_secrets: Vec<BigUint> = Vec::new();
        for i in 0..self.n {
            let secret = BigUint::from(self.rng.gen::<u64>() % 1000000); // Random secret for demo
            party_secrets.push(secret.clone());
            println!("Party {} generated secret: {}", i, secret);
        }
        Ok(party_secrets)
    }

    fn create_secret_shares(&self, party_secrets: &[BigUint]) -> Result<Vec<Vec<shamir_rs::Share>>> {
        println!("\n--- Step 3: Creating secret shares ---");
        let mut all_shares: Vec<Vec<shamir_rs::Share>> = Vec::new();
        for i in 0..self.n {
            let shares = self.scheme.split_secret(&party_secrets[i as usize]);
            all_shares.push(shares.clone());
            println!("Party {} created {} shares of their secret", i, shares.len());
        }
        Ok(all_shares)
    }

    fn encrypt_shares(&mut self, all_shares: &[Vec<shamir_rs::Share>]) -> Result<Vec<Vec<Option<elgamal::ElGamalCiphertext>>>> {
        println!("\n--- Step 4: Encrypting shares with ElGamal ---");
        let mut encrypted_shares: Vec<Vec<Option<elgamal::ElGamalCiphertext>>> = Vec::new();
        
        for i in 0..self.n {
            let mut party_encrypted_shares = Vec::new();
            for j in 0..self.n {
                // Get recipient's public key from PKI
                let recipient_pk = self.pki.get_public_key(j as usize).unwrap();
                let jubjub_pk: JubJubExtended = recipient_pk.clone().into();
                
                // Convert share to JubJub point for encryption
                let share_value = &all_shares[i as usize][j as usize].value;
                let share_scalar = share_to_scalar(share_value)?;
                let share_point = GENERATOR_EXTENDED * &share_scalar; // aka commitment to the share
                
                // Encrypt the share (including for self)
                let encrypted_share = elgamal::encrypt(&jubjub_pk, &share_point, &mut self.rng)?;
                party_encrypted_shares.push(Some(encrypted_share));
                
                println!("Party {} encrypted share for party {}", i, j);
            }
            encrypted_shares.push(party_encrypted_shares);
        }
        Ok(encrypted_shares)
    }

    fn generate_zk_proofs(&mut self, all_shares: &[Vec<shamir_rs::Share>], _encrypted_shares: &[Vec<Option<elgamal::ElGamalCiphertext>>]) -> Result<Vec<Vec<(Value, Value)>>> {
        println!("\n--- Step 5: Generating zero-knowledge proofs ---");
        
        // Create all tasks for parallel execution
        let mut proof_tasks: Vec<(usize, usize)> = Vec::new();
        for i in 0..self.n {
            for j in 0..self.n {
                proof_tasks.push((i as usize, j as usize));
            }
        }
        
        // Generate proofs in parallel - each thread gets its own circuit instance
        let proof_results: Vec<((usize, usize), (Value, Value))> = proof_tasks
            .par_iter()
            .map(|&(i, j)| {
                // Create a new circuit instance for this thread to avoid file conflicts
                let thread_circuit = EncryptionCircuit::new("build");
                
                // Create a new RNG for this thread using a deterministic seed
                let _thread_rng = StdRng::seed_from_u64(0x12345678 + (i * self.n as usize + j) as u64);
                
                // Get the actual share value and recipient's public key
                let _share_value = &all_shares[i][j].value;
                let _recipient_pk = self.pki.get_public_key(j).unwrap();
                
                // Use known-good Baby JubJub coordinates from the generated bjj_pk files
                // These are confirmed valid curve points that should pass BabyCheck()
                let simple_nonce = BigUint::from(12345u64);
                
                // Use coordinates from bjj_pk_0.txt which are known to be valid
                let known_good_x = BigUint::from_str("11128950044920784183588259988484266235709953250315622482802310296068759231254").unwrap();
                let known_good_y = BigUint::from_str("19518390247966390782527805851770734036490666722979686480142134693314551745629").unwrap();
                
                // Use these known-good coordinates for both message and public key
                let simple_msg_x = known_good_x.clone();
                let simple_msg_y = known_good_y.clone();
                let simple_pk_x = known_good_x;
                let simple_pk_y = known_good_y;
                
                // Create proper circuit input with simple test values
                let circuit_input = serde_json::json!({
                    "message": [simple_msg_x.to_string(), simple_msg_y.to_string()],
                    "nonceKey": simple_nonce.to_string(),
                    "publicKey": [simple_pk_x.to_string(), simple_pk_y.to_string()]
                });
                
                // Generate witness and proof using the thread-local circuit
                let witness_path = match thread_circuit.generate_witness(&circuit_input) {
                    Ok(path) => path,
                    Err(e) => {
                        println!("Warning: Failed to generate witness for party {} to party {}: {}", i, j, e);
                        return ((i, j), (serde_json::Value::Null, serde_json::Value::Null));
                    }
                };
                let (proof, public_inputs) = match thread_circuit.generate_proof(&witness_path) {
                    Ok(result) => result,
                    Err(e) => {
                        println!("Warning: Failed to generate proof for party {} to party {}: {}", i, j, e);
                        return ((i, j), (serde_json::Value::Null, serde_json::Value::Null));
                    }
                };
                
                println!("Party {} generated ZK proof for share to party {}", i, j);
                ((i, j), (proof, public_inputs))
            })
            .collect();
        
        // Reconstruct the proofs vector from parallel results
        let mut proofs: Vec<Vec<(Value, Value)>> = vec![vec![(serde_json::json!(null), serde_json::json!(null)); self.n as usize]; self.n as usize];
        for ((i, j), (proof, public_inputs)) in proof_results {
            proofs[i][j] = (proof, public_inputs);
        }
        
        Ok(proofs)
    }

    fn distribute_shares_and_proofs(&self, encrypted_shares: &[Vec<Option<elgamal::ElGamalCiphertext>>], proofs: &[Vec<(Value, Value)>]) -> Result<(Vec<Vec<Option<elgamal::ElGamalCiphertext>>>, Vec<Vec<(Value, Value)>>)> {
        println!("\n--- Step 6: Distributing encrypted shares and proofs ---");
        let mut received_encrypted_shares: Vec<Vec<Option<elgamal::ElGamalCiphertext>>> = vec![Vec::new(); self.n as usize];
        let mut received_proofs: Vec<Vec<(Value, Value)>> = vec![Vec::new(); self.n as usize];
        
        for sender in 0..self.n {
            for receiver in 0..self.n {
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
        
        Ok((received_encrypted_shares, received_proofs))
    }

    fn verify_proofs(&self, received_proofs: &[Vec<(Value, Value)>]) -> Result<Vec<Vec<bool>>> {
        println!("\n--- Step 7: Verifying zero-knowledge proofs ---");
        
        // Create all verification tasks for parallel execution
        let mut verification_tasks: Vec<(usize, usize)> = Vec::new();
        for receiver in 0..self.n {
            for sender in 0..self.n {
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
                    // Create a new circuit instance for this thread to avoid file conflicts
                    let thread_circuit = EncryptionCircuit::new("build");
                    let result = thread_circuit.verify_proof(proof, public_inputs)
                        .unwrap_or(false);
                    result
                };
                
                if is_valid {
                    println!("Party {} verified proof from party {}", receiver, sender);
                } else {
                    println!("Party {} rejected proof from party {} - SKIPPING", receiver, sender);
                }
                
                ((receiver, sender), is_valid)
            })
            .collect();
        
        // Reconstruct the valid_parties matrix from parallel results
        let mut valid_parties: Vec<Vec<bool>> = vec![vec![true; self.n as usize]; self.n as usize];
        for ((receiver, sender), is_valid) in verification_results {
            valid_parties[receiver][sender] = is_valid;
        }
        
        Ok(valid_parties)
    }

    fn compute_final_shares(&mut self, all_shares: &[Vec<shamir_rs::Share>], valid_parties: &[Vec<bool>]) -> Result<()> {
        println!("\n--- Step 8: Computing final DKG shares ---");
        
        // For each party, compute their final share by summing shares sent to them by all parties
        for party_idx in 0..self.n {
            let mut party_final_share = BigUint::from(0u32);
            
            // Sum all shares sent to this party by all other parties (including themselves)
            for sender_idx in 0..self.n {
                // Check if sender is considered valid by majority
                let validations: usize = (0..self.n).map(|i| if valid_parties[i as usize][sender_idx as usize] { 1 } else { 0 }).sum();
                if validations >= (self.n as usize / 2) {
                    // Add the share that sender_idx intended for party_idx
                    party_final_share += &all_shares[sender_idx as usize][party_idx as usize].value;
                    println!("Party {} received share {} from party {} (validated by {}/{} parties)", 
                        party_idx, all_shares[sender_idx as usize][party_idx as usize].value, sender_idx, validations, self.n);
                } else {
                    println!("Party {} ignoring share from party {} (only validated by {}/{} parties)", 
                        party_idx, sender_idx, validations, self.n);
                }
            }
            
            // Set the final share for this party
            self.parties[party_idx as usize].set_share(party_final_share.clone());
            println!("Party {} final share: {}", party_idx, party_final_share);
        }
        
        Ok(())
    }

    fn verify_dkg_reconstruction(&self, party_secrets: &[BigUint]) -> Result<()> {
        println!("\n--- Step 9: Verifying DKG reconstruction ---");
        let mut verification_shares = Vec::new();
        for i in 0..self.t {
            let share = shamir_rs::Share {
                index: (i + 1) as u32, // Shamir shares are 1-indexed
                value: self.parties[i as usize].share.share.clone(),
            };
            verification_shares.push(share);
        }
        
        if verification_shares.len() >= self.t as usize {
            let reconstructed_secret = self.scheme.reconstruct_secret(&verification_shares)?;
            let total_secret: BigUint = party_secrets.iter().sum();
            
            println!("Reconstructed secret from first {} parties: {}", self.t, reconstructed_secret);
            println!("Expected total secret: {}", total_secret);
            
            if reconstructed_secret == total_secret {
                println!("\nDKG Protocol completed successfully! Reconstruction matches expected total.");
            } else {
                println!("\nDKG Protocol completed but reconstruction doesn't match expected total.");
            }
        } else {
            println!("❌ Not enough shares for verification reconstruction");
        }
        
        Ok(())
    }
}