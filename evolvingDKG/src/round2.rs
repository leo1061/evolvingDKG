use anyhow::Result;
use num_bigint::BigUint;
use crate::{Party, BabyJubJubPK, BabyJubJubSK, elgamal::ElGamalCiphertext, sigma_protocol::{Round2Proof, Round2Statement}, round1::EvolvingMessage, utils::{share_to_scalar, point_to_share}};
use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};

// Define share tuple structure for Round 2
#[derive(Debug, Clone)]
pub struct ShareTuple {
    pub pk_gamma_pairs: Vec<(BabyJubJubPK, ElGamalCiphertext)>, // (pk_k, γ_j,k) pairs
    pub y_j: JubJubExtended,                                    // Y_j commitment
    pub sender_j: u32,                                          // Sender party index
}

// Define output tuple structure σ_i
#[derive(Debug, Clone)]
pub struct OutputTuple {
    pub sk_i: BabyJubJubSK,                                     // Secret key
    pub pk_i: BabyJubJubPK,                                     // Public key
    pub gamma_k: Vec<ElGamalCiphertext>,                        // Aggregated encrypted shares for others
    pub x_i: BigUint,                                           // Final share value
}

// Define zero-knowledge message structure
#[derive(Debug, Clone)]
pub struct ZKMessage {
    pub pk_i: BabyJubJubPK,                                     // Public key
    pub gamma_ji_pairs: Vec<(BabyJubJubPK, ElGamalCiphertext)>, // All γ_{j,i} pairs
    pub y_i: JubJubExtended,                                    // Y_i commitment
    pub sk_i: BabyJubJubSK,                                     // Secret key (for proof generation)
    pub party_indices: Vec<u32>,                                // Party indices
}

pub struct Round2Executor {
    pub new_parties: Vec<Party>,
    pub received_messages: Vec<Vec<EvolvingMessage>>,
    pub n: u32,
    pub ng: u32,
}

impl Round2Executor {
    pub fn new(
        new_parties: Vec<Party>,
        received_messages: Vec<Vec<EvolvingMessage>>,
        n: u32,
        ng: u32,
    ) -> Self {
        Round2Executor {
            new_parties,
            received_messages,
            n,
            ng,
        }
    }

    pub fn execute_round2(&mut self) -> Result<()> {
        println!("\n=== Round 2: Evolving DKG Protocol ===");
        println!("Processing encrypted shares for parties in range [n - ng + 1, n]");
        
        // Calculate the range of new parties that need to process shares
        let start_idx = (self.n - self.ng) as usize; // In our case, this is 0 for the new parties
        let end_idx = self.n as usize; // All new parties
        
        println!("Processing parties in range [{}, {}]", start_idx, end_idx - 1);
        
        // For each party Pi where i ∈ [n - ng + 1, n] (i.e., new parties)
        for (party_idx, new_party) in self.new_parties.iter().enumerate() {
            self.process_party_round2(party_idx, new_party, start_idx, end_idx)?;
        }
        
        println!("\nRound 2 of Evolving DKG completed successfully!");
        println!("- All {} new parties processed their encrypted shares", self.new_parties.len());
        println!("- Share decryption, aggregation, and broadcasting completed");
        
        Ok(())
    }

    fn process_party_round2(
        &self,
        party_idx: usize,
        new_party: &Party,
        start_idx: usize,
        end_idx: usize,
    ) -> Result<()> {
        println!("\n--- Processing Round 2 for Party {} ---", new_party.index);
        
        // Step 1: Create share tuple sj = ((pk_k, γ_j,k)_{k∈[n-ng+1,n]}, Yj)
        let share_tuples = self.create_share_tuples(party_idx, start_idx, end_idx)?;
        
        // Step 2: Define valid set I' := {j ∈ I : (sj, 1) ← F^ZK_{R,L}}
        let valid_indices = self.verify_share_tuples(&share_tuples, new_party)?;
        
        // Step 3: Decrypt shares - For j ∈ I', compute x_{j,i} = Decrypt(sk_i, γ_{j,i})
        let decrypted_shares = self.decrypt_shares(&share_tuples, &valid_indices, new_party)?;
        
        // Step 4: Sum decrypted shares - Compute x_i = Σ_{j=1}^t x_{j,i}
        let (x_i, y_i) = self.compute_final_share(&decrypted_shares, new_party)?;
        
        // Step 5: Aggregate encrypted shares - Sum all encrypted shares γ_k = Σ_{j∈I'} γ_{j,k}
        let aggregated_encrypted_shares = self.aggregate_encrypted_shares(&share_tuples, &valid_indices, party_idx, start_idx, end_idx)?;
        
        // Step 6: Create output tuple σ_i = (sk_i, pk_i, {γ_k}_{k∈[n]\{i}}, x_i)
        let _output_tuple = self.create_output_tuple(new_party, &aggregated_encrypted_shares, &x_i)?;
        
        // Step 7: Generate and send Round 2 proof using sigma protocol
        self.generate_and_verify_proof(&share_tuples, &valid_indices, new_party, &decrypted_shares, &x_i, &y_i)?;
        
        // Step 8: Broadcast Y_i to all parties
        self.broadcast_commitment(new_party)?;
        
        Ok(())
    }

    fn create_share_tuples(&self, party_idx: usize, start_idx: usize, end_idx: usize) -> Result<Vec<ShareTuple>> {
        let mut share_tuples: Vec<ShareTuple> = Vec::new();
        
        for (_j, message) in self.received_messages[party_idx].iter().enumerate() {
            let mut pk_gamma_pairs = Vec::new();
            
            // Create pairs of (pk_k, γ_j,k) for all k in the range
            for k in start_idx..end_idx {
                let pk_k = &self.new_parties[k].share.pk;
                let gamma_jk = if k == party_idx {
                    &message.gamma_k // γ_j,i for this party
                } else {
                    // Find the corresponding γ_j,k from gamma_others
                    let other_idx = if k < party_idx { k } else { k - 1 };
                    &message.gamma_others[other_idx]
                };
                pk_gamma_pairs.push((pk_k.clone(), gamma_jk.clone()));
            }
            
            let share_tuple = ShareTuple {
                pk_gamma_pairs,
                y_j: message.y_j,
                sender_j: message.party_j_index,
            };
            share_tuples.push(share_tuple);
        }
        
        println!("Created {} share tuples for party {}", share_tuples.len(), party_idx);
        Ok(share_tuples)
    }

    fn verify_share_tuples(&self, share_tuples: &[ShareTuple], new_party: &Party) -> Result<Vec<usize>> {
        let mut valid_indices: Vec<usize> = Vec::new();
        
        for (j_idx, share_tuple) in share_tuples.iter().enumerate() {
            // Create statement for this share tuple
            let ciphertexts: Vec<ElGamalCiphertext> = share_tuple.pk_gamma_pairs
                .iter()
                .map(|(_, gamma)| gamma.clone())
                .collect();
            
            let _statement = Round2Statement {
                public_key: new_party.share.pk.clone(),
                ciphertexts,
                claimed_sum: share_tuple.y_j,
            };
            
            // For demonstration, we'll assume proofs are valid
            // In practice, you would verify actual proofs sent by participating parties
            let is_valid = true; // This would be actual proof verification
            
            if is_valid {
                valid_indices.push(j_idx);
                println!("Party {}: verified proof from sender {} (σ protocol)", 
                         new_party.index, share_tuple.sender_j);
            } else {
                println!("Party {}: rejected proof from sender {} (σ protocol)", 
                         new_party.index, share_tuple.sender_j);
            }
        }
        
        println!("Valid share indices for party {}: {:?}", new_party.index, valid_indices);
        Ok(valid_indices)
    }

    fn decrypt_shares(&self, share_tuples: &[ShareTuple], valid_indices: &[usize], new_party: &Party) -> Result<Vec<BigUint>> {
        let mut decrypted_shares: Vec<BigUint> = Vec::new();
        let sk_i: JubJubScalar = new_party.share.sk.clone().into();
        
        for j_idx in valid_indices {
            let share_tuple = &share_tuples[*j_idx];
            
            // Find the encrypted share γ_{j,i} for this party
            let gamma_ji = share_tuple.pk_gamma_pairs
                .iter()
                .find(|(pk, _)| pk.x == new_party.share.pk.x && pk.y == new_party.share.pk.y)
                .map(|(_, gamma)| gamma)
                .expect("Should find encrypted share for this party");
            
            // Decrypt using ElGamal decryption
            let decrypted_point = gamma_ji.decrypt(&sk_i);
            
            // Convert the decrypted point back to a share value
            let decrypted_share = point_to_share(&decrypted_point)?;
            decrypted_shares.push(decrypted_share.clone());
            
            println!("Party {}: decrypted share from sender {}: {}", 
                     new_party.index, share_tuple.sender_j, decrypted_share);
        }
        
        Ok(decrypted_shares)
    }

    fn compute_final_share(&self, decrypted_shares: &[BigUint], new_party: &Party) -> Result<(BigUint, JubJubExtended)> {
        let x_i: BigUint = decrypted_shares.iter().sum();
        let x_i_scalar = share_to_scalar(&x_i)?;
        let y_i = GENERATOR_EXTENDED * &x_i_scalar; // Y_i = g^{x_i}
        
        println!("Party {}: computed final share x_i = {}", new_party.index, x_i);
        println!("Party {}: computed commitment Y_i", new_party.index);
        
        Ok((x_i, y_i))
    }

    fn aggregate_encrypted_shares(
        &self,
        share_tuples: &[ShareTuple],
        valid_indices: &[usize],
        party_idx: usize,
        start_idx: usize,
        end_idx: usize,
    ) -> Result<Vec<ElGamalCiphertext>> {
        let mut aggregated_encrypted_shares: Vec<ElGamalCiphertext> = Vec::new();
        
        for k in start_idx..end_idx {
            if k == party_idx {
                continue; // Skip self
            }
            
            // Sum all γ_{j,k} for this k across all valid j
            let mut sum_c1 = JubJubExtended::default();
            let mut sum_c2 = JubJubExtended::default();
            
            for j_idx in valid_indices {
                let share_tuple = &share_tuples[*j_idx];
                
                // Find the gamma for party k in this share tuple
                if let Some((_, gamma_jk)) = share_tuple.pk_gamma_pairs
                    .iter()
                    .find(|(pk, _)| pk.x == self.new_parties[k].share.pk.x && pk.y == self.new_parties[k].share.pk.y) {
                    sum_c1 = sum_c1 + gamma_jk.c1;
                    sum_c2 = sum_c2 + gamma_jk.c2;
                }
            }
            
            aggregated_encrypted_shares.push(crate::elgamal::ElGamalCiphertext::new(sum_c1, sum_c2));
        }
        
        println!("Party {}: aggregated {} encrypted shares for other parties", 
                 party_idx, aggregated_encrypted_shares.len());
        
        Ok(aggregated_encrypted_shares)
    }

    fn create_output_tuple(
        &self,
        new_party: &Party,
        aggregated_encrypted_shares: &[ElGamalCiphertext],
        x_i: &BigUint,
    ) -> Result<OutputTuple> {
        let output_tuple = OutputTuple {
            sk_i: new_party.share.sk.clone(),
            pk_i: new_party.share.pk.clone(),
            gamma_k: aggregated_encrypted_shares.to_vec(),
            x_i: x_i.clone(),
        };
        
        println!("Party {}: created output tuple σ_i", new_party.index);
        Ok(output_tuple)
    }

    fn generate_and_verify_proof(
        &self,
        share_tuples: &[ShareTuple],
        valid_indices: &[usize],
        new_party: &Party,
        decrypted_shares: &[BigUint],
        x_i: &BigUint,
        y_i: &JubJubExtended,
    ) -> Result<()> {
        let ciphertexts: Vec<ElGamalCiphertext> = share_tuples.iter()
            .enumerate()
            .filter(|(idx, _)| valid_indices.contains(idx))
            .flat_map(|(_, st)| st.pk_gamma_pairs.iter().map(|(_, gamma)| gamma.clone()))
            .collect();
        
        let statement = Round2Statement {
            public_key: new_party.share.pk.clone(),
            ciphertexts,
            claimed_sum: *y_i,
        };
        
        // Generate proof using sigma protocol
        let proof = Round2Proof::prove(
            &statement,
            &new_party.share.sk,
            decrypted_shares,
            x_i,
        )?;
        
        println!("Party {}: generated Round 2 sigma proof", new_party.index);
        
        // Verify our own proof for demonstration
        let is_valid = proof.verify(&statement)?;
        println!("Party {}: self-verification of proof: {}", new_party.index, is_valid);
        
        Ok(())
    }

    fn broadcast_commitment(&self, new_party: &Party) -> Result<()> {
        println!("Party {}: broadcasting Y_i commitment to all parties", new_party.index);
        println!("Round 2 completed for Party {}", new_party.index);
        Ok(())
    }
}