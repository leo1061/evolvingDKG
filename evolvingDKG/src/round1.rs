use anyhow::Result;
use num_bigint::BigUint;
use crate::{key_gen, read_keys, Party, PKI, BabyJubJubPK, elgamal, utils::share_to_scalar};
use rand::{rngs::StdRng, Rng};
use dusk_jubjub::{JubJubExtended, GENERATOR_EXTENDED};
use rayon::prelude::*;

// Define message structure for σ̃_{j,k}
#[derive(Debug, Clone)]
pub struct EvolvingMessage {
    pub y_j: JubJubExtended,                                    // Y_j commitment
    pub gamma_others: Vec<elgamal::ElGamalCiphertext>,         // {γ_{j,i}}_{i∈[n]\{k}}
    pub gamma_k: elgamal::ElGamalCiphertext,                   // γ_{j,k}
    pub party_j_index: u32,                                    // Which party j sent this
    pub recipient_k_index: u32,                                // Which party k should receive this
}

pub struct Round1Executor {
    pub participating_parties: Vec<Party>,
    pub new_parties: Vec<Party>,
    pub pki: PKI,
    pub t: u32,
    pub n: u32,
    pub g: u32,
    pub rng: StdRng,
}

impl Round1Executor {
    pub fn new(
        participating_parties: Vec<Party>,
        mut pki: PKI,
        t: u32,
        n: u32,
        g: u32,
        rng: StdRng,
    ) -> Result<Self> {
        // Initialize new parties for generation g
        println!("\nInitializing {} new parties for generation {}", n, g);
        let mut new_parties = Vec::new();
        
        // Create new party tasks for parallel execution
        let new_party_tasks: Vec<usize> = (0..n).map(|i| i as usize).collect();
        
        // Generate keys for new parties in parallel
        let new_key_results: Result<Vec<Party>> = new_party_tasks
            .par_iter()
            .map(|&i| -> Result<Party> {
                let party_id = (participating_parties.len() + i) as u32; // Continue numbering from existing parties
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
        
        Ok(Round1Executor {
            participating_parties,
            new_parties,
            pki,
            t,
            n,
            g,
            rng,
        })
    }

    pub fn execute_round1(&mut self) -> Result<Vec<Vec<EvolvingMessage>>> {
        println!("\n=== Round 1: Evolving DKG Protocol ===");
        println!("Generation: {}", self.g);
        println!("Parties in generation {}: {}", self.g, self.n);
        println!("Threshold for generation {}: {}", self.g, self.t);
        
        // Step 1: Parse the Share and compute Y_j for each participating party
        let party_commitments = self.compute_party_commitments()?;
        
        // Step 2: Generate random polynomials G_j for each participating party
        let party_polynomials = self.generate_polynomials()?;
        
        // Step 3: Evaluate polynomials at each party index
        let polynomial_shares = self.evaluate_polynomials(&party_polynomials)?;
        
        // Step 4: Generate encryption randomness and encrypt shares
        let (encrypted_shares_evolving, randomness_values) = self.encrypt_polynomial_shares(&polynomial_shares)?;
        
        // Step 5: Create message bundles σ̃_{j,k} for each recipient
        let evolving_messages = self.create_message_bundles(&party_commitments, &encrypted_shares_evolving)?;
        
        // Step 6: Zero-Knowledge Functionality (Placeholder)
        self.zero_knowledge_functionality(&encrypted_shares_evolving, &polynomial_shares, &randomness_values)?;
        
        // Step 7: Broadcast messages to new parties
        self.broadcast_messages(&evolving_messages)?;
        
        Ok(evolving_messages)
    }

    fn compute_party_commitments(&self) -> Result<Vec<JubJubExtended>> {
        println!("\n--- Step 1: Parse shares and compute Y_j ---");
        let mut party_commitments: Vec<JubJubExtended> = Vec::new();
        
        for (_j, party) in self.participating_parties.iter().enumerate() {
            // Parse the Share (sk_j, pk_j, C_j, x_j) ← σ_j of the party
            let sk_j = &party.share.sk;
            let _pk_j = &party.share.pk;
            let _c_j = party.share.encr_share.as_ref(); // Option<Vec<ElGamalCiphertext>>
            let x_j = &party.share.share; // BigUint representing the secret value
            
            println!("Party {}: sk_j={}, x_j={}", party.index, sk_j.value, x_j);
            
            // Compute Y_j = g^{x_j} using group exponentiation
            // Convert x_j (BigUint) to JubJubScalar for exponentiation
            let x_j_scalar = share_to_scalar(x_j)?;
            let y_j = GENERATOR_EXTENDED * &x_j_scalar; // Y_j = g^{x_j}
            
            party_commitments.push(y_j);
            println!("Party {}: computed Y_j (commitment)", party.index);
        }
        
        Ok(party_commitments)
    }

    fn generate_polynomials(&mut self) -> Result<Vec<Vec<BigUint>>> {
        println!("\n--- Step 2: Generate random polynomials G_j ---");
        let mut party_polynomials: Vec<Vec<BigUint>> = Vec::new();
        
        for (_j, party) in self.participating_parties.iter().enumerate() {
            let x_j = &party.share.share;
            
            // Choose a random degree-(t^{(g)} - 1) polynomial G_j with G_j(0) = x_j
            let degree = self.t - 1; // degree is t^{(g)} - 1
            let mut polynomial = Vec::new();
            
            // Constant term (coefficient of x^0) must equal x_j
            polynomial.push(x_j.clone());
            
            // Generate random coefficients for x^1, x^2, ..., x^{t-1}
            for _i in 1..=degree {
                let random_coeff = BigUint::from(self.rng.gen::<u64>() % 1000000); // Random coefficient
                polynomial.push(random_coeff);
            }
            
            party_polynomials.push(polynomial.clone());
            println!("Party {}: generated polynomial G_j of degree {} with G_j(0) = {}", 
                     party.index, degree, x_j);
            println!("  Polynomial coefficients: {:?}", polynomial);
        }
        
        Ok(party_polynomials)
    }

    fn evaluate_polynomials(&self, party_polynomials: &[Vec<BigUint>]) -> Result<Vec<Vec<BigUint>>> {
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
            for k in 1..=self.n {
                let x_jk = evaluate_polynomial(polynomial, k as u32);
                shares_for_party_j.push(x_jk.clone());
                println!("Party {}: x_{{j={},k={}}} = G_{}({}) = {}", 
                         self.participating_parties[j].index, j, k, j, k, x_jk);
            }
            
            polynomial_shares.push(shares_for_party_j);
        }
        
        Ok(polynomial_shares)
    }

    fn encrypt_polynomial_shares(&mut self, polynomial_shares: &[Vec<BigUint>]) -> Result<(Vec<Vec<elgamal::ElGamalCiphertext>>, Vec<Vec<BigUint>>)> {
        println!("\n--- Step 4: Generate encryption randomness and encrypt shares ---");
        let mut encrypted_shares_evolving: Vec<Vec<elgamal::ElGamalCiphertext>> = Vec::new();
        let mut randomness_values: Vec<Vec<BigUint>> = Vec::new();
        
        for (j, shares_for_j) in polynomial_shares.iter().enumerate() {
            let mut encrypted_shares_for_j = Vec::new();
            let mut randomness_for_j = Vec::new();
            
            for (k, x_jk) in shares_for_j.iter().enumerate() {
                // Choose ω_{j,k} ←$ {0,1}* (random encryption randomness)
                let omega_jk = BigUint::from(self.rng.gen::<u64>());
                randomness_for_j.push(omega_jk.clone());
                
                // Get recipient's public key (new party k)
                let recipient_pk = &self.new_parties[k].share.pk;
                let jubjub_pk: JubJubExtended = recipient_pk.clone().into();
                
                // Convert share to a smaller value for practical discrete log computation
                // Take the share modulo a manageable value for demo purposes
                let share_mod = x_jk % BigUint::from(1000u64); // Reduced for performance
                let share_scalar = dusk_jubjub::JubJubScalar::from(share_mod.to_u64_digits()[0] as u64);
                let share_point = GENERATOR_EXTENDED * &share_scalar;
                
                // Compute γ_{j,k} = Enc(pk_k, (x_{j,k}, ω_{j,k}))
                // For now, we encrypt just the share (the randomness ω_{j,k} will be sent separately)
                let gamma_jk = elgamal::encrypt(&jubjub_pk, &share_point, &mut self.rng)?;
                encrypted_shares_for_j.push(gamma_jk);
                
                println!("Party {}: encrypted share x_{{j={},k={}}} = {} for new party {}", 
                         self.participating_parties[j].index, j, k, x_jk, self.new_parties[k].index);
            }
            
            encrypted_shares_evolving.push(encrypted_shares_for_j);
            randomness_values.push(randomness_for_j);
        }
        
        Ok((encrypted_shares_evolving, randomness_values))
    }

    fn create_message_bundles(&self, party_commitments: &[JubJubExtended], encrypted_shares_evolving: &[Vec<elgamal::ElGamalCiphertext>]) -> Result<Vec<Vec<EvolvingMessage>>> {
        println!("\n--- Step 5: Create message bundles σ̃_{{j,k}} ---");
        
        let mut evolving_messages: Vec<Vec<EvolvingMessage>> = Vec::new(); // [j][k] = message from j to k
        
        for (j, _) in self.participating_parties.iter().enumerate() {
            let mut messages_from_j = Vec::new();
            
            for k in 0..self.n {
                // Create σ̃_{j,k} = {Y_j, {γ_{j,i}}_{i∈[n]\{k}}, γ_{j,k}}
                let y_j = party_commitments[j];
                let gamma_k = encrypted_shares_evolving[j][k as usize].clone();
                
                // Create {γ_{j,i}}_{i∈[n]\{k}} (all encrypted shares except for party k)
                let mut gamma_others = Vec::new();
                for i in 0..self.n {
                    if i != k {
                        gamma_others.push(encrypted_shares_evolving[j][i as usize].clone());
                    }
                }
                
                let message = EvolvingMessage {
                    y_j,
                    gamma_others,
                    gamma_k,
                    party_j_index: self.participating_parties[j].index,
                    recipient_k_index: self.new_parties[k as usize].index,
                };
                
                messages_from_j.push(message);
                println!("Created message σ̃_{{j={},k={}}} from party {} to new party {}", 
                         j, k, self.participating_parties[j].index, self.new_parties[k as usize].index);
            }
            
            evolving_messages.push(messages_from_j);
        }
        
        Ok(evolving_messages)
    }

    fn zero_knowledge_functionality(&self, encrypted_shares_evolving: &[Vec<elgamal::ElGamalCiphertext>], polynomial_shares: &[Vec<BigUint>], randomness_values: &[Vec<BigUint>]) -> Result<()> {
        println!("\n--- Step 6: Zero-Knowledge Functionality (Placeholder) ---");
        
        // Bundle data for zero-knowledge functionality
        for (j, _) in self.participating_parties.iter().enumerate() {
            // Bundle ({(pk_i, γ_{j,i})}_{i∈[n]}, Y_j), {(x_{j,i}, ω_{j,i})}_{i∈[n]}, P_j), {P_{n-n_g+1}, ..., P_n})
            let mut pk_gamma_pairs = Vec::new();
            for (i, new_party) in self.new_parties.iter().enumerate() {
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
                     self.participating_parties[j].index, pk_gamma_pairs.len(), x_omega_pairs.len());
            println!("  [PLACEHOLDER] Zero-knowledge proof would verify correct encryption");
        }
        
        Ok(())
    }

    fn broadcast_messages(&self, evolving_messages: &[Vec<EvolvingMessage>]) -> Result<()> {
        println!("\n--- Step 7: Broadcasting messages to new parties ---");
        
        // Simulate network broadcast
        let mut received_evolving_messages: Vec<Vec<EvolvingMessage>> = vec![Vec::new(); self.n as usize];
        
        for (j, messages_from_j) in evolving_messages.iter().enumerate() {
            for (k, message) in messages_from_j.iter().enumerate() {
                // Broadcast σ̃_{j,k} to new party k
                received_evolving_messages[k].push(message.clone());
                println!("New party {} received message from party {} (σ̃_{{j={},k={}}})", 
                         self.new_parties[k].index, self.participating_parties[j].index, j, k);
            }
        }
        
        println!("\nRound 1 of Evolving DKG completed successfully!");
        println!("- {} participating parties from generation {} sent shares", 
                 self.participating_parties.len(), self.g-1);
        println!("- {} new parties in generation {} received encrypted shares", 
                 self.new_parties.len(), self.g);
        println!("- All messages broadcast and zero-knowledge proofs prepared (placeholder)");
        
        Ok(())
    }
}