vse anyhow::Result;
use evolvingDKG::{protocol_init::ProtocolInitializer, round1::Round1Executor, round2::Round2Executor};
use rand::{rngs::StdRng, SeedableRng};

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
    let mut round1_executor = Round1Executor::new(
        participating_parties,
        initializer.pki.clone(),
        t,
        n,
        g,
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

    Ok(())
}
