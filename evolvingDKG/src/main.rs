use anyhow::Result;
use num_bigint::BigUint;
use shamir_rs::Scheme;
use evolvingDKG::{key_gen, read_keys, Party, PartyList, PKI, setup_zk::CircuitSetup, circom_encryption::EncryptionCircuit};
use std::str::FromStr;

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

    // Choose a large prime for the field
    // Using a 128-bit prime for better security
    let prime = BigUint::from_str("340282366920938463463374607431768211297")?;
    println!("\nUsing prime field of size: {}", prime);
    
    // Create the Shamir scheme
    let scheme = Scheme::new(t as usize, n as usize, prime.clone())?;
    
    // Generate a random secret (in practice, this would be your actual secret)
    // Using a 64-bit random number for demonstration
    let secret = BigUint::from_str("12345678901234567890")?;
    println!("\nOriginal secret: {}", secret);
    
    // Split the secret into shares
    println!("\nSplitting secret into shares...");
    let shares = scheme.split_secret(&secret);
    
    // Distribute shares to parties
    println!("\nDistributing shares to parties:");
    for i in 0..n {
        parties[i as usize].set_share(shares[i as usize].value.clone());
        println!("Party {} received share: {}", i, shares[i as usize].value);
    }
    
    // Demonstrate reconstruction with threshold number of shares
    println!("\nReconstructing secret using {} shares...", t);
    let reconstructed = scheme.reconstruct_secret(&shares[0..t as usize])?;
    println!("Reconstructed secret: {}", reconstructed);
    
    // Verify the reconstruction
    assert_eq!(reconstructed, secret, "Secret reconstruction failed!");
    println!("\n✅ Secret successfully reconstructed!");
    
    // Demonstrate that fewer than threshold shares cannot reconstruct
    println!("\nAttempting reconstruction with {} shares (should fail)...", t-1);
    match scheme.reconstruct_secret(&shares[0..(t-1) as usize]) {
        Ok(_) => println!("❌ Error: Reconstruction succeeded with insufficient shares!"),
        Err(_) => println!("✅ Correct: Reconstruction failed with insufficient shares"),
    }
    
    println!("Current state of all parties: {}", PartyList(parties));

    // Setup the circuits
    let setup = CircuitSetup::new("build");
    setup.setup_all()?;

    // Encrypt the secret
    let encryption_circuit = EncryptionCircuit::new("build");
    let encrypted_secret = encryption_circuit.encrypt(&secret)?;
    println!("Encrypted secret: {}", encrypted_secret);

    Ok(())
}

