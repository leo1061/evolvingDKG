use anyhow::Result;
use num_bigint::BigUint;
use shamir_rs::Scheme;
use elgamal_keygen::{key_gen, read_keys, Party};

fn main() -> Result<()> {
    let n = 5; // total number of initial parties
    let t = 3; // initial threshold
    
    for i in 0..n {
        key_gen(i)?;
        let (sk, pk) = read_keys(i);
        let party = Party::new(i, sk, pk)?;
        println!("{}", party);
    }

    // Choose a prime larger than the secret and total shares
    let prime = BigUint::from(257u32);
    // TODO: put a bigger prime
    
    // Create a new scheme with a minimum threshold of 3 shares to reconstruct, and 5 shares total
    let scheme = Scheme::new(t as usize, n as usize, prime).unwrap();

    // The secret to be shared    
    let secret = BigUint::from(123u32);
    // TODO: put a bigger secret

    // Split the secret into shares    
    let shares = scheme.split_secret(&secret);

    for i in 0..n {
        println!("Share {} has value {}", i, shares[i as usize].value)
    }

    // Reconstruct the secret from a subset of shares
    let reconstructed = scheme.reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);

    Ok(())
}

