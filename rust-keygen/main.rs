use std::{env, fs, path::Path, process::Command, str::FromStr, fmt};
use anyhow::Result;
use num_bigint::BigUint;
use shamir_rs::Scheme;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BabyJubJubPK {
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Debug, Clone)]
pub struct BabyJubJubSK {
    pub value: BigUint,
}

struct Party {
    index: u32,
    sk: BabyJubJubSK,
    pk: BabyJubJubPK,
    share: BigUint,
    //encr_shares: 
    //TODO: add exncrypted shares to the struct

}

impl Party {
    fn new(i: u32, sk: BabyJubJubSK, pk: BabyJubJubPK) -> Result<Self> {
        Ok(Self {
            index: i,
            sk,
            pk,
            share: BigUint::from(0u32), // Initialize share as 0, will be set later
        })
    }

    fn set_share(&mut self, share: BigUint) {
        self.share = share;
    }
}

impl fmt::Display for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Party {}:", self.index)?;
        writeln!(f, "  Secret Key: {}", self.sk.value)?;
        writeln!(f, "  Public Key: ({}, {})", self.pk.x, self.pk.y)?;
        writeln!(f, "  Share: {}", self.share)
    }
}

fn key_gen(i: u32) -> Result<()> {
    
    // Get the parent directory path
    let parent_dir = Path::new("..");
    
    // Execute the Node.js script with the correct path
    let output = Command::new("node")
        .current_dir(parent_dir)  // Set working directory to parent
        .arg("scripts/gen_bjj_keys.js")
        .arg(i.to_string())
        .output()?;

    // Check if the command was successful
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to generate keys: {}", error);
    }

    Ok(())
}

fn read_keys(i: u32) -> (BabyJubJubSK, BabyJubJubPK) {
    let sk_file_path = format!("../bjj_sk_{}.txt", i);
    let sk_contents = fs::read_to_string(sk_file_path)
        .expect("Should have been able to read the file");
    let sk = BabyJubJubSK {
        value: BigUint::from_str(&sk_contents).unwrap()
    };

    let pk_file_path = format!("../bjj_pk_{}.txt", i);
    let pk_contents = fs::read_to_string(pk_file_path)
        .expect("Should have been able to read the file");
    
    let pk_array: Vec<String> = serde_json::from_str(&pk_contents)
        .expect("Failed to parse public key array");
    
    let pk = BabyJubJubPK {
        x: BigUint::from_str(&pk_array[0]).unwrap(),
        y: BigUint::from_str(&pk_array[1]).unwrap()
    };

    // println!("SK: {}", sk.value);
    // println!("PK: ({}, {})", pk.x, pk.y);

    (sk, pk)
}


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
        println!("Share {} has value {}", i  , shares[i as usize].value )
    }



    // Reconstruct the secret from a subset of shares
    let reconstructed = scheme.reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);

    Ok(())
}

