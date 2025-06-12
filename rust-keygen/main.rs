use std::{env, fs, path::Path, process::Command};
use anyhow::Result;
use num_bigint::BigUint;
use shamir_rs::Scheme;

// struct Party {
//     index: u32,
//     sk: ,
//     pk: ,
//     share: BigUint,
//     //encr_shares: 
//     //TODO: add exncrypted shares to the struct
//
// }


fn key_gen(i: u32) -> Result<()> {
    println!("🔐 Generating BabyJubJub keys using Node.js script...");
    
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

    // Print the output
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);

    println!("✅ Key generation complete!");
    Ok(())
}

// fn read_keys(P: Party){
//     let i = P.index;
//
//     let sk_file_path = concat("../bjj_sk_", i.to_string(), ".txt" );
//     // let pk_file_path = concat(,i.to_string());
//
//
//     let sk_contents = fs::read_to_string(file_path)
//         .expect("Should have been able to read the file");
//
//     let sk = BigUint::
//
//
// }(<>)


fn main() -> Result<()> {
    let n = 5; // total number of initial parties
    let t = 3; // initial threshold
    
    for i in 0..n {
        key_gen(i)?;
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

