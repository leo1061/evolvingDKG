use std::{fs, path::Path, process::Command, str::FromStr, fmt};
use anyhow::Result;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json;
use dusk_jubjub::{JubJubScalar, JubJubExtended};

pub mod elgamal;
use elgamal::ElGamalCiphertext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BabyJubJubPK {
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Debug, Clone)]
pub struct BabyJubJubSK {
    pub value: BigUint,
}

#[derive(Debug)]
pub struct Share {
    pub sk: BabyJubJubSK,
    pub pk: BabyJubJubPK,
    pub share: BigUint,
    pub encr_share: Option<ElGamalCiphertext>,  // Encrypted share using ElGamal
}

impl Share {
    pub fn new(sk: BabyJubJubSK, pk: BabyJubJubPK) -> Self {
        Self {
            sk,
            pk,
            share: BigUint::from(0u32),
            encr_share: None,
        }
    }

    pub fn set_share(&mut self, share: BigUint) {
        self.share = share;
    }

    pub fn set_encrypted_share(&mut self, encr_share: ElGamalCiphertext) {
        self.encr_share = Some(encr_share);
    }
}

impl fmt::Display for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  Secret Key: {}", self.sk.value)?;
        writeln!(f, "  Public Key: ({}, {})", self.pk.x, self.pk.y)?;
        writeln!(f, "  Share: {}", self.share)
    }
}

#[derive(Debug)]
pub struct Party {
    pub index: u32,
    pub share: Share,   
}

impl Party {
    pub fn new(i: u32, sk: BabyJubJubSK, pk: BabyJubJubPK) -> Result<Self> {
        Ok(Self {
            index: i,
            share: Share::new(sk, pk),
        })
    }

    pub fn set_share(&mut self, share: BigUint) {
        self.share.set_share(share);
    }
}

impl fmt::Display for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Party {}:", self.index)?;
        write!(f, "{}", self.share)
    }
}

// Wrapper type for Vec<Party>
pub struct PartyList(pub Vec<Party>);

impl fmt::Display for PartyList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\nAll Parties:")?;
        writeln!(f, "{}", "=".repeat(50))?;
        for party in &self.0 {
            writeln!(f, "{}", party)?;
            writeln!(f, "{}", "-".repeat(50))?;
        }
        Ok(())
    }
}

pub fn key_gen(i: u32) -> Result<()> {
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

pub fn read_keys(i: u32) -> (BabyJubJubSK, BabyJubJubPK) {
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

    (sk, pk)
} 