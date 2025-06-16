use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use serde_json::{json, Value};
use anyhow::{Result, Context};
use num_bigint::BigUint;

pub struct EncryptionCircuit {
    build_dir: PathBuf,
}

impl EncryptionCircuit {
    pub fn new<P: AsRef<Path>>(build_dir: P) -> Self {
        Self {
            build_dir: build_dir.as_ref().to_path_buf(),
        }
    }

    pub fn generate_witness(&self, input: &Value) -> Result<PathBuf> {
        let input_path = self.build_dir.join("input.json");
        fs::write(&input_path, serde_json::to_string_pretty(input)?)
            .context("Failed to write input file")?;

        let witness_path = self.build_dir.join("witness.wtns");
        let encryption_js_dir = self.build_dir.join("encryption_js");

        Command::new("node")
            .current_dir(&encryption_js_dir)
            .args([
                "generate_witness.js",
                "encryption.wasm",
                "../input.json",
                "../witness.wtns",
            ])
            .output()
            .context("Failed to generate witness")?;

        Ok(witness_path)
    }

    pub fn generate_proof(&self, witness_path: &Path) -> Result<(Value, Value)> {
        let proof_path = self.build_dir.join("proof.json");
        let public_path = self.build_dir.join("public.json");
        let zkey_path = self.build_dir.join("encryption_final.zkey");

        Command::new("snarkjs")
            .args([
                "groth16",
                "prove",
                zkey_path.to_str().unwrap(),
                witness_path.to_str().unwrap(),
                proof_path.to_str().unwrap(),
                public_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to generate proof")?;

        let proof = fs::read_to_string(&proof_path)
            .context("Failed to read proof file")?;
        let public = fs::read_to_string(&public_path)
            .context("Failed to read public file")?;

        Ok((
            serde_json::from_str(&proof)?,
            serde_json::from_str(&public)?,
        ))
    }

    pub fn verify_proof(&self, proof: &Value, public_inputs: &Value) -> Result<bool> {
        let verification_key_path = self.build_dir.join("verification_key.json");
        let proof_path = self.build_dir.join("proof.json");
        let public_path = self.build_dir.join("public.json");

        fs::write(&proof_path, serde_json::to_string(proof)?)
            .context("Failed to write proof file")?;
        fs::write(&public_path, serde_json::to_string(public_inputs)?)
            .context("Failed to write public inputs file")?;

        let output = Command::new("snarkjs")
            .args([
                "groth16",
                "verify",
                verification_key_path.to_str().unwrap(),
                public_path.to_str().unwrap(),
                proof_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to verify proof")?;

        Ok(output.status.success())
    }

    pub fn encrypt(&self, secret: &BigUint) -> Result<Value> {
        // Convert the secret to a point on the BabyJubjub curve
        // This is a simplified example - in practice, you'd need proper point conversion
        let input = json!({
            "message": [
                secret.to_string(),
                "0"  // y-coordinate (simplified)
            ],
            "nonceKey": "123456789",  // In practice, this should be a random value
            "publicKey": [
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
                "16950150798460657717958625567821834550301663161624707787222815936182638968203"
            ]
        });

        // Generate witness
        let witness_path = self.generate_witness(&input)?;

        // Generate proof
        let (proof, public_inputs) = self.generate_proof(&witness_path)?;

        // Return the encrypted result
        Ok(json!({
            "proof": proof,
            "publicInputs": public_inputs
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn setup_test_environment() -> Result<PathBuf> {
        let build_dir = PathBuf::from("build");
        if !build_dir.exists() {
            fs::create_dir_all(&build_dir)
                .context("Failed to create build directory")?;
        }
        
        // Ensure encryption_js directory exists with required files
        let encryption_js_dir = build_dir.join("encryption_js");
        if !encryption_js_dir.exists() {
            return Err(anyhow::anyhow!("encryption_js directory not found in build directory"));
        }

        // Check for required files
        let required_files = [
            "encryption.wasm",
            "generate_witness.js",
            "witness_calculator.js",
        ];

        for file in required_files.iter() {
            let file_path = encryption_js_dir.join(file);
            if !file_path.exists() {
                return Err(anyhow::anyhow!("Required file {} not found in encryption_js directory", file));
            }
        }

        // Check for zkey and verification key
        let zkey_path = build_dir.join("encryption_final.zkey");
        let verification_key_path = build_dir.join("verification_key.json");
        
        if !zkey_path.exists() {
            return Err(anyhow::anyhow!("encryption_final.zkey not found in build directory"));
        }
        if !verification_key_path.exists() {
            return Err(anyhow::anyhow!("verification_key.json not found in build directory"));
        }

        Ok(build_dir)
    }

    #[test]
    fn test_encryption_circuit() -> Result<()> {
        let build_dir = setup_test_environment()?;
        let circuit = EncryptionCircuit::new(&build_dir);

        // Example input values for ElGamal encryption
        // These are example values - in a real test, you would use actual valid points on the BabyJubjub curve
        let input = json!({
            "message": [
                "5299619240641551281634865583518297031282874472190772894086521144482721001553",
                "16950150798460657717958625567821834550301663161624707787222815936182638968203"
            ],
            "nonceKey": "123456789",
            "publicKey": [
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
                "16950150798460657717958625567821834550301663161624707787222815936182638968203"
            ]
        });

        // Generate witness
        let witness_path = circuit.generate_witness(&input)?;
        assert!(witness_path.exists(), "Witness file should be created");

        // Generate proof
        let (proof, public_inputs) = circuit.generate_proof(&witness_path)?;
        assert!(!proof.is_null(), "Proof should be generated");
        assert!(!public_inputs.is_null(), "Public inputs should be generated");

        // Verify proof
        let is_valid = circuit.verify_proof(&proof, &public_inputs)?;
        assert!(is_valid, "Proof verification should succeed");

        Ok(())
    }
} 