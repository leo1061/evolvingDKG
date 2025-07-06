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
        // Use thread ID to create unique file names and avoid conflicts
        let thread_id = std::thread::current().id();
        let input_path = self.build_dir.join(format!("input_{:?}.json", thread_id));
        fs::write(&input_path, serde_json::to_string_pretty(input)?)
            .context("Failed to write input file")?;

        let witness_path = self.build_dir.join(format!("witness_{:?}.wtns", thread_id));
        let encryption_js_dir = self.build_dir.join("encryption_js");

        let output = Command::new("node")
            .current_dir(&encryption_js_dir)
            .args([
                "generate_witness.js",
                "encryption.wasm",
                &format!("../input_{:?}.json", thread_id),
                &format!("../witness_{:?}.wtns", thread_id),
            ])
            .output()
            .context("Failed to execute node generate_witness command")?;

        // Check if the witness generation succeeded
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow::anyhow!(
                "Node generate_witness command failed. Exit status: {:?}\nStdout: {}\nStderr: {}", 
                output.status.code(), stdout, stderr
            ));
        }

        // Check if witness file was actually created
        if !witness_path.exists() {
            return Err(anyhow::anyhow!(
                "Witness file was not created: {:?}", witness_path
            ));
        }

        Ok(witness_path)
    }

    pub fn generate_proof(&self, witness_path: &Path) -> Result<(Value, Value)> {
        // Use thread ID to create unique file names and avoid conflicts
        let thread_id = std::thread::current().id();
        let proof_path = self.build_dir.join(format!("proof_{:?}.json", thread_id));
        let public_path = self.build_dir.join(format!("public_{:?}.json", thread_id));
        let zkey_path = self.build_dir.join("encryption_final.zkey");

        let output = Command::new("snarkjs")
            .args([
                "groth16",
                "prove",
                zkey_path.to_str().unwrap(),
                witness_path.to_str().unwrap(),
                proof_path.to_str().unwrap(),
                public_path.to_str().unwrap(),
            ])
            .output()
            .context("Failed to execute snarkjs prove command")?;

        // Check if the command succeeded
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow::anyhow!(
                "snarkjs prove command failed. Exit status: {:?}\nStdout: {}\nStderr: {}", 
                output.status.code(), stdout, stderr
            ));
        }

        // Check if files were actually created
        if !proof_path.exists() {
            return Err(anyhow::anyhow!(
                "Proof file was not created by snarkjs: {:?}", proof_path
            ));
        }
        if !public_path.exists() {
            return Err(anyhow::anyhow!(
                "Public file was not created by snarkjs: {:?}", public_path
            ));
        }

        let proof = fs::read_to_string(&proof_path)
            .with_context(|| format!("Failed to read proof file: {:?}", proof_path))?;
        let public = fs::read_to_string(&public_path)
            .with_context(|| format!("Failed to read public file: {:?}", public_path))?;

        // Parse JSON with better error handling
        let proof_json = serde_json::from_str(&proof)
            .with_context(|| format!("Failed to parse proof JSON from file: {:?}. Content (first 200 chars): {}", proof_path, &proof[..std::cmp::min(200, proof.len())]))?;
        let public_json = serde_json::from_str(&public)
            .with_context(|| format!("Failed to parse public JSON from file: {:?}. Content (first 200 chars): {}", public_path, &public[..std::cmp::min(200, public.len())]))?;

        // Clean up temporary files
        let _ = fs::remove_file(&proof_path);
        let _ = fs::remove_file(&public_path);
        let input_path = self.build_dir.join(format!("input_{:?}.json", thread_id));
        let _ = fs::remove_file(&input_path);
        let _ = fs::remove_file(witness_path);

        Ok((proof_json, public_json))
    }

    pub fn verify_proof(&self, proof: &Value, public_inputs: &Value) -> Result<bool> {
        // Use thread ID to create unique file names and avoid conflicts
        let thread_id = std::thread::current().id();
        let verification_key_path = self.build_dir.join("verification_key.json");
        let proof_path = self.build_dir.join(format!("proof_verify_{:?}.json", thread_id));
        let public_path = self.build_dir.join(format!("public_verify_{:?}.json", thread_id));

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

        // Clean up temporary files
        let _ = fs::remove_file(&proof_path);
        let _ = fs::remove_file(&public_path);

        Ok(output.status.success())
    }

    pub fn encrypt_with_proof(&self, message_point: &(BigUint, BigUint), nonce: &BigUint, public_key: &(BigUint, BigUint)) -> Result<Value> {
        // Create proper circuit input with actual cryptographic values
        let input = json!({
            "message": [message_point.0.to_string(), message_point.1.to_string()],
            "nonceKey": nonce.to_string(),
            "publicKey": [public_key.0.to_string(), public_key.1.to_string()]
        });

        // Generate witness
        let witness_path = self.generate_witness(&input)?;

        // Generate proof
        let (proof, public_inputs) = self.generate_proof(&witness_path)?;

        // Return the encrypted result with proof
        Ok(json!({
            "proof": proof,
            "publicInputs": public_inputs,
            "ephemeralKey": public_inputs.get("ephemeralKey"),
            "encryptedMessage": public_inputs.get("encryptedMessage")
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

        // Use valid BabyJubJub curve points from the codebase
        // These coordinates are known to be valid and pass BabyCheck constraints
        let input = json!({
            "message": [
                "11128950044920784183588259988484266235709953250315622482802310296068759231254",
                "19518390247966390782527805851770734036490666722979686480142134693314551745629"
            ],
            "nonceKey": "12345",
            "publicKey": [
                "11128950044920784183588259988484266235709953250315622482802310296068759231254",
                "19518390247966390782527805851770734036490666722979686480142134693314551745629"
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