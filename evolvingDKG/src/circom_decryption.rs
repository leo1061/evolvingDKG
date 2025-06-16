use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use serde_json::{json, Value};
use anyhow::{Result, Context};
use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use rand::rngs::StdRng;
use rand::SeedableRng;
use ff::Field;
use group::GroupEncoding;
use crate::circom_encryption::EncryptionCircuit;
use group::Curve;

pub struct DecryptionCircuit {
    build_dir: PathBuf,
}

impl DecryptionCircuit {
    pub fn new(build_dir: impl AsRef<Path>) -> Self {
        Self {
            build_dir: build_dir.as_ref().to_path_buf(),
        }
    }

    pub fn generate_witness(&self, input: &Value) -> Result<PathBuf> {
        let input_path = self.build_dir.join("decrypt_input.json");
        fs::write(&input_path, serde_json::to_string_pretty(input)?)
            .context("Failed to write input file")?;

        let witness_path = self.build_dir.join("decrypt_witness.wtns");
        let decryption_js_dir = self.build_dir.join("decryption_js");

        Command::new("node")
            .current_dir(&decryption_js_dir)
            .args([
                "generate_witness.js",
                "decryption.wasm",
                "../decrypt_input.json",
                "../decrypt_witness.wtns",
            ])
            .output()
            .context("Failed to generate witness")?;

        Ok(witness_path)
    }

    pub fn generate_proof(&self, witness_path: &Path) -> Result<(Value, Value)> {
        let proof_path = self.build_dir.join("decrypt_proof.json");
        let public_path = self.build_dir.join("decrypt_public.json");

        Command::new("snarkjs")
            .current_dir(&self.build_dir)
            .args([
                "groth16",
                "prove",
                "decryption_final.zkey",
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
        let verification_key_path = self.build_dir.join("decrypt_verification_key.json");
        let proof_path = self.build_dir.join("decrypt_proof.json");
        let public_path = self.build_dir.join("decrypt_public.json");

        fs::write(&proof_path, serde_json::to_string(proof)?)
            .context("Failed to write proof file")?;
        fs::write(&public_path, serde_json::to_string(public_inputs)?)
            .context("Failed to write public inputs file")?;

        let output = Command::new("snarkjs")
            .current_dir(&self.build_dir)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    fn setup_test_circuit() -> (DecryptionCircuit, EncryptionCircuit, tempfile::TempDir) {
        let temp_dir = tempdir().unwrap();
        let decryption_circuit = DecryptionCircuit::new(temp_dir.path());
        let encryption_circuit = EncryptionCircuit::new(temp_dir.path());
        
        // Create necessary directory structure
        fs::create_dir_all(temp_dir.path().join("decryption_js")).unwrap();
        fs::create_dir_all(temp_dir.path().join("encryption_js")).unwrap();
        
        // Copy circuit files to temp directory
        let circuit_dir = Path::new("../circuits");
        fs::copy(
            circuit_dir.join("decryption.circom"),
            temp_dir.path().join("decryption.circom")
        ).unwrap();
        fs::copy(
            circuit_dir.join("encryption.circom"),
            temp_dir.path().join("encryption.circom")
        ).unwrap();
        
        // Compile both circuits
        let circomlib_path = "/Users/fadi/Projects/evolvingDKG/node_modules";
        
        // Compile decryption circuit
        let decryption_output = Command::new("circom")
            .current_dir(temp_dir.path())
            .args([
                "decryption.circom",
                "--r1cs",
                "--wasm",
                "--sym",
                "-o",
                ".",
                "-l",
                circomlib_path
            ])
            .output()
            .expect("Failed to compile decryption circuit");
        assert!(decryption_output.status.success(), "Decryption circuit compilation failed");

        // Compile encryption circuit
        let encryption_output = Command::new("circom")
            .current_dir(temp_dir.path())
            .args([
                "encryption.circom",
                "--r1cs",
                "--wasm",
                "--sym",
                "-o",
                ".",
                "-l",
                circomlib_path
            ])
            .output()
            .expect("Failed to compile encryption circuit");
        assert!(encryption_output.status.success(), "Encryption circuit compilation failed");

        // Setup snarkjs for both circuits
        // First setup powers of tau
        Command::new("snarkjs")
            .current_dir(temp_dir.path())
            .args([
                "powersoftau",
                "new",
                "bn128",
                "12",
                "pot12_0000.ptau",
                "-v"
            ])
            .output()
            .expect("Failed to setup powers of tau");

        Command::new("snarkjs")
            .current_dir(temp_dir.path())
            .args([
                "powersoftau",
                "contribute",
                "pot12_0000.ptau",
                "pot12_0001.ptau",
                "--name",
                "First contribution",
                "-v"
            ])
            .output()
            .expect("Failed to contribute to powers of tau");

        Command::new("snarkjs")
            .current_dir(temp_dir.path())
            .args([
                "powersoftau",
                "prepare",
                "phase2",
                "pot12_0001.ptau",
                "pot12_final.ptau",
                "-v"
            ])
            .output()
            .expect("Failed to prepare phase2");

        // Setup decryption circuit
        Command::new("snarkjs")
            .current_dir(temp_dir.path())
            .args([
                "groth16",
                "setup",
                "decryption.r1cs",
                "pot12_final.ptau",
                "decryption_final.zkey"
            ])
            .output()
            .expect("Failed to setup decryption circuit");

        Command::new("snarkjs")
            .current_dir(temp_dir.path())
            .args([
                "zkey",
                "export",
                "verificationkey",
                "decryption_final.zkey",
                "decrypt_verification_key.json"
            ])
            .output()
            .expect("Failed to export decryption verification key");

        // Setup encryption circuit
        Command::new("snarkjs")
            .current_dir(temp_dir.path())
            .args([
                "groth16",
                "setup",
                "encryption.r1cs",
                "pot12_final.ptau",
                "encryption_final.zkey"
            ])
            .output()
            .expect("Failed to setup encryption circuit");

        Command::new("snarkjs")
            .current_dir(temp_dir.path())
            .args([
                "zkey",
                "export",
                "verificationkey",
                "encryption_final.zkey",
                "verification_key.json"
            ])
            .output()
            .expect("Failed to export encryption verification key");

        (decryption_circuit, encryption_circuit, temp_dir)
    }

    #[test]
    fn test_decryption_circuit() {
        let (decryption_circuit, encryption_circuit, _temp_dir) = setup_test_circuit();
        
        // Generate test keypair
        let mut rng = StdRng::seed_from_u64(0x123);
        let private_key = JubJubScalar::random(&mut rng);
        let _public_key = GENERATOR_EXTENDED * &private_key;
        
        // Create a random message point
        let message = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
        
        // Convert message to BigUint for encryption
        let message_affine = message.to_affine();
        let message_x = num_bigint::BigInt::from_bytes_le(num_bigint::Sign::Plus, &message_affine.get_u().to_bytes());
        let message_y = num_bigint::BigInt::from_bytes_le(num_bigint::Sign::Plus, &message_affine.get_v().to_bytes());
        
        // Encrypt the message using the encryption circuit
        let encrypted_result = encryption_circuit.encrypt(&message_x.to_biguint().unwrap())
            .expect("Failed to encrypt message");
        
        // Extract the encrypted message from the proof's public inputs
        let public_inputs = encrypted_result["publicInputs"].as_object().unwrap();
        let encrypted_message_x = public_inputs["encryptedMessage[0]"].as_str().unwrap();
        let encrypted_message_y = public_inputs["encryptedMessage[1]"].as_str().unwrap();
        let ephemeral_key_x = public_inputs["ephemeralKey[0]"].as_str().unwrap();
        let ephemeral_key_y = public_inputs["ephemeralKey[1]"].as_str().unwrap();

        // Prepare decryption input
        let decryption_input = json!({
            "ephemeralKey": [
                ephemeral_key_x,
                ephemeral_key_y
            ],
            "encryptedMessage": [
                encrypted_message_x,
                encrypted_message_y
            ],
            "privateKey": private_key.to_string()
        });

        // Generate witness for decryption
        let witness_path = decryption_circuit.generate_witness(&decryption_input)
            .expect("Failed to generate decryption witness");
        assert!(witness_path.exists(), "Decryption witness file was not created");

        // Generate proof for decryption
        let (proof, public_inputs) = decryption_circuit.generate_proof(&witness_path)
            .expect("Failed to generate decryption proof");

        // Verify the decryption proof
        let is_valid = decryption_circuit.verify_proof(&proof, &public_inputs)
            .expect("Failed to verify decryption proof");
        assert!(is_valid, "Decryption proof verification failed");

        // Extract the decrypted message from the public inputs
        let decrypted_message_x = public_inputs["decryptedMessage[0]"].as_str().unwrap();
        let decrypted_message_y = public_inputs["decryptedMessage[1]"].as_str().unwrap();

        // Compare the original and decrypted messages
        assert_eq!(decrypted_message_x, message_x.to_string(), "Decrypted message X coordinate doesn't match original");
        assert_eq!(decrypted_message_y, message_y.to_string(), "Decrypted message Y coordinate doesn't match original");
    }

    #[test]
    fn test_decryption_circuit_invalid_input() {
        let (decryption_circuit, _, _) = setup_test_circuit();
        
        // Test with invalid input (wrong format)
        let invalid_input = json!({
            "ephemeralKey": "invalid",
            "encryptedMessage": "invalid",
            "privateKey": "invalid"
        });

        // Try to generate witness and expect failure (non-zero exit code or error output)
        let input_path = decryption_circuit.build_dir.join("decrypt_input.json");
        fs::write(&input_path, serde_json::to_string_pretty(&invalid_input).unwrap()).expect("Failed to write input file");
        let decryption_js_dir = decryption_circuit.build_dir.join("decryption_js");
        let output = Command::new("node")
            .current_dir(&decryption_js_dir)
            .args([
                "generate_witness.js",
                "decryption.wasm",
                "../decrypt_input.json",
                "../decrypt_witness.wtns",
            ])
            .output()
            .expect("Failed to run node for witness generation");
        assert!(!output.status.success() || !output.stderr.is_empty(), "generate_witness should fail with invalid input, but got success. Stdout: {} Stderr: {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    }
} 