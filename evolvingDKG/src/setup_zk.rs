use std::fs;
use std::path::PathBuf;
use std::process::Command;
use anyhow::{Result, Context};

pub struct CircuitSetup {
    build_dir: PathBuf,
}

impl CircuitSetup {
    pub fn new(build_dir: &str) -> Self {
        CircuitSetup {
            build_dir: PathBuf::from(build_dir),
            
        }
    }

    // run command `npm run compile-all`
    fn compile_all(&self) -> Result<()> {
        self.run_command(&format!(
            "cd .. && npm run compile-all-rust"
        ))?;
        
        Ok(())
    }

    fn check_required_files(&self) -> Result<()> {
        let required_files = [
            "encryption.r1cs",
            "decryption.r1cs",
        ];

        for file in required_files.iter() {
            let path = self.build_dir.join(file);
            if !path.exists() {
                anyhow::bail!(
                    "Required circuit file '{}' not found in {}. Please compile your circuits first.",
                    file,
                    self.build_dir.display()
                );
            }
        }
        Ok(())
    }

    fn run_command(&self, cmd: &str) -> Result<()> {
        // Ensure build directory exists
        fs::create_dir_all(&self.build_dir)
            .context("Failed to create build directory")?;

        println!("Running command: {}", cmd);
        
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .context("Failed to execute command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            anyhow::bail!(
                "Command failed with status {}:\nSTDOUT:\n{}\nSTDERR:\n{}",
                output.status,
                stdout,
                stderr
            );
        }
        Ok(())
    }

    pub fn generate_powers_of_tau(&self) -> Result<()> {
        println!("Generating powers of tau...");
        
        // Generate initial ptau file
        self.run_command(&format!(
            "snarkjs powersoftau new bn128 14 {} -v",
            self.build_dir.join("pot12_0000.ptau").display()
        ))?;

        // Contribute to ptau
        self.run_command(&format!(
            "snarkjs powersoftau contribute {} {} --name=\"First contribution\" --entropy=\"some random text here\" -v",
            self.build_dir.join("pot12_0000.ptau").display(),
            self.build_dir.join("pot12_0001.ptau").display()
        ))?;

        // Prepare phase 2
        self.run_command(&format!(
            "snarkjs powersoftau prepare phase2 {} {} -v",
            self.build_dir.join("pot12_0001.ptau").display(),
            self.build_dir.join("pot12_final.ptau").display()
        ))?;

        Ok(())
    }

    pub fn setup_encryption_circuit(&self) -> Result<()> {
        println!("Setting up encryption circuit...");

        // Setup encryption circuit
        self.run_command(&format!(
            "snarkjs groth16 setup {} {} {}",
            self.build_dir.join("encryption.r1cs").display(),
            self.build_dir.join("pot12_final.ptau").display(),
            self.build_dir.join("encryption_0000.zkey").display()
        ))?;

        // Contribute to zkey
        self.run_command(&format!(
            "snarkjs zkey contribute {} {} --name=\"First contribution\" --entropy=\"more random text\" -v",
            self.build_dir.join("encryption_0000.zkey").display(),
            self.build_dir.join("encryption_0001.zkey").display()
        ))?;

        // Export verification key
        self.run_command(&format!(
            "snarkjs zkey export verificationkey {} {}",
            self.build_dir.join("encryption_0001.zkey").display(),
            self.build_dir.join("verification_key.json").display()
        ))?;

        // Copy final zkey
        fs::copy(
            self.build_dir.join("encryption_0001.zkey"),
            self.build_dir.join("encryption_final.zkey"),
        ).context("Failed to copy zkey file")?;

        Ok(())
    }

    pub fn setup_decryption_circuit(&self) -> Result<()> {
        println!("Setting up decryption circuit...");

        // Setup decryption circuit
        self.run_command(&format!(
            "snarkjs groth16 setup {} {} {}",
            self.build_dir.join("decryption.r1cs").display(),
            self.build_dir.join("pot12_final.ptau").display(),
            self.build_dir.join("decryption_0000.zkey").display()
        ))?;

        // Contribute to zkey
        self.run_command(&format!(
            "snarkjs zkey contribute {} {} --name=\"First contribution\" --entropy=\"even more random text\" -v",
            self.build_dir.join("decryption_0000.zkey").display(),
            self.build_dir.join("decryption_0001.zkey").display()
        ))?;

        // Export verification key
        self.run_command(&format!(
            "snarkjs zkey export verificationkey {} {}",
            self.build_dir.join("decryption_0001.zkey").display(),
            self.build_dir.join("decrypt_verification_key.json").display()
        ))?;

        // Copy final zkey
        fs::copy(
            self.build_dir.join("decryption_0001.zkey"),
            self.build_dir.join("decryption_final.zkey"),
        ).context("Failed to copy zkey file")?;

        Ok(())
    }

    pub fn setup_all(&self) -> Result<()> {
        // Check for required circuit files first
        // self.check_required_files()?;
        
        self.compile_all()?;
        self.generate_powers_of_tau()?;
        self.setup_encryption_circuit()?;
        self.setup_decryption_circuit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_circuit_setup_creation() {
        let temp_dir = TempDir::new().unwrap();
        let setup = CircuitSetup::new(temp_dir.path().to_str().unwrap());
        assert_eq!(setup.build_dir, temp_dir.path());
    }
} 