const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

class CircuitSetup {
  constructor(buildDir = "build") {
    this.buildDir = buildDir;
  }

  generatePowersOfTau() {
    console.log("Generating powers of tau...");
    execSync(
      `snarkjs powersoftau new bn128 14 ${path.join(
        this.buildDir,
        "pot12_0000.ptau"
      )} -v`
    );
    execSync(
      `snarkjs powersoftau contribute ${path.join(
        this.buildDir,
        "pot12_0000.ptau"
      )} ${path.join(
        this.buildDir,
        "pot12_0001.ptau"
      )} --name="First contribution" --entropy="some random text here" -v`
    );
    execSync(
      `snarkjs powersoftau prepare phase2 ${path.join(
        this.buildDir,
        "pot12_0001.ptau"
      )} ${path.join(this.buildDir, "pot12_final.ptau")} -v`
    );
  }

  setupEncryptionCircuit() {
    console.log("Setting up encryption circuit...");
    execSync(
      `snarkjs groth16 setup ${path.join(
        this.buildDir,
        "encryption.r1cs"
      )} ${path.join(this.buildDir, "pot12_final.ptau")} ${path.join(
        this.buildDir,
        "encryption_0000.zkey"
      )}`
    );
    execSync(
      `snarkjs zkey contribute ${path.join(
        this.buildDir,
        "encryption_0000.zkey"
      )} ${path.join(
        this.buildDir,
        "encryption_0001.zkey"
      )} --name="First contribution" --entropy="more random text" -v`
    );
    execSync(
      `snarkjs zkey export verificationkey ${path.join(
        this.buildDir,
        "encryption_0001.zkey"
      )} ${path.join(this.buildDir, "verification_key.json")}`
    );
    fs.copyFileSync(
      path.join(this.buildDir, "encryption_0001.zkey"),
      path.join(this.buildDir, "encryption_final.zkey")
    );
  }

  setupDecryptionCircuit() {
    console.log("Setting up decryption circuit...");
    execSync(
      `snarkjs groth16 setup ${path.join(
        this.buildDir,
        "decryption.r1cs"
      )} ${path.join(this.buildDir, "pot12_final.ptau")} ${path.join(
        this.buildDir,
        "decryption_0000.zkey"
      )}`
    );
    execSync(
      `snarkjs zkey contribute ${path.join(
        this.buildDir,
        "decryption_0000.zkey"
      )} ${path.join(
        this.buildDir,
        "decryption_0001.zkey"
      )} --name="First contribution" --entropy="even more random text" -v`
    );
    execSync(
      `snarkjs zkey export verificationkey ${path.join(
        this.buildDir,
        "decryption_0001.zkey"
      )} ${path.join(this.buildDir, "decrypt_verification_key.json")}`
    );
    fs.copyFileSync(
      path.join(this.buildDir, "decryption_0001.zkey"),
      path.join(this.buildDir, "decryption_final.zkey")
    );
  }

  setupAll() {
    this.generatePowersOfTau();
    this.setupEncryptionCircuit();
    this.setupDecryptionCircuit();
  }
}

module.exports = CircuitSetup;
