const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

class DecryptionCircuit {
  constructor(buildDir = "build") {
    this.buildDir = buildDir;
  }

  generateWitness(input) {
    const inputPath = path.join(this.buildDir, "decrypt_input.json");
    fs.writeFileSync(inputPath, JSON.stringify(input, null, 2));

    const witnessPath = path.join(this.buildDir, "decrypt_witness.wtns");
    execSync(
      `cd ${path.join(
        this.buildDir,
        "decryption_js"
      )} && node generate_witness.js decryption.wasm ../decrypt_input.json ../decrypt_witness.wtns`
    );

    return witnessPath;
  }

  generateProof(witnessPath) {
    const proofPath = path.join(this.buildDir, "decrypt_proof.json");
    const publicPath = path.join(this.buildDir, "decrypt_public.json");

    execSync(
      `snarkjs groth16 prove ${path.join(
        this.buildDir,
        "decryption_final.zkey"
      )} ${witnessPath} ${proofPath} ${publicPath}`
    );

    return {
      proof: JSON.parse(fs.readFileSync(proofPath)),
      public: JSON.parse(fs.readFileSync(publicPath)),
    };
  }

  verifyProof(proof, publicInputs) {
    const verificationKeyPath = path.join(
      this.buildDir,
      "decrypt_verification_key.json"
    );
    const proofPath = path.join(this.buildDir, "decrypt_proof.json");
    const publicPath = path.join(this.buildDir, "decrypt_public.json");

    fs.writeFileSync(proofPath, JSON.stringify(proof));
    fs.writeFileSync(publicPath, JSON.stringify(publicInputs));

    execSync(
      `snarkjs groth16 verify ${verificationKeyPath} ${publicPath} ${proofPath}`
    );
    return true;
  }
}

module.exports = DecryptionCircuit;
