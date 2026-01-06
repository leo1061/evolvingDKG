const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

class EncryptionCircuit {
  constructor(buildDir = "build") {
    this.buildDir = buildDir;
  }

  generateWitness(input) {
    const inputPath = path.join(this.buildDir, "input.json");
    fs.writeFileSync(inputPath, JSON.stringify(input, null, 2));

    const witnessPath = path.join(this.buildDir, "witness.wtns");
    execSync(
      `cd ${path.join(
        this.buildDir,
        "encryption_js"
      )} && node generate_witness.js encryption.wasm ../input.json ../witness.wtns`
    );

    return witnessPath;
  }

  generateProof(witnessPath) {
    const proofPath = path.join(this.buildDir, "proof.json");
    const publicPath = path.join(this.buildDir, "public.json");

    execSync(
      `snarkjs groth16 prove ${path.join(
        this.buildDir,
        "encryption_final.zkey"
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
      "verification_key.json"
    );
    const proofPath = path.join(this.buildDir, "proof.json");
    const publicPath = path.join(this.buildDir, "public.json");

    fs.writeFileSync(proofPath, JSON.stringify(proof));
    fs.writeFileSync(publicPath, JSON.stringify(publicInputs));

    execSync(
      `snarkjs groth16 verify ${verificationKeyPath} ${publicPath} ${proofPath}`
    );
    return true;
  }
}

module.exports = EncryptionCircuit;
