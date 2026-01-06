// scripts/testRLpot17.js
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const circomlib = require("circomlibjs");
const { execSync } = require("child_process");

// genera un BigInt casuale di 64 bit
function randomInt64() {
  return BigInt("0x" + crypto.randomBytes(8).toString("hex"));
}
// JSON.stringify per BigInt
function bigintReplacer(_, v) {
  return typeof v === "bigint" ? v.toString() : v;
}

(async () => {
  // Parse command line arguments
  const args = process.argv.slice(2);

  if (args.length < 1) {
    console.error(
      "Usage: node testRLpot17.js <coeffs> [n]"
    );
    console.error("  coeffs: polynomial coefficients as comma-separated values");
    console.error("  n: number of parties (optional, default: 3)");
    console.error("  Note: Circuit will be configured based on coefficients and n");
    console.error("  Example: '1,2' 3 for polynomial f(x) = 1 + 2x with 3 parties");
    console.error("  Example: '1,2,3' 5 for polynomial f(x) = 1 + 2x + 3x² with 5 parties");
    process.exit(1);
  }

  // 1) Parse polynomial coefficients from command line
  const coeffsStr = args[0].split(',');
  const coeffs = coeffsStr.map(c => {
    const val = BigInt(c.trim());
    // Keep coefficients small to avoid Elligator2 issues
    return val % 1000n;
  });
  console.log(`→ Polynomial coefficients: ${coeffs.map(c => c.toString())}`);

  // 2) Configure circuit parameters based on coefficients and command line args
  const n = args.length >= 2 ? parseInt(args[1]) : 3; // Allow configurable n, default 3
  const t = coeffs.length - 1; // Infer degree from number of coefficients
  
  if (isNaN(n) || n < 1) {
    console.error("Error: n must be a positive integer");
    process.exit(1);
  }
  
  console.log(`→ Inferred parameters: n=${n}, t=${t} (degree ${t} polynomial)`);
  
  // Update the circuit parameters dynamically
  let finalT = t;
  
  console.log(`→ Updating circuit to use parameters: n=${n}, t=${t}`);
  
  console.log(`→ Final parameters used: n=${n}, t=${finalT}`);
  
  // 2.5) Dynamically update the circuit file with correct parameters
  const circuitPath = path.resolve(__dirname, "..", "circuits", "RL.circom");
  let circuitContent = fs.readFileSync(circuitPath, "utf8");
  
  // Replace the hardcoded instantiation with the dynamic one
  const oldInstantiation = /component main = HomomorphicPolyEval\(\d+, \d+\);/;
  const newInstantiation = `component main = HomomorphicPolyEval(${n}, ${finalT});`;
  
  if (circuitContent.match(oldInstantiation)) {
    circuitContent = circuitContent.replace(oldInstantiation, newInstantiation);
    fs.writeFileSync(circuitPath, circuitContent);
    console.log(`→ Updated circuit instantiation to: ${newInstantiation}`);
  } else {
    console.warn(`→ Could not find circuit instantiation pattern to update`);
  }

  // 3) Initialize BabyJub
  const babyJub = await circomlib.buildBabyjub();
  const F = babyJub.F;

  // 4) Generate random public keys for each party
  const pk_x = [];
  const pk_y = [];
  const omega = [];
  
  for (let i = 0; i < n; i++) {
    // Generate random private key and derive public key
    const sk_i = randomInt64();
    const pk_i = babyJub.mulPointEscalar(babyJub.Base8, sk_i);
    pk_x.push(BigInt(F.toObject(pk_i[0])));
    pk_y.push(BigInt(F.toObject(pk_i[1])));
    
    // Generate random omega for encryption
    omega.push(randomInt64());
  }

  // 5) Evaluate polynomial at each index to get x_j values
  const x_j = [];
  for (let j = 0; j < n; j++) {
    const x = BigInt(j + 1); // 1-based indices
    let result = 0n;
    // Horner's method: f(x) = a_0 + x(a_1 + x(a_2 + ... + x*a_t))
    for (let i = coeffs.length - 1; i >= 0; i--) {
      result = coeffs[i] + x * result;
    }
    x_j.push(result);
  }
  console.log(`→ Polynomial evaluations x_j: ${x_j.map(x => x.toString())}`);

  // 6) For testing, use dummy ciphertexts that will pass the constraints
  // In a real implementation, these would be properly generated ElGamal ciphertexts
  const c1_x = [];
  const c1_y = [];
  const c2_x = [];
  const c2_y = [];
  
  for (let j = 0; j < n; j++) {
    // c1 = g^omega
    const c1_point = babyJub.mulPointEscalar(babyJub.Base8, omega[j]);
    c1_x.push(BigInt(F.toObject(c1_point[0])));
    c1_y.push(BigInt(F.toObject(c1_point[1])));
    
    // For testing, generate c2 that will match what the circuit expects
    // This is a simplified approach - real implementation would use proper ElGamal
    const dummy_msg_point = babyJub.mulPointEscalar(babyJub.Base8, x_j[j]);
    const pk_point = [F.e(pk_x[j]), F.e(pk_y[j])];
    const pk_omega = babyJub.mulPointEscalar(pk_point, omega[j]);
    const msg_point_f = [F.e(dummy_msg_point[0]), F.e(dummy_msg_point[1])];
    const c2_point = babyJub.addPoint(msg_point_f, pk_omega);
    c2_x.push(BigInt(F.toObject(c2_point[0])));
    c2_y.push(BigInt(F.toObject(c2_point[1])));
  }

  // 7) Calculate Y = g^{f(0)}
  const f_0 = coeffs[0]; // f(0) = a_0
  const Y_point = babyJub.mulPointEscalar(babyJub.Base8, f_0);
  const Y_x = BigInt(F.toObject(Y_point[0]));
  const Y_y = BigInt(F.toObject(Y_point[1]));
  console.log(`→ Y = g^{f(0)} where f(0) = ${f_0}: [${Y_x}, ${Y_y}]`);

  // 8) Prepare input for circuit
  const BUILD = path.resolve(__dirname, "..", "build");
  fs.mkdirSync(BUILD, { recursive: true });
  
  const input = {
    pk_x,
    pk_y,
    c1_x,
    c1_y,
    c2_x,
    c2_y,
    Y_x,
    Y_y,
    coeffs,
    omega
  };
  
  fs.writeFileSync(
    path.join(BUILD, "input_RL.json"),
    JSON.stringify(input, bigintReplacer, 2)
  );
  
  console.log(`→ Input written to build/input_RL.json`);
  console.log(`→ Circuit parameters: n=${n}, t=${t}`);
  
  // 9) Run full circuit pipeline: compile → setup → prove → verify
  try {
    console.log("→ Compiling circuit...");
    execSync(`circom circuits/RL.circom --r1cs --wasm -o build`, { 
      cwd: path.resolve(__dirname, ".."), 
      stdio: "inherit" 
    });
    
    console.log("→ Generating witness...");
    execSync(`node build/RL_js/generate_witness.js build/RL_js/RL.wasm build/input_RL.json build/witness_RL.wtns`, {
      cwd: path.resolve(__dirname, ".."),
      stdio: "inherit"
    });
    
    console.log("→ Checking witness...");
    execSync(`snarkjs wtns check build/RL.r1cs build/witness_RL.wtns`, {
      cwd: path.resolve(__dirname, ".."),
      stdio: "inherit"
    });
    
    console.log("→ Setting up trusted setup using pot17...");
    execSync(`snarkjs groth16 setup build/RL.r1cs build/pot17_final.ptau build/RL_0000.zkey`, {
      cwd: path.resolve(__dirname, ".."),
      stdio: "inherit"
    });
    
    console.log("→ Contributing to ceremony...");
    execSync(`echo "random entropy text $(date)" | snarkjs zkey contribute build/RL_0000.zkey build/RL_final.zkey --name="First contribution" -v`, {
      cwd: path.resolve(__dirname, ".."),
      stdio: "inherit",
      shell: true
    });
    
    console.log("→ Exporting verification key...");
    execSync(`snarkjs zkey export verificationkey build/RL_final.zkey build/RL_verification_key.json`, {
      cwd: path.resolve(__dirname, ".."),
      stdio: "inherit"
    });
    
    console.log("→ Generating proof...");
    execSync(`snarkjs groth16 prove build/RL_final.zkey build/witness_RL.wtns build/proof_RL.json build/public_RL.json`, {
      cwd: path.resolve(__dirname, ".."),
      stdio: "inherit"
    });
    
    console.log("→ Verifying proof...");
    execSync(`snarkjs groth16 verify build/RL_verification_key.json build/public_RL.json build/proof_RL.json`, {
      cwd: path.resolve(__dirname, ".."),
      stdio: "inherit"
    });
    
    console.log("✓ Full proof pipeline completed successfully!");
    
  } catch (error) {
    console.error("Error during circuit execution:", error.message);
    process.exit(1);
  }
})();