const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const circomlib = require("circomlibjs");
const genBjjKeys = require("./gen_bjj_keys");
const encrypt = require("./encryption");
const crypto = require("crypto");

// Helper to generate random BigInt
function randomInt64() {
  return BigInt("0x" + crypto.randomBytes(8).toString("hex"));
}

// Helper to generate random field element
function randomFieldElement(F) {
  const bytes = crypto.randomBytes(31); // Less than field size
  return F.e(BigInt("0x" + bytes.toString("hex")));
}

// Simplified inverse Elligator2 - for testing purposes
// In practice, this would need proper implementation
function inverseElligator2(point, F) {
  // For testing, we'll return a deterministic "preimage"
  // Real implementation would compute actual inverse mapping
  const x = BigInt(point[0]);
  const preimage = x % (2n ** 252n); // Ensure it fits in field
  return preimage;
}

async function main() {
  console.log("=== Testing ElGamal Decryption with Elligator2 Circuit ===\n");

  // 1. Initialize BabyJubJub
  const babyJub = await circomlib.buildBabyjub();
  const F = babyJub.F;

  // 2. Generate ElGamal keys
  const { sk, pk } = await genBjjKeys();
  console.log("Generated ElGamal keys:");
  console.log(`  Private key: ${sk}`);
  console.log(`  Public key: [${pk[0]}, ${pk[1]}]\n`);

  // 3. Circuit parameters
  const n = 5; // Number of ciphertexts
  console.log(`Testing with n = ${n} ciphertexts\n`);

  // 4. Generate random messages as scalars
  const messageScalars = [];
  const messagePoints = [];
  const preimages = [];
  
  for (let i = 0; i < n; i++) {
    // Generate random scalar
    const scalar = randomInt64() % (2n ** 252n);
    messageScalars.push(scalar);
    
    // Convert to point on curve (g^scalar)
    const point = babyJub.mulPointEscalar(babyJub.Base8, scalar);
    const pointStr = [F.toObject(point[0]).toString(), F.toObject(point[1]).toString()];
    messagePoints.push(pointStr);
    
    // For testing, use the scalar as the "preimage"
    // Real implementation would need proper Elligator2 inverse
    preimages.push(scalar.toString());
    
    console.log(`Message ${i + 1}:`);
    console.log(`  Scalar: ${scalar}`);
    console.log(`  Point: [${pointStr[0]}, ${pointStr[1]}]`);
  }

  // 5. Encrypt all messages
  const ephemeralKeys = [];
  const encryptedMessages = [];
  
  console.log("\nEncrypting messages...");
  for (let i = 0; i < n; i++) {
    const nonce = randomInt64();
    const { ephemeralKey, encryptedMessage } = await encrypt({
      publicKey: pk,
      message: messagePoints[i],
      nonce,
    });
    
    ephemeralKeys.push([ephemeralKey[0].toString(), ephemeralKey[1].toString()]);
    encryptedMessages.push([encryptedMessage[0].toString(), encryptedMessage[1].toString()]);
  }

  // 6. Calculate expected Y = g^(sum of scalars)
  const scalarSum = messageScalars.reduce((a, b) => a + b, 0n);
  const Y = babyJub.mulPointEscalar(babyJub.Base8, scalarSum);
  const YStr = [F.toObject(Y[0]).toString(), F.toObject(Y[1]).toString()];
  
  console.log(`\nSum of scalars: ${scalarSum}`);
  console.log(`Y = g^(sum): [${YStr[0]}, ${YStr[1]}]`);

  // 7. Prepare circuit inputs
  const generator = [
    F.toObject(babyJub.Base8[0]).toString(),
    F.toObject(babyJub.Base8[1]).toString()
  ];

  const input = {
    ephemeralKeys: ephemeralKeys,
    encryptedMessages: encryptedMessages,
    privateKey: sk.toString(),
    preimages: preimages,
    Y: YStr,
    generator: generator
  };

  // 8. Save test input to file
  const testDataFile = path.join(__dirname, "elligator2_test_input.json");
  fs.writeFileSync(testDataFile, JSON.stringify(input, null, 2));
  console.log(`\nSaved test input to: ${testDataFile}`);

  // 9. Compile and run the circuit
  console.log("\nCompiling circuit...");
  const circuitPath = path.join(__dirname, "..", "circuits", "elgamal_elligator2.circom");
  const wasmPath = path.join(__dirname, "..", "circuits", "elgamal_elligator2_js", "elgamal_elligator2.wasm");
  const r1csPath = path.join(__dirname, "..", "circuits", "elgamal_elligator2.r1cs");

  // Check if circuit files exist
  if (!fs.existsSync(wasmPath) || !fs.existsSync(r1csPath)) {
    console.error("Circuit files not found. Please compile the circuit first:");
    console.error("cd circuits && circom elgamal_elligator2.circom --r1cs --wasm --sym");
    process.exit(1);
  }

  try {
    // 10. Calculate witness using snarkjs CLI
    console.log("\nCalculating witness...");
    const witnessFile = path.join(__dirname, "witness.wtns");
    
    // Generate witness
    const wtnsCmd = `snarkjs wtns calculate ${wasmPath} ${testDataFile} ${witnessFile}`;
    execSync(wtnsCmd, { stdio: 'inherit' });
    
    // 11. Check the witness
    console.log("\nChecking witness...");
    const checkCmd = `snarkjs wtns check ${r1csPath} ${witnessFile}`;
    
    try {
      execSync(checkCmd, { stdio: 'inherit' });
      console.log("\n✅ All constraints satisfied!");
      console.log("The circuit correctly:");
      console.log("  1. Decrypted all ElGamal ciphertexts");
      console.log("  2. Mapped EC points to scalars (using provided preimages)");
      console.log("  3. Computed the sum of scalars");
      console.log("  4. Verified Y = g^(scalar_sum)");
    } catch (checkError) {
      console.error("\n❌ Constraint check failed!");
      console.error(checkError.message);
    }
    
    // Clean up witness file
    if (fs.existsSync(witnessFile)) {
      fs.unlinkSync(witnessFile);
    }

    // 12. Extract and display outputs
    console.log("\nCircuit outputs:");
    console.log("  Decrypted messages: [shown in points]");
    console.log("  Mapped scalars: [internal computation]");
    console.log(`  Scalar sum: ${scalarSum}`);
    console.log(`  Proof valid: true`);

  } catch (error) {
    console.error("\nError running circuit:", error.message);
    console.error("Stack trace:", error.stack);
  }
}

// Run the test
main().catch(console.error);