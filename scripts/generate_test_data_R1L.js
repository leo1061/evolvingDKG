// Generate test data for test_R1Lpot20.js
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

// JSON.stringify replacer for BigInt
function bigintReplacer(_, v) {
  return typeof v === "bigint" ? v.toString() : v;
}

(async () => {
  console.log("=== Generating Test Data for R1L Circuit ===\n");

  // 1. Generate ElGamal keys
  const { sk, pk } = await genBjjKeys();
  console.log("Generated ElGamal keys:");
  console.log(`  Private key (sk): ${sk}`);
  console.log(`  Public key (pk): [${pk[0]}, ${pk[1]}]`);

  // 2. Initialize BabyJubJub
  const babyJub = await circomlib.buildBabyjub();
  const F = babyJub.F;

  // 3. Generate test cases
  const testCases = [
    { n: 4, name: "even_4" },
    { n: 5, name: "odd_5" },
    { n: 10, name: "even_10" }
  ];

  for (const testCase of testCases) {
    console.log(`\n--- Test Case: ${testCase.name} (n=${testCase.n}) ---`);
    
    let n = testCase.n;
    const originalN = n;
    
    // Generate random messages
    const msgs = Array.from({ length: n }, randomInt64);
    console.log(`Generated ${n} random messages`);
    
    // Handle padding for odd n
    let padded = false;
    if (n % 2 === 1) {
      msgs.push(0n);
      n += 1;
      padded = true;
      console.log(`Added padding (0 message) - new n=${n}`);
    }
    
    // Encrypt all messages
    const ciphertexts = [];
    for (let m of msgs) {
      const Pm = babyJub.mulPointEscalar(babyJub.Base8, m);
      const M = [F.toObject(Pm[0]).toString(), F.toObject(Pm[1]).toString()];
      const nonce = randomInt64();
      const { ephemeralKey, encryptedMessage } = await encrypt({
        publicKey: pk,
        message: M,
        nonce,
      });
      ciphertexts.push([
        [ephemeralKey[0], ephemeralKey[1]],
        [encryptedMessage[0], encryptedMessage[1]]
      ]);
    }
    
    // Calculate Y = Base8^(sum of original messages)
    const sumOriginal = msgs
      .slice(0, padded ? msgs.length - 1 : msgs.length)
      .reduce((a, b) => a + b, 0n);
    const Psum = babyJub.mulPointEscalar(babyJub.Base8, sumOriginal);
    const Y = [F.toObject(Psum[0]).toString(), F.toObject(Psum[1]).toString()];
    
    // Save test data
    const testData = {
      description: `Test case with n=${originalN}${padded ? " (padded to " + n + ")" : ""}`,
      sk: sk.toString(),
      pk: [pk[0].toString(), pk[1].toString()],
      n: originalN,
      actualN: n,
      padded: padded,
      Y: Y,
      ciphertexts: ciphertexts,
      // Include original messages for verification (in real use, these wouldn't be available)
      _debug_messages: msgs.map(m => m.toString())
    };
    
    const filename = path.join(__dirname, `testdata_${testCase.name}.json`);
    fs.writeFileSync(filename, JSON.stringify(testData, null, 2));
    console.log(`Saved test data to: ${filename}`);
    
    // Print usage command
    console.log(`\nUsage command:`);
    console.log(`node test_R1Lpot20.js ${sk} ${pk[0]} ${pk[1]} ${originalN} testdata_${testCase.name}.json ${Y[0]} ${Y[1]}`);
  }
  
  // Save Y values for script generation
  const Ys = [];
  
  for (let i = 0; i < testCases.length; i++) {
    const testData = JSON.parse(fs.readFileSync(path.join(__dirname, `testdata_${testCases[i].name}.json`), 'utf8'));
    Ys.push(testData.Y);
  }
  
  // Create a script to run all tests
  const runAllScript = `#!/bin/bash
# Run all test cases for R1L circuit

echo "Running all R1L test cases..."

# Test case 1: even n=4
echo -e "\\n=== Test Case: even_4 ==="
node test_R1Lpot20.js ${sk} ${pk[0]} ${pk[1]} 4 testdata_even_4.json ${Ys[0][0]} ${Ys[0][1]}

# Test case 2: odd n=5 (with padding)
echo -e "\\n=== Test Case: odd_5 ==="
node test_R1Lpot20.js ${sk} ${pk[0]} ${pk[1]} 5 testdata_odd_5.json ${Ys[1][0]} ${Ys[1][1]}

# Test case 3: even n=10
echo -e "\\n=== Test Case: even_10 ==="
node test_R1Lpot20.js ${sk} ${pk[0]} ${pk[1]} 10 testdata_even_10.json ${Ys[2][0]} ${Ys[2][1]}

echo -e "\\nAll tests completed!"
`;

  fs.writeFileSync(path.join(__dirname, "run_all_tests_R1L.sh"), runAllScript);
  fs.chmodSync(path.join(__dirname, "run_all_tests_R1L.sh"), 0o755);
  console.log("\n\nCreated run_all_tests_R1L.sh - execute it to run all test cases");
  
  console.log("\n=== Test Data Generation Complete ===");
})();