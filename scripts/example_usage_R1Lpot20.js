// Example usage of test_R1Lpot20.js
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

// Example 1: Generate random messages and encrypt them
console.log("\n=== Example 1: Generate random messages ===");
console.log("Command: node test_R1Lpot20.js 12345 1234567890 9876543210 5");
console.log("This will:");
console.log("- Use sk=12345, pk=[1234567890, 9876543210]");
console.log("- Generate 5 random messages");
console.log("- Since 5 is odd, it will pad to 6 messages");
console.log("- Encrypt all messages and run the circuit proof\n");

// Example 2: Use external ciphertexts
console.log("\n=== Example 2: Use external ciphertexts ===");

// First, create a sample ciphertext file
const sampleCiphertexts = [
  [
    ["1234567890123456789", "9876543210987654321"],
    ["1111111111111111111", "2222222222222222222"]
  ],
  [
    ["3333333333333333333", "4444444444444444444"],
    ["5555555555555555555", "6666666666666666666"]
  ],
  [
    ["7777777777777777777", "8888888888888888888"],
    ["9999999999999999999", "1010101010101010101"]
  ],
  [
    ["1111111111111111111", "1212121212121212121"],
    ["1313131313131313131", "1414141414141414141"]
  ]
];

const cipherFile = path.join(__dirname, "example_ciphertexts.json");
fs.writeFileSync(cipherFile, JSON.stringify(sampleCiphertexts, null, 2));

console.log(`Created example ciphertext file: ${cipherFile}`);
console.log("\nCommand: node test_R1Lpot20.js 12345 1234567890 9876543210 4 example_ciphertexts.json 123456789 987654321");
console.log("This will:");
console.log("- Use sk=12345, pk=[1234567890, 9876543210]");
console.log("- Read 4 ciphertexts from example_ciphertexts.json");
console.log("- Use Y=[123456789, 987654321] as the expected sum point");
console.log("- Run the circuit proof with these inputs\n");

// Example 3: Odd number with padding
console.log("\n=== Example 3: Odd number with padding ===");

const paddedCiphertexts = [
  ...sampleCiphertexts,
  [
    ["1515151515151515151", "1616161616161616161"],
    ["1717171717171717171", "1818181818181818181"]
  ],
  [
    ["0", "0"],  // Padding ciphertext
    ["0", "0"]
  ]
];

const paddedFile = path.join(__dirname, "example_padded_ciphertexts.json");
fs.writeFileSync(paddedFile, JSON.stringify(paddedCiphertexts, null, 2));

console.log(`Created padded ciphertext file: ${paddedFile}`);
console.log("\nCommand: node test_R1Lpot20.js 12345 1234567890 9876543210 5 example_padded_ciphertexts.json 123456789 987654321");
console.log("This will:");
console.log("- Use sk=12345, pk=[1234567890, 9876543210]");
console.log("- Read 6 ciphertexts from example_padded_ciphertexts.json (5 + 1 padding)");
console.log("- Automatically detect padding since file has 6 ciphertexts for n=5");
console.log("- Use Y=[123456789, 987654321] as the expected sum point");
console.log("- Run the circuit proof with these inputs\n");

// Example 4: Using the alternative JSON format
console.log("\n=== Example 4: Alternative JSON format ===");

const altFormatCiphertexts = {
  cipher: sampleCiphertexts
};

const altFile = path.join(__dirname, "example_alt_format.json");
fs.writeFileSync(altFile, JSON.stringify(altFormatCiphertexts, null, 2));

console.log(`Created alternative format file: ${altFile}`);
console.log("\nCommand: node test_R1Lpot20.js 12345 1234567890 9876543210 4 example_alt_format.json 123456789 987654321");
console.log("This will work the same as Example 2 but uses the {cipher: [...]} format\n");

// Show actual execution examples (commented out to avoid running the actual script)
console.log("\n=== To run these examples: ===");
console.log("# Example 1 (random generation):");
console.log("node test_R1Lpot20.js 12345 1234567890 9876543210 5");
console.log("\n# Example 2 (external ciphertexts):");
console.log("node test_R1Lpot20.js 12345 1234567890 9876543210 4 example_ciphertexts.json 123456789 987654321");
console.log("\n# Example 3 (with padding):");
console.log("node test_R1Lpot20.js 12345 1234567890 9876543210 5 example_padded_ciphertexts.json 123456789 987654321");

// Clean up example files (optional)
console.log("\n\nNote: Example JSON files created in the current directory.");
console.log("You can delete them after testing with:");
console.log(`rm ${cipherFile} ${paddedFile} ${altFile}`);