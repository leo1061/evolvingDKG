#!/bin/bash


set -e

# Function to clean up build artifacts
cleanup() {
    echo "🧹 Cleaning up build artifacts..."
    rm -rf build
    mkdir -p build
    rm -f bjj_sk*.txt bjj_pk*.txt
    rm -f *.wtns
    if [ -f "package.json" ]; then
        mv package.json package.json.tmp
        rm -f *.json
        mv package.json.tmp package.json
    else
        rm -f *.json
    fi
    echo "Cleanup complete"
}

# Function to handle errors
handle_error() {
    echo "Error occurred at step: $1"
    # cleanup
    exit 1
}

# Set up error handling
trap 'handle_error $LINENO' ERR

echo "🔐 ElGamal Demo Script"
echo "====================="

# Clean up any existing artifacts
# cleanup


# Use Node.js for BabyJubJub key generation
echo "1. Generating keys..."
node -e "
const gen = require('./gen_bjj_keys');
gen().then(({ sk, pk }) => {
  const fs = require('fs');
  fs.writeFileSync('bjj_sk.txt', sk);
  fs.writeFileSync('bjj_pk.txt', JSON.stringify(pk));
  console.log('Generated BabyJubJub keys');
});
"

# Get the generated keys
SK=$(cat bjj_sk.txt)
PUBKEY=$(cat bjj_pk.txt)

echo "2. Compiling circuits..."
npm run compile-all

echo "3. Setting up circuits..."
# Use our new setup module
node -e "
const CircuitSetup = require('./circuits/setup');
const setup = new CircuitSetup();
setup.setupAll();
"

# 4. Encrypt message
MSG=123
echo -e "\n4. Encrypting message $MSG..."
# Encode message as a BabyJubJub point
ENCODED_MSG=$(node encode_message.js $MSG)

# Generate a random nonce key that's within the field range using Node.js
NONCE_KEY=$(node -e "
const fieldSize = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const randomBytes = require('crypto').randomBytes(10);
const randomBigInt = BigInt('0x' + randomBytes.toString('hex'));
console.log((randomBigInt % fieldSize).toString());
")

# Create input.json for the circuit
echo "{
    \"message\": $ENCODED_MSG,
    \"nonceKey\": \"$NONCE_KEY\",
    \"publicKey\": $PUBKEY
}" > build/input.json

# Generate encryption proof using our new module
echo -e "\n5. Generating and verifying encryption proof..."
node -e "
const EncryptionCircuit = require('./circuits/encryption');
const encryptionCircuit = new EncryptionCircuit();
const witnessPath = encryptionCircuit.generateWitness(require('./build/input.json'));
const { proof, public: publicInputs } = encryptionCircuit.generateProof(witnessPath);
encryptionCircuit.verifyProof(proof, publicInputs);
"

# 6. Decrypt message
echo -e "\n6. Decrypting message..."
# Create decryption input
cat > build/decrypt_input.json << EOF
{
  "ephemeralKeys": [
    [$(cat build/public.json | jq '.[0] | tonumber'), $(cat build/public.json | jq '.[1] | tonumber')],
    [$(cat build/public.json | jq '.[0] | tonumber'), $(cat build/public.json | jq '.[1] | tonumber')],
    [$(cat build/public.json | jq '.[0] | tonumber'), $(cat build/public.json | jq '.[1] | tonumber')],
    [$(cat build/public.json | jq '.[0] | tonumber'), $(cat build/public.json | jq '.[1] | tonumber')],
    [$(cat build/public.json | jq '.[0] | tonumber'), $(cat build/public.json | jq '.[1] | tonumber')]
  ],

  "encryptedMessages": [
    [$(cat build/public.json | jq '.[2] | tonumber'), $(cat build/public.json | jq '.[3] | tonumber')],
    [$(cat build/public.json | jq '.[2] | tonumber'), $(cat build/public.json | jq '.[3] | tonumber')],
    [$(cat build/public.json | jq '.[2] | tonumber'), $(cat build/public.json | jq '.[3] | tonumber')],
    [$(cat build/public.json | jq '.[2] | tonumber'), $(cat build/public.json | jq '.[3] | tonumber')],
    [$(cat build/public.json | jq '.[2] | tonumber'), $(cat build/public.json | jq '.[3] | tonumber')]
  ],

  "preimages": [1, 1, 1, 1, 1],

  "Y": [0, 0],
  "generator": [1, 2],

  "privateKey": "$SK"
}
EOF

# Generate and verify decryption proof using our new module
echo -e "\n7. Generating and verifying decryption proof..."
node -e "
const DecryptionCircuit = require('./circuits/decryption');
const decryptionCircuit = new DecryptionCircuit();
const witnessPath = decryptionCircuit.generateWitness(require('./build/decrypt_input.json'));
const { proof, public } = decryptionCircuit.generateProof(witnessPath);
decryptionCircuit.verifyProof(proof, public);
"

echo -e "\n✨ Demo completed successfully!"
echo -e "\n✨ All done! Build artifacts are preserved in the build directory."
