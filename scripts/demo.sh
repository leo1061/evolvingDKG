#!/bin/bash

set -e

# Function to clean up build artifacts
cleanup() {
    echo "🧹 Cleaning up build artifacts..."
    rm -rf build
    mkdir -p build
    rm -f bjj_sk.txt bjj_pk.txt
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
    cleanup
    exit 1
}

# Set up error handling
trap 'handle_error $LINENO' ERR

echo "🔐 ElGamal Demo Script"
echo "====================="

# Clean up any existing artifacts
# cleanup
mkdir -p build

echo "1. Generating keys..."
# Use Rust keygen for BabyJubJub keys
cd rust-keygen
cargo run
cd ..

# Get the generated keys
SK=$(cat bjj_sk.txt)
PUBKEY=$(cat bjj_pk.txt | jq '[.[] | tonumber]')

echo "2. Compiling circuits..."
npm run compile-all

echo "3. Keys generated:"
if [ -f "bjj_sk.txt" ]; then
    echo "BabyJubJub Private key: bjj_sk.txt"
else
    echo "Missing private key"
    exit 1
fi

if [ -f "bjj_pk.txt" ]; then
    echo "BabyJubJub Public key: bjj_pk.txt"
else
    echo "Missing public key"
    exit 1
fi

echo "4. Circuits compiled:"
if [ -d "build" ]; then
    echo "Build directory created"
    ls -l build
else
    echo "Missing build directory"
    exit 1
fi

# 5. Encrypt message
MSG=123
echo -e "\n5. Encrypting message $MSG..."
# Encode message as a BabyJubJub point and ensure it's a proper number array
ENCODED_MSG=$(node scripts/encode_message.js $MSG | grep -o '\[.*\]' | jq '[.[] | tonumber]')

# Generate a random nonce key that's within the field range using BigInt
NONCE_KEY=$(node -e "
const fieldSize = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const randomBytes = require('crypto').randomBytes(10);
const randomBigInt = BigInt('0x' + randomBytes.toString('hex'));
console.log((randomBigInt % fieldSize).toString());
")

# Create input.json for the circuit
cat > build/input.json << EOF
{
    "message": $(echo $ENCODED_MSG | jq '[.[] | tostring]'),
    "nonceKey": "$NONCE_KEY",
    "publicKey": $(echo $PUBKEY | jq '[.[] | tostring]')
}
EOF

# Generate witness
cd build/encryption_js
node generate_witness.js encryption.wasm ../input.json ../witness.wtns
cd ../..

# Generate zkey files
echo -e "\n6. Generating zkey files..."
# snarkjs powersoftau new bn128 12 build/pot12_0000.ptau -v
snarkjs powersoftau new bn128 14 build/pot12_0000.ptau -v

snarkjs powersoftau contribute build/pot12_0000.ptau build/pot12_0001.ptau --name="First contribution" --entropy="some random text here" -v
snarkjs powersoftau prepare phase2 build/pot12_0001.ptau build/pot12_final.ptau -v

# Generate encryption zkey files
snarkjs groth16 setup build/encryption.r1cs build/pot12_final.ptau build/encryption_0000.zkey
snarkjs zkey contribute build/encryption_0000.zkey build/encryption_0001.zkey --name="First contribution" --entropy="more random text" -v
snarkjs zkey export verificationkey build/encryption_0001.zkey build/verification_key.json
cp build/encryption_0001.zkey build/encryption_final.zkey

# Generate decryption zkey files
snarkjs groth16 setup build/decryption.r1cs build/pot12_final.ptau build/decryption_0000.zkey
snarkjs zkey contribute build/decryption_0000.zkey build/decryption_0001.zkey --name="First contribution" --entropy="even more random text" -v
snarkjs zkey export verificationkey build/decryption_0001.zkey build/decrypt_verification_key.json
cp build/decryption_0001.zkey build/decryption_final.zkey
# 7. Generate proof
echo -e "\n7. Generating proof..."
snarkjs groth16 prove build/encryption_final.zkey build/witness.wtns build/proof.json build/public.json

# 8. Verify proof
echo -e "\n8. Verifying proof..."
snarkjs groth16 verify build/verification_key.json build/public.json build/proof.json

# 9. Decrypt message
echo -e "\n9. Decrypting message..."
# Create decryption input
cat > build/decrypt_input.json << EOF
{
  "ephemeralKey": [
    $(cat build/public.json | jq '.[0]'),
    $(cat build/public.json | jq '.[1]')
  ],
  "encryptedMessage": [
    $(cat build/public.json | jq '.[2]'),
    $(cat build/public.json | jq '.[3]')
  ],
  "privateKey": "$SK"
}
EOF

cd build/decryption_js
node generate_witness.js decryption.wasm ../decrypt_input.json ../decrypt_witness.wtns
cd ../..

# Generate decryption proof
snarkjs groth16 prove build/decryption_final.zkey build/decrypt_witness.wtns build/decrypt_proof.json build/decrypt_public.json

# Verify decryption proof
snarkjs groth16 verify build/decrypt_verification_key.json build/decrypt_public.json build/decrypt_proof.json

echo -e "\nDemo completed successfully!"


echo -e "\n✨ All done! Build artifacts are preserved in the build directory."
