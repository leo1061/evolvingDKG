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
    # cleanup
    exit 1
}

# Set up error handling
trap 'handle_error $LINENO' ERR

echo "🔐 Polynomial Encryption Demo Script"
echo "==================================="

# Clean up any existing artifacts
# cleanup
mkdir -p build

echo "1. Generating BabyJubJub keys..."
node scripts/gen_bjj_keys.js

# Use BabyJubJub keys
SK=$(cat bjj_sk.txt)
# Parse public key as numbers (not strings)
PUBKEY=$(cat bjj_pk.txt | jq '[.[] | tonumber]')

echo "2. Compiling circuits..."
# Compile the poly_encryption circuit specifically
circom circuits/poly_encryption.circom --r1cs --wasm --sym -o build -l node_modules
cd build/poly_encryption_js
npm install
cd ../..

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

# 5. Generate polynomial coefficients and evaluations
echo -e "\n5. Generating polynomial data..."
# Generate random coefficients for a degree 2 polynomial
COEFF0=$(node -e "console.log(Math.floor(Math.random() * 1000))")
COEFF1=$(node -e "console.log(Math.floor(Math.random() * 1000))")
COEFF2=$(node -e "console.log(Math.floor(Math.random() * 1000))")

# Calculate evaluations at points 1,2,3
X1=$((COEFF0 + COEFF1 + COEFF2))
X2=$((COEFF0 + 2*COEFF1 + 4*COEFF2))
X3=$((COEFF0 + 3*COEFF1 + 9*COEFF2))

# Generate random nonces for encryption
OMEGA1=$(node -e "console.log(Math.floor(Math.random() * 1000))")
OMEGA2=$(node -e "console.log(Math.floor(Math.random() * 1000))")
OMEGA3=$(node -e "console.log(Math.floor(Math.random() * 1000))")

# Create input.json for the circuit
cat > build/input.json << EOF
{
    "publicKeys": [
        $PUBKEY,
        $PUBKEY,
        $PUBKEY
    ],
    "ciphertexts": [
        [
            [0, 0],  // Will be filled by encryption
            [0, 0]
        ],
        [
            [0, 0],
            [0, 0]
        ],
        [
            [0, 0],
            [0, 0]
        ]
    ],
    "Y": [0, 0],  // Will be filled with g^f(0)
    "x": ["$X1", "$X2", "$X3"],
    "omega": ["$OMEGA1", "$OMEGA2", "$OMEGA3"],
    "coeffs": ["$COEFF0", "$COEFF1", "$COEFF2"]
}
EOF

# Generate witness
cd build/poly_encryption_js
node generate_witness.js poly_encryption.wasm ../input.json ../witness.wtns
cd ../..

# Generate zkey files
echo -e "\n6. Generating zkey files..."
snarkjs powersoftau new bn128 14 build/pot12_0000.ptau -v
snarkjs powersoftau contribute build/pot12_0000.ptau build/pot12_0001.ptau --name="First contribution" --entropy="some random text here" -v
snarkjs powersoftau prepare phase2 build/pot12_0001.ptau build/pot12_final.ptau -v

# Generate zkey files
snarkjs groth16 setup build/poly_encryption.r1cs build/pot12_final.ptau build/poly_encryption_0000.zkey
snarkjs zkey contribute build/poly_encryption_0000.zkey build/poly_encryption_0001.zkey --name="First contribution" --entropy="more random text" -v
snarkjs zkey export verificationkey build/poly_encryption_0001.zkey build/verification_key.json
cp build/poly_encryption_0001.zkey build/poly_encryption_final.zkey

# 7. Generate proof
echo -e "\n7. Generating proof..."
snarkjs groth16 prove build/poly_encryption_final.zkey build/witness.wtns build/proof.json build/public.json

# 8. Verify proof
echo -e "\n8. Verifying proof..."
snarkjs groth16 verify build/verification_key.json build/public.json build/proof.json

echo -e "\nDemo completed successfully!"
echo -e "\n✨ All done! Build artifacts are preserved in the build directory." 