#!/bin/bash

set -e

# Function to handle errors
handle_error() {
    echo "🛑 Error occurred at line $1"
    exit 1
}

trap 'handle_error $LINENO' ERR

echo "🔍 Testing keys_check.circom"
echo "==========================="

# 1. Generate a new BabyJubJub key pair
echo "1. Generating BabyJubJub key pair..."
node scripts/gen_bjj_keys.js
PRIVATE_KEY=$(< bjj_sk.txt)
PUBLIC_KEY=$(< bjj_pk.txt)

echo "   Private Key: $PRIVATE_KEY"
echo "   Public Key: $PUBLIC_KEY"

# 2. Compile all circuits (including keys_check)
echo -e "\n2. Compiling all circuits..."
npm run compile-all

# 3. Run trusted setup for all circuits (including keys_check)
echo -e "\n3. Running trusted setup..."
node -e "
const CircuitSetup = require('./scripts/circuits/setup');
new CircuitSetup().setupAll();
"

# 4. Prepare input JSON for keys_check
echo -e "\n4. Preparing input JSON for keys_check..."
cat > build/keys_check_input.json << EOF
{
  "privateKey": $PRIVATE_KEY,
  "publicKey": $PUBLIC_KEY
}
EOF

# 5. Calculate the witness
echo -e "\n5. Calculating witness..."
snarkjs wtns calculate \
  build/keys_check_js/keys_check.wasm \
  build/keys_check_input.json \
  build/keys_check_witness.wtns

# 6. Generate the proof
echo -e "\n6. Generating proof..."
snarkjs groth16 prove \
  build/keys_check_final.zkey \
  build/keys_check_witness.wtns \
  build/keys_check_proof.json \
  build/keys_check_public.json

# 7. Verify the proof
echo -e "\n7. Verifying proof..."
snarkjs groth16 verify \
  build/keys_check_verification_key.json \
  build/keys_check_public.json \
  build/keys_check_proof.json

echo -e "\n✅ keys_check circuit verification completed successfully!"
# Clean up generated files
echo -e "\nCleaning up generated files..."
rm -f bjj_sk.txt bjj_pk.txt
rm -rf build/keys_check_js
rm -f build/keys_check_witness.wtns
rm -f build/keys_check_proof.json build/keys_check_public.json
rm -f build/keys_check_final.zkey build/keys_check_verification_key.json        