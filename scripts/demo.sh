#!/bin/bash

set -e

echo "🔐 ElGamal Demo Script"
echo "====================="

echo "1. Generating keys..."
cd rust-keygen
cargo run --bin keygen
cd ..

echo "2. Compiling circuits..."
npm run compile-all

echo "3. Keys generated:"
if [ -f "sk.txt" ]; then
    echo "✅ Private key: sk.txt"
else
    echo "❌ Private key not found"
fi

if [ -f "pk.txt" ]; then
    echo "✅ Public key: pk.txt"
else
    echo "❌ Public key not found"
fi

echo "4. Circuits compiled:"
if [ -d "build" ]; then
    echo "✅ Build directory created"
    ls -la build/
else
    echo "❌ Build directory not found"
fi

# --- Encryption/Decryption Demo ---

# Check if encryption circuit was compiled
if [ ! -f build/encryption_js/encryption.wasm ]; then
    echo "❌ Encryption circuit wasm not found. Skipping encryption/decryption demo."
    echo "🎉 Demo complete!"
    exit 0
fi

MESSAGE=42
NONCE=12345
PUBKEY_X=$(head -n 1 pk.txt)
PUBKEY_Y=$(tail -n 1 pk.txt)

cat > encrypt_input.json <<EOF
{
  "plaintext": $MESSAGE,
  "nonceKey": $NONCE,
  "publicKey": [$PUBKEY_X, $PUBKEY_Y]
}
EOF

echo "\n5. Encrypting message $MESSAGE..."
node build/encryption_js/generate_witness.js build/encryption_js/encryption.wasm encrypt_input.json encrypt_witness.wtns

CIPHERTEXT=$(snarkjs wtns export json encrypt_witness.wtns | jq '.encryptedMessage')
echo "Encrypted message: $CIPHERTEXT"

# Prepare decryption input (assuming decryption circuit expects ciphertext, nonceKey, sk)
SK=$(cat sk.txt)
C1=$(echo $CIPHERTEXT | jq '.[0]')
C2=$(echo $CIPHERTEXT | jq '.[1]')

cat > decrypt_input.json <<EOF
{
  "ciphertext": [$C1, $C2],
  "nonceKey": $NONCE,
  "sk": $SK
}
EOF

echo "\n6. Decrypting message..."
if [ -f build/decryption_js/decryption.wasm ]; then
  node build/decryption_js/generate_witness.js build/decryption_js/decryption.wasm decrypt_input.json decrypt_witness.wtns
  DECRYPTED=$(snarkjs wtns export json decrypt_witness.wtns | jq '.plaintext')
  echo "Decrypted message: $DECRYPTED"
else
  echo "❌ Decryption circuit wasm not found. Skipping decryption."
fi

echo "🎉 Demo complete!"
