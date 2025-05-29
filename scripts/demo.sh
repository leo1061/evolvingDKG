#!/bin/bash

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

echo "🎉 Demo complete!"
