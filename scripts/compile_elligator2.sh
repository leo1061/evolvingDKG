#!/bin/bash
# Compile ElGamalDecryptWithElligator2 circuit

echo "Compiling ElGamalDecryptWithElligator2 circuit..."

# You'll need to adjust the circuit name and path
CIRCUIT_NAME="ElGamalDecryptWithElligator2"
CIRCUIT_FILE="../circuits/elgamal_elligator2.circom"

# Create build directory
mkdir -p build

# Compile for different n values
for n in 3 5 8; do
  echo "Compiling for n=$n..."
  
  # You may need to modify the circuit to parameterize n
  circom $CIRCUIT_FILE --r1cs --wasm --sym -o build/ --inspect
  
  # Setup (you'll need a powers of tau file)
  # snarkjs groth16 setup build/${CIRCUIT_NAME}.r1cs powersOfTau28_hez_final_15.ptau build/${CIRCUIT_NAME}_${n}.zkey
  
  # Export verification key
  # snarkjs zkey export verificationkey build/${CIRCUIT_NAME}_${n}.zkey build/verification_key_${n}.json
done

echo "Compilation complete! (Setup steps commented out - you'll need a powers of tau file)"
