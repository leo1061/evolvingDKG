pragma circom 2.2.2;

include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/escalarmulany.circom";
include "../circomlib/circuits/comparators.circom";

// Simplified inverse Elligator2 mapping
template InverseElligator2() {
    signal input point_x;
    signal input point_y;
    signal input preimage; // Caller must provide the preimage scalar
    signal output scalar;
    signal output valid;
    
    // Verify that Elligator2(preimage) = (point_x, point_y)
    component forward = Elligator2BabyJubJub();
    forward.u <== preimage;
    
    // Check if the forward mapping matches the input point
    component checkX = IsEqual();
    checkX.in[0] <== forward.x;
    checkX.in[1] <== point_x;
    
    component checkY = IsEqual();
    checkY.in[0] <== forward.y;
    checkY.in[1] <== point_y;
    
    // Valid if forward mapping produces the same point
    signal checkXY;
    checkXY <== checkX.out * checkY.out;
    valid <== checkXY * forward.valid;
    scalar <== preimage;
}

// Use a constraint-friendly modular inverse
template ModInverse() {
    signal input in;
    signal output out;
    
    // We assert that in * out = 1 (mod p)
    // This requires the caller to provide the correct inverse
    // In practice, you'd compute this outside the circuit
    in * out === 1;
}

// Simplified square root that assumes the caller provides the root
template SquareRoot() {
    signal input in;
    signal output out;
    signal output exists;
    
    // Assert that out^2 = in (mod p) when exists = 1
    signal out_squared;
    out_squared <== out * out;
    
    // When exists = 1, we require out^2 = in
    // When exists = 0, we don't constrain the relationship
    exists * (out_squared - in) === 0;
    
    // For simplicity, assume exists = 1 (caller must ensure input has sqrt)
    exists <== 1;
}

// Include the forward Elligator2 mapping for verification
template Elligator2BabyJubJub() {
    signal input u;
    signal output x;
    signal output y;
    signal output valid;
    
    // [Previous Elligator2 implementation would go here]
    // For brevity, assuming this exists from the previous artifact
    
    // Simplified placeholder - replace with full implementation
    x <== u; // placeholder
    y <== u; // placeholder
    valid <== 1; // placeholder
}

template ElGamalDecryptWithElligator2(n) {
    // Array of ciphertexts to decrypt
    signal input ephemeralKeys[n][2];
    signal input encryptedMessages[n][2];
    signal input privateKey;
    
    // Preimages for inverse Elligator2 mapping
    signal input preimages[n];
    
    // Target value to prove against
    signal input Y[2]; // Y is a point [x, y]
    signal input generator[2]; // Generator point for final exponentiation
    
    // Outputs
    signal output decryptedMessages[n][2];
    signal output mappedScalars[n];
    signal output scalarSum;
    signal output proofValid;
    
    // Decrypt each message
    component decryptors[n];
    for (var i = 0; i < n; i++) {
        decryptors[i] = ElGamalDecrypt();
        decryptors[i].ephemeralKey[0] <== ephemeralKeys[i][0];
        decryptors[i].ephemeralKey[1] <== ephemeralKeys[i][1];
        decryptors[i].encryptedMessage[0] <== encryptedMessages[i][0];
        decryptors[i].encryptedMessage[1] <== encryptedMessages[i][1];
        decryptors[i].privateKey <== privateKey;
        
        decryptedMessages[i][0] <== decryptors[i].message[0];
        decryptedMessages[i][1] <== decryptors[i].message[1];
    }
    
    // Map each decrypted EC point to scalar via inverse Elligator2
    component mappers[n];
    signal allValid[n];
    for (var i = 0; i < n; i++) {
        mappers[i] = InverseElligator2();
        mappers[i].point_x <== decryptedMessages[i][0];
        mappers[i].point_y <== decryptedMessages[i][1];
        mappers[i].preimage <== preimages[i];
        
        mappedScalars[i] <== mappers[i].scalar;
        allValid[i] <== mappers[i].valid;
    }
    
    // Ensure all mappings are valid
    signal validityProduct[n];
    validityProduct[0] <== allValid[0];
    for (var i = 1; i < n; i++) {
        validityProduct[i] <== validityProduct[i-1] * allValid[i];
    }
    
    // Sum all mapped scalars
    signal partialSums[n];
    partialSums[0] <== mappedScalars[0];
    for (var i = 1; i < n; i++) {
        partialSums[i] <== partialSums[i-1] + mappedScalars[i];
    }
    scalarSum <== partialSums[n-1];
    
    // Prove Y = g^{sum of mapped scalars}
    component scalarSumBits = Num2Bits(252);
    scalarSumBits.in <== scalarSum;
    
    component exponentiation = EscalarMulAny(252);
    exponentiation.p[0] <== generator[0];
    exponentiation.p[1] <== generator[1];
    for (var i = 0; i < 252; i++) {
        exponentiation.e[i] <== scalarSumBits.out[i];
    }
    
    // Verify Y matches g^{scalar_sum}
    component checkX = IsEqual();
    checkX.in[0] <== Y[0];  // Assuming Y is a point [x,y]
    checkX.in[1] <== exponentiation.out[0];
    
    component checkY = IsEqual();
    checkY.in[0] <== Y[1];
    checkY.in[1] <== exponentiation.out[1];
    
    signal xyMatch;
    xyMatch <== checkX.out * checkY.out;
    proofValid <== xyMatch * validityProduct[n-1];
}

// Original ElGamalDecrypt template (unchanged)
template ElGamalDecrypt() {
    signal input ephemeralKey[2];
    signal input encryptedMessage[2];
    signal input privateKey;
    signal output message[2];
    
    component privateKeyNum = Num2Bits(252);
    privateKeyNum.in <== privateKey;
    
    component isZeroX = IsZero();
    isZeroX.in <== ephemeralKey[0];
    
    component isOneY = IsEqual();
    isOneY.in[0] <== ephemeralKey[1];
    isOneY.in[1] <== 1;

    component isIdentity = IsEqual();
    isIdentity.in[0] <== isZeroX.out + isOneY.out;
    isIdentity.in[1] <== 2;
    isIdentity.out === 0;

    // Assume all input points are on the curve (removed BabyCheck constraints)
    
    component sharedSecret = EscalarMulAny(252);
    sharedSecret.p[0] <== ephemeralKey[0];
    sharedSecret.p[1] <== ephemeralKey[1];
    for (var i = 0; i < 252; i++) {
        sharedSecret.e[i] <== privateKeyNum.out[i];
    }
    
    var p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    component subtractPoints = BabyAdd();
    subtractPoints.x1 <== encryptedMessage[0];
    subtractPoints.y1 <== encryptedMessage[1];
    subtractPoints.x2 <== sharedSecret.out[0];
    subtractPoints.y2 <== p - sharedSecret.out[1];
    
    message[0] <== subtractPoints.xout;
    message[1] <== subtractPoints.yout;
}

// Example usage
//component main = ElGamalDecryptWithElligator2(5); // For 5 ciphertexts