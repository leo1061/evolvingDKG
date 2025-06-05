pragma circom 2.2.2;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/comparators.circom";
include "elgamal.circom";

template PolyEncryption(n, t) {
    // Public inputs
    signal input publicKeys[n][2];  // Array of public keys
    signal input ciphertexts[n][2][2];  // Array of ciphertexts (ephemeral key + encrypted message)
    signal input Y[2];  // g^f(0)

    // Private inputs
    signal input x[n];  // Values f(j) for each j
    signal input omega[n];  // Randomness for each encryption
    signal input coeffs[t+1];  // Coefficients of polynomial f

    // Baby Jubjub curve base point (generator)
    var base[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // Declare components outside loops
    component encodeX[n];
    component enc[n];
    component evalAtZero;
    component xBits[n];
    component coeff0Bits;

    // Initialize components
    for (var i = 0; i < n; i++) {
        xBits[i] = Num2Bits(250);
        encodeX[i] = EscalarMulFix(250, base);
        enc[i] = ElGamalEncrypt();
    }
    coeff0Bits = Num2Bits(250);
    evalAtZero = EscalarMulFix(250, base);

    // Verify each encryption
    for (var i = 0; i < n; i++) {
        // Convert x[i] to bits
        xBits[i].in <== x[i];
        // Encode x[i] as a point on the curve
        for (var j = 0; j < 250; j++) {
            encodeX[i].e[j] <== xBits[i].out[j];
        }
        
        // Verify encryption using existing ElGamal circuit
        enc[i].message[0] <== encodeX[i].out[0];
        enc[i].message[1] <== encodeX[i].out[1];
        enc[i].nonceKey <== omega[i];
        enc[i].publicKey[0] <== publicKeys[i][0];
        enc[i].publicKey[1] <== publicKeys[i][1];
        
        // Verify ciphertext matches
        enc[i].ephemeralKey[0] === ciphertexts[i][0][0];
        enc[i].ephemeralKey[1] === ciphertexts[i][0][1];
        enc[i].encryptedMessage[0] === ciphertexts[i][1][0];
        enc[i].encryptedMessage[1] === ciphertexts[i][1][1];
    }

    // Convert coeffs[0] to bits
    coeff0Bits.in <== coeffs[0];
    for (var j = 0; j < 250; j++) {
        evalAtZero.e[j] <== coeff0Bits.out[j];
    }

    // Verify polynomial evaluation at 0 equals Y
    evalAtZero.out[0] === Y[0];
    evalAtZero.out[1] === Y[1];

    // Verify polynomial evaluations at points 1..n
    for (var i = 0; i < n; i++) {
        var point = i + 1;  // Evaluate at points 1..n
        var eval = 0;
        
        // Horner's method for polynomial evaluation
        for (var j = t; j >= 0; j--) {
            eval = eval * point + coeffs[j];
        }
        
        // Verify evaluation matches x[i]
        eval === x[i];
    }
} 