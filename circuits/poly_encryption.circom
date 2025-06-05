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

    // Verify each encryption
    for (var i = 0; i < n; i++) {
        // Encode x[i] as a point on the curve
        component encodeX = EscalarMulFix(250, base);
        encodeX.e <== x[i];
        
        // Verify encryption using existing ElGamal circuit
        component enc = ElGamalEncrypt();
        enc.message[0] <== encodeX.out[0];
        enc.message[1] <== encodeX.out[1];
        enc.nonceKey <== omega[i];
        enc.publicKey[0] <== publicKeys[i][0];
        enc.publicKey[1] <== publicKeys[i][1];
        
        // Verify ciphertext matches
        enc.ephemeralKey[0] === ciphertexts[i][0][0];
        enc.ephemeralKey[1] === ciphertexts[i][0][1];
        enc.encryptedMessage[0] === ciphertexts[i][1][0];
        enc.encryptedMessage[1] === ciphertexts[i][1][1];
    }

    // Verify polynomial evaluation at 0 equals Y
    component evalAtZero = EscalarMulFix(250, base);
    evalAtZero.e <== coeffs[0];  // f(0) is just the constant term
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

component main = PolyEncryption(3, 2);  // Example: 3 points, degree 2 polynomial 