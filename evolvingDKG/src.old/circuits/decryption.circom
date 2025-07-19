pragma circom 2.2.2;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/comparators.circom";

template ElGamalDecrypt() {
    // ephemeral key from encryption: [nonce].Base
    signal input ephemeralKey[2];
    // encrypted message from encryption
    signal input encryptedMessage[2];
    // private key of the receiver (scalar)
    signal input privateKey;

    // decrypted message: message = encryptedMessage - [privateKey].ephemeralKey
    signal output message[2];
    
    // Convert privateKey to bits for scalar multiplication
    component privateKeyNum = Num2Bits(254);
    privateKeyNum.in <== privateKey;
    
    // Validate ephemeral key is not the identity point (0,1)
    component isZeroX = IsZero();
    isZeroX.in <== ephemeralKey[0];
    
    component isOneY = IsEqual();
    isOneY.in[0] <== ephemeralKey[1];
    isOneY.in[1] <== 1;

    // Ensure ephemeral key is not the identity point
    component isIdentity = IsEqual();
    isIdentity.in[0] <== isZeroX.out + isOneY.out;
    isIdentity.in[1] <== 2;
    isIdentity.out === 0;  // Should not be identity point

    // Validate the ephemeral key is a point on the curve
    component isOnCurveEph = BabyCheck();
    isOnCurveEph.x <== ephemeralKey[0];
    isOnCurveEph.y <== ephemeralKey[1];
    
    // Validate the encrypted message is a point on the curve
    component isOnCurveEnc = BabyCheck();
    isOnCurveEnc.x <== encryptedMessage[0];
    isOnCurveEnc.y <== encryptedMessage[1];
    
    // Calculate the shared secret: [privateKey] * ephemeralKey
    component sharedSecret = EscalarMulAny(254);
    sharedSecret.p[0] <== ephemeralKey[0];
    sharedSecret.p[1] <== ephemeralKey[1];
    for (var i = 0; i < 254; i++) {
        sharedSecret.e[i] <== privateKeyNum.out[i];
    }
    
    // Calculate decrypted message: encryptedMessage - sharedSecret
    // This is equivalent to: encryptedMessage + (-sharedSecret)
    // In Baby Jubjub curve, -P = (x, p - y) where p is the field prime
    // Baby Jubjub field prime
    var p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // Negate the shared secret point: -P = (x, p - y)
    component subtractPoints = BabyAdd();
    subtractPoints.x1 <== encryptedMessage[0];
    subtractPoints.y1 <== encryptedMessage[1];
    subtractPoints.x2 <== sharedSecret.out[0];
    subtractPoints.y2 <== p - sharedSecret.out[1];
    
    message[0] <== subtractPoints.xout;
    message[1] <== subtractPoints.yout;
}

component main = ElGamalDecrypt();