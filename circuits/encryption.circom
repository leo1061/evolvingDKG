pragma circom 2.2.2;

include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/escalarmulany.circom";
include "../circomlib/circuits/escalarmulfix.circom";
include "../circomlib/circuits/comparators.circom";

template ElGamalEncrypt(B) {
    // message encoded as a point on the curve
    signal input message[2];
    // secret nonceKey
    signal input nonceKey;
    // public key
    signal input publicKey[2];

    // outputs
    signal output ephemeralKey[2];
    signal output encryptedMessage[2];

    // 1) Convert nonceKey to bits
    component nonceNum = Num2Bits(B);
    nonceNum.in <== nonceKey;

    // 2) Sanity-check publicKey ≠ identity e “on-curve”
    component isZeroX = IsZero();
    isZeroX.in <== publicKey[0];
    component isOneY = IsEqual();
    isOneY.in[0] <== publicKey[1];
    isOneY.in[1] <== 1;
    component isIdentity = IsEqual();
    isIdentity.in[0] <== isZeroX.out + isOneY.out;
    isIdentity.in[1] <== 2;
    isIdentity.out === 0;
    component isOnCurvePub = BabyCheck();
    isOnCurvePub.x <== publicKey[0];
    isOnCurvePub.y <== publicKey[1];

    // 3) Sanity-check message “on-curve”
    component isOnCurveMsg = BabyCheck();
    isOnCurveMsg.x <== message[0];
    isOnCurveMsg.y <== message[1];

    // 4) Base point (BabyJubJub generator = Base8)
    var base[2] = [
      5299619240641551281634865583518297030282874472190772894086521144482721001553,
      16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // 5) Ephemeral key = [nonceKey] * Base
    component eph = EscalarMulFix(B, base);
    for (var i = 0; i < B; i++) {
      eph.e[i] <== nonceNum.out[i];
    }
    ephemeralKey[0] <== eph.out[0];
    ephemeralKey[1] <== eph.out[1];

    // 6) Shared secret = [nonceKey] * publicKey
    component shared = EscalarMulAny(B);
    shared.p[0] <== publicKey[0];
    shared.p[1] <== publicKey[1];
    for (var i = 0; i < B; i++) {
      shared.e[i] <== nonceNum.out[i];
    }

    // 7) encryptedMessage = message + sharedSecret
    component add = BabyAdd();
    add.x1 <== message[0];
    add.y1 <== message[1];
    add.x2 <== shared.out[0];
    add.y2 <== shared.out[1];
    encryptedMessage[0] <== add.xout;
    encryptedMessage[1] <== add.yout;
}
