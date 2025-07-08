pragma circom 2.2.2;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/comparators.circom";

/*
  Template per controllare che publicKey == privateKey * Base8.
  Utilizza una finestra a 252 bit (sottogruppo BabyJubJub).
*/
template KeysCheck() {
    // Chiave privata in input (scalar < 2^252)
    signal input privateKey;

    // Coordinate della chiave pubblica fornite
    signal input publicKey[2];

    // Converti privateKey in 252 bit little-endian
    component privBits = Num2Bits(250);
    privBits.in <== privateKey;

    // Base8 = 8 * G (punto di base da circomlibjs.buildBabyjub().Base8)
    var base[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    // Calcola publicKeyCandidate = [privateKey] * Base8 con 250-bit window
    component pubCalc = EscalarMulFix(250, base);
    for (var i = 0; i < 250; i++) {
        pubCalc.e[i] <== privBits.out[i];
    }

    // Vincola che il risultato coincida con la chiave pubblica fornita
    pubCalc.out[0] === publicKey[0];
    pubCalc.out[1] === publicKey[1];

    // Sanity check: la publicKey è effettivamente sul curve
    component onCurve = BabyCheck();
    onCurve.x <== publicKey[0];
    onCurve.y <== publicKey[1];
}

component main = KeysCheck();
