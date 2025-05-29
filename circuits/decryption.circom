pragma circom 2.0.0;

// 1) decomposizione in bit di sk
include "../node_modules/circomlib/circuits/bitify.circom";       // Num2Bits
// 2) moltiplicazione scalare fissa con base G
include "../node_modules/circomlib/circuits/escalarmulfix.circom"; // EscalarMulFix
// 3) addizione di punti su BabyJubjub
include "../node_modules/circomlib/circuits/babyjub.circom";       // BabyAdd

template ElGamalDecrypt() {
    // ─── Inputs ─────────────────────────────────────────────────────────────
    signal input sk;       // chiave privata ∈ Fr
    signal input c2x;      // C2.x
    signal input c2y;      // C2.y

    // ─── 1) decomponi sk in bit (253 bit) ─────────────────────────────────
    component bits = Num2Bits(253);
    bits.in <== sk;

    // ─── 2) costanti del generatore G = BASE8[0] (da babyjub.circom) ───────
    var Gx = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var Gy = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    // ─── 3) calcola S = sk * G ─────────────────────────────────────────────
    component mul = EscalarMulFix(253, [Gx, Gy]);
    for (var i = 0; i < 253; i++) {
        mul.e[i] <== bits.out[i];
    }
    signal Sx <== mul.out[0];
    signal Sy <== mul.out[1];

    // ─── 4) invSy = -Sy  ───────────────────────────────────────────────────
    signal invSy;
    invSy <== 0 - Sy;

    // ─── 5) M = C2 + ( - S ) = C2 + (Sx, invSy) ───────────────────────────
    component add = BabyAdd();
    add.x1 <== c2x;
    add.y1 <== c2y;
    add.x2 <== Sx;
    add.y2 <== invSy;
    signal Mx <== add.xout;
    signal My <== add.yout;

    // ─── 6) Outputs ───────────────────────────────────────────────────────
    signal output mx; mx <== Mx;
    signal output my; my <== My;
}

component main = ElGamalDecrypt();






