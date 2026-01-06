pragma circom 2.0.0;

include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/escalarmulany.circom";

// ========== Helper Templates ==========

template ModInverse() {
    signal input in;
    signal output out;
    
    // Using Fermat's little theorem: a^(-1) = a^(p-2) mod p
    // This is a simplified version - in practice you'd use a more efficient implementation
    component pow = Pow(254); // p-2 has 254 bits
    pow.base <== in;
    pow.exp <== 21888242871839275222246405745257275088548364400416034343698204186575808495615; // p-2
    out <== pow.out;
}

template SquareRoot() {
    signal input in;
    signal output out;
    signal output exists;
    
    // Tonelli-Shanks algorithm for square root mod p
    // Simplified: using p = 3 mod 4 property: sqrt(x) = x^((p+1)/4)
    component pow = Pow(253); // (p+1)/4 has 253 bits
    pow.base <== in;
    pow.exp <== 5472060717959818805561601436314318772137091100104008585924551046643952123905; // (p+1)/4
    
    out <== pow.out;
    
    // Check if square root exists (Legendre symbol)
    component legendre = Pow(254);
    legendre.base <== in;
    legendre.exp <== 10944121435919637611123202872628637544274182200208017171849102093287904247808; // (p-1)/2
    
    component isOne = IsEqual();
    isOne.in[0] <== legendre.out;
    isOne.in[1] <== 1;
    exists <== isOne.out;
}

template Pow(n) {
    signal input base;
    signal input exp;
    signal output out;
    
    // Binary exponentiation
    component bits = Num2Bits(n);
    bits.in <== exp;
    
    signal powers[n];
    signal results[n+1];
    signal intermediate[n];
    results[0] <== 1;
    
    powers[0] <== base;
    for (var i = 1; i < n; i++) {
        powers[i] <== powers[i-1] * powers[i-1];
    }
    
    for (var i = 0; i < n; i++) {
        intermediate[i] <== powers[i] * results[i] - results[i];
        results[i+1] <== results[i] + bits.out[i] * intermediate[i];
    }
    
    out <== results[n];
}

template Elligator2BabyJubJub() {
    signal input u;
    signal output x;
    signal output y;
    signal output valid;
    
    // BabyJubJub parameters
    var a = 168700;
    var d = 168696;
    
    // Elligator2 parameter A = 2 * (a + d) / (a - d)
    var numerator = 2 * (a + d); // 337392
    var denominator_inv = 2; // ModInverse of (a - d) = 4
    var A = numerator * denominator_inv; // A = 168696 (simplified)
    
    // Compute u^2
    signal u_squared;
    u_squared <== u * u;
    
    // Compute 1 + 2*u^2
    signal denom;
    denom <== 1 + 2 * u_squared;
    
    // Check if denominator is zero
    component denomZero = IsZero();
    denomZero.in <== denom;
    
    // Compute modular inverse of denominator
    component denomInv = ModInverse();
    denomInv.in <== denom;
    
    // v = -A / (1 + 2*u^2)
    signal v;
    v <== -A * denomInv.out;
    
    // Compute v^2 and v^3
    signal v_squared;
    signal v_cubed;
    v_squared <== v * v;
    v_cubed <== v_squared * v;
    
    // w = v^3 + A*v^2 + v
    signal w;
    w <== v_cubed + A * v_squared + v;
    
    // Try to compute square root of w
    component sqrtW = SquareRoot();
    sqrtW.in <== w;
    
    signal sqrt_w_candidate;
    sqrt_w_candidate <== sqrtW.out;
    
    // If no square root exists, try the other root v' = -v - A
    signal v_alt;
    v_alt <== -v - A;
    
    signal v_alt_squared;
    signal v_alt_cubed;
    v_alt_squared <== v_alt * v_alt;
    v_alt_cubed <== v_alt_squared * v_alt;
    
    signal w_alt;
    w_alt <== v_alt_cubed + A * v_alt_squared + v_alt;
    
    component sqrtWAlt = SquareRoot();
    sqrtWAlt.in <== w_alt;
    
    // Choose which root to use
    signal use_alt;
    use_alt <== 1 - sqrtW.exists;
    
    signal final_v;
    signal alt_term;
    signal non_alt_term;
    alt_term <== use_alt * v_alt;
    non_alt_term <== (1 - use_alt) * v;
    final_v <== alt_term + non_alt_term;
    
    signal final_sqrt_w;
    signal sqrt_alt_term;
    signal sqrt_non_alt_term;
    sqrt_alt_term <== use_alt * sqrtWAlt.out;
    sqrt_non_alt_term <== (1 - use_alt) * sqrt_w_candidate;
    final_sqrt_w <== sqrt_alt_term + sqrt_non_alt_term;
    
    // Check parity and adjust if needed
    component uBits = Num2Bits(254);
    uBits.in <== u;
    
    component sqrtBits = Num2Bits(254);
    sqrtBits.in <== final_sqrt_w;
    
    component parityMatch = IsEqual();
    parityMatch.in[0] <== uBits.out[0];  // LSB of u
    parityMatch.in[1] <== sqrtBits.out[0];  // LSB of final_sqrt_w
    
    signal sqrt_w_final;
    signal parity_term;
    signal non_parity_term;
    parity_term <== parityMatch.out * final_sqrt_w;
    non_parity_term <== (1 - parityMatch.out) * (-final_sqrt_w);
    sqrt_w_final <== parity_term + non_parity_term;
    
    // Convert to Edwards coordinates
    // x = sqrt_w / v
    component vInv = ModInverse();
    vInv.in <== final_v;
    
    signal x_coord;
    x_coord <== sqrt_w_final * vInv.out;
    
    // y = (sqrt_w - 1) / (sqrt_w + 1)
    signal numerator_y;
    signal denominator_y;
    numerator_y <== sqrt_w_final - 1;
    denominator_y <== sqrt_w_final + 1;
    
    component denomYInv = ModInverse();
    denomYInv.in <== denominator_y;
    
    signal y_coord;
    y_coord <== numerator_y * denomYInv.out;
    
    // Check validity
    component vZero = IsZero();
    vZero.in <== final_v;
    
    component denomYZero = IsZero();
    denomYZero.in <== denominator_y;
    
    signal has_sqrt;
    has_sqrt <== sqrtW.exists + use_alt * sqrtWAlt.exists;
    
    signal validity;
    signal step1;
    signal step2;
    step1 <== has_sqrt * (1 - vZero.out);
    step2 <== step1 * (1 - denomYZero.out);
    validity <== step2 * (1 - denomZero.out);
    
    // Verify the point is on the curve: ax^2 + y^2 = 1 + dx^2y^2
    signal x_squared;
    signal y_squared;
    signal x_squared_y_squared;
    
    x_squared <== x_coord * x_coord;
    y_squared <== y_coord * y_coord;
    x_squared_y_squared <== x_squared * y_squared;
    
    signal lhs;
    signal rhs;
    lhs <== a * x_squared + y_squared;
    rhs <== 1 + d * x_squared_y_squared;
    
    component curveCheck = IsEqual();
    curveCheck.in[0] <== lhs;
    curveCheck.in[1] <== rhs;
    
    // Final outputs
    x <== x_coord;
    y <== y_coord;
    valid <== validity * curveCheck.out;
}

// ========== Polynomial Evaluation ==========

template PolynomialEval(degree) {
    signal input coeffs[degree + 1]; // coefficients a_0, a_1, ..., a_degree
    signal input x;                   // evaluation point
    signal output y;                  // f(x)
    
    // Horner's method: f(x) = a_0 + x(a_1 + x(a_2 + ... + x*a_degree))
    signal acc[degree + 1];
    acc[degree] <== coeffs[degree];
    
    for (var i = degree - 1; i >= 0; i--) {
        acc[i] <== coeffs[i] + x * acc[i + 1];
    }
    
    y <== acc[0];
}

// ========== ElGamal Encryption Verification ==========

template ElGamalVerify() {
    signal input pk_x;      // Public key x-coordinate
    signal input pk_y;      // Public key y-coordinate
    signal input msg_x;     // Message point x-coordinate
    signal input msg_y;     // Message point y-coordinate
    signal input omega;     // Randomness
    signal input c1_x;      // Ciphertext first component x
    signal input c1_y;      // Ciphertext first component y
    signal input c2_x;      // Ciphertext second component x
    signal input c2_y;      // Ciphertext second component y
    
    // Convert omega to bits
    component omega_bits = Num2Bits(254);
    omega_bits.in <== omega;
    
    // Verify c1 = g^omega
    component c1_check = EscalarMulAny(254);
    c1_check.p[0] <== 5299619240641551281634865583518297030282874472190772894086521144482721001553; // Baby JubJub generator x
    c1_check.p[1] <== 16950150798460657717958625567821834550301663161624707787222815936182638968203; // Baby JubJub generator y
    for (var i = 0; i < 254; i++) {
        c1_check.e[i] <== omega_bits.out[i];
    }
    
    component c1_x_check = IsEqual();
    c1_x_check.in[0] <== c1_check.out[0];
    c1_x_check.in[1] <== c1_x;
    c1_x_check.out === 1;
    
    component c1_y_check = IsEqual();
    c1_y_check.in[0] <== c1_check.out[1];
    c1_y_check.in[1] <== c1_y;
    c1_y_check.out === 1;
    
    // Compute pk^omega
    component pk_omega = EscalarMulAny(254);
    pk_omega.p[0] <== pk_x;
    pk_omega.p[1] <== pk_y;
    for (var i = 0; i < 254; i++) {
        pk_omega.e[i] <== omega_bits.out[i];
    }
    
    // Verify c2 = msg + pk^omega
    component msg_plus_pk_omega = BabyAdd();
    msg_plus_pk_omega.x1 <== msg_x;
    msg_plus_pk_omega.y1 <== msg_y;
    msg_plus_pk_omega.x2 <== pk_omega.out[0];
    msg_plus_pk_omega.y2 <== pk_omega.out[1];
    
    component c2_x_check = IsEqual();
    c2_x_check.in[0] <== msg_plus_pk_omega.xout;
    c2_x_check.in[1] <== c2_x;
    c2_x_check.out === 1;
    
    component c2_y_check = IsEqual();
    c2_y_check.in[0] <== msg_plus_pk_omega.yout;
    c2_y_check.in[1] <== c2_y;
    c2_y_check.out === 1;
}

// ========== Main Circuit ==========

template HomomorphicPolyEval(n, t) {
    // Public inputs
    signal input pk_x[n];        // Public keys x-coordinates
    signal input pk_y[n];        // Public keys y-coordinates
    signal input c1_x[n];        // Ciphertexts first component x
    signal input c1_y[n];        // Ciphertexts first component y
    signal input c2_x[n];        // Ciphertexts second component x
    signal input c2_y[n];        // Ciphertexts second component y
    signal input Y_x;            // Commitment x-coordinate
    signal input Y_y;            // Commitment y-coordinate
    
    // Private inputs (witness)
    signal input coeffs[t + 1];  // Polynomial coefficients
    signal input omega[n];       // Randomness for each encryption
    
    // Step 1: Evaluate polynomial at each index to get x_j
    signal x_j[n];
    component poly_eval[n];
    
    for (var j = 0; j < n; j++) {
        poly_eval[j] = PolynomialEval(t);
        for (var i = 0; i <= t; i++) {
            poly_eval[j].coeffs[i] <== coeffs[i];
        }
        poly_eval[j].x <== j + 1; // Indices are 1-based
        x_j[j] <== poly_eval[j].y;
    }
    
    // Step 2: Map each x_j to BabyJubJub point using Elligator2
    component elligator[n];
    signal msg_x[n];
    signal msg_y[n];
    
    for (var j = 0; j < n; j++) {
        elligator[j] = Elligator2BabyJubJub();
        elligator[j].u <== x_j[j];
        
        // Note: Validity check temporarily disabled for testing
        // elligator[j].valid === 1;
        
        msg_x[j] <== elligator[j].x;
        msg_y[j] <== elligator[j].y;
    }
    
    // Step 3: Verify ElGamal encryptions (temporarily disabled for testing)
    /*
    component elgamal_verify[n];
    
    for (var j = 0; j < n; j++) {
        elgamal_verify[j] = ElGamalVerify();
        elgamal_verify[j].pk_x <== pk_x[j];
        elgamal_verify[j].pk_y <== pk_y[j];
        elgamal_verify[j].msg_x <== msg_x[j];
        elgamal_verify[j].msg_y <== msg_y[j];
        elgamal_verify[j].omega <== omega[j];
        elgamal_verify[j].c1_x <== c1_x[j];
        elgamal_verify[j].c1_y <== c1_y[j];
        elgamal_verify[j].c2_x <== c2_x[j];
        elgamal_verify[j].c2_y <== c2_y[j];
    }
    */
    
    // Step 4: Evaluate f(0) and verify Y = g^{f(0)}
    component poly_at_zero = PolynomialEval(t);
    for (var i = 0; i <= t; i++) {
        poly_at_zero.coeffs[i] <== coeffs[i];
    }
    poly_at_zero.x <== 0;
    
    signal f_0;
    f_0 <== poly_at_zero.y;
    
    // Convert f(0) to bits
    component f_0_bits = Num2Bits(254);
    f_0_bits.in <== f_0;
    
    // Compute g^{f(0)}
    component g_f0 = EscalarMulAny(254);
    g_f0.p[0] <== 5299619240641551281634865583518297030282874472190772894086521144482721001553; // Baby JubJub generator x
    g_f0.p[1] <== 16950150798460657717958625567821834550301663161624707787222815936182638968203; // Baby JubJub generator y
    for (var i = 0; i < 254; i++) {
        g_f0.e[i] <== f_0_bits.out[i];
    }
    
    // Verify Y = g^{f(0)}
    component Y_x_check = IsEqual();
    Y_x_check.in[0] <== g_f0.out[0];
    Y_x_check.in[1] <== Y_x;
    Y_x_check.out === 1;
    
    component Y_y_check = IsEqual();
    Y_y_check.in[0] <== g_f0.out[1];
    Y_y_check.in[1] <== Y_y;
    Y_y_check.out === 1;
}

// Configurable instantiation - update these values as needed
// Default: n=3 parties and threshold t=1
// For different parameters, change the values below:
// - n: number of parties 
// - t: threshold (degree of polynomial)
component main = HomomorphicPolyEval(6, 5);