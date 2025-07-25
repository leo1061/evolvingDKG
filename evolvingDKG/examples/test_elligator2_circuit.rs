use num_bigint::BigUint;
use rand::Rng;
use std::process::Command;
use std::fs;
use std::path::Path;
use serde_json::{json, Value};
use ark_ed_on_bn254::Fq;
use ark_ff::{PrimeField, BigInteger};

// Import the required modules
use evolvingDKG::curve_converter::{CurveConverter, Elligator2};
use evolvingDKG::elgamal::ElGamal;
use ark_ed_on_bn254::{EdwardsProjective, Fr};
use ark_ec::{PrimeGroup, CurveGroup, AdditiveGroup};

const MAX_ELLIGATOR_ATTEMPTS: usize = 1000;

// Utility functions for BigUint/Fr conversion

fn fr_to_biguint(fr: &Fr) -> BigUint {
    let bytes = fr.into_bigint().to_bytes_le();
    BigUint::from_bytes_le(&bytes)
}

fn fq_to_biguint(fq: &Fq) -> BigUint {
    let bytes = fq.into_bigint().to_bytes_le();
    BigUint::from_bytes_le(&bytes)
}

/// Generate Elligator2-compatible scalars for circuit testing
fn generate_elligator_compatible_scalars(n: usize) -> Vec<Fr> {
    let mut rng = ark_std::rand::thread_rng();
    let mut scalars = Vec::new();
    
    let mont_a = CurveConverter::montgomery_a();
    let mont_b = CurveConverter::montgomery_b();
    
    println!("Generating {} Elligator2-compatible scalars...", n);
    
    for i in 0..n {
        let mut attempts = 0;
        let scalar = loop {
            attempts += 1;
            if attempts > MAX_ELLIGATOR_ATTEMPTS {
                panic!("Failed to generate Elligator2-compatible scalar after {} attempts", MAX_ELLIGATOR_ATTEMPTS);
            }
            
            // Generate random scalar
            let random_scalar = Fr::from(rng.gen::<u64>());
            
            // Convert to field element for Elligator2
            let scalar_biguint = fr_to_biguint(&random_scalar);
            let value_bytes = scalar_biguint.to_bytes_le();
            let fq_value = Fq::from_le_bytes_mod_order(&value_bytes);
            
            // Check if it's Elligator2 compatible
            if let Some((x, y)) = Elligator2::encode(&fq_value, &mont_a, &mont_b) {
                if CurveConverter::verify_montgomery_point(x, y) {
                    if let Some(_decoded) = Elligator2::decode(&x, &y, &mont_a, &mont_b) {
                        break random_scalar;
                    }
                }
            }
        };
        
        println!("  Scalar {}: {} (attempts: {})", i + 1, scalar, attempts);
        scalars.push(scalar);
    }
    
    scalars
}

/// Create circuit input JSON for the given parameters
fn create_circuit_input(
    ephemeral_keys: &[(Fq, Fq)],
    encrypted_messages: &[(Fq, Fq)], 
    private_key: &Fr,
    preimages: &[Fr],
    y_point: &(Fq, Fq),
    generator: &(Fq, Fq)
) -> Value {
    json!({
        "ephemeralKeys": ephemeral_keys.iter().map(|(x, y)| {
            [fq_to_biguint(x).to_string(), fq_to_biguint(y).to_string()]
        }).collect::<Vec<_>>(),
        "encryptedMessages": encrypted_messages.iter().map(|(x, y)| {
            [fq_to_biguint(x).to_string(), fq_to_biguint(y).to_string()]
        }).collect::<Vec<_>>(),
        "privateKey": fr_to_biguint(private_key).to_string(),
        "preimages": preimages.iter().map(|p| fr_to_biguint(p).to_string()).collect::<Vec<_>>(),
        "Y": [fq_to_biguint(&y_point.0).to_string(), fq_to_biguint(&y_point.1).to_string()],
        "generator": [fq_to_biguint(&generator.0).to_string(), fq_to_biguint(&generator.1).to_string()]
    })
}

/// Run the circuit with given input and return success/failure
fn run_circuit_test(input_json: &Value) -> bool {
    // Write input to temporary file
    let input_file = "/tmp/elligator2_circuit_input.json";
    fs::write(input_file, serde_json::to_string_pretty(input_json).unwrap())
        .expect("Failed to write input file");
    
    // Run snarkjs to calculate witness
    let witness_file = "/tmp/elligator2_witness.wtns";
    let wasm_path = "../circuits/elgamal_elligator2_js/elgamal_elligator2.wasm";
    let r1cs_path = "../circuits/elgamal_elligator2.r1cs";
    
    println!("  Running circuit witness calculation...");
    let calc_result = Command::new("snarkjs")
        .args(&["wtns", "calculate", wasm_path, input_file, witness_file])
        .output();
    
    match calc_result {
        Ok(output) => {
            if !output.status.success() {
                println!("    Witness calculation failed: {}", String::from_utf8_lossy(&output.stderr));
                return false;
            }
        }
        Err(e) => {
            println!("    Error running snarkjs: {}", e);
            return false;
        }
    }
    
    println!("  Running circuit constraint check...");
    let check_result = Command::new("snarkjs")
        .args(&["wtns", "check", r1cs_path, witness_file])
        .output();
    
    match check_result {
        Ok(output) => {
            let success = output.status.success();
            if !success {
                println!("    Constraint check failed: {}", String::from_utf8_lossy(&output.stderr));
            }
            
            // Clean up
            let _ = fs::remove_file(witness_file);
            let _ = fs::remove_file(input_file);
            
            success
        }
        Err(e) => {
            println!("    Error running snarkjs check: {}", e);
            false
        }
    }
}

fn main() {
    println!("=== Elligator2 Circuit Round-trip Verification Test ===\n");
    
    // Check if circuit files exist
    let wasm_path = Path::new("../circuits/elgamal_elligator2_js/elgamal_elligator2.wasm");
    let r1cs_path = Path::new("../circuits/elgamal_elligator2.r1cs");
    
    if !wasm_path.exists() || !r1cs_path.exists() {
        println!("❌ Circuit files not found. Please compile the circuit first:");
        println!("   cd circuits && circom elgamal_elligator2.circom --r1cs --wasm --sym");
        return;
    }
    
    // Generate ElGamal keypair
    let mut rng = ark_std::rand::thread_rng();
    let (private_key, public_key) = ElGamal::generate_keypair(&mut rng);
    
    println!("Generated ElGamal keypair:");
    println!("  Private key: {}", private_key);
    let pk_affine = public_key.into_affine();
    println!("  Public key: ({}, {})\n", pk_affine.x, pk_affine.y);
    
    // Test parameters
    let n = 5; // Number of ciphertexts
    
    // Step 1: Generate Elligator2-compatible scalars
    let scalars = generate_elligator_compatible_scalars(n);
    
    // Step 2: Encrypt scalars using ElGamal
    println!("\nEncrypting scalars with ElGamal...");
    let mut ciphertexts = Vec::new();
    for (i, scalar) in scalars.iter().enumerate() {
        match ElGamal::encrypt_scalar(&public_key, scalar, &mut rng) {
            Ok(ciphertext) => {
                println!("  Encrypted scalar {}: {}", i + 1, scalar);
                ciphertexts.push(ciphertext);
            }
            Err(e) => {
                println!("❌ Failed to encrypt scalar {}: {}", i + 1, e);
                return;
            }
        }
    }
    
    // Step 3: Prepare circuit inputs
    println!("\nPreparing circuit inputs...");
    
    // Extract ephemeral keys and encrypted messages from ciphertexts
    let ephemeral_keys: Vec<(Fq, Fq)> = ciphertexts.iter().map(|ct| {
        let c1_affine = ct.c1.into_affine();
        (c1_affine.x, c1_affine.y)
    }).collect();
    
    let encrypted_messages: Vec<(Fq, Fq)> = ciphertexts.iter().map(|ct| {
        let c2_affine = ct.c2.into_affine();
        (c2_affine.x, c2_affine.y)
    }).collect();
    
    // Use the original scalars as preimages (this is the key test)
    let preimages = scalars.clone();
    
    // Calculate expected Y = generator^(sum of scalars)
    let scalar_sum: Fr = scalars.iter().fold(Fr::ZERO, |acc, s| acc + s);
    let y_point_proj = EdwardsProjective::generator() * scalar_sum;
    let y_point_affine = y_point_proj.into_affine();
    let y_point = (y_point_affine.x, y_point_affine.y);
    
    // Generator point
    let generator_affine = EdwardsProjective::generator().into_affine();
    let generator = (generator_affine.x, generator_affine.y);
    
    println!("  Sum of scalars: {}", scalar_sum);
    println!("  Expected Y: ({}, {})", y_point.0, y_point.1);
    
    // Step 4: Create circuit input
    let circuit_input = create_circuit_input(
        &ephemeral_keys,
        &encrypted_messages,
        &private_key,
        &preimages,
        &y_point,
        &generator
    );
    
    // Step 5: Run circuit test
    println!("\nRunning circuit verification...");
    let circuit_success = run_circuit_test(&circuit_input);
    
    // Step 6: Verify against Rust implementation
    println!("\nVerifying against Rust implementation...");
    let mut rust_success = true;
    
    for (i, (ciphertext, expected_scalar)) in ciphertexts.iter().zip(scalars.iter()).enumerate() {
        match ElGamal::decrypt_to_scalar(ciphertext, &private_key) {
            Some(decrypted_scalar) => {
                if decrypted_scalar == *expected_scalar {
                    println!("  ✅ Scalar {} decryption matches: {}", i + 1, decrypted_scalar);
                } else {
                    println!("  ❌ Scalar {} mismatch: expected {}, got {}", i + 1, expected_scalar, decrypted_scalar);
                    rust_success = false;
                }
            }
            None => {
                println!("  ❌ Failed to decrypt scalar {}", i + 1);
                rust_success = false;
            }
        }
    }
    
    // Final results
    println!("\n=== Test Results ===");
    println!("Circuit verification: {}", if circuit_success { "✅ PASSED" } else { "❌ FAILED" });
    println!("Rust verification: {}", if rust_success { "✅ PASSED" } else { "❌ FAILED" });
    
    if circuit_success && rust_success {
        println!("\n🎉 Round-trip verification SUCCESSFUL!");
        println!("The circuit correctly:");
        println!("  1. Decrypted ElGamal ciphertexts");
        println!("  2. Used Elligator2 inverse mapping with provided preimages");
        println!("  3. Summed the recovered scalars");
        println!("  4. Verified Y = generator^(scalar_sum)");
    } else {
        println!("\n❌ Round-trip verification FAILED!");
        if !circuit_success {
            println!("  Circuit constraints are not satisfied");
        }
        if !rust_success {
            println!("  Rust implementation verification failed");
        }
    }
}