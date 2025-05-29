use ark_bn254::{Fr, G1Projective};
use ark_ec::{PrimeGroup, CurveGroup};   // ← PrimeGroup per generator(), CurveGroup per into_affine()
use ark_ff::{UniformRand, PrimeField};   // ← PrimeField per into_bigint()
use rand::thread_rng;
use anyhow::Result;
use std::fs::write;

fn main() -> Result<()> {
    // 1) Genera sk ∈ Fr
    let mut rng = thread_rng();
    let sk: Fr = Fr::rand(&mut rng);

    // 2) Public key = G * sk
    let G = G1Projective::generator();
    let pk_proj = G * sk;
    let pk_aff = pk_proj.into_affine();    // ora disponibile

    // 3) Serializza su file
    write("../sk.txt", sk.into_bigint().to_string().as_bytes())?;                // ora disponibile
    write(
        "../pk.txt",
        format!("{}\n{}\n", pk_aff.x.into_bigint(), pk_aff.y.into_bigint()).as_bytes(),
    )?;

    println!("Key generation complete → ../sk.txt, ../pk.txt");
    Ok(())
}
