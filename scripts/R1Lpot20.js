// scripts/R1Lpot20.js
const { execSync } = require("child_process");
const fs           = require("fs");
const path         = require("path");

const ROOT     = path.resolve(__dirname, "..");
const CIRCUITS = path.join(ROOT, "circuits");
const BUILD    = path.join(ROOT, "build");
const PTAU     = path.join(BUILD, "pot20_final.ptau");

fs.mkdirSync(BUILD, { recursive: true });

// 1) Compila il circuito
execSync(`circom ${path.join(CIRCUITS,"R1L.circom")} --r1cs --wasm -o ${BUILD}`, { stdio: "inherit" });
// 2) Trusted setup (Groth16)
execSync(`snarkjs groth16 setup ${BUILD}/R1L.r1cs ${PTAU} ${BUILD}/R1L_0000.zkey`, { stdio: "inherit" });
execSync(`snarkjs zkey contribute ${BUILD}/R1L_0000.zkey ${BUILD}/R1L_final.zkey --name="1st" -v -e="entropy"`, { stdio: "inherit" });
execSync(`snarkjs zkey export verificationkey ${BUILD}/R1L_final.zkey ${BUILD}/R1L_verification_key.json`, { stdio: "inherit" });

// 3) Genera e verifica proof
execSync(`node ${BUILD}/R1L_js/generate_witness.js ${BUILD}/R1L_js/R1L.wasm ${BUILD}/input.json ${BUILD}/witness.wtns`, { stdio: "inherit" });
execSync(`snarkjs groth16 prove ${BUILD}/R1L_final.zkey ${BUILD}/witness.wtns ${BUILD}/proof.json ${BUILD}/public.json`, { stdio: "inherit" });
execSync(`snarkjs groth16 verify ${BUILD}/R1L_verification_key.json ${BUILD}/public.json ${BUILD}/proof.json`, { stdio: "inherit" });

console.log("✅ R1L proof generation & verification complete");
