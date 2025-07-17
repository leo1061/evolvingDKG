// scripts/R1L.js
const { execSync } = require("child_process");
const path         = require("path");
const fs           = require("fs");

const ROOT     = path.resolve(__dirname, "..");
const CIRCUITS = path.join(ROOT, "circuits");
const BUILD    = path.join(ROOT, "build");
const PTAU     = path.join(BUILD, "pot17_final.ptau");

fs.mkdirSync(BUILD, { recursive: true });

console.log("*** 1) Compile R1L.circom");
// rimosso `--sym` per evitare panico su grandi n
execSync(
  `circom ${path.join(CIRCUITS, "R1L.circom")} --r1cs --wasm -o ${BUILD}`,
  { stdio: "inherit" }
);

console.log("*** 2) Setup Groth16 parameters");
execSync(
  `snarkjs groth16 setup ${BUILD}/R1L.r1cs ${PTAU} ${BUILD}/R1L_0000.zkey`,
  { stdio: "inherit" }
);

console.log("*** 3) Contribute to phase 2");
execSync(
  `snarkjs zkey contribute ${BUILD}/R1L_0000.zkey ${BUILD}/R1L_final.zkey --name="1st contribution" -v -e="entropy"`,
  { stdio: "inherit" }
);

console.log("*** 4) Export verification key");
execSync(
  `snarkjs zkey export verificationkey ${BUILD}/R1L_final.zkey ${BUILD}/R1L_verification_key.json`,
  { stdio: "inherit" }
);

console.log("*** 5) Generate witness");
execSync(
  `node ${BUILD}/R1L_js/generate_witness.js ${BUILD}/R1L_js/R1L.wasm ${BUILD}/input.json ${BUILD}/witness.wtns`,
  { stdio: "inherit" }
);

console.log("*** 6) Generate proof");
execSync(
  `snarkjs groth16 prove ${BUILD}/R1L_final.zkey ${BUILD}/witness.wtns ${BUILD}/proof.json ${BUILD}/public.json`,
  { stdio: "inherit" }
);

console.log("*** 7) Verify proof");
execSync(
  `snarkjs groth16 verify ${BUILD}/R1L_verification_key.json ${BUILD}/public.json ${BUILD}/proof.json`,
  { stdio: "inherit" }
);

console.log("✅ R1L proof generation & verification complete");
