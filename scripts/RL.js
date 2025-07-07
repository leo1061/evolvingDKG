// scripts/RL.js
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT_DIR     = path.resolve(__dirname, "..");   // evolvingDKG root
const CIRCUITS_DIR = path.join(ROOT_DIR, "circuits");
const BUILD_DIR    = path.join(__dirname, "build");
const PTAU         = path.join(CIRCUITS_DIR, "powersOfTau28_hez_final_10.ptau");
const Z0           = path.join(BUILD_DIR, "RL_0000.zkey");
const ZF           = path.join(BUILD_DIR, "RL_final.zkey");
const VK           = path.join(BUILD_DIR, "verification_key.json");

fs.mkdirSync(BUILD_DIR, { recursive: true });

console.log("*** 1) Compile RL.circom");
execSync(
  `circom ${path.join(CIRCUITS_DIR, "RL.circom")} --r1cs --wasm --sym -o ${BUILD_DIR}`,
  { stdio: "inherit" }
);

console.log("*** 2) Setup Groth16 parameters");
execSync(
  `snarkjs groth16 setup ${BUILD_DIR}/RL.r1cs ${PTAU} ${Z0}`,
  { stdio: "inherit" }
);

console.log("*** 3) Contribute to phase 2");
execSync(
  `snarkjs zkey contribute ${Z0} ${ZF} --name="1st contribution" -v -e="entropy"`,
  { stdio: "inherit" }
);

console.log("*** 4) Export verification key");
execSync(
  `snarkjs zkey export verificationkey ${ZF} ${VK}`,
  { stdio: "inherit" }
);

console.log("*** 5) Generate witness");
execSync(
  `node ${BUILD_DIR}/RL_js/generate_witness.js ${BUILD_DIR}/RL_js/RL.wasm ${BUILD_DIR}/input.json ${BUILD_DIR}/witness.wtns`,
  { stdio: "inherit" }
);

console.log("*** 6) Generate proof");
execSync(
  `snarkjs groth16 prove ${ZF} ${BUILD_DIR}/witness.wtns ${BUILD_DIR}/proof.json ${BUILD_DIR}/public.json`,
  { stdio: "inherit" }
);

console.log("*** 7) Verify proof");
execSync(
  `snarkjs groth16 verify ${VK} ${BUILD_DIR}/public.json ${BUILD_DIR}/proof.json`,
  { stdio: "inherit" }
);

console.log("✅ RL proof generation & verification complete");
