// scripts/test_RL.js
const fs = require("fs");
const path = require("path");
const encodeMessage = require("./encode_message");
const genBjjKeys    = require("./gen_bjj_keys");
const encrypt       = require("./encryption");
const { execSync }  = require("child_process");
const circomlib     = require("circomlibjs");

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

(async () => {
  // 1) Parametri
  const n = randomInt(2, 9);
  const t = randomInt(2, 9);
  console.log(`→ Parametri scelti: n=${n}, t=${t}`);

  // 2) Coefficienti
  const coeffs = Array.from({ length: t + 1 }, () => randomInt(1, 100));
  console.log("coeffs:", coeffs);

  // 3) Valuta polinomio
  const xs = Array.from({ length: n + 1 }, (_, i) =>
    coeffs.reduce((sum, a, j) => sum + a * i ** j, 0)
  );
  console.log("xs:", xs);

  // 4) Calcola Y = x[0]*G
  const babyJub = await circomlib.buildBabyjub();
  const F       = babyJub.F;
  const P0      = babyJub.mulPointEscalar(babyJub.Base8, xs[0]);
  const Y       = [F.toObject(P0[0]).toString(), F.toObject(P0[1]).toString()];
  console.log("Y (x[0]*G):", Y);

  // 5) Encode punti
  const points = [];
  for (const x of xs) {
    points.push(await encodeMessage(x));
  }

  // 6) Keygen ElGamal
  const keyPairs = [];
  for (let i = 0; i < n; i++) {
    keyPairs.push(await genBjjKeys());
  }

  // 7) Encrypt x[1..n]
  const cipher = [];
  for (let i = 0; i < n; i++) {
    const { sk, pk } = keyPairs[i];
    const { ephemeralKey, encryptedMessage } = await encrypt({
      publicKey: pk,
      message: points[i + 1],
      nonce: sk,
    });
    cipher.push({ ephemeralKey, encryptedMessage });
  }

  // 8) Genera RL.circom unrolled
  const CIRCUITS_DIR = path.resolve(__dirname, "..", "circuits");
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });

  const BASE = [
    "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    "16950150798460657717958625567821834550301663161624707787222815936182638968203"
  ];

  let code = `pragma circom 2.2.2;

// include
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/escalarmulfix.circom";
include "../circomlib/circuits/escalarmulany.circom";
include "../circomlib/circuits/comparators.circom";
include "encryption.circom";

template RL() {
    signal input pk[${n}][2];
    signal input Y[2];
    signal input msg[${n}][2];
    signal input cipher[${n}][2][2];
    signal input sk[${n}];
    signal input coeffs[${t + 1}];
    signal input x[${n + 1}];

    // 1) Y = x[0]*G (252 bit)
    component bits = Num2Bits(252);
    bits.in <== x[0];
    component mulG = EscalarMulFix(252, [${BASE[0]}, ${BASE[1]}]);
`;
  for (let i = 0; i < 252; i++) {
    code += `    mulG.e[${i}] <== bits.out[${i}];\n`;
  }
  code += `    mulG.out[0] === Y[0];
    mulG.out[1] === Y[1];

    // 2) Polinomio
`;
  for (let i = 0; i <= n; i++) {
    code += `    { var acc = coeffs[0];\n`;
    for (let j = 1; j <= t; j++) {
      code += `      acc += coeffs[${j}] * ${i ** j};\n`;
    }
    code += `      x[${i}] === acc;\n    }\n`;
  }
  code += `    // 3) ElGamalEncrypt su msg/cipher\n`;
  for (let i = 0; i < n; i++) {
    code += `    component enc${i} = ElGamalEncrypt();\n`;
    code += `    enc${i}.message[0]       <== msg[${i}][0];\n`;
    code += `    enc${i}.message[1]       <== msg[${i}][1];\n`;
    code += `    enc${i}.nonceKey         <== sk[${i}];\n`;
    code += `    enc${i}.publicKey[0]     <== pk[${i}][0];\n`;
    code += `    enc${i}.publicKey[1]     <== pk[${i}][1];\n`;
    code += `    enc${i}.ephemeralKey[0]  === cipher[${i}][0][0];\n`;
    code += `    enc${i}.ephemeralKey[1]  === cipher[${i}][0][1];\n`;
    code += `    enc${i}.encryptedMessage[0] === cipher[${i}][1][0];\n`;
    code += `    enc${i}.encryptedMessage[1] === cipher[${i}][1][1];\n\n`;
  }
  code += `}\ncomponent main = RL();\n`;

  fs.writeFileSync(path.join(CIRCUITS_DIR, "RL.circom"), code);
  console.log("✔ Generato:", path.join(CIRCUITS_DIR, "RL.circom"));

  // 9) Pulisci build/ (mantieni solo .ptau)
  const BUILD_DIR = path.resolve(__dirname, "..", "build");
  fs.readdirSync(BUILD_DIR).forEach(f => {
    if (!f.endsWith(".ptau")) fs.rmSync(path.join(BUILD_DIR, f), { recursive: true, force: true });
  });

  // 10) Scrivi input.json
  const input = {
    pk:     keyPairs.map(k => k.pk),
    Y,
    msg:    points.slice(1),
    cipher: cipher.map(c => [c.ephemeralKey, c.encryptedMessage]),
    sk:     keyPairs.map(k => k.sk),
    coeffs,
    x:      xs,
  };
  fs.writeFileSync(path.join(BUILD_DIR, "input.json"), JSON.stringify(input, null, 2));
  console.log("✔ Scritti:", path.join(BUILD_DIR, "input.json"));

  // 11) Esegui RL.js
  console.log("→ Lancio RL.js …");
  execSync("node RL.js", { cwd: __dirname, stdio: "inherit" });
})();
