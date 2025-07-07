// scripts/test_RL.js
const fs = require("fs");
const path = require("path");
const encodeMessage = require("./encode_message");
const genBjjKeys    = require("./gen_bjj_keys");
const encrypt       = require("./encryption");
const { execSync }  = require("child_process");

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

(async () => {
  // 1) Parametri
  const n = randomInt(2, 9);
  const t = randomInt(2, 9);
  console.log(`→ Parametri scelti: n=${n}, t=${t}`);

  // 2) Polinomio
  const coeffs = Array.from({ length: t + 1 }, () => randomInt(1, 100));
  console.log("coeffs:", coeffs);

  // 3) Valutazioni f(i)
  const xs = Array.from({ length: n + 1 }, (_, i) =>
    coeffs.reduce((sum, a, j) => sum + a * i ** j, 0)
  );
  console.log("xs:", xs);

  // 4) Encode
  const points = [];
  for (const x of xs) {
    const P = await encodeMessage(x);
    console.log(`x=${x} →`, P);
    points.push(P);
  }

  // 5) Keygen
  const keyPairs = [];
  for (let i = 1; i <= n; i++) {
    const { sk, pk } = await genBjjKeys();
    console.log(`Key#${i}: sk=${sk}, pk=${JSON.stringify(pk)}`);
    keyPairs.push({ sk, pk });
  }

  // 6) Encrypt
  const cipher = [];
  for (let i = 1; i <= n; i++) {
    const { sk, pk } = keyPairs[i - 1];
    const { ephemeralKey, encryptedMessage } = await encrypt({
      publicKey: pk,
      message: points[i],
      nonce: sk,
    });
    console.log(`c${i}:`, { ephemeralKey, encryptedMessage });
    cipher.push({ ephemeralKey, encryptedMessage });
  }

  // 7) Genera RL.circom unrolled, manual Y = x[0]*G
  const CIRCUITS_DIR = path.resolve(__dirname, "..", "circuits");
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });

  // definiamo BASE come stringhe intere
  const BASE = [
    "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    "16950150798460657717958625567821834550301663161624707787222815936182638968203"
  ];

  let rl = `pragma circom 2.2.2;

// include relativi
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/escalarmulfix.circom";
include "../circomlib/circuits/escalarmulany.circom";
include "../circomlib/circuits/comparators.circom";
include "encryption.circom";

template RL() {
    signal input pk[${n}][2];
    signal input Y[2];
    signal input cipher[${n}][2][2];
    signal sk[${n}];
    signal coeffs[${t + 1}];
    signal x[${n + 1}];

    // 1) verifica Y = x[0] * G
    component bits = Num2Bits(250);
    bits.in <== x[0];
    component pbk = EscalarMulFix(250, [${BASE[0]}, ${BASE[1]}]);
    for (var i = 0; i < 250; i++) {
        pbk.e[i] <== bits.out[i];
    }
    pbk.out[0] === Y[0];
    pbk.out[1] === Y[1];

    // 2) verifica f(j)=x_j
`;

  // Unroll polinomio
  for (let i = 0; i <= n; i++) {
    rl += `    {\n`;
    rl += `        var acc = coeffs[0];\n`;
    for (let j = 1; j <= t; j++) {
      rl += `        acc += coeffs[${j}] * ${i ** j};\n`;
    }
    rl += `        x[${i}] === acc;\n`;
    rl += `    }\n\n`;
  }

  // Unroll encryption checks
  rl += `    // 3) verifica cifratura ElGamal\n`;
  for (let i = 1; i <= n; i++) {
    rl += `    component enc${i} = ElGamalEncrypt();\n`;
    rl += `    enc${i}.message           <== cipher[${i - 1}].ephemeralKey;\n`;
    rl += `    enc${i}.nonceKey          <== sk[${i - 1}];\n`;
    rl += `    enc${i}.publicKey         <== pk[${i - 1}];\n`;
    rl += `    enc${i}.encryptedMessage[0] === cipher[${i - 1}].encryptedMessage[0];\n`;
    rl += `    enc${i}.encryptedMessage[1] === cipher[${i - 1}].encryptedMessage[1];\n\n`;
  }

  rl += `}\n\ncomponent main = RL();\n`;

  fs.writeFileSync(path.join(CIRCUITS_DIR, "RL.circom"), rl);
  console.log("✔ Generato:", path.join(CIRCUITS_DIR, "RL.circom"));

  // 8) Prepara input.json
  const BUILD_DIR = path.join(__dirname, "build");
  fs.rmSync(BUILD_DIR, { recursive: true, force: true });
  fs.mkdirSync(BUILD_DIR, { recursive: true });

  const input = {
    pk:     keyPairs.map(k => k.pk),
    Y:      points[0],
    cipher: cipher.map(c => [c.ephemeralKey, c.encryptedMessage]),
    sk:     keyPairs.map(k => k.sk),
    coeffs,
    x:      xs,
  };
  fs.writeFileSync(path.join(BUILD_DIR, "input.json"), JSON.stringify(input, null, 2));
  console.log("✔ Scritti:", path.join(BUILD_DIR, "input.json"));

  // 9) Esegui RL.js
  console.log("→ Lancio RL.js …");
  execSync("node RL.js", { cwd: __dirname, stdio: "inherit" });

  // 10) Cleanup
  fs.rmSync(BUILD_DIR, { recursive: true, force: true });
  console.log("🧹 build/ ripulita");
})();
