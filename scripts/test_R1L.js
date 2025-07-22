// scripts/test_R1L.js
const fs         = require("fs");
const path       = require("path");
const crypto     = require("crypto");
const circomlib  = require("circomlibjs");
const genBjjKeys = require("./gen_bjj_keys");
const encrypt    = require("./encryption");
const { execSync } = require("child_process");

// Genera un BigInt casuale a 64 bit
function randomInt64() {
  const buf = crypto.randomBytes(8);         // 8 byte = 64 bit
  return BigInt("0x" + buf.toString("hex"));
}

(async () => {
  // 1) Coppia di chiavi ElGamal
  const { sk, pk } = await genBjjKeys();

  // 2) Scegli n e genera n messaggi a 64 bit

  const n = 20; // adesso è settato a 20

  //const n    = Math.floor(Math.random() * 190) + 10; // per esempio tra 10 e 199
  console.log(`→ Parametro scelto: n=${n}`);
  const msgs = Array.from({ length: n }, () => randomInt64());
  console.log("messages (64‑bit):", msgs.map(m => m.toString()));

  // 3) Cifra ogni m come punto M = m·Base8
  const babyJub = await circomlib.buildBabyjub();
  const F       = babyJub.F;
  const cipher  = [];
  for (const m of msgs) {
    const Pm = babyJub.mulPointEscalar(babyJub.Base8, m);
    const M  = [
      F.toObject(Pm[0]).toString(),
      F.toObject(Pm[1]).toString()
    ];
    const { ephemeralKey, encryptedMessage } = await encrypt({
      publicKey: pk,
      message: M,
      nonce: sk,
    });
    cipher.push([ephemeralKey, encryptedMessage]);
  }
  console.log("→ Encrypted all messages");

  // 4) Somma chiara e Y = Base8^(somma dei m)
  const sumM = msgs.reduce((a, b) => a + b, 0n);
  const Psum = babyJub.mulPointEscalar(babyJub.Base8, sumM);
  const Y    = [
    F.toObject(Psum[0]).toString(),
    F.toObject(Psum[1]).toString()
  ];
  console.log("→ Y (somma punto):", Y);

  // 5) Genera dinamicamente circuits/R1L.circom
  const CIRCUITS_DIR = path.resolve(__dirname, "..", "circuits");
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });
  const BASE8 = babyJub.Base8.map(x => F.toObject(x).toString());

  let code = `pragma circom 2.2.2;
include "decryption.circom";
include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/escalarmulany.circom";

template R1L(n) {
    signal input sk;
    signal input pk[2];
    signal input Y[2];
    signal input cipher[n][2][2];
    signal accx[n];
    signal accy[n];

    // 1) Verifica pk = sk*Base8, con 254 bit e EscalarMulAny
    component b2 = Num2Bits(254);
    b2.in <== sk;
    component mg = EscalarMulAny(254);
    mg.p[0] <== ${BASE8[0]};
    mg.p[1] <== ${BASE8[1]};
`;
  for (let i = 0; i < 254; i++) {
    code += `    mg.e[${i}] <== b2.out[${i}];\n`;
  }
  code += `
    mg.out[0] === pk[0];
    mg.out[1] === pk[1];

    // 2) Decrypt primo e accumula
    component dec0 = ElGamalDecrypt();
    dec0.ephemeralKey     <== cipher[0][0];
    dec0.encryptedMessage <== cipher[0][1];
    dec0.privateKey       <== sk;
    accx[0] <== dec0.message[0];
    accy[0] <== dec0.message[1];
`;

  for (let j = 1; j < n; j++) {
    code += `
    component dec${j} = ElGamalDecrypt();
    dec${j}.ephemeralKey     <== cipher[${j}][0];
    dec${j}.encryptedMessage <== cipher[${j}][1];
    dec${j}.privateKey       <== sk;

    component add${j} = BabyAdd();
    add${j}.x1 <== accx[${j-1}];
    add${j}.y1 <== accy[${j-1}];
    add${j}.x2 <== dec${j}.message[0];
    add${j}.y2 <== dec${j}.message[1];
    accx[${j}] <== add${j}.xout;
    accy[${j}] <== add${j}.yout;
`;
  }

  code += `
    // 3) Verifica somma punto = Y
    accx[${n-1}] === Y[0];
    accy[${n-1}] === Y[1];
}

component main = R1L(${n});
`;

  fs.writeFileSync(path.join(CIRCUITS_DIR, "R1L.circom"), code);
  console.log("✔ Generato:", path.join(CIRCUITS_DIR, "R1L.circom"));

  // 6) Pulisci build/ lasciando intatti i .ptau
  const BUILD = path.resolve(__dirname, "..", "build");
  fs.mkdirSync(BUILD, { recursive: true });
  fs.readdirSync(BUILD).forEach(f => {
    if (!f.endsWith(".ptau")) fs.rmSync(path.join(BUILD, f), { recursive: true, force: true });
  });

  // 7) Scrivi input.json
  const input = { sk, pk, Y, cipher };
  fs.writeFileSync(path.join(BUILD, "input.json"), JSON.stringify(input, null, 2));
  console.log("✔ Scritti:", path.join(BUILD, "input.json"));

  // 8) Esegui lo script di compilazione/proof
  console.log("→ Lancio R1L.js …");
  execSync("node R1L.js", { cwd: __dirname, stdio: "inherit" });
})();
