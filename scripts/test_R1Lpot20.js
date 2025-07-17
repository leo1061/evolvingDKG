// scripts/test_R1Lpot20.js
const fs         = require("fs");
const path       = require("path");
const crypto     = require("crypto");
const circomlib  = require("circomlibjs");
const genBjjKeys = require("./gen_bjj_keys");
const encrypt    = require("./encryption");
const { execSync } = require("child_process");

// genera un BigInt casuale di 64 bit
function randomInt64() {
  return BigInt("0x" + crypto.randomBytes(8).toString("hex"));
}
// JSON.stringify per BigInt
function bigintReplacer(_, v) {
  return typeof v === "bigint" ? v.toString() : v;
}

;(async () => {
  // 1) Genera chiavi ElGamal
  const { sk, pk } = await genBjjKeys();

  // 2) Scegli n originale
  let n = 400;    // puoi cambiare in 3,4,5,...
  console.log(`→ Parametro scelto: n originale = ${n}`);

  // 3) Prepara msgs
  const babyJub = await circomlib.buildBabyjub();
  const F       = babyJub.F;
  const msgs    = Array.from({ length: n }, randomInt64);

  // Stampa i messaggi scelti
  console.log("→ Messaggi casuali generati:", msgs.map(m => m.toString()));

  // Se n dispari, faccio padding con un messaggio zero
  let padded = false;
  if (n % 2 === 1) {
    msgs.push(0n);
    n += 1;
    padded = true;
    console.log(`→ Padding aggiunto, nuovo n = ${n}`);
  }

  // 4) Cifra tutti i messaggi (incluso eventualmente lo zero)
  const cipher = [];
  for (let m of msgs) {
    const Pm = babyJub.mulPointEscalar(babyJub.Base8, m);
    const M  = [F.toObject(Pm[0]).toString(), F.toObject(Pm[1]).toString()];
    const nonce = randomInt64();
    const { ephemeralKey, encryptedMessage } = await encrypt({
      publicKey: pk,
      message:   M,
      nonce,
    });
    cipher.push([
      [BigInt(ephemeralKey[0]),     BigInt(ephemeralKey[1])],
      [BigInt(encryptedMessage[0]), BigInt(encryptedMessage[1])]
    ]);
  }

  // 5) Calcola Y = Base8^(somma dei msgs originali)
  const sumOriginal = msgs.slice(0, padded ? msgs.length-1 : msgs.length)
                           .reduce((a,b)=>a+b, 0n);
  const Psum = babyJub.mulPointEscalar(babyJub.Base8, sumOriginal);
  const Y    = [
    BigInt(F.toObject(Psum[0])),
    BigInt(F.toObject(Psum[1]))
  ];

  // 6) Genera dinamicamente circuits/R1L.circom con parametro pari
  const CIRCUITS_DIR = path.resolve(__dirname, "..", "circuits");
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });

  const BASE8 = babyJub.Base8.map(x => F.toObject(x).toString());
  let circom = `
pragma circom 2.2.2;
include "decryption.circom";
include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/escalarmulany.circom";

template R1L(n) {
    signal input sk;
    signal input pk[2];
    signal input Y[2];
    signal input cipher[n][2][2];

    // verifica pk = sk * Base8
    component b2 = Num2Bits(254);
    b2.in <== sk;
    component mg = EscalarMulAny(254);
    mg.p[0] <== ${BASE8[0]};
    mg.p[1] <== ${BASE8[1]};
`;
  for (let i = 0; i < 254; i++) {
    circom += `    mg.e[${i}] <== b2.out[${i}];\n`;
  }
  circom += `
    mg.out[0] === pk[0];
    mg.out[1] === pk[1];

    // decrypt + accumulate
    signal accx[n];
    signal accy[n];
    component dec0 = ElGamalDecrypt();
    dec0.ephemeralKey     <== cipher[0][0];
    dec0.encryptedMessage <== cipher[0][1];
    dec0.privateKey       <== sk;
    accx[0] <== dec0.message[0];
    accy[0] <== dec0.message[1];
`;
  for (let i = 1; i < n; i++) {
    circom += `
    component dec${i} = ElGamalDecrypt();
    dec${i}.ephemeralKey     <== cipher[${i}][0];
    dec${i}.encryptedMessage <== cipher[${i}][1];
    dec${i}.privateKey       <== sk;
    component add${i} = BabyAdd();
    add${i}.x1 <== accx[${i-1}];
    add${i}.y1 <== accy[${i-1}];
    add${i}.x2 <== dec${i}.message[0];
    add${i}.y2 <== dec${i}.message[1];
    accx[${i}] <== add${i}.xout;
    accy[${i}] <== add${i}.yout;
`;
  }
  circom += `
    // confronto finale
    accx[n-1] === Y[0];
    accy[n-1] === Y[1];
}

component main = R1L(${n});
`.trim();

  fs.writeFileSync(path.join(CIRCUITS_DIR, "R1L.circom"), circom);

  // 7) Pulisci build (tranne .ptau) e scrivi input.json
  const BUILD = path.resolve(__dirname, "..", "build");
  fs.mkdirSync(BUILD, { recursive: true });
  for (const f of fs.readdirSync(BUILD)) {
    if (!f.endsWith(".ptau")) fs.rmSync(path.join(BUILD, f), { recursive: true, force: true });
  }
  const input = { sk, pk, Y, cipher };
  fs.writeFileSync(path.join(BUILD, "input.json"), JSON.stringify(input, bigintReplacer, 2));

  // 8) Lancia il runner per compile→setup→proof
  execSync("node R1Lpot20.js", { cwd: __dirname, stdio: "inherit" });
})();
