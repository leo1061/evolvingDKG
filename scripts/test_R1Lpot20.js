// scripts/test_R1Lpot20.js
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const circomlib = require("circomlibjs");
const genBjjKeys = require("./gen_bjj_keys");
const encrypt = require("./encryption");
const { execSync } = require("child_process");

// genera un BigInt casuale di 64 bit
function randomInt64() {
  return BigInt("0x" + crypto.randomBytes(8).toString("hex"));
}
// JSON.stringify per BigInt
function bigintReplacer(_, v) {
  return typeof v === "bigint" ? v.toString() : v;
}

(async () => {
  // Parse command line arguments
  const args = process.argv.slice(2);

  if (args.length < 4) {
    console.error(
      "Usage: node test_R1Lpot20.js <sk> <pk_x> <pk_y> <n> [ciphertext_file] [Y_x Y_y]"
    );
    console.error("  sk: private key (decimal string or BigInt)");
    console.error("  pk_x: public key x coordinate");
    console.error("  pk_y: public key y coordinate");
    console.error("  n: number of ciphertexts");
    console.error(
      "  ciphertext_file: optional JSON file containing ciphertexts"
    );
    console.error(
      "  Y_x Y_y: optional Y point coordinates (required when using external ciphertexts)"
    );
    process.exit(1);
  }

  // 1) Parse ElGamal keys from command line
  const sk = BigInt(args[0]);
  const pk = [BigInt(args[1]), BigInt(args[2])];

  // 2) Parse n from command line
  let n = parseInt(args[3]);
  if (isNaN(n) || n < 1) {
    console.error("Error: n must be a positive integer");
    process.exit(1);
  }
  console.log(`→ Parametro scelto: n originale = ${n}`);

  // 3) Initialize BabyJub
  const babyJub = await circomlib.buildBabyjub();
  const F = babyJub.F;

  // 4) Handle ciphertexts
  let cipher = [];
  let msgs = [];
  let padded = false;

  if (args.length >= 5 && args[4]) {
    // Read ciphertexts from file
    try {
      const cipherData = JSON.parse(fs.readFileSync(args[4], "utf8"));

      // Convert string values to BigInt
      if (Array.isArray(cipherData)) {
        cipher = cipherData.map((c) => [
          [BigInt(c[0][0]), BigInt(c[0][1])],
          [BigInt(c[1][0]), BigInt(c[1][1])],
        ]);
      } else if (cipherData.cipher) {
        cipher = cipherData.cipher.map((c) => [
          [BigInt(c[0][0]), BigInt(c[0][1])],
          [BigInt(c[1][0]), BigInt(c[1][1])],
        ]);
      } else if (cipherData.ciphertexts) {
        cipher = cipherData.ciphertexts.map((c) => [
          [BigInt(c[0][0]), BigInt(c[0][1])],
          [BigInt(c[1][0]), BigInt(c[1][1])],
        ]);
      } else {
        console.error("Error: Invalid ciphertext file format");
        console.error(
          "Expected format: array, or object with 'cipher' or 'ciphertexts' key"
        );
        process.exit(1);
      }

      // Adjust n if needed to match the number of ciphertexts
      if (cipher.length !== n) {
        if (cipher.length === n + 1 && n % 2 === 1) {
          // Likely padded - adjust n
          console.log(
            `→ Detected padded ciphertexts (${cipher.length} ciphertexts for n=${n})`
          );
          n = cipher.length;
          padded = true;
        } else {
          console.error(
            `Error: Number of ciphertexts (${cipher.length}) doesn't match n (${n})`
          );
          console.error(
            `Note: If n is odd, the file might contain n+1 ciphertexts (with padding)`
          );
          process.exit(1);
        }
      }

      console.log(`→ Loaded ${cipher.length} ciphertexts from file`);
    } catch (err) {
      console.error("Error reading ciphertext file:", err.message);
      process.exit(1);
    }
  } else {
    // Generate random messages and encrypt them
    msgs = Array.from({ length: n }, randomInt64);

    // Stampa i messaggi scelti
    console.log(
      "→ Messaggi casuali generati:",
      msgs.map((m) => m.toString())
    );

    // Se n dispari, faccio padding con un messaggio zero
    if (n % 2 === 1) {
      msgs.push(0n);
      n += 1;
      padded = true;
      console.log(`→ Padding aggiunto, nuovo n = ${n}`);
    }

    // Cifra tutti i messaggi (incluso eventualmente lo zero)
    for (let m of msgs) {
      const Pm = babyJub.mulPointEscalar(babyJub.Base8, m);
      const M = [F.toObject(Pm[0]).toString(), F.toObject(Pm[1]).toString()];
      const nonce = randomInt64();
      const { ephemeralKey, encryptedMessage } = await encrypt({
        publicKey: pk,
        message: M,
        nonce,
      });
      cipher.push([
        [BigInt(ephemeralKey[0]), BigInt(ephemeralKey[1])],
        [BigInt(encryptedMessage[0]), BigInt(encryptedMessage[1])],
      ]);
    }
  }

  // 5) Calcola Y = Base8^(somma dei msgs originali)
  let Y;
  if (args.length >= 5 && args[4]) {
    // When using external ciphertexts, Y must be provided
    if (args.length >= 7) {
      // Y coordinates provided
      Y = [BigInt(args[5]), BigInt(args[6])];
      console.log(`→ Using provided Y point: [${Y[0]}, ${Y[1]}]`);
    } else {
      console.error(
        "Error: When using external ciphertexts, Y point coordinates must be provided"
      );
      console.error(
        "Usage: node test_R1Lpot20.js <sk> <pk_x> <pk_y> <n> <ciphertext_file> <Y_x> <Y_y>"
      );
      process.exit(1);
    }
  } else {
    // When generating random messages, calculate Y normally
    const sumOriginal = msgs
      .slice(0, padded ? msgs.length - 1 : msgs.length)
      .reduce((a, b) => a + b, 0n);
    const Psum = babyJub.mulPointEscalar(babyJub.Base8, sumOriginal);
    Y = [BigInt(F.toObject(Psum[0])), BigInt(F.toObject(Psum[1]))];
  }

  // 6) Genera dinamicamente circuits/R1L.circom con parametro pari
  const CIRCUITS_DIR = path.resolve(__dirname, "..", "circuits");
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });

  const BASE8 = babyJub.Base8.map((x) => F.toObject(x).toString());
  let circom = `
pragma circom 2.2.2;
include "elgamal_elligator2.circom";
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
    add${i}.x1 <== accx[${i - 1}];
    add${i}.y1 <== accy[${i - 1}];
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
    if (!f.endsWith(".ptau"))
      fs.rmSync(path.join(BUILD, f), { recursive: true, force: true });
  }
  const input = { sk, pk, Y, cipher };
  fs.writeFileSync(
    path.join(BUILD, "input.json"),
    JSON.stringify(input, bigintReplacer, 2)
  );

  // 8) Lancia il runner per compile→setup→proof
  execSync("node R1Lpot20.js", { cwd: __dirname, stdio: "inherit" });
})();
