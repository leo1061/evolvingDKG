// scripts/gen_bjj_keys.js
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const circomlibjs = require("circomlibjs");
const ff = require("ffjavascript");

async function genBjjKeys(i) {
  const babyjub = await circomlibjs.buildBabyjub();

  let sk;
  do {
    sk = ff.utils.leBuff2int(crypto.randomBytes(32));
  } while (sk === BigInt(0) || sk >= babyjub.subOrder);

  const P = babyjub.mulPointEscalar(babyjub.Base8, sk);
  const pk = [
    babyjub.F.toObject(P[0]).toString(),
    babyjub.F.toObject(P[1]).toString(),
  ];

  // Write files in the working directory (Rust expects this)
  fs.writeFileSync(`bjj_sk_${i}.txt`, sk.toString());
  fs.writeFileSync(`bjj_pk_${i}.txt`, JSON.stringify(pk));

  console.log(`Generated BabyJubJub keys for party ${i}`);
}

(async () => {
  const i = process.argv[2];
  if (!i) {
    console.error("Missing index argument");
    process.exit(1);
  }
  await genBjjKeys(i);
})();