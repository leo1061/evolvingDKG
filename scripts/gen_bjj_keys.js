// scripts/gen_bjj_keys.js
const crypto = require("crypto");
const circomlibjs = require("circomlibjs");
const ff = require("ffjavascript");

async function genBjjKeys() {
  if (!genBjjKeys._babyjub) {
    genBjjKeys._babyjub = await circomlibjs.buildBabyjub();
  }
  const babyjub = genBjjKeys._babyjub;
  let sk;
  do {
    sk = ff.utils.leBuff2int(crypto.randomBytes(32));
  } while (sk === BigInt(0) || sk >= babyjub.subOrder);

  const P = babyjub.mulPointEscalar(babyjub.Base8, sk);
  const pk = [
    babyjub.F.toObject(P[0]).toString(),
    babyjub.F.toObject(P[1]).toString(),
  ];
  return { sk: sk.toString(), pk };
}

module.exports = genBjjKeys;
