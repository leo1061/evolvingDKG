// scripts/encryption.js
const circomlibjs = require("circomlibjs");

async function encrypt({ publicKey, message, nonce }) {
  if (!encrypt._babyjub) {
    encrypt._babyjub = await circomlibjs.buildBabyjub();
  }
  const babyjub = encrypt._babyjub;
  const F = babyjub.F;
  const pk = [ F.e(BigInt(publicKey[0])), F.e(BigInt(publicKey[1])) ];
  const msg = [ F.e(BigInt(message[0])),    F.e(BigInt(message[1])) ];
  const k   = BigInt(nonce);

  const E = babyjub.mulPointEscalar(babyjub.Base8, k);
  const S = babyjub.mulPointEscalar(pk, k);
  const C = babyjub.addPoint(msg, S);

  return {
    ephemeralKey: [F.toObject(E[0]).toString(), F.toObject(E[1]).toString()],
    encryptedMessage: [F.toObject(C[0]).toString(), F.toObject(C[1]).toString()]
  };
}

module.exports = encrypt;
