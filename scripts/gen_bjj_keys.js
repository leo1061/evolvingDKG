const fs = require("fs");
const crypto = require("crypto");
const circomlibjs = require("circomlibjs");
const ff = require("ffjavascript");

(async () => {
  // Initialize babyjub
  const babyjub = await circomlibjs.buildBabyjub();

  // Generate private key as a random scalar mod babyjub.subOrder
  const prv = ff.utils.leBuff2int(crypto.randomBytes(32)) % babyjub.subOrder;

  // Generate public key as a point using the correct base point
  const pub = babyjub.mulPointEscalar(babyjub.Base8, prv);

  // Verify the public key is on the curve
  if (!babyjub.inCurve(pub)) {
    throw new Error("Generated public key is not on the curve");
  }

  // Write private key
  fs.writeFileSync("bjj_sk.txt", prv.toString());

  // Write public key as a JSON array of strings
  const pubkeyJson = JSON.stringify([
    babyjub.F.toObject(pub[0]).toString(),
    babyjub.F.toObject(pub[1]).toString(),
  ]);
  fs.writeFileSync("bjj_pk.txt", pubkeyJson);

  console.log("BabyJubJub Private key written to bjj_sk.txt");
  console.log("BabyJubJub Public key written to bjj_pk.txt");
  console.log("Private key:", prv.toString());
  console.log("Public key:", pubkeyJson);
  console.log("Public key is on curve:", babyjub.inCurve(pub));
})();
