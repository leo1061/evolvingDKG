const fs = require("fs");
const crypto = require("crypto");
const circomlibjs = require("circomlibjs");
const ff = require("ffjavascript");

async function generateBJJKeys(index = null) {
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

  // Determine filenames based on whether index is provided
  const skFilename = index !== null ? `bjj_sk_${index}.txt` : "bjj_sk.txt";
  const pkFilename = index !== null ? `bjj_pk_${index}.txt` : "bjj_pk.txt";

  // Write private key
  fs.writeFileSync(skFilename, prv.toString());

  // Write public key as a JSON array of strings
  const pubkeyJson = JSON.stringify([
    babyjub.F.toObject(pub[0]).toString(),
    babyjub.F.toObject(pub[1]).toString(),
  ]);
  fs.writeFileSync(pkFilename, pubkeyJson);

  // console.log(`BabyJubJub Private key written to ${skFilename}`);
  // console.log(`BabyJubJub Public key written to ${pkFilename}`);
  // console.log("Private key:", prv.toString());
  // console.log("Public key:", pubkeyJson);
  // console.log("Public key is on curve:", babyjub.inCurve(pub));

  return { privateKey: prv.toString(), publicKey: pubkeyJson };
}

// If this file is run directly (not imported as a module)
if (require.main === module) {
  const index = process.argv[2] || null; // Only use index if explicitly provided
  generateBJJKeys(index).catch(console.error);
}

// Export the function for use in other files
module.exports = generateBJJKeys;
