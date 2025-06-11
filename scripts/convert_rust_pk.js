const fs = require("fs");
const circomlibjs = require("circomlibjs");

(async () => {
  // Read the Rust-generated public key
  const pkRaw = fs.readFileSync("bjj_pk.txt", "utf8");
  // Parse as array of big integers
  const pkArr = JSON.parse(pkRaw.replace(/'/g, '"'));
  const x = BigInt(pkArr[0]);
  const y = BigInt(pkArr[1]);

  // Initialize BabyJubJub
  const babyjub = await circomlibjs.buildBabyjub();

  // Convert to field elements (as circomlibjs expects)
  const xF = babyjub.F.toObject(babyjub.F.e(x)).toString();
  const yF = babyjub.F.toObject(babyjub.F.e(y)).toString();

  // Output as JSON array of strings
  const output = JSON.stringify([xF, yF]);
  console.log(output);
})();
