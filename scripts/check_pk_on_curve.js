const fs = require("fs");
const circomlibjs = require("circomlibjs");

(async () => {
  const pkRaw = fs.readFileSync("bjj_pk.txt", "utf8");
  const pkArr = JSON.parse(pkRaw.replace(/'/g, '"'));
  const x = BigInt(pkArr[0]);
  const y = BigInt(pkArr[1]);
  const babyjub = await circomlibjs.buildBabyjub();
  const point = [babyjub.F.e(x), babyjub.F.e(y)];
  console.log(
    "Public key:",
    point.map((e) => babyjub.F.toObject(e).toString())
  );
  console.log("Is public key on curve?", babyjub.inCurve(point));
})();
