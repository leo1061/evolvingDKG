// scripts/encode_message.js
const circomlibjs = require("circomlibjs");
const ff = require("ffjavascript");

async function encodeMessage(message) {
  if (!encodeMessage._babyjub) {
    encodeMessage._babyjub = await circomlibjs.buildBabyjub();
  }
  const babyjub = encodeMessage._babyjub;
  const scalar = BigInt(message) % babyjub.subOrder;
  const point  = babyjub.mulPointEscalar(babyjub.Base8, scalar);
  const x = babyjub.F.toObject(point[0]).toString();
  const y = babyjub.F.toObject(point[1]).toString();
  if (!babyjub.inCurve(point)) {
    throw new Error("Point not on curve");
  }
  return [x, y];
}

module.exports = encodeMessage;
