const ff = require("ffjavascript");
const circomlibjs = require("circomlibjs");

async function encodeMessage(message) {
  // Initialize BabyJubJub curve
  const babyjub = await circomlibjs.buildBabyjub();

  // Convert message to a number and ensure it's within the field range
  const fieldSize = BigInt(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
  );
  const scalar = BigInt(message) % fieldSize;

  // Use the base point to generate a point on the curve
  const point = babyjub.mulPointEscalar(babyjub.Base8, scalar);

  // Convert to numbers and ensure they're properly formatted for JSON
  const x = babyjub.F.toObject(point[0]).toString();
  const y = babyjub.F.toObject(point[1]).toString();

  console.log("Message:", message);
  console.log("Scalar:", scalar.toString());
  console.log("Generated point:", [x, y]);

  // Verify the point is on the curve
  if (!babyjub.inCurve(point)) {
    throw new Error("Generated point is not on the curve");
  }

  return [x, y];
}

// Get message from command line argument
const message = process.argv[2];
if (!message) {
  console.error("Please provide a message to encode");
  process.exit(1);
}

// Run the async function
encodeMessage(message)
  .then((encodedPoint) => {
    // Ensure the output is valid JSON with numbers
    const output = JSON.stringify(encodedPoint);
    if (!output) {
      throw new Error("Failed to stringify encoded point");
    }
    console.log(output);
  })
  .catch((error) => {
    console.error("Error encoding message:", error);
    process.exit(1);
  });
