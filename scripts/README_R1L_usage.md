# R1L Circuit Test Script Usage

## Overview
The `test_R1Lpot20.js` script has been modified to accept command-line parameters for testing the R1L circuit with custom inputs.

## Usage Modes

### Mode 1: Generate Random Messages (Original Behavior)
```bash
node test_R1Lpot20.js <sk> <pk_x> <pk_y> <n>
```
- Generates `n` random messages
- Encrypts them using the provided public key
- If `n` is odd, automatically pads to `n+1`
- Calculates Y as Base8^(sum of messages)

### Mode 2: Use External Ciphertexts
```bash
node test_R1Lpot20.js <sk> <pk_x> <pk_y> <n> <ciphertext_file> <Y_x> <Y_y>
```
- Reads ciphertexts from a JSON file
- Requires Y point coordinates (the expected sum)
- Supports automatic padding detection

## Parameters
- `sk`: Private key (decimal string or BigInt)
- `pk_x`, `pk_y`: Public key coordinates
- `n`: Number of ciphertexts (original, before padding)
- `ciphertext_file`: JSON file with ciphertexts (optional)
- `Y_x`, `Y_y`: Y point coordinates (required with ciphertext_file)

## Ciphertext File Format

### Format 1: Array of ciphertexts
```json
[
  [["ephemeral_x", "ephemeral_y"], ["encrypted_x", "encrypted_y"]],
  [["ephemeral_x", "ephemeral_y"], ["encrypted_x", "encrypted_y"]]
]
```

### Format 2: Object with cipher array
```json
{
  "cipher": [
    [["ephemeral_x", "ephemeral_y"], ["encrypted_x", "encrypted_y"]],
    [["ephemeral_x", "ephemeral_y"], ["encrypted_x", "encrypted_y"]]
  ]
}
```

## Examples

### Example 1: Random Generation
```bash
# Generate and encrypt 5 random messages (will pad to 6)
node test_R1Lpot20.js 12345 1234567890 9876543210 5
```

### Example 2: External Ciphertexts
```bash
# Use 4 ciphertexts from file with known Y
node test_R1Lpot20.js 12345 1234567890 9876543210 4 ciphers.json 111111 222222
```

### Example 3: Generate Test Data
```bash
# Generate realistic test data with proper BabyJubJub keys
node generate_test_data_R1L.js

# This creates:
# - testdata_even_4.json
# - testdata_odd_5.json
# - testdata_even_10.json
# - run_all_tests_R1L.sh

# Run all tests
./run_all_tests_R1L.sh
```

## Notes
- When `n` is odd and using external ciphertexts, the file should contain `n+1` ciphertexts (with padding)
- The script will automatically detect and handle padding
- All numeric values in JSON files should be strings to handle large BigInt values