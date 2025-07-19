#!/bin/bash
example=$1

rustc examples/$example.rs \
  --extern ark_ed_on_bn254 \
  --extern ark_ec \
  --extern ark_ff \
  --extern ark_std \
  --extern ark_bn254 \
  -L target/debug/deps \
  -o $example

# Then run it
./$example
