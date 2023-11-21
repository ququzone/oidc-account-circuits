#!/bin/sh
set -e

cd output
snarkjs powersoftau new bn128 20 pot20_0000.ptau
snarkjs powersoftau contribute pot20_0000.ptau pot20_0001.ptau --name="First contribution" -e="$(openssl rand -base64 20)"
snarkjs powersoftau prepare phase2 pot20_0001.ptau pot20_final.ptau
snarkjs groth16 setup oidc.r1cs pot20_final.ptau oidc_0000.zkey
snarkjs zkey contribute oidc_0000.zkey oidc_0001.zkey --name="Second contribution" -e="$(openssl rand -base64 20)"
snarkjs zkey export verificationkey oidc_0001.zkey verification_key.json
rm -rf *.ptau