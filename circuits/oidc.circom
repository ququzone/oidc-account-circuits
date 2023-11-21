pragma circom 2.1.0;

include "./jwt-verifier.circom";

component main {
    public [
        nonce_hash,
        address_hash
    ]
} = JwtVerifier(640, 165, 145, 32, 121, 17);
