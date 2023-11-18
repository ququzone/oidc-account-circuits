pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "./helpers/sha.circom";
include "./helpers/rsa.circom";

template JwtVerifier(max_bytes, n, k) {
    assert(max_bytes % 64 == 0);
    // constraints for 2048 bit RSA
    assert(n * k > 2048);
    // we want a multiplication to fit into a circom signal
    assert(n < (255 \ 2));

    // prehashed unsigned jwt data, includes up to 512 + 64? bytes of padding pre SHA256, and padded with lots of 0s at end after the length
    signal input in_padded[max_bytes];
    // rsa pubkey, verified with smart contract + DNSSEC proof. split up into k parts of n bits each.
    signal input pubkey[k];
    // rsa signature. split up into k parts of n bits each.
    signal input signature[k];
    // length of in jwt data including the padding, which will inform the sha256 block length
    signal input in_len_padded_bytes;

    signal sha[256] <== Sha256Bytes(max_bytes)(in_padded, in_len_padded_bytes);
    signal pubkey_hash;

    var msg_len = (256 + n) \ n;

    component base_msg[msg_len];
    for (var i = 0; i < msg_len; i++) {
        base_msg[i] = Bits2Num(n);
    }
    for (var i = 0; i < 256; i++) {
        base_msg[i \ n].in[i % n] <== sha[255 - i];
    }
    for (var i = 256; i < n * msg_len; i++) {
        base_msg[i \ n].in[i % n] <== 0;
    }

    // VERIFY RSA SIGNATURE: 149,251 constraints
    // The fields that this signature actually signs are defined as the body and the values in the header
    component rsa = RSAVerify65537(n, k);
    for (var i = 0; i < msg_len; i++) {
        rsa.base_message[i] <== base_msg[i].out;
    }
    for (var i = msg_len; i < k; i++) {
        rsa.base_message[i] <== 0;
    }
    rsa.modulus <== pubkey;
    rsa.signature <== signature;
}
