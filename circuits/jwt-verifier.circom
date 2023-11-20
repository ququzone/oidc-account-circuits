pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

include "./helpers/string.circom";
include "./helpers/sha.circom";
include "./helpers/rsa.circom";
include "./helpers/base64.circom";
include "./helpers/hasher.circom";

template JwtVerifier(max_bytes, n, k) {
    // constraints for 2048 bit RSA
    assert(n * k > 2048);
    // we want a multiplication to fit into a circom signal
    assert(n < (255 \ 2));

    signal input in_padded[max_bytes];
    signal input signature[k];
    signal input pubkey[k];

    // jwt hash
    signal sha[256] <== Sha256String(max_bytes)(in_padded);

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

    // Verify RSA signature
    component rsa = RSAVerify65537(n, k);
    for (var i = 0; i < msg_len; i++) {
        rsa.base_message[i] <== base_msg[i].out;
    }
    for (var i = msg_len; i < k; i++) {
        rsa.base_message[i] <== 0;
    }

    rsa.signature <== signature;
    rsa.modulus <== pubkey;

    component splitBy = SplitBy(max_bytes, 46, 2); // 46 is '.'
    splitBy.text <== in_padded;
    signal jwt_header[max_bytes] <== splitBy.out[0];
    signal jwt_payload[max_bytes] <== splitBy.out[1];

    // Base64 decode payload from JWT
    component base64Decode = Base64Decode(max_bytes);
    base64Decode.in <== jwt_payload;
    signal payload[max_bytes] <== base64Decode.out;

    // Extract nonce from payload, "nonce":" ==> 34 110 111 110 99 101 34 58 34 0
    signal nonceStartChars[10];
    nonceStartChars[0] <== 34;
    nonceStartChars[1] <== 110;
    nonceStartChars[2] <== 111;
    nonceStartChars[3] <== 110;
    nonceStartChars[4] <== 99;
    nonceStartChars[5] <== 101;
    nonceStartChars[6] <== 34;
    nonceStartChars[7] <== 58;
    nonceStartChars[8] <== 34;
    nonceStartChars[9] <== 0;

    component extractNonceComp = Extract(max_bytes, 10, 32);
    extractNonceComp.text <== payload;
    extractNonceComp.start_chars <== nonceStartChars;
    extractNonceComp.end_char <== 34; // 34 is "
    extractNonceComp.start_index <== 0;

    signal nonce[32] <== extractNonceComp.extracted_text;
    signal output nonce_value_F <== HashBytesToField(32)(nonce);

    /*
    component kcConcat3Comp = Concat3(1, 12, 3);
    kcConcat3Comp.text1[0] <== 34; // 34 is "
    kcConcat3Comp.text2 <== kc_name;   
    kcConcat3Comp.text3[0] <== 34; // 34 is "
    kcConcat3Comp.text3[1] <== 58; // 34 is :
    kcConcat3Comp.text3[2] <== 34; // 34 is "

    component extractSubComp = Extract(jwt_max_bytes, 16, 32);
    extractSubComp.text <== payload;
    extractSubComp.start_chars <== kcConcat3Comp.out;
    extractSubComp.end_char <== 34; // 34 is "
    extractSubComp.start_index <== 0;

    kc_value <== extractSubComp.extracted_text;
    */
}
