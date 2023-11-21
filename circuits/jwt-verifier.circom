pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

include "./helpers/string.circom";
include "./helpers/sha.circom";
include "./helpers/rsa.circom";
include "./helpers/base64.circom";
include "./helpers/hasher.circom";

template JwtVerifier(max_bytes, max_iss_len, max_aud_len, max_sub_len, n, k) {
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

    component extractNonceComp = Extract(max_bytes, 10, 42);
    extractNonceComp.text <== payload;
    extractNonceComp.start_chars <== nonceStartChars;
    extractNonceComp.end_char <== 34; // 34 is "
    extractNonceComp.start_index <== 0;
    signal nonce[42] <== extractNonceComp.extracted_text;
    signal nonce_value_F <== HashBytesToField(42)(nonce);

    signal input nonce_hash;
    nonce_hash === nonce_value_F;

    // Extract iss from payload, "iss":" ==> 34 105 115 115 34 58 34 0
    signal issStartChars[8];
    issStartChars[0] <== 34;
    issStartChars[1] <== 105;
    issStartChars[2] <== 115;
    issStartChars[3] <== 115;
    issStartChars[4] <== 34;
    issStartChars[5] <== 58;
    issStartChars[6] <== 34;
    issStartChars[7] <== 0;

    component extractIssComp = Extract(max_bytes, 8, max_iss_len);
    extractIssComp.text <== payload;
    extractIssComp.start_chars <== issStartChars;
    extractIssComp.end_char <== 34; // 34 is "
    extractIssComp.start_index <== 0;
    signal iss[max_iss_len] <== extractIssComp.extracted_text;
    signal iss_value_F <== HashBytesToField(max_iss_len)(iss);

    // Extract aud from payload, "aud":" ==> 34 97 117 100 34 58 34 0
    signal audStartChars[8];
    audStartChars[0] <== 34;
    audStartChars[1] <== 97;
    audStartChars[2] <== 117;
    audStartChars[3] <== 100;
    audStartChars[4] <== 34;
    audStartChars[5] <== 58;
    audStartChars[6] <== 34;
    audStartChars[7] <== 0;

    component extractAudComp = Extract(max_bytes, 8, max_aud_len);
    extractAudComp.text <== payload;
    extractAudComp.start_chars <== audStartChars;
    extractAudComp.end_char <== 34; // 34 is "
    extractAudComp.start_index <== 0;
    signal aud[max_aud_len] <== extractAudComp.extracted_text;
    signal aud_value_F <== HashBytesToField(max_aud_len)(aud);

    // Extract sub from payload, "sub":" ==> 34 115 117 98 34 58 34 0
    signal subStartChars[8];
    subStartChars[0] <== 34;
    subStartChars[1] <== 115;
    subStartChars[2] <== 117;
    subStartChars[3] <== 98;
    subStartChars[4] <== 34;
    subStartChars[5] <== 58;
    subStartChars[6] <== 34;
    subStartChars[7] <== 0;

    component extractSubComp = Extract(max_bytes, 8, max_sub_len);
    extractSubComp.text <== payload;
    extractSubComp.start_chars <== subStartChars;
    extractSubComp.end_char <== 34; // 34 is "
    extractSubComp.start_index <== 0;
    signal sub[max_sub_len] <== extractSubComp.extracted_text;
    signal sub_value_F <== HashBytesToField(max_sub_len)(sub);

    signal address_hash_F <== Hasher(3)([
        iss_value_F,
        aud_value_F,
        sub_value_F
    ]);
    signal input address_hash;
    address_hash === address_hash_F;
}
