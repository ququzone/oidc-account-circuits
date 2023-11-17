pragma circom 2.0.0;

include "helpers/sha256.circom";
include "helpers/misc.circom";
include "helpers/strings.circom";
include "helpers/hasher.circom";
include "helpers/rsa/rsa.circom";

/**
  Construction params:
    - maxHeaderLen:             Maximum length of the JWT header (in bytes)
    - maxPaddedUnsignedJWTLen:  Maximum length of the padded unsigned JWT. Must be a multiple of 64.
    - maxKCNameLen:             Maximum length of the key_claim_name (in bytes)
    - maxKCValueLen:            Maximum length of the key_claim_value (in bytes)
    - maxAudValueLen:           Maximum length of aud (in bytes)
    - maxWhiteSpaceLen:         The number of JSON whitespaces that we can tolerate in an extended claim
    - maxExtIssLength:          Maximum length the extended iss claim (in ASCII bytes)
 */
template OIDC(maxHeaderLen, maxPaddedUnsignedJWTLen,
        maxKCNameLen, maxKCValueLen, maxExtKCLen,
        maxAudValueLen, maxWhiteSpaceLen, maxExtIssLength) {
    var inWidth = 8; // input is in bytes
    var inCount = maxPaddedUnsignedJWTLen;

    // 1. Parse out the JWT header
    signal input padded_unsigned_jwt[inCount];
    signal input payload_start_index;

    // Extract the header
    var header_length = payload_start_index - 1;
    signal header[maxHeaderLen] <== SliceFromStart(inCount, maxHeaderLen)(
        padded_unsigned_jwt, header_length
    );
    signal header_F <== HashBytesToField(maxHeaderLen)(header);

    // Check that there is a dot after header
    var x = SingleMultiplexer(inCount)(padded_unsigned_jwt, header_length);
    x === 46;

    // SHA2 operations over padded_unsigned_jwt
    //    - Compute SHA2(padded_unsigned_jwt)
    signal input num_sha2_blocks;
    // signal input payload_len;

    var hashCount = 4;
    var hashWidth = 256 / hashCount;
    signal jwt_sha2_hash[hashCount] <== Sha2_wrapper(inWidth, inCount, hashWidth, hashCount)(
        padded_unsigned_jwt, num_sha2_blocks
    );

    // check signature
    signal input signature[32]; // The JWT signature  
    signal input modulus[32];
    var jwt_sha2_hash_le[4]; // converting to little endian
    for (var i = 0; i < 4; i++) {
        jwt_sha2_hash_le[i] = jwt_sha2_hash[3 - i];
    }
    RSAVerify65537()(signature, modulus, jwt_sha2_hash_le);

    // HashToField for revealing modulus
    var modulus_be[32]; // converting to big endian
    for (var i = 0; i < 32; i++) {
        modulus_be[i] = modulus[31 - i];
    }
    signal modulus_F <== HashToField(64, 32)(modulus_be);
}

component main = OIDC(248, 64 * 25, 32, 115, 126, 145, 6, 165);
