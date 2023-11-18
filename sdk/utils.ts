
import * as CryptoJS from 'crypto';
import {
    assert,
    Uint8ArrayToCharArray,
    int8toBytes,
    mergeUInt8Arrays,
    toCircomBigIntBytes,
    int64toBytes,
} from "./binaryFormat";

type CircuitInput = {
    in_padded: string[];
    pubkey: string[];
    signature: string[];
    in_len_padded_bytes: string;
}

// Puts an end selector, a bunch of 0s, then the length, then fill the rest with 0s.
export function sha256Pad(prehash_prepad_m: Uint8Array, maxShaBytes: number): [Uint8Array, number] {
    let length_bits = prehash_prepad_m.length * 8; // bytes to bits
    let length_in_bytes = int64toBytes(length_bits);
    prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int8toBytes(2 ** 7)); // Add the 1 on the end, length 505
    // while ((prehash_prepad_m.length * 8 + length_in_bytes.length * 8) % 512 !== 0) {
    while ((prehash_prepad_m.length * 8 + length_in_bytes.length * 8) % 512 !== 0) {
         prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int8toBytes(0));
    }
    prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, length_in_bytes);
    assert((prehash_prepad_m.length * 8) % 512 === 0, "Padding did not complete properly!");
    let messageLen = prehash_prepad_m.length;
    while (prehash_prepad_m.length < maxShaBytes) {
         prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int64toBytes(0));
    }
    assert(
        prehash_prepad_m.length === maxShaBytes,
        `Padding to max length did not complete properly! Your padded message is ${prehash_prepad_m.length} long but max is ${maxShaBytes}!`
    );
    return [prehash_prepad_m, messageLen];
}

export function generateCircuitInputs(params: {
    data: Buffer;
    rsaSignature: BigInt;
    rsaPublicKey: BigInt;
    maxDataLength: number;
}): CircuitInput {
    const [dataPadded, dataPaddedLen] = sha256Pad(
        params.data,
        params.maxDataLength
    );

    const circuitInputs : CircuitInput = {
        in_padded: Uint8ArrayToCharArray(dataPadded),
        pubkey: toCircomBigIntBytes(params.rsaPublicKey),
        signature: toCircomBigIntBytes(params.rsaSignature),
        in_len_padded_bytes: dataPaddedLen.toString(),
    };

    return circuitInputs;
}

export function shaHash(str: Uint8Array) {
    return CryptoJS.createHash('sha256').update(str).digest();
}
