import { poseidonHash } from "./poseidon";

const MAX_KEY_CLAIM_NAME_LENGTH = 32;
const MAX_KEY_CLAIM_VALUE_LENGTH = 115;
const MAX_AUD_VALUE_LENGTH = 145;
const PACK_WIDTH = 248;

export function chunkArray<T>(array: T[], chunk_size: number): T[][] {
	const chunks = Array(Math.ceil(array.length / chunk_size));
	const revArray = array.reverse();
	for (let i = 0; i < chunks.length; i++) {
		chunks[i] = revArray.slice(i * chunk_size, (i + 1) * chunk_size).reverse();
	}
	return chunks.reverse();
}

function bytesBEToBigInt(bytes: number[]): bigint {
	const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
	if (hex.length === 0) {
		return BigInt(0);
	}
	return BigInt('0x' + hex);
}

export function toPaddedASCIIStr(str: string, maxSize: number): number[] {
	if (str.length > maxSize) {
		throw new Error(`String ${str} is longer than ${maxSize} chars`);
	}

	// Note: Padding with zeroes is safe because we are only using this function to map human-readable sequence of bytes.
	// So the ASCII values of those characters will never be zero (null character).
	return str
		.padEnd(maxSize, String.fromCharCode(0))
		.split('')
		.map((c) => c.charCodeAt(0));
}

// hashes an ASCII string to a field element
export function hashASCIIStrToField(str: string, maxSize: number) {
    const chunkSize = PACK_WIDTH / 8;
	const packed = chunkArray(toPaddedASCIIStr(str, maxSize), chunkSize).map((chunk) => bytesBEToBigInt(chunk));
	return poseidonHash(packed);
}

const b64DecodeUnicode = (str: string) => {
    return decodeURIComponent(atob(str).replace(/(.)/g, (m, p) => {
        let code = p.charCodeAt(0).toString(16).toUpperCase();
        if (code.length < 2) {
            code = "0" + code;
        }
        return "%" + code;
    }));
}

export const base64UrlDecode = (str: string) => {
    let output = str.replace(/-/g, "+").replace(/_/g, "/");
    switch (output.length % 4) {
        case 0:
            break;
        case 2:
            output += "==";
            break;
        case 3:
            output += "=";
            break;
        default:
            throw new Error("base64 string is not of the correct length");
    }
    try {
        return b64DecodeUnicode(output);
    } catch (err) {
        return atob(output);
    }
  }

export function bigIntToArray(n: number, k: number, x: bigint) {
    let mod: bigint = 1n;
    for (var idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    let ret: bigint[] = [];
    var x_temp: bigint = x;
    for (var idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}
