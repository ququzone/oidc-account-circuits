import {
	poseidon1,
	poseidon2,
	poseidon3,
	poseidon4,
	poseidon5,
	poseidon6,
	poseidon7,
	poseidon8,
	poseidon9,
	poseidon10,
	poseidon11,
	poseidon12,
	poseidon13,
	poseidon14,
	poseidon15,
	poseidon16,
} from 'poseidon-lite';

const PACK_WIDTH = 248;

const poseidonNumToHashFN = [
	poseidon1,
	poseidon2,
	poseidon3,
	poseidon4,
	poseidon5,
	poseidon6,
	poseidon7,
	poseidon8,
	poseidon9,
	poseidon10,
	poseidon11,
	poseidon12,
	poseidon13,
	poseidon14,
	poseidon15,
	poseidon16,
];

export function poseidonHash(inputs: (number | bigint | string)[]): bigint {
	const hashFN = poseidonNumToHashFN[inputs.length - 1];

	if (hashFN) {
		return hashFN(inputs);
	} else if (inputs.length <= 32) {
		const hash1 = poseidonHash(inputs.slice(0, 16));
		const hash2 = poseidonHash(inputs.slice(16));
		return poseidonHash([hash1, hash2]);
	} else {
		throw new Error(`Yet to implement: Unable to hash a vector of length ${inputs.length}`);
	}
}

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

export function hashASCIIStrToField(str: string, maxSize: number) {
	if (str.length > maxSize) {
		throw new Error(`String ${str} is longer than ${maxSize} chars`);
	}

	// Note: Padding with zeroes is safe because we are only using this function to map human-readable sequence of bytes.
	// So the ASCII values of those characters will never be zero (null character).
	const strPadded = str
		.padEnd(maxSize, String.fromCharCode(0))
		.split('')
		.map((c) => c.charCodeAt(0));

	const chunkSize = PACK_WIDTH / 8;
	const packed = chunkArray(strPadded, chunkSize).map((chunk) => bytesBEToBigInt(chunk));
	return poseidonHash(packed);
}
