import chai from "chai";
import path from "path";
import { generateCircuitInputs, padString, shaHash } from "../sdk/utils";
import { hashASCIIStrToField } from "../sdk/poseidon";
const wasm_tester = require("circom_tester").wasm;
const getCurveFromName = require("ffjavascript").getCurveFromName;

const assert = chai.assert;

describe("OIDC Circuit test", function () {
    let F;
    let circuit;

    const jwk = {
        "alg": "RS256",
        "n": "4VCFlBofjCVMvApNQ97Y-473vGov--idNmGQioUg0PXJv0oRaAClXWINwNaMuLIegChkWNNpbvsrdJpapSNHra_cdAoSrhd_tLNWDtBGm6tsVZM8vciggnJHuJwMtGwZUiUjHeYWebaJrZmWh1WemYluQgyxgDAY_Rf7OdIthAlwsAzvmObuByoykU-74MyMJVal7QzATaEh0je7BqoDEafG750UrMwzSnACjlZvnmrCHR4KseT4Tv4Fa0rCc_wpRP-Uuplri_EbMSr15OXoGTDub6UM8_0LIjNL0yRqh5JpesbOtxW_OU1bMeSUOJeAZzAA4-vq_l-jrDlelHxZxw==",
        "e": "AQAB",
        "kty": "RSA",
        "use": "sig",
        "kid": "5b3706960e3e60024a2655e78cfa63f87c97d309"
    };
    const jwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjViMzcwNjk2MGUzZTYwMDI0YTI2NTVlNzhjZmE2M2Y4N2M5N2QzMDkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3MzU2MDQwOTAwMC1idWtqZHFndTBhbjlqcmhhc3RndWNzcG9odGpkMGVoZC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjczNTYwNDA5MDAwLWJ1a2pkcWd1MGFuOWpyaGFzdGd1Y3Nwb2h0amQwZWhkLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTAxMDYzMzg1NTEzODkxOTA0MTk2Iiwibm9uY2UiOiIxIiwibmJmIjoxNzAwMTk4NTU4LCJpYXQiOjE3MDAxOTg4NTgsImV4cCI6MTcwMDIwMjQ1OCwianRpIjoiNjYyMGVhOTlkNjhmYzdlYTYxNjRlN2M1YzNkNmFiNDg2ZWRkZWFmZiJ9.BiDxqDHbzpf4w9c9AtFgaEJEb-732cw46DSvHQInv37uHvEYyQFPCVsJpn6PzgFmYvSKQKE_fGkH_jQzaqDhL9R-de--4TqkBSpD7bWfD0xX9hkCvDLpu8-g06KuXRj6cN2w9UnqOmz6vRuGwA_2FQCkmkfegOE9AjUCErRp2Dp-_rHzD3KDUTlo4YI4XGi5eDpaCOJnhURW1NB4_eVKpbIrkzOalvE1IZbjRJ-52Bslz4_kbvyxtlUgUk9AdHYe7sZSb_FZipj1yOfljChwxHmFUSoKv6HDafG-d10Wrpk7l56oxFerCBSuGa-41A2pShH42EelJpUN9MLKAzPEZA';
    const jwtInput = jwt.split('.').slice(0,2).join('.');
    const jwtSignature = jwt.split('.')[2];

    this.timeout(1000000);

    before( async () => {
        const bn128 = await getCurveFromName("bn128", true);
        F = bn128.Fr;
        circuit = await wasm_tester(path.join(__dirname, "../circuits", "oidc.circom"));
    });

    it("Should check constrain", async () => {
        const signature = BigInt("0x" + Buffer.from(jwtSignature, "base64").toString('hex'));
        const publicKey = BigInt("0x" + Buffer.from(jwk.n, "base64").toString('hex'));

        const input = generateCircuitInputs({
            data: jwtInput,
            rsaSignature: signature,
            rsaPublicKey: publicKey,
            maxDataLength: 640
        });
        
        const witness = await circuit.calculateWitness(input, true);
        await circuit.checkConstraints(witness);

        const header_F = hashASCIIStrToField('1', 32);

        await circuit.assertOut(witness, {
            nonce_value_F: header_F,
        });
    });
});
