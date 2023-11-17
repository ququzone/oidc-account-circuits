async function main() {
    const jwk = {
        "alg": "RS256",
        "n": "4VCFlBofjCVMvApNQ97Y-473vGov--idNmGQioUg0PXJv0oRaAClXWINwNaMuLIegChkWNNpbvsrdJpapSNHra_cdAoSrhd_tLNWDtBGm6tsVZM8vciggnJHuJwMtGwZUiUjHeYWebaJrZmWh1WemYluQgyxgDAY_Rf7OdIthAlwsAzvmObuByoykU-74MyMJVal7QzATaEh0je7BqoDEafG750UrMwzSnACjlZvnmrCHR4KseT4Tv4Fa0rCc_wpRP-Uuplri_EbMSr15OXoGTDub6UM8_0LIjNL0yRqh5JpesbOtxW_OU1bMeSUOJeAZzAA4-vq_l-jrDlelHxZxw==",
        "e": "AQAB",
        "kty": "RSA",
        "use": "sig",
        "kid": "5b3706960e3e60024a2655e78cfa63f87c97d309"
    };

    const jwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjViMzcwNjk2MGUzZTYwMDI0YTI2NTVlNzhjZmE2M2Y4N2M5N2QzMDkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3MzU2MDQwOTAwMC1idWtqZHFndTBhbjlqcmhhc3RndWNzcG9odGpkMGVoZC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjczNTYwNDA5MDAwLWJ1a2pkcWd1MGFuOWpyaGFzdGd1Y3Nwb2h0amQwZWhkLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTAxMDYzMzg1NTEzODkxOTA0MTk2Iiwibm9uY2UiOiIxIiwibmJmIjoxNzAwMTM1MzI0LCJpYXQiOjE3MDAxMzU2MjQsImV4cCI6MTcwMDEzOTIyNCwianRpIjoiZmY2MzFkOTg2MGE5MzgxOTZkODhlYjdjYTllMzdhYzlmNTQ2YjgzNiJ9.FRLc69f7w5F7q_TloMXryp_klunYKbm-GXytPOpFB6EpqM4Fne4bFqMmVF3Jv3ns1I45R50oevWd8UcT5AbUgZ1HU_PVqqHJFVWnCPNmCPAox_ECBTvexV1rc19PtctKnEwhfQAjPS_COV6XqUEKP7OitBvWykJ6-W1Op2AOMJgqBcGq5z9adnAWAos-FXQ89pOc1xX5i6WB65ZangXGmU5viqB07swwnAwv_HujlzSBv78UV0EZ5BP-u1EmGV_9_lyfp21UMYmtO6h8b5ay-SBYyuk9NWXTA25382tZEWFCweDLlF1C_dIOu2BvE4T7SksZsX7UH-O5foEeCV90QQ';
    const jwtInput = jwt.split('.').slice(0,2).join('.');
    const jwtSignature = jwt.split('.')[2];

    const signature = BigInt("0x" + Buffer.from(jwtSignature, "base64").toString('hex'));
    const modulus = BigInt("0x" + Buffer.from(jwk.n, "base64").toString('hex'));
}

main()
