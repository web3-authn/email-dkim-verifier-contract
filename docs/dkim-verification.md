# DKIM Verification Logic Analysis

## Overview

Both files implement **identical DKIM verification logic**.
1. `email-dkim-verifier-contract/src/verify_dkim.rs` (Onchain Contract Version)
2. `src/verify_dkim.rs` (Outlayer Wasm Worker Version)

There are no semantic differences in how they process emails, handle cryptographic operations, or validate signatures.

## Verification Logic

This is the verification process used by both implementations:

1.  **Parsing**: The email is split into headers and body.
2.  **Signature Discovery**: Iterates through all `DKIM-Signature` headers.
3.  **Tag Validation**:
    *   `v`: Must be "1".
    *   `a`: Must be "rsa-sha256".
    *   `c`: Must be "relaxed/relaxed" (defaults to simple if missing, but code enforces relaxed).
    *   `d`, `s`: Domain and selector must be present.
4.  **Base64 Decoding**: Cleans and decodes the body hash (`bh`) and signature (`b`).
5.  **Body Hash Verification**:
    *   Canonicalizes body using `relaxed` simple.
    *   Respects the length tag (`l`) if present.
    *   Computes SHA-256 hash and compares with `bh`.
6.  **Signature Verification**:
    *   Canonicalizes headers using `relaxed`.
    *   Computes SHA-256 hash of the canonicalized headers + canonicalized DKIM header.
    *    fetches DNS records for `s._domainkey.d`.
    *   Parses DNS records for RSA public key (`v=DKIM1`, `k=rsa`, `p=...`).
    *   Verifies the RSA signature against the computed hash.
