# DKIM verifier limitations

This document summarizes how the DKIM verifier diverges from RFC 6376 and the trade‑offs of the new privacy‑preserving TEE flow.

## Trust Models

With the unified `request_email_verification` API, there are two modes:

1. **On‑chain (public)**
   - Plaintext `email_blob` is sent.
   - Worker returns DKIM TXT records (`get-dns-records`); the contract recomputes DKIM on‑chain.
   - Fully auditable by any NEAR node, but the email is public.

2. **TEE‑private (encrypted)**
   - Only an encrypted envelope is sent.
   - Outlayer worker (TEE) decrypts and verifies DKIM, then returns a summarized result.
   - The chain never sees the plaintext; you trust the Outlayer TEE + worker code instead of on‑chain re‑execution.

## Current limitations (vs RFC 6376)

These limitations apply primarily to the Rust implementation (both on-chain and in the worker).

- **Algorithms and canonicalization**
  - Only `a=rsa-sha256` and `c=relaxed/relaxed` are supported.
  - Other legal combinations (`rsa-sha1`, Ed25519, `simple/relaxed`, etc.) are treated as invalid.

- **Simplified result model**
  - The API exposes a boolean `verified` and does not distinguish RFC 6376’s `SUCCESS` / `PERMFAIL` / `TEMPFAIL`.

- **Single Key Crypto**
  - Only RSA keys (`k=rsa`) are supported for DKIM signatures; Ed25519 DKIM is not yet implemented.

## Implemented RFC 6376 improvements

Implemented in `email-dkim-verifier-contract/src/parsers.rs` and `src/verify_dkim.rs`:

- **Honor the `l=` body length tag**
  - Parses `l=` and hashes only the first `l` octets, allowing benign footers without breaking signatures.

- **Correct header selection order**
  - Selects header instances from the bottom up as required by RFC 6376 §5.4.2.

- **Robust `b=` zeroing with FWS**
  - Correctly removes the `b=` value even with folding whitespace before applying relaxed canonicalization.

- **Support for multiple signatures**
  - Iterates over all `DKIM-Signature` headers and accepts if any one verifies.

- **Tight Validation**
  - Enforces `v=1`, `d=`, `s=`, and base64 correctness for signature tags.
  - Enforces `v=DKIM1` and `k=rsa` (if present) for DNS records; treats empty `p=` as revoked.

## Planned improvements

- **Ed25519 Support**
  - Support `k=ed25519` keys and `a=ed25519-sha256` signatures once on-chain dependencies / precompiles make it practical.
