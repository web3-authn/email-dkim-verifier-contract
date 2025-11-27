# DKIM verifier limitations

This document tracks how the on-chain DKIM verifier in `email-dkim-verifier-contract` diverges from RFC 6376 and which fixes are planned, with an eye to keeping gas costs low.

## Current limitations (vs RFC 6376)

- **Algorithms and canonicalization**  
  Only signatures with `a=rsa-sh256` and `c=relaxed/relaxed` are accepted. Other RFC‑allowed combinations (e.g. `rsa-sha1`, `simple/relaxed`) are treated as invalid.

- **Simplified result model**  
  The public API exposes only a boolean result. It does not distinguish RFC 6376’s `SUCCESS` / `PERMFAIL` / `TEMPFAIL` states, which may be acceptable for the current use case but is technically less expressive than the RFC.

## Implemented RFC 6376 improvements

These items from the original TODO list are now implemented and live in `src/parsers.rs` / `src/verify_dkim.rs`.

- **Honor the `l=` body length tag**  
  - The verifier now parses the `l=` tag (when present) from the DKIM-Signature header and, after relaxed body canonicalization, hashes only the first `l` octets when computing and verifying `bh`.  
  - Signatures with `l=` that allow trailing content (e.g. mailing list footers) now verify correctly, as long as the canonicalized body length is at least `l`.

- **Correct header selection order for repeated fields**  
  - When applying the `h=` list, header instances are now selected from the bottom of the header block upward (physically last first), as required by RFC 6376 §5.4.2.  
  - This avoids false negatives when there are multiple instances of a header field (e.g. multiple `Subject`, `From`, or `Received` lines) and the signer intended specific instances to be covered.

- **Robust `b=` zeroing with folding whitespace (FWS)**  
  - The code that constructs the canonicalized DKIM-Signature header (`build_canonicalized_dkim_header_relaxed`) now scans for the `b` tag in a tag-aware way and tolerates optional whitespace and folding around the `=` (e.g. `b = ...`, with line breaks).  
  - It removes exactly the `b=` value (including any FWS) before relaxed header canonicalization, matching RFC 6376’s requirement that the `b` value be treated as empty for hashing.

- **Support for multiple DKIM-Signature headers**  
  - The verifier now collects all `DKIM-Signature` headers on the message and attempts verification for each one, accepting if **any** signature verifies successfully.  
  - This aligns with RFC 6376’s expectations for handling multiple signatures (e.g. original sender plus intermediary or multiple keys in rotation).

- **Tighter DKIM-Signature tag validation**  
  - When present, `v=1` is required; signatures with an unsupported `v` value are skipped.  
  - `d=` (signing domain) and `s=` (selector) are required and must be non-empty.  
  - Only `a=rsa-sha256` and `c=relaxed/relaxed` are currently accepted; others are treated as unsupported and ignored.  
  - `bh`, `b`, and `h` tags must be present and non-empty, and `bh`/`b` values are validated as base64 before use.

- **Tighter DNS key record validation**  
  - For TXT key records, `v=DKIM1` is required when present; records with unknown or unsupported versions are ignored.  
  - When present, `k=` must be compatible (`k=rsa`); records with incompatible `k` are ignored.  
  - Empty `p=` values are treated as explicitly revoked keys and are skipped.  
  - The first usable `p=` that base64-decodes into a valid RSA SPKI key is used for verification.

## Low-gas TODOs

Remaining changes that are technically feasible and should not significantly increase per-call gas usage:

- **Broader algorithm/canonicalization support**  
  - Optionally add support for other RFC-allowed combinations (e.g. `rsa-sha1`, `simple/relaxed`, `relaxed/simple`) if needed for interoperability.  
  - This would be gated behind careful measurement to avoid unnecessary gas costs.

- **Richer result model (optional)**  
  - If future callers need to distinguish PERMFAIL vs TEMPFAIL semantics, expand the verifier API to return a richer enum or status code alongside the boolean.  
  - This is purely an API / semantics change and does not affect on-chain cryptographic behavior.
