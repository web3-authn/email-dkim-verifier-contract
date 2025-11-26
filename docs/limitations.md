# DKIM verifier limitations

This document tracks how the on-chain DKIM verifier in `email-dkim-verifier-contract` diverges from RFC 6376 and which fixes are planned, with an eye to keeping gas costs low.

## Current limitations (vs RFC 6376)

- **Algorithms and canonicalization**  
  Only signatures with `a=rsa-sh256` and `c=relaxed/relaxed` are accepted. Other RFC‑allowed combinations (e.g. `rsa-sha1`, `simple/relaxed`) are treated as invalid.

- **`l=` body length tag is ignored**  
  The verifier always hashes the full canonicalized body and compares it to `bh`, regardless of any `l=` tag. RFC 6376 requires hashing only the first `l` octets of the canonicalized body.

- **Multiple instances of a header field**  
  When applying the `h=` list, headers are picked from the top of the header block downward. RFC 6376 requires selecting multiple instances from the bottom up (physically last first), which can matter when a field (e.g. `Received`) appears multiple times.

- **Multiple DKIM-Signature headers**  
  Only the first `DKIM-Signature` header field is parsed and verified. RFC 6376 allows multiple signatures and expects verifiers to try each until one verifies (or all fail).

- **`b=` handling is fragile with folding whitespace**  
  To zero out `b=` before hashing, the code looks for a literal `b` immediately followed by `=`. Signatures that use valid folding whitespace around `=` (e.g. `b = ...`, `b\t= ...`) may not be handled correctly.

- **Limited DKIM-Signature tag validation**  
  The verifier enforces only a subset of required DKIM-Signature tags (`a`, `c`, `bh`, `b`, `h`) and does not currently reject unsupported `v=` values or missing `d=` / `s=` tags.

- **Limited DNS key record validation**  
  From TXT records it picks the first decodable `p=` value and treats it as a DER-encoded SPKI key. It ignores other key-record tags (`v`, `k`, `h`, `t`) and does not explicitly treat empty `p=` as a revoked key.

- **Simplified result model**  
  The public API exposes only a boolean result. It does not distinguish RFC 6376’s `SUCCESS` / `PERMFAIL` / `TEMPFAIL` states, which may be acceptable for the current use case but is technically less expressive than the RFC.

## Low-gas TODOs

These are changes that are both technically feasible and should not significantly increase per-call gas usage.

- **Honor the `l=` body length tag**  
  - Parse `l=` from the DKIM-Signature header (when present).  
  - After relaxed body canonicalization, hash only the first `l` octets when computing `bh`/verifying `bh`.  
  - Reject signatures where `l` exceeds the canonicalized body length or does not match `bh`.

- **Fix header selection order for repeated fields**  
  - When applying the `h=` list, select header instances from the bottom of the header block upward, as required by RFC 6376 5.4.2.  
  - Keep the implementation simple (e.g. pre-index header positions by name) to avoid extra passes over the data.

- **Make `b=` zeroing robust to folding whitespace**  
  - Replace the current state machine with a tag-aware scan that tolerates optional WSP around `=` (e.g. `b =`, `b\t =`).  
  - Ensure we remove exactly the `b=` value (including any FWS) before relaxed header canonicalization.

- **Tighten DKIM-Signature tag validation**  
  - Require `v=1` when present and reject unsupported versions.  
  - Enforce presence and non-emptiness of `d=` and `s=` tags.  
  - Treat malformed or out-of-range tag values as a permanent verification failure.

- **Tighten DNS key record validation (low overhead)**  
  - Require `v=DKIM1` on key records and ignore records with unknown/unsupported versions.  
  - Treat empty `p=` values as explicitly revoked keys.  
  - Optionally enforce `k=rsa` when present, ignoring keys with incompatible `k`.

- **Support a bounded number of DKIM-Signature headers**  
  - Iterate over up to a small fixed number of `DKIM-Signature` headers (e.g. 2–3) and accept if any one verifies.  
  - This keeps gas usage bounded while aligning better with RFC 6376’s expectations around multiple signatures.
