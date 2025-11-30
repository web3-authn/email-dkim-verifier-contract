# Outlayer‑side DKIM Verification with Encrypted Emails

This document proposes moving DKIM verification into the Outlayer worker and only sending **encrypted** email blobs on‑chain, to improve privacy for users and recovered accounts.

## High‑Level Architecture

- Outlayer worker is configured with a **decryption key** stored as a secret (`secrets` API), e.g.:
  - A symmetric AEAD key, or X25519 private key for hybrid public‑key encryption.
- The relayer obtains the corresponding **public key** (hard‑coded or from config) and:
  - Encrypts the raw email into `encrypted_email_blob` (plus `nonce` / `salt` / associated data).
- `EmailRecoverer` and `EmailDKIMVerifier` are updated to:
  - Accept `encrypted_email_blob` instead of raw `email_blob`, and
  - Forward the ciphertext to Outlayer as input data.
- Inside the Outlayer worker:
  - It reads the decryption key from its secret environment.
  - Decrypts `encrypted_email_blob` and recovers the raw email.
  - Performs full DKIM verification and parsing (equivalent to the current Rust contract logic).
  - Returns a small JSON result back to NEAR:
    - `verified: bool`
    - `account_id: String`
    - `new_public_key: String`
    - `email_timestamp_ms: Option<u64>`
- The NEAR contract becomes a thin adapter:
  - It no longer re‑verifies DKIM, because it never sees the plaintext email.
  - It only checks the Outlayer result and enforces any additional contract‑level rules.

## Trade‑offs

- **On‑chain transparency vs. email privacy**
  - Today, the email contents are part of public arguments; anyone can read the full message and correlate accounts.
  - With ciphertext:
    - The chain only sees encrypted data and the derived recovery outputs.
    - Explorers and indexers can still show `verified`, `account_id`, `new_public_key`, and timestamp, but not the email text.
  - This improves user privacy at the cost of less on‑chain verifiability of the DKIM computation.
  - Alternatively, you get best of both worls with ZK-email

- **Trust assumptions**
  - **Current model**:
    - Outlayer is used only as a DNS/TXT fetcher and resource meter.
    - The NEAR contract re‑computes DKIM verification deterministically and is fully auditable.
  - **Proposed model**:
    - Outlayer + the WASI worker become the **source of truth** for DKIM verification.
    - NEAR nodes cannot recompute DKIM because they don’t see the plaintext.
    - You must trust:
      - The Outlayer code and runtime to protect the decryption key.
      - The DKIM verification code running in the worker to be correct and unmodified (modulo whatever attestation or reproducible‑build guarantees you set up).

- **Key management & rotation**
  - The decryption key lives only in Outlayer secrets; it is never stored on NEAR.
  - Need:
    - A process for generating and rotating the keypair.
    - A way for relayers to learn the current public key (e.g. config, well‑known JSON, or hard‑code per deployment).
  - Old ciphertexts become undecryptable if you rotate keys without a compatibility plan.



