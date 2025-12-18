# Email DKIM Verifier Contract

This repo contains a NEAR contract (`email-dkim-verifier-contract`) that uses yield/resume with [OutLayer](https://outlayer.fastnear.com/docs/getting-started) to run a WASI worker in a TEE. The worker fetches DKIM DNS TXT records **and verifies the DKIM signature inside the worker**, returning a summarized `VerificationResult` back on‑chain.

Used for email-based account recovery for tatchi.xyz accounts; other contracts call this one as a stateless global verifier.

## Quick usage

- Run DKIM tests:
  ```bash
  cd email-dkim-verifier-contract
  cargo test --features unit-testing
  # or
  just test
  ```

- Configure environment:
  ```bash
  cp env.example .env
  # edit .env to set CONTRACT_ID, NEAR_NETWORK_ID, keys, etc.
  ```

- Deploy / upgrade contract from repo root:
  ```bash
  # dev (testnet, non-reproducible WASM)
  just deploy-dev
  just upgrade-dev

  # prod (reproducible WASM)
  just deploy
  just upgrade
  ```

## Outlayer worker key management

The encrypted DKIM flow uses a KEM + AEAD scheme (X25519 + HKDF‑SHA256 + ChaCha20‑Poly1305). The worker derives a static X25519 keypair `(sk_worker, pk_worker)` from a protected seed:

- `PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32` (private, protected): 64‑char hex string (32 bytes) stored as an Outlayer **protected** secret (“Hex 32 bytes (64 chars)”).
- `sk_worker` / `pk_worker`: derived inside the worker via HKDF‑SHA256 (info = `"outlayer-email-dkim-x25519"`). The private key never leaves the TEE.
- `pk_worker` is stored in contract state and exposed via `get_outlayer_encryption_public_key`.

For local testing (outside Outlayer), the worker also accepts `OUTLAYER_WORKER_SK_SEED_HEX32` with the same 64‑char hex seed.

### Create / rotate the protected secret + refresh contract public key

1. In the Outlayer [Secrets Management](https://outlayer.fastnear.com/secrets) page, create a protected secret `PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32` with type **"Hex 32 bytes (64 chars)"**. Outlayer will generate the value for you.
  - leave `Branch` empty
  - set `profile` to `main` (or whatever is set in `lib.rs`: `SECRETS_PROFILE = "main"`)
2. Restart/redeploy the worker so it picks up the updated secret.
3. Refresh the contract’s stored public key (owner‑only; triggers worker `get-public-key`):
   ```bash
   just set-outlayer-keys
   # or: sh ./scripts/set_outlayer_keys.sh
   ```

After rotation:

- The worker decrypts using the new `sk_worker`.
- Relayers fetch the new `pk_worker` via `get_outlayer_encryption_public_key` and encrypt to that key going forward.
