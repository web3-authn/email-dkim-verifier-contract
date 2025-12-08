# Email DKIM Verifier Contract

This repo contains a NEAR contract (`email-dkim-verifier-contract`) that uses yield/resume with [OutLayer](https://outlayer.fastnear.com/docs/getting-started) to fetch DKIM DNS TXT records for an email and verify the DKIM signature on‑chain.

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

- Call DKIM verifier with a real Gmail sample:
  ```bash
  just request
  ```

## Outlayer worker key management

The encrypted DKIM flow uses a KEM + AEAD scheme (X25519 + HKDF‑SHA256 + ChaCha20‑Poly1305). Each deployment needs a worker keypair `(sk_worker, pk_worker)`:

- `sk_worker` (private): stored as `OUTLAYER_EMAIL_DKIM_SK` in the Outlayer worker secrets/env.
- `pk_worker` (public): stored in contract state and exposed via `get_outlayer_encryption_public_key`.

### Generate a keypair

From the repo root:

```bash
just gen-keypair
```

This runs `cargo run --bin generate_x25519_keypair` and prints:

```text
OUTLAYER_WORKER_SK_B64=...
OUTLAYER_WORKER_PK_B64=...
```

- Set `OUTLAYER_WORKER_SK_B64` as the worker secret `OUTLAYER_EMAIL_DKIM_SK` (Outlayer dashboard/infra).
- Use `OUTLAYER_WORKER_PK_B64` when initializing or rotating the contract’s public key.

### Rotate keys

There is a helper script to guide rotation:

```bash
scripts/rotate_outlayer_keys.sh
```

What it does:

1. Runs the keygen binary to produce a new X25519 keypair and prints `OUTLAYER_WORKER_SK_B64` / `OUTLAYER_WORKER_PK_B64`.
2. Prompts you to update the Outlayer worker secret `OUTLAYER_EMAIL_DKIM_SK` with `OUTLAYER_WORKER_SK_B64` and restart the worker (this step is still manual, because it depends on your Outlayer deployment).
3. Calls `set_outlayer_encryption_public_key` on the deployed `EmailDkimVerifier` contract using `OUTLAYER_WORKER_PK_B64`, reading `CONTRACT_ID`, `NEAR_NETWORK_ID`, `DEPLOYER_PUBLIC_KEY`, and `DEPLOYER_PRIVATE_KEY` from `.env`.

After rotation:

- The worker decrypts using the new `sk_worker`.
- Relayers fetch the new `pk_worker` via `get_outlayer_encryption_public_key` and encrypt to that key going forward.
