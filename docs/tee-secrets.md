# TEE Secrets & Worker Key Reference

This repo uses Outlayer’s **protected secrets** as the root of trust for the DKIM worker’s X25519 encryption keypair. The private key never leaves the TEE; the contract only needs the corresponding public key.

## Secret model

- Protected secret in Outlayer:
  - Accessible only inside the worker via `std::env::var("PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32")`.
  - Intended as a derivation seed, not used directly.

- Key derivation (inside worker):
  - `seed = hex_decode(PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32)` (32 bytes from a 64‑char hex string)
  - `sk = HKDF-SHA256(seed, info = "outlayer-email-dkim-x25519")[0..32]`
  - `pk = X25519PublicKey::from(sk)`
  - `sk` is used for DKIM email decryption; `pk` is the public encryption key the contract exposes.


## Worker responsibilities

- Derive static X25519 keypair from the protected seed on startup or per call.
- Exposes a simple API method:
  - `method: "get-public-key"`
  - Response:
    ```json
    {
      "method": "get-public-key",
      "params": { "public_key": "<base64 x25519 pk>" }
    }
    ```


## Contract integration

The contract stores the worker’s public encryption key:

- State:
  - `EmailDkimVerifier { outlayer_encryption_public_key: String, ... }`
- Methods:
  - `get_outlayer_encryption_public_key() -> String`
  - `set_outlayer_encryption_public_key()` (owner‑only, triggers worker fetch)

Typical flow:

1. Off‑chain script calls the worker’s `get-public-key`.
2. Script calls `set_outlayer_encryption_public_key()` on the contract.
3. Relayers read `get_outlayer_encryption_public_key()` and encrypt new emails to that key.

This keeps the contract simple and avoids on‑chain key derivation.


## Key rotation

To rotate the worker keypair:

1. **Rotate the protected seed in Outlayer**
   - Use Outlayer’s UI/CLI to rotate `PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32`.
   - Restart the worker so it picks up the new seed and derives a new X25519 keypair.

2. **Refresh the contract’s public key**
   - Call worker `get-public-key` again to fetch the new `public_key`.
   - Call `set_outlayer_encryption_public_key()` on the contract (requires 0.01 NEAR for callback).

This setup gives you a TEE‑protected root secret, a derived X25519 worker key, and a clear, minimal contract surface for publishing the worker’s public key.
