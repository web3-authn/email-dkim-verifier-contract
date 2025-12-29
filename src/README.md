# Outlayer WASI Worker

This crate (`src/`) is the Outlayer WASI worker that the
`email-dkim-verifier-contract` calls into. It is built as a
`wasm32-wasip2` binary and run by Outlayer inside a TEE.

The worker:
- Reads a single JSON request from `stdin`.
- Executes one of its supported methods.
- Writes a single JSON response to `stdout`.

See also:
- Contract details: `email-dkim-verifier-contract/README.md`
- DKIM behavior notes: `docs/dkim-verification.md`
- Trust / limitations: `docs/limitations.md`
- TEE key management plan: `docs/tee-secrets.md`

## Request / Response shape

The worker uses the following types (see `src/api.rs`):

- `RequestType`:
  ```jsonc
  {
    "method": "get-dns-records" | "verify-encrypted-email",
    "args": { /* method-specific JSON */ }
  }
  ```

- `ResponseType`:
  ```jsonc
  {
    "method": "<same method name>",
    "response": { /* method-specific JSON result */ }
  }
  ```

Method names are centralized as constants in `src/api.rs`:
- `GET_DNS_RECORDS_METHOD: &str = "get-dns-records"`
- `VERIFY_ENCRYPTED_EMAIL_METHOD: &str = "verify-encrypted-email"`

## Methods

### `get-dns-records`

Used by the **on‑chain (public)** DKIM path. The contract sends the raw
email and the worker only performs the DNS TXT lookup; the contract
recomputes DKIM on‑chain.

Request params (`DnsLookupParams` in `src/api.rs`):
```jsonc
{
  // Either `name` or `email_blob` must be provided
  "email_blob": "full RFC-5322 email as string (optional)",
  "name": "override DNS name (optional)",
  "type": "TXT" // optional, defaults to "TXT"
}
```

Behavior:
- If `name` is provided, it is used directly.
- Else, if `email_blob` is provided, the worker extracts the DKIM
  selector + domain and constructs `"<selector>._domainkey.<domain>"`.
- Uses `wasi-http-client = { version = "0.2.1", features = ["json"] }`
  to call `https://dns.google/resolve?name=<name>&type=TXT`.

Response params (`DnsLookupResult`):
```jsonc
{
  "selector": "optional DKIM selector",
  "domain": "optional DKIM domain",
  "name": "final DNS name queried",
  "type": "TXT",
  "records": ["v=DKIM1; k=rsa; p=..."],
  "error": "optional error string"
}
```

On parse/validation errors, the worker returns:
```jsonc
{
  "method": "get-dns-records",
  "response": {
    "error": "invalid get-dns-records params: ...",
    "records": []
  }
}
```

### `verify-encrypted-email`

Used by the **TEE‑private (encrypted)** DKIM path. The contract sends an
encrypted email envelope; the worker decrypts, verifies DKIM, and returns
only a summarized verification result.

Request params:
```jsonc
{
  "encrypted_email_blob": {
    "version": 1,
    "ephemeral_pub": "<base64 X25519 public key>",
    "nonce": "<base64 ChaCha20-Poly1305 nonce>",
    "ciphertext": "<base64 ciphertext of raw email>"
  },
  "context": {
    // Arbitrary JSON used as AEAD associated data (AAD),
    // typically includes `account_id`, `network_id`, `payer_account_id`.
  },
  "request_id": "optional polling request id (echoed back on errors)"
}
```

The worker:
- Loads `OUTLAYER_EMAIL_DKIM_SK` from the environment (base64 X25519
  static secret) to derive the shared key.
- Decrypts the email using X25519 + HKDF‑SHA256 + ChaCha20‑Poly1305
  (`src/crypto.rs`).
- Extracts the DKIM selector + domain, fetches TXT records, and runs
  DKIM verification with the same logic as the contract
  (`src/verify_dkim.rs`).
- Parses recovery instructions from the decrypted email (account id,
  new public key, timestamp, from address).

Response params (on success):
```jsonc
{
  "verified": true,
  "account_id": "<recovered account id or \"\">",
  "new_public_key": "<ed25519:... or \"\">",
  "from_address": "normalized from address",
  "email_timestamp_ms": 1730000000000,
  "request_id": "123ABC",
  "error": null
}
```

On failure, `verified` is `false` and `error` contains a human‑readable
message; all other fields are empty or `null`.

## Building & Testing locally

From the repo root:

- Run worker tests (encryption + DKIM):
  ```bash
  cargo test
  ```

- Run the worker binary natively (for debugging):
  ```bash
  echo '{"method":"get-dns-records","args":{"email_blob":"..."}}' \
    | cargo run --quiet
  ```

Outlayer builds this crate with:
- Target: `wasm32-wasip2`
- Runtime: WASI Preview 2

See the Outlayer docs for the exact build configuration and deployment:
https://outlayer.fastnear.com/docs/wasi#wasi-preview
