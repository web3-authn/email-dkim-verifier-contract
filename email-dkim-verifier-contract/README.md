# Email DKIM Verifier Contract

A NEAR contract that uses OutLayer to fetch DKIM DNS TXT records for an email and verify the DKIM signature fully on‑chain.

This is a **stateless, global** verifier. Other contracts (e.g. per‑user recovery contracts) call it to check `dkim_valid == true` and then apply their own allow‑list / recovery policies.

## Layout

- Contract crate: `email-dkim-verifier-contract/`
  - Contract entrypoint: `src/lib.rs`
  - DKIM parser + canonicalization: `src/parsers.rs`
  - Real Gmail fixture: `tests/data/gmail_reset_full.eml`
  - DKIM behavior tests: `tests/dkim_verifier_tests.rs`

The OutLayer WASI worker that fetches TXT records lives in the **root crate** (`src/main.rs`) and is built from the same repository.

## Contract Interface

### `request_email_verification`

```rust
/// Payable entrypoint: delegate DKIM TXT fetch + verification to OutLayer.
#[payable]
pub fn request_email_verification(
    &mut self,
    payer_account_id: AccountId,
    email_blob: Option<String>,
    encrypted_email_blob: Option<serde_json::Value>,
    aead_context: Option<AeadContext>,
    request_id: Option<String>,
) -> Promise
```

- `payer_account_id`
  Account that pays for the OutLayer execution (typically the relayer).

- `email_blob`
  Full raw RFC‑5322 email as received by your mail gateway (what your email worker logs as `message.raw`), including:
  - All headers (`DKIM-Signature`, `From`, `To`, `Subject`, `Date`, `Message-ID`, MIME headers, etc.).
  - Full MIME body (plain + HTML parts, boundaries).
  - **Use this field only for the on‑chain DKIM path** (public, plaintext mode).

- `encrypted_email_blob`
  Encrypted email envelope (matching the worker’s `EncryptedEmailEnvelope` type).
  - Contains an X25519 ephemeral public key, nonce, and ChaCha20‑Poly1305 ciphertext.
  - **Use this field only for the TEE‑private DKIM path** (encrypted mode).

- `aead_context`
  Optional typed context forwarded to the OutLayer worker (used as AEAD associated data in encrypted mode):
  - In on‑chain mode, it is ignored (the worker receives an empty context).
  - In encrypted mode, it is serialized to JSON and passed as `context` to the worker, and then used as ChaCha20‑Poly1305 AAD when decrypting.
  - The struct is:
    ```rust
    #[near(serializers = [json, borsh])]
    pub struct AeadContext {
        pub account_id: String,
        pub network_id: String,
        pub payer_account_id: String,
    }
    ```

- `request_id`
  Optional request ID hint used for frontend polling.
  - In on‑chain mode, the contract derives `request_id` from the email Subject when present.
  - In encrypted mode, pass `request_id` so the contract can store a terminal failure result even if the worker cannot decrypt/parse the Subject (e.g. wrong AEAD context / Outlayer execution failure).

- Attached deposit
  - Must attach at least `MIN_DEPOSIT` (currently `0.01 NEAR`):
    ```rust
    assert!(
        attached >= MIN_DEPOSIT,
        "Attach at least 0.01 NEAR for Outlayer execution"
    );
    ```
  - Exactly `MIN_DEPOSIT` is forwarded to OutLayer to fund the execution; any extra deposit attached to `request_email_verification` is immediately refunded back to the caller.

- Return value
  - Returns a `Promise`. The final outcome is the `VerificationResult` returned by one of the private callbacks:
    ```rust
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    pub struct VerificationResult {
        pub verified: bool,
        pub account_id: String,
        pub new_public_key: String,
        pub from_address: String,
        pub email_timestamp_ms: Option<u64>,
        pub request_id: String,
    }

    #[private]
    pub fn on_email_verification_onchain_result(
        &mut self,
        requested_by: AccountId,
        email_blob: String,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> VerificationResult

    #[private]
    pub fn on_email_verification_private_result(
        &mut self,
        requested_by: AccountId,
        request_id: String,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> VerificationResult
    ```
  - On‑chain mode (`email_blob` set, `encrypted_email_blob` unset):
    - OutLayer returns DNS TXT records for the DKIM selector and domain.
    - The contract runs `verify_dkim(email_blob, &records)` on‑chain.
    - `from_address` is parsed from the `From:` header and normalized to a bare email (e.g. `alice@example.com`).
  - Encrypted mode (`encrypted_email_blob` set, `email_blob` unset):
    - OutLayer decrypts the email inside the TEE and runs DKIM verification there.
    - The contract **trusts the worker result** and does not recompute DKIM.
    - `from_address` is provided by the worker, already normalized.
  - In both modes:
    - `verified == true` means DKIM verification passed and the message contained a valid recovery instruction, if present.
    - `verified == false` covers any failure (OutLayer error, DNS error, DKIM mismatch, RSA failure, malformed recovery instruction, etc.).
    - `account_id` / `new_public_key`:
      - When `verified == true` and the email matches the recovery format
        `Subject: recover-<REQUEST_ID> <account_id>` and body line `ed25519:<new_public_key>`, they are populated as:
        - `account_id`: `"user.testnet".to_string()`
        - `new_public_key`: `"ed25519:new_public_keyxxxxxxxxxxxxxxxxxxx".to_string()`
      - When the format does not match, `account_id` / `new_public_key` are empty strings, and callers can treat the result as “DKIM verified, but no usable recovery instruction embedded in the message”.
    - `email_timestamp_ms`:
      - Parsed from the `Date:` header using RFC 2822 parsing and converted to milliseconds since Unix epoch (UTC).
      - `None` if the `Date:` header is missing or can’t be parsed.

### Request IDs and frontend polling

For email‑recovery flows, the contract supports a short‑lived `request_id` embedded in the Subject so the frontend can poll the result without talking to the relayer:

- Subject format with `request_id`:
  - `Subject: recover-<REQUEST_ID> <account_id> ed25519:<public_key>`
  - Example: `recover-123ABC alice.testnet ed25519:HPHNMfHwmBJSqcArYZ5ptTZpukvFoMtuU8TcV2T7mEEy`
- When OutLayer finishes (on‑chain or TEE mode), the contract:
  - Parses `REQUEST_ID` from the Subject if present.
  - Stores the `VerificationResult` in an internal map keyed by `request_id`.
  - Schedules a `clear_verification_result(request_id)` call via yield‑resume so the entry is automatically deleted after ~200 blocks.
- For encrypted mode, passing `request_id` to `request_email_verification(...)` ensures the contract can still write a terminal failure result for polling even if Outlayer fails before the worker returns a parsed `request_id`.
- Frontend API:
  - Call `get_verification_result(request_id: String) -> Option<VerificationResult>`.
  - Interpret the response as:
    - `None` → pending, expired, or already cleared.
    - `Some(VerificationResult { verified: true, .. })` → DKIM passed and recovery instruction parsed.
    - `Some(VerificationResult { verified: false, .. })` → DKIM or recovery parsing failed.

Typical usage from another contract:

1. For **on‑chain DKIM** (public, plaintext):
   - Call `request_email_verification` with `email_blob = Some(raw_email)` and `encrypted_email_blob = None`.
2. For **TEE‑private DKIM** (encrypted):
   - Call `request_email_verification` with `email_blob = None` and `encrypted_email_blob = Some(encrypted_email_json)`.
3. In your own callback, inspect `VerificationResult` and, if `verified == true`, apply your recovery / allow‑list logic (e.g. `add_key(new_public_key)`).

### How to construct `email_blob`

When you call `request_email_verification`, `email_blob` must be the **exact raw message** as seen on the wire:

- Include all headers, including the `DKIM-Signature:` header that you want to verify.
- Preserve original line endings and folding: headers and body separated by a blank line (`\r\n\r\n`), and any folded headers kept as-is.
- Include the full MIME body (plain text, HTML, attachments, boundaries, etc.), not just the human-visible part.

Typical sources for `email_blob`:

- An SMTP ingress or mail worker that logs the full RFC‑5322 message as a string (`message.raw` or equivalent).
- A mail API that exposes the “raw” or “RFC‑822 / RFC‑5322” form of a message; decode any transport/base64 encoding and pass the resulting bytes as UTF‑8.

From your contract, you simply forward that string:

```rust
let promise = email_dkim_verifier_contract::ext(VERIFIER_CONTRACT_ID.parse().unwrap())
    .with_attached_deposit(MIN_DEPOSIT.into())
    .request_email_verification(
        payer_account_id,
        Some(email_blob),
        None,
        None,
    );
```

## Building & Testing

From the repo root:

```bash
cd email-dkim-verifier-contract

# Run DKIM unit + integration tests
cargo test --features unit-testing

# (Optional) build WASM locally
cargo near build non-reproducible-wasm
```

The cargo‑near build outputs:

- Contract WASM: `email-dkim-verifier-contract/target/near/email_dkim_verifier_contract.wasm`
- ABI JSON: `email-dkim-verifier-contract/target/near/email_dkim_verifier_contract_abi.json`

## Deploying & Upgrading

Deployment is driven from the **repo root** using the scripts in `scripts/` and the `justfile`.

1. Configure environment:

   ```bash
   cp env.example .env
   # edit .env to set CONTRACT_ID, NEAR_NETWORK_ID, keys, etc.
   ```

2. Use the helper recipes (these call `scripts/deploy*.sh` / `scripts/upgrade*.sh` under the hood):

   ```bash
   # From repo root

   # Development deploy / upgrade (testnet, non-reproducible WASM)
   just deploy-dev
   just upgrade-dev

   # Production deploy / upgrade (reproducible WASM)
   just deploy
   just upgrade
   ```

You normally shouldn’t call `near contract deploy` manually; the scripts handle
`cargo near` builds, ABI generation, and signing based on `.env`.

## Manual DKIM Verification Call (for debugging)

There is a convenience script to exercise the full OutLayer → DNS TXT → DKIM verification path with a real Gmail email:

```bash
# From repo root, after deploying the contract and setting .env
just request
```

`scripts/request_email_verification.sh`:

- Loads `email-dkim-verifier-contract/tests/data/gmail_reset_full.eml` as `email_blob`.
- Calls `request_email_verification(payer_account_id, email_blob=Some(...), encrypted_email_blob=None, aead_context=None, request_id=None)` on `$CONTRACT_ID`.
- Attaches enough gas and deposit for OutLayer execution.
