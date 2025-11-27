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
    email_blob: String,
    params: Option<serde_json::Value>,
) -> Promise
```

- `email_blob`  
  Full raw RFC‑5322 email as received by your mail gateway (what your email worker logs as `message.raw`), including:
  - All headers (`DKIM-Signature`, `From`, `To`, `Subject`, `Date`, `Message-ID`, MIME headers, etc.).
  - Full MIME body (plain + HTML parts, boundaries).

- `params`  
  Optional JSON blob forwarded to the OutLayer worker. Currently unused by the contract itself; reserved for caller‑specific metadata / future extensions.

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
  - Returns a `Promise`. The final outcome is the `VerificationResult` returned by the private callback:
    ```rust
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    pub struct VerificationResult {
        pub verified: bool,
        pub account_id: Option<String>,
        pub new_public_key: Option<String>,
        pub email_timestamp_ms: Option<u64>,
    }

    #[private]
    pub fn on_email_verification_result(
        &mut self,
        requested_by: AccountId,
        email_blob: String,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> VerificationResult
    ```
  - `verified == true`: OutLayer succeeded, TXT records were fetched, and `verify_dkim(email_blob, &records)` passed.
  - `verified == false`: any failure (OutLayer error, no TXT records, DKIM mismatch, RSA verification failure, etc.).
  - `account_id` / `new_public_key`:
    - When `verified == true` and the `Subject:` header matches the format  
      `recover|user.testnet|ed25519:new_public_keyxxxxxxxxxxxxxxxxxxx`, they are populated as:
      - `account_id`: `Some("user.testnet".to_string())`
      - `new_public_key`: `Some("ed25519:new_public_keyxxxxxxxxxxxxxxxxxxx".to_string())`
    - Otherwise they are `None`, and callers can treat the result as “DKIM verified, but no recover instruction embedded in Subject”.
  - `email_timestamp_ms`:
    - Parsed from the `Date:` header using RFC 2822 parsing and converted to milliseconds since Unix epoch (UTC).
    - `None` if the `Date:` header is missing or can’t be parsed.

Typical usage from another contract:

1. Call `request_email_verification` with the raw email and enough deposit/gas.
2. In your own callback, accept a `bool verified` and, if `true`, apply your recovery / allow‑list logic (e.g. `add_key(new_public_key)`).

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
    .request_email_verification(email_blob, None);
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
- Calls `request_email_verification(email_blob, params={})` on `$CONTRACT_ID`.
- Attaches enough gas and deposit for OutLayer execution.
