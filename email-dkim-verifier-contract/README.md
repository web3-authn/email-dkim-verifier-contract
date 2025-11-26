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
  - This funds the OutLayer execution; unused funds are refunded at the end of the transaction.

- Return value  
  - Returns a `Promise`. The final outcome is the `bool` returned by the private callback:
    ```rust
    #[private]
    pub fn on_email_verification_result(
        &mut self,
        requested_by: AccountId,
        email_blob: String,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> bool
    ```
  - `true`: OutLayer succeeded, TXT records were fetched, and `verify_dkim(email_blob, &records)` passed.
  - `false`: any failure (OutLayer error, no TXT records, DKIM mismatch, RSA verification failure, etc.).

Typical usage from another contract:

1. Call `request_email_verification` with the raw email and enough deposit/gas.
2. In your own callback, accept a `bool verified` and, if `true`, apply your recovery / allow‑list logic (e.g. `add_key(new_public_key)`).

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
