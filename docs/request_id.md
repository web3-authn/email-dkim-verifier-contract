# Request ID Reference (Email Recovery UX)

This contract uses a short‑lived `request_id` embedded in the email Subject so that a frontend can poll the DKIM verification result on‑chain without talking to the relayer.

## Subject format

- Legacy recovery format (no `request_id`, still accepted by the worker for backwards compatibility):
  - `Subject: recover <account_id> ed25519:<public_key>`
- Request‑ID format (preferred for email recovery UX, and required for on‑chain `request_id` polling):
  - `Subject: recover-<REQUEST_ID> <account_id> ed25519:<public_key>k`
  - Example:
    - `Subject: recover-123ABC alice.testnet ed25519:HPHNMfHwmBJSqcArYZ5ptTZpukvFoMtuU8TcV2T7mEEy`

Parsers on both the contract and the Outlayer worker understand this convention:

- Worker (TEE / encrypted path, `email-dkim-verifier-contract/src/parsers.rs`):
  - Accepts both `recover <account_id> ...` and `recover-<REQUEST_ID> <account_id> ...`.
  - Exposes:
    - `parse_recover_request_id(subject: &str) -> Option<String>`
    - `parse_recover_subject(subject: &str) -> Option<String>`
    - `parse_recover_instruction(subject: &str) -> Option<(String, String)>`
- Contract (on‑chain path, `email-dkim-verifier-contract/src/parsers.rs`):
  - Expects the `recover-<REQUEST_ID> <account_id> ed25519:<public_key>` format when deriving `request_id` / `account_id`.
  - Exposes:
    - `parse_recover_request_id(subject: &str) -> Option<String>`
    - `parse_recover_subject(subject: &str) -> Option<AccountId>`
    - `parse_recover_instruction(subject: &str) -> Option<(AccountId, String)>`


## Contract storage and lifecycle

The contract stores verification results keyed by `request_id`:

- State (in `EmailDkimVerifier`):
  - `verification_results_by_request_id: IterableMap<String, StoredVerificationResult>`
  - `StoredVerificationResult { result: VerificationResult, created_at_ms: u64 }`
- Write paths:
  - `on_email_verification_onchain_result`:
    - Parses Subject, derives `request_id`, writes `VerificationResult` if present.
  - `on_email_verification_private_result`:
    - Reads `request_id` from the worker `verify-encrypted-email` JSON response and writes `VerificationResult`.

Lifetime is controlled by **yield‑resume cleanup (~200 blocks)**:

- After storing a result, the contract calls:
  - `env::promise_yield_create("clear_verification_result", args, Gas::from_tgas(8), GasWeight(0), 0);`
- `clear_verification_result(request_id: String)` removes the entry from the map.
- In practice, entries are available for polling until NEAR schedules and runs this callback after roughly 200 blocks.
- Verified by integration test: `tests/request_id_clearing.rs` (checks automatic clearing after fast-forward).
