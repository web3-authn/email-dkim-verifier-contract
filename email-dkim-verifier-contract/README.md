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
