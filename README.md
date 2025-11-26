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

- Configure environment (once):
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
