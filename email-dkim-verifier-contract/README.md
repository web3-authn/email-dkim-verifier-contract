# Email DKIM Verifier Contract

A NEAR contract that uses OutLayer to fetch email DNS records and relay them onchain for DKIM verification.

Used for email-based social recovery of tatchi.xyz accounts.


## Build

```bash
cargo near build non-reproducible-wasm
```

WASM: `target/wasm32-unknown-unknown/release/email_dkim_verifier.wasm`

## Deploy

```bash
near contract deploy coin-toss.testnet \
  use-file target/wasm32-unknown-unknown/release/email_dkim_verifier.wasm \
  with-init-call new \
  json-args '{}' \
  prepaid-gas '100.0 Tgas' \
  attached-deposit '0 NEAR' \
  network-config testnet \
  sign-with-keychain \
  send
```

