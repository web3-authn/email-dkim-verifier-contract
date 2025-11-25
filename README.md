# Email DKIM Verifier Contract

This repo contains a NEAR contract (`email-dkim-verifier-contract`) that uses yield/resume with [OutLayer](https://outlayer.fastnear.com/docs/getting-started) to fetch email DNS records and relay them back onchain for DKIM verification.

We use this for email-based account recovery for tatchi.xyz accounts.


TODO:
- turn into proper cargo workspace

Run tests:
```
cd email-dkim-verifier-contract
cargo test --features unit-testing
```
