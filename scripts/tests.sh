#!/bin/bash
cd email-dkim-verifier-contract
cargo near build non-reproducible-wasm
cargo test --features unit-testing
cd ../