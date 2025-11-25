#!/bin/bash
set -e

# Development contract upgrade script
# This script can be used to upgrade the contract without requiring a clean git state
# Useful for rapid development and testing

source .env
echo "Upgrading contract: $CONTRACT_ID"
echo "Building contract with non-reproducible WASM (faster for dev)..."

cd email-dkim-verifier-contract

# Build the contract using non-reproducible WASM for faster development builds
cargo near build non-reproducible-wasm

cargo near deploy build-non-reproducible-wasm "$CONTRACT_ID" \
    without-init-call \
    network-config "$NEAR_NETWORK_ID" \
	sign-with-plaintext-private-key \
	--signer-public-key "$DEPLOYER_PUBLIC_KEY" \
	--signer-private-key "$DEPLOYER_PRIVATE_KEY" \
    send
