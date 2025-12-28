#!/bin/bash
set -e
source .env

echo "Upgrading contract: $CONTRACT_ID"
echo "Building contract with reproducible WASM..."

cd email-dkim-verifier-contract

cargo near deploy build-reproducible-wasm "$CONTRACT_ID" \
	without-init-call \
	network-config "$NEAR_NETWORK_ID" \
	sign-with-plaintext-private-key \
	--signer-public-key "$DEPLOYER_PUBLIC_KEY" \
	--signer-private-key "$DEPLOYER_PRIVATE_KEY" \
	send

# If storage layout has changed, run scripts/migrate.sh after the upgrade.
