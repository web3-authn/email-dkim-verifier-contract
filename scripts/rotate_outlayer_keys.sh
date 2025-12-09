#!/usr/bin/env bash
set -euo pipefail

# Rotate the Outlayer worker X25519 keypair and update the contract's
# public encryption key.
# Script assumes:
#   .env is configured with CONTRACT_ID, NEAR_NETWORK_ID,
#   DEPLOYER_PUBLIC_KEY, DEPLOYER_PRIVATE_KEY.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f .env ]]; then
  echo ".env file not found in repo root; please create it from env.example."
  exit 1
fi

source .env
: "${CONTRACT_ID:?Set CONTRACT_ID in .env to the deployed EmailDkimVerifier contract account ID}"
: "${NEAR_NETWORK_ID:?Set NEAR_NETWORK_ID in .env (e.g. testnet)}"
: "${DEPLOYER_PUBLIC_KEY:?Set DEPLOYER_PUBLIC_KEY in .env to the contract's signer public key}"
: "${DEPLOYER_PRIVATE_KEY:?Set DEPLOYER_PRIVATE_KEY in .env to the contract's signer private key}"

echo "This script triggers the contract to refresh its public key from the Outlayer worker."
echo "Ensure you have updated the PROTECTED_OUTLAYER_WORKER_SK_SEED_B64 in the Outlayer secrets if needed."
echo
echo "Repository (for reference):"
echo "  https://github.com/web3-authn/email-dkim-verifier-contract"
echo
echo

read -p "Press enter to trigger key refresh on the contract..." _

echo "Updating contract public key via set_outlayer_encryption_public_key..."

near contract call-function as-transaction "$CONTRACT_ID" set_outlayer_encryption_public_key \
  json-args {} \
  prepaid-gas '100.0 Tgas' \
  attached-deposit '0.05 NEAR' \
  sign-as "$CONTRACT_ID" \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-plaintext-private-key "$DEPLOYER_PRIVATE_KEY" \
  send

echo "Done. Relayers should now fetch the new public key from get_outlayer_encryption_public_key()."
