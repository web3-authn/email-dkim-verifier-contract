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

echo "Generating new X25519 worker keypair..."
KEY_OUTPUT="$(cargo run --quiet --bin generate_x25519_keypair)"
echo "$KEY_OUTPUT"

# Expect lines:
# OUTLAYER_WORKER_SK_B64=...
# OUTLAYER_WORKER_PK_B64=...
eval "$KEY_OUTPUT"

if [[ -z "${OUTLAYER_WORKER_SK_B64:-}" || -z "${OUTLAYER_WORKER_PK_B64:-}" ]]; then
  echo "Failed to parse generated keypair."
  exit 1
fi

echo
echo "=== ACTION REQUIRED: Update Outlayer worker secret ==="
echo "Set the Outlayer worker secret/env variable:"
echo "  OUTLAYER_EMAIL_DKIM_SK=${OUTLAYER_WORKER_SK_B64}"
echo "using your Outlayer deployment's secrets mechanism, then restart the worker."
echo

read -p "Press enter after the worker has been updated and restarted, or Ctrl+C to abort..." _

echo "Updating contract public key via set_outlayer_encryption_public_key..."

near call "$CONTRACT_ID" \
  set_outlayer_encryption_public_key \
  "{\"public_key\":\"${OUTLAYER_WORKER_PK_B64}\"}" \
  --accountId "$CONTRACT_ID" \
  --networkId "$NEAR_NETWORK_ID" \
  --signerPublicKey "$DEPLOYER_PUBLIC_KEY" \
  --signerPrivateKey "$DEPLOYER_PRIVATE_KEY"

echo "Done. Relayers should now fetch the new public key from get_outlayer_encryption_public_key()."
