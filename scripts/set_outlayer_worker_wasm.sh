#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f .env ]]; then
  echo ".env file not found in repo root; please create it from env.example." >&2
  exit 1
fi

source .env
: "${CONTRACT_ID:?Set CONTRACT_ID in .env to the deployed EmailDkimVerifier contract account ID}"
: "${NEAR_NETWORK_ID:?Set NEAR_NETWORK_ID in .env (e.g. testnet)}"
: "${DEPLOYER_PRIVATE_KEY:?Set DEPLOYER_PRIVATE_KEY in .env to the contract's signer private key}"
: "${OUTLAYER_WORKER_WASM_URL:?Set OUTLAYER_WORKER_WASM_URL in .env to the hosted worker wasm URL}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to fetch the wasm hash from R2." >&2
  exit 1
fi

HASH_URL="${OUTLAYER_WORKER_WASM_URL}.sha256"
WASM_HASH="$(curl -fsSL "$HASH_URL" | awk '{print $1}' | tr -d '\n')"
if [[ -z "$WASM_HASH" ]]; then
  echo "Failed to fetch wasm hash from ${HASH_URL}" >&2
  exit 1
fi

JSON_ARGS="$(jq -n \
  --arg url "$OUTLAYER_WORKER_WASM_URL" \
  --arg hash "$WASM_HASH" \
  '{url: $url, hash: $hash}')"

echo "Setting Outlayer worker wasm source on contract..."
echo "  url:  $OUTLAYER_WORKER_WASM_URL"
echo "  hash: $WASM_HASH (from ${HASH_URL})"
echo "  hash: $WASM_HASH"

near contract call-function as-transaction "$CONTRACT_ID" set_outlayer_worker_wasm_source \
  json-args "$JSON_ARGS" \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as "$CONTRACT_ID" \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-plaintext-private-key "$DEPLOYER_PRIVATE_KEY" \
  send
