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
: "${DEPLOYER_PRIVATE_KEY:?Set DEPLOYER_PRIVATE_KEY in .env to the contract signer private key}"
: "${OUTLAYER_WORKER_WASM_URL:?Set OUTLAYER_WORKER_WASM_URL in .env to the hosted worker wasm URL}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to fetch the wasm from R2." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to format JSON arguments for near-cli." >&2
  exit 1
fi

hash_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  echo "Missing shasum or sha256sum for hashing." >&2
  exit 1
}

TMP_WASM="$(mktemp -t outlayer-worker-wasm.XXXXXX)"
cleanup() {
  rm -f "$TMP_WASM"
}
trap cleanup EXIT

echo "Downloading wasm from ${OUTLAYER_WORKER_WASM_URL}..."
curl -fsSL "$OUTLAYER_WORKER_WASM_URL" -o "$TMP_WASM"

WASM_HASH="$(hash_file "$TMP_WASM" | tr -d '\n')"
if [[ -z "$WASM_HASH" ]]; then
  echo "Failed to compute wasm hash from downloaded object." >&2
  exit 1
fi

JSON_ARGS="$(jq -n \
  --arg url "$OUTLAYER_WORKER_WASM_URL" \
  --arg hash "$WASM_HASH" \
  '{url: $url, hash: $hash}')"

echo "Setting Outlayer worker wasm source on contract..."
echo "  url:  $OUTLAYER_WORKER_WASM_URL"
echo "  hash: $WASM_HASH (computed from downloaded object)"

near contract call-function as-transaction "$CONTRACT_ID" set_outlayer_worker_wasm_source \
  json-args "$JSON_ARGS" \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as "$CONTRACT_ID" \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-plaintext-private-key "$DEPLOYER_PRIVATE_KEY" \
  send
