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
OUTLAYER_WORKER_WASM_URL="${OUTLAYER_WORKER_WASM_URL:-}"
OUTLAYER_WORKER_WASM_LATEST_MANIFEST_URL="${OUTLAYER_WORKER_WASM_LATEST_MANIFEST_URL:-https://outlayer.tatchi.xyz/workers/email-dkim/latest.json}"
OUTLAYER_WORKER_WASM_LATEST_URL="${OUTLAYER_WORKER_WASM_LATEST_URL:-https://outlayer.tatchi.xyz/workers/email-dkim/latest.wasm}"
WASM_URL="${OUTLAYER_WORKER_WASM_URL}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to fetch the wasm from R2." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to format JSON arguments for near-cli." >&2
  exit 1
fi

rfc3339_to_epoch() {
  local ts="${1:-}"
  if [[ -z "${ts}" ]]; then
    return 1
  fi

  if date -u -d "${ts}" +%s >/dev/null 2>&1; then
    date -u -d "${ts}" +%s
    return 0
  fi

  if date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "${ts}" +%s >/dev/null 2>&1; then
    date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "${ts}" +%s
    return 0
  fi

  return 1
}

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

MANIFEST_JSON=""
MANIFEST_BUILT_AT=""
MANIFEST_COMMIT_SHA=""
MANIFEST_SHA=""
MANIFEST_SHA_URL=""

if [[ -z "${WASM_URL}" ]]; then
  echo "Fetching latest build manifest: ${OUTLAYER_WORKER_WASM_LATEST_MANIFEST_URL}"
  MANIFEST_JSON="$(curl -fsSL "${OUTLAYER_WORKER_WASM_LATEST_MANIFEST_URL}" || true)"
  if [[ -n "${MANIFEST_JSON}" ]]; then
    WASM_URL="$(printf '%s' "${MANIFEST_JSON}" | jq -r '.wasm_url // empty')"
    MANIFEST_SHA="$(printf '%s' "${MANIFEST_JSON}" | jq -r '.sha256 // empty')"
    MANIFEST_SHA_URL="$(printf '%s' "${MANIFEST_JSON}" | jq -r '.sha256_url // empty')"
    MANIFEST_BUILT_AT="$(printf '%s' "${MANIFEST_JSON}" | jq -r '.built_at // empty')"
    MANIFEST_COMMIT_SHA="$(printf '%s' "${MANIFEST_JSON}" | jq -r '.commit_sha // empty')"
  fi

  if [[ -z "${WASM_URL}" ]]; then
    echo "Manifest missing wasm_url; falling back to: ${OUTLAYER_WORKER_WASM_LATEST_URL}" >&2
    WASM_URL="${OUTLAYER_WORKER_WASM_LATEST_URL}"
  fi
fi

SHA_URL="${MANIFEST_SHA_URL:-${WASM_URL}.sha256}"
REMOTE_HASH_FILE="$(curl -fsSL "$SHA_URL" 2>/dev/null | awk '{print $1}' | tr -d '\n' || true)"
if [[ -n "${MANIFEST_SHA}" && -n "${REMOTE_HASH_FILE}" && "${MANIFEST_SHA}" != "${REMOTE_HASH_FILE}" ]]; then
  echo "Hash mismatch between manifest and ${SHA_URL}:" >&2
  echo "  manifest sha256: ${MANIFEST_SHA}" >&2
  echo "  sha256 file:     ${REMOTE_HASH_FILE}" >&2
  exit 1
fi

REMOTE_HASH="${REMOTE_HASH_FILE:-${MANIFEST_SHA}}"

if [[ -n "${MANIFEST_BUILT_AT}" || -n "${MANIFEST_COMMIT_SHA}" ]]; then
  echo "Latest build:"
  if [[ -n "${MANIFEST_COMMIT_SHA}" ]]; then
    echo "  commit:   ${MANIFEST_COMMIT_SHA}"
  fi
  if [[ -n "${MANIFEST_BUILT_AT}" ]]; then
    echo "  built_at: ${MANIFEST_BUILT_AT}"
    if built_epoch="$(rfc3339_to_epoch "${MANIFEST_BUILT_AT}" 2>/dev/null)"; then
      now_epoch="$(date -u +%s)"
      if [[ "${now_epoch}" =~ ^[0-9]+$ && "${built_epoch}" =~ ^[0-9]+$ ]]; then
        age_seconds="$((now_epoch - built_epoch))"
        if ((age_seconds < 0)); then
          age_seconds=0
        fi
        echo "  age:      ~$((age_seconds / 3600))h"
      fi
    fi
  fi
fi

echo "Downloading wasm from ${WASM_URL}..."
curl -fsSL "$WASM_URL" -o "$TMP_WASM"

LOCAL_HASH="$(hash_file "$TMP_WASM" | tr -d '\n')"
if [[ -z "$LOCAL_HASH" ]]; then
  echo "Failed to compute wasm hash from downloaded object." >&2
  exit 1
fi

if [[ -n "$REMOTE_HASH" && "$REMOTE_HASH" != "$LOCAL_HASH" ]]; then
  echo "Hash mismatch for ${WASM_URL}:" >&2
  echo "  sha256 file: $REMOTE_HASH" >&2
  echo "  computed:    $LOCAL_HASH" >&2
  exit 1
fi

JSON_ARGS="$(jq -n \
  --arg url "$WASM_URL" \
  --arg hash "$LOCAL_HASH" \
  '{url: $url, hash: $hash}')"

echo "Setting Outlayer worker wasm source on contract..."
echo "  url:  $WASM_URL"
if [[ -n "$REMOTE_HASH" ]]; then
  echo "  sha256: $REMOTE_HASH (from ${SHA_URL})"
fi
echo "  hash: $LOCAL_HASH (computed from downloaded object)"

near contract call-function as-transaction "$CONTRACT_ID" set_outlayer_worker_wasm_source \
  json-args "$JSON_ARGS" \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as "$CONTRACT_ID" \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-plaintext-private-key "$DEPLOYER_PRIVATE_KEY" \
  send
