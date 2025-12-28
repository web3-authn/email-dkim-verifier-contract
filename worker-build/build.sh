#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="wasm32-wasip2"
BIN_NAME="email-dkim-verifier-contract"
OUT_DIR="${ROOT_DIR}/worker-build/dist"

cargo build --release --target "${TARGET}" --manifest-path "${ROOT_DIR}/Cargo.toml"

WASM_PATH="${ROOT_DIR}/target/${TARGET}/release/${BIN_NAME}.wasm"
if [[ ! -f "${WASM_PATH}" ]]; then
  echo "Expected wasm binary not found at ${WASM_PATH}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
cp "${WASM_PATH}" "${OUT_DIR}/${BIN_NAME}.wasm"

HASH="$(shasum -a 256 "${OUT_DIR}/${BIN_NAME}.wasm" | awk '{print $1}')"
echo "${HASH}" > "${OUT_DIR}/${BIN_NAME}.wasm.sha256"
printf "WASM_SHA256=%s\n" "${HASH}"
