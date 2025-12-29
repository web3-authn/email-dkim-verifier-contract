#!/usr/bin/env bash
set -euo pipefail

# Script to call the EmailDkimVerifier contract's `request_email_verification`
# with a sample email that includes the DKIM-Signature (on-chain DKIM mode).
#
# Usage:
#   cp env.example .env
#   # edit .env to set CONTRACT_ID, NEAR_NETWORK_ID, SIGNER_ID
#   ./scripts/request_email_verification.sh
#
# Prerequisites:
#   - `near` CLI v3 installed and configured
#   - SIGNER_ID has a full-access key in your local keychain

source .env

: "${CONTRACT_ID:?Set CONTRACT_ID in .env to the deployed EmailDkimVerifier contract account ID}"
: "${NEAR_NETWORK_ID:?Set NEAR_NETWORK_ID in .env (e.g. testnet)}"
: "${SIGNER_ID:?Set SIGNER_ID in .env to the signer account ID}"

# Use a real Gmail DKIM sample (full raw message) that our contract
# verifies in unit tests (see email-dkim-verifier-contract/tests/data/gmail_reset_full.eml).
EMAIL_BLOB="$(cat email-dkim-verifier-contract/tests/data/gmail_reset_full.eml)"

# In this CLI scenario, the payer is the signer (relayer).
JSON_ARGS=$(jq -n \
  --arg payer_account_id "$SIGNER_ID" \
  --arg email_blob "$EMAIL_BLOB" \
  '{payer_account_id: $payer_account_id, email_blob: $email_blob, encrypted_email_blob: null, aead_context: null, request_id: null}')

near contract call-function as-transaction "$CONTRACT_ID" request_email_verification \
  json-args "$JSON_ARGS" \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0.1 NEAR' \
  sign-as "$SIGNER_ID" \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-keychain send
