#!/usr/bin/env bash
set -euo pipefail

# Script to call the EmailDkimVerifier contract's `request_email_verification`
# with a sample email that includes the DKIM-Signature.
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

EMAIL_BLOB=$(
  cat <<'EOF'
From: n6378056@gmail.com
To: reset@web3authn.org
Subject: test8
Date: Tue, 30 Jun 2020 10:43:08 +0200
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601; t=1764065518; x=1764670318; darn=web3authn.org; h=to:subject:message-id:date:from:mime-version:from:to:cc:subject :date:message-id:reply-to; bh=/3T/I4LKUj/5W2dhs5sEhe+rpsHRZVi0ngI9SyPKWSw=; b=O+LksKnZtVUpN9Omaz1pYKPa9EJc+NmIku/ZQ18zCvbimPjIDjdIONBTyYnO3JCgE7 yaySupoHQ+Dh3/z5NYufBPqkThR3Gu/7YwmmX4C76J7h6bc5u82WSlJ5FqHN/Y1cKWKl ZG5fh1kcmYYN8bPWeAluIZ/X1c9LMajWNRgIM/gOa+fqImUKXn3B18EVjnRui0duOQTP FHDAEK9wuqxvxl15PVFv3gjhqh1Z7FE4HNL8yvDtsKxabeUJwX/zHiwCLb8OYm9pnb0G HA69cdD/g55kcFQoBdc1zhdAFQyzJ07rSNBYXcIUA0KcSEiOGaOSeuYHoKE3zXUBgrtG 6Q8w==

This is a test email body for DKIM verification.
EOF
)

JSON_ARGS=$(jq -n --arg email_blob "$EMAIL_BLOB" --argjson params '{}' \
  '{email_blob: $email_blob, params: $params}')

near contract call-function as-transaction "$CONTRACT_ID" request_email_verification \
  json-args "$JSON_ARGS" \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0.1 NEAR' \
  sign-as "$SIGNER_ID" \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-keychain send
