use crate::api::{handle_request, RequestType};
use super::crypto::encrypt_email;
use base64;
use sha2::{Digest, Sha256};
use crate::parsers::parse_from_address;

#[test]
fn verify_encrypted_dkim_flow_fails_without_secret() {
    std::env::remove_var("PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32");
    std::env::remove_var("OUTLAYER_WORKER_SK_SEED_HEX32");
    let params = serde_json::json!({
        "encrypted_email_blob": {
            "version": 1,
            "ephemeral_pub": "",
            "nonce": base64::encode(&[0u8; 12]),
            "ciphertext": base64::encode(&[0u8; 16]),
        },
        "context": {},
    });

    let request = RequestType {
        method: "verify-encrypted-email".to_string(),
        args: params,
    };

    let response = handle_request(request);
    assert_eq!(response.method, "verify-encrypted-email");
    let err = response
        .response
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(!err.is_empty());
}

#[test]
fn encrypted_flow_runs_dkim_verification_in_worker() {
    let email_blob = include_str!("../../email-dkim-verifier-contract/tests/data/gmail_reset_full.eml");
    let context = serde_json::json!({
        "account_id": "kerp30.w3a-v1.testnet",
        "network_id": "testnet",
        "payer_account_id": "kerp30.w3a-v1.testnet"
    });

    let envelope = encrypt_email(email_blob, &context);

    let args = serde_json::json!({
        "encrypted_email_blob": {
            "version": envelope.version,
            "ephemeral_pub": envelope.ephemeral_pub,
            "nonce": envelope.nonce,
            "ciphertext": envelope.ciphertext,
        },
        "context": context,
    });

    let request = RequestType {
        method: "verify-encrypted-email".to_string(),
        args: args,
    };

    let response = handle_request(request);
    assert_eq!(response.method, "verify-encrypted-email");

    let verified = response
        .response
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(verified, "expected DKIM verification to succeed in worker");

    let account_id = response
        .response
        .get("account_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(account_id, "kerp30.w3a-v1.testnet");

    let new_public_key = response
        .response
        .get("new_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        new_public_key,
        "ed25519:86mqiBdv45gM4c5uLmvT3TU4g7DAg6KLpuabBSFweigm"
    );

    assert!(
        response.response.get("from_address").is_none(),
        "worker response must not leak sender email address"
    );

    let from_address_hash = response
        .response
        .get("from_address_hash")
        .and_then(|v| v.as_array())
        .expect("from_address_hash array");
    assert_eq!(from_address_hash.len(), 32);
    let from_address_hash_bytes: Vec<u8> = from_address_hash
        .iter()
        .map(|v| v.as_u64().expect("hash byte") as u8)
        .collect();
    let canonical_from = parse_from_address(email_blob).trim().to_lowercase();
    let salt = "kerp30.w3a-v1.testnet";
    let expected = Sha256::digest(format!("{canonical_from}|{salt}").as_bytes()).to_vec();
    assert_eq!(from_address_hash_bytes, expected);

    let email_timestamp_ms = response
        .response
        .get("email_timestamp_ms")
        .and_then(|v| v.as_u64());
    assert!(email_timestamp_ms.is_some());

    let error = response
        .response
        .get("error")
        .and_then(|v| v.as_str());
    assert!(error.is_none(), "expected no error from worker");
}

#[test]
fn encrypted_flow_fails_for_tampered_public_key() {
    let email_blob = include_str!("../../email-dkim-verifier-contract/tests/data/gmail_reset_full.eml");
    let tampered = email_blob.replacen(
        "ed25519:86mqiBdv45gM4c5uLmvT3TU4g7DAg6KLpuabBSFweigm",
        "ed25519:86mqiBdv45gM4c5uLmvT3TU4g7DAg6KLpuabBSFweign",
        1,
    );
    let context = serde_json::json!({
        "account_id": "kerp30.w3a-v1.testnet",
        "network_id": "testnet"
    });

    let envelope = encrypt_email(&tampered, &context);

    let params = serde_json::json!({
        "encrypted_email_blob": {
            "version": envelope.version,
            "ephemeral_pub": envelope.ephemeral_pub,
            "nonce": envelope.nonce,
            "ciphertext": envelope.ciphertext,
        },
        "context": context,
    });

    let request = RequestType {
        method: "verify-encrypted-email".to_string(),
        args: params,
    };

    let response = handle_request(request);
    assert_eq!(response.method, "verify-encrypted-email");

    let verified = response
        .response
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    assert!(!verified, "expected DKIM verification to fail for tampered key");

    let account_id = response
        .response
        .get("account_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(account_id, "");

    let new_public_key = response
        .response
        .get("new_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(new_public_key, "");

    assert!(response.response.get("from_address").is_none());

    let from_address_hash = response
        .response
        .get("from_address_hash")
        .and_then(|v| v.as_array())
        .expect("from_address_hash array");
    assert!(from_address_hash.is_empty());

    let email_timestamp_ms = response
        .response
        .get("email_timestamp_ms")
        .and_then(|v| v.as_u64());
    assert!(email_timestamp_ms.is_none());

    let error = response
        .response
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        error.contains("DKIM verification failed"),
        "expected DKIM failure error, got: {error}"
    );
}
