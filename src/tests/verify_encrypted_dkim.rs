use crate::api::handle_request;
use crate::api::RequestType;
use super::crypto::encrypt_email;
use base64;

#[test]
fn verify_encrypted_dkim_flow_fails_without_secret() {
    std::env::remove_var("OUTLAYER_EMAIL_DKIM_SK");
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
        params,
    };

    let response = handle_request(request);
    assert_eq!(response.method, "verify-encrypted-email");
    let err = response
        .params
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
        "network_id": "testnet"
    });

    let envelope = encrypt_email(email_blob, &context);

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
        params,
    };

    let response = handle_request(request);
    assert_eq!(response.method, "verify-encrypted-email");

    let verified = response
        .params
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(verified, "expected DKIM verification to succeed in worker");

    let account_id = response
        .params
        .get("account_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(account_id, "kerp30.w3a-v1.testnet");

    let new_public_key = response
        .params
        .get("new_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(
        new_public_key,
        "ed25519:86mqiBdv45gM4c5uLmvT3TU4g7DAg6KLpuabBSFweigm"
    );

    let from_address = response
        .params
        .get("from_address")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(from_address, "n6378056@gmail.com");

    let email_timestamp_ms = response
        .params
        .get("email_timestamp_ms")
        .and_then(|v| v.as_u64());
    assert!(email_timestamp_ms.is_some());

    let error = response
        .params
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
        params,
    };

    let response = handle_request(request);
    assert_eq!(response.method, "verify-encrypted-email");

    let verified = response
        .params
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    assert!(!verified, "expected DKIM verification to fail for tampered key");

    let account_id = response
        .params
        .get("account_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(account_id, "");

    let new_public_key = response
        .params
        .get("new_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(new_public_key, "");

    let from_address = response
        .params
        .get("from_address")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert_eq!(from_address, "");

    let email_timestamp_ms = response
        .params
        .get("email_timestamp_ms")
        .and_then(|v| v.as_u64());
    assert!(email_timestamp_ms.is_none());

    let error = response
        .params
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        error.contains("DKIM verification failed"),
        "expected DKIM failure error, got: {error}"
    );
}
