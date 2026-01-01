use email_dkim_verifier_contract::{onchain_verify, tee_verify, EmailDkimVerifier};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use near_sdk::AccountId;
use near_sdk::serde_json;

fn test_account_id(account_id: &str) -> AccountId {
    account_id.parse().expect("invalid AccountId")
}

#[test]
fn private_verification_propagates_request_id_and_error() {
    testing_env!(VMContextBuilder::new().build());

    let requested_by = test_account_id("relayer.testnet");
    let request_id = "RID123".to_string();

    let val = serde_json::json!({
        "method": "verify-encrypted-email",
        "response": {
            "verified": false,
            "account_id": "",
            "new_public_key": "",
            "from_address_hash": [],
            "email_timestamp_ms": null,
            "request_id": "",
            "error": "secrets_not_found"
        }
    });

    let vr = tee_verify::on_email_verification_private_result(
        requested_by,
        request_id.clone(),
        Ok(Some(val)),
    );

    assert!(!vr.verified);
    assert!(vr.from_address_hash.is_empty());
    assert_eq!(vr.request_id, request_id);
    assert_eq!(vr.error.as_deref(), Some("secrets_not_found"));
}

#[test]
fn private_verification_worker_request_id_overrides_argument() {
    testing_env!(VMContextBuilder::new().build());

    let requested_by = test_account_id("relayer.testnet");
    let request_id = "RID123".to_string();

    let val = serde_json::json!({
        "method": "verify-encrypted-email",
        "response": {
            "verified": true,
            "account_id": "alice.testnet",
            "new_public_key": "ed25519:abc",
            "from_address_hash": [1, 2, 3],
            "email_timestamp_ms": 1700000000000u64,
            "request_id": "RID456",
            "error": null
        }
    });

    let vr = tee_verify::on_email_verification_private_result(
        requested_by,
        request_id,
        Ok(Some(val)),
    );

    assert!(vr.verified);
    assert_eq!(vr.from_address_hash, vec![1, 2, 3]);
    assert_eq!(vr.request_id, "RID456");
    assert!(vr.error.is_none());
}

#[test]
fn private_verification_unexpected_method_returns_error_and_request_id() {
    testing_env!(VMContextBuilder::new().build());

    let requested_by = test_account_id("relayer.testnet");
    let request_id = "RID123".to_string();

    let val = serde_json::json!({
        "method": "some-other-method",
        "response": {}
    });

    let vr = tee_verify::on_email_verification_private_result(
        requested_by,
        request_id.clone(),
        Ok(Some(val)),
    );

    assert!(!vr.verified);
    assert_eq!(vr.request_id, request_id);
    assert_eq!(
        vr.error.as_deref(),
        Some("unexpected_worker_method: some-other-method")
    );
}

#[test]
fn private_verification_invalid_verify_response_returns_error_and_request_id() {
    testing_env!(VMContextBuilder::new().build());

    let requested_by = test_account_id("relayer.testnet");
    let request_id = "RID123".to_string();

    let val = serde_json::json!({
        "method": "verify-encrypted-email",
        "response": {}
    });

    let vr = tee_verify::on_email_verification_private_result(
        requested_by,
        request_id.clone(),
        Ok(Some(val)),
    );

    assert!(!vr.verified);
    assert_eq!(vr.request_id, request_id);
    assert_eq!(vr.error.as_deref(), Some("invalid_verify_response"));
}

#[test]
fn onchain_outlayer_failure_returns_request_id_and_error() {
    let mut contract = EmailDkimVerifier::new();
    let requested_by = test_account_id("relayer.testnet");

    let email_blob = concat!(
        "Subject: recover-ABC123 alice.testnet ed25519:deadbeef\r\n",
        "\r\n",
        "hello\r\n"
    )
    .to_string();

    let vr = onchain_verify::on_email_verification_onchain_result(
        &mut contract,
        requested_by,
        email_blob,
        Ok(None),
    );

    assert!(!vr.verified);
    assert_eq!(vr.request_id, "ABC123");
    assert_eq!(vr.error.as_deref(), Some("outlayer_execution_failed"));
}
