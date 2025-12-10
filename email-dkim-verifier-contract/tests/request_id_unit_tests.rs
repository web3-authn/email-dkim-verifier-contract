use email_dkim_verifier_contract::{EmailDkimVerifier, VerificationResult};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;

fn context_with_timestamp_ms(ts_ms: u64) -> VMContextBuilder {
    let mut builder = VMContextBuilder::new();
    builder
        .current_account_id("contract.testnet".parse().unwrap())
        .signer_account_id("contract.testnet".parse().unwrap())
        .predecessor_account_id("caller.testnet".parse().unwrap())
        .block_timestamp(ts_ms * 1_000_000);
    builder
}

#[test]
fn get_verification_result_returns_stored_entry_for_request_id() {
    let context = context_with_timestamp_ms(0);
    testing_env!(context.build());

    let mut contract = EmailDkimVerifier::new();

    let vr = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: "ed25519:111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        from_address: "alice@example.com".to_string(),
        email_timestamp_ms: Some(0),
        request_id: "123ABC".to_string(),
    };

    contract.store_verification_result_for_testing("123ABC", &vr);

    let fetched = contract
        .get_verification_result("123ABC".to_string())
        .expect("expected verification result for request_id");

    assert!(fetched.verified);
    assert_eq!(fetched.account_id, "alice.testnet");
    assert_eq!(
        fetched.new_public_key,
        "ed25519:111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(fetched.from_address, "alice@example.com");
}
