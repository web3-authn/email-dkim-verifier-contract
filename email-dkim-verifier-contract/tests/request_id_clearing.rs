use near_sdk::serde_json;
use near_workspaces::network::Sandbox;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::Worker;
use serde_json::json;

async fn fast_forward(
    sandbox: &Worker<Sandbox>,
    blocks: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    sandbox.fast_forward(blocks).await?;
    Ok(())
}

/// End-to-end test that:
/// 1. Stores a VerificationResult keyed by `request_id` by calling the
///    on_email_verification_onchain_result callback (which schedules a
///    yield-resume cleanup via promise_yield_create).
/// 2. Fast-forwards 200+ blocks in the sandbox.
/// 3. Asserts that get_verification_result(request_id) returns None after
///    the scheduled clear_verification_result has executed.
#[tokio::test]
#[ignore]
async fn request_id_cleared_after_yield_resume() -> Result<(), Box<dyn std::error::Error>> {
    // Compile and deploy the EmailDkimVerifier contract.
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Initialize contract state.
    let init_outcome = contract
        .call("new")
        .args_json(json!({}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(init_outcome.is_success(), "EmailDkimVerifier initialization should succeed");

    fast_forward(&sandbox, 1).await?;

    // Start from the real Gmail sample used in DKIM tests, and rewrite the
    // Subject to include a request_id in the new format:
    //   "recover-<REQUEST_ID> <account_id> ed25519:<public_key>"
    let request_id = "ABC123";
    let email_blob_raw = include_str!("data/gmail_reset_full.eml");
    let original_subject = "Subject: recover berp61.w3a-v1.testnet ed25519:HPHNMfHwmBJSqcArYZ5ptTZpukvFoMtuU8TcV2T7mEEy";
    let updated_subject = format!(
        "Subject: recover-{request_id} berp61.w3a-v1.testnet ed25519:HPHNMfHwmBJSqcArYZ5ptTZpukvFoMtuU8TcV2T7mEEy"
    );
    let email_blob = email_blob_raw.replacen(original_subject, &updated_subject, 1);

    // Call the main entrypoint so the full flow runs:
    // - request_email_verification creates the Outlayer promise and yield promise.
    // - The callback on_email_verification_onchain_result receives a PromiseError
    //   (since Outlayer is not deployed in this sandbox), stores a `verified: false`
    //   result for this request_id, and schedules clear_verification_result.
    let tx_outcome = contract
        .call("request_email_verification")
        .args_json(json!({
            "email_blob": email_blob,
            "encrypted_email_blob": serde_json::Value::Null,
            "params": serde_json::Value::Null,
            "payer_account_id": contract.id(),
        }))
        .deposit(NearToken::from_yoctonear(10_000_000_000_000_000_000_000u128))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?;
    assert!(
        tx_outcome.is_success(),
        "request_email_verification transaction should succeed"
    );

    fast_forward(&sandbox, 1).await?;

    // Before fast-forwarding 200+ blocks, the verification result should
    // be present for this request_id.
    let view_before = contract
        .call("get_verification_result")
        .args_json(json!({ "request_id": request_id }))
        .view()
        .await?;
    let before: Option<serde_json::Value> = view_before.json()?;
    assert!(
        before.is_some(),
        "expected verification result to be present before yield-resume cleanup"
    );

    // Fast-forward ~200+ blocks in the sandbox to trigger yield-resume.
    fast_forward(&sandbox, 240).await?;

    // After yield-resume executes clear_verification_result, the entry should
    // be removed and get_verification_result should return None.
    let view_after = contract
        .call("get_verification_result")
        .args_json(json!({ "request_id": request_id }))
        .view()
        .await?;
    let after: Option<serde_json::Value> = view_after.json()?;
    assert!(
        after.is_none(),
        "expected verification result to be cleared after yield-resume"
    );

    Ok(())
}
