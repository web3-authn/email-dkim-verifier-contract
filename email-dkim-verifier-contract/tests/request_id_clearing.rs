use near_sdk::serde_json;
use near_workspaces::network::Sandbox;
use near_workspaces::Worker;
use near_workspaces::types::Gas;
use std::error::Error;

#[tokio::test]
async fn request_id_cleared_after_yield_resume() -> Result<(), Box<dyn Error>> {
    // Load the pre-built WASM artifact (built in CI or locally via cargo build).
    // This avoids needing `cargo-near` inside the test runner and improves performance.
    let wasm_path = "target/near/email_dkim_verifier_contract.wasm";

    // Fallback logic purely for local convenience if running from different dirs,
    // but in CI `cd email-dkim-verifier-contract` is done before test.
    let wasm = if std::path::Path::new(wasm_path).exists() {
        std::fs::read(wasm_path)?
    } else {
        // As a fallback for local runs where artifacts might be in the root target or otherwise named
        // we try to use compile_project, but note this requires cargo-near.
        // For CI specifically, we expect the file to exist.
        near_workspaces::compile_project("./").await?
    };

    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&wasm).await?;

    // Initialize the contract (calls #[init] fn new()).
    let init_outcome = contract
        .call("new")
        .args_json(serde_json::json!({}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    if let Err(e) = init_outcome.into_result() {
        return Err(format!("contract initialization failed: {:?}", e).into());
    }

    // Helper to fast-forward blocks in the sandbox.
    async fn fast_forward(sandbox: &Worker<Sandbox>, blocks: u64) -> Result<(), Box<dyn Error>> {
        sandbox.fast_forward(blocks).await?;
        let _block = sandbox.view_block().await?;
        Ok(())
    }

    let request_id = "XYZ999".to_string();
    let contract_clone = contract.clone();
    let _request_id_clone = request_id.clone();

    // Task 1: Perform the transaction (which will yield and wait).
    let store_verification_promise = contract_clone
        .call("test_store_verification_result_with_yield")
        .args_json(serde_json::json!({ "request_id": request_id }))
        .gas(Gas::from_tgas(30))
        .transact_async() // use transact_async() insted of tokio::join!(fut1, fut2)
        .await?;

    // Wait for the async transaction to complete
    let store_verification_outcome = store_verification_promise.await?;
    assert!(
        store_verification_outcome.is_success(),
        "test_store_verification_result_with_yield failed"
    );

    // Task 2: Verify the initial state and trigger the yield resumption.
    fast_forward(&sandbox, 1).await?;
    let fetched_now: Option<serde_json::Value> = contract
        .view("get_verification_result")
        .args_json(serde_json::json!({ "request_id": "XYZ999".to_string() }))
        .await?
        .json()?;


    if let Some(val) = fetched_now {
        if let Some(rid) = val.get("request_id") {
            assert_eq!(rid.as_str().unwrap(), "XYZ999");
        } else {
            panic!("request_id field missing in VerificationResult");
        }
    }

    // Fast-forward 200+ blocks so the yield‑resume callback runs on-chain.
    fast_forward(&sandbox, 220).await?;

    // After yield‑resume runs, the entry should be gone without calling
    // clear_verification_result manually.
    let fetched_later: Option<serde_json::Value> = contract
        .view("get_verification_result")
        .args_json(serde_json::json!({ "request_id": "XYZ999".to_string() }))
        .await?
        .json()?;

    assert!(
        fetched_later.is_none(),
        "expected entry to be cleared automatically after yield-resume"
    );

    Ok(())
}
