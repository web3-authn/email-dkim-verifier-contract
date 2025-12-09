use near_sdk::serde_json;
use near_workspaces::network::Sandbox;
use near_workspaces::Worker;
use near_workspaces::types::Gas;
use std::error::Error;

#[tokio::test]
async fn request_id_cleared_after_yield_resume() -> Result<(), Box<dyn Error>> {
    // Load the pre-built contract WASM to avoid deadlock with running cargo test.
    let wasm = std::fs::read("target/near/email_dkim_verifier_contract.wasm")?;

    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&wasm).await?;

    // Initialize the contract (calls #[init] fn new()).
    let init_outcome = contract
        .call("new")
        .args_json(serde_json::json!({}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    if let Err(_e) = init_outcome.into_result() {
        return Err("contract initialization failed".into());
    }

    // Helper to fast-forward blocks in the sandbox.
    async fn fast_forward(sandbox: &Worker<Sandbox>, blocks: u64) -> Result<(), Box<dyn Error>> {
        sandbox.fast_forward(blocks).await?;
        let _block = sandbox.view_block().await?;
        Ok(())
    }

    let request_id = "XYZ999".to_string();
    let contract_clone = contract.clone();
    let request_id_clone = request_id.clone();

    // Task 1: Perform the transaction (which will yield and wait).
    let store_task = async move {
        contract_clone
            .call("test_store_verification_result_with_yield")
            .args_json(serde_json::json!({ "request_id": request_id }))
            .gas(Gas::from_tgas(30))
            .transact().await
            // Note: We could also use `transact_async()` to fire-and-forget the transaction
            // and await its result later, effectively avoiding the need for `tokio::join!`.
    };

    // Task 2: Verify the initial state and trigger the yield resumption.
    let verify_and_resume_task = async {
        // Poll until the entry is visible to ensure the transaction has executed the insert.
        let mut fetched_now: Option<serde_json::Value> = None;
        for _ in 0..20 {
            fetched_now = contract
                .view("get_verification_result")
                .args_json(serde_json::json!({ "request_id": "XYZ999".to_string() }))
                .await?
                .json()?;
            if fetched_now.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        if fetched_now.is_none() {
            return Err("Timed out waiting for verification result to be stored".into());
        }

        // Fast-forward 200+ blocks so the yield‑resume callback runs on-chain.
        // This effectively "unblocks" the store_task.
        fast_forward(&sandbox, 240).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };

    // Run both tasks concurrently. verify_and_resume_task will unblock store_task.
    let (store_outcome, verify_result) = tokio::join!(store_task, verify_and_resume_task);

    // Propagate errors.
    verify_result?;
    let outcome = store_outcome?;
    assert!(outcome.is_success());

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
