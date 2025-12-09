use crate::{
    ext_outlayer, ext_self, EmailDkimVerifier, VerificationResult, VerifyParams,
    WorkerResponse, MIN_DEPOSIT_3, OUTLAYER_CONTRACT_ID, OUTLAYER_WORKER_COMMIT,
    VERIFY_ENCRYPTED_EMAIL_METHOD,
};
use near_sdk::serde_json::{self, json};
use near_sdk::{env, AccountId, NearToken, Promise, PromiseError};

/// Internal helper: encrypted/TEE DKIM verification request path.
pub fn request_email_verification_private_inner(
    _contract: &mut EmailDkimVerifier,
    payer_account_id: AccountId,
    encrypted_email_blob: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Promise {
    let caller = env::predecessor_account_id();
    let attached = env::attached_deposit().as_yoctonear();
    assert!(
        attached >= MIN_DEPOSIT_3,
        "Attach at least 0.01 NEAR for Outlayer execution"
    );

    let outlayer_deposit = MIN_DEPOSIT_3;
    let refund = attached.saturating_sub(outlayer_deposit);

    if refund > 0 {
        env::log_str(&format!(
            "Refunding {} yoctoNEAR of unused DKIM fees to {}",
            refund, caller
        ));
        let _ = Promise::new(caller.clone()).transfer(NearToken::from_yoctonear(refund));
    }

    let input_payload = json!({
        "method": VERIFY_ENCRYPTED_EMAIL_METHOD,
        "params": {
            "encrypted_email_blob": encrypted_email_blob,
            "context": params.unwrap_or_else(|| json!({})),
        },
    })
    .to_string();

    let code_source = json!({
        "GitHub": {
            "repo": "https://github.com/web3-authn/email-dkim-verifier-contract",
            "commit": OUTLAYER_WORKER_COMMIT,
            "build_target": "wasm32-wasip2"
        }
    });

    let resource_limits = json!({
        "max_instructions": 10_000_000_000u64,
        "max_memory_mb": 256u64,
        "max_execution_seconds": 60u64
    });

    ext_outlayer::ext(OUTLAYER_CONTRACT_ID.parse().unwrap())
        .with_attached_deposit(NearToken::from_yoctonear(outlayer_deposit))
        .with_unused_gas_weight(1)
        .request_execution(
            code_source,
            resource_limits,
            input_payload,
            None,
            "Json".to_string(),
            Some(payer_account_id),
        )
        .then(
            ext_self::ext(env::current_account_id())
                .with_unused_gas_weight(1)
                .on_email_verification_private_result(caller),
        )
}

/// Internal helper: encrypted/TEE DKIM verification callback path.
pub fn on_email_verification_private_result(
    contract: &mut EmailDkimVerifier,
    requested_by: AccountId,
    result: Result<Option<serde_json::Value>, PromiseError>,
) -> VerificationResult {
    let _ = requested_by;
    let value = match result {
        Ok(Some(v)) => v,
        _ => {
            let vr = VerificationResult {
                verified: false,
                account_id: String::new(),
                new_public_key: String::new(),
                from_address: String::new(),
                email_timestamp_ms: None,
            };
            return vr;
        }
    };

    let worker_response: WorkerResponse = match serde_json::from_value(value.clone()) {
        Ok(r) => r,
        Err(e) => {
            env::log_str(&format!(
                "Failed to parse worker response (private): {e}"
            ));
            let vr = VerificationResult {
                verified: false,
                account_id: String::new(),
                new_public_key: String::new(),
                from_address: String::new(),
                email_timestamp_ms: None,
            };
            return vr;
        }
    };

    if worker_response.method != VERIFY_ENCRYPTED_EMAIL_METHOD {
        env::log_str(&format!(
            "Unexpected worker method in on_email_verification_private_result: {}",
            worker_response.method
        ));
        let vr = VerificationResult {
            verified: false,
            account_id: String::new(),
            new_public_key: String::new(),
            from_address: String::new(),
            email_timestamp_ms: None,
        };
        return vr;
    }

    let verify_params: VerifyParams =
        match serde_json::from_value(worker_response.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                env::log_str(&format!(
                    "Failed to parse verify-encrypted-email params: {e}"
                ));
                let vr = VerificationResult {
                    verified: false,
                    account_id: String::new(),
                    new_public_key: String::new(),
                    from_address: String::new(),
                    email_timestamp_ms: None,
                };
                return vr;
            }
        };

    if let Some(err) = verify_params.error.as_deref() {
        env::log_str(&format!(
            "verify-encrypted-email worker error: {err}"
        ));
    }

    let vr = VerificationResult {
        verified: verify_params.verified,
        account_id: verify_params.account_id,
        new_public_key: verify_params.new_public_key,
        from_address: verify_params.from_address,
        email_timestamp_ms: verify_params.email_timestamp_ms,
    };
    contract.store_verification_result_if_needed(&verify_params.request_id, &vr);
    vr
}
