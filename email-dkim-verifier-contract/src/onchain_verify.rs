use crate::parsers::{
    extract_header_value, parse_email_timestamp_ms, parse_from_address, parse_recover_instruction,
    parse_recover_public_key_from_body, parse_recover_subject,
};
use crate::{
    ext_outlayer, ext_self, EmailDkimVerifier, VerificationResult,
    WorkerResponse, MIN_DEPOSIT, OUTLAYER_CONTRACT_ID,
};
use near_sdk::serde_json::{self, json};
use near_sdk::{env, AccountId, NearToken, Promise, PromiseError};

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct DnsLookupParams {
    #[allow(dead_code)]
    selector: Option<String>,
    #[allow(dead_code)]
    domain: Option<String>,
    #[allow(dead_code)]
    name: String,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    record_type: String,
    records: Vec<String>,
    error: Option<String>,
}

/// Internal helper: on-chain DKIM verification request path.
pub fn request_email_verification_onchain_inner(
    _contract: &mut EmailDkimVerifier,
    payer_account_id: AccountId,
    email_blob: String,
    params: Option<serde_json::Value>,
) -> Promise {
    let caller = env::predecessor_account_id();
    let attached = env::attached_deposit().as_yoctonear();
    assert!(
        attached >= MIN_DEPOSIT,
        "Attach at least 0.01 NEAR for Outlayer execution"
    );

    let outlayer_deposit = MIN_DEPOSIT;
    let refund = attached.saturating_sub(outlayer_deposit);

    if refund > 0 {
        env::log_str(&format!(
            "Refunding {} yoctoNEAR of unused DKIM fees to {}",
            refund, caller
        ));
        let _ = Promise::new(caller.clone()).transfer(NearToken::from_yoctonear(refund));
    }

    let input_payload = json!({
        "method": "get-dns-records",
        "params": {
            "email_blob": email_blob,
            "params": params.unwrap_or_else(|| json!({})),
        },
    })
    .to_string();

    let code_source = json!({
        "GitHub": {
            "repo": "https://github.com/web3-authn/email-dkim-verifier-contract",
            "commit": "13f99e811147c000d48269a72bb0ecf6a0bd3de0",
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
                .on_email_verification_onchain_result(caller, email_blob),
        )
}

/// Internal helper: on-chain DKIM verification callback path.
pub fn on_email_verification_onchain_result(
    contract: &mut EmailDkimVerifier,
    requested_by: AccountId,
    email_blob: String,
    result: Result<Option<serde_json::Value>, PromiseError>,
) -> VerificationResult {
    let _ = requested_by;
    let subject = extract_header_value(&email_blob, "Subject");
    let request_id = subject.as_deref().and_then(crate::parsers::parse_recover_request_id);

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
            contract.store_verification_result_if_needed(&request_id, &vr);
            return vr;
        }
    };

    let worker_response: WorkerResponse = match serde_json::from_value(value.clone()) {
        Ok(r) => r,
        Err(e) => {
            env::log_str(&format!("Failed to parse worker response: {e}"));
            let vr = VerificationResult {
                verified: false,
                account_id: String::new(),
                new_public_key: String::new(),
                from_address: String::new(),
                email_timestamp_ms: None,
            };
            contract.store_verification_result_if_needed(&request_id, &vr);
            return vr;
        }
    };

    if worker_response.method != "get-dns-records"
        && worker_response.method != "dnsLookup"
        && worker_response.method != "request_email_dns_records"
    {
        env::log_str(&format!(
            "Unexpected worker method in on_email_verification_onchain_result: {}",
            worker_response.method
        ));
        let vr = VerificationResult {
            verified: false,
            account_id: String::new(),
            new_public_key: String::new(),
            from_address: String::new(),
            email_timestamp_ms: None,
        };
        contract.store_verification_result_if_needed(&request_id, &vr);
        return vr;
    }

    let dns_params: DnsLookupParams =
        match serde_json::from_value(worker_response.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                env::log_str(&format!("Failed to parse get-dns-records params: {e}"));
                let vr = VerificationResult {
                    verified: false,
                    account_id: String::new(),
                    new_public_key: String::new(),
                    from_address: String::new(),
                    email_timestamp_ms: None,
                };
                contract.store_verification_result_if_needed(&request_id, &vr);
                return vr;
            }
        };

    if let Some(err) = dns_params.error.as_deref() {
        env::log_str(&format!("DKIM DNS fetch error: {err}"));
        let vr = VerificationResult {
            verified: false,
            account_id: String::new(),
            new_public_key: String::new(),
            from_address: String::new(),
            email_timestamp_ms: None,
        };
        contract.store_verification_result_if_needed(&request_id, &vr);
        return vr;
    }

    let record_strings = dns_params.records;

    if record_strings.is_empty() {
        let vr = VerificationResult {
            verified: false,
            account_id: String::new(),
            new_public_key: String::new(),
            from_address: String::new(),
            email_timestamp_ms: None,
        };
        contract.store_verification_result_if_needed(&request_id, &vr);
        return vr;
    }

    let verified = crate::verify_dkim(&email_blob, &record_strings);

    if !verified {
        let vr = VerificationResult {
            verified: false,
            account_id: String::new(),
            new_public_key: String::new(),
            from_address: String::new(),
            email_timestamp_ms: None,
        };
        contract.store_verification_result_if_needed(&request_id, &vr);
        return vr;
    }

    let subject = extract_header_value(&email_blob, "Subject");

    // Primary: parse both account_id and key from the Subject line.
    let (account_id, new_public_key) = if let Some(s) = subject.as_deref() {
        if let Some((acc, pk)) = parse_recover_instruction(s) {
            (acc.to_string(), pk)
        } else {
            let acc = parse_recover_subject(s)
                .map(|a| a.to_string())
                .unwrap_or_default();
            let pk = parse_recover_public_key_from_body(&email_blob).unwrap_or_default();
            (acc, pk)
        }
    } else {
        let pk = parse_recover_public_key_from_body(&email_blob).unwrap_or_default();
        (String::new(), pk)
    };

    let from_address = parse_from_address(&email_blob);
    let email_timestamp_ms = parse_email_timestamp_ms(&email_blob);

    let vr = VerificationResult {
        verified: true,
        account_id,
        new_public_key,
        from_address,
        email_timestamp_ms,
    };
    contract.store_verification_result_if_needed(&request_id, &vr);
    vr
}
