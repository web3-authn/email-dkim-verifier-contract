use crate::{
    ext_outlayer, ext_self,
    EmailDkimVerifier, OutlayerInputArgs, VerificationResult,
    OutlayerWorkerResponse, MIN_DEPOSIT,
    OUTLAYER_CONTRACT_ID,
    GET_DNS_RECORDS_METHOD,
    SecretsReference, SECRETS_OWNER_ID, SECRETS_PROFILE,
};
pub mod parsers;
pub mod dkim;
pub use parsers::parse_dkim_tags;

use parsers::*;
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
    contract: &mut EmailDkimVerifier,
    payer_account_id: AccountId,
    email_blob: String,
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

    let input_args = OutlayerInputArgs::new(
        GET_DNS_RECORDS_METHOD,
        serde_json::json!({
            "email_blob": email_blob,
            "context": serde_json::json!({}), // no context needed
        }),
    );
    let input_payload = input_args.to_json_string();

    let worker_wasm_source = contract.resolve_outlayer_worker_wasm_source();
    let source = if !worker_wasm_source.url.is_empty() && !worker_wasm_source.hash.is_empty() {
        json!({
            "WasmUrl": {
                "url": worker_wasm_source.url,
                "hash": worker_wasm_source.hash,
                "build_target": "wasm32-wasip2"
            }
        })
    } else if worker_wasm_source.url.is_empty() && worker_wasm_source.hash.is_empty() {
        json!({
            "GitHub": {
                "repo": "https://github.com/web3-authn/email-dkim-verifier-contract",
                "commit": "main",
                "build_target": "wasm32-wasip2"
            }
        })
    } else {
        env::panic_str(
            "Outlayer worker wasm source is partially configured; set both url + hash or leave both empty to use GitHub source",
        );
    };

    let resource_limits = json!({
        "max_instructions": 10_000_000_000u64,
        "max_memory_mb": 256u32,
        "max_execution_seconds": 60u64
    });

    let secrets = SecretsReference {
        profile: SECRETS_PROFILE.to_string(),
        account_id: SECRETS_OWNER_ID.parse().unwrap(),
    };

    ext_outlayer::ext(OUTLAYER_CONTRACT_ID.parse().unwrap())
        .with_attached_deposit(NearToken::from_yoctonear(outlayer_deposit))
        .with_unused_gas_weight(1)
        .request_execution(
            source,
            resource_limits,
            input_payload,
            Some(secrets), // secrets
            "Json".to_string(),
            Some(payer_account_id),
            None, // params
        )
        .then(
            ext_self::ext(env::current_account_id())
                .with_unused_gas_weight(1)
                .on_email_verification_onchain_result(caller, email_blob),
        )
}

/// Internal helper: on-chain DKIM verification callback path.
pub fn on_email_verification_onchain_result(
    _contract: &mut EmailDkimVerifier,
    requested_by: AccountId,
    email_blob: String,
    result: Result<Option<serde_json::Value>, PromiseError>,
) -> VerificationResult {
    let _ = requested_by;
    let subject = extract_header_value(&email_blob, "Subject");
    let request_id = subject.as_deref()
        .and_then(parsers::parse_recover_request_id)
        .unwrap_or_default();

    let value = match result {
        Ok(Some(v)) => v,
        _ => {
            return VerificationResult::failure(&request_id, "outlayer_execution_failed");
        }
    };

    let worker_response: OutlayerWorkerResponse = match serde_json::from_value(value.clone()) {
        Ok(r) => r,
        Err(e) => {
            env::log_str(&format!("Failed to parse worker response: {e}"));
            return VerificationResult::failure(&request_id, "invalid_worker_response");
        }
    };

    if worker_response.method != GET_DNS_RECORDS_METHOD {
        env::log_str(&format!(
            "Unexpected worker method in on_email_verification_onchain_result: {}",
            worker_response.method
        ));
        return VerificationResult::failure(
            &request_id,
            format!(
            "unexpected_worker_method: {}",
            worker_response.method
            ),
        );
    }

    let dns_params: DnsLookupParams =
        match serde_json::from_value(worker_response.response.clone()) {
            Ok(p) => p,
            Err(e) => {
                env::log_str(&format!("Failed to parse {GET_DNS_RECORDS_METHOD} response: {e}"));
                return VerificationResult::failure(&request_id, "invalid_dns_response");
            }
        };

    if let Some(err) = dns_params.error.as_deref() {
        env::log_str(&format!("DKIM DNS fetch error: {err}"));
        return VerificationResult::failure(&request_id, format!("dns_error: {err}"));
    }

    let record_strings = dns_params.records;

    if record_strings.is_empty() {
        return VerificationResult::failure(&request_id, "dns_records_empty");
    }

    let verified = dkim::verify_dkim(&email_blob, &record_strings);

    if !verified {
        return VerificationResult::failure(&request_id, "dkim_verification_failed");
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

    let email_timestamp_ms = parse_email_timestamp_ms(&email_blob);
    let from_address_hash = compute_from_address_hash(&email_blob, &account_id);

    let vr = VerificationResult {
        verified: true,
        account_id,
        new_public_key,
        from_address_hash,
        email_timestamp_ms,
        request_id: request_id.clone(),
        error: None,
    };
    vr
}

fn compute_from_address_hash(email_blob: &str, account_id: &str) -> Vec<u8> {
    let from_header = extract_header_value(email_blob, "From").unwrap_or_default();
    let canonical_from = canonicalize_email_address(&from_header);
    let salt = account_id.trim().to_lowercase();
    if canonical_from.is_empty() || salt.is_empty() {
        return Vec::new();
    }
    let input = format!("{canonical_from}|{salt}");
    env::sha256(input.as_bytes())
}

fn canonicalize_email_address(input: &str) -> String {
    let raw = input.trim();
    if raw.is_empty() {
        return String::new();
    }

    // Strip leading "Header-Name:" when present (e.g. "From: ...").
    let without_header_name = if let Some(colon_idx) = raw.find(':') {
        let (prefix, rest) = raw.split_at(colon_idx);
        let prefix = prefix.trim();
        if !prefix.is_empty()
            && prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            rest[1..].trim_start()
        } else {
            raw
        }
    } else {
        raw
    };

    // Prefer the common "Name <email@domain>" format.
    let mut candidates: [&str; 2] = ["", without_header_name];
    if let Some(start) = without_header_name.find('<') {
        if let Some(end_rel) = without_header_name[start + 1..].find('>') {
            let end = start + 1 + end_rel;
            candidates[0] = &without_header_name[start + 1..end];
        }
    }

    for candidate in candidates.iter().copied() {
        let candidate = candidate.trim();
        if candidate.is_empty() {
            continue;
        }

        let candidate = if candidate.len() >= 7 && candidate[..7].eq_ignore_ascii_case("mailto:") {
            candidate[7..].trim_start()
        } else {
            candidate
        };

        if let Some(found) = extract_email_like(candidate) {
            return found.to_lowercase();
        }
    }

    without_header_name.to_lowercase()
}

fn extract_email_like(input: &str) -> Option<&str> {
    let bytes = input.as_bytes();
    for (idx, b) in bytes.iter().enumerate() {
        if *b != b'@' {
            continue;
        }

        let mut start = idx;
        while start > 0 && is_email_local_byte(bytes[start - 1]) {
            start -= 1;
        }

        let mut end = idx + 1;
        while end < bytes.len() && (is_email_domain_byte(bytes[end]) || bytes[end] == b'.') {
            end += 1;
        }

        if start == idx || end == idx + 1 {
            continue;
        }

        // Domain must not end with '.'.
        if bytes[end - 1] == b'.' {
            continue;
        }

        return Some(&input[start..end]);
    }
    None
}

fn is_email_local_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9')
        || matches!(
            b,
            b'.' | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'/' | b'=' | b'?' | b'^'
                | b'_' | b'`' | b'{' | b'|' | b'}' | b'~' | b'-'
        )
}

fn is_email_domain_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-')
}
