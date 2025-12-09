mod parsers;
mod verify_dkim;

use crate::parsers::{
    extract_header_value, parse_email_timestamp_ms, parse_from_address, parse_recover_instruction,
    parse_recover_public_key_from_body, parse_recover_request_id, parse_recover_subject,
};
use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedMap;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::serde_json::{self, json};
use near_sdk::{env, ext_contract, near, AccountId, BorshStorageKey, NearToken, Promise, PromiseError};
use schemars::JsonSchema;

pub use crate::parsers::parse_dkim_tags;
pub use crate::verify_dkim::verify_dkim;

const OUTLAYER_CONTRACT_ID: &str = "outlayer.testnet";
// Default public encryption key for the Outlayer worker (can be overridden via contract state).
const OUTLAYER_ENCRYPTION_PUBKEY: &str = "";
// Minimum deposit forwarded to OutLayer (0.01 NEAR).
// OutLayer currently requires ~7.001e21 yoctoNEAR for the configured limits,
// so 1e22 yoctoNEAR provides a safe margin.
const MIN_DEPOSIT: u128 = 10_000_000_000_000_000_000_000;
// TTL for stored verification results keyed by request_id (in milliseconds).
const VERIFICATION_RESULT_TTL_MS: u64 = 24 * 60 * 60 * 1000; // 24 hours

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    VerificationResultsByRequestId,
}

#[near(contract_state)]
pub struct EmailDkimVerifier {
    outlayer_encryption_public_key: String,
    verification_results_by_request_id: UnorderedMap<String, StoredVerificationResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, BorshSerialize, BorshDeserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct VerificationResult {
    pub verified: bool,
    pub account_id: String,
    pub new_public_key: String,
    pub from_address: String,
    pub email_timestamp_ms: Option<u64>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct StoredVerificationResult {
    result: VerificationResult,
    created_at_ms: u64,
}

#[ext_contract(ext_outlayer)]
trait OutLayer {
    fn request_execution(
        &mut self,
        code_source: serde_json::Value,
        resource_limits: serde_json::Value,
        input_data: String,
        secrets_ref: Option<serde_json::Value>,
        response_format: String,
        payer_account_id: Option<AccountId>,
    );
}

#[ext_contract(ext_self)]
trait ExtEmailDkimVerifier {
    fn on_email_verification_onchain_result(
        &mut self,
        requested_by: AccountId,
        email_blob: String,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> VerificationResult;

    fn on_email_verification_private_result(
        &mut self,
        requested_by: AccountId,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> VerificationResult;

    fn clear_verification_result(&mut self, request_id: String);
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct WorkerResponse {
    method: String,
    params: serde_json::Value,
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct DnsLookupParams {
    selector: Option<String>,
    domain: Option<String>,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    records: Vec<String>,
    error: Option<String>,
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct VerifyParams {
    verified: bool,
    account_id: String,
    new_public_key: String,
    from_address: String,
    email_timestamp_ms: Option<u64>,
    error: Option<String>,
}


#[near]
impl EmailDkimVerifier {
    #[init]
    pub fn new() -> Self {
        Self {
            outlayer_encryption_public_key: OUTLAYER_ENCRYPTION_PUBKEY.to_string(),
            verification_results_by_request_id: UnorderedMap::new(
                StorageKey::VerificationResultsByRequestId,
            ),
        }
    }

    pub fn get_outlayer_encryption_public_key(&self) -> String {
        if self.outlayer_encryption_public_key.trim().is_empty() {
            env::panic_str(
                "Outlayer encryption public key is not configured on EmailDkimVerifier",
            );
        }
        self.outlayer_encryption_public_key.clone()
    }

    pub fn set_outlayer_encryption_public_key(&mut self, public_key: String) {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "Only the contract owner can set the Outlayer encryption public key"
        );
        self.outlayer_encryption_public_key = public_key;
    }

    pub fn get_verification_result(&self, request_id: String) -> Option<VerificationResult> {
        let stored = self.verification_results_by_request_id.get(&request_id)?;
        if is_expired(stored.created_at_ms, VERIFICATION_RESULT_TTL_MS) {
            // Log but do not mutate state in a view method.
            env::log_str("verification result expired for request_id");
            return None;
        }
        Some(stored.result)
    }

    /// Unified entrypoint for email DKIM verification.
    ///
    /// @params
    /// - `payer_account_id`: Account that pays for the Outlayer execution (typically the relayer).
    /// - `email_blob`: Plaintext raw RFC‑5322 email; set only for on‑chain DKIM verification.
    /// - `encrypted_email_blob`: Encrypted email envelope; set only for TEE‑private DKIM verification.
    /// - `params`: Optional JSON context forwarded to the worker (used as AEAD AAD in encrypted mode).
    ///
    /// @returns
    /// - A `Promise` that resolves to `VerificationResult` via either `on_email_verification_onchain_result`
    ///   (on‑chain mode) or `on_email_verification_private_result` (encrypted mode).
    #[payable]
    pub fn request_email_verification(
        &mut self,
        payer_account_id: AccountId,
        email_blob: Option<String>,
        encrypted_email_blob: Option<serde_json::Value>,
        params: Option<serde_json::Value>,
    ) -> Promise {
        match (email_blob, encrypted_email_blob) {
            (Some(email), None) => self.request_email_verification_onchain_inner(
                payer_account_id,
                email,
                params,
            ),
            (None, Some(blob)) => self.request_email_verification_private_inner(
                payer_account_id,
                blob,
                params,
            ),
            (Some(_), Some(_)) => {
                env::panic_str("provide either email_blob or encrypted_email_blob, not both")
            }
            (None, None) => {
                env::panic_str("either email_blob or encrypted_email_blob must be provided")
            }
        }
    }

    fn request_email_verification_onchain_inner(
        &mut self,
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
            Promise::new(caller.clone()).transfer(NearToken::from_yoctonear(refund));
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
                "repo": "https://github.com/web3-authn/dkim-verifier-contract",
                "commit": "main",
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

    fn request_email_verification_private_inner(
        &mut self,
        payer_account_id: AccountId,
        encrypted_email_blob: serde_json::Value,
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
            Promise::new(caller.clone()).transfer(NearToken::from_yoctonear(refund));
        }

        let input_payload = json!({
            "method": "verify-encrypted-email",
            "params": {
                "encrypted_email_blob": encrypted_email_blob,
                "context": params.unwrap_or_else(|| json!({})),
            },
        })
        .to_string();

        let code_source = json!({
            "GitHub": {
                "repo": "https://github.com/web3-authn/dkim-verifier-contract",
                "commit": "main",
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

    #[private]
    pub fn on_email_verification_onchain_result(
        &mut self,
        requested_by: AccountId,
        email_blob: String,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> VerificationResult {
        let _ = requested_by;
        let subject = extract_header_value(&email_blob, "Subject");
        let request_id = subject.as_deref().and_then(parse_recover_request_id);

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
                self.store_verification_result_if_needed(&request_id, &vr);
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
                self.store_verification_result_if_needed(&request_id, &vr);
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
            self.store_verification_result_if_needed(&request_id, &vr);
            return vr;
        }

        let dns_params: DnsLookupParams = match serde_json::from_value(worker_response.params.clone()) {
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
                    self.store_verification_result_if_needed(&request_id, &vr);
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
            self.store_verification_result_if_needed(&request_id, &vr);
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
            self.store_verification_result_if_needed(&request_id, &vr);
            return vr;
        }

        let verified = verify_dkim(&email_blob, &record_strings);

        if !verified {
            let vr = VerificationResult {
                verified: false,
                account_id: String::new(),
                new_public_key: String::new(),
                from_address: String::new(),
                email_timestamp_ms: None,
            };
            self.store_verification_result_if_needed(&request_id, &vr);
            return vr;
        }

        let subject = extract_header_value(&email_blob, "Subject");

        // Primary: parse both account_id and key from the Subject line.
        // Fallback: legacy format with account_id in Subject and key in body.
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
        self.store_verification_result_if_needed(&request_id, &vr);
        vr
    }

    #[private]
    pub fn on_email_verification_private_result(
        &mut self,
        requested_by: AccountId,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
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
                // No request_id available in the current private flow.
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

        if worker_response.method != "verify-encrypted-email" {
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

        VerificationResult {
            verified: verify_params.verified,
            account_id: verify_params.account_id,
            new_public_key: verify_params.new_public_key,
            from_address: verify_params.from_address,
            email_timestamp_ms: verify_params.email_timestamp_ms,
        }
    }

    #[private]
    pub fn clear_verification_result(&mut self, request_id: String) {
        self.verification_results_by_request_id.remove(&request_id);
    }
}

impl Default for EmailDkimVerifier {
    fn default() -> Self {
        env::panic_str("Contract is not initialized");
    }
}

fn is_expired(created_at_ms: u64, ttl_ms: u64) -> bool {
    let now_ms = env::block_timestamp() / 1_000_000;
    now_ms.saturating_sub(created_at_ms) > ttl_ms
}

impl EmailDkimVerifier {
    fn store_verification_result_if_needed(
        &mut self,
        request_id: &Option<String>,
        result: &VerificationResult,
    ) {
        let Some(id) = request_id else {
            return;
        };
        if id.is_empty() {
            return;
        }

        let entry = StoredVerificationResult {
            result: result.clone(),
            created_at_ms: env::block_timestamp() / 1_000_000,
        };
        self.verification_results_by_request_id.insert(id, &entry);
    }
}
