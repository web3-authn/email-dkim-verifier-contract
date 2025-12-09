mod parsers;
mod verify_dkim;
mod onchain_verify;
mod tee_verify;

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::store::IterableMap;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::serde_json::{self, json};
use near_sdk::{
    env, ext_contract, near, AccountId, BorshStorageKey, Gas, GasWeight, Promise,
    PromiseError,
};
use schemars::JsonSchema;

pub use crate::parsers::parse_dkim_tags;
pub use crate::verify_dkim::verify_dkim;

const OUTLAYER_CONTRACT_ID: &str = "outlayer.testnet";
// Default public encryption key for the Outlayer worker (can be overridden via contract state).
const OUTLAYER_ENCRYPTION_PUBKEY: &str = "";
// Method name returned by the Outlayer worker for encrypted DKIM verification.
const VERIFY_ENCRYPTED_EMAIL_METHOD: &str = "verify-encrypted-email";
// Minimum deposit forwarded to OutLayer (0.01 NEAR).
// OutLayer currently requires ~7.001e21 yoctoNEAR for the configured limits,
// so 1e22 yoctoNEAR provides a safe margin.
pub const MIN_DEPOSIT: u128 = 10_000_000_000_000_000_000_000;

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    VerificationResultsByRequestId,
}

#[near(contract_state)]
pub struct EmailDkimVerifier {
    outlayer_encryption_public_key: String,
    verification_results_by_request_id: IterableMap<String, StoredVerificationResult>,
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
pub struct StoredVerificationResult {
    result: VerificationResult,
    created_at_ms: u64,
}

#[ext_contract(ext_outlayer)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct WorkerResponse {
    method: String,
    params: serde_json::Value,
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct VerifyParams {
    verified: bool,
    account_id: String,
    new_public_key: String,
    from_address: String,
    email_timestamp_ms: Option<u64>,
    #[serde(default)]
    request_id: Option<String>,
    error: Option<String>,
}


#[near]
impl EmailDkimVerifier {
    #[init]
    pub fn new() -> Self {
        Self {
            outlayer_encryption_public_key: OUTLAYER_ENCRYPTION_PUBKEY.to_string(),
            verification_results_by_request_id: IterableMap::new(
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
        self.verification_results_by_request_id
            .get(&request_id)
            .map(|stored| stored.result.clone())
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
            (None, Some(blob)) => {
                self.request_email_verification_private_inner(payer_account_id, blob, params)
            }
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
        onchain_verify::request_email_verification_onchain_inner(
            self,
            payer_account_id,
            email_blob,
            params,
        )
    }

    fn request_email_verification_private_inner(
        &mut self,
        payer_account_id: AccountId,
        encrypted_email_blob: serde_json::Value,
        params: Option<serde_json::Value>,
    ) -> Promise {
        tee_verify::request_email_verification_private_inner(
            self,
            payer_account_id,
            encrypted_email_blob,
            params,
        )
    }

    #[private]
    pub fn on_email_verification_onchain_result(
        &mut self,
        requested_by: AccountId,
        email_blob: String,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> VerificationResult {
        onchain_verify::on_email_verification_onchain_result(self, requested_by, email_blob, result)
    }

    #[private]
    pub fn on_email_verification_private_result(
        &mut self,
        requested_by: AccountId,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> VerificationResult {
        tee_verify::on_email_verification_private_result(self, requested_by, result)
    }

    /// Private test-only helper used from near-workspaces integration tests.
    ///
    /// Stores a dummy `VerificationResult` for the given `request_id` and
    /// schedules automatic cleanup via `promise_yield_create`, exercising the
    /// same path as real Outlayer callbacks.
    #[private]
    pub fn test_store_verification_result_with_yield(&mut self, request_id: String) {
        let vr = VerificationResult {
            verified: false,
            account_id: String::new(),
            new_public_key: String::new(),
            from_address: String::new(),
            email_timestamp_ms: None,
        };
        let request_id_opt = if request_id.is_empty() {
            None
        } else {
            Some(request_id)
        };
        self.store_verification_result_if_needed(&request_id_opt, &vr);
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
        self.verification_results_by_request_id
            .insert(id.clone(), entry);

        // Schedule automatic cleanup via yield-resume after ~200 blocks.
        // The runtime will invoke clear_verification_result(request_id) later,
        // so the entry remains available for polling until then.
        let args = serde_json::to_vec(&json!({ "request_id": id })).unwrap_or_default();
        // We don't need the data_id, so we use a dummy register index (0) and ignore its contents.
        env::promise_yield_create(
            "clear_verification_result",
            &args,
            Gas::from_tgas(8),
            GasWeight(0),
            0,
        );
    }
}

/// Helper for inserting a verification result without scheduling a yield promise.
/// Used by tests; not exported as a NEAR method because it lives outside
/// the #[near] impl block.
impl EmailDkimVerifier {
    pub fn store_verification_result_for_testing(
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
        self.verification_results_by_request_id
            .insert(id.clone(), entry);
    }
}
