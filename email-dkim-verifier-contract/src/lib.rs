pub mod onchain_verify;
pub mod tee_verify;

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::store::IterableMap;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::serde_json::{self, json};
use near_sdk::{
    env, ext_contract, near, AccountId, BorshStorageKey, Gas, GasWeight, Promise,
    PromiseError,
};
use schemars::JsonSchema;
use tee_verify::AeadContext;

const OUTLAYER_CONTRACT_ID: &str = "outlayer.testnet";
// Git commit hash of the Outlayer WASI worker to execute.
const OUTLAYER_WORKER_COMMIT: &str = "main";
// Default public encryption key for the Outlayer worker (can be overridden via contract state).
const OUTLAYER_ENCRYPTION_PUBKEY: &str = "";
// Minimum deposit forwarded to OutLayer (0.01 NEAR).
pub const MIN_DEPOSIT: u128 = 10_000_000_000_000_000_000_000;
// Account which set the secrets in https://outlayer.fastnear.com/secrets
pub const SECRETS_OWNER_ID: &str = "email-dkim-verifier-v1.testnet";
pub const SECRETS_PROFILE: &str = "main";

// Method names on Outlayer worker
pub const GET_DNS_RECORDS_METHOD: &str = "get-dns-records";
pub const VERIFY_ENCRYPTED_EMAIL_METHOD: &str = "verify-encrypted-email";
pub const GET_PUBLIC_KEY_METHOD: &str = "get-public-key";


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
    pub request_id: String,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct StoredVerificationResult {
    result: VerificationResult,
    created_at_ms: u64,
}

#[derive(near_sdk::serde::Serialize, near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct SecretsReference {
    profile: String,
    account_id: AccountId,
}

#[derive(near_sdk::serde::Serialize, near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct ExecutionParams {
    force_rebuild: bool,
    compile_only: bool,
    store_on_fastfs: bool,
}

/// OutLayer interface for `request_execution`.
///
/// Important: The parameter *names* here (`code_source`, `resource_limits`, `input_data`,
/// `secrets_ref`, `response_format`, `payer_account_id`, `params`) become the JSON
/// field names that OutLayer sees. Near SDK's `#[ext_contract]` macro uses these
/// identifiers when serializing arguments, so a Rust call like:
///
/// ```ignore
/// ext_outlayer::ext(outlayer_account)
///     .request_execution(
///         code_source,
///         resource_limits,
///         input_payload,
///         Some(secrets),
///         "Json".to_string(),
///         None,
///         Some(params),
///     );
/// ```
///
/// is equivalent on chain to the CLI example from the OutLayer docs:
/// ```text
/// near call outlayer.testnet request_execution '{
///   "code_source": { ... },
///   "resource_limits": { ... },
///   "input_data": "{...}",
///   "secrets_ref": { "profile": "...", "account_id": "..." },
///   "response_format": "Json",
///   "payer_account_id": null,
///   "params": { "force_rebuild": true, "compile_only": false, "store_on_fastfs": false }
/// }' --accountId <caller> --deposit <yoctoNEAR>
/// ```
#[ext_contract(ext_outlayer)]
#[allow(dead_code)]
trait OutLayer {
    fn request_execution(
        &mut self,
        code_source: serde_json::Value,
        resource_limits: serde_json::Value,
        input_data: String,
        secrets_ref: Option<SecretsReference>,
        response_format: String,
        payer_account_id: Option<AccountId>,
        params: Option<ExecutionParams>,
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

    fn on_worker_public_key_result(
        &mut self,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    );
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct OutlayerWorkerResponse {
    method: String,
    response: serde_json::Value,
}

/// Payload sent to the Outlayer WASI worker over `stdin`.
///
/// This must match the worker's `RequestType` shape:
/// `{ "method": "<name>", "args": { ... } }`.
#[derive(near_sdk::serde::Serialize)]
#[serde(crate = "near_sdk::serde")]
pub struct OutlayerInputArgs {
    method: String,
    args: serde_json::Value,
}

impl OutlayerInputArgs {
    pub fn new(method: impl Into<String>, args: serde_json::Value) -> Self {
        Self {
            method: method.into(),
            args,
        }
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).expect("OutlayerInputArgs must serialize to JSON")
    }
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

    #[payable]
    pub fn set_outlayer_encryption_public_key(&mut self) -> Promise {
        assert_eq!(env::predecessor_account_id(), env::current_account_id(),
            "Only the contract owner can set the Outlayer encryption public key");

        let attached = env::attached_deposit().as_yoctonear();
        assert!(attached >= MIN_DEPOSIT,
            "Attach at least 0.01 NEAR for Outlayer execution");

        let code_source = serde_json::json!({
            "GitHub": {
                "repo": "github.com/web3-authn/email-dkim-verifier-contract",
                "commit": OUTLAYER_WORKER_COMMIT,
                "build_target": "wasm32-wasip2",
            }
        });

        let resource_limits = serde_json::json!({
            "max_instructions": 10_000_000_000u64,
            "max_memory_mb": 256u64,
            "max_execution_seconds": 60u64
        });

        let input_payload = OutlayerInputArgs::new(
            GET_PUBLIC_KEY_METHOD,
            serde_json::json!({})
        ).to_json_string();

        let secrets = SecretsReference {
            profile: SECRETS_PROFILE.to_string(),
            account_id: SECRETS_OWNER_ID.parse().unwrap(),
        };

        let params = ExecutionParams {
            force_rebuild: true,
            compile_only: false,
            store_on_fastfs: false,
        };

        ext_outlayer::ext(OUTLAYER_CONTRACT_ID.parse().unwrap())
            .with_attached_deposit(near_sdk::NearToken::from_yoctonear(MIN_DEPOSIT))
            .with_unused_gas_weight(1)
            .request_execution(
                code_source,
                resource_limits,
                input_payload,
                Some(secrets),
                "Json".to_string(),
                None, // payer_id
                Some(params),
            )
            .then(
                ext_self::ext(env::current_account_id())
                    .with_unused_gas_weight(1)
                    .on_worker_public_key_result(),
            )
    }

    #[private]
    pub fn on_worker_public_key_result(
        &mut self,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) {
        match result {
            Ok(Some(val)) => {
                let response: OutlayerWorkerResponse = serde_json::from_value(val)
                    .expect("Failed to parse worker response");

                if response.method != GET_PUBLIC_KEY_METHOD {
                     env::panic_str(&format!("Unexpected method: {}", response.method));
                }

                let pubkey_str = response.response
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .expect("Response missing public_key")
                    .to_string();

                self.outlayer_encryption_public_key = pubkey_str;
            }
            Ok(None) => env::panic_str("Worker returned empty result"),
            Err(_) => env::panic_str("Worker execution failed"),
        }
    }

    pub fn get_verification_result(&self, request_id: String) -> Option<VerificationResult> {
        self.verification_results_by_request_id
            .get(&request_id)
            .map(|stored| stored.result.clone())
    }

    /// @params
    /// - `payer_account_id`: Account that pays for the Outlayer execution.
    /// - `encrypted_email_blob`: encrypted email envelope.
    /// - `aead_context`:
    ///   - forwarded to the worker (used for ChaCha20-Poly1305 AEAD AAD in decrypting email).
    ///   - context fields must follow alphabetization:
    ///     { "account_id": "...", "network_id": "...", "payer_account_id": "..." }`
    ///
    /// @returns
    /// - A `Promise` that resolves to `VerificationResult`
    #[payable]
    pub fn request_email_verification_private(
        &mut self,
        payer_account_id: AccountId,
        encrypted_email_blob: serde_json::Value,
        aead_context: AeadContext,
    ) -> Promise {
        tee_verify::request_email_verification_private_inner(
            self,
            payer_account_id,
            encrypted_email_blob,
            aead_context,
        )
    }

    /// @deprecated Public Onchain Email DKIM verifier.
    /// User for legacy testing purposes.
    /// @params
    /// - `payer_account_id`: Account that pays for the Outlayer execution.
    /// - `email_blob`: Plaintext RFC‑5322 email: for on‑chain DKIM verification.
    /// @returns
    /// - A `Promise` that resolves to `VerificationResult`
    #[payable]
    pub fn request_email_verification_onchain(
        &mut self,
        payer_account_id: AccountId,
        email_blob: String,
    ) -> Promise {
        onchain_verify::request_email_verification_onchain_inner(
            self,
            payer_account_id,
            email_blob,
        )
    }

    fn store_verification_result(&mut self, request_id: &str, result: &VerificationResult) {
        if request_id.is_empty() {
            return;
        }

        let id = request_id.to_string();

        let entry = StoredVerificationResult {
            result: result.clone(),
            created_at_ms: env::block_timestamp() / 1_000_000,
        };
        self.verification_results_by_request_id
            .insert(id.clone(), entry);

        // Schedule automatic cleanup via yield-resume after ~200 blocks (~2min).
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

    #[private]
    pub fn clear_verification_result(&mut self, request_id: String) {
        self.verification_results_by_request_id.remove(&request_id);
    }

    /// Private test-only helper used from near-workspaces integration tests.
    /// Stores a dummy `VerificationResult` for the given `request_id` and
    /// schedules automatic cleanup via `promise_yield_create`
    #[private]
    pub fn test_store_verification_result_with_yield(&mut self, request_id: String) {
        let vr = VerificationResult {
            verified: false,
            account_id: String::new(),
            new_public_key: String::new(),
            from_address: String::new(),
            email_timestamp_ms: None,
            request_id: request_id.clone(),
        };
        self.store_verification_result(&request_id, &vr);
    }
}

impl Default for EmailDkimVerifier {
    fn default() -> Self {
        env::panic_str("Contract is not initialized");
    }
}
