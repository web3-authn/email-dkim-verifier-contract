use near_sdk::{env, ext_contract, near, AccountId, NearToken, Promise, PromiseError};
use near_sdk::serde_json::{self, json};

mod parsers;

pub use crate::parsers::{parse_dkim_tags, verify_dkim};

const OUTLAYER_CONTRACT_ID: &str = "outlayer.testnet";
const MIN_DEPOSIT: u128 = 10_000_000_000_000_000_000_000;

#[near(contract_state)]
pub struct EmailDkimVerifier;

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
    fn on_email_verification_result(
        &mut self,
        requested_by: AccountId,
        email_blob: String,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> bool;
}

#[near]
impl EmailDkimVerifier {
    #[init]
    pub fn new() -> Self {
        Self
    }

    #[payable]
    pub fn request_email_verification(
        &mut self,
        email_blob: String,
        params: Option<serde_json::Value>,
    ) -> Promise {
        let caller = env::predecessor_account_id();
        let attached = env::attached_deposit().as_yoctonear();
        assert!(
            attached >= MIN_DEPOSIT,
            "Attach at least 0.01 NEAR for Outlayer execution"
        );

        let input_payload = json!({
            "email_blob": email_blob,
            "params": params.unwrap_or_else(|| json!({})),
        })
        .to_string();

        // OutLayer currently expects a typed `CodeSource` enum with variants
        // `GitHub` and `WasmUrl`. Wrap the GitHub source in the `GitHub`
        // variant to match that schema.
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
            .with_attached_deposit(NearToken::from_yoctonear(attached))
            .with_unused_gas_weight(1)
            .request_execution(
                code_source,
                resource_limits,
                input_payload,
                None,
                "Json".to_string(),
                Some(caller.clone()),
            )
            .then(
                ext_self::ext(env::current_account_id())
                    .with_unused_gas_weight(1)
                    .on_email_verification_result(caller, email_blob),
            )
    }

    #[private]
    pub fn on_email_verification_result(
        &mut self,
        requested_by: AccountId,
        email_blob: String,
        #[callback_result] result: Result<Option<serde_json::Value>, PromiseError>,
    ) -> bool {
        let _ = requested_by;
        let value = match result {
            Ok(Some(v)) => v,
            _ => return false,
        };

        if let Some(err) = value.get("error").and_then(|v| v.as_str()) {
            env::log_str(&format!("DKIM DNS fetch error: {err}"));
            return false;
        }

        let records = value
            .get("records")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let record_strings: Vec<String> = records
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        if record_strings.is_empty() {
            return false;
        }

        verify_dkim(&email_blob, &record_strings)
    }
}

impl Default for EmailDkimVerifier {
    fn default() -> Self {
        env::panic_str("Contract is not initialized");
    }
}
