use crate::crypto::{decrypt_encrypted_email, get_worker_public_key, EncryptedEmailEnvelope};
use crate::dns::fetch_txt_records;
use crate::parsers::{
    extract_dkim_selector_and_domain, extract_header_value, parse_email_timestamp_ms,
    parse_from_address, parse_recover_instruction, parse_recover_public_key_from_body,
    parse_recover_request_id, parse_recover_subject,
};
use crate::verify_dkim::verify_dkim;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Method name for plaintext DNS lookup requests from the contract.
const GET_DNS_RECORDS_METHOD: &str = "get-dns-records";
// Method name for encrypted DKIM verification; must match the contract.
const VERIFY_ENCRYPTED_EMAIL_METHOD: &str = "verify-encrypted-email";
const GET_PUBLIC_KEY_METHOD: &str = "get-public-key";

#[derive(Deserialize)]
pub struct RequestType {
    /// Name of the operation to perform (e.g. "get-dns-records", "verify-encrypted-email").
    pub method: String,
    /// Arbitrary JSON payload interpreted based on `method`.
    pub params: Value,
}

#[derive(Serialize)]
pub struct ResponseType {
    /// Mirrors the incoming `method`
    pub method: String,
    /// Method-specific response payload.
    pub params: Value,
}

#[derive(Deserialize)]
struct DnsLookupParams {
    email_blob: Option<String>,
    name: Option<String>,
    #[serde(default = "default_record_type", rename = "type")]
    record_type: String,
}

#[derive(Serialize)]
struct DnsLookupResult {
    selector: Option<String>,
    domain: Option<String>,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    records: Vec<String>,
    error: Option<String>,
}

pub fn handle_request(request: RequestType) -> ResponseType {
    match request.method.as_str() {
        GET_DNS_RECORDS_METHOD => handle_dns_lookup(request.params),
        VERIFY_ENCRYPTED_EMAIL_METHOD => handle_verify_encrypted_dkim(request.params),
        GET_PUBLIC_KEY_METHOD => handle_get_public_key(),
        other => ResponseType {
            method: other.to_string(),
            params: serde_json::json!({
                "error": format!("unknown method: {other}"),
            }),
        },
    }
}

fn default_record_type() -> String {
    "TXT".to_string()
}

fn handle_dns_lookup(params: Value) -> ResponseType {
    let parsed: Result<DnsLookupParams, _> = serde_json::from_value(params);
    let DnsLookupParams {
        email_blob,
        name,
        record_type,
    } = match parsed {
        Ok(p) => p,
        Err(e) => {
            return ResponseType {
                method: GET_DNS_RECORDS_METHOD.to_string(),
                params: serde_json::json!({
                    "error": format!("invalid {GET_DNS_RECORDS_METHOD} params: {e}"),
                    "records": Vec::<String>::new(),
                }),
            }
        }
    };

    let mut error: Option<String> = None;
    let mut selector: Option<String> = None;
    let mut domain: Option<String> = None;

    let name = if let Some(name) = name {
        name
    } else if let Some(email) = email_blob {
        match extract_dkim_selector_and_domain(&email) {
            Ok((s, d)) => {
                selector = Some(s.clone());
                domain = Some(d.clone());
                format!("{}._domainkey.{}", s, d)
            }
            Err(e) => {
                error = Some(e);
                String::new()
            }
        }
    } else {
        error = Some(format!(
            "{GET_DNS_RECORDS_METHOD} requires either `name` or `email_blob`"
        ));
        String::new()
    };

    let records = match record_type.as_str() {
        "TXT" if !name.is_empty() && error.is_none() => match fetch_txt_records(&name) {
            Ok(records) => records,
            Err(e) => {
                error = Some(e);
                Vec::new()
            }
        },
        other => {
            if error.is_none() {
                error = Some(format!(
                    "unsupported DNS record type for {GET_DNS_RECORDS_METHOD}: {other}"
                ));
            }
            Vec::new()
        }
    };

    let result = DnsLookupResult {
        selector,
        domain,
        name,
        record_type,
        records,
        error,
    };

    ResponseType {
        method: GET_DNS_RECORDS_METHOD.to_string(),
        params: serde_json::to_value(result).unwrap_or_else(|_| serde_json::json!({})),
    }
}

fn handle_verify_encrypted_dkim(params: Value) -> ResponseType {
    #[derive(Deserialize)]
    struct VerifyParams {
        encrypted_email_blob: EncryptedEmailEnvelope,
        #[serde(default)]
        context: Value,
    }

    let parsed: Result<VerifyParams, _> = serde_json::from_value(params);
    let verify_params = match parsed {
        Ok(p) => p,
        Err(e) => {
            return ResponseType {
                method: VERIFY_ENCRYPTED_EMAIL_METHOD.to_string(),
                params: serde_json::json!({
                    "verified": false,
                    "account_id": "",
                    "new_public_key": "",
                    "from_address": "",
                    "email_timestamp_ms": null,
                    "request_id": serde_json::Value::Null,
                    "error": format!("invalid {VERIFY_ENCRYPTED_EMAIL_METHOD} params: {e}"),
                }),
            }
        }
    };

    let decrypted_email = match decrypt_encrypted_email(
        &verify_params.encrypted_email_blob,
        &verify_params.context,
    ) {
        Ok(e) => e,
        Err(e) => {
            return ResponseType {
                method: VERIFY_ENCRYPTED_EMAIL_METHOD.to_string(),
                params: serde_json::json!({
                    "verified": false,
                    "account_id": "",
                    "new_public_key": "",
                    "from_address": "",
                    "email_timestamp_ms": null,
                    "request_id": serde_json::Value::Null,
                    "error": e,
                }),
            }
        }
    };

    let subject = extract_header_value(&decrypted_email, "Subject");
    let request_id = subject.as_deref().and_then(parse_recover_request_id);

    let (selector, domain) = match extract_dkim_selector_and_domain(&decrypted_email) {
        Ok(v) => v,
        Err(e) => {
            return ResponseType {
                method: VERIFY_ENCRYPTED_EMAIL_METHOD.to_string(),
                params: serde_json::json!({
                    "verified": false,
                    "account_id": "",
                    "new_public_key": "",
                    "from_address": "",
                    "email_timestamp_ms": Option::<u64>::None,
                    "request_id": request_id,
                    "error": e,
                }),
            }
        }
    };

    let name = format!("{}._domainkey.{}", selector, domain);
    let dns_records = match fetch_txt_records(&name) {
        Ok(records) => records,
        Err(e) => {
            return ResponseType {
                method: VERIFY_ENCRYPTED_EMAIL_METHOD.to_string(),
                params: serde_json::json!({
                    "verified": false,
                    "account_id": "",
                    "new_public_key": "",
                    "from_address": "",
                    "email_timestamp_ms": Option::<u64>::None,
                    "request_id": request_id,
                    "error": e,
                }),
            }
        }
    };

    if dns_records.is_empty() {
        return ResponseType {
            method: VERIFY_ENCRYPTED_EMAIL_METHOD.to_string(),
            params: serde_json::json!({
                "verified": false,
                "account_id": "",
                "new_public_key": "",
                "from_address": "",
                "email_timestamp_ms": Option::<u64>::None,
                "request_id": request_id,
                "error": "no DKIM DNS records found",
            }),
        };
    }

    let verified = verify_dkim(&decrypted_email, &dns_records);

    if !verified {
        return ResponseType {
            method: VERIFY_ENCRYPTED_EMAIL_METHOD.to_string(),
            params: serde_json::json!({
                "verified": false,
                "account_id": "",
                "new_public_key": "",
                "from_address": "",
                "email_timestamp_ms": Option::<u64>::None,
                "request_id": request_id,
                "error": "DKIM verification failed",
            }),
        };
    }

    let (account_id, new_public_key) = if let Some(s) = subject.as_deref() {
        if let Some((acc, pk)) = parse_recover_instruction(s) {
            (acc, pk)
        } else {
            let acc = parse_recover_subject(s).unwrap_or_default();
            let pk = parse_recover_public_key_from_body(&decrypted_email).unwrap_or_default();
            (acc, pk)
        }
    } else {
        let pk = parse_recover_public_key_from_body(&decrypted_email).unwrap_or_default();
        (String::new(), pk)
    };

    let from_address = parse_from_address(&decrypted_email);
    let email_timestamp_ms = parse_email_timestamp_ms(&decrypted_email);

    ResponseType {
        method: VERIFY_ENCRYPTED_EMAIL_METHOD.to_string(),
        params: serde_json::json!({
            "verified": true,
            "account_id": account_id,
            "new_public_key": new_public_key,
            "from_address": from_address,
            "email_timestamp_ms": email_timestamp_ms,
            "request_id": request_id,
            "error": serde_json::Value::Null,
        }),
    }
}

fn handle_get_public_key() -> ResponseType {
    match get_worker_public_key() {
        Ok(pk) => ResponseType {
            method: GET_PUBLIC_KEY_METHOD.to_string(),
            params: serde_json::json!({ "public_key": pk }),
        },
        Err(e) => ResponseType {
            method: GET_PUBLIC_KEY_METHOD.to_string(),
            params: serde_json::json!({ "error": e }),
        },
    }
}

