use crate::crypto::{decrypt_encrypted_email, EncryptedEmailEnvelope};
use crate::dns::fetch_txt_records;
use crate::parsers::{
    extract_dkim_selector_and_domain, extract_header_value, parse_email_timestamp_ms,
    parse_from_address, parse_recover_instruction, parse_recover_public_key_from_body,
    parse_recover_subject,
};
use crate::verify_dkim::verify_dkim;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
        "get-dns-records" => handle_dns_lookup(request.params),
        "verify-encrypted-email" => handle_verify_encrypted_dkim(request.params),
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
                method: "get-dns-records".to_string(),
                params: serde_json::json!({
                    "error": format!("invalid get-dns-records params: {e}"),
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
        error = Some("get-dns-records requires either `name` or `email_blob`".to_string());
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
                    "unsupported DNS record type for get-dns-records: {other}"
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
        method: "get-dns-records".to_string(),
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
                method: "verify-encrypted-email".to_string(),
                params: serde_json::json!({
                    "verified": false,
                    "account_id": "",
                    "new_public_key": "",
                    "from_address": "",
                    "email_timestamp_ms": null,
                    "error": format!("invalid verify-encrypted-email params: {e}"),
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
                method: "verify-encrypted-email".to_string(),
                params: serde_json::json!({
                    "verified": false,
                    "account_id": "",
                    "new_public_key": "",
                    "from_address": "",
                    "email_timestamp_ms": null,
                    "error": e,
                }),
            }
        }
    };

    let (selector, domain) = match extract_dkim_selector_and_domain(&decrypted_email) {
        Ok(v) => v,
        Err(e) => {
            return ResponseType {
                method: "verify-encrypted-email".to_string(),
                params: serde_json::json!({
                    "verified": false,
                    "account_id": "",
                    "new_public_key": "",
                    "from_address": "",
                    "email_timestamp_ms": Option::<u64>::None,
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
                method: "verifyEncryptedDKIM".to_string(),
                params: serde_json::json!({
                    "verified": false,
                    "account_id": "",
                    "new_public_key": "",
                    "from_address": "",
                    "email_timestamp_ms": Option::<u64>::None,
                    "error": e,
                }),
            }
        }
    };

    if dns_records.is_empty() {
        return ResponseType {
            method: "verify-encrypted-email".to_string(),
            params: serde_json::json!({
                "verified": false,
                "account_id": "",
                "new_public_key": "",
                "from_address": "",
                "email_timestamp_ms": Option::<u64>::None,
                "error": "no DKIM DNS records found",
            }),
        };
    }

    let verified = verify_dkim(&decrypted_email, &dns_records);

    if !verified {
        return ResponseType {
            method: "verify-encrypted-email".to_string(),
            params: serde_json::json!({
                "verified": false,
                "account_id": "",
                "new_public_key": "",
                "from_address": "",
                "email_timestamp_ms": Option::<u64>::None,
                "error": "DKIM verification failed",
            }),
        };
    }

    let subject = extract_header_value(&decrypted_email, "Subject");
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
        method: "verify-encrypted-email".to_string(),
        params: serde_json::json!({
            "verified": true,
            "account_id": account_id,
            "new_public_key": new_public_key,
            "from_address": from_address,
            "email_timestamp_ms": email_timestamp_ms,
            "error": serde_json::Value::Null,
        }),
    }
}
