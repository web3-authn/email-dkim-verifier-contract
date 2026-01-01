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
use sha2::{Digest, Sha256};

// Method names
const GET_DNS_RECORDS_METHOD: &str = "get-dns-records";
const VERIFY_ENCRYPTED_EMAIL_METHOD: &str = "verify-encrypted-email";
const GET_PUBLIC_KEY_METHOD: &str = "get-public-key";

#[derive(Deserialize)]
pub struct RequestType {
    /// Name of the operation to perform (e.g. "get-dns-records", "verify-encrypted-email").
    pub method: String,
    /// Arbitrary JSON payload interpreted based on `method`.
    pub args: Value,
}

#[derive(Serialize)]
pub struct ResponseType {
    /// Mirrors the incoming `method`
    pub method: String,
    /// Method-specific response payload.
    pub response: Value,
}

impl ResponseType {
    /// Convenience helper for building `verify-encrypted-email` error responses with
    /// a consistent shape.
    fn error(
        request_id: String,
        error: impl Into<String>,
        context: Option<Value>,
    ) -> Self {
        ResponseType {
            method: VERIFY_ENCRYPTED_EMAIL_METHOD.to_string(),
            response: serde_json::json!({
                "verified": false,
                "account_id": "",
                "new_public_key": "",
                "from_address_hash": Vec::<u8>::new(),
                "email_timestamp_ms": Option::<u64>::None,
                "request_id": request_id,
                "error": error.into(),
                "context": context.unwrap_or(Value::Null),
            }),
        }
    }
}

#[derive(Deserialize)]
struct DnsLookupArgs {
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
        GET_DNS_RECORDS_METHOD => handle_dns_lookup(request.args),
        VERIFY_ENCRYPTED_EMAIL_METHOD => handle_verify_encrypted_dkim(request.args),
        GET_PUBLIC_KEY_METHOD => handle_get_public_key(),
        other => ResponseType {
            method: other.to_string(),
            response: serde_json::json!({
                "error": format!("unknown method: {other}"),
            }),
        },
    }
}

fn default_record_type() -> String {
    "TXT".to_string()
}

fn handle_dns_lookup(args: Value) -> ResponseType {
    let args_parsed: Result<DnsLookupArgs, _> = serde_json::from_value(args);
    let DnsLookupArgs {
        email_blob,
        name,
        record_type,
    } = match args_parsed {
        Ok(p) => p,
        Err(e) => {
            return ResponseType {
                method: GET_DNS_RECORDS_METHOD.to_string(),
                response: serde_json::json!({
                    "error": format!("invalid {GET_DNS_RECORDS_METHOD} args: {e}"),
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
        response: serde_json::to_value(result).unwrap_or_else(|_| serde_json::json!({})),
    }
}

fn handle_verify_encrypted_dkim(args: Value) -> ResponseType {
    #[derive(Deserialize)]
    struct VerifyArgs {
        encrypted_email_blob: EncryptedEmailEnvelope,
        #[serde(default)]
        context: Value, // forwarded directly from contract `args.context` as worker `context` (AEAD AAD)
        #[serde(default)]
        request_id: String,
    }

    let request_id_hint = args
        .get("request_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let args_parsed: Result<VerifyArgs, _> = serde_json::from_value(args);
    let verify_args = match args_parsed {
        Ok(a) => a,
        Err(e) => {
            return ResponseType::error(
                request_id_hint,
                format!("invalid {VERIFY_ENCRYPTED_EMAIL_METHOD} args: {e}"),
                None,
            );
        }
    };

    let request_id_hint = if verify_args.request_id.trim().is_empty() {
        request_id_hint
    } else {
        verify_args.request_id.clone()
    };

    // Pass the JSON `context` object to crypto; it will be serialized with
    // serde_json and used as ChaCha20‑Poly1305 AAD. The SDK constructs this
    // context with keys in alphabetical order to match serde's canonical form.
    let decrypted_email = match decrypt_encrypted_email(
        &verify_args.encrypted_email_blob,
        &verify_args.context,
    ) {
        Ok(e) => e,
        Err(e) => {
            return ResponseType::error(
                request_id_hint,
                e,
                Some(verify_args.context),
            );
        }
    };

    let subject = extract_header_value(&decrypted_email, "Subject");
    let request_id_from_email = subject
        .as_deref()
        .and_then(parse_recover_request_id)
        .unwrap_or_default();
    let request_id = if request_id_from_email.trim().is_empty() {
        request_id_hint
    } else {
        request_id_from_email
    };

    let (selector, domain) = match extract_dkim_selector_and_domain(&decrypted_email) {
        Ok(v) => v,
        Err(e) => {
            return ResponseType::error(request_id, e, None);
        }
    };

    let name = format!("{}._domainkey.{}", selector, domain);
    let dns_records = match fetch_txt_records(&name) {
        Ok(records) => records,
        Err(e) => {
            return ResponseType::error(request_id, e, None);
        }
    };

    if dns_records.is_empty() {
        return ResponseType::error(
            request_id,
            "no DKIM DNS records found",
            None,
        );
    }

    let verified = verify_dkim(&decrypted_email, &dns_records);

    if !verified {
        return ResponseType::error(
            request_id,
            "DKIM verification failed",
            None,
        );
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

    let email_timestamp_ms = parse_email_timestamp_ms(&decrypted_email);

    let canonical_from = parse_from_address(&decrypted_email).trim().to_lowercase();
    let salt = verify_args
        .context
        .get("account_id")
        .and_then(|v| v.as_str())
        .unwrap_or(account_id.as_str())
        .trim()
        .to_lowercase();
    let from_address_hash = if canonical_from.is_empty() || salt.is_empty() {
        Vec::<u8>::new()
    } else {
        let input = format!("{canonical_from}|{salt}");
        let digest = Sha256::digest(input.as_bytes());
        digest.to_vec()
    };

    ResponseType {
        method: VERIFY_ENCRYPTED_EMAIL_METHOD.to_string(),
        response: serde_json::json!({
            "verified": true,
            "account_id": account_id,
            "new_public_key": new_public_key,
            "from_address_hash": from_address_hash,
            "email_timestamp_ms": email_timestamp_ms,
            "request_id": request_id,
            "error": serde_json::Value::Null,
            "context": verify_args.context,
        }),
    }
}

fn handle_get_public_key() -> ResponseType {
    match get_worker_public_key() {
        Ok(pk) => ResponseType {
            method: GET_PUBLIC_KEY_METHOD.to_string(),
            response: serde_json::json!({ "public_key": pk }),
        },
        Err(e) => ResponseType {
            method: GET_PUBLIC_KEY_METHOD.to_string(),
            response: serde_json::json!({ "error": e }),
        },
    }
}
