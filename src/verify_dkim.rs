use base64;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::RsaPublicKey;

use crate::parsers::{
    build_canonicalized_dkim_header_relaxed, canonicalize_body_relaxed,
    canonicalize_headers_relaxed, parse_dkim_tags, parse_headers, split_headers_body,
};

pub fn verify_dkim(email_blob: &str, dns_records: &[String]) -> bool {
    let (raw_headers, body) = split_headers_body(email_blob);
    let headers = parse_headers(raw_headers);

    let dkim_values: Vec<String> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("DKIM-Signature"))
        .map(|(_, v)| v.clone())
        .collect();

    if dkim_values.is_empty() {
        return false;
    }

    'signatures: for dkim_value in dkim_values {
        let tags = parse_dkim_tags(&dkim_value);

        if let Some(v) = tags.get("v") {
            if v != "1" {
                continue 'signatures;
            }
        }

        let d = match tags.get("d") {
            Some(v) if !v.is_empty() => v,
            _ => continue 'signatures,
        };
        let s = match tags.get("s") {
            Some(v) if !v.is_empty() => v,
            _ => continue 'signatures,
        };

        let _ = (d, s);

        match tags.get("a").map(String::as_str) {
            Some("rsa-sha256") => {}
            _ => continue 'signatures,
        }

        let canon = tags.get("c").map(String::as_str).unwrap_or("simple/simple");
        if canon != "relaxed/relaxed" {
            continue 'signatures;
        }

        let bh_b64 = match tags.get("bh") {
            Some(v) if !v.is_empty() => v,
            _ => continue 'signatures,
        };
        let bh_clean: String = bh_b64
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .collect();
        let bh = match base64::decode(&bh_clean) {
            Ok(v) => v,
            Err(_) => continue 'signatures,
        };

        let b_b64 = match tags.get("b") {
            Some(v) if !v.is_empty() => v,
            _ => continue 'signatures,
        };
        let b_clean: String = b_b64
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .collect();
        let signature = match base64::decode(&b_clean) {
            Ok(v) => v,
            Err(_) => continue 'signatures,
        };

        let h_list = match tags.get("h") {
            Some(v) if !v.is_empty() => v,
            _ => continue 'signatures,
        };
        let signed_headers: Vec<String> =
            h_list.split(':').map(|s| s.trim().to_ascii_lowercase()).collect();

        let canon_body = canonicalize_body_relaxed(body);
        let body_bytes = canon_body.as_bytes();
        let body_to_hash: &[u8] = if let Some(l_str) = tags.get("l") {
            let l_val = match l_str.parse::<u128>() {
                Ok(v) => v,
                Err(_) => continue 'signatures,
            };
            if l_val > body_bytes.len() as u128 {
                continue 'signatures;
            }
            &body_bytes[..(l_val as usize)]
        } else {
            body_bytes
        };

        let mut hasher = Sha256::new();
        hasher.update(body_to_hash);
        let computed_bh = hasher.finalize().to_vec();
        if computed_bh != bh {
            continue 'signatures;
        }

        let canon_headers = canonicalize_headers_relaxed(&headers, &signed_headers);
        let canon_dkim_header = build_canonicalized_dkim_header_relaxed(&dkim_value);
        let mut data = canon_headers;
        data.push_str(&canon_dkim_header);

        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let data_hash = hasher.finalize().to_vec();

        let mut pk_bytes_opt = None;
        for rec in dns_records {
            let key_tags = parse_dkim_tags(rec);

            if let Some(v) = key_tags.get("v") {
                if v != "DKIM1" {
                    continue;
                }
            }
            if let Some(k) = key_tags.get("k") {
                if k.to_ascii_lowercase() != "rsa" {
                    continue;
                }
            }

            if let Some(p) = key_tags.get("p") {
                if p.is_empty() {
                    continue;
                }
                if let Ok(bytes) = base64::decode(p) {
                    pk_bytes_opt = Some(bytes);
                    break;
                }
            }
        }
        let pk_bytes = match pk_bytes_opt {
            Some(v) => v,
            None => continue 'signatures,
        };

        let public_key = match RsaPublicKey::from_public_key_der(&pk_bytes) {
            Ok(k) => k,
            Err(_) => continue 'signatures,
        };

        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let sig = match RsaSignature::try_from(signature.as_slice()) {
            Ok(s) => s,
            Err(_) => continue 'signatures,
        };

        if verifying_key.verify_prehash(&data_hash, &sig).is_ok() {
            return true;
        }
    }

    false
}

