use base64;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::RsaPublicKey;

fn split_headers_body(email: &str) -> (&str, &str) {
    if let Some(idx) = email.find("\r\n\r\n") {
        let (h, rest) = email.split_at(idx);
        let body = &rest[4..];
        (h, body)
    } else if let Some(idx) = email.find("\n\n") {
        let (h, rest) = email.split_at(idx);
        let body = &rest[2..];
        (h, body)
    } else {
        (email, "")
    }
}

fn parse_headers(raw_headers: &str) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_value = String::new();

    for line in raw_headers.split("\r\n") {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if current_name.is_some() {
                current_value.push_str("\r\n");
                current_value.push_str(line);
            }
        } else {
            if let Some(name) = current_name.take() {
                headers.push((name, current_value));
                current_value = String::new();
            }
            if let Some(pos) = line.find(':') {
                let (name, rest) = line.split_at(pos);
                current_name = Some(name.to_string());
                current_value.push_str(&rest[1..]);
            }
        }
    }

    if let Some(name) = current_name {
        headers.push((name, current_value));
    }

    headers
}

fn canonicalize_header_relaxed(value: String) -> String {
    let mut v = value.replace('\t', " ");
    v = v.replace("\r\n", " ");

    while v.ends_with(' ') {
        v.pop();
    }
    while v.starts_with(' ') {
        v.remove(0);
    }

    let mut previous_space = false;
    v.retain(|c| {
        if c == ' ' {
            if previous_space {
                false
            } else {
                previous_space = true;
                true
            }
        } else {
            previous_space = false;
            true
        }
    });

    v
}

fn canonicalize_headers_relaxed(
    headers: &[(String, String)],
    signed_headers: &[String],
) -> String {
    let mut result = String::new();
    let mut used = Vec::<usize>::new();

    for signed in signed_headers {
        for (idx, (name, value)) in headers.iter().enumerate() {
            if used.contains(&idx) {
                continue;
            }
            if name.eq_ignore_ascii_case(signed) {
                result.push_str(&name.to_ascii_lowercase());
                result.push(':');
                result.push_str(&canonicalize_header_relaxed(value.clone()));
                result.push_str("\r\n");
                used.push(idx);
                break;
            }
        }
    }

    result
}

fn canonicalize_body_relaxed(body: &str) -> String {
    let mut body = body.replace('\t', " ");

    let mut previous_space = false;
    body.retain(|c| {
        if c == ' ' {
            if previous_space {
                false
            } else {
                previous_space = true;
                true
            }
        } else {
            previous_space = false;
            true
        }
    });

    while let Some(idx) = body.find(" \r\n") {
        body.remove(idx);
    }

    while body.ends_with("\r\n\r\n") {
        body.pop();
        body.pop();
    }

    if !body.is_empty() && !body.ends_with("\r\n") {
        body.push_str("\r\n");
    }

    body
}

fn parse_dkim_header(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("DKIM-Signature"))
        .map(|(_, v)| v.clone())
}

pub fn parse_dkim_tags(value: &str) -> std::collections::HashMap<String, String> {
    let mut tags = std::collections::HashMap::new();
    let unfolded = value.replace("\r\n", " ");
    for part in unfolded.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = part.find('=') {
            let (k, v) = part.split_at(pos);
            let key = k.trim().to_ascii_lowercase();
            let val = v[1..].trim().to_string();
            tags.insert(key, val);
        }
    }
    tags
}

fn build_canonicalized_dkim_header_relaxed(value: &str) -> String {
    let unfolded = value.replace("\r\n", " ");
    let mut parts = Vec::<(String, String)>::new();

    for part in unfolded.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = part.find('=') {
            let (k, v) = part.split_at(pos);
            let key = k.trim().to_ascii_lowercase();
            let val = if key == "b" { String::new() } else { v[1..].trim().to_string() };
            parts.push((key, val));
        }
    }

    let mut reconstructed = String::new();
    for (idx, (k, v)) in parts.iter().enumerate() {
        if idx > 0 {
            reconstructed.push_str("; ");
        }
        reconstructed.push_str(k);
        reconstructed.push('=');
        reconstructed.push_str(v);
    }

    let canon_value = canonicalize_header_relaxed(reconstructed);
    format!("dkim-signature:{}", canon_value)
}

pub fn verify_dkim(email_blob: &str, dns_records: &[String]) -> bool {
    let (raw_headers, body) = split_headers_body(email_blob);
    let headers = parse_headers(raw_headers);

    let dkim_value = match parse_dkim_header(&headers) {
        Some(v) => v,
        None => return false,
    };

    let tags = parse_dkim_tags(&dkim_value);

    let algo = tags.get("a").map(String::as_str).unwrap_or("");
    if algo != "rsa-sha256" {
        return false;
    }

    let canon = tags.get("c").map(String::as_str).unwrap_or("simple/simple");
    if canon != "relaxed/relaxed" {
        return false;
    }

    let bh_b64 = match tags.get("bh") {
        Some(v) => v,
        None => return false,
    };
    let bh = match base64::decode(bh_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let b_b64 = match tags.get("b") {
        Some(v) => v,
        None => return false,
    };
    let signature = match base64::decode(b_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let h_list = match tags.get("h") {
        Some(v) => v,
        None => return false,
    };
    let signed_headers: Vec<String> =
        h_list.split(':').map(|s| s.trim().to_ascii_lowercase()).collect();

    let canon_body = canonicalize_body_relaxed(body);
    let mut hasher = Sha256::new();
    hasher.update(canon_body.as_bytes());
    let computed_bh = hasher.finalize().to_vec();
    if computed_bh != bh {
        return false;
    }

    let canon_headers = canonicalize_headers_relaxed(&headers, &signed_headers);
    let canon_dkim_header = build_canonicalized_dkim_header_relaxed(&dkim_value);
    let mut data = canon_headers;
    data.push_str(&canon_dkim_header);

    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let data_hash = hasher.finalize().to_vec();

    // Extract RSA public key bytes from the DKIM DNS records (p= tag).
    let mut pk_bytes_opt = None;
    for rec in dns_records {
        let tags = parse_dkim_tags(rec);
        if let Some(p) = tags.get("p") {
            if let Ok(bytes) = base64::decode(p) {
                pk_bytes_opt = Some(bytes);
                break;
            }
        }
    }
    let pk_bytes = match pk_bytes_opt {
        Some(v) => v,
        None => return false,
    };

    // Interpret the DKIM p= value as a PKCS#1 DER-encoded RSA public key.
    let public_key = match RsaPublicKey::from_pkcs1_der(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // Verify RSASSA-PKCS1-v1_5 with SHA-256 over the canonicalized data.
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let sig = match RsaSignature::try_from(signature.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify_prehash(&data_hash, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_dkim_without_signature_fails() {
        let email = "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nHello\r\n";
        let records: Vec<String> = Vec::new();
        assert!(!verify_dkim(email, &records));
    }
}
