use base64;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::RsaPublicKey;

use crate::parsers::{
    build_canonicalized_dkim_header_relaxed,
    canonicalize_body_relaxed,
    canonicalize_headers_relaxed,
    parse_dkim_header,
    parse_dkim_tags,
    parse_headers,
    split_headers_body,
};

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
    // Some implementations insert folding whitespace inside base64-encoded values.
    // Strip any non-base64 characters before decoding.
    let bh_clean: String = bh_b64
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();
    let bh = match base64::decode(&bh_clean) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let b_b64 = match tags.get("b") {
        Some(v) => v,
        None => return false,
    };
    let b_clean: String = b_b64
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();
    let signature = match base64::decode(&b_clean) {
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

    // Interpret the DKIM p= value as a DER-encoded SubjectPublicKeyInfo (SPKI).
    let public_key = match RsaPublicKey::from_public_key_der(&pk_bytes) {
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

    fn real_gmail_dns_records() -> Vec<String> {
        vec!["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB".to_string()]
    }

    #[test]
    fn modifying_subject_breaks_dkim() {
        let email_blob = include_str!("../tests/data/gmail_reset_full.eml");
        let modified = email_blob.replacen(
            "Subject: reset|bob.near|ed25519:xxxxxxxxxxxyz",
            "Subject: reset|alice.near|ed25519:xxxxxxxxxxxyz",
            1,
        );
        assert!(!verify_dkim(&modified, &real_gmail_dns_records()));
    }

    #[test]
    fn modifying_body_plain_text_breaks_dkim() {
        let email_blob = include_str!("../tests/data/gmail_reset_full.eml");
        // Change the plain-text body content.
        let modified = email_blob.replacen("test9", "test9-modified", 1);
        assert!(!verify_dkim(&modified, &real_gmail_dns_records()));
    }

    #[test]
    fn modifying_from_breaks_dkim() {
        let email_blob = include_str!("../tests/data/gmail_reset_full.eml");
        let modified = email_blob.replacen(
            "From: Pta <n6378056@gmail.com>",
            "From: Mallory <mallory@example.com>",
            1,
        );
        assert!(!verify_dkim(&modified, &real_gmail_dns_records()));
    }
}
