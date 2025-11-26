use near_sdk::AccountId;

pub fn extract_header_value(email: &str, header_name: &str) -> Option<String> {
    let target = header_name.to_ascii_lowercase();
    let mut lines = email.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with(&format!("{target}:")) {
            let mut value = trimmed.splitn(2, ':').nth(1)?.trim().to_string();
            while let Some(next) = lines.peek() {
                if next.starts_with(' ') || next.starts_with('\t') {
                    let cont = next.trim();
                    if !cont.is_empty() {
                        value.push(' ');
                        value.push_str(cont);
                    }
                    lines.next();
                } else {
                    break;
                }
            }
            if value.is_empty() {
                return None;
            } else {
                return Some(value);
            }
        }
    }
    None
}

pub fn parse_recover_subject(subject: &str) -> Option<(AccountId, String)> {
    let subject = subject.trim();
    let mut parts = subject.split('|');

    let kind = parts.next()?;
    if kind != "recover" {
        return None;
    }

    let account_id_str = parts.next()?.trim();
    let key_str = parts.next()?.trim();

    if parts.next().is_some() {
        return None;
    }

    if !key_str.starts_with("ed25519:") {
        return None;
    }
    if key_str.len() <= "ed25519:".len() {
        return None;
    }

    let account_id: AccountId = match account_id_str.parse() {
        Ok(a) => a,
        Err(_) => return None,
    };

    Some((account_id, key_str.to_string()))
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

pub fn split_headers_body(email: &str) -> (&str, &str) {
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

pub fn parse_headers(raw_headers: &str) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_value = String::new();

    for raw_line in raw_headers.split('\n') {
        let line = raw_line.trim_end_matches('\r');
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

pub fn canonicalize_header_relaxed(value: String) -> String {
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

pub fn canonicalize_headers_relaxed(
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

pub fn canonicalize_body_relaxed(body: &str) -> String {
    // Implement relaxed body canonicalization per RFC 6376:
    // - Convert all whitespace runs within lines to a single SP.
    // - Remove trailing WSP at end of lines.
    // - Remove trailing empty lines.
    // - Ensure the body ends with a single CRLF.

    // Split on LF, normalize optional preceding CR.
    let mut lines: Vec<String> = Vec::new();
    for raw_line in body.split('\n') {
        let mut line = raw_line.trim_end_matches('\r').to_string();
        // Replace HTAB with SP.
        line = line.replace('\t', " ");
        // Remove trailing spaces.
        while line.ends_with(' ') {
            line.pop();
        }
        // Collapse WSP runs to a single SP.
        let mut out = String::new();
        let mut prev_space = false;
        for ch in line.chars() {
            if ch == ' ' {
                if !prev_space {
                    out.push(' ');
                    prev_space = true;
                }
            } else {
                out.push(ch);
                prev_space = false;
            }
        }
        lines.push(out);
    }

    // Remove trailing empty lines.
    while matches!(lines.last(), Some(l) if l.is_empty()) {
        lines.pop();
    }

    if lines.is_empty() {
        // An empty body canonicalizes to a single CRLF.
        return "\r\n".to_string();
    }

    let mut result = lines.join("\r\n");
    result.push_str("\r\n");
    result
}

pub fn parse_dkim_header(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("DKIM-Signature"))
        .map(|(_, v)| v.clone())
}

pub fn build_canonicalized_dkim_header_relaxed(value: &str) -> String {
    // Follow the approach from the reference DKIM implementation:
    // locate the b= tag and remove its value, then apply relaxed
    // header canonicalization to the resulting field value.

    #[derive(PartialEq)]
    enum State {
        B,
        EqualSign,
        Semicolon,
    }

    let mut state = State::B;
    let mut b_idx = 0;
    let mut b_end_idx = 0;
    for (idx, c) in value.chars().enumerate() {
        match state {
            State::B => {
                if c == 'b' {
                    state = State::EqualSign;
                }
            }
            State::EqualSign => {
                if c == '=' {
                    b_idx = idx + 1;
                    state = State::Semicolon;
                } else {
                    state = State::B;
                }
            }
            State::Semicolon => {
                if c == ';' {
                    b_end_idx = idx;
                    break;
                }
            }
        }
    }

    if b_end_idx == 0 && state == State::Semicolon {
        b_end_idx = value.len();
    }

    // Build the DKIM value with an empty b= tag.
    let mut save = value
        .get(..b_idx)
        .map(|v| v.to_string())
        .unwrap_or_default();
    save.push_str(match value.get(b_end_idx..) {
        Some(end) => end,
        None => "",
    });

    let canon_value = canonicalize_header_relaxed(save);
    format!("dkim-signature:{}", canon_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::sha2::{Digest, Sha256};
    use rsa::RsaPublicKey;

    #[test]
    fn real_gmail_full_message_body_hash_matches_bh() {
        let email_blob = include_str!("../tests/data/gmail_reset_full.eml");

        let (raw_headers, body) = split_headers_body(email_blob);
        let headers = parse_headers(raw_headers);
        let dkim_value = parse_dkim_header(&headers).expect("dkim header");
        let tags = parse_dkim_tags(&dkim_value);

        let bh_b64 = tags.get("bh").expect("bh tag");
        let bh = base64::decode(bh_b64).expect("bh base64");

        let canon_body = canonicalize_body_relaxed(body);
        let mut hasher = Sha256::new();
        hasher.update(canon_body.as_bytes());
        let computed_bh = hasher.finalize().to_vec();

        assert_eq!(bh, computed_bh, "body hash mismatch");
    }

    #[test]
    fn real_gmail_dns_p_parses_as_rsa_key() {
        let dns_record = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB";
        let tags = parse_dkim_tags(dns_record);
        let p_b64 = tags.get("p").expect("p tag");
        let pk_bytes = base64::decode(p_b64).expect("p base64");
        RsaPublicKey::from_public_key_der(&pk_bytes).expect("valid RSA public key");
    }
}
