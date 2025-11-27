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
    let mut used = vec![false; headers.len()];

    // RFC 6376 §5.4.2: when multiple instances of a field are signed,
    // they must be selected from the bottom of the header block upward.
    for signed in signed_headers {
        let mut selected: Option<usize> = None;
        for idx in (0..headers.len()).rev() {
            if used[idx] {
                continue;
            }
            let (name, _) = &headers[idx];
            if name.eq_ignore_ascii_case(signed) {
                selected = Some(idx);
                break;
            }
        }
        if let Some(idx) = selected {
            let (name, value) = &headers[idx];
            result.push_str(&name.to_ascii_lowercase());
            result.push(':');
            result.push_str(&canonicalize_header_relaxed(value.clone()));
            result.push_str("\r\n");
            used[idx] = true;
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

pub fn parse_email_timestamp_ms(email: &str) -> Option<u64> {
    let date_value = extract_header_value(email, "Date")?;
    let date_str = date_value.trim();

    // Strip optional weekday prefix, e.g. "Wed, "
    let core = match date_str.find(',') {
        Some(idx) => date_str.get(idx + 1..)?.trim(),
        None => date_str,
    };

    // Expect a simplified RFC 2822 subset:
    // "26 Nov 2025 12:30:59 +0900"
    let mut parts = core.split_whitespace();

    let day_str = parts.next()?;
    let month_str = parts.next()?;
    let year_str = parts.next()?;
    let time_str = parts.next()?;
    let offset_str = parts.next()?; // "+HHMM" or "-HHMM"

    let day: u32 = day_str.parse().ok()?;
    let year: i32 = year_str.parse().ok()?;
    if year < 1970 {
        return None;
    }

    let month: u32 = match month_str {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };

    let mut time_parts = time_str.split(':');
    let hour: u32 = time_parts.next()?.parse().ok()?;
    let minute: u32 = time_parts.next()?.parse().ok()?;
    let second: u32 = time_parts.next()?.parse().ok()?;

    // Parse numeric zone offset of the form "+HHMM" or "-HHMM".
    if offset_str.len() < 3 {
        return None;
    }
    let sign = match &offset_str[0..1] {
        "+" => 1i64,
        "-" => -1i64,
        _ => return None,
    };
    let (off_hour_str, off_min_str) = offset_str[1..].split_at(2);
    let off_hour: i64 = off_hour_str.parse().ok()?;
    let off_min: i64 = off_min_str.parse().ok()?;
    let offset_sec = sign
        .checked_mul(off_hour.checked_mul(3600)? + off_min.checked_mul(60)?)?;

    let days = days_since_unix_epoch(year, month, day)?;
    let seconds_local = days
        .checked_mul(86_400)?
        .checked_add(hour as i64 * 3600 + minute as i64 * 60 + second as i64)?;
    let seconds_utc = seconds_local.checked_sub(offset_sec)?;
    if seconds_utc < 0 {
        return None;
    }
    let ms = seconds_utc.checked_mul(1000)?;
    Some(ms as u64)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    if month < 1 || month > 12 {
        return None;
    }
    let mut days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    Some(days)
}

fn days_since_unix_epoch(year: i32, month: u32, day: u32) -> Option<i64> {
    if year < 1970 || month < 1 || month > 12 {
        return None;
    }
    let dim = days_in_month(year, month)?;
    if day < 1 || day > dim {
        return None;
    }

    let mut days: i64 = 0;
    let mut y = 1970;
    while y < year {
        days += if is_leap_year(y) { 366 } else { 365 };
        y += 1;
    }

    let mut m = 1;
    while m < month {
        days += match days_in_month(year, m) {
            Some(d) => d as i64,
            None => return None,
        };
        m += 1;
    }

    days += (day - 1) as i64;
    Some(days)
}

pub fn build_canonicalized_dkim_header_relaxed(value: &str) -> String {
    // Locate the b= tag and remove its value (handling optional FWS),
    // then apply relaxed header canonicalization to the resulting field value.

    let bytes = value.as_bytes();
    let mut b_value_start: Option<usize> = None;
    let mut b_value_end: Option<usize> = None;

    let mut i = 0;
    while i < bytes.len() {
        // Skip leading WSP and semicolons between tags.
        while i < bytes.len()
            && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\r' || bytes[i] == b'\n')
        {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b';' {
            i += 1;
            continue;
        }

        if i >= bytes.len() {
            break;
        }

        // Potential start of a tag name.
        if bytes[i] == b'b' || bytes[i] == b'B' {
            let mut j = i + 1;
            // Skip optional FWS between "b" and "=".
            while j < bytes.len()
                && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\r' || bytes[j] == b'\n')
            {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                // Move past "=" and any following FWS to the start of the value.
                j += 1;
                while j < bytes.len()
                    && (bytes[j] == b' '
                        || bytes[j] == b'\t'
                        || bytes[j] == b'\r'
                        || bytes[j] == b'\n')
                {
                    j += 1;
                }
                b_value_start = Some(j);

                // The b= value runs until the next ";" or end of string.
                let mut k = j;
                while k < bytes.len() {
                    if bytes[k] == b';' {
                        break;
                    }
                    k += 1;
                }
                b_value_end = Some(k);
                break;
            }
        }

        // Not a b= tag here; advance one byte and continue scanning.
        i += 1;
    }

    let save = if let (Some(start), Some(end)) = (b_value_start, b_value_end) {
        // Build the DKIM value with an empty b= tag.
        let mut tmp = String::new();
        tmp.push_str(&value[..start]);
        tmp.push_str(&value[end..]);
        tmp
    } else {
        // No b= tag detected; fall back to the original value.
        value.to_string()
    };

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

    #[test]
    fn gmail_reset_full_email_timestamp_parses() {
        let email_blob = include_str!("../tests/data/gmail_reset_full.eml");

        let ts_ms = parse_email_timestamp_ms(email_blob);
        assert!(ts_ms.is_some(), "expected email timestamp to parse");
    }
}
