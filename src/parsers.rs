use std::collections::HashMap;

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

pub fn parse_dkim_tags(value: &str) -> HashMap<String, String> {
    let mut tags = HashMap::new();
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
    let mut lines: Vec<String> = Vec::new();
    for raw_line in body.split('\n') {
        let mut line = raw_line.trim_end_matches('\r').to_string();
        line = line.replace('\t', " ");
        while line.ends_with(' ') {
            line.pop();
        }
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

    while matches!(lines.last(), Some(l) if l.is_empty()) {
        lines.pop();
    }

    if lines.is_empty() {
        return "\r\n".to_string();
    }

    let mut result = lines.join("\r\n");
    result.push_str("\r\n");
    result
}

pub fn build_canonicalized_dkim_header_relaxed(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut b_value_start: Option<usize> = None;
    let mut b_value_end: Option<usize> = None;

    let mut i = 0;
    while i < bytes.len() {
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

        if bytes[i] == b'b' || bytes[i] == b'B' {
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\r' || bytes[j] == b'\n')
            {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
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

        i += 1;
    }

    let save = if let (Some(start), Some(end)) = (b_value_start, b_value_end) {
        let mut tmp = String::new();
        tmp.push_str(&value[..start]);
        tmp.push_str(&value[end..]);
        tmp
    } else {
        value.to_string()
    };

    let canon_value = canonicalize_header_relaxed(save);
    format!("dkim-signature:{}", canon_value)
}

pub fn extract_dkim_selector_and_domain(email: &str) -> Result<(String, String), String> {
    let header_value =
        extract_header_value(email, "DKIM-Signature").ok_or("missing DKIM-Signature header")?;

    let mut selector: Option<String> = None;
    let mut domain: Option<String> = None;

    for part in header_value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut it = part.splitn(2, '=');
        let name = it
            .next()
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let value = it.next().map(|s| s.trim()).unwrap_or_default();
        match name.as_str() {
            "d" => {
                if !value.is_empty() {
                    domain = Some(value.to_string());
                }
            }
            "s" => {
                if !value.is_empty() {
                    selector = Some(value.to_string());
                }
            }
            _ => {}
        }
    }

    let selector = selector.ok_or("missing s= selector in DKIM header")?;
    let domain = domain.ok_or("missing d= domain in DKIM header")?;
    Ok((selector, domain))
}

pub fn parse_email_timestamp_ms(email: &str) -> Option<u64> {
    let date_value = extract_header_value(email, "Date")?;
    let date_str = date_value.trim();

    let core = match date_str.find(',') {
        Some(idx) => date_str.get(idx + 1..)?.trim(),
        None => date_str,
    };

    let mut parts = core.split_whitespace();

    let day_str = parts.next()?;
    let month_str = parts.next()?;
    let year_str = parts.next()?;
    let time_str = parts.next()?;
    let offset_str = parts.next()?;

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

    fn is_leap_year(year: i32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }

    fn days_in_month(year: i32, month: u32) -> Option<u32> {
        if month < 1 || month > 12 {
            return None;
        }
        let days = match month {
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

pub fn parse_recover_subject(subject: &str) -> Option<String> {
    let subject = subject.trim();
    let mut parts = subject.split_whitespace();

    let kind = parts.next()?;
    let account_id_str = if kind == "recover" {
        // Legacy format: "recover <account_id> ..."
        parts.next()?
    } else if let Some(rest) = kind.strip_prefix("recover-") {
        // New format: "recover-<REQUEST_ID> <account_id> ..."
        let _request_id = rest;
        parts.next()?
    } else {
        return None;
    };

    let account_id_str = account_id_str.trim();
    if account_id_str.is_empty() {
        return None;
    }

    Some(account_id_str.to_string())
}

pub fn parse_recover_instruction(subject: &str) -> Option<(String, String)> {
    let subject = subject.trim();
    let mut parts = subject.split_whitespace();

    let kind = parts.next()?;
    let account_id_str = if kind == "recover" {
        // Legacy format.
        parts.next()?
    } else if let Some(rest) = kind.strip_prefix("recover-") {
        // New format with request_id in the first token.
        let _request_id = rest;
        parts.next()?
    } else {
        return None;
    };

    let account_id_str = account_id_str.trim();
    if account_id_str.is_empty() {
        return None;
    }

    let mut new_public_key: Option<String> = None;
    for token in parts {
        if token.starts_with("ed25519:") && token.len() > "ed25519:".len() {
            new_public_key = Some(token.to_string());
            break;
        }
    }

    let new_public_key = new_public_key?;
    Some((account_id_str.to_string(), new_public_key))
}

/// Parse the short request_id from a recovery Subject header (worker side).
///
/// Expected format:
///   "recover-<REQUEST_ID> <account_id> ed25519:<public_key>"
/// Returns Some("<REQUEST_ID>") when the prefix is present; otherwise None.
pub fn parse_recover_request_id(subject: &str) -> Option<String> {
    let subject = subject.trim();
    let mut parts = subject.split_whitespace();
    let first = parts.next()?;

    if let Some(rest) = first.strip_prefix("recover-") {
        if !rest.is_empty() {
            return Some(rest.to_string());
        }
    }

    None
}

pub fn parse_recover_public_key_from_body(email: &str) -> Option<String> {
    let (_, body) = split_headers_body(email);
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ed25519:") && trimmed.len() > "ed25519:".len() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Parse the `From:` header into a bare email address.
///
/// This helper is used in the Outlayer worker so that `from_address` in the
/// worker/contract responses is always of the form `user@example.com`, not a
/// full display string like `User <user@example.com>`.
pub fn parse_from_address(email: &str) -> String {
    let value = match extract_header_value(email, "From") {
        Some(v) => v.trim().to_string(),
        None => return String::new(),
    };

    // Prefer the address inside angle brackets if present.
    if let Some(start) = value.find('<') {
        if let Some(end_rel) = value[start + 1..].find('>') {
            let end = start + 1 + end_rel;
            let inner = &value[start + 1..end];
            return inner.trim().to_string();
        }
    }

    // Fallback: pick the last token containing '@'.
    for token in value.split_whitespace().rev() {
        if token.contains('@') {
            let cleaned = token
                .trim_matches(|c| c == '<' || c == '>' || c == '"' || c == '\'')
                .to_string();
            if !cleaned.is_empty() {
                return cleaned;
            }
        }
    }

    // As a last resort, return the raw header value.
    value
}
