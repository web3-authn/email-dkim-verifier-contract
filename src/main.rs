use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

#[derive(Deserialize)]
struct Input {
    email_blob: String,
}

#[derive(Serialize)]
struct Output {
    selector: Option<String>,
    domain: Option<String>,
    records: Vec<String>,
    error: Option<String>,
}

fn extract_header_value(email: &str, header_name: &str) -> Option<String> {
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

fn extract_dkim_selector_and_domain(email: &str) -> Result<(String, String), String> {
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

fn fetch_dkim_txt_records(selector: &str, domain: &str) -> Result<Vec<String>, String> {
    let resolver =
        Resolver::new(ResolverConfig::default(), ResolverOpts::default()).map_err(|e| {
            format!("failed to create DNS resolver: {e}")
        })?;

    let name = format!("{}._domainkey.{}", selector, domain);
    let txt_lookup = resolver
        .txt_lookup(name.as_str())
        .map_err(|e| format!("TXT lookup failed for {name}: {e}"))?;

    let mut records = Vec::new();
    for txt in txt_lookup.iter() {
        let mut combined = String::new();
        for packet in txt.txt_data() {
            combined.push_str(&String::from_utf8_lossy(packet));
        }
        if !combined.is_empty() {
            records.push(combined);
        }
    }

    if records.is_empty() {
        Err("no DKIM TXT records found".to_string())
    } else {
        Ok(records)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input_string = String::new();
    io::stdin().read_to_string(&mut input_string)?;
    let input: Input = serde_json::from_str(&input_string)?;

    let mut error = None;

    let (selector, domain, records) = match extract_dkim_selector_and_domain(&input.email_blob) {
        Ok((s, d)) => match fetch_dkim_txt_records(&s, &d) {
            Ok(records) => (Some(s), Some(d), records),
            Err(e) => {
                error = Some(e);
                (None, None, Vec::new())
            }
        },
        Err(e) => {
            error = Some(e);
            (None, None, Vec::new())
        }
    };

    let output = Output {
        selector,
        domain,
        records,
        error,
    };

    print!("{}", serde_json::to_string(&output)?);

    Ok(())
}
