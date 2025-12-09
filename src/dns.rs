use serde::Deserialize;
use wasi_http_client::Client;

#[derive(Deserialize)]
struct DnsAnswer {
    data: String,
}

#[derive(Deserialize)]
struct DnsResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DnsAnswer>>,
}

#[cfg(not(test))]
pub fn fetch_txt_records(name: &str) -> Result<Vec<String>, String> {
    let url = format!("https://dns.google/resolve?name={name}&type=TXT");
    let client = Client::new();
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let status = resp.status();
    if !(200..300).contains(&status) {
        return Err(format!(
            "HTTP status {} when querying DNS for {}",
            status, name
        ));
    }

    let body_bytes = resp
        .body()
        .map_err(|e| format!("failed to read HTTP body: {e}"))?;

    let dns: DnsResponse = serde_json::from_slice(&body_bytes)
        .map_err(|e| format!("failed to parse DNS JSON: {e}"))?;

    let mut records = Vec::new();
    if let Some(answers) = dns.answer {
        for ans in answers {
            let mut data = ans.data;
            // DNS-over-HTTPS TXT answers are often wrapped in quotes.
            if data.starts_with('\"') && data.ends_with('\"') && data.len() >= 2 {
                data = data[1..data.len() - 1].to_string();
            }
            if !data.is_empty() {
                records.push(data);
            }
        }
    }

    if records.is_empty() {
        Err(format!("no TXT records found for {}", name))
    } else {
        Ok(records)
    }
}

#[cfg(test)]
pub fn fetch_txt_records(_name: &str) -> Result<Vec<String>, String> {
    // In tests we stub DNS lookups with a fixed, known-good record from a
    // real Gmail DKIM DNS entry. This avoids network flakiness while still
    // exercising the full DKIM verification logic.
    Ok(vec!["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB".to_string()])
}

