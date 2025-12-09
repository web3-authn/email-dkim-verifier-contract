use email_dkim_verifier_contract::{parse_dkim_tags, verify_dkim};
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;

fn real_gmail_dns_records() -> Vec<String> {
    vec!["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB".to_string()]
}

#[test]
fn verify_dkim_without_signature_fails() {
    let email = "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nHello\r\n";
    let records: Vec<String> = Vec::new();
    assert!(!verify_dkim(email, &records));
}

#[test]
fn parse_real_gmail_dkim_header_tags() {
    const REAL_GMAIL_DKIM_VALUE: &str = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601; t=1764065518; x=1764670318; darn=web3authn.org; h=to:subject:message-id:date:from:mime-version:from:to:cc:subject :date:message-id:reply-to; bh=/3T/I4LKUj/5W2dhs5sEhe+rpsHRZVi0ngI9SyPKWSw=; b=O+LksKnZtVUpN9Omaz1pYKPa9EJc+NmIku/ZQ18zCvbimPjIDjdIONBTyYnO3JCgE7 yaySupoHQ+Dh3/z5NYufBPqkThR3Gu/7YwmmX4C76J7h6bc5u82WSlJ5FqHN/Y1cKWKl ZG5fh1kcmYYN8bPWeAluIZ/X1c9LMajWNRgIM/gOa+fqImUKXn3B18EVjnRui0duOQTP FHDAEK9wuqxvxl15PVFv3gjhqh1Z7FE4HNL8yvDtsKxabeUJwX/zHiwCLb8OYm9pnb0G HA69cdD/g55kcFQoBdc1zhdAFQyzJ07rSNBYXcIUA0KcSEiOGaOSeuYHoKE3zXUBgrtG 6Q8w==";

    let tags = parse_dkim_tags(REAL_GMAIL_DKIM_VALUE);

    assert_eq!(tags.get("v").map(String::as_str), Some("1"));
    assert_eq!(tags.get("a").map(String::as_str), Some("rsa-sha256"));
    assert_eq!(tags.get("c").map(String::as_str), Some("relaxed/relaxed"));
    assert_eq!(tags.get("d").map(String::as_str), Some("gmail.com"));
    assert_eq!(tags.get("s").map(String::as_str), Some("20230601"));
    assert_eq!(
        tags.get("bh").map(String::as_str),
        Some("/3T/I4LKUj/5W2dhs5sEhe+rpsHRZVi0ngI9SyPKWSw=")
    );

    assert!(tags.get("h").is_some());
    assert!(tags
        .get("b")
        .map(|v| v.starts_with("O+LksKnZtVUpN9Omaz1pYKPa9EJc+NmIku/ZQ18zCvbimPjIDjdIONBTyYnO3JCgE7"))
        .unwrap_or(false));
}

#[test]
fn real_gmail_dkim_sample_currently_fails() {
    // Simplified email with missing signed headers; should fail verification.
    let email_blob = "\
From: n6378056@gmail.com\r\n\
To: reset@web3authn.org\r\n\
Subject: test8\r\n\
Date: Tue, 30 Jun 2020 10:43:08 +0200\r\n\
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601; t=1764065518; x=1764670318; darn=web3authn.org; h=to:subject:message-id:date:from:mime-version:from:to:cc:subject :date:message-id:reply-to; bh=/3T/I4LKUj/5W2dhs5sEhe+rpsHRZVi0ngI9SyPKWSw=; b=O+LksKnZtVUpN9Omaz1pYKPa9EJc+NmIku/ZQ18zCvbimPjIDjdIONBTyYnO3JCgE7 yaySupoHQ+Dh3/z5NYufBPqkThR3Gu/7YwmmX4C76J7h6bc5u82WSlJ5FqHN/Y1cKWKl ZG5fh1kcmYYN8bPWeAluIZ/X1c9LMajWNRgIM/gOa+fqImUKXn3B18EVjnRui0duOQTP FHDAEK9wuqxvxl15PVFv3gjhqh1Z7FE4HNL8yvDtsKxabeUJwX/zHiwCLb8OYm9pnb0G HA69cdD/g55kcFQoBdc1zhdAFQyzJ07rSNBYXcIUA0KcSEiOGaOSeuYHoKE3zXUBgrtG 6Q8w==\r\n\
\r\n\
This is a test email body for DKIM verification.\r\n";

    assert!(!verify_dkim(email_blob, &real_gmail_dns_records()));
}

#[test]
fn real_gmail_full_message_verifies() {
    // Full raw email as received by the worker.
    let email_blob = include_str!("data/gmail_reset_full.eml");
    assert!(verify_dkim(email_blob, &real_gmail_dns_records()));
}

#[test]
fn real_gmail_dns_p_parses_as_rsa_key() {
    let dns_record = real_gmail_dns_records().pop().unwrap();
    let tags = parse_dkim_tags(&dns_record);
    let p_b64 = tags.get("p").expect("p tag");
    let pk_bytes = base64::decode(p_b64).expect("p base64");
    RsaPublicKey::from_public_key_der(&pk_bytes).expect("valid RSA public key");
}

#[test]
fn modifying_subject_breaks_dkim() {
    let email_blob = include_str!("data/gmail_reset_full.eml");
    let modified = email_blob.replacen(
        "Subject: recover-123abc kerp30.w3a-v1.testnet",
        "Subject: recover-123abc alice.testnet",
        1,
    );
    assert!(!verify_dkim(&modified, &real_gmail_dns_records()));
}

#[test]
fn modifying_body_plain_text_breaks_dkim() {
    let email_blob = include_str!("data/gmail_reset_full.eml");
    let modified = email_blob.replacen(
        "<div dir=\"ltr\"><br></div>",
        "<div dir=\"ltr\">tampered</div>",
        1,
    );
    assert!(!verify_dkim(&modified, &real_gmail_dns_records()));
}

#[test]
fn modifying_from_breaks_dkim() {
    let email_blob = include_str!("data/gmail_reset_full.eml");
    let modified = email_blob.replacen(
        "From: Pta <n6378056@gmail.com>",
        "From: Mallory <mallory@example.com>",
        1,
    );
    assert!(!verify_dkim(&modified, &real_gmail_dns_records()));
}
