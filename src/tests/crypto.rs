use crate::crypto::{decrypt_encrypted_email, EncryptedEmailEnvelope, load_worker_static_secret};
use crate::parsers::{extract_header_value, parse_email_timestamp_ms, parse_from_address};
use base64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub(crate) fn setup_worker_static_secret() -> StaticSecret {
    // Use a fixed hex seed so tests are deterministic.
    let seed_hex = "07".repeat(32); // 32 bytes of 0x07 as hex
    std::env::set_var("PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32", seed_hex);

    // Derive the same StaticSecret as the worker would.
    load_worker_static_secret().expect("worker static secret to load from seed")
}

pub(crate) fn encrypt_email(email_blob: &str, context: &serde_json::Value) -> EncryptedEmailEnvelope {
    let static_secret = setup_worker_static_secret();
    let static_public = X25519PublicKey::from(&static_secret);

    let eph_bytes = [9u8; 32];
    let eph_secret = StaticSecret::from(eph_bytes);
    let eph_public = X25519PublicKey::from(&eph_secret);

    let shared = eph_secret.diffie_hellman(&static_public);
    let shared_bytes = shared.as_bytes();

    let hk = Hkdf::<Sha256>::new(None, shared_bytes);
    let mut key_bytes = [0u8; 32];
    hk.expand(b"email-dkim-encryption-key", &mut key_bytes)
        .expect("hkdf expand");

    let cipher = ChaCha20Poly1305::new((&key_bytes).into());

    let nonce_bytes = [1u8; 12];
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let aad = serde_json::to_vec(context).expect("context to serialize for AAD");

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: email_blob.as_bytes(),
                aad: &aad,
            },
        )
        .expect("encryption to succeed");

    EncryptedEmailEnvelope {
        version: 1,
        ephemeral_pub: base64::encode(eph_public.as_bytes()),
        nonce: base64::encode(nonce_bytes),
        ciphertext: base64::encode(ciphertext),
    }
}

#[test]
fn encrypted_email_decrypts_and_parses_fields() {
    let email_blob = include_str!("../../email-dkim-verifier-contract/tests/data/gmail_reset_full.eml");
    let context = serde_json::json!({
        "account_id": "kerp30.w3a-v1.testnet",
        "network_id": "testnet"
    });

    let envelope = encrypt_email(email_blob, &context);

    let decrypted =
        decrypt_encrypted_email(&envelope, &context).expect("decrypts email");

    assert_eq!(decrypted, email_blob);

    let subject =
        extract_header_value(&decrypted, "Subject").expect("subject header");
    assert!(
        subject.contains("kerp30.w3a-v1.testnet"),
        "subject should mention the recovered account id"
    );

    let from_full =
        extract_header_value(&decrypted, "From").expect("from header");
    assert_eq!(from_full, "Pta <n6378056@gmail.com>");

    let from_addr = parse_from_address(&decrypted);
    assert_eq!(from_addr, "n6378056@gmail.com");

    let ts = parse_email_timestamp_ms(&decrypted);
    assert!(ts.is_some(), "expected email timestamp to parse");
}
