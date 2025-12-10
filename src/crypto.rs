use base64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Deserialize)]
pub struct EncryptedEmailEnvelope {
    // Versioned envelope so we can evolve the format.
    #[serde(default)]
    pub version: u8,
    // Public key of the relayer's ephemeral keypair (X25519), base64-encoded.
    #[serde(default)]
    pub ephemeral_pub: String,
    // Nonce / IV for the AEAD cipher, base64-encoded.
    #[serde(default)]
    pub nonce: String,
    // Ciphertext of the raw RFC-5322 email, base64-encoded.
    #[serde(default)]
    pub ciphertext: String,
}

pub fn get_worker_public_key() -> Result<String, String> {
    let sk = load_worker_static_secret()?;
    let pk = X25519PublicKey::from(&sk);
    Ok(base64::encode(pk.as_bytes()))
}

pub(crate) fn load_worker_static_secret() -> Result<StaticSecret, String> {

    // Primary source: protected secret, hex-encoded 32-byte seed.
    if let Ok(val) = std::env::var("PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32") {
        let seed = parse_hex_32(&val).map_err(|_| {
            "PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32 must be a 64-char hex string (32 bytes)"
                .to_string()
        })?;
        return derive_secret_key(seed);
    }

    // Fallback: unprotected (trusted) hex-encoded 32-byte seed
    let val = std::env::var("OUTLAYER_WORKER_SK_SEED_HEX32").map_err(|_| {
        "Secrets Not Found: PROTECTED_OUTLAYER_WORKER_SK_SEED_HEX32 and OUTLAYER_WORKER_SK_SEED_HEX32"
            .to_string()
    })?;
    let seed = parse_hex_32(&val).map_err(|_| {
        "OUTLAYER_WORKER_SK_SEED_HEX32 must be a 64-char hex string (32 bytes)"
            .to_string()
    })?;

    return derive_secret_key(seed);
}

fn derive_secret_key(seed: [u8; 32]) -> Result<StaticSecret, String> {
    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut okm = [0u8; 32];
    hk.expand(b"outlayer-email-dkim-x25519", &mut okm)
        .map_err(|_| "HKDF expansion failed".to_string())?;
    Ok(StaticSecret::from(okm))
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], ()> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(());
    }

    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let str_chunk = std::str::from_utf8(chunk).map_err(|_| ())?;
        let byte = u8::from_str_radix(str_chunk, 16).map_err(|_| ())?;
        out[i] = byte;
    }
    Ok(out)
}

pub fn decrypt_encrypted_email(
    envelope: &EncryptedEmailEnvelope,
    context: &Value,
) -> Result<String, String> {
    let static_secret = load_worker_static_secret()?;

    let eph_bytes = base64::decode(envelope.ephemeral_pub.trim())
        .map_err(|_| "invalid ephemeral_pub".to_string())?;

    if eph_bytes.len() != 32 {
        return Err("ephemeral_pub must be 32 bytes".to_string());
    }
    let mut eph_array = [0u8; 32];
    eph_array.copy_from_slice(&eph_bytes);
    let eph_public = X25519PublicKey::from(eph_array);

    let shared = static_secret.diffie_hellman(&eph_public);
    let shared_bytes = shared.as_bytes();

    let hk = Hkdf::<Sha256>::new(None, shared_bytes);
    let mut key_bytes = [0u8; 32];
    hk.expand(b"email-dkim-encryption-key", &mut key_bytes)
        .map_err(|_| "failed to derive AEAD key".to_string())?;

    let cipher = ChaCha20Poly1305::new((&key_bytes).into());

    let nonce_bytes =
        base64::decode(envelope.nonce.trim()).map_err(|_| "invalid nonce".to_string())?;
    if nonce_bytes.len() != 12 {
        return Err("nonce must be 12 bytes for ChaCha20-Poly1305".to_string());
    }
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let ciphertext =
        base64::decode(envelope.ciphertext.trim()).map_err(|_| "invalid ciphertext".to_string())?;

    // Serialize the logical `context` object as JSON and use the bytes as
    // ChaCha20‑Poly1305 AAD. The SDK constructs `context` with keys in
    // alphabetical order (`account_id`, `network_id`, `payer_account_id`)
    // so that serde_json produces the same byte sequence on this side.
    let aad = serde_json::to_vec(context)
        .map_err(|_| "failed to serialize context for AAD".to_string())?;

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| "decryption failed".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "decrypted email is not valid UTF-8".to_string())
}
