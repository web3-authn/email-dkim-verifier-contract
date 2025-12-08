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

fn load_worker_static_secret() -> Result<StaticSecret, String> {
    let sk_b64 = std::env::var("OUTLAYER_EMAIL_DKIM_SK")
        .map_err(|_| "missing OUTLAYER_EMAIL_DKIM_SK env var".to_string())?;
    let sk_bytes = base64::decode(sk_b64.trim())
        .map_err(|_| "OUTLAYER_EMAIL_DKIM_SK must be base64-encoded".to_string())?;
    if sk_bytes.len() != 32 {
        return Err("OUTLAYER_EMAIL_DKIM_SK must be 32 bytes".to_string());
    }
    let mut sk_array = [0u8; 32];
    sk_array.copy_from_slice(&sk_bytes);
    Ok(StaticSecret::from(sk_array))
}

pub fn decrypt_encrypted_email(
    envelope: &EncryptedEmailEnvelope,
    context: &Value,
) -> Result<String, String> {
    let static_secret = load_worker_static_secret()?;

    let eph_bytes =
        base64::decode(envelope.ephemeral_pub.trim()).map_err(|_| "invalid ephemeral_pub".to_string())?;
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

