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
    let seed_raw = std::env::var("PROTECTED_OUTLAYER_WORKER_SK_SEED_B64")
        .map_err(|_| "missing PROTECTED_OUTLAYER_WORKER_SK_SEED_B64 env var".to_string())?;

    let seed_str = seed_raw.trim();

    // First, try base64 (old behavior, still supported).
    let seed_bytes = match base64::decode(seed_str) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => {
            // Fallback: accept a 64-char hex string (Outlayer "Hex 32 bytes" secret type).
            if seed_str.len() == 64 && seed_str.chars().all(|c| c.is_ascii_hexdigit()) {
                let mut out = Vec::with_capacity(32);
                for i in (0..64).step_by(2) {
                    let byte = u8::from_str_radix(&seed_str[i..i + 2], 16)
                        .map_err(|_| "PROTECTED_OUTLAYER_WORKER_SK_SEED_B64 must be base64 or hex-encoded 32 bytes".to_string())?;
                    out.push(byte);
                }
                out
            } else {
                return Err("PROTECTED_OUTLAYER_WORKER_SK_SEED_B64 must be base64 or hex-encoded 32 bytes".to_string());
            }
        }
    };

    let hk = Hkdf::<Sha256>::new(None, &seed_bytes);
    let mut okm = [0u8; 32];
    hk.expand(b"outlayer-email-dkim-x25519", &mut okm)
        .map_err(|_| "HKDF expansion failed".to_string())?;

    Ok(StaticSecret::from(okm))
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
