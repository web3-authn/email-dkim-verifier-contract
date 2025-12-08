use base64;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn main() {
    // Generate a random 32-byte X25519 private key.
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let static_secret = StaticSecret::from(sk_bytes);
    let public_key = X25519PublicKey::from(&static_secret);

    let sk_b64 = base64::encode(sk_bytes);
    let pk_b64 = base64::encode(public_key.as_bytes());

    println!("OUTLAYER_WORKER_SK_B64={}", sk_b64);
    println!("OUTLAYER_WORKER_PK_B64={}", pk_b64);
}
