//! Vetted crypto primitives (RustCrypto): Argon2id KDF + AES-256-GCM AEAD.
//! Key material is held in `Zeroizing` so it is wiped from memory on drop.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Cryptographically-secure random bytes.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| anyhow!("rng failure: {e}"))?;
    Ok(b)
}

/// Derive a 32-byte key-encryption key from a passphrase via Argon2id.
pub fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params =
        Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    a2.hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| anyhow!("argon2 derivation failed: {e}"))?;
    Ok(key)
}

/// AES-256-GCM encrypt. Returns ciphertext||tag. `nonce` MUST be unique per key.
pub fn aead_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| anyhow!("AEAD encrypt failed"))
}

/// AES-256-GCM decrypt + verify. Fails on wrong key or tampered data.
pub fn aead_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| anyhow!("decrypt failed — wrong passphrase or tampered data"))
}
