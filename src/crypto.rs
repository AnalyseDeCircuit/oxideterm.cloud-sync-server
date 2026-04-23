// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Parse a 32-byte hex-encoded key.
pub fn parse_hex_key(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", bytes.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Derive a 32-byte symmetric key from arbitrary secret material using SHA-256.
pub fn derive_key(secret_material: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(secret_material);
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Encrypt data at rest using ChaCha20-Poly1305.
/// Returns: nonce (12 bytes) || ciphertext (with 16-byte auth tag appended).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data encrypted by `encrypt()`.
/// Input: nonce (12 bytes) || ciphertext (with auth tag).
pub fn decrypt(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted.len() < 12 + 16 {
        return Err("Encrypted data too short".to_string());
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {e}"))
}

/// Compute SHA-256 hash of data, return hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, OxideTerm Cloud Sync!";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let encrypted = encrypt(&key1, b"secret data").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn parse_hex_key_valid() {
        let hex = "00".repeat(32);
        assert!(parse_hex_key(&hex).is_ok());
    }

    #[test]
    fn parse_hex_key_invalid_length() {
        let hex = "00".repeat(16);
        assert!(parse_hex_key(&hex).is_err());
    }

    #[test]
    fn derive_key_is_stable() {
        let key1 = derive_key(b"admin-secret");
        let key2 = derive_key(b"admin-secret");
        let key3 = derive_key(b"different-secret");
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
