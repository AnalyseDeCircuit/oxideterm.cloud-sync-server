// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hash a plaintext API token for storage (SHA-256, not reversible).
pub fn hash_api_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Hash admin password with bcrypt for storage.
pub fn hash_admin_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

/// Verify admin password against bcrypt hash.
pub fn verify_admin_password(password: &str, hash: &str) -> bool {
    verify(password, hash).unwrap_or(false)
}

/// JWT claims for admin session tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminClaims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

/// Create a short-lived admin JWT (24h).
pub fn create_admin_jwt(secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = AdminClaims {
        sub: "admin".to_string(),
        exp: now + 86400, // 24 hours
        iat: now,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Validate an admin JWT. Returns Ok(claims) if valid.
pub fn validate_admin_jwt(
    token: &str,
    secret: &str,
) -> Result<AdminClaims, jsonwebtoken::errors::Error> {
    let data = decode::<AdminClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}

/// Authenticate a sync API request. Returns the namespace pattern associated with the token.
/// Checks bearer token or basic auth credentials against stored token hashes.
pub fn authenticate_bearer(token: &str, token_hashes: &[(String, String)]) -> Option<String> {
    let incoming_hash = hash_api_token(token);
    for (stored_hash, namespace_pattern) in token_hashes {
        if incoming_hash == *stored_hash {
            return Some(namespace_pattern.clone());
        }
    }
    None
}

/// Check if a namespace matches a pattern.
/// Patterns: "*" matches all, "exact-name" matches exactly, "prefix*" matches prefix.
pub fn namespace_matches(namespace: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return namespace.starts_with(prefix);
    }
    namespace == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_roundtrip() {
        let token = "test-token-12345";
        let hashed = hash_api_token(token);
        assert_eq!(hashed, hash_api_token(token));
        assert_ne!(hashed, hash_api_token("wrong-token"));
    }

    #[test]
    fn admin_password_roundtrip() {
        let pw = "admin-secret-pass";
        let hashed = hash_admin_password(pw).unwrap();
        assert!(verify_admin_password(pw, &hashed));
        assert!(!verify_admin_password("wrong", &hashed));
    }

    #[test]
    fn namespace_pattern_matching() {
        assert!(namespace_matches("my-sync", "*"));
        assert!(namespace_matches("my-sync", "my-sync"));
        assert!(!namespace_matches("my-sync", "other"));
        assert!(namespace_matches("team-prod", "team-*"));
        assert!(namespace_matches("team-staging", "team-*"));
        assert!(!namespace_matches("other-prod", "team-*"));
    }

    #[test]
    fn admin_jwt_roundtrip() {
        let secret = "test-jwt-secret-key";
        let token = create_admin_jwt(secret).unwrap();
        let claims = validate_admin_jwt(&token, secret).unwrap();
        assert_eq!(claims.sub, "admin");
    }
}
