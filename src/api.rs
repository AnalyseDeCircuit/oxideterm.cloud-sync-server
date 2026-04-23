// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tower_http::cors::{Any, CorsLayer};

use crate::auth;
use crate::config::*;
use crate::crypto;
use crate::db::{ConditionalWriteError, Database};
use crate::error::AppError;
use crate::panel;

#[derive(Debug)]
pub struct LoginAttemptState {
    pub first_failure_at: Instant,
    pub failures: u32,
    pub blocked_until: Option<Instant>,
}

#[derive(Copy, Clone)]
enum SyncPermission {
    Read,
    Write,
}

impl SyncPermission {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub encryption_key: Option<[u8; 32]>,
    pub admin_password_hash: Option<String>,
    pub jwt_secret: String,
    pub token_reveal_key: [u8; 32],
    pub token_reveal_persistent: bool,
    pub login_attempts: Arc<Mutex<HashMap<IpAddr, LoginAttemptState>>>,
    pub trust_proxy_headers: bool,
    pub max_blob_size: usize,
    pub max_object_size: usize,
}

pub fn router(state: AppState) -> Router {
    let shared = Arc::new(state);

    let metadata_api = Router::new()
        .route(
            "/v1/namespaces/{namespace}/metadata",
            get(get_metadata).put(put_metadata),
        )
        .layer(DefaultBodyLimit::max(256 * 1024));

    let blob_api = Router::new()
        .route(
            "/v1/namespaces/{namespace}/blob",
            get(get_blob).put(put_blob),
        )
        .layer(DefaultBodyLimit::max(shared.max_blob_size));

    let object_api = Router::new()
        .route(
            "/v1/namespaces/{namespace}/objects/{*path}",
            get(get_object).put(put_object),
        )
        .layer(DefaultBodyLimit::max(shared.max_object_size));

    let sync_api = Router::new()
        .merge(metadata_api)
        .merge(blob_api)
        .merge(object_api)
        .route("/", get(|| async { Redirect::temporary("/admin") }))
        .route("/health", get(health_check))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    let admin_api = panel::admin_router();

    sync_api.merge(admin_api).with_state(shared)
}

// ── Health Check ──

async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "oxideterm-cloud-sync-server" }))
}

// ── Auth Helper ──

fn extract_auth(headers: &HeaderMap, state: &AppState) -> Result<ApiToken, AppError> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

    let token = if let Some(bearer) = auth_header.strip_prefix("Bearer ") {
        bearer.trim().to_string()
    } else if let Some(basic) = auth_header.strip_prefix("Basic ") {
        // Decode basic auth, extract password portion as token
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, basic.trim())
                .map_err(|_| AppError::Unauthorized("Invalid Basic auth encoding".to_string()))?;
        let credential = String::from_utf8(decoded)
            .map_err(|_| AppError::Unauthorized("Invalid Basic auth encoding".to_string()))?;
        // Format: username:password — extract password as the token
        credential
            .splitn(2, ':')
            .nth(1)
            .unwrap_or(&credential)
            .to_string()
    } else {
        return Err(AppError::Unauthorized(
            "Unsupported auth scheme".to_string(),
        ));
    };

    let token_hash = auth::hash_api_token(&token);
    let token = state
        .db
        .get_token_by_hash(&token_hash)
        .map_err(|e| AppError::Internal(format!("Token lookup error: {e}")))?;

    token.ok_or_else(|| AppError::Unauthorized("Invalid token".to_string()))
}

fn authorize_sync_request_with_permission(
    headers: &HeaderMap,
    state: &AppState,
    namespace: &str,
    permission: SyncPermission,
) -> Result<ApiToken, AppError> {
    let token = extract_auth(headers, state)?;
    if !auth::namespace_matches(namespace, &token.namespace_pattern) {
        return Err(AppError::Forbidden(format!(
            "Token not authorized for namespace '{namespace}'"
        )));
    }

    if !auth::permissions_allow(&token.permissions, permission.as_str()) {
        return Err(AppError::Forbidden(format!(
            "Token is missing '{}' permission",
            permission.as_str()
        )));
    }

    state
        .db
        .touch_token_last_used(&token.id, &chrono::Utc::now().to_rfc3339())
        .map_err(|e| AppError::Internal(format!("Failed to update token audit info: {e}")))?;

    Ok(token)
}

/// Decode and validate a namespace path parameter.
fn decode_namespace(raw: &str) -> Result<String, AppError> {
    let decoded = urlencoding::decode(raw)
        .map_err(|_| AppError::BadRequest("Invalid namespace encoding".to_string()))?
        .into_owned();
    validate_namespace(&decoded)?;
    Ok(decoded)
}

fn decode_object_path(raw: &str) -> Result<String, AppError> {
    let decoded = urlencoding::decode(raw)
        .map_err(|_| AppError::BadRequest("Invalid object path encoding".to_string()))?
        .into_owned();

    if decoded.is_empty() || decoded.len() > 1024 || decoded.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest(
            "Object path must be 1-1024 visible characters".to_string(),
        ));
    }

    Ok(decoded)
}

fn map_conditional_write_error(error: ConditionalWriteError) -> AppError {
    match error {
        ConditionalWriteError::Conflict {
            remote_revision,
            remote_etag,
            message,
        } => AppError::Conflict {
            code: "etag_conflict_detected".to_string(),
            message,
            remote_revision,
            remote_etag,
        },
        ConditionalWriteError::Storage(error) => {
            AppError::Internal(format!("Database error: {error}"))
        }
        ConditionalWriteError::Serialization(error) => {
            AppError::Internal(format!("Serialization error: {error}"))
        }
    }
}

/// Validate namespace names: 1-128 chars, alphanumeric + dash/underscore/dot only.
pub(crate) fn validate_namespace(ns: &str) -> Result<(), AppError> {
    if ns.is_empty() || ns.len() > 128 {
        return Err(AppError::BadRequest(
            "Namespace must be 1-128 characters".to_string(),
        ));
    }
    if !ns
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(AppError::BadRequest(
            "Namespace may only contain alphanumeric, dash, underscore, dot".to_string(),
        ));
    }
    Ok(())
}

// ── Storage Helpers ──

fn encrypt_if_needed(state: &AppState, data: &[u8]) -> Result<Vec<u8>, AppError> {
    match &state.encryption_key {
        Some(key) => crypto::encrypt(key, data).map_err(|e| AppError::Internal(e)),
        None => Ok(data.to_vec()),
    }
}

fn decrypt_if_needed(state: &AppState, data: &[u8]) -> Result<Vec<u8>, AppError> {
    match &state.encryption_key {
        Some(key) => crypto::decrypt(key, data).map_err(|e| AppError::Internal(e)),
        None => Ok(data.to_vec()),
    }
}

// ── GET /v1/namespaces/:namespace/metadata ──

async fn get_metadata(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let namespace = decode_namespace(&namespace)?;
    authorize_sync_request_with_permission(&headers, &state, &namespace, SyncPermission::Read)?;

    match state.db.get_metadata(&namespace)? {
        Some(data) => {
            let meta: SyncMetadata = serde_json::from_slice(&data)?;
            Ok(Json(meta).into_response())
        }
        None => Ok(Json(SyncMetadata::empty()).into_response()),
    }
}

// ── PUT /v1/namespaces/:namespace/metadata ──

async fn put_metadata(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MetadataWriteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let namespace = decode_namespace(&namespace)?;
    authorize_sync_request_with_permission(&headers, &state, &namespace, SyncPermission::Write)?;

    // Build new metadata from existing + request
    let existing = state
        .db
        .get_metadata(&namespace)?
        .and_then(|d| serde_json::from_slice::<SyncMetadata>(&d).ok());

    let etag = uuid::Uuid::new_v4().to_string();

    let meta = SyncMetadata {
        exists: true,
        format: body.format,
        revision: Some(body.revision),
        etag: Some(etag.clone()),
        content_hash: existing.as_ref().and_then(|e| e.content_hash.clone()),
        uploaded_at: body
            .uploaded_at
            .or_else(|| Some(chrono::Utc::now().to_rfc3339())),
        device_id: body.device_id,
        content_length: existing.as_ref().map(|e| e.content_length).unwrap_or(0),
        section_revisions: body.section_revisions,
        sections: body.sections,
        content_type: body.content_type,
        scope: body.scope,
    };

    let serialized = serde_json::to_vec(&meta)?;
    state.db.set_metadata(&namespace, &serialized)?;

    Ok(Json(json!({ "etag": etag })))
}

// ── GET /v1/namespaces/:namespace/blob ──

async fn get_blob(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let namespace = decode_namespace(&namespace)?;
    authorize_sync_request_with_permission(&headers, &state, &namespace, SyncPermission::Read)?;

    let encrypted_blob = state
        .db
        .get_blob(&namespace)?
        .ok_or_else(|| AppError::NotFound("No blob found".to_string()))?;

    let blob = decrypt_if_needed(&state, &encrypted_blob)?;

    // Get metadata for etag
    let etag = state
        .db
        .get_metadata(&namespace)?
        .and_then(|d| serde_json::from_slice::<SyncMetadata>(&d).ok())
        .and_then(|m| m.etag);

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "content-type",
        "application/vnd.oxideterm.oxide".parse().unwrap(),
    );
    if let Some(etag_val) = etag {
        if let Ok(hv) = etag_val.parse() {
            response_headers.insert("etag", hv);
        }
    }

    Ok((response_headers, blob))
}

// ── PUT /v1/namespaces/:namespace/blob ──

async fn put_blob(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    let namespace = decode_namespace(&namespace)?;
    authorize_sync_request_with_permission(&headers, &state, &namespace, SyncPermission::Write)?;

    if body.len() > state.max_blob_size {
        return Err(AppError::PayloadTooLarge(format!(
            "Blob size {} exceeds limit {}",
            body.len(),
            state.max_blob_size
        )));
    }

    let existing_meta = state
        .db
        .get_metadata(&namespace)?
        .and_then(|d| serde_json::from_slice::<SyncMetadata>(&d).ok());

    let if_match = headers.get("if-match").and_then(|v| v.to_str().ok());
    let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());

    // Extract headers
    let revision = headers
        .get("x-oxideterm-revision")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let device_id = headers
        .get("x-oxideterm-device-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let section_revisions_raw = headers
        .get("x-oxideterm-section-revisions")
        .and_then(|v| v.to_str().ok());
    let section_revisions: Option<SectionRevisions> =
        section_revisions_raw.and_then(|raw| serde_json::from_str(raw).ok());

    // Encrypt and store
    let content_hash = crypto::sha256_hex(&body);
    let encrypted = encrypt_if_needed(&state, &body)?;

    // Update metadata
    let new_etag = uuid::Uuid::new_v4().to_string();
    let meta = SyncMetadata {
        exists: true,
        format: existing_meta.as_ref().and_then(|m| m.format.clone()),
        revision: revision.clone(),
        etag: Some(new_etag.clone()),
        content_hash: Some(content_hash),
        uploaded_at: Some(chrono::Utc::now().to_rfc3339()),
        device_id,
        content_length: body.len() as u64,
        section_revisions: section_revisions.clone(),
        sections: existing_meta.as_ref().and_then(|m| m.sections.clone()),
        content_type: Some("application/vnd.oxideterm.oxide".to_string()),
        scope: existing_meta.as_ref().and_then(|m| m.scope.clone()),
    };

    // Atomic write: blob + metadata in a single transaction to prevent TOCTOU race
    let serialized_meta = serde_json::to_vec(&meta)?;
    state
        .db
        .put_blob_if_matches(
            &namespace,
            if_match,
            if_none_match == Some("*"),
            &encrypted,
            &serialized_meta,
        )
        .map_err(map_conditional_write_error)?;

    Ok(Json(WriteResponse {
        ok: true,
        revision,
        etag: Some(new_etag),
        section_revisions,
        error: None,
    }))
}

// ── GET /v1/namespaces/:namespace/objects/*path ──

async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((namespace, obj_path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let namespace = decode_namespace(&namespace)?;
    authorize_sync_request_with_permission(&headers, &state, &namespace, SyncPermission::Read)?;

    let decoded_path = decode_object_path(&obj_path)?;

    match state.db.get_object(&namespace, &decoded_path)? {
        Some(encrypted) => {
            let data = decrypt_if_needed(&state, &encrypted)?;
            let object_meta = state.db.get_object_metadata(&namespace, &decoded_path)?;

            let content_type = if decoded_path.ends_with(".json") {
                "application/json"
            } else if decoded_path.ends_with(".oxide") {
                "application/vnd.oxideterm.oxide"
            } else {
                "application/octet-stream"
            };

            let mut response_headers = HeaderMap::new();
            response_headers.insert("content-type", content_type.parse().unwrap());
            if let Some(object_meta) = object_meta {
                if let Ok(hv) = object_meta.etag.parse() {
                    response_headers.insert("etag", hv);
                }
            }

            Ok((StatusCode::OK, response_headers, data).into_response())
        }
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

// ── PUT /v1/namespaces/:namespace/objects/*path ──

async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((namespace, obj_path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    let namespace = decode_namespace(&namespace)?;
    authorize_sync_request_with_permission(&headers, &state, &namespace, SyncPermission::Write)?;

    let decoded_path = decode_object_path(&obj_path)?;

    if body.len() > state.max_object_size {
        return Err(AppError::PayloadTooLarge(format!(
            "Object size {} exceeds limit {}",
            body.len(),
            state.max_object_size
        )));
    }

    let encrypted = encrypt_if_needed(&state, &body)?;
    let etag = uuid::Uuid::new_v4().to_string();
    let object_meta = StoredObjectMetadata {
        etag: etag.clone(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    let if_match = headers.get("if-match").and_then(|v| v.to_str().ok());
    let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());

    state
        .db
        .put_object_if_matches(
            &namespace,
            &decoded_path,
            if_match,
            if_none_match == Some("*"),
            &encrypted,
            &object_meta,
        )
        .map_err(map_conditional_write_error)?;

    Ok(Json(ObjectWriteResponse { etag: Some(etag) }))
}
