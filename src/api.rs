// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::{ffi::CString, sync::Arc};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use crate::auth;
use crate::config::*;
use crate::crypto;
use crate::db::{ConditionalWriteError, Database};
use crate::error::AppError;
use crate::panel;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub db_path: String,
    pub encryption_key: Option<[u8; 32]>,
    pub admin_password_hash: Option<String>,
    pub jwt_secret: String,
    pub admin_jwt_secret_persistent: bool,
    pub admin_cookie_secure: bool,
    pub token_reveal_key: [u8; 32],
    pub token_reveal_persistent: bool,
    pub trust_proxy_headers: bool,
    pub sync_cors_allowed_origins: Vec<String>,
    pub max_blob_size: usize,
    pub max_object_size: usize,
    pub login_window_seconds: i64,
    pub login_lockout_seconds: i64,
    pub max_login_failures: u32,
    pub default_token_ttl_seconds: Option<i64>,
    pub metadata_retention: MetadataRetentionConfig,
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
        .route("/ready", get(readiness_check));

    let sync_api =
        if let Some(cors_layer) = build_sync_cors_layer(&shared.sync_cors_allowed_origins) {
            sync_api.layer(cors_layer)
        } else {
            sync_api
        };

    let admin_api = panel::admin_router();

    sync_api.merge(admin_api).with_state(shared)
}

fn build_sync_cors_layer(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }

    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::PUT, Method::OPTIONS])
        .allow_headers(Any);

    if origins.iter().any(|origin| origin == "*") {
        Some(layer.allow_origin(Any))
    } else {
        let values = origins
            .iter()
            .map(|origin| {
                HeaderValue::from_str(origin)
                    .unwrap_or_else(|_| panic!("Invalid CORS origin configured: {origin}"))
            })
            .collect::<Vec<_>>();
        Some(layer.allow_origin(AllowOrigin::list(values)))
    }
}

// ── Health Check ──

async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "oxideterm-cloud-sync-server" }))
}

async fn readiness_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let db_writable = state.db.check_writable().is_ok();
    let disk_free_bytes = disk_free_bytes(&state.db_path);
    let db_size_bytes = std::fs::metadata(&state.db_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let ready = db_writable;

    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(json!({
            "status": if ready { "ready" } else { "degraded" },
            "dbWritable": db_writable,
            "dbSizeBytes": db_size_bytes,
            "diskFreeBytes": disk_free_bytes,
            "encryptionEnabled": state.encryption_key.is_some(),
            "adminEnabled": state.admin_password_hash.is_some(),
            "jwtSecretPersistent": state.admin_jwt_secret_persistent,
        })),
    )
}

#[cfg(unix)]
fn disk_free_bytes(path: &str) -> Option<u64> {
    let c_path = CString::new(path).ok()?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let stats = unsafe { stats.assume_init() };
    Some((stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64))
}

#[cfg(not(unix))]
fn disk_free_bytes(_path: &str) -> Option<u64> {
    None
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
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, basic.trim())
                .map_err(|_| AppError::Unauthorized("Invalid Basic auth encoding".to_string()))?;
        let credential = String::from_utf8(decoded)
            .map_err(|_| AppError::Unauthorized("Invalid Basic auth encoding".to_string()))?;
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

    let token = token.ok_or_else(|| AppError::Unauthorized("Invalid token".to_string()))?;
    ensure_token_active(&token)?;
    Ok(token)
}

fn ensure_token_active(token: &ApiToken) -> Result<(), AppError> {
    if !token.enabled {
        return Err(AppError::Unauthorized("Token is disabled".to_string()));
    }
    if token_expired(token) {
        return Err(AppError::Unauthorized("Token has expired".to_string()));
    }
    Ok(())
}

fn token_expired(token: &ApiToken) -> bool {
    token
        .expires_at
        .as_deref()
        .and_then(parse_rfc3339_utc)
        .is_some_and(|expires_at| expires_at <= chrono::Utc::now())
}

fn parse_rfc3339_utc(input: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(input)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn authorize_sync_request_with_permission(
    headers: &HeaderMap,
    state: &AppState,
    namespace: &str,
    permission: SyncPermission,
) -> Result<ApiToken, AppError> {
    ensure_namespace_active(state, namespace)?;
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

fn ensure_namespace_active(state: &AppState, namespace: &str) -> Result<(), AppError> {
    if state.db.is_namespace_deleted(namespace)? {
        return Err(AppError::NotFound(format!(
            "Namespace '{}' is soft-deleted",
            namespace
        )));
    }
    Ok(())
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
        Some(key) => crypto::encrypt(key, data).map_err(AppError::Internal),
        None => Ok(data.to_vec()),
    }
}

fn decrypt_if_needed(state: &AppState, data: &[u8]) -> Result<Vec<u8>, AppError> {
    match &state.encryption_key {
        Some(key) => crypto::decrypt(key, data).map_err(AppError::Internal),
        None => Ok(data.to_vec()),
    }
}

fn retain_metadata_value<T>(enabled: bool, value: Option<T>) -> Option<T> {
    if enabled {
        value
    } else {
        None
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

    let existing = state
        .db
        .get_metadata(&namespace)?
        .and_then(|d| serde_json::from_slice::<SyncMetadata>(&d).ok());

    let etag = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let response_revision = Some(body.revision.clone());

    let meta = SyncMetadata {
        exists: true,
        format: body.format,
        revision: retain_metadata_value(
            state.metadata_retention.store_revision,
            Some(body.revision),
        ),
        etag: Some(etag.clone()),
        content_hash: retain_metadata_value(
            state.metadata_retention.store_content_hash,
            existing.as_ref().and_then(|e| e.content_hash.clone()),
        ),
        uploaded_at: retain_metadata_value(
            state.metadata_retention.store_uploaded_at,
            body.uploaded_at.or(Some(now)),
        ),
        device_id: retain_metadata_value(state.metadata_retention.store_device_id, body.device_id),
        content_length: existing.as_ref().map(|e| e.content_length).unwrap_or(0),
        section_revisions: body.section_revisions,
        sections: body.sections,
        content_type: body.content_type,
        scope: body.scope,
    };

    let serialized = serde_json::to_vec(&meta)?;
    state.db.set_metadata(&namespace, &serialized)?;

    Ok(Json(WriteResponse {
        ok: true,
        revision: response_revision,
        etag: Some(etag),
        section_revisions: meta.section_revisions,
        error: None,
    }))
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

    let content_hash = crypto::sha256_hex(&body);
    let encrypted = encrypt_if_needed(&state, &body)?;

    let new_etag = uuid::Uuid::new_v4().to_string();
    let meta = SyncMetadata {
        exists: true,
        format: existing_meta.as_ref().and_then(|m| m.format.clone()),
        revision: retain_metadata_value(state.metadata_retention.store_revision, revision.clone()),
        etag: Some(new_etag.clone()),
        content_hash: retain_metadata_value(
            state.metadata_retention.store_content_hash,
            Some(content_hash),
        ),
        uploaded_at: retain_metadata_value(
            state.metadata_retention.store_uploaded_at,
            Some(chrono::Utc::now().to_rfc3339()),
        ),
        device_id: retain_metadata_value(state.metadata_retention.store_device_id, device_id),
        content_length: body.len() as u64,
        section_revisions: section_revisions.clone(),
        sections: existing_meta.as_ref().and_then(|m| m.sections.clone()),
        content_type: Some("application/vnd.oxideterm.oxide".to_string()),
        scope: existing_meta.as_ref().and_then(|m| m.scope.clone()),
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_tokens_are_rejected() {
        let token = ApiToken {
            id: "tok-1".into(),
            name: "test".into(),
            token_hash: "hash".into(),
            encrypted_token: None,
            namespace_pattern: "*".into(),
            permissions: vec!["read".into()],
            created_at: chrono::Utc::now().to_rfc3339(),
            enabled: true,
            expires_at: Some((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339()),
            rotated_at: None,
            disabled_at: None,
            last_used_at: None,
        };
        assert!(ensure_token_active(&token).is_err());
    }

    #[test]
    fn retain_metadata_value_clears_when_disabled() {
        assert_eq!(
            retain_metadata_value(false, Some("value".to_string())),
            None
        );
        assert_eq!(
            retain_metadata_value(true, Some("value".to_string())),
            Some("value".to_string())
        );
    }
}
