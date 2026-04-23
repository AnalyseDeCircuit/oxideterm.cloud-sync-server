// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Json, Router,
};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use crate::api::AppState;
use crate::auth;
use crate::config::*;
use crate::crypto;
use crate::error::AppError;

const ADMIN_COOKIE_NAME: &str = "admin_session";
const ADMIN_COOKIE_PATH: &str = "/admin";

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin", get(admin_page))
        .route("/admin/api/login", post(admin_login))
        .route("/admin/api/logout", post(admin_logout))
        .route(
            "/admin/api/namespaces",
            get(admin_list_namespaces).post(admin_create_namespace),
        )
        .route(
            "/admin/api/namespaces/{namespace}",
            delete(admin_delete_namespace),
        )
        .route(
            "/admin/api/namespaces/{namespace}/restore",
            post(admin_restore_namespace),
        )
        .route(
            "/admin/api/tokens",
            get(admin_list_tokens).post(admin_create_token),
        )
        .route(
            "/admin/api/tokens/{id}",
            delete(admin_delete_token).patch(admin_update_token),
        )
        .route("/admin/api/tokens/{id}/rotate", post(admin_rotate_token))
        .route("/admin/api/tokens/{id}/reveal", get(admin_reveal_token))
        .route("/admin/api/stats", get(admin_stats))
}

// ── Admin Auth ──

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(';').find_map(|part| {
                let part = part.trim();
                let (cookie_name, cookie_value) = part.split_once('=')?;
                (cookie_name == name).then(|| cookie_value.to_string())
            })
        })
}

fn extract_admin_token(headers: &HeaderMap) -> Option<String> {
    extract_cookie(headers, ADMIN_COOKIE_NAME).or_else(|| {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| v.trim().to_string())
    })
}

fn build_admin_session_cookie(token: &str, secure: bool) -> String {
    format!(
        "{ADMIN_COOKIE_NAME}={token}; HttpOnly; Max-Age=86400; Path={ADMIN_COOKIE_PATH}; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

fn clear_admin_session_cookie(secure: bool) -> String {
    format!(
        "{ADMIN_COOKIE_NAME}=; HttpOnly; Max-Age=0; Path={ADMIN_COOKIE_PATH}; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT{}",
        if secure { "; Secure" } else { "" }
    )
}

fn verify_admin(headers: &HeaderMap, state: &AppState) -> Result<(), AppError> {
    if state.admin_password_hash.is_none() {
        return Err(AppError::NotFound("Admin panel disabled".to_string()));
    }

    let token = extract_admin_token(headers)
        .ok_or_else(|| AppError::Unauthorized("Missing admin session".to_string()))?;

    auth::validate_admin_jwt(token.trim(), &state.jwt_secret)
        .map_err(|_| AppError::Unauthorized("Invalid or expired admin session".to_string()))?;

    Ok(())
}

fn normalize_optional_timestamp(value: Option<String>) -> Result<Option<String>, AppError> {
    value
        .map(|value| {
            chrono::DateTime::parse_from_rfc3339(value.trim())
                .map(|dt| dt.with_timezone(&chrono::Utc).to_rfc3339())
                .map_err(|_| {
                    AppError::BadRequest("Timestamp must be valid RFC3339 / ISO-8601".to_string())
                })
        })
        .transpose()
}

fn effective_token_expiry(
    state: &AppState,
    requested: Option<String>,
) -> Result<Option<String>, AppError> {
    if let Some(expires_at) = normalize_optional_timestamp(requested)? {
        return Ok(Some(expires_at));
    }
    Ok(state
        .default_token_ttl_seconds
        .map(|ttl| (chrono::Utc::now() + chrono::Duration::seconds(ttl)).to_rfc3339()))
}

fn token_expired(token: &ApiToken) -> bool {
    token.expires_at.as_deref().is_some_and(|expires_at| {
        chrono::DateTime::parse_from_rfc3339(expires_at)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc) <= chrono::Utc::now())
            .unwrap_or(false)
    })
}

fn serialize_token_summary(token: &ApiToken) -> serde_json::Value {
    json!({
        "id": token.id,
        "name": token.name,
        "canReveal": token.encrypted_token.is_some(),
        "namespacePattern": token.namespace_pattern,
        "permissions": token.permissions,
        "createdAt": token.created_at,
        "lastUsedAt": token.last_used_at,
        "enabled": token.enabled,
        "expiresAt": token.expires_at,
        "rotatedAt": token.rotated_at,
        "disabledAt": token.disabled_at,
        "expired": token_expired(token),
    })
}

fn resolve_client_ip(headers: &HeaderMap, peer_ip: IpAddr, state: &AppState) -> IpAddr {
    if !state.trust_proxy_headers {
        return peer_ip;
    }

    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
        })
        .map(str::trim)
        .and_then(|value| value.parse::<IpAddr>().ok())
        .unwrap_or(peer_ip)
}

fn ensure_login_allowed(state: &AppState, ip: IpAddr) -> Result<(), AppError> {
    let now = chrono::Utc::now();
    state
        .db
        .cleanup_login_attempts(now, state.login_window_seconds)?;

    let ip_key = ip.to_string();
    if let Some(attempt) = state.db.get_login_attempt(&ip_key)? {
        if let Some(blocked_until) = attempt
            .blocked_until
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
        {
            if blocked_until > now {
                let retry_after = blocked_until.signed_duration_since(now).num_seconds();
                tracing::warn!(
                    target: "audit",
                    event = "admin_login_blocked",
                    client_ip = %ip,
                    retry_after_seconds = retry_after.max(1),
                    "Admin login blocked by rate limiter"
                );
                return Err(AppError::TooManyRequests(format!(
                    "Too many login attempts. Retry in {} seconds",
                    retry_after.max(1)
                )));
            }
        }
    }

    Ok(())
}

fn record_login_failure(state: &AppState, ip: IpAddr) -> Result<LoginAttemptRecord, AppError> {
    let now = chrono::Utc::now();
    let ip_key = ip.to_string();
    let mut attempt = state
        .db
        .get_login_attempt(&ip_key)?
        .unwrap_or(LoginAttemptRecord {
            first_failure_at: now.to_rfc3339(),
            failures: 0,
            blocked_until: None,
        });

    let first_failure_at = chrono::DateTime::parse_from_rfc3339(&attempt.first_failure_at)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc));
    if first_failure_at.is_none()
        || now
            .signed_duration_since(first_failure_at.unwrap())
            .num_seconds()
            > state.login_window_seconds
    {
        attempt.first_failure_at = now.to_rfc3339();
        attempt.failures = 0;
        attempt.blocked_until = None;
    }

    attempt.failures += 1;
    if attempt.failures >= state.max_login_failures {
        attempt.blocked_until =
            Some((now + chrono::Duration::seconds(state.login_lockout_seconds)).to_rfc3339());
    }
    state.db.set_login_attempt(&ip_key, &attempt)?;

    tracing::warn!(
        target: "audit",
        event = "admin_login_failed",
        client_ip = %ip,
        failures = attempt.failures,
        blocked_until = attempt.blocked_until.as_deref().unwrap_or(""),
        "Admin login failed"
    );

    Ok(attempt)
}

fn clear_login_failures(state: &AppState, ip: IpAddr) -> Result<(), AppError> {
    state.db.delete_login_attempt(&ip.to_string())?;
    Ok(())
}

// ── Admin Page (Embedded SPA) ──

async fn admin_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.admin_password_hash.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Html("Admin panel disabled".to_string()),
        );
    }
    (StatusCode::OK, Html(ADMIN_HTML.to_string()))
}

// ── POST /admin/api/login ──

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

async fn admin_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);
    ensure_login_allowed(&state, client_ip)?;

    let hash = state
        .admin_password_hash
        .as_ref()
        .ok_or_else(|| AppError::NotFound("Admin panel disabled".to_string()))?;

    if !auth::verify_admin_password(&body.password, hash) {
        let _ = record_login_failure(&state, client_ip)?;
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    clear_login_failures(&state, client_ip)?;

    let jwt = auth::create_admin_jwt(&state.jwt_secret)
        .map_err(|e| AppError::Internal(format!("JWT creation failed: {e}")))?;
    let cookie = build_admin_session_cookie(&jwt, state.admin_cookie_secure);

    tracing::info!(
        target: "audit",
        event = "admin_login_succeeded",
        client_ip = %client_ip,
        "Admin login succeeded"
    );

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "set-cookie",
        HeaderValue::from_str(&cookie)
            .map_err(|e| AppError::Internal(format!("Invalid session cookie: {e}")))?,
    );
    Ok((response_headers, Json(json!({ "ok": true }))))
}

async fn admin_logout(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    let mut response_headers = HeaderMap::new();
    let cookie = clear_admin_session_cookie(state.admin_cookie_secure);
    response_headers.insert(
        "set-cookie",
        HeaderValue::from_str(&cookie)
            .map_err(|e| AppError::Internal(format!("Invalid clear cookie: {e}")))?,
    );
    Ok((response_headers, Json(json!({ "ok": true }))))
}

// ── GET /admin/api/namespaces ──

async fn admin_list_namespaces(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;

    let mut infos = Vec::new();

    for ns in state.db.list_namespaces()? {
        let meta = state
            .db
            .get_metadata(&ns)?
            .and_then(|d| serde_json::from_slice::<SyncMetadata>(&d).ok());
        let obj_count = state.db.count_objects(&ns)?;

        infos.push(NamespaceInfo {
            namespace: ns,
            revision: meta.as_ref().and_then(|m| m.revision.clone()),
            uploaded_at: meta.as_ref().and_then(|m| m.uploaded_at.clone()),
            device_id: meta.as_ref().and_then(|m| m.device_id.clone()),
            blob_size: meta.as_ref().map(|m| m.content_length).unwrap_or(0),
            object_count: obj_count,
            format: meta.as_ref().and_then(|m| m.format.clone()),
            deleted_at: None,
        });
    }

    for (ns, deleted) in state.db.list_deleted_namespaces()? {
        let meta = state
            .db
            .get_metadata(&ns)?
            .and_then(|d| serde_json::from_slice::<SyncMetadata>(&d).ok());
        let obj_count = state.db.count_objects(&ns)?;

        infos.push(NamespaceInfo {
            namespace: ns,
            revision: meta.as_ref().and_then(|m| m.revision.clone()),
            uploaded_at: meta.as_ref().and_then(|m| m.uploaded_at.clone()),
            device_id: meta.as_ref().and_then(|m| m.device_id.clone()),
            blob_size: meta.as_ref().map(|m| m.content_length).unwrap_or(0),
            object_count: obj_count,
            format: meta.as_ref().and_then(|m| m.format.clone()),
            deleted_at: Some(deleted.deleted_at),
        });
    }

    infos.sort_by(|a, b| a.namespace.cmp(&b.namespace));
    Ok(Json(infos))
}

// ── POST /admin/api/namespaces ──

#[derive(Deserialize)]
struct CreateNamespaceRequest {
    namespace: String,
}

async fn admin_create_namespace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<CreateNamespaceRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    let namespace = body.namespace.trim().to_string();
    crate::api::validate_namespace(&namespace)?;

    if state.db.is_namespace_deleted(&namespace)? {
        return Err(AppError::BadRequest(format!(
            "Namespace '{}' is soft-deleted. Restore or purge it first.",
            namespace
        )));
    }
    if state.db.get_metadata(&namespace)?.is_some() {
        return Err(AppError::BadRequest(format!(
            "Namespace '{}' already exists",
            namespace
        )));
    }

    let meta = SyncMetadata::empty();
    let serialized = serde_json::to_vec(&meta)
        .map_err(|e| AppError::Internal(format!("Failed to serialize metadata: {e}")))?;
    state.db.set_metadata(&namespace, &serialized)?;

    tracing::info!(
        target: "audit",
        event = "namespace_created",
        client_ip = %client_ip,
        namespace = %namespace,
        "Namespace created"
    );

    Ok(Json(json!({ "ok": true, "namespace": namespace })))
}

// ── DELETE /admin/api/namespaces/:namespace ──

#[derive(Deserialize)]
struct DeleteNamespaceQuery {
    hard: Option<bool>,
}

async fn admin_delete_namespace(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(namespace): axum::extract::Path<String>,
    Query(query): Query<DeleteNamespaceQuery>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);
    let hard = query.hard.unwrap_or(false);

    if hard {
        state.db.hard_delete_namespace(&namespace)?;
        tracing::info!(
            target: "audit",
            event = "namespace_hard_deleted",
            client_ip = %client_ip,
            namespace = %namespace,
            "Namespace permanently deleted"
        );
        return Ok(Json(json!({ "ok": true, "mode": "hard" })));
    }

    if state.db.is_namespace_deleted(&namespace)? {
        return Err(AppError::BadRequest(format!(
            "Namespace '{}' is already soft-deleted",
            namespace
        )));
    }
    if state.db.get_metadata(&namespace)?.is_none() {
        return Err(AppError::NotFound(format!(
            "Namespace '{}' not found",
            namespace
        )));
    }

    state
        .db
        .soft_delete_namespace(&namespace, &chrono::Utc::now().to_rfc3339())?;

    tracing::info!(
        target: "audit",
        event = "namespace_soft_deleted",
        client_ip = %client_ip,
        namespace = %namespace,
        "Namespace soft-deleted"
    );

    Ok(Json(json!({ "ok": true, "mode": "soft" })))
}

async fn admin_restore_namespace(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(namespace): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    if !state.db.is_namespace_deleted(&namespace)? {
        return Err(AppError::NotFound(format!(
            "Namespace '{}' is not soft-deleted",
            namespace
        )));
    }
    state.db.restore_namespace(&namespace)?;

    tracing::info!(
        target: "audit",
        event = "namespace_restored",
        client_ip = %client_ip,
        namespace = %namespace,
        "Namespace restored"
    );

    Ok(Json(json!({ "ok": true })))
}

// ── Tokens ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenRequest {
    name: String,
    namespace_pattern: String,
    permissions: Option<Vec<String>>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTokenRequest {
    enabled: Option<bool>,
    expires_at: Option<Option<String>>,
}

async fn admin_list_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let tokens = state.db.get_all_tokens()?;
    let safe_tokens: Vec<serde_json::Value> = tokens.iter().map(serialize_token_summary).collect();
    Ok(Json(safe_tokens))
}

async fn admin_create_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<CreateTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    if !auth::validate_namespace_pattern(&body.namespace_pattern) {
        return Err(AppError::BadRequest(
            "Namespace pattern must be '*' , an exact namespace, or a prefix ending with '*'"
                .to_string(),
        ));
    }

    let permissions = auth::normalize_permissions(
        body.permissions
            .unwrap_or_else(|| vec!["read".into(), "write".into()]),
    );
    if !auth::validate_permissions(&permissions) {
        return Err(AppError::BadRequest(
            "Permissions must be a non-empty subset of ['read', 'write']".to_string(),
        ));
    }

    let raw_token = uuid::Uuid::new_v4().to_string();
    let token_hash = auth::hash_api_token(&raw_token);
    let encrypted_token = crypto::encrypt(&state.token_reveal_key, raw_token.as_bytes())
        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
        .map_err(|e| AppError::Internal(format!("Token encryption failed: {e}")))?;
    let id = uuid::Uuid::new_v4().to_string();
    let expires_at = effective_token_expiry(&state, body.expires_at)?;

    let token = ApiToken {
        id: id.clone(),
        name: body.name,
        token_hash,
        encrypted_token: Some(encrypted_token),
        namespace_pattern: body.namespace_pattern,
        permissions,
        created_at: chrono::Utc::now().to_rfc3339(),
        enabled: true,
        expires_at,
        rotated_at: None,
        disabled_at: None,
        last_used_at: None,
    };

    state.db.set_token(&token)?;

    tracing::info!(
        target: "audit",
        event = "token_created",
        client_ip = %client_ip,
        token_id = %id,
        namespace_pattern = %token.namespace_pattern,
        permissions = %token.permissions.join(","),
        expires_at = token.expires_at.as_deref().unwrap_or(""),
        "API token created"
    );

    Ok(Json(json!({
        "id": id,
        "token": raw_token,
        "name": token.name,
        "namespacePattern": token.namespace_pattern,
        "permissions": token.permissions,
        "createdAt": token.created_at,
        "expiresAt": token.expires_at,
    })))
}

async fn admin_update_token(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<UpdateTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    let mut token = state
        .db
        .get_token(&id)?
        .ok_or_else(|| AppError::NotFound(format!("Token '{}' not found", id)))?;

    if let Some(enabled) = body.enabled {
        token.enabled = enabled;
        token.disabled_at = if enabled {
            None
        } else {
            Some(chrono::Utc::now().to_rfc3339())
        };
    }
    if let Some(expires_at) = body.expires_at {
        token.expires_at = normalize_optional_timestamp(expires_at)?;
    }

    state.db.set_token(&token)?;

    tracing::info!(
        target: "audit",
        event = "token_updated",
        client_ip = %client_ip,
        token_id = %token.id,
        enabled = token.enabled,
        expires_at = token.expires_at.as_deref().unwrap_or(""),
        "API token updated"
    );

    Ok(Json(serialize_token_summary(&token)))
}

async fn admin_rotate_token(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    let mut token = state
        .db
        .get_token(&id)?
        .ok_or_else(|| AppError::NotFound(format!("Token '{}' not found", id)))?;

    let raw_token = uuid::Uuid::new_v4().to_string();
    token.token_hash = auth::hash_api_token(&raw_token);
    token.encrypted_token = Some(
        base64::engine::general_purpose::STANDARD.encode(
            crypto::encrypt(&state.token_reveal_key, raw_token.as_bytes())
                .map_err(|e| AppError::Internal(format!("Token encryption failed: {e}")))?,
        ),
    );
    token.rotated_at = Some(chrono::Utc::now().to_rfc3339());
    state.db.set_token(&token)?;

    tracing::info!(
        target: "audit",
        event = "token_rotated",
        client_ip = %client_ip,
        token_id = %token.id,
        "API token rotated"
    );

    Ok(Json(json!({
        "id": token.id,
        "token": raw_token,
        "rotatedAt": token.rotated_at,
    })))
}

async fn admin_reveal_token(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    let token = state
        .db
        .get_token(&id)?
        .ok_or_else(|| AppError::NotFound(format!("Token '{}' not found", id)))?;
    let encrypted_token = token.encrypted_token.ok_or_else(|| {
        AppError::BadRequest(
            "This token was created before reveal support and cannot be recovered. Create a new token to enable reveal.".to_string(),
        )
    })?;

    let encrypted_bytes = base64::engine::general_purpose::STANDARD
        .decode(encrypted_token)
        .map_err(|e| AppError::Internal(format!("Stored token decode failed: {e}")))?;
    let raw_token = crypto::decrypt(&state.token_reveal_key, &encrypted_bytes)
        .map_err(|_| {
            AppError::BadRequest(
                "This token can no longer be revealed because the server secret changed. Re-create it to recover access.".to_string(),
            )
        })
        .and_then(|bytes| {
            String::from_utf8(bytes).map_err(|e| {
                AppError::Internal(format!("Stored token is not valid UTF-8: {e}"))
            })
        })?;

    tracing::info!(
        target: "audit",
        event = "token_revealed",
        client_ip = %client_ip,
        token_id = %token.id,
        "API token revealed"
    );

    Ok(Json(json!({
        "id": token.id,
        "token": raw_token,
        "persistent": state.token_reveal_persistent,
    })))
}

async fn admin_delete_token(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    state.db.delete_token(&id)?;

    tracing::info!(
        target: "audit",
        event = "token_deleted",
        client_ip = %client_ip,
        token_id = %id,
        "API token deleted"
    );

    Ok(Json(json!({ "ok": true })))
}

// ── GET /admin/api/stats ──

async fn admin_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;

    let namespaces = state.db.list_namespaces()?;
    let deleted_namespaces = state.db.list_deleted_namespaces()?;
    let tokens = state.db.get_all_tokens()?;
    let encrypted = state.encryption_key.is_some();
    let db_writable = state.db.check_writable().is_ok();
    let db_size_bytes = std::fs::metadata(&state.db_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let disabled_tokens = tokens.iter().filter(|token| !token.enabled).count();
    let expired_tokens = tokens.iter().filter(|token| token_expired(token)).count();

    Ok(Json(json!({
        "namespaceCount": namespaces.len(),
        "deletedNamespaceCount": deleted_namespaces.len(),
        "tokenCount": tokens.len(),
        "disabledTokenCount": disabled_tokens,
        "expiredTokenCount": expired_tokens,
        "encryptionEnabled": encrypted,
        "tokenRevealPersistent": state.token_reveal_persistent,
        "jwtSecretPersistent": state.admin_jwt_secret_persistent,
        "adminCookieSecure": state.admin_cookie_secure,
        "dbWritable": db_writable,
        "dbSizeBytes": db_size_bytes,
        "syncCorsOrigins": state.sync_cors_allowed_origins,
        "defaultTokenTtlSeconds": state.default_token_ttl_seconds,
        "loginWindowSeconds": state.login_window_seconds,
        "loginLockoutSeconds": state.login_lockout_seconds,
        "maxLoginFailures": state.max_login_failures,
        "metadataRetention": {
            "storeRevision": state.metadata_retention.store_revision,
            "storeUploadedAt": state.metadata_retention.store_uploaded_at,
            "storeDeviceId": state.metadata_retention.store_device_id,
            "storeContentHash": state.metadata_retention.store_content_hash,
        },
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

// ── Embedded Admin SPA ──

const ADMIN_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OxideTerm Cloud Sync — Admin</title>
<style>
  :root {
    --ot-bg-page: #f8f4eb;
    --ot-bg-surface: #f0eadd;
    --ot-bg-elevated: #e8e0d0;
    --ot-border: #d4cbbf;
    --ot-text-primary: #2a2118;
    --ot-text-secondary: #5c4f3e;
    --ot-text-muted: #8c7f6e;
    --ot-accent: #b7410e;
    --ot-accent-hover: #9e3a0c;
    --ot-green: #2d6a30;
    --ot-red: #9e2a1f;
    --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --font-mono: 'JetBrains Mono', 'Cascadia Code', 'Fira Code', monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --ot-bg-page: #1a1714;
      --ot-bg-surface: #221e1a;
      --ot-bg-elevated: #2d2822;
      --ot-border: #3d3630;
      --ot-text-primary: #e8e0d4;
      --ot-text-secondary: #b0a494;
      --ot-text-muted: #7a6e60;
    }
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: var(--font-sans);
    background: var(--ot-bg-page);
    color: var(--ot-text-primary);
    min-height: 100vh;
  }
  .container { max-width: 1120px; margin: 0 auto; padding: 2rem 1.5rem; }
  h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 0.25rem; }
  .subtitle { color: var(--ot-text-muted); font-size: 0.875rem; margin-bottom: 2rem; }
  .card {
    background: var(--ot-bg-surface);
    border: 1px solid var(--ot-border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .card h2 {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem;
  }
  .stat-item {
    background: var(--ot-bg-elevated);
    border-radius: 6px;
    padding: 1rem;
    text-align: center;
  }
  .stat-value {
    font-size: 1.75rem;
    font-weight: 700;
    font-family: var(--font-mono);
    color: var(--ot-accent);
  }
  .stat-label {
    font-size: 0.75rem;
    color: var(--ot-text-muted);
    margin-top: 0.25rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .status-strip {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-top: 1rem;
  }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th { text-align: left; padding: 0.5rem; color: var(--ot-text-muted); font-weight: 500; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--ot-border); }
  td { padding: 0.625rem 0.5rem; border-bottom: 1px solid var(--ot-border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: var(--font-mono); font-size: 0.8125rem; }
  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.6875rem;
    font-weight: 500;
  }
  .badge-green { background: #d4edda; color: var(--ot-green); }
  .badge-red { background: #f8d7da; color: var(--ot-red); }
  .badge-muted { background: var(--ot-bg-elevated); color: var(--ot-text-muted); }
  @media (prefers-color-scheme: dark) {
    .badge-green { background: #1a3d1e; }
    .badge-red { background: #3d1a1a; }
  }
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
    padding: 0.5rem 1rem;
    border: 1px solid var(--ot-border);
    border-radius: 6px;
    background: var(--ot-bg-surface);
    color: var(--ot-text-primary);
    font-size: 0.8125rem;
    font-family: inherit;
    cursor: pointer;
    transition: all 0.15s;
    margin-right: 0.25rem;
    margin-bottom: 0.25rem;
  }
  .btn:hover { background: var(--ot-bg-elevated); }
  .btn-primary {
    background: var(--ot-accent);
    color: #fff;
    border-color: var(--ot-accent);
  }
  .btn-primary:hover { background: var(--ot-accent-hover); }
  .btn-danger { color: var(--ot-red); }
  .btn-danger:hover { background: #f8d7da; }
  .btn-sm { padding: 0.25rem 0.625rem; font-size: 0.75rem; }
  input[type="text"], input[type="password"], input[type="datetime-local"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--ot-border);
    border-radius: 6px;
    background: var(--ot-bg-page);
    color: var(--ot-text-primary);
    font-size: 0.875rem;
    font-family: inherit;
  }
  input:focus { outline: 2px solid var(--ot-accent); outline-offset: -1px; }
  .form-group { margin-bottom: 1rem; }
  .form-group label { display: block; font-size: 0.8125rem; color: var(--ot-text-secondary); margin-bottom: 0.25rem; font-weight: 500; }
  .form-row { display: flex; gap: 1rem; }
  .form-row > * { flex: 1; }
  .token-reveal {
    background: var(--ot-bg-elevated);
    border: 1px solid var(--ot-accent);
    border-radius: 6px;
    padding: 1rem;
    margin-top: 1rem;
    word-break: break-all;
  }
  .token-reveal .label { font-size: 0.75rem; color: var(--ot-text-muted); margin-bottom: 0.25rem; }
  .token-reveal .value { font-family: var(--font-mono); font-size: 0.875rem; }
  .token-inline {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .token-inline .value {
    font-family: var(--font-mono);
    font-size: 0.8125rem;
    word-break: break-all;
  }
  .empty-state { text-align: center; padding: 2rem; color: var(--ot-text-muted); }
  .login-wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .login-card {
    background: var(--ot-bg-surface);
    border: 1px solid var(--ot-border);
    border-radius: 12px;
    padding: 2.5rem;
    width: 100%;
    max-width: 380px;
  }
  .login-card h1 { text-align: center; margin-bottom: 0.5rem; }
  .login-card .subtitle { text-align: center; }
  .error-msg { color: var(--ot-red); font-size: 0.8125rem; margin-top: 0.5rem; }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
  }
  .header-left h1 { margin-bottom: 0; }
  .hidden { display: none; }
  .flex-between { display: flex; justify-content: space-between; align-items: center; }
  .mb-1 { margin-bottom: 1rem; }
</style>
</head>
<body>

<div id="login-screen" class="login-wrapper hidden">
  <div class="login-card">
    <h1>OxideTerm Sync</h1>
    <p class="subtitle">Admin Panel</p>
    <form id="login-form">
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" placeholder="Enter admin password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%">Sign In</button>
      <div id="login-error" class="error-msg hidden"></div>
    </form>
  </div>
</div>

<div id="dashboard" class="container hidden">
  <div class="header">
    <div class="header-left">
      <h1>OxideTerm Cloud Sync</h1>
      <p class="subtitle">Server Administration</p>
    </div>
    <button class="btn btn-sm" onclick="logout()">Sign Out</button>
  </div>

  <div class="card">
    <h2>Overview</h2>
    <div class="stats-grid">
      <div class="stat-item">
        <div class="stat-value" id="stat-namespaces">-</div>
        <div class="stat-label">Namespaces</div>
      </div>
      <div class="stat-item">
        <div class="stat-value" id="stat-deleted-namespaces">-</div>
        <div class="stat-label">Soft Deleted</div>
      </div>
      <div class="stat-item">
        <div class="stat-value" id="stat-tokens">-</div>
        <div class="stat-label">API Tokens</div>
      </div>
      <div class="stat-item">
        <div class="stat-value" id="stat-disabled-tokens">-</div>
        <div class="stat-label">Disabled Tokens</div>
      </div>
      <div class="stat-item">
        <div class="stat-value" id="stat-ready">-</div>
        <div class="stat-label">DB Writable</div>
      </div>
      <div class="stat-item">
        <div class="stat-value" id="stat-version">-</div>
        <div class="stat-label">Version</div>
      </div>
    </div>
    <div class="status-strip" id="status-strip"></div>
  </div>

  <div class="card">
    <div class="flex-between mb-1">
      <h2>API Tokens</h2>
      <button class="btn btn-primary btn-sm" onclick="showCreateToken()">Create Token</button>
    </div>
    <div id="create-token-form" class="hidden" style="margin-bottom:1rem">
      <div class="form-row">
        <div class="form-group">
          <label>Name</label>
          <input type="text" id="token-name" placeholder="e.g. My MacBook">
        </div>
        <div class="form-group">
          <label>Namespace Pattern</label>
          <input type="text" id="token-ns" placeholder="* or my-namespace">
        </div>
        <div class="form-group">
          <label>Expires At (optional)</label>
          <input type="datetime-local" id="token-expiry">
        </div>
      </div>
      <button class="btn btn-primary btn-sm" onclick="createToken()">Generate</button>
      <button class="btn btn-sm" onclick="hideCreateToken()">Cancel</button>
    </div>
    <div id="new-token-reveal" class="token-reveal hidden">
      <div class="label">Copy this token now. You can reveal or rotate it later from this panel while the server keeps its reveal key.</div>
      <div class="value" id="new-token-value"></div>
    </div>
    <div id="tokens-table"></div>
  </div>

  <div class="card">
    <div class="flex-between mb-1">
      <h2>Namespaces</h2>
      <button class="btn btn-primary btn-sm" onclick="showCreateNs()">Create Namespace</button>
    </div>
    <div id="create-ns-form" class="hidden" style="margin-bottom:1rem">
      <div class="form-group">
        <label>Namespace Name</label>
        <input type="text" id="ns-name" placeholder="e.g. my-workspace">
      </div>
      <button class="btn btn-primary btn-sm" onclick="createNs()">Create</button>
      <button class="btn btn-sm" onclick="hideCreateNs()">Cancel</button>
    </div>
    <div id="namespaces-table"></div>
  </div>
</div>

<script>
const API = '/admin/api';
let tokenRevealPersistent = false;
const revealedTokens = {};

bootstrap();

async function bootstrap() {
  try {
    const res = await api('/stats', { allowUnauthorized: true });
    if (res.ok) {
      showDashboard();
      await loadAll();
      return;
    }
  } catch {}
  showLogin();
}

function showLogin() {
  document.getElementById('login-screen').classList.remove('hidden');
  document.getElementById('dashboard').classList.add('hidden');
}

function showDashboard() {
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
}

async function loadAll() {
  await loadStats();
  await loadTokens();
  await loadNamespaces();
}

async function logout() {
  try {
    await fetch(`${API}/logout`, { method: 'POST', credentials: 'same-origin' });
  } catch {}
  Object.keys(revealedTokens).forEach((key) => delete revealedTokens[key]);
  showLogin();
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = document.getElementById('password').value;
  const errEl = document.getElementById('login-error');
  errEl.classList.add('hidden');
  try {
    const res = await fetch(`${API}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ password: pw }),
    });
    if (!res.ok) {
      const data = await res.json();
      errEl.textContent = data.error?.message || 'Login failed';
      errEl.classList.remove('hidden');
      return;
    }
    document.getElementById('password').value = '';
    showDashboard();
    await loadAll();
  } catch {
    errEl.textContent = 'Network error';
    errEl.classList.remove('hidden');
  }
});

async function api(path, opts = {}) {
  const { allowUnauthorized, ...rest } = opts;
  const res = await fetch(`${API}${path}`, {
    credentials: 'same-origin',
    ...rest,
    headers: { 'Content-Type': 'application/json', ...rest.headers },
  });
  if (res.status === 401 && !allowUnauthorized) {
    showLogin();
  }
  return res;
}

async function loadStats() {
  const res = await api('/stats');
  if (!res.ok) return;
  const d = await res.json();
  document.getElementById('stat-namespaces').textContent = d.namespaceCount;
  document.getElementById('stat-deleted-namespaces').textContent = d.deletedNamespaceCount;
  document.getElementById('stat-tokens').textContent = d.tokenCount;
  document.getElementById('stat-disabled-tokens').textContent = d.disabledTokenCount;
  document.getElementById('stat-ready').textContent = d.dbWritable ? 'YES' : 'NO';
  document.getElementById('stat-version').textContent = 'v' + d.version;
  tokenRevealPersistent = !!d.tokenRevealPersistent;
  const strip = document.getElementById('status-strip');
  strip.innerHTML = [
    badge(d.encryptionEnabled ? 'At-rest encryption' : 'Plaintext storage', d.encryptionEnabled ? 'green' : 'red'),
    badge(d.jwtSecretPersistent ? 'Persistent JWT secret' : 'Ephemeral JWT secret', d.jwtSecretPersistent ? 'green' : 'red'),
    badge(d.adminCookieSecure ? 'Secure admin cookie' : 'Insecure admin cookie', d.adminCookieSecure ? 'green' : 'red'),
    badge(d.syncCorsOrigins.length ? `CORS: ${d.syncCorsOrigins.join(', ')}` : 'CORS disabled', d.syncCorsOrigins.length ? 'green' : 'muted'),
    badge(`Expired tokens: ${d.expiredTokenCount}`, d.expiredTokenCount ? 'red' : 'green'),
    badge(`DB size: ${formatBytes(d.dbSizeBytes)}`, 'muted'),
  ].join('');
}

async function loadTokens() {
  const res = await api('/tokens');
  if (!res.ok) return;
  const tokens = await res.json();
  const el = document.getElementById('tokens-table');
  if (!tokens.length) {
    el.innerHTML = '<div class="empty-state">No API tokens. Create one to get started.</div>';
    return;
  }
  el.innerHTML = `<table>
    <thead><tr><th>Name</th><th>Status</th><th>Namespace</th><th>Expires</th><th>Token</th><th>Last Used</th><th>Actions</th></tr></thead>
    <tbody>${tokens.map(t => `<tr>
      <td>${esc(t.name)}</td>
      <td>${renderTokenStatus(t)}</td>
      <td class="mono">${esc(t.namespacePattern)}</td>
      <td>${t.expiresAt ? new Date(t.expiresAt).toLocaleString() : '-'}</td>
      <td>${renderTokenCell(t)}</td>
      <td>${t.lastUsedAt ? new Date(t.lastUsedAt).toLocaleString() : '-'}</td>
      <td>
        ${t.canReveal ? `<button class="btn btn-sm" onclick="toggleTokenReveal('${t.id}')">${revealedTokens[t.id] ? 'Hide' : 'Show'}</button>` : `<span class="badge badge-red">Legacy</span>`}
        <button class="btn btn-sm" onclick="rotateToken('${t.id}')">Rotate</button>
        <button class="btn btn-sm" onclick="toggleTokenEnabled('${t.id}', ${!t.enabled})">${t.enabled ? 'Disable' : 'Enable'}</button>
        <button class="btn btn-sm" onclick="editTokenExpiry('${t.id}', ${t.expiresAt ? `'${escJs(t.expiresAt)}'` : 'null'})">Expiry</button>
        <button class="btn btn-danger btn-sm" onclick="deleteToken('${t.id}')">Delete</button>
      </td>
    </tr>`).join('')}</tbody>
  </table>`;
}

function renderTokenStatus(token) {
  if (!token.enabled) return badge('Disabled', 'red');
  if (token.expired) return badge('Expired', 'red');
  return badge('Active', 'green');
}

function renderTokenCell(token) {
  if (revealedTokens[token.id]) {
    return `<div class="token-inline"><span class="value">${esc(revealedTokens[token.id])}</span><button class="btn btn-sm" onclick="copyToken('${token.id}')">Copy</button></div>`;
  }
  if (token.canReveal) {
    return `<span class="badge badge-green">${tokenRevealPersistent ? 'Recoverable' : 'Recoverable until restart'}</span>`;
  }
  return '<span class="badge badge-red">Legacy token</span>';
}

function showCreateToken() {
  document.getElementById('create-token-form').classList.remove('hidden');
  document.getElementById('new-token-reveal').classList.add('hidden');
}

function hideCreateToken() {
  document.getElementById('create-token-form').classList.add('hidden');
}

async function createToken() {
  const name = document.getElementById('token-name').value.trim();
  const ns = document.getElementById('token-ns').value.trim() || '*';
  const expiry = document.getElementById('token-expiry').value;
  if (!name) return;
  const expiresAt = expiry ? new Date(expiry).toISOString() : undefined;
  const res = await api('/tokens', {
    method: 'POST',
    body: JSON.stringify({ name, namespacePattern: ns, expiresAt }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to create token');
    return;
  }
  document.getElementById('new-token-value').textContent = data.token;
  document.getElementById('new-token-reveal').classList.remove('hidden');
  hideCreateToken();
  document.getElementById('token-name').value = '';
  document.getElementById('token-ns').value = '';
  document.getElementById('token-expiry').value = '';
  await loadStats();
  await loadTokens();
}

async function toggleTokenReveal(id) {
  if (revealedTokens[id]) {
    delete revealedTokens[id];
    await loadTokens();
    return;
  }
  const res = await api(`/tokens/${id}/reveal`);
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to reveal token');
    return;
  }
  revealedTokens[id] = data.token;
  await loadTokens();
}

async function rotateToken(id) {
  if (!confirm('Rotate this token now? Existing clients will need the new token.')) return;
  const res = await api(`/tokens/${id}/rotate`, { method: 'POST' });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to rotate token');
    return;
  }
  revealedTokens[id] = data.token;
  document.getElementById('new-token-value').textContent = data.token;
  document.getElementById('new-token-reveal').classList.remove('hidden');
  await loadTokens();
}

async function toggleTokenEnabled(id, enabled) {
  const res = await api(`/tokens/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to update token');
    return;
  }
  await loadStats();
  await loadTokens();
}

async function editTokenExpiry(id, currentExpiresAt) {
  const input = prompt('Enter a new ISO timestamp (leave blank to clear expiry).', currentExpiresAt || '');
  if (input === null) return;
  const expiresAt = input.trim() ? input.trim() : null;
  const res = await api(`/tokens/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ expiresAt }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to update expiry');
    return;
  }
  await loadStats();
  await loadTokens();
}

async function copyToken(id) {
  const token = revealedTokens[id];
  if (!token) return;
  try {
    await navigator.clipboard.writeText(token);
  } catch {}
}

async function deleteToken(id) {
  if (!confirm('Delete this token? Clients using it will lose access.')) return;
  const res = await api(`/tokens/${id}`, { method: 'DELETE' });
  if (!res.ok) {
    const data = await res.json();
    alert(data.error?.message || 'Failed to delete token');
    return;
  }
  delete revealedTokens[id];
  await loadStats();
  await loadTokens();
}

async function loadNamespaces() {
  const res = await api('/namespaces');
  if (!res.ok) return;
  const nss = await res.json();
  const el = document.getElementById('namespaces-table');
  if (!nss.length) {
    el.innerHTML = '<div class="empty-state">No namespaces yet.</div>';
    return;
  }
  el.innerHTML = `<table>
    <thead><tr><th>Namespace</th><th>Status</th><th>Format</th><th>Objects</th><th>Last Sync</th><th>Actions</th></tr></thead>
    <tbody>${nss.map(n => `<tr>
      <td class="mono">${esc(n.namespace)}</td>
      <td>${n.deletedAt ? badge('Soft deleted', 'red') : badge('Active', 'green')}</td>
      <td><span class="badge ${n.format ? 'badge-green' : 'badge-muted'}">${n.format || 'legacy'}</span></td>
      <td>${n.objectCount}</td>
      <td>${n.uploadedAt ? new Date(n.uploadedAt).toLocaleString() : '-'}</td>
      <td>
        ${n.deletedAt
          ? `<button class="btn btn-sm" onclick="restoreNs('${escJs(n.namespace)}')">Restore</button><button class="btn btn-danger btn-sm" onclick="purgeNs('${escJs(n.namespace)}')">Purge</button>`
          : `<button class="btn btn-danger btn-sm" onclick="softDeleteNs('${escJs(n.namespace)}')">Soft Delete</button>`}
      </td>
    </tr>`).join('')}</tbody>
  </table>`;
}

async function softDeleteNs(ns) {
  if (!confirm(`Soft delete namespace "${ns}"? Sync requests will stop until you restore it.`)) return;
  const res = await api(`/namespaces/${encodeURIComponent(ns)}`, { method: 'DELETE' });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to soft delete namespace');
    return;
  }
  await loadStats();
  await loadNamespaces();
}

async function restoreNs(ns) {
  const res = await api(`/namespaces/${encodeURIComponent(ns)}/restore`, { method: 'POST' });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to restore namespace');
    return;
  }
  await loadStats();
  await loadNamespaces();
}

async function purgeNs(ns) {
  if (!confirm(`Permanently delete namespace "${ns}" and all retained data? This cannot be undone.`)) return;
  const res = await api(`/namespaces/${encodeURIComponent(ns)}?hard=true`, { method: 'DELETE' });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to purge namespace');
    return;
  }
  await loadStats();
  await loadNamespaces();
}

function showCreateNs() {
  document.getElementById('create-ns-form').classList.remove('hidden');
}

function hideCreateNs() {
  document.getElementById('create-ns-form').classList.add('hidden');
}

async function createNs() {
  const name = document.getElementById('ns-name').value.trim();
  if (!name) return;
  const res = await api('/namespaces', {
    method: 'POST',
    body: JSON.stringify({ namespace: name }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to create namespace');
    return;
  }
  hideCreateNs();
  document.getElementById('ns-name').value = '';
  await loadStats();
  await loadNamespaces();
}

function badge(text, color) {
  const cls = color === 'green' ? 'badge badge-green' : color === 'red' ? 'badge badge-red' : 'badge badge-muted';
  return `<span class="${cls}">${esc(text)}</span>`;
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s ?? '';
  return d.innerHTML.replace(/'/g, '&#39;').replace(/"/g, '&quot;');
}

function escJs(s) {
  return String(s ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
</script>
</body>
</html>"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_extraction_prefers_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("other=1; admin_session=abc123; theme=dark"),
        );
        assert_eq!(
            extract_cookie(&headers, ADMIN_COOKIE_NAME).as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn normalize_optional_timestamp_accepts_rfc3339() {
        let normalized =
            normalize_optional_timestamp(Some("2026-04-23T12:34:56Z".to_string())).unwrap();
        assert_eq!(normalized.as_deref(), Some("2026-04-23T12:34:56+00:00"));
    }
}
