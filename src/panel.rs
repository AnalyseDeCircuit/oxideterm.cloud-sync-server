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
const ADMIN_CSRF_COOKIE_NAME: &str = "admin_csrf";
const ADMIN_CSRF_HEADER_NAME: &str = "x-csrf-token";
const ADMIN_COOKIE_PATH: &str = "/admin";

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin", get(admin_page))
        .route("/admin/api/login", post(admin_login))
        .route("/admin/api/logout", post(admin_logout))
        .route("/admin/api/me", get(admin_current_user))
        .route("/admin/api/me/password", post(admin_change_own_password))
        .route(
            "/admin/api/users",
            get(admin_list_users).post(admin_create_user),
        )
        .route(
            "/admin/api/users/{username}",
            delete(admin_delete_user).patch(admin_update_user),
        )
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
        .route(
            "/admin/api/devices",
            get(admin_list_devices).post(admin_create_device),
        )
        .route(
            "/admin/api/devices/{id}",
            delete(admin_delete_device).patch(admin_update_device),
        )
        .route("/admin/api/conflicts", get(admin_list_conflicts))
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

fn build_csrf_cookie(token: &str, secure: bool) -> String {
    format!(
        "{ADMIN_CSRF_COOKIE_NAME}={token}; Max-Age=86400; Path={ADMIN_COOKIE_PATH}; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

fn clear_admin_session_cookie(secure: bool) -> String {
    format!(
        "{ADMIN_COOKIE_NAME}=; HttpOnly; Max-Age=0; Path={ADMIN_COOKIE_PATH}; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT{}",
        if secure { "; Secure" } else { "" }
    )
}

fn clear_csrf_cookie(secure: bool) -> String {
    format!(
        "{ADMIN_CSRF_COOKIE_NAME}=; Max-Age=0; Path={ADMIN_COOKIE_PATH}; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT{}",
        if secure { "; Secure" } else { "" }
    )
}

fn verify_admin(headers: &HeaderMap, state: &AppState) -> Result<(), AppError> {
    validate_admin_session(headers, state).map(|_| ())
}

fn validate_admin_session(headers: &HeaderMap, state: &AppState) -> Result<String, AppError> {
    if !state.admin_enabled {
        return Err(AppError::NotFound("Admin panel disabled".to_string()));
    }

    let token = extract_admin_token(headers)
        .ok_or_else(|| AppError::Unauthorized("Missing admin session".to_string()))?;

    let claims = auth::validate_admin_jwt(token.trim(), &state.jwt_secret)
        .map_err(|_| AppError::Unauthorized("Invalid or expired admin session".to_string()))?;

    let user = state
        .db
        .get_admin_user(&claims.sub)?
        .ok_or_else(|| AppError::Unauthorized("Admin user no longer exists".to_string()))?;
    if !user.enabled {
        return Err(AppError::Unauthorized("Admin user is disabled".to_string()));
    }

    Ok(user.username)
}

fn verify_csrf(headers: &HeaderMap) -> Result<(), AppError> {
    let cookie_token = extract_cookie(headers, ADMIN_CSRF_COOKIE_NAME)
        .ok_or_else(|| AppError::Forbidden("Missing CSRF cookie".to_string()))?;
    let header_token = headers
        .get(ADMIN_CSRF_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Forbidden("Missing CSRF token".to_string()))?;

    if cookie_token.is_empty() || cookie_token != header_token {
        return Err(AppError::Forbidden("Invalid CSRF token".to_string()));
    }
    Ok(())
}

fn verify_admin_mutation(headers: &HeaderMap, state: &AppState) -> Result<(), AppError> {
    verify_admin(headers, state)?;
    verify_csrf(headers)
}

fn request_uses_https(headers: &HeaderMap, state: &AppState) -> bool {
    state.trust_proxy_headers
        && headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(',').next().unwrap_or("").trim() == "https")
}

fn effective_admin_cookie_secure(headers: &HeaderMap, state: &AppState) -> bool {
    state.admin_cookie_secure && request_uses_https(headers, state)
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

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn validate_admin_username(username: &str) -> Result<(), AppError> {
    if username.is_empty() || username.len() > 64 {
        return Err(AppError::BadRequest(
            "Username must be 1-64 characters".to_string(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(AppError::BadRequest(
            "Username may only contain ASCII letters, numbers, dash, underscore, and dot"
                .to_string(),
        ));
    }
    Ok(())
}

fn timestamp_max(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => {
            let left_dt = chrono::DateTime::parse_from_rfc3339(&left)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc));
            let right_dt = chrono::DateTime::parse_from_rfc3339(&right)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc));
            if right_dt
                .zip(left_dt)
                .is_some_and(|(right, left)| right > left)
            {
                Some(right)
            } else {
                Some(left)
            }
        }
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
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
        "deviceId": token.device_id,
        "readCount": token.read_count,
        "writeCount": token.write_count,
        "failedCount": token.failed_count,
        "lastNamespace": token.last_namespace,
        "lastPermission": token.last_permission,
        "lastClientIp": token.last_client_ip,
        "lastClientVersion": token.last_client_version,
        "expired": token_expired(token),
    })
}

fn serialize_device(device: &DeviceRecord) -> serde_json::Value {
    json!({
        "id": device.id,
        "name": device.name,
        "namespacePattern": device.namespace_pattern,
        "tokenId": device.token_id,
        "enabled": device.enabled,
        "createdAt": device.created_at,
        "updatedAt": device.updated_at,
        "lastSeenAt": device.last_seen_at,
        "lastClientIp": device.last_client_ip,
        "lastClientVersion": device.last_client_version,
        "notes": device.notes,
    })
}

fn serialize_admin_user(user: &AdminUserRecord) -> serde_json::Value {
    json!({
        "username": user.username,
        "role": user.role,
        "enabled": user.enabled,
        "createdAt": user.created_at,
        "updatedAt": user.updated_at,
        "lastLoginAt": user.last_login_at,
        "lastLoginIp": user.last_login_ip,
        "failedLoginCount": user.failed_login_count,
        "lastFailedLoginAt": user.last_failed_login_at,
        "passwordUpdatedAt": user.password_updated_at,
        "disabledAt": user.disabled_at,
    })
}

fn enabled_admin_user_count(state: &AppState) -> Result<usize, AppError> {
    Ok(state
        .db
        .list_admin_users()?
        .iter()
        .filter(|user| user.enabled)
        .count())
}

fn set_token_device_link(
    state: &AppState,
    old_token_id: Option<&str>,
    new_token_id: Option<&str>,
    device_id: &str,
) -> Result<(), AppError> {
    if old_token_id == new_token_id {
        return Ok(());
    }

    if let Some(old_token_id) = old_token_id {
        if let Some(mut token) = state.db.get_token(old_token_id)? {
            if token.device_id.as_deref() == Some(device_id) {
                token.device_id = None;
                state.db.set_token(&token)?;
            }
        }
    }

    if let Some(new_token_id) = new_token_id {
        let mut token = state
            .db
            .get_token(new_token_id)?
            .ok_or_else(|| AppError::BadRequest(format!("Token '{}' not found", new_token_id)))?;
        token.device_id = Some(device_id.to_string());
        state.db.set_token(&token)?;
    }

    Ok(())
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

fn record_user_login_failure(state: &AppState, user: &mut AdminUserRecord) -> Result<(), AppError> {
    user.failed_login_count = user.failed_login_count.saturating_add(1);
    user.last_failed_login_at = Some(chrono::Utc::now().to_rfc3339());
    user.updated_at = chrono::Utc::now().to_rfc3339();
    state.db.set_admin_user(user)?;
    Ok(())
}

// ── Admin Page (Embedded SPA) ──

async fn admin_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if !state.admin_enabled {
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
    username: Option<String>,
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

    if !state.admin_enabled {
        return Err(AppError::NotFound("Admin panel disabled".to_string()));
    }

    let username = body
        .username
        .as_deref()
        .map(str::trim)
        .filter(|username| !username.is_empty())
        .unwrap_or("admin")
        .to_string();
    let Some(mut user) = state.db.get_admin_user(&username)? else {
        let _ = record_login_failure(&state, client_ip)?;
        tracing::warn!(
            target: "audit",
            event = "admin_login_failed_user",
            client_ip = %client_ip,
            username = %username,
            "Admin login failed for unknown user"
        );
        return Err(AppError::Unauthorized(
            "Invalid username or password".to_string(),
        ));
    };

    if !user.enabled || !auth::verify_admin_password(&body.password, &user.password_hash) {
        record_user_login_failure(&state, &mut user)?;
        let _ = record_login_failure(&state, client_ip)?;
        tracing::warn!(
            target: "audit",
            event = "admin_login_failed_user",
            client_ip = %client_ip,
            username = %username,
            "Admin login failed for user"
        );
        return Err(AppError::Unauthorized(
            "Invalid username or password".to_string(),
        ));
    }

    clear_login_failures(&state, client_ip)?;

    user.last_login_at = Some(chrono::Utc::now().to_rfc3339());
    user.last_login_ip = Some(client_ip.to_string());
    user.failed_login_count = 0;
    user.last_failed_login_at = None;
    user.updated_at = chrono::Utc::now().to_rfc3339();
    state.db.set_admin_user(&user)?;

    let jwt = auth::create_admin_jwt_for_user(&state.jwt_secret, &username)
        .map_err(|e| AppError::Internal(format!("JWT creation failed: {e}")))?;
    let csrf = uuid::Uuid::new_v4().to_string();
    let secure_cookie = effective_admin_cookie_secure(&headers, &state);
    let cookie = build_admin_session_cookie(&jwt, secure_cookie);
    let csrf_cookie = build_csrf_cookie(&csrf, secure_cookie);

    tracing::info!(
        target: "audit",
        event = "admin_login_succeeded",
        client_ip = %client_ip,
        username = %username,
        "Admin login succeeded"
    );

    let mut response_headers = HeaderMap::new();
    response_headers.append(
        "set-cookie",
        HeaderValue::from_str(&cookie)
            .map_err(|e| AppError::Internal(format!("Invalid session cookie: {e}")))?,
    );
    response_headers.append(
        "set-cookie",
        HeaderValue::from_str(&csrf_cookie)
            .map_err(|e| AppError::Internal(format!("Invalid CSRF cookie: {e}")))?,
    );
    Ok((
        response_headers,
        Json(json!({ "ok": true, "csrfToken": csrf })),
    ))
}

async fn admin_logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin_mutation(&headers, &state)?;
    let mut response_headers = HeaderMap::new();
    let secure_cookie = effective_admin_cookie_secure(&headers, &state);
    let cookie = clear_admin_session_cookie(secure_cookie);
    let csrf_cookie = clear_csrf_cookie(secure_cookie);
    response_headers.append(
        "set-cookie",
        HeaderValue::from_str(&cookie)
            .map_err(|e| AppError::Internal(format!("Invalid clear cookie: {e}")))?,
    );
    response_headers.append(
        "set-cookie",
        HeaderValue::from_str(&csrf_cookie)
            .map_err(|e| AppError::Internal(format!("Invalid clear CSRF cookie: {e}")))?,
    );
    Ok((response_headers, Json(json!({ "ok": true }))))
}

// ── Current Admin User ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeOwnPasswordRequest {
    current_password: String,
    new_password: String,
}

async fn admin_current_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let username = validate_admin_session(&headers, &state)?;
    let user = state
        .db
        .get_admin_user(&username)?
        .ok_or_else(|| AppError::Unauthorized("Admin user no longer exists".to_string()))?;
    Ok(Json(serialize_admin_user(&user)))
}

async fn admin_change_own_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<ChangeOwnPasswordRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
    let username = validate_admin_session(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);
    if body.new_password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    let mut user = state
        .db
        .get_admin_user(&username)?
        .ok_or_else(|| AppError::Unauthorized("Admin user no longer exists".to_string()))?;
    if !auth::verify_admin_password(&body.current_password, &user.password_hash) {
        record_user_login_failure(&state, &mut user)?;
        return Err(AppError::Unauthorized(
            "Current password is incorrect".to_string(),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    user.password_hash = auth::hash_admin_password(&body.new_password)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))?;
    user.password_updated_at = Some(now.clone());
    user.updated_at = now;
    state.db.set_admin_user(&user)?;

    tracing::info!(
        target: "audit",
        event = "admin_user_self_password_changed",
        client_ip = %client_ip,
        username = %username,
        "Admin user changed own password"
    );

    Ok(Json(serialize_admin_user(&user)))
}

// ── Admin Users ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateUserRequest {
    username: String,
    password: String,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateUserRequest {
    password: Option<String>,
    enabled: Option<bool>,
}

async fn admin_list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let mut users = state.db.list_admin_users()?;
    users.sort_by(|a, b| a.username.cmp(&b.username));
    Ok(Json(
        users
            .iter()
            .map(serialize_admin_user)
            .collect::<Vec<serde_json::Value>>(),
    ))
}

async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
    let actor = validate_admin_session(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);
    let username = body.username.trim().to_string();
    validate_admin_username(&username)?;
    if body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters".to_string(),
        ));
    }
    if state.db.get_admin_user(&username)?.is_some() {
        return Err(AppError::BadRequest(format!(
            "Admin user '{}' already exists",
            username
        )));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let user = AdminUserRecord {
        username: username.clone(),
        password_hash: auth::hash_admin_password(&body.password)
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))?,
        role: "admin".to_string(),
        enabled: body.enabled.unwrap_or(true),
        created_at: now.clone(),
        updated_at: now,
        last_login_at: None,
        last_login_ip: None,
        failed_login_count: 0,
        last_failed_login_at: None,
        password_updated_at: Some(chrono::Utc::now().to_rfc3339()),
        disabled_at: None,
    };
    state.db.set_admin_user(&user)?;

    tracing::info!(
        target: "audit",
        event = "admin_user_created",
        client_ip = %client_ip,
        actor = %actor,
        username = %username,
        enabled = user.enabled,
        "Admin user created"
    );

    Ok(Json(serialize_admin_user(&user)))
}

async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(username): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
    let actor = validate_admin_session(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);
    validate_admin_username(&username)?;

    let mut user = state
        .db
        .get_admin_user(&username)?
        .ok_or_else(|| AppError::NotFound(format!("Admin user '{}' not found", username)))?;

    let password_changed = body.password.is_some();
    if let Some(password) = body.password {
        if password.len() < 8 {
            return Err(AppError::BadRequest(
                "Password must be at least 8 characters".to_string(),
            ));
        }
        user.password_hash = auth::hash_admin_password(&password)
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))?;
        user.password_updated_at = Some(chrono::Utc::now().to_rfc3339());
    }

    if let Some(enabled) = body.enabled {
        if !enabled && user.enabled && enabled_admin_user_count(&state)? <= 1 {
            return Err(AppError::BadRequest(
                "Cannot disable the last enabled admin user".to_string(),
            ));
        }
        user.enabled = enabled;
        user.disabled_at = if enabled {
            None
        } else {
            Some(chrono::Utc::now().to_rfc3339())
        };
    }
    user.updated_at = chrono::Utc::now().to_rfc3339();
    state.db.set_admin_user(&user)?;

    tracing::info!(
        target: "audit",
        event = "admin_user_updated",
        client_ip = %client_ip,
        actor = %actor,
        username = %username,
        enabled = user.enabled,
        password_changed,
        "Admin user updated"
    );

    Ok(Json(serialize_admin_user(&user)))
}

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(username): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin_mutation(&headers, &state)?;
    let actor = validate_admin_session(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);
    validate_admin_username(&username)?;

    let user = state
        .db
        .get_admin_user(&username)?
        .ok_or_else(|| AppError::NotFound(format!("Admin user '{}' not found", username)))?;
    if user.enabled && enabled_admin_user_count(&state)? <= 1 {
        return Err(AppError::BadRequest(
            "Cannot delete the last enabled admin user".to_string(),
        ));
    }
    state.db.delete_admin_user(&username)?;

    tracing::info!(
        target: "audit",
        event = "admin_user_deleted",
        client_ip = %client_ip,
        actor = %actor,
        username = %username,
        "Admin user deleted"
    );

    Ok(Json(json!({ "ok": true })))
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
        let (object_count, object_bytes, object_last_write_at) =
            state.db.namespace_object_stats(&ns)?;
        let blob_size = state.db.blob_size(&ns)?;
        let total_bytes = blob_size.saturating_add(object_bytes);
        let usage = state.db.get_namespace_usage(&ns)?;

        infos.push(NamespaceInfo {
            namespace: ns,
            revision: meta.as_ref().and_then(|m| m.revision.clone()),
            uploaded_at: meta.as_ref().and_then(|m| m.uploaded_at.clone()),
            device_id: meta.as_ref().and_then(|m| m.device_id.clone()),
            blob_size,
            object_count,
            object_bytes,
            total_bytes,
            growth_bytes: usage.as_ref().map(|usage| usage.growth_bytes).unwrap_or(0),
            last_write_at: timestamp_max(
                meta.as_ref().and_then(|m| m.uploaded_at.clone()),
                object_last_write_at,
            ),
            storage_observed_at: usage.map(|usage| usage.observed_at),
            deleted_bytes: 0,
            format: meta.as_ref().and_then(|m| m.format.clone()),
            deleted_at: None,
        });
    }

    for (ns, deleted) in state.db.list_deleted_namespaces()? {
        let meta = state
            .db
            .get_metadata(&ns)?
            .and_then(|d| serde_json::from_slice::<SyncMetadata>(&d).ok());
        let (object_count, object_bytes, object_last_write_at) =
            state.db.namespace_object_stats(&ns)?;
        let blob_size = state.db.blob_size(&ns)?;
        let total_bytes = blob_size.saturating_add(object_bytes);
        let usage = state.db.get_namespace_usage(&ns)?;

        infos.push(NamespaceInfo {
            namespace: ns,
            revision: meta.as_ref().and_then(|m| m.revision.clone()),
            uploaded_at: meta.as_ref().and_then(|m| m.uploaded_at.clone()),
            device_id: meta.as_ref().and_then(|m| m.device_id.clone()),
            blob_size,
            object_count,
            object_bytes,
            total_bytes,
            growth_bytes: usage.as_ref().map(|usage| usage.growth_bytes).unwrap_or(0),
            last_write_at: timestamp_max(
                meta.as_ref().and_then(|m| m.uploaded_at.clone()),
                object_last_write_at,
            ),
            storage_observed_at: usage.map(|usage| usage.observed_at),
            deleted_bytes: total_bytes,
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
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
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
    verify_admin_mutation(&headers, &state)?;
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
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;

    state
        .db
        .soft_delete_namespace(&namespace, &chrono::Utc::now().to_rfc3339())?;
    state
        .db
        .refresh_namespace_usage(&namespace, &chrono::Utc::now().to_rfc3339(), true)?;

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
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    if !state.db.is_namespace_deleted(&namespace)? {
        return Err(AppError::NotFound(format!(
            "Namespace '{}' is not soft-deleted",
            namespace
        )));
    }
    state.db.restore_namespace(&namespace)?;
    state
        .db
        .refresh_namespace_usage(&namespace, &chrono::Utc::now().to_rfc3339(), false)?;

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
    device_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTokenRequest {
    enabled: Option<bool>,
    expires_at: Option<Option<String>>,
    device_id: Option<Option<String>>,
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
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
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
    let device_id = normalize_optional_text(body.device_id);
    if let Some(device_id) = device_id.as_deref() {
        state
            .db
            .get_device(device_id)?
            .ok_or_else(|| AppError::BadRequest(format!("Device '{}' not found", device_id)))?;
    }

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
        device_id: device_id.clone(),
        read_count: 0,
        write_count: 0,
        failed_count: 0,
        last_namespace: None,
        last_permission: None,
        last_client_ip: None,
        last_client_version: None,
    };

    state.db.set_token(&token)?;
    if let Some(device_id) = device_id.as_deref() {
        if let Some(mut device) = state.db.get_device(device_id)? {
            device.token_id = Some(id.clone());
            device.updated_at = chrono::Utc::now().to_rfc3339();
            state.db.set_device(&device)?;
        }
    }

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
        "deviceId": token.device_id,
    })))
}

async fn admin_update_token(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<UpdateTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
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
    if let Some(device_id) = body.device_id {
        let old_device_id = token.device_id.clone();
        let next_device_id = normalize_optional_text(device_id);
        if let Some(next_device_id) = next_device_id.as_deref() {
            state.db.get_device(next_device_id)?.ok_or_else(|| {
                AppError::BadRequest(format!("Device '{}' not found", next_device_id))
            })?;
        }
        token.device_id = next_device_id.clone();
        if old_device_id != next_device_id {
            if let Some(old_device_id) = old_device_id.as_deref() {
                if let Some(mut device) = state.db.get_device(old_device_id)? {
                    if device.token_id.as_deref() == Some(token.id.as_str()) {
                        device.token_id = None;
                        device.updated_at = chrono::Utc::now().to_rfc3339();
                        state.db.set_device(&device)?;
                    }
                }
            }
            if let Some(next_device_id) = next_device_id.as_deref() {
                if let Some(mut device) = state.db.get_device(next_device_id)? {
                    device.token_id = Some(token.id.clone());
                    device.updated_at = chrono::Utc::now().to_rfc3339();
                    state.db.set_device(&device)?;
                }
            }
        }
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
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
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
    verify_admin_mutation(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    for mut device in state.db.list_devices()? {
        if device.token_id.as_deref() == Some(id.as_str()) {
            device.token_id = None;
            device.updated_at = chrono::Utc::now().to_rfc3339();
            state.db.set_device(&device)?;
        }
    }
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

// ── Devices ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateDeviceRequest {
    name: String,
    namespace_pattern: Option<String>,
    token_id: Option<String>,
    enabled: Option<bool>,
    last_client_version: Option<String>,
    notes: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateDeviceRequest {
    name: Option<String>,
    namespace_pattern: Option<Option<String>>,
    token_id: Option<Option<String>>,
    enabled: Option<bool>,
    notes: Option<Option<String>>,
}

async fn admin_list_devices(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let mut devices = state.db.list_devices()?;
    devices.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    Ok(Json(
        devices
            .iter()
            .map(serialize_device)
            .collect::<Vec<serde_json::Value>>(),
    ))
}

async fn admin_create_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<CreateDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::BadRequest(
            "Device name must not be empty".to_string(),
        ));
    }

    let namespace_pattern = normalize_optional_text(body.namespace_pattern);
    if let Some(namespace_pattern) = namespace_pattern.as_deref() {
        if !auth::validate_namespace_pattern(namespace_pattern) {
            return Err(AppError::BadRequest(
                "Namespace pattern must be '*' , an exact namespace, or a prefix ending with '*'"
                    .to_string(),
            ));
        }
    }

    let token_id = normalize_optional_text(body.token_id);
    if let Some(token_id) = token_id.as_deref() {
        state
            .db
            .get_token(token_id)?
            .ok_or_else(|| AppError::BadRequest(format!("Token '{}' not found", token_id)))?;
    }

    let now = chrono::Utc::now().to_rfc3339();
    let device = DeviceRecord {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        namespace_pattern,
        token_id: token_id.clone(),
        enabled: body.enabled.unwrap_or(true),
        created_at: now.clone(),
        updated_at: now,
        last_seen_at: None,
        last_client_ip: None,
        last_client_version: normalize_optional_text(body.last_client_version),
        notes: normalize_optional_text(body.notes),
    };
    state.db.set_device(&device)?;
    set_token_device_link(&state, None, token_id.as_deref(), &device.id)?;

    tracing::info!(
        target: "audit",
        event = "device_created",
        client_ip = %client_ip,
        device_id = %device.id,
        token_id = device.token_id.as_deref().unwrap_or(""),
        "Device created"
    );

    Ok(Json(serialize_device(&device)))
}

async fn admin_update_device(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<UpdateDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin_mutation(&headers, &state)?;
    crate::api::ensure_disk_capacity(&state, 256 * 1024)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);

    let mut device = state
        .db
        .get_device(&id)?
        .ok_or_else(|| AppError::NotFound(format!("Device '{}' not found", id)))?;
    let old_token_id = device.token_id.clone();

    if let Some(name) = body.name {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest(
                "Device name must not be empty".to_string(),
            ));
        }
        device.name = name;
    }
    if let Some(namespace_pattern) = body.namespace_pattern {
        let namespace_pattern = normalize_optional_text(namespace_pattern);
        if let Some(namespace_pattern) = namespace_pattern.as_deref() {
            if !auth::validate_namespace_pattern(namespace_pattern) {
                return Err(AppError::BadRequest(
                    "Namespace pattern must be '*' , an exact namespace, or a prefix ending with '*'"
                        .to_string(),
                ));
            }
        }
        device.namespace_pattern = namespace_pattern;
    }
    if let Some(token_id) = body.token_id {
        let token_id = normalize_optional_text(token_id);
        if let Some(token_id) = token_id.as_deref() {
            state
                .db
                .get_token(token_id)?
                .ok_or_else(|| AppError::BadRequest(format!("Token '{}' not found", token_id)))?;
        }
        device.token_id = token_id;
    }
    if let Some(enabled) = body.enabled {
        device.enabled = enabled;
    }
    if let Some(notes) = body.notes {
        device.notes = normalize_optional_text(notes);
    }
    device.updated_at = chrono::Utc::now().to_rfc3339();

    state.db.set_device(&device)?;
    set_token_device_link(
        &state,
        old_token_id.as_deref(),
        device.token_id.as_deref(),
        &device.id,
    )?;

    tracing::info!(
        target: "audit",
        event = "device_updated",
        client_ip = %client_ip,
        device_id = %device.id,
        token_id = device.token_id.as_deref().unwrap_or(""),
        enabled = device.enabled,
        "Device updated"
    );

    Ok(Json(serialize_device(&device)))
}

async fn admin_delete_device(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin_mutation(&headers, &state)?;
    let client_ip = resolve_client_ip(&headers, addr.ip(), &state);
    let device = state
        .db
        .get_device(&id)?
        .ok_or_else(|| AppError::NotFound(format!("Device '{}' not found", id)))?;

    set_token_device_link(&state, device.token_id.as_deref(), None, &device.id)?;
    state.db.delete_device(&id)?;

    tracing::info!(
        target: "audit",
        event = "device_deleted",
        client_ip = %client_ip,
        device_id = %id,
        "Device deleted"
    );

    Ok(Json(json!({ "ok": true })))
}

// ── Sync Conflicts ──

async fn admin_list_conflicts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    Ok(Json(state.db.list_sync_conflicts(50)?))
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
    let devices = state.db.list_devices()?;
    let conflicts = state.db.list_sync_conflicts(50)?;
    let admin_users = state.db.list_admin_users()?;
    let encrypted = state.encryption_key.is_some();
    let db_writable = state.db.check_writable().is_ok();
    let db_size_bytes = std::fs::metadata(&state.db_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let disk_free_bytes = crate::api::disk_free_bytes(&state.db_path);
    let disk_above_minimum = disk_free_bytes
        .map(|free| free >= state.min_free_disk_bytes)
        .unwrap_or(true);

    let disabled_tokens = tokens.iter().filter(|token| !token.enabled).count();
    let expired_tokens = tokens.iter().filter(|token| token_expired(token)).count();
    let disabled_devices = devices.iter().filter(|device| !device.enabled).count();
    let mut namespace_storage_bytes = 0u64;
    for namespace in namespaces.iter().map(String::as_str).chain(
        deleted_namespaces
            .iter()
            .map(|(namespace, _)| namespace.as_str()),
    ) {
        let blob_size = state.db.blob_size(namespace)?;
        let (_, object_bytes, _) = state.db.namespace_object_stats(namespace)?;
        namespace_storage_bytes =
            namespace_storage_bytes.saturating_add(blob_size.saturating_add(object_bytes));
    }

    Ok(Json(json!({
        "namespaceCount": namespaces.len(),
        "deletedNamespaceCount": deleted_namespaces.len(),
        "tokenCount": tokens.len(),
        "disabledTokenCount": disabled_tokens,
        "expiredTokenCount": expired_tokens,
        "deviceCount": devices.len(),
        "disabledDeviceCount": disabled_devices,
        "adminUserCount": admin_users.len(),
        "recentConflictCount": conflicts.len(),
        "namespaceStorageBytes": namespace_storage_bytes,
        "encryptionEnabled": encrypted,
        "tokenRevealPersistent": state.token_reveal_persistent,
        "jwtSecretPersistent": state.admin_jwt_secret_persistent,
        "adminCookieSecure": state.admin_cookie_secure,
        "dbWritable": db_writable,
        "dbSizeBytes": db_size_bytes,
        "diskFreeBytes": disk_free_bytes,
        "minFreeDiskBytes": state.min_free_disk_bytes,
        "diskAboveMinimum": disk_above_minimum,
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
  .stat-link {
    cursor: pointer;
    transition: transform 0.15s, box-shadow 0.15s;
  }
  .stat-link:hover,
  .stat-link:focus {
    transform: translateY(-1px);
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.08);
    outline: 2px solid var(--ot-accent);
    outline-offset: 2px;
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
  input[type="text"], input[type="password"], input[type="datetime-local"], select {
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
  .admin-nav {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-bottom: 1.5rem;
  }
  .admin-nav a {
    color: var(--ot-text-secondary);
    text-decoration: none;
    border: 1px solid var(--ot-border);
    border-radius: 9999px;
    padding: 0.4rem 0.8rem;
    font-size: 0.8125rem;
    background: var(--ot-bg-surface);
  }
  .admin-nav a:hover,
  .admin-nav a.active {
    color: #fff;
    background: var(--ot-accent);
    border-color: var(--ot-accent);
  }
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
        <label for="username">Username</label>
        <input type="text" id="username" placeholder="admin" autocomplete="username" value="admin" required>
      </div>
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
    <div>
      <button class="btn btn-sm" onclick="changeOwnPassword()">Change Password</button>
      <button class="btn btn-sm" onclick="logout()">Sign Out</button>
    </div>
  </div>

  <nav class="admin-nav" aria-label="Admin sections">
    <a href="#overview" data-nav-page="overview">Overview</a>
    <a href="#users" data-nav-page="users">Users</a>
    <a href="#tokens" data-nav-page="tokens">Tokens</a>
    <a href="#conflicts" data-nav-page="conflicts">Conflicts</a>
    <a href="#devices" data-nav-page="devices">Devices</a>
    <a href="#namespaces" data-nav-page="namespaces">Namespaces</a>
  </nav>

  <div class="card" data-page="overview">
    <h2>Overview</h2>
    <div class="stats-grid">
      <div class="stat-item stat-link" onclick="showPage('namespaces')" role="button" tabindex="0">
        <div class="stat-value" id="stat-namespaces">-</div>
        <div class="stat-label">Namespaces</div>
      </div>
      <div class="stat-item stat-link" onclick="showPage('namespaces')" role="button" tabindex="0">
        <div class="stat-value" id="stat-deleted-namespaces">-</div>
        <div class="stat-label">Soft Deleted</div>
      </div>
      <div class="stat-item stat-link" onclick="showPage('tokens')" role="button" tabindex="0">
        <div class="stat-value" id="stat-tokens">-</div>
        <div class="stat-label">API Tokens</div>
      </div>
      <div class="stat-item stat-link" onclick="showPage('users')" role="button" tabindex="0">
        <div class="stat-value" id="stat-users">-</div>
        <div class="stat-label">Admin Users</div>
      </div>
      <div class="stat-item">
        <div class="stat-value" id="stat-disabled-tokens">-</div>
        <div class="stat-label">Disabled Tokens</div>
      </div>
      <div class="stat-item stat-link" onclick="showPage('devices')" role="button" tabindex="0">
        <div class="stat-value" id="stat-devices">-</div>
        <div class="stat-label">Devices</div>
      </div>
      <div class="stat-item stat-link" onclick="showPage('namespaces')" role="button" tabindex="0">
        <div class="stat-value" id="stat-storage">-</div>
        <div class="stat-label">Stored Data</div>
      </div>
      <div class="stat-item stat-link" onclick="showPage('conflicts')" role="button" tabindex="0">
        <div class="stat-value" id="stat-conflicts">-</div>
        <div class="stat-label">Recent Conflicts</div>
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

  <div class="card" data-page="users">
    <div class="flex-between mb-1">
      <h2>Admin Users</h2>
      <button class="btn btn-primary btn-sm" onclick="showCreateUser()">Create User</button>
    </div>
    <div id="create-user-form" class="hidden" style="margin-bottom:1rem">
      <div class="form-row">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="user-name" placeholder="e.g. ops-admin">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="user-password" placeholder="At least 8 characters" autocomplete="new-password">
        </div>
      </div>
      <button class="btn btn-primary btn-sm" onclick="createUser()">Create</button>
      <button class="btn btn-sm" onclick="hideCreateUser()">Cancel</button>
    </div>
    <div id="users-table"></div>
  </div>

  <div class="card" data-page="tokens">
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
        <div class="form-group">
          <label>Device (optional)</label>
          <select id="token-device"></select>
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

  <div class="card" data-page="conflicts">
    <div class="flex-between mb-1">
      <h2>Sync Conflicts</h2>
      <button class="btn btn-sm" onclick="loadConflicts()">Refresh</button>
    </div>
    <p class="subtitle">Recent ETag conflicts. Payload contents and plaintext tokens are never recorded.</p>
    <div id="conflicts-table"></div>
  </div>

  <div class="card" data-page="devices">
    <div class="flex-between mb-1">
      <h2>Devices</h2>
      <button class="btn btn-primary btn-sm" onclick="showCreateDevice()">Register Device</button>
    </div>
    <div id="create-device-form" class="hidden" style="margin-bottom:1rem">
      <div class="form-row">
        <div class="form-group">
          <label>Name</label>
          <input type="text" id="device-name" placeholder="e.g. Work Laptop">
        </div>
        <div class="form-group">
          <label>Namespace Pattern (optional)</label>
          <input type="text" id="device-ns" placeholder="* or my-namespace">
        </div>
        <div class="form-group">
          <label>Linked Token (optional)</label>
          <select id="device-token"></select>
        </div>
      </div>
      <div class="form-group">
        <label>Notes (optional)</label>
        <input type="text" id="device-notes" placeholder="Owner, location, or recovery notes">
      </div>
      <button class="btn btn-primary btn-sm" onclick="createDevice()">Create</button>
      <button class="btn btn-sm" onclick="hideCreateDevice()">Cancel</button>
    </div>
    <div id="devices-table"></div>
  </div>

  <div class="card" data-page="namespaces">
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
let csrfToken = getCookie('admin_csrf');
const revealedTokens = {};
let userCache = [];
let tokenCache = [];
let deviceCache = [];
const validPages = new Set(['overview', 'users', 'tokens', 'conflicts', 'devices', 'namespaces']);

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
  showPage(pageFromHash(), { updateHash: false });
}

function pageFromHash() {
  const page = window.location.hash.replace(/^#/, '') || 'overview';
  return validPages.has(page) ? page : 'overview';
}

function showPage(page, opts = {}) {
  const targetPage = validPages.has(page) ? page : 'overview';
  document.querySelectorAll('[data-page]').forEach((section) => {
    section.classList.toggle('hidden', section.dataset.page !== targetPage);
  });
  document.querySelectorAll('[data-nav-page]').forEach((link) => {
    link.classList.toggle('active', link.dataset.navPage === targetPage);
  });
  if (opts.updateHash !== false && window.location.hash !== `#${targetPage}`) {
    window.location.hash = targetPage;
  }
}

window.addEventListener('hashchange', () => {
  if (!document.getElementById('dashboard').classList.contains('hidden')) {
    showPage(pageFromHash(), { updateHash: false });
  }
});

document.querySelectorAll('.stat-link').forEach((item) => {
  item.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      item.click();
    }
  });
});

async function loadAll() {
  await loadStats();
  await loadUsers();
  await loadTokens();
  await loadConflicts();
  await loadDevices();
  await loadNamespaces();
}

async function logout() {
  try {
    await api('/logout', { method: 'POST', allowUnauthorized: true });
  } catch {}
  csrfToken = null;
  Object.keys(revealedTokens).forEach((key) => delete revealedTokens[key]);
  userCache = [];
  tokenCache = [];
  deviceCache = [];
  showLogin();
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('username').value.trim() || 'admin';
  const pw = document.getElementById('password').value;
  const errEl = document.getElementById('login-error');
  errEl.classList.add('hidden');
  try {
    const res = await fetch(`${API}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ username, password: pw }),
    });
    if (!res.ok) {
      const data = await res.json();
      errEl.textContent = data.error?.message || 'Login failed';
      errEl.classList.remove('hidden');
      return;
    }
    const data = await res.json();
    csrfToken = data.csrfToken || getCookie('admin_csrf');
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
  const method = (rest.method || 'GET').toUpperCase();
  const headers = { 'Content-Type': 'application/json', ...rest.headers };
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    csrfToken = csrfToken || getCookie('admin_csrf');
    if (csrfToken) headers['x-csrf-token'] = csrfToken;
  }
  const res = await fetch(`${API}${path}`, {
    credentials: 'same-origin',
    ...rest,
    headers,
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
  document.getElementById('stat-users').textContent = d.adminUserCount;
  document.getElementById('stat-disabled-tokens').textContent = d.disabledTokenCount;
  document.getElementById('stat-devices').textContent = d.deviceCount;
  document.getElementById('stat-storage').textContent = formatBytes(d.namespaceStorageBytes);
  document.getElementById('stat-conflicts').textContent = d.recentConflictCount;
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
    badge(`Disk free: ${formatBytes(d.diskFreeBytes)}`, d.diskAboveMinimum ? 'green' : 'red'),
    badge(`Disk reserve: ${formatBytes(d.minFreeDiskBytes)}`, 'muted'),
  ].join('');
}

async function loadTokens() {
  const res = await api('/tokens');
  if (!res.ok) return;
  const tokens = await res.json();
  tokenCache = tokens;
  renderDeviceSelectors();
  const el = document.getElementById('tokens-table');
  if (!tokens.length) {
    el.innerHTML = '<div class="empty-state">No API tokens. Create one to get started.</div>';
    return;
  }
  el.innerHTML = `<table>
    <thead><tr><th>Name</th><th>Status</th><th>Namespace</th><th>Usage</th><th>Device</th><th>Expires</th><th>Token</th><th>Last Used</th><th>Actions</th></tr></thead>
    <tbody>${tokens.map(t => `<tr>
      <td>${esc(t.name)}</td>
      <td>${renderTokenStatus(t)}</td>
      <td class="mono">${esc(t.namespacePattern)}</td>
      <td>${renderTokenUsage(t)}</td>
      <td>${t.deviceId ? esc(deviceName(t.deviceId)) : '-'}</td>
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

function renderTokenUsage(token) {
  return [
    badge(`R ${token.readCount || 0}`, 'muted'),
    badge(`W ${token.writeCount || 0}`, 'muted'),
    badge(`Fail ${token.failedCount || 0}`, token.failedCount ? 'red' : 'green'),
    token.lastNamespace ? `<div class="mono">${esc(token.lastNamespace)}</div>` : '',
    token.lastClientIp ? `<div class="mono">${esc(token.lastClientIp)}</div>` : '',
    token.lastClientVersion ? `<div>${esc(token.lastClientVersion)}</div>` : '',
  ].join(' ');
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

async function loadUsers() {
  const res = await api('/users');
  if (!res.ok) return;
  const users = await res.json();
  userCache = users;
  const el = document.getElementById('users-table');
  if (!users.length) {
    el.innerHTML = '<div class="empty-state">No admin users. Bootstrap one with ADMIN_PASSWORD.</div>';
    return;
  }
  el.innerHTML = `<table>
    <thead><tr><th>Username</th><th>Status</th><th>Role</th><th>Last Login</th><th>Security</th><th>Actions</th></tr></thead>
    <tbody>${users.map(u => `<tr>
      <td class="mono">${esc(u.username)}</td>
      <td>${u.enabled ? badge('Enabled', 'green') : badge('Disabled', 'red')}</td>
      <td>${esc(u.role || 'admin')}</td>
      <td>${u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : '-'}${u.lastLoginIp ? `<div class="mono">${esc(u.lastLoginIp)}</div>` : ''}</td>
      <td>${badge(`Failures ${u.failedLoginCount || 0}`, u.failedLoginCount ? 'red' : 'green')}${u.lastFailedLoginAt ? `<div class="mono">last failed ${new Date(u.lastFailedLoginAt).toLocaleString()}</div>` : ''}${u.passwordUpdatedAt ? `<div class="mono">password ${new Date(u.passwordUpdatedAt).toLocaleString()}</div>` : ''}</td>
      <td>
        <button class="btn btn-sm" onclick="toggleUserEnabled('${escJs(u.username)}', ${!u.enabled})">${u.enabled ? 'Disable' : 'Enable'}</button>
        <button class="btn btn-sm" onclick="changeUserPassword('${escJs(u.username)}')">Password</button>
        <button class="btn btn-danger btn-sm" onclick="deleteUser('${escJs(u.username)}')">Delete</button>
      </td>
    </tr>`).join('')}</tbody>
  </table>`;
}

async function changeOwnPassword() {
  const currentPassword = prompt('Enter your current password.');
  if (currentPassword === null) return;
  const newPassword = prompt('Enter your new password (at least 8 characters).');
  if (newPassword === null) return;
  const res = await api('/me/password', {
    method: 'POST',
    body: JSON.stringify({ currentPassword, newPassword }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to change password');
    return;
  }
  alert('Password changed.');
  await loadUsers();
}

function showCreateUser() {
  document.getElementById('create-user-form').classList.remove('hidden');
}

function hideCreateUser() {
  document.getElementById('create-user-form').classList.add('hidden');
}

async function createUser() {
  const username = document.getElementById('user-name').value.trim();
  const password = document.getElementById('user-password').value;
  if (!username || !password) return;
  const res = await api('/users', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to create user');
    return;
  }
  hideCreateUser();
  document.getElementById('user-name').value = '';
  document.getElementById('user-password').value = '';
  await loadStats();
  await loadUsers();
}

async function toggleUserEnabled(username, enabled) {
  const res = await api(`/users/${encodeURIComponent(username)}`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to update user');
    return;
  }
  await loadStats();
  await loadUsers();
}

async function changeUserPassword(username) {
  const password = prompt(`Enter a new password for "${username}" (at least 8 characters).`);
  if (password === null) return;
  const res = await api(`/users/${encodeURIComponent(username)}`, {
    method: 'PATCH',
    body: JSON.stringify({ password }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to change password');
    return;
  }
  await loadUsers();
}

async function deleteUser(username) {
  if (!confirm(`Delete admin user "${username}"?`)) return;
  const res = await api(`/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
  if (!res.ok) {
    const data = await res.json();
    alert(data.error?.message || 'Failed to delete user');
    return;
  }
  await loadStats();
  await loadUsers();
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
  const deviceId = document.getElementById('token-device').value || undefined;
  if (!name) return;
  const expiresAt = expiry ? new Date(expiry).toISOString() : undefined;
  const res = await api('/tokens', {
    method: 'POST',
    body: JSON.stringify({ name, namespacePattern: ns, expiresAt, deviceId }),
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
  document.getElementById('token-device').value = '';
  await loadStats();
  await loadTokens();
  await loadDevices();
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
  await loadDevices();
}

async function loadConflicts() {
  const res = await api('/conflicts');
  if (!res.ok) return;
  const conflicts = await res.json();
  const el = document.getElementById('conflicts-table');
  if (!conflicts.length) {
    el.innerHTML = '<div class="empty-state">No recent sync conflicts.</div>';
    return;
  }
  el.innerHTML = `<table>
    <thead><tr><th>Time</th><th>Namespace</th><th>Operation</th><th>Device</th><th>Requested</th><th>Remote</th><th>Message</th></tr></thead>
    <tbody>${conflicts.map(c => `<tr>
      <td>${c.occurredAt ? new Date(c.occurredAt).toLocaleString() : '-'}</td>
      <td class="mono">${esc(c.namespace)}${c.objectPath ? `<div>${esc(c.objectPath)}</div>` : ''}</td>
      <td>${badge(c.operation || 'write', 'muted')}</td>
      <td class="mono">${esc(c.deviceId || '-')}</td>
      <td>${renderRevisionEtags(c.requestedRevision, c.requestedEtag)}</td>
      <td>${renderRevisionEtags(c.remoteRevision, c.remoteEtag)}</td>
      <td>${esc(c.message)}</td>
    </tr>`).join('')}</tbody>
  </table>`;
}

function renderRevisionEtags(revision, etag) {
  return [
    revision ? `<div>rev <span class="mono">${esc(revision)}</span></div>` : '',
    etag ? `<div>etag <span class="mono">${esc(etag)}</span></div>` : '',
  ].join('') || '-';
}

async function loadDevices() {
  const res = await api('/devices');
  if (!res.ok) return;
  const devices = await res.json();
  deviceCache = devices;
  renderDeviceSelectors();
  const el = document.getElementById('devices-table');
  if (!devices.length) {
    el.innerHTML = '<div class="empty-state">No devices registered yet.</div>';
    return;
  }
  el.innerHTML = `<table>
    <thead><tr><th>Name</th><th>Status</th><th>Namespace</th><th>Token</th><th>Last Seen</th><th>Client</th><th>Actions</th></tr></thead>
    <tbody>${devices.map(d => `<tr>
      <td>${esc(d.name)}${d.notes ? `<div class="mono">${esc(d.notes)}</div>` : ''}</td>
      <td>${d.enabled ? badge('Enabled', 'green') : badge('Disabled', 'red')}</td>
      <td class="mono">${esc(d.namespacePattern || '-')}</td>
      <td>${d.tokenId ? esc(tokenName(d.tokenId)) : '-'}</td>
      <td>${d.lastSeenAt ? new Date(d.lastSeenAt).toLocaleString() : '-'}${d.lastClientIp ? `<div class="mono">${esc(d.lastClientIp)}</div>` : ''}</td>
      <td>${d.lastClientVersion ? esc(d.lastClientVersion) : '-'}</td>
      <td>
        <button class="btn btn-sm" onclick="toggleDeviceEnabled('${d.id}', ${!d.enabled})">${d.enabled ? 'Disable' : 'Enable'}</button>
        <button class="btn btn-sm" onclick="editDeviceToken('${d.id}', ${d.tokenId ? `'${escJs(d.tokenId)}'` : 'null'})">Token</button>
        <button class="btn btn-sm" onclick="editDeviceNotes('${d.id}', ${d.notes ? `'${escJs(d.notes)}'` : 'null'})">Notes</button>
        <button class="btn btn-danger btn-sm" onclick="deleteDevice('${d.id}')">Delete</button>
      </td>
    </tr>`).join('')}</tbody>
  </table>`;
}

function renderDeviceSelectors() {
  const tokenDevice = document.getElementById('token-device');
  const deviceToken = document.getElementById('device-token');
  if (tokenDevice) {
    tokenDevice.innerHTML = `<option value="">No device</option>${deviceCache.map(d => `<option value="${esc(d.id)}">${esc(d.name)}</option>`).join('')}`;
  }
  if (deviceToken) {
    deviceToken.innerHTML = `<option value="">No token</option>${tokenCache.map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('')}`;
  }
}

function deviceName(id) {
  return deviceCache.find((device) => device.id === id)?.name || id;
}

function tokenName(id) {
  return tokenCache.find((token) => token.id === id)?.name || id;
}

function showCreateDevice() {
  renderDeviceSelectors();
  document.getElementById('create-device-form').classList.remove('hidden');
}

function hideCreateDevice() {
  document.getElementById('create-device-form').classList.add('hidden');
}

async function createDevice() {
  const name = document.getElementById('device-name').value.trim();
  const namespacePattern = document.getElementById('device-ns').value.trim() || undefined;
  const tokenId = document.getElementById('device-token').value || undefined;
  const notes = document.getElementById('device-notes').value.trim() || undefined;
  if (!name) return;
  const res = await api('/devices', {
    method: 'POST',
    body: JSON.stringify({ name, namespacePattern, tokenId, notes }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to create device');
    return;
  }
  hideCreateDevice();
  document.getElementById('device-name').value = '';
  document.getElementById('device-ns').value = '';
  document.getElementById('device-token').value = '';
  document.getElementById('device-notes').value = '';
  await loadStats();
  await loadTokens();
  await loadDevices();
}

async function toggleDeviceEnabled(id, enabled) {
  const res = await api(`/devices/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to update device');
    return;
  }
  await loadStats();
  await loadDevices();
}

async function editDeviceToken(id, currentTokenId) {
  const input = prompt('Enter linked token ID (leave blank to clear).', currentTokenId || '');
  if (input === null) return;
  const tokenId = input.trim() ? input.trim() : null;
  const res = await api(`/devices/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ tokenId }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to update device token');
    return;
  }
  await loadTokens();
  await loadDevices();
}

async function editDeviceNotes(id, currentNotes) {
  const input = prompt('Enter device notes (leave blank to clear).', currentNotes || '');
  if (input === null) return;
  const notes = input.trim() ? input.trim() : null;
  const res = await api(`/devices/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ notes }),
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error?.message || 'Failed to update notes');
    return;
  }
  await loadDevices();
}

async function deleteDevice(id) {
  if (!confirm('Delete this device record? Linked tokens will remain usable but detached.')) return;
  const res = await api(`/devices/${id}`, { method: 'DELETE' });
  if (!res.ok) {
    const data = await res.json();
    alert(data.error?.message || 'Failed to delete device');
    return;
  }
  await loadStats();
  await loadTokens();
  await loadDevices();
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
    <thead><tr><th>Namespace</th><th>Status</th><th>Format</th><th>Storage</th><th>Objects</th><th>Last Write</th><th>Actions</th></tr></thead>
    <tbody>${nss.map(n => `<tr>
      <td class="mono">${esc(n.namespace)}</td>
      <td>${n.deletedAt ? badge('Soft deleted', 'red') : badge('Active', 'green')}</td>
      <td><span class="badge ${n.format ? 'badge-green' : 'badge-muted'}">${n.format || 'legacy'}</span></td>
      <td>${formatBytes(n.totalBytes)} ${renderGrowth(n.growthBytes)}<div class="mono">blob ${formatBytes(n.blobSize)} / objects ${formatBytes(n.objectBytes)}</div>${n.deletedBytes ? `<div class="mono">deleted ${formatBytes(n.deletedBytes)}</div>` : ''}${n.storageObservedAt ? `<div class="mono">observed ${new Date(n.storageObservedAt).toLocaleString()}</div>` : ''}</td>
      <td>${n.objectCount}</td>
      <td>${n.lastWriteAt ? new Date(n.lastWriteAt).toLocaleString() : '-'}</td>
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

function renderGrowth(bytes) {
  const value = Number(bytes || 0);
  if (value === 0) return badge('0 B trend', 'muted');
  const label = `${value > 0 ? '+' : '-'}${formatBytes(Math.abs(value))}`;
  return badge(label, value > 0 ? 'red' : 'green');
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

function getCookie(name) {
  return document.cookie
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1) || null;
}
</script>
</body>
</html>"##;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn test_state(admin_cookie_secure: bool, trust_proxy_headers: bool) -> AppState {
        let file = NamedTempFile::new().unwrap();
        AppState {
            db: crate::db::Database::open(file.path().to_str().unwrap()).unwrap(),
            db_path: file.path().to_string_lossy().to_string(),
            encryption_key: None,
            admin_enabled: true,
            jwt_secret: "secret".to_string(),
            admin_jwt_secret_persistent: true,
            admin_cookie_secure,
            token_reveal_key: [0; 32],
            token_reveal_persistent: true,
            trust_proxy_headers,
            sync_cors_allowed_origins: Vec::new(),
            max_blob_size: 1024,
            max_object_size: 1024,
            min_free_disk_bytes: 0,
            login_window_seconds: 900,
            login_lockout_seconds: 900,
            max_login_failures: 5,
            default_token_ttl_seconds: None,
            metadata_retention: MetadataRetentionConfig {
                store_revision: true,
                store_uploaded_at: true,
                store_device_id: true,
                store_content_hash: true,
            },
        }
    }

    #[test]
    fn cookie_extraction_prefers_named_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_static("other=1; admin_session=abc123; admin_csrf=csrf123"),
        );
        assert_eq!(
            extract_cookie(&headers, ADMIN_COOKIE_NAME).as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn csrf_verification_requires_matching_cookie_and_header() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("admin_csrf=csrf123"));
        headers.insert(ADMIN_CSRF_HEADER_NAME, HeaderValue::from_static("csrf123"));

        assert!(verify_csrf(&headers).is_ok());
    }

    #[test]
    fn csrf_verification_rejects_missing_header() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("admin_csrf=csrf123"));

        assert!(verify_csrf(&headers).is_err());
    }

    #[test]
    fn normalize_optional_timestamp_accepts_rfc3339() {
        let normalized =
            normalize_optional_timestamp(Some("2026-04-23T12:34:56Z".to_string())).unwrap();
        assert_eq!(normalized.as_deref(), Some("2026-04-23T12:34:56+00:00"));
    }

    #[test]
    fn admin_username_validation_rejects_unsafe_names() {
        assert!(validate_admin_username("ops-admin_1").is_ok());
        assert!(validate_admin_username("").is_err());
        assert!(validate_admin_username("ops/admin").is_err());
    }

    #[test]
    fn user_login_failure_updates_user_security_state() {
        let state = test_state(true, false);
        let now = chrono::Utc::now().to_rfc3339();
        let mut user = AdminUserRecord {
            username: "ops".to_string(),
            password_hash: "hash".to_string(),
            role: "admin".to_string(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
            last_login_at: None,
            last_login_ip: None,
            failed_login_count: 0,
            last_failed_login_at: None,
            password_updated_at: None,
            disabled_at: None,
        };

        record_user_login_failure(&state, &mut user).unwrap();
        let stored = state.db.get_admin_user("ops").unwrap().unwrap();

        assert_eq!(stored.failed_login_count, 1);
        assert!(stored.last_failed_login_at.is_some());
    }

    #[test]
    fn secure_cookie_is_omitted_for_plain_http_requests() {
        let headers = HeaderMap::new();
        let state = test_state(true, false);

        assert!(!effective_admin_cookie_secure(&headers, &state));
        assert!(!build_admin_session_cookie(
            "jwt",
            effective_admin_cookie_secure(&headers, &state)
        )
        .contains("; Secure"));
    }

    #[test]
    fn secure_cookie_is_kept_for_trusted_https_proxy_requests() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let state = test_state(true, true);

        assert!(effective_admin_cookie_secure(&headers, &state));
        assert!(
            build_admin_session_cookie("jwt", effective_admin_cookie_secure(&headers, &state))
                .contains("; Secure")
        );
    }
}
