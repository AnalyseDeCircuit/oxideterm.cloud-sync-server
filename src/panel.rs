// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::api::AppState;
use crate::auth;
use crate::config::*;
use crate::error::AppError;

const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
const LOGIN_LOCKOUT: Duration = Duration::from_secs(15 * 60);
const MAX_LOGIN_FAILURES: u32 = 5;

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        // Admin SPA
        .route("/admin", get(admin_page))
        // Admin API
        .route("/admin/api/login", post(admin_login))
        .route(
            "/admin/api/namespaces",
            get(admin_list_namespaces).post(admin_create_namespace),
        )
        .route(
            "/admin/api/namespaces/{namespace}",
            delete(admin_delete_namespace),
        )
        .route(
            "/admin/api/tokens",
            get(admin_list_tokens).post(admin_create_token),
        )
        .route("/admin/api/tokens/{id}", delete(admin_delete_token))
        .route("/admin/api/stats", get(admin_stats))
}

// ── Admin Auth ──

fn verify_admin(headers: &HeaderMap, state: &AppState) -> Result<(), AppError> {
    if state.admin_password_hash.is_none() {
        return Err(AppError::NotFound("Admin panel disabled".to_string()));
    }

    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("Missing admin token".to_string()))?;

    // Use independent JWT secret, not the bcrypt hash
    auth::validate_admin_jwt(token.trim(), &state.jwt_secret)
        .map_err(|_| AppError::Unauthorized("Invalid or expired admin token".to_string()))?;

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
        record_login_failure(&state, client_ip)?;
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    clear_login_failures(&state, client_ip)?;

    let jwt = auth::create_admin_jwt(&state.jwt_secret)
        .map_err(|e| AppError::Internal(format!("JWT creation failed: {e}")))?;

    Ok(Json(json!({ "token": jwt })))
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

// ── GET /admin/api/namespaces ──

async fn admin_list_namespaces(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;

    let namespaces = state.db.list_namespaces()?;
    let mut infos = Vec::new();

    for ns in namespaces {
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
        });
    }

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
    Json(body): Json<CreateNamespaceRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;

    let namespace = body.namespace.trim().to_string();
    crate::api::validate_namespace(&namespace)?;

    // Check if namespace already exists
    if state.db.get_metadata(&namespace)?.is_some() {
        return Err(AppError::BadRequest(format!(
            "Namespace '{}' already exists",
            namespace
        )));
    }

    // Write empty metadata to create the namespace
    let meta = SyncMetadata::empty();
    let serialized = serde_json::to_vec(&meta)
        .map_err(|e| AppError::Internal(format!("Failed to serialize metadata: {e}")))?;
    state.db.set_metadata(&namespace, &serialized)?;

    Ok(Json(json!({ "ok": true, "namespace": namespace })))
}

// ── DELETE /admin/api/namespaces/:namespace ──

async fn admin_delete_namespace(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(namespace): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    state.db.delete_namespace(&namespace)?;
    Ok(Json(json!({ "ok": true })))
}

// ── GET /admin/api/tokens ──

async fn admin_list_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    let tokens = state.db.get_all_tokens()?;
    // Return tokens without the hash
    let safe_tokens: Vec<serde_json::Value> = tokens
        .iter()
        .map(|t| {
            json!({
                "id": t.id,
                "name": t.name,
                "namespacePattern": t.namespace_pattern,
                "permissions": t.permissions,
                "createdAt": t.created_at,
                "lastUsedAt": t.last_used_at,
            })
        })
        .collect();
    Ok(Json(safe_tokens))
}

// ── POST /admin/api/tokens ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenRequest {
    name: String,
    namespace_pattern: String,
    permissions: Option<Vec<String>>,
}

async fn admin_create_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;

    // Validate namespace pattern
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

    // Generate a secure random token
    let raw_token = uuid::Uuid::new_v4().to_string();
    let token_hash = auth::hash_api_token(&raw_token);
    let id = uuid::Uuid::new_v4().to_string();

    let token = ApiToken {
        id: id.clone(),
        name: body.name,
        token_hash,
        namespace_pattern: body.namespace_pattern,
        permissions,
        created_at: chrono::Utc::now().to_rfc3339(),
        last_used_at: None,
    };

    state.db.set_token(&token)?;

    // Return the raw token ONCE — it cannot be retrieved again
    Ok(Json(json!({
        "id": id,
        "token": raw_token,
        "name": token.name,
        "namespacePattern": token.namespace_pattern,
        "permissions": token.permissions,
        "createdAt": token.created_at,
    })))
}

fn ensure_login_allowed(state: &AppState, ip: IpAddr) -> Result<(), AppError> {
    let now = Instant::now();
    let mut attempts = state
        .login_attempts
        .lock()
        .map_err(|_| AppError::Internal("Login rate limiter lock poisoned".to_string()))?;

    attempts.retain(|_, attempt| {
        if let Some(blocked_until) = attempt.blocked_until {
            blocked_until > now
        } else {
            now.duration_since(attempt.first_failure_at) <= LOGIN_WINDOW
        }
    });

    if let Some(attempt) = attempts.get(&ip) {
        if let Some(blocked_until) = attempt.blocked_until {
            if blocked_until > now {
                let retry_after = blocked_until.duration_since(now).as_secs();
                return Err(AppError::TooManyRequests(format!(
                    "Too many login attempts. Retry in {} seconds",
                    retry_after.max(1)
                )));
            }
        }
    }

    Ok(())
}

fn record_login_failure(state: &AppState, ip: IpAddr) -> Result<(), AppError> {
    let now = Instant::now();
    let mut attempts = state
        .login_attempts
        .lock()
        .map_err(|_| AppError::Internal("Login rate limiter lock poisoned".to_string()))?;

    let attempt = attempts.entry(ip).or_insert(crate::api::LoginAttemptState {
        first_failure_at: now,
        failures: 0,
        blocked_until: None,
    });

    if now.duration_since(attempt.first_failure_at) > LOGIN_WINDOW {
        attempt.first_failure_at = now;
        attempt.failures = 0;
        attempt.blocked_until = None;
    }

    attempt.failures += 1;
    if attempt.failures >= MAX_LOGIN_FAILURES {
        attempt.blocked_until = Some(now + LOGIN_LOCKOUT);
    }

    Ok(())
}

fn clear_login_failures(state: &AppState, ip: IpAddr) -> Result<(), AppError> {
    let mut attempts = state
        .login_attempts
        .lock()
        .map_err(|_| AppError::Internal("Login rate limiter lock poisoned".to_string()))?;
    attempts.remove(&ip);
    Ok(())
}

// ── DELETE /admin/api/tokens/:id ──

async fn admin_delete_token(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;
    state.db.delete_token(&id)?;
    Ok(Json(json!({ "ok": true })))
}

// ── GET /admin/api/stats ──

async fn admin_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    verify_admin(&headers, &state)?;

    let namespaces = state.db.list_namespaces()?;
    let tokens = state.db.get_all_tokens()?;
    let encrypted = state.encryption_key.is_some();

    Ok(Json(json!({
        "namespaceCount": namespaces.len(),
        "tokenCount": tokens.len(),
        "encryptionEnabled": encrypted,
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
  .container { max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem; }
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
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th { text-align: left; padding: 0.5rem; color: var(--ot-text-muted); font-weight: 500; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--ot-border); }
  td { padding: 0.625rem 0.5rem; border-bottom: 1px solid var(--ot-border); }
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
  input[type="text"], input[type="password"] {
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

<!-- Login Screen -->
<div id="login-screen" class="login-wrapper">
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

<!-- Dashboard -->
<div id="dashboard" class="container hidden">
  <div class="header">
    <div class="header-left">
      <h1>OxideTerm Cloud Sync</h1>
      <p class="subtitle">Server Administration</p>
    </div>
    <button class="btn btn-sm" onclick="logout()">Sign Out</button>
  </div>

  <!-- Stats -->
  <div class="card">
    <h2>Overview</h2>
    <div class="stats-grid">
      <div class="stat-item">
        <div class="stat-value" id="stat-namespaces">-</div>
        <div class="stat-label">Namespaces</div>
      </div>
      <div class="stat-item">
        <div class="stat-value" id="stat-tokens">-</div>
        <div class="stat-label">API Tokens</div>
      </div>
      <div class="stat-item">
        <div class="stat-value" id="stat-encryption">-</div>
        <div class="stat-label">Encryption</div>
      </div>
      <div class="stat-item">
        <div class="stat-value" id="stat-version">-</div>
        <div class="stat-label">Version</div>
      </div>
    </div>
  </div>

  <!-- API Tokens -->
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
      </div>
      <button class="btn btn-primary btn-sm" onclick="createToken()">Generate</button>
      <button class="btn btn-sm" onclick="hideCreateToken()">Cancel</button>
    </div>
    <div id="new-token-reveal" class="token-reveal hidden">
      <div class="label">This token will only be shown once. Copy it now.</div>
      <div class="value" id="new-token-value"></div>
    </div>
    <div id="tokens-table"></div>
  </div>

  <!-- Namespaces -->
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
let jwt = localStorage.getItem('admin_jwt');

// ── Init ──
if (jwt) { showDashboard(); } else { showLogin(); }

function showLogin() {
  document.getElementById('login-screen').classList.remove('hidden');
  document.getElementById('dashboard').classList.add('hidden');
}

function showDashboard() {
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
  loadStats();
  loadTokens();
  loadNamespaces();
}

function logout() {
  jwt = null;
  localStorage.removeItem('admin_jwt');
  showLogin();
}

// ── Login ──
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = document.getElementById('password').value;
  const errEl = document.getElementById('login-error');
  errEl.classList.add('hidden');
  try {
    const res = await fetch(`${API}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
    });
    if (!res.ok) {
      const data = await res.json();
      errEl.textContent = data.error?.message || 'Login failed';
      errEl.classList.remove('hidden');
      return;
    }
    const data = await res.json();
    jwt = data.token;
    localStorage.setItem('admin_jwt', jwt);
    showDashboard();
  } catch (err) {
    errEl.textContent = 'Network error';
    errEl.classList.remove('hidden');
  }
});

// ── API Helper ──
async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${jwt}`, 'Content-Type': 'application/json', ...opts.headers },
  });
  if (res.status === 401) { logout(); throw new Error('Session expired'); }
  return res;
}

// ── Stats ──
async function loadStats() {
  try {
    const res = await api('/stats');
    const d = await res.json();
    document.getElementById('stat-namespaces').textContent = d.namespaceCount;
    document.getElementById('stat-tokens').textContent = d.tokenCount;
    document.getElementById('stat-encryption').textContent = d.encryptionEnabled ? 'ON' : 'OFF';
    document.getElementById('stat-version').textContent = 'v' + d.version;
  } catch {}
}

// ── Tokens ──
async function loadTokens() {
  try {
    const res = await api('/tokens');
    const tokens = await res.json();
    const el = document.getElementById('tokens-table');
    if (!tokens.length) {
      el.innerHTML = '<div class="empty-state">No API tokens. Create one to get started.</div>';
      return;
    }
    el.innerHTML = `<table>
      <thead><tr><th>Name</th><th>Namespace</th><th>Created</th><th></th></tr></thead>
      <tbody>${tokens.map(t => `<tr>
        <td>${esc(t.name)}</td>
        <td class="mono">${esc(t.namespacePattern)}</td>
        <td>${new Date(t.createdAt).toLocaleDateString()}</td>
        <td><button class="btn btn-danger btn-sm" onclick="deleteToken('${t.id}')">Delete</button></td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch {}
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
  if (!name) return;
  try {
    const res = await api('/tokens', {
      method: 'POST',
      body: JSON.stringify({ name, namespacePattern: ns }),
    });
    const data = await res.json();
    document.getElementById('new-token-value').textContent = data.token;
    document.getElementById('new-token-reveal').classList.remove('hidden');
    hideCreateToken();
    document.getElementById('token-name').value = '';
    document.getElementById('token-ns').value = '';
    loadTokens();
    loadStats();
  } catch {}
}

async function deleteToken(id) {
  if (!confirm('Delete this token? Clients using it will lose access.')) return;
  try {
    await api(`/tokens/${id}`, { method: 'DELETE' });
    loadTokens();
    loadStats();
  } catch {}
}

// ── Namespaces ──
async function loadNamespaces() {
  try {
    const res = await api('/namespaces');
    const nss = await res.json();
    const el = document.getElementById('namespaces-table');
    if (!nss.length) {
      el.innerHTML = '<div class="empty-state">No synced namespaces yet.</div>';
      return;
    }
    el.innerHTML = `<table>
      <thead><tr><th>Namespace</th><th>Format</th><th>Objects</th><th>Last Sync</th><th></th></tr></thead>
      <tbody>${nss.map(n => `<tr>
        <td class="mono">${esc(n.namespace)}</td>
        <td><span class="badge ${n.format ? 'badge-green' : 'badge-muted'}">${n.format || 'legacy'}</span></td>
        <td>${n.objectCount}</td>
        <td>${n.uploadedAt ? new Date(n.uploadedAt).toLocaleString() : '-'}</td>
        <td><button class="btn btn-danger btn-sm" onclick="deleteNs('${esc(n.namespace)}')">Delete</button></td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch {}
}

async function deleteNs(ns) {
  if (!confirm(`Delete namespace "${ns}" and all its data? This cannot be undone.`)) return;
  try {
    await api(`/namespaces/${encodeURIComponent(ns)}`, { method: 'DELETE' });
    loadNamespaces();
    loadStats();
  } catch {}
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
  try {
    const res = await api('/namespaces', {
      method: 'POST',
      body: JSON.stringify({ namespace: name }),
    });
    if (!res.ok) {
      const data = await res.json();
      alert(data.error?.message || 'Failed to create namespace');
      return;
    }
    hideCreateNs();
    document.getElementById('ns-name').value = '';
    loadNamespaces();
    loadStats();
  } catch {}
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML.replace(/'/g, '&#39;').replace(/"/g, '&quot;'); }
</script>
</body>
</html>"##;
