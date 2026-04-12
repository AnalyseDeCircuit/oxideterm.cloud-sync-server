// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod error;
mod panel;

use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "oxideterm-cloud-sync-server")]
#[command(about = "Self-hosted cloud sync server for OxideTerm")]
#[command(version)]
struct Cli {
    /// Listen address
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:8730")]
    listen: SocketAddr,

    /// Database file path
    #[arg(long, env = "DB_PATH", default_value = "/data/sync.db")]
    db_path: String,

    /// Server-side encryption master key (hex, 32 bytes).
    /// If set, all stored blobs/objects are encrypted at rest with ChaCha20-Poly1305.
    /// Generate with: openssl rand -hex 32
    #[arg(long, env = "ENCRYPTION_KEY")]
    encryption_key: Option<String>,

    /// Admin password for the web management panel.
    /// If not set, the admin panel is disabled.
    #[arg(long, env = "ADMIN_PASSWORD")]
    admin_password: Option<String>,

    /// JWT signing secret for admin sessions.
    /// If omitted, a random secret is generated and all admin sessions expire on restart.
    #[arg(long, env = "ADMIN_JWT_SECRET")]
    admin_jwt_secret: Option<String>,

    /// Trust reverse-proxy headers such as X-Forwarded-For / X-Real-IP for admin login throttling.
    /// Only enable this when the server is behind a trusted reverse proxy that overwrites these headers.
    #[arg(long, env = "TRUST_PROXY_HEADERS", default_value_t = false)]
    trust_proxy_headers: bool,

    /// Maximum blob size in bytes (default: 64 MiB)
    #[arg(long, env = "MAX_BLOB_SIZE", default_value = "67108864")]
    max_blob_size: usize,

    /// Maximum object size in bytes (default: 16 MiB)
    #[arg(long, env = "MAX_OBJECT_SIZE", default_value = "16777216")]
    max_object_size: usize,
}

fn empty_to_none(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "oxideterm_cloud_sync_server=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    let encryption_key_raw = empty_to_none(cli.encryption_key.clone());
    let admin_password_raw = empty_to_none(cli.admin_password.clone());
    let admin_jwt_secret = empty_to_none(cli.admin_jwt_secret.clone());

    let encryption_key = encryption_key_raw.as_deref().map(|hex_key| {
        crypto::parse_hex_key(hex_key).expect("ENCRYPTION_KEY must be 64 hex chars (32 bytes)")
    });

    let admin_password_hash = admin_password_raw
        .as_deref()
        .map(|pw| auth::hash_admin_password(pw).expect("Failed to hash admin password"));

    let database = db::Database::open(&cli.db_path).expect("Failed to open database");

    let state = api::AppState {
        db: database,
        encryption_key,
        admin_password_hash: admin_password_hash.clone(),
        jwt_secret: admin_jwt_secret
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        login_attempts: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        trust_proxy_headers: cli.trust_proxy_headers,
        max_blob_size: cli.max_blob_size,
        max_object_size: cli.max_object_size,
    };

    let app = api::router(state).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .expect("Failed to bind listener");

    tracing::info!("OxideTerm Cloud Sync Server listening on {}", cli.listen);
    if encryption_key.is_some() {
        tracing::info!("Server-side encryption: ENABLED");
    } else {
        tracing::warn!("Server-side encryption: DISABLED — blobs stored in plaintext");
    }
    if admin_password_hash.is_some() {
        tracing::info!("Admin panel: ENABLED at /admin");
        if admin_jwt_secret.is_none() {
            tracing::warn!(
                "Admin JWT secret not configured — all admin sessions will be invalidated on restart"
            );
        }
    } else {
        tracing::info!("Admin panel: DISABLED (set ADMIN_PASSWORD to enable)");
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Server error");
}
