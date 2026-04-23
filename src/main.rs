// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod error;
mod panel;

use clap::Parser;
use config::MetadataRetentionConfig;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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

    /// Mark admin cookies as Secure. Disable only for local plain HTTP development.
    #[arg(long, env = "ADMIN_COOKIE_SECURE", default_value_t = true)]
    admin_cookie_secure: bool,

    /// Trust reverse-proxy headers such as X-Forwarded-For / X-Real-IP for admin login throttling.
    /// Only enable this when the server is behind a trusted reverse proxy that overwrites these headers.
    #[arg(long, env = "TRUST_PROXY_HEADERS", default_value_t = false)]
    trust_proxy_headers: bool,

    /// Comma-separated allowlist of origins for the sync API CORS policy. Use '*' to allow any origin.
    #[arg(long, env = "SYNC_CORS_ALLOWED_ORIGINS", value_delimiter = ',')]
    sync_cors_allowed_origins: Vec<String>,

    /// Maximum blob size in bytes (default: 64 MiB)
    #[arg(long, env = "MAX_BLOB_SIZE", default_value = "67108864")]
    max_blob_size: usize,

    /// Maximum object size in bytes (default: 16 MiB)
    #[arg(long, env = "MAX_OBJECT_SIZE", default_value = "16777216")]
    max_object_size: usize,

    /// Login failure observation window in seconds.
    #[arg(long, env = "LOGIN_WINDOW_SECONDS", default_value = "900")]
    login_window_seconds: i64,

    /// Login lockout duration in seconds once the failure threshold is crossed.
    #[arg(long, env = "LOGIN_LOCKOUT_SECONDS", default_value = "900")]
    login_lockout_seconds: i64,

    /// Maximum failed admin logins before temporary lockout.
    #[arg(long, env = "MAX_LOGIN_FAILURES", default_value = "5")]
    max_login_failures: u32,

    /// Default token lifetime in seconds. Tokens created without an explicit expiresAt inherit this.
    #[arg(long, env = "DEFAULT_TOKEN_TTL_SECONDS")]
    default_token_ttl_seconds: Option<i64>,

    /// Persist the revision field in namespace metadata.
    #[arg(long, env = "STORE_METADATA_REVISION", default_value_t = true)]
    store_metadata_revision: bool,

    /// Persist uploaded_at in namespace metadata.
    #[arg(long, env = "STORE_METADATA_UPLOADED_AT", default_value_t = true)]
    store_metadata_uploaded_at: bool,

    /// Persist device_id in namespace metadata.
    #[arg(long, env = "STORE_METADATA_DEVICE_ID", default_value_t = true)]
    store_metadata_device_id: bool,

    /// Persist content_hash in namespace metadata.
    #[arg(long, env = "STORE_METADATA_CONTENT_HASH", default_value_t = true)]
    store_metadata_content_hash: bool,

    /// Export the redb database to the given file and write a .sha256 sidecar.
    #[arg(long, env = "BACKUP_TO")]
    backup_to: Option<String>,

    /// Restore the redb database from a backup file. Verifies the .sha256 sidecar when present.
    #[arg(long, env = "RESTORE_FROM")]
    restore_from: Option<String>,

    /// Verify a backup file against its .sha256 sidecar.
    #[arg(long, env = "VERIFY_BACKUP")]
    verify_backup: Option<String>,
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

fn read_file_bytes(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

fn checksum_sidecar_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sha256", path.display()))
}

fn write_checksum(path: &Path) {
    let data = read_file_bytes(path);
    let digest = crypto::sha256_hex(&data);
    let checksum_path = checksum_sidecar_path(path);
    let payload = format!(
        "{digest}  {}\n",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    fs::write(&checksum_path, payload)
        .unwrap_or_else(|e| panic!("Failed to write {}: {}", checksum_path.display(), e));
}

fn verify_backup_file(path: &Path) {
    let checksum_path = checksum_sidecar_path(path);
    let checksum = fs::read_to_string(&checksum_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", checksum_path.display(), e));
    let expected = checksum
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("Checksum file {} is malformed", checksum_path.display()));
    let actual = crypto::sha256_hex(&read_file_bytes(path));
    assert_eq!(actual, expected, "Checksum mismatch for {}", path.display());
}

fn backup_database(db_path: &Path, output_path: &Path) {
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("Failed to create {}: {}", parent.display(), e));
    }
    fs::copy(db_path, output_path).unwrap_or_else(|e| {
        panic!(
            "Failed to copy database from {} to {}: {}",
            db_path.display(),
            output_path.display(),
            e
        )
    });
    write_checksum(output_path);
}

fn restore_database(backup_path: &Path, db_path: &Path) {
    let checksum_path = checksum_sidecar_path(backup_path);
    if checksum_path.exists() {
        verify_backup_file(backup_path);
    }
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("Failed to create {}: {}", parent.display(), e));
    }
    fs::copy(backup_path, db_path).unwrap_or_else(|e| {
        panic!(
            "Failed to restore database from {} to {}: {}",
            backup_path.display(),
            db_path.display(),
            e
        )
    });
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "oxideterm_cloud_sync_server=info,tower_http=info,audit=info".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let db_path = PathBuf::from(&cli.db_path);

    let maintenance_modes = [
        cli.backup_to.is_some(),
        cli.restore_from.is_some(),
        cli.verify_backup.is_some(),
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count();
    if maintenance_modes > 1 {
        panic!("Only one of --backup-to, --restore-from, or --verify-backup may be used at a time");
    }
    if let Some(output_path) = cli.backup_to.as_deref() {
        backup_database(&db_path, Path::new(output_path));
        tracing::info!("Backup written to {}", output_path);
        return;
    }
    if let Some(input_path) = cli.restore_from.as_deref() {
        restore_database(Path::new(input_path), &db_path);
        tracing::info!("Database restored from {}", input_path);
        return;
    }
    if let Some(input_path) = cli.verify_backup.as_deref() {
        verify_backup_file(Path::new(input_path));
        tracing::info!("Backup verification succeeded for {}", input_path);
        return;
    }

    let encryption_key_raw = empty_to_none(cli.encryption_key.clone());
    let admin_password_raw = empty_to_none(cli.admin_password.clone());
    let admin_jwt_secret = empty_to_none(cli.admin_jwt_secret.clone());

    let encryption_key = encryption_key_raw.as_deref().map(|hex_key| {
        crypto::parse_hex_key(hex_key).expect("ENCRYPTION_KEY must be 64 hex chars (32 bytes)")
    });

    let admin_password_hash = admin_password_raw
        .as_deref()
        .map(|pw| auth::hash_admin_password(pw).expect("Failed to hash admin password"));

    let jwt_secret = admin_jwt_secret
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let token_reveal_key =
        encryption_key.unwrap_or_else(|| crypto::derive_key(jwt_secret.as_bytes()));
    let token_reveal_persistent = encryption_key.is_some() || admin_jwt_secret.is_some();

    let database = db::Database::open(&cli.db_path).expect("Failed to open database");

    let state = api::AppState {
        db: database,
        db_path: cli.db_path.clone(),
        encryption_key,
        admin_password_hash: admin_password_hash.clone(),
        jwt_secret,
        admin_jwt_secret_persistent: admin_jwt_secret.is_some(),
        admin_cookie_secure: cli.admin_cookie_secure,
        token_reveal_key,
        token_reveal_persistent,
        trust_proxy_headers: cli.trust_proxy_headers,
        sync_cors_allowed_origins: cli
            .sync_cors_allowed_origins
            .iter()
            .map(|origin| origin.trim().to_string())
            .filter(|origin| !origin.is_empty())
            .collect(),
        max_blob_size: cli.max_blob_size,
        max_object_size: cli.max_object_size,
        login_window_seconds: cli.login_window_seconds,
        login_lockout_seconds: cli.login_lockout_seconds,
        max_login_failures: cli.max_login_failures,
        default_token_ttl_seconds: cli.default_token_ttl_seconds,
        metadata_retention: MetadataRetentionConfig {
            store_revision: cli.store_metadata_revision,
            store_uploaded_at: cli.store_metadata_uploaded_at,
            store_device_id: cli.store_metadata_device_id,
            store_content_hash: cli.store_metadata_content_hash,
        },
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
                "Admin JWT secret not configured — all admin sessions and secure token reveal will be invalidated on restart"
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
