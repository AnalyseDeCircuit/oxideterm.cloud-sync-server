// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use serde::{Deserialize, Serialize};

/// Namespace-scoped metadata as stored in the database and served via API.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncMetadata {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploaded_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default)]
    pub content_length: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_revisions: Option<SectionRevisions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sections: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<serde_json::Value>,
}

impl SyncMetadata {
    pub fn empty() -> Self {
        Self {
            exists: false,
            format: None,
            revision: None,
            etag: None,
            content_hash: None,
            uploaded_at: None,
            device_id: None,
            content_length: 0,
            section_revisions: None,
            sections: None,
            content_type: None,
            scope: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionRevisions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwards: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_settings: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_settings: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Response envelope for write operations.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_revisions: Option<SectionRevisions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_etag: Option<String>,
}

/// Object write result.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectWriteResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredObjectMetadata {
    pub etag: String,
    pub updated_at: String,
}

/// Metadata write request body (PUT /metadata).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataWriteRequest {
    pub format: Option<String>,
    pub revision: String,
    pub uploaded_at: Option<String>,
    pub device_id: Option<String>,
    pub content_type: Option<String>,
    pub scope: Option<serde_json::Value>,
    pub sections: Option<serde_json::Value>,
    pub section_revisions: Option<SectionRevisions>,
}

/// Admin panel: user/namespace listing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceInfo {
    pub namespace: String,
    pub revision: Option<String>,
    pub uploaded_at: Option<String>,
    pub device_id: Option<String>,
    pub blob_size: u64,
    pub object_count: u64,
    #[serde(default)]
    pub object_bytes: u64,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub growth_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_write_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_observed_at: Option<String>,
    #[serde(default)]
    pub deleted_bytes: u64,
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

/// Admin panel: API token record.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_token: Option<String>,
    pub namespace_pattern: String,
    pub permissions: Vec<String>,
    pub created_at: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default)]
    pub read_count: u64,
    #[serde(default)]
    pub write_count: u64,
    #[serde(default)]
    pub failed_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_permission: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_client_version: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Admin-managed device identity linked to API tokens and sync observations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_client_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MetadataRetentionConfig {
    pub store_revision: bool,
    pub store_uploaded_at: bool,
    pub store_device_id: bool,
    pub store_content_hash: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginAttemptRecord {
    pub first_failure_at: String,
    pub failures: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_until: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletedNamespaceRecord {
    pub deleted_at: String,
}

/// Recent optimistic-lock conflict observed by the sync API.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncConflictRecord {
    pub id: String,
    pub occurred_at: String,
    pub namespace: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_etag: Option<String>,
    pub message: String,
}

/// Last known namespace storage snapshot used to show short-term growth.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceUsageRecord {
    pub namespace: String,
    pub observed_at: String,
    pub blob_bytes: u64,
    pub object_count: u64,
    pub object_bytes: u64,
    pub total_bytes: u64,
    pub growth_bytes: i64,
    pub soft_deleted: bool,
}

/// Admin panel user account. Password hashes are bcrypt values, never plaintext.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserRecord {
    pub username: String,
    pub password_hash: String,
    pub role: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_ip: Option<String>,
    #[serde(default)]
    pub failed_login_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_failed_login_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_at: Option<String>,
}
