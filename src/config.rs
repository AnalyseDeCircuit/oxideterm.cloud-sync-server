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
    pub format: Option<String>,
}

/// Admin panel: API token record.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    pub namespace_pattern: String,
    pub permissions: Vec<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}
