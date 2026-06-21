// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

#![allow(clippy::result_large_err)]

use redb::{Database as RedbDatabase, ReadableTable, TableDefinition};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use crate::config::{
    AdminUserRecord, ApiToken, DeletedNamespaceRecord, DeviceRecord, LoginAttemptRecord,
    NamespaceUsageRecord, StoredObjectMetadata, SyncConflictRecord, SyncMetadata,
};

const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const BLOB_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
const OBJECT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("objects");
const OBJECT_META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("object_metadata");
const TOKEN_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("tokens");
const TOKEN_HASH_TABLE: TableDefinition<&str, &str> = TableDefinition::new("token_hashes");
const LOGIN_ATTEMPT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("login_attempts");
const DELETED_NAMESPACE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("deleted_namespaces");
const DEVICE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("devices");
const SYNC_CONFLICT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("sync_conflicts");
const NAMESPACE_USAGE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("namespace_usage");
const ADMIN_USER_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("admin_users");

fn metadata_key(namespace: &str) -> String {
    format!("ns:{namespace}")
}

fn blob_key(namespace: &str) -> String {
    format!("ns:{namespace}")
}

fn object_key(namespace: &str, path: &str) -> String {
    format!("ns:{namespace}/obj:{path}")
}

fn object_meta_key(namespace: &str, path: &str) -> String {
    object_key(namespace, path)
}

fn token_key(id: &str) -> String {
    format!("tok:{id}")
}

fn device_key(id: &str) -> String {
    format!("dev:{id}")
}

fn sync_conflict_key(occurred_at: &str, id: &str) -> String {
    format!("conflict:{occurred_at}:{id}")
}

fn namespace_usage_key(namespace: &str) -> String {
    format!("usage:{namespace}")
}

fn admin_user_key(username: &str) -> String {
    format!("admin:{username}")
}

fn timestamp_is_after(current: Option<&str>, candidate: &str) -> bool {
    let Some(current) = current else {
        return true;
    };
    let current = chrono::DateTime::parse_from_rfc3339(current)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc));
    let candidate = chrono::DateTime::parse_from_rfc3339(candidate)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc));
    candidate
        .zip(current)
        .is_some_and(|(candidate, current)| candidate > current)
}

#[derive(Debug)]
pub enum ConditionalWriteError {
    Conflict {
        remote_revision: Option<String>,
        remote_etag: Option<String>,
        message: String,
    },
    Storage(String),
    Serialization(serde_json::Error),
}

impl From<redb::Error> for ConditionalWriteError {
    fn from(value: redb::Error) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<redb::TableError> for ConditionalWriteError {
    fn from(value: redb::TableError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<redb::StorageError> for ConditionalWriteError {
    fn from(value: redb::StorageError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<redb::CommitError> for ConditionalWriteError {
    fn from(value: redb::CommitError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<redb::TransactionError> for ConditionalWriteError {
    fn from(value: redb::TransactionError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<serde_json::Error> for ConditionalWriteError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

#[derive(Clone)]
pub struct Database {
    inner: Arc<RedbDatabase>,
}

impl Database {
    pub fn open(path: &str) -> Result<Self, redb::Error> {
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let db = RedbDatabase::create(path)?;

        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(METADATA_TABLE)?;
            let _ = write_txn.open_table(BLOB_TABLE)?;
            let _ = write_txn.open_table(OBJECT_TABLE)?;
            let _ = write_txn.open_table(OBJECT_META_TABLE)?;
            let _ = write_txn.open_table(TOKEN_TABLE)?;
            let _ = write_txn.open_table(TOKEN_HASH_TABLE)?;
            let _ = write_txn.open_table(LOGIN_ATTEMPT_TABLE)?;
            let _ = write_txn.open_table(DELETED_NAMESPACE_TABLE)?;
            let _ = write_txn.open_table(DEVICE_TABLE)?;
            let _ = write_txn.open_table(SYNC_CONFLICT_TABLE)?;
            let _ = write_txn.open_table(NAMESPACE_USAGE_TABLE)?;
            let _ = write_txn.open_table(ADMIN_USER_TABLE)?;
        }
        write_txn.commit()?;

        Ok(Self {
            inner: Arc::new(db),
        })
    }

    pub fn check_writable(&self) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        write_txn.commit()?;
        Ok(())
    }

    // ── Metadata ──

    pub fn get_metadata(&self, namespace: &str) -> Result<Option<Vec<u8>>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(METADATA_TABLE)?;
        Ok(table
            .get(metadata_key(namespace).as_str())?
            .map(|v| v.value().to_vec()))
    }

    pub fn set_metadata(&self, namespace: &str, data: &[u8]) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(METADATA_TABLE)?;
            table.insert(metadata_key(namespace).as_str(), data)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ── Blobs ──

    pub fn get_blob(&self, namespace: &str) -> Result<Option<Vec<u8>>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(BLOB_TABLE)?;
        Ok(table
            .get(blob_key(namespace).as_str())?
            .map(|v| v.value().to_vec()))
    }

    pub fn put_blob_if_matches(
        &self,
        namespace: &str,
        expected_etag: Option<&str>,
        require_absent: bool,
        blob: &[u8],
        metadata: &[u8],
    ) -> Result<(), ConditionalWriteError> {
        let write_txn = self.inner.begin_write()?;
        {
            let meta_key = metadata_key(namespace);
            let mut meta_table = write_txn.open_table(METADATA_TABLE)?;
            let current_meta = meta_table
                .get(meta_key.as_str())?
                .map(|value| serde_json::from_slice::<SyncMetadata>(value.value()))
                .transpose()?;

            if let Some(expected_etag) = expected_etag {
                let current_etag = current_meta
                    .as_ref()
                    .and_then(|meta| meta.etag.as_deref())
                    .unwrap_or("");
                if current_etag != expected_etag {
                    return Err(ConditionalWriteError::Conflict {
                        remote_revision: current_meta
                            .as_ref()
                            .and_then(|meta| meta.revision.clone()),
                        remote_etag: current_meta.as_ref().and_then(|meta| meta.etag.clone()),
                        message: "Remote snapshot changed before upload completed".to_string(),
                    });
                }
            } else if require_absent && current_meta.as_ref().is_some_and(|meta| meta.exists) {
                return Err(ConditionalWriteError::Conflict {
                    remote_revision: current_meta.as_ref().and_then(|meta| meta.revision.clone()),
                    remote_etag: current_meta.as_ref().and_then(|meta| meta.etag.clone()),
                    message: "Remote snapshot already exists".to_string(),
                });
            }

            let mut blob_table = write_txn.open_table(BLOB_TABLE)?;
            blob_table.insert(blob_key(namespace).as_str(), blob)?;
            meta_table.insert(meta_key.as_str(), metadata)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ── Objects ──

    pub fn get_object(&self, namespace: &str, path: &str) -> Result<Option<Vec<u8>>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(OBJECT_TABLE)?;
        Ok(table
            .get(object_key(namespace, path).as_str())?
            .map(|v| v.value().to_vec()))
    }

    pub fn get_object_metadata(
        &self,
        namespace: &str,
        path: &str,
    ) -> Result<Option<StoredObjectMetadata>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(OBJECT_META_TABLE)?;
        table
            .get(object_meta_key(namespace, path).as_str())?
            .map(|v| serde_json::from_slice::<StoredObjectMetadata>(v.value()))
            .transpose()
            .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }

    pub fn put_object_if_matches(
        &self,
        namespace: &str,
        path: &str,
        expected_etag: Option<&str>,
        require_absent: bool,
        data: &[u8],
        metadata: &StoredObjectMetadata,
    ) -> Result<(), ConditionalWriteError> {
        let write_txn = self.inner.begin_write()?;
        {
            let key = object_key(namespace, path);
            let meta_key = object_meta_key(namespace, path);
            let serialized_meta = serde_json::to_vec(metadata)?;

            let mut meta_table = write_txn.open_table(OBJECT_META_TABLE)?;
            let current_meta = meta_table
                .get(meta_key.as_str())?
                .map(|value| serde_json::from_slice::<StoredObjectMetadata>(value.value()))
                .transpose()?;

            if let Some(expected_etag) = expected_etag {
                let current_etag = current_meta
                    .as_ref()
                    .map(|meta| meta.etag.as_str())
                    .unwrap_or("");
                if current_etag != expected_etag {
                    return Err(ConditionalWriteError::Conflict {
                        remote_revision: None,
                        remote_etag: current_meta.as_ref().map(|meta| meta.etag.clone()),
                        message: "Remote object changed before upload completed".to_string(),
                    });
                }
            } else if require_absent && current_meta.is_some() {
                return Err(ConditionalWriteError::Conflict {
                    remote_revision: None,
                    remote_etag: current_meta.as_ref().map(|meta| meta.etag.clone()),
                    message: "Remote object already exists".to_string(),
                });
            }

            let mut object_table = write_txn.open_table(OBJECT_TABLE)?;
            object_table.insert(key.as_str(), data)?;
            meta_table.insert(meta_key.as_str(), serialized_meta.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn blob_size(&self, namespace: &str) -> Result<u64, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(BLOB_TABLE)?;
        Ok(table
            .get(blob_key(namespace).as_str())?
            .map(|value| value.value().len() as u64)
            .unwrap_or(0))
    }

    pub fn namespace_object_stats(
        &self,
        namespace: &str,
    ) -> Result<(u64, u64, Option<String>), redb::Error> {
        let prefix = format!("ns:{namespace}/obj:");
        let read_txn = self.inner.begin_read()?;
        let object_table = read_txn.open_table(OBJECT_TABLE)?;
        let mut count = 0u64;
        let mut bytes = 0u64;
        let iter = object_table.range(prefix.as_str()..)?;
        for entry in iter {
            let entry = entry?;
            let key: &str = entry.0.value();
            if key.starts_with(&prefix) {
                count += 1;
                bytes = bytes.saturating_add(entry.1.value().len() as u64);
            } else {
                break;
            }
        }

        let meta_table = read_txn.open_table(OBJECT_META_TABLE)?;
        let mut last_write_at: Option<String> = None;
        let iter = meta_table.range(prefix.as_str()..)?;
        for entry in iter {
            let entry = entry?;
            let key: &str = entry.0.value();
            if !key.starts_with(&prefix) {
                break;
            }

            let Ok(meta) = serde_json::from_slice::<StoredObjectMetadata>(entry.1.value()) else {
                continue;
            };
            if timestamp_is_after(last_write_at.as_deref(), &meta.updated_at) {
                last_write_at = Some(meta.updated_at);
            }
        }

        Ok((count, bytes, last_write_at))
    }

    pub fn get_namespace_usage(
        &self,
        namespace: &str,
    ) -> Result<Option<NamespaceUsageRecord>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(NAMESPACE_USAGE_TABLE)?;
        table
            .get(namespace_usage_key(namespace).as_str())?
            .map(|value| serde_json::from_slice::<NamespaceUsageRecord>(value.value()))
            .transpose()
            .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }

    pub fn refresh_namespace_usage(
        &self,
        namespace: &str,
        observed_at: &str,
        soft_deleted: bool,
    ) -> Result<NamespaceUsageRecord, redb::Error> {
        let blob_bytes = self.blob_size(namespace)?;
        let (object_count, object_bytes, _) = self.namespace_object_stats(namespace)?;
        let total_bytes = blob_bytes.saturating_add(object_bytes);
        let previous_total = self
            .get_namespace_usage(namespace)?
            .map(|usage| usage.total_bytes)
            .unwrap_or(total_bytes);
        let growth_bytes = total_bytes as i128 - previous_total as i128;
        let usage = NamespaceUsageRecord {
            namespace: namespace.to_string(),
            observed_at: observed_at.to_string(),
            blob_bytes,
            object_count,
            object_bytes,
            total_bytes,
            growth_bytes: growth_bytes.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
            soft_deleted,
        };

        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(NAMESPACE_USAGE_TABLE)?;
            let data = serde_json::to_vec(&usage).map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            table.insert(namespace_usage_key(namespace).as_str(), data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(usage)
    }

    // ── Sync Conflicts ──

    pub fn add_sync_conflict(&self, conflict: &SyncConflictRecord) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(SYNC_CONFLICT_TABLE)?;
            let data = serde_json::to_vec(conflict).map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            table.insert(
                sync_conflict_key(&conflict.occurred_at, &conflict.id).as_str(),
                data.as_slice(),
            )?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn list_sync_conflicts(
        &self,
        limit: usize,
    ) -> Result<Vec<SyncConflictRecord>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(SYNC_CONFLICT_TABLE)?;
        let mut conflicts = Vec::new();
        let iter = table.iter()?;
        for entry in iter {
            let entry = entry?;
            let val: &[u8] = entry.1.value();
            if let Ok(conflict) = serde_json::from_slice::<SyncConflictRecord>(val) {
                conflicts.push(conflict);
            }
        }
        conflicts.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));
        conflicts.truncate(limit);
        Ok(conflicts)
    }

    // ── Admin Users ──

    pub fn list_admin_users(&self) -> Result<Vec<AdminUserRecord>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(ADMIN_USER_TABLE)?;
        let mut users = Vec::new();
        let iter = table.iter()?;
        for entry in iter {
            let entry = entry?;
            let val: &[u8] = entry.1.value();
            if let Ok(user) = serde_json::from_slice::<AdminUserRecord>(val) {
                users.push(user);
            }
        }
        Ok(users)
    }

    pub fn get_admin_user(&self, username: &str) -> Result<Option<AdminUserRecord>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(ADMIN_USER_TABLE)?;
        table
            .get(admin_user_key(username).as_str())?
            .map(|value| serde_json::from_slice::<AdminUserRecord>(value.value()))
            .transpose()
            .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }

    pub fn set_admin_user(&self, user: &AdminUserRecord) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(ADMIN_USER_TABLE)?;
            let data = serde_json::to_vec(user).map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            table.insert(admin_user_key(&user.username).as_str(), data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn delete_admin_user(&self, username: &str) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(ADMIN_USER_TABLE)?;
            table.remove(admin_user_key(username).as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ── Tokens ──

    pub fn get_all_tokens(&self) -> Result<Vec<ApiToken>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(TOKEN_TABLE)?;
        let mut tokens = Vec::new();
        let iter = table.iter()?;
        for entry in iter {
            let entry = entry?;
            let val: &[u8] = entry.1.value();
            if let Ok(token) = serde_json::from_slice::<ApiToken>(val) {
                tokens.push(token);
            }
        }
        Ok(tokens)
    }

    pub fn get_token_by_hash(&self, token_hash: &str) -> Result<Option<ApiToken>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let hash_table = read_txn.open_table(TOKEN_HASH_TABLE)?;
        let Some(token_id) = hash_table.get(token_hash)? else {
            return Ok(None);
        };

        self.get_token(token_id.value())
    }

    pub fn get_token(&self, id: &str) -> Result<Option<ApiToken>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let token_table = read_txn.open_table(TOKEN_TABLE)?;
        token_table
            .get(token_key(id).as_str())?
            .map(|value| serde_json::from_slice::<ApiToken>(value.value()))
            .transpose()
            .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }

    pub fn set_token(&self, token: &ApiToken) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(TOKEN_TABLE)?;
            let mut hash_table = write_txn.open_table(TOKEN_HASH_TABLE)?;

            if let Some(existing) = table.get(token_key(&token.id).as_str())? {
                let existing =
                    serde_json::from_slice::<ApiToken>(existing.value()).map_err(|e| {
                        redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                    })?;
                hash_table.remove(existing.token_hash.as_str())?;
            }

            let data = serde_json::to_vec(token).map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            table.insert(token_key(&token.id).as_str(), data.as_slice())?;
            hash_table.insert(token.token_hash.as_str(), token.id.as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn record_token_usage(
        &self,
        id: &str,
        namespace: &str,
        permission: &str,
        client_ip: &str,
        client_version: Option<&str>,
        observed_at: &str,
    ) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut token_table = write_txn.open_table(TOKEN_TABLE)?;
            let existing_data = token_table
                .get(token_key(id).as_str())?
                .map(|existing| existing.value().to_vec());
            if let Some(existing_data) = existing_data {
                let mut token =
                    serde_json::from_slice::<ApiToken>(&existing_data).map_err(|e| {
                        redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                    })?;
                token.last_used_at = Some(observed_at.to_string());
                token.last_namespace = Some(namespace.to_string());
                token.last_permission = Some(permission.to_string());
                token.last_client_ip = Some(client_ip.to_string());
                token.last_client_version = client_version.map(str::to_string);
                match permission {
                    "read" => token.read_count = token.read_count.saturating_add(1),
                    "write" => token.write_count = token.write_count.saturating_add(1),
                    _ => {}
                }

                let device_id = token.device_id.clone();
                let data = serde_json::to_vec(&token).map_err(|e| {
                    redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                })?;
                token_table.insert(token_key(id).as_str(), data.as_slice())?;

                if let Some(device_id) = device_id {
                    let mut device_table = write_txn.open_table(DEVICE_TABLE)?;
                    let existing_device = device_table
                        .get(device_key(&device_id).as_str())?
                        .map(|device| device.value().to_vec());
                    if let Some(existing_device) = existing_device {
                        let mut device = serde_json::from_slice::<DeviceRecord>(&existing_device)
                            .map_err(|e| {
                            redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                        })?;
                        device.token_id.get_or_insert_with(|| id.to_string());
                        device.last_seen_at = Some(observed_at.to_string());
                        device.last_client_ip = Some(client_ip.to_string());
                        if let Some(client_version) = client_version {
                            device.last_client_version = Some(client_version.to_string());
                        }
                        device.updated_at = observed_at.to_string();
                        let data = serde_json::to_vec(&device).map_err(|e| {
                            redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                        })?;
                        device_table.insert(device_key(&device_id).as_str(), data.as_slice())?;
                    }
                }
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn record_token_failure(&self, id: &str) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(TOKEN_TABLE)?;
            let existing_data = table
                .get(token_key(id).as_str())?
                .map(|existing| existing.value().to_vec());
            if let Some(existing_data) = existing_data {
                let mut token =
                    serde_json::from_slice::<ApiToken>(&existing_data).map_err(|e| {
                        redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                    })?;
                token.failed_count = token.failed_count.saturating_add(1);
                let data = serde_json::to_vec(&token).map_err(|e| {
                    redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                })?;
                table.insert(token_key(id).as_str(), data.as_slice())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn delete_token(&self, id: &str) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(TOKEN_TABLE)?;
            let mut hash_table = write_txn.open_table(TOKEN_HASH_TABLE)?;
            if let Some(existing) = table.get(token_key(id).as_str())? {
                let existing =
                    serde_json::from_slice::<ApiToken>(existing.value()).map_err(|e| {
                        redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                    })?;
                hash_table.remove(existing.token_hash.as_str())?;
            }
            table.remove(token_key(id).as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ── Devices ──

    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(DEVICE_TABLE)?;
        let mut devices = Vec::new();
        let iter = table.iter()?;
        for entry in iter {
            let entry = entry?;
            let val: &[u8] = entry.1.value();
            if let Ok(device) = serde_json::from_slice::<DeviceRecord>(val) {
                devices.push(device);
            }
        }
        Ok(devices)
    }

    pub fn get_device(&self, id: &str) -> Result<Option<DeviceRecord>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(DEVICE_TABLE)?;
        table
            .get(device_key(id).as_str())?
            .map(|value| serde_json::from_slice::<DeviceRecord>(value.value()))
            .transpose()
            .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }

    pub fn set_device(&self, device: &DeviceRecord) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(DEVICE_TABLE)?;
            let data = serde_json::to_vec(device).map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            table.insert(device_key(&device.id).as_str(), data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn delete_device(&self, id: &str) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(DEVICE_TABLE)?;
            table.remove(device_key(id).as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ── Login Attempts ──

    pub fn get_login_attempt(&self, ip: &str) -> Result<Option<LoginAttemptRecord>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(LOGIN_ATTEMPT_TABLE)?;
        table
            .get(ip)?
            .map(|value| serde_json::from_slice::<LoginAttemptRecord>(value.value()))
            .transpose()
            .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }

    pub fn set_login_attempt(
        &self,
        ip: &str,
        attempt: &LoginAttemptRecord,
    ) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(LOGIN_ATTEMPT_TABLE)?;
            let data = serde_json::to_vec(attempt).map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            table.insert(ip, data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn delete_login_attempt(&self, ip: &str) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(LOGIN_ATTEMPT_TABLE)?;
            table.remove(ip)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn cleanup_login_attempts(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        window_seconds: i64,
    ) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(LOGIN_ATTEMPT_TABLE)?;
            let mut expired = Vec::new();
            let iter = table.iter()?;
            for entry in iter {
                let entry = entry?;
                let key = entry.0.value().to_string();
                let parsed = serde_json::from_slice::<LoginAttemptRecord>(entry.1.value()).ok();
                let should_keep = parsed.as_ref().is_some_and(|record| {
                    let first_failure_at =
                        chrono::DateTime::parse_from_rfc3339(&record.first_failure_at)
                            .ok()
                            .map(|dt| dt.with_timezone(&chrono::Utc));
                    let blocked_until = record
                        .blocked_until
                        .as_deref()
                        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc));

                    if let Some(blocked_until) = blocked_until {
                        blocked_until > now
                    } else if let Some(first_failure_at) = first_failure_at {
                        now.signed_duration_since(first_failure_at).num_seconds() <= window_seconds
                    } else {
                        false
                    }
                });
                if !should_keep {
                    expired.push(key);
                }
            }
            for key in expired {
                table.remove(key.as_str())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    // ── Namespaces ──

    pub fn list_namespaces(&self) -> Result<Vec<String>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let deleted_table = read_txn.open_table(DELETED_NAMESPACE_TABLE)?;
        let deleted = deleted_table
            .iter()?
            .map(|entry| entry.map(|(key, _)| key.value().to_string()))
            .collect::<Result<HashSet<_>, _>>()?;

        let table = read_txn.open_table(METADATA_TABLE)?;
        let mut namespaces = Vec::new();
        let iter = table.iter()?;
        for entry in iter {
            let entry = entry?;
            let key: &str = entry.0.value();
            if let Some(ns) = key.strip_prefix("ns:") {
                if !deleted.contains(ns) {
                    namespaces.push(ns.to_string());
                }
            }
        }
        Ok(namespaces)
    }

    pub fn list_deleted_namespaces(
        &self,
    ) -> Result<Vec<(String, DeletedNamespaceRecord)>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(DELETED_NAMESPACE_TABLE)?;
        let mut deleted = Vec::new();
        let iter = table.iter()?;
        for entry in iter {
            let entry = entry?;
            let namespace = entry.0.value().to_string();
            let record = serde_json::from_slice::<DeletedNamespaceRecord>(entry.1.value())
                .map_err(|e| {
                    redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                })?;
            deleted.push((namespace, record));
        }
        Ok(deleted)
    }

    pub fn is_namespace_deleted(&self, namespace: &str) -> Result<bool, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(DELETED_NAMESPACE_TABLE)?;
        Ok(table.get(namespace)?.is_some())
    }

    pub fn soft_delete_namespace(
        &self,
        namespace: &str,
        deleted_at: &str,
    ) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(DELETED_NAMESPACE_TABLE)?;
            let record = DeletedNamespaceRecord {
                deleted_at: deleted_at.to_string(),
            };
            let data = serde_json::to_vec(&record).map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            table.insert(namespace, data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn restore_namespace(&self, namespace: &str) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(DELETED_NAMESPACE_TABLE)?;
            table.remove(namespace)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn hard_delete_namespace(&self, namespace: &str) -> Result<(), redb::Error> {
        let obj_prefix = format!("ns:{namespace}/obj:");

        let write_txn = self.inner.begin_write()?;
        {
            let mut meta_table = write_txn.open_table(METADATA_TABLE)?;
            meta_table.remove(metadata_key(namespace).as_str())?;

            let mut blob_table = write_txn.open_table(BLOB_TABLE)?;
            blob_table.remove(blob_key(namespace).as_str())?;

            let mut deleted_table = write_txn.open_table(DELETED_NAMESPACE_TABLE)?;
            deleted_table.remove(namespace)?;

            let mut usage_table = write_txn.open_table(NAMESPACE_USAGE_TABLE)?;
            usage_table.remove(namespace_usage_key(namespace).as_str())?;

            let mut object_meta_table = write_txn.open_table(OBJECT_META_TABLE)?;

            let obj_table = write_txn.open_table(OBJECT_TABLE)?;
            let mut to_delete = Vec::new();
            let iter = obj_table.iter()?;
            for entry in iter {
                let entry = entry?;
                let key: &str = entry.0.value();
                if key.starts_with(&obj_prefix) {
                    to_delete.push(key.to_string());
                }
            }
            drop(obj_table);

            let mut obj_table = write_txn.open_table(OBJECT_TABLE)?;
            for key in &to_delete {
                obj_table.remove(key.as_str())?;
                object_meta_table.remove(key.as_str())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn open_test_db() -> Database {
        let file = NamedTempFile::new().unwrap();
        Database::open(file.path().to_str().unwrap()).unwrap()
    }

    fn test_token(id: &str, device_id: Option<String>) -> ApiToken {
        ApiToken {
            id: id.to_string(),
            name: "test token".to_string(),
            token_hash: format!("hash-{id}"),
            encrypted_token: None,
            namespace_pattern: "*".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            created_at: chrono::Utc::now().to_rfc3339(),
            enabled: true,
            expires_at: None,
            rotated_at: None,
            disabled_at: None,
            last_used_at: None,
            device_id,
            read_count: 0,
            write_count: 0,
            failed_count: 0,
            last_namespace: None,
            last_permission: None,
            last_client_ip: None,
            last_client_version: None,
        }
    }

    fn test_device(id: &str, token_id: Option<String>) -> DeviceRecord {
        let now = chrono::Utc::now().to_rfc3339();
        DeviceRecord {
            id: id.to_string(),
            name: "work laptop".to_string(),
            namespace_pattern: Some("*".to_string()),
            token_id,
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
            last_seen_at: None,
            last_client_ip: None,
            last_client_version: None,
            notes: None,
        }
    }

    fn test_conflict(id: &str, occurred_at: &str) -> SyncConflictRecord {
        SyncConflictRecord {
            id: id.to_string(),
            occurred_at: occurred_at.to_string(),
            namespace: "demo".to_string(),
            operation: "blob".to_string(),
            object_path: None,
            device_id: Some("device-1".to_string()),
            requested_revision: Some("rev-local".to_string()),
            requested_etag: Some("etag-local".to_string()),
            remote_revision: Some("rev-remote".to_string()),
            remote_etag: Some("etag-remote".to_string()),
            message: "Remote snapshot changed before upload completed".to_string(),
        }
    }

    fn test_admin_user(username: &str) -> AdminUserRecord {
        let now = chrono::Utc::now().to_rfc3339();
        AdminUserRecord {
            username: username.to_string(),
            password_hash: "bcrypt-hash".to_string(),
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
        }
    }

    #[test]
    fn login_attempt_roundtrip() {
        let db = open_test_db();
        let attempt = LoginAttemptRecord {
            first_failure_at: chrono::Utc::now().to_rfc3339(),
            failures: 3,
            blocked_until: None,
        };
        db.set_login_attempt("127.0.0.1", &attempt).unwrap();
        let loaded = db.get_login_attempt("127.0.0.1").unwrap().unwrap();
        assert_eq!(loaded.failures, 3);
    }

    #[test]
    fn admin_user_roundtrip_and_delete() {
        let db = open_test_db();
        let user = test_admin_user("ops");

        db.set_admin_user(&user).unwrap();
        assert_eq!(db.list_admin_users().unwrap().len(), 1);
        assert_eq!(db.get_admin_user("ops").unwrap().unwrap().role, "admin");

        db.delete_admin_user("ops").unwrap();
        assert!(db.get_admin_user("ops").unwrap().is_none());
    }

    #[test]
    fn namespace_soft_delete_and_restore() {
        let db = open_test_db();
        let meta = serde_json::to_vec(&SyncMetadata::empty()).unwrap();
        db.set_metadata("demo", &meta).unwrap();

        db.soft_delete_namespace("demo", &chrono::Utc::now().to_rfc3339())
            .unwrap();
        assert!(db.is_namespace_deleted("demo").unwrap());
        assert!(db.list_namespaces().unwrap().is_empty());

        db.restore_namespace("demo").unwrap();
        assert!(!db.is_namespace_deleted("demo").unwrap());
        assert_eq!(db.list_namespaces().unwrap(), vec!["demo".to_string()]);
    }

    #[test]
    fn hard_delete_removes_soft_deleted_namespace_data() {
        let db = open_test_db();
        let meta = serde_json::to_vec(&SyncMetadata::empty()).unwrap();
        db.set_metadata("demo", &meta).unwrap();
        db.soft_delete_namespace("demo", &chrono::Utc::now().to_rfc3339())
            .unwrap();

        db.hard_delete_namespace("demo").unwrap();

        assert!(db.get_metadata("demo").unwrap().is_none());
        assert!(!db.is_namespace_deleted("demo").unwrap());
    }

    #[test]
    fn device_record_roundtrip_and_delete() {
        let db = open_test_db();
        let device = test_device("dev-1", None);

        db.set_device(&device).unwrap();
        assert_eq!(db.list_devices().unwrap().len(), 1);
        assert_eq!(db.get_device("dev-1").unwrap().unwrap().name, "work laptop");

        db.delete_device("dev-1").unwrap();
        assert!(db.get_device("dev-1").unwrap().is_none());
    }

    #[test]
    fn token_usage_updates_profile_and_linked_device() {
        let db = open_test_db();
        let token = test_token("tok-1", Some("dev-1".to_string()));
        let device = test_device("dev-1", Some("tok-1".to_string()));
        let observed_at = chrono::Utc::now().to_rfc3339();

        db.set_token(&token).unwrap();
        db.set_device(&device).unwrap();
        db.record_token_usage(
            "tok-1",
            "demo",
            "write",
            "127.0.0.1",
            Some("OxideTerm/1.0"),
            &observed_at,
        )
        .unwrap();
        db.record_token_failure("tok-1").unwrap();

        let token = db.get_token("tok-1").unwrap().unwrap();
        assert_eq!(token.write_count, 1);
        assert_eq!(token.failed_count, 1);
        assert_eq!(token.last_namespace.as_deref(), Some("demo"));
        assert_eq!(token.last_client_version.as_deref(), Some("OxideTerm/1.0"));

        let device = db.get_device("dev-1").unwrap().unwrap();
        assert_eq!(device.last_seen_at.as_deref(), Some(observed_at.as_str()));
        assert_eq!(device.last_client_ip.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn sync_conflicts_are_returned_newest_first() {
        let db = open_test_db();
        db.add_sync_conflict(&test_conflict("old", "2026-01-01T00:00:00Z"))
            .unwrap();
        db.add_sync_conflict(&test_conflict("new", "2026-01-02T00:00:00Z"))
            .unwrap();

        let conflicts = db.list_sync_conflicts(1).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].id, "new");
    }

    #[test]
    fn namespace_usage_tracks_growth_between_snapshots() {
        let db = open_test_db();
        let meta = StoredObjectMetadata {
            etag: "etag-1".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };

        db.put_object_if_matches("demo", "a.json", None, false, b"1234", &meta)
            .unwrap();
        let first = db
            .refresh_namespace_usage("demo", "2026-01-01T00:00:00Z", false)
            .unwrap();
        assert_eq!(first.total_bytes, 4);
        assert_eq!(first.growth_bytes, 0);

        db.put_object_if_matches("demo", "a.json", None, false, b"123456", &meta)
            .unwrap();
        let second = db
            .refresh_namespace_usage("demo", "2026-01-02T00:00:00Z", false)
            .unwrap();
        assert_eq!(second.total_bytes, 6);
        assert_eq!(second.growth_bytes, 2);
    }
}
