// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use redb::{Database as RedbDatabase, ReadableTable, TableDefinition};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use crate::config::{
    ApiToken, DeletedNamespaceRecord, LoginAttemptRecord, StoredObjectMetadata, SyncMetadata,
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
        Ok(table
            .get(object_meta_key(namespace, path).as_str())?
            .map(|v| serde_json::from_slice::<StoredObjectMetadata>(v.value()))
            .transpose()
            .map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?)
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

    pub fn count_objects(&self, namespace: &str) -> Result<u64, redb::Error> {
        let prefix = format!("ns:{namespace}/obj:");
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(OBJECT_TABLE)?;
        let mut count = 0u64;
        let iter = table.range(prefix.as_str()..)?;
        for entry in iter {
            let entry = entry?;
            let key: &str = entry.0.value();
            if key.starts_with(&prefix) {
                count += 1;
            } else {
                break;
            }
        }
        Ok(count)
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
        Ok(token_table
            .get(token_key(id).as_str())?
            .map(|value| serde_json::from_slice::<ApiToken>(value.value()))
            .transpose()
            .map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?)
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

    pub fn touch_token_last_used(&self, id: &str, last_used_at: &str) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(TOKEN_TABLE)?;
            let existing_data = table
                .get(token_key(id).as_str())?
                .map(|existing| existing.value().to_vec());
            let Some(existing_data) = existing_data else {
                return Ok(());
            };
            let mut token = serde_json::from_slice::<ApiToken>(&existing_data).map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            token.last_used_at = Some(last_used_at.to_string());
            let data = serde_json::to_vec(&token).map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?;
            table.insert(token_key(id).as_str(), data.as_slice())?;
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

    // ── Login Attempts ──

    pub fn get_login_attempt(&self, ip: &str) -> Result<Option<LoginAttemptRecord>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(LOGIN_ATTEMPT_TABLE)?;
        Ok(table
            .get(ip)?
            .map(|value| serde_json::from_slice::<LoginAttemptRecord>(value.value()))
            .transpose()
            .map_err(|e| {
                redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?)
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
}
