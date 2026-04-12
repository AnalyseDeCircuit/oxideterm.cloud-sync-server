// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use redb::{Database as RedbDatabase, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

use crate::config::{ApiToken, StoredObjectMetadata, SyncMetadata};

// Table definitions
const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const BLOB_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
const OBJECT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("objects");
const OBJECT_META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("object_metadata");
const TOKEN_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("tokens");
const TOKEN_HASH_TABLE: TableDefinition<&str, &str> = TableDefinition::new("token_hashes");

/// Key format for metadata: "ns:{namespace}"
fn metadata_key(namespace: &str) -> String {
    format!("ns:{namespace}")
}

/// Key format for blobs: "ns:{namespace}"
fn blob_key(namespace: &str) -> String {
    format!("ns:{namespace}")
}

/// Key format for objects: "ns:{namespace}/obj:{path}"
fn object_key(namespace: &str, path: &str) -> String {
    format!("ns:{namespace}/obj:{path}")
}

/// Key format for object metadata: "ns:{namespace}/obj:{path}"
fn object_meta_key(namespace: &str, path: &str) -> String {
    object_key(namespace, path)
}

/// Key format for tokens: "tok:{id}"
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

        // Initialize tables
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(METADATA_TABLE)?;
            let _ = write_txn.open_table(BLOB_TABLE)?;
            let _ = write_txn.open_table(OBJECT_TABLE)?;
            let _ = write_txn.open_table(OBJECT_META_TABLE)?;
            let _ = write_txn.open_table(TOKEN_TABLE)?;
            let _ = write_txn.open_table(TOKEN_HASH_TABLE)?;
        }
        write_txn.commit()?;

        Ok(Self {
            inner: Arc::new(db),
        })
    }

    // ── Metadata ──

    pub fn get_metadata(&self, namespace: &str) -> Result<Option<Vec<u8>>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(METADATA_TABLE)?;
        Ok(table.get(metadata_key(namespace).as_str())?.map(|v| v.value().to_vec()))
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
        Ok(table.get(blob_key(namespace).as_str())?.map(|v| v.value().to_vec()))
    }

    /// Compare-and-set blob + metadata in a single transaction.
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
                        remote_revision: current_meta.as_ref().and_then(|meta| meta.revision.clone()),
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
        Ok(table.get(object_key(namespace, path).as_str())?.map(|v| v.value().to_vec()))
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
            .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?)
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

    /// Count objects in a namespace by prefix scan.
    pub fn count_objects(&self, namespace: &str) -> Result<u64, redb::Error> {
        let prefix = format!("ns:{namespace}/obj:");
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(OBJECT_TABLE)?;
        let mut count = 0u64;
        // Use range scan starting from the prefix to skip unrelated entries
        let iter = table.range(prefix.as_str()..)?;
        for entry in iter {
            let entry = entry?;
            let key: &str = entry.0.value();
            if key.starts_with(&prefix) {
                count += 1;
            } else {
                break; // Past our prefix range
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

        let token_table = read_txn.open_table(TOKEN_TABLE)?;
        Ok(token_table
            .get(token_key(token_id.value()).as_str())?
            .map(|value| serde_json::from_slice::<ApiToken>(value.value()))
            .transpose()
            .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?)
    }

    pub fn set_token(&self, token: &ApiToken) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(TOKEN_TABLE)?;
            let mut hash_table = write_txn.open_table(TOKEN_HASH_TABLE)?;

            if let Some(existing) = table.get(token_key(&token.id).as_str())? {
                let existing = serde_json::from_slice::<ApiToken>(existing.value())
                    .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
                hash_table.remove(existing.token_hash.as_str())?;
            }

            let data = serde_json::to_vec(token)
                .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
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
            let mut token = serde_json::from_slice::<ApiToken>(&existing_data)
                .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            token.last_used_at = Some(last_used_at.to_string());
            let data = serde_json::to_vec(&token)
                .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
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
                let existing = serde_json::from_slice::<ApiToken>(existing.value())
                    .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
                hash_table.remove(existing.token_hash.as_str())?;
            }
            table.remove(token_key(id).as_str())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all namespaces by scanning metadata keys.
    pub fn list_namespaces(&self) -> Result<Vec<String>, redb::Error> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(METADATA_TABLE)?;
        let mut namespaces = Vec::new();
        let iter = table.iter()?;
        for entry in iter {
            let entry = entry?;
            let key: &str = entry.0.value();
            if let Some(ns) = key.strip_prefix("ns:") {
                namespaces.push(ns.to_string());
            }
        }
        Ok(namespaces)
    }

    /// Delete an entire namespace: metadata + blob + all objects.
    pub fn delete_namespace(&self, namespace: &str) -> Result<(), redb::Error> {
        let obj_prefix = format!("ns:{namespace}/obj:");

        let write_txn = self.inner.begin_write()?;
        {
            let mut meta_table = write_txn.open_table(METADATA_TABLE)?;
            meta_table.remove(metadata_key(namespace).as_str())?;

            let mut blob_table = write_txn.open_table(BLOB_TABLE)?;
            blob_table.remove(blob_key(namespace).as_str())?;

            let mut object_meta_table = write_txn.open_table(OBJECT_META_TABLE)?;

            // Collect object keys to delete (can't mutate while iterating)
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
