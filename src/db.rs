// Copyright (C) 2026 AnalyseDeCircuit. Licensed under AGPL-3.0-or-later.

use redb::{Database as RedbDatabase, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

use crate::config::ApiToken;

// Table definitions
const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const BLOB_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
const OBJECT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("objects");
const TOKEN_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("tokens");

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

/// Key format for tokens: "tok:{id}"
fn token_key(id: &str) -> String {
    format!("tok:{id}")
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
            let _ = write_txn.open_table(TOKEN_TABLE)?;
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

    pub fn set_blob(&self, namespace: &str, data: &[u8]) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(BLOB_TABLE)?;
            table.insert(blob_key(namespace).as_str(), data)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Atomically write blob + metadata in a single transaction.
    /// Prevents TOCTOU race between etag check and data write.
    pub fn put_blob_with_metadata(
        &self,
        namespace: &str,
        blob: &[u8],
        metadata: &[u8],
    ) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut blob_table = write_txn.open_table(BLOB_TABLE)?;
            blob_table.insert(blob_key(namespace).as_str(), blob)?;
            let mut meta_table = write_txn.open_table(METADATA_TABLE)?;
            meta_table.insert(metadata_key(namespace).as_str(), metadata)?;
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

    pub fn set_object(
        &self,
        namespace: &str,
        path: &str,
        data: &[u8],
    ) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(OBJECT_TABLE)?;
            table.insert(object_key(namespace, path).as_str(), data)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn delete_object(&self, namespace: &str, path: &str) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(OBJECT_TABLE)?;
            table.remove(object_key(namespace, path).as_str())?;
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

    pub fn set_token(&self, token: &ApiToken) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(TOKEN_TABLE)?;
            let data = serde_json::to_vec(token)
                .map_err(|e| redb::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            table.insert(token_key(&token.id).as_str(), data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn delete_token(&self, id: &str) -> Result<(), redb::Error> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(TOKEN_TABLE)?;
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
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}
