//! The committed frontier: how far the store has durably ingested. One tiny JSON file,
//! replaced atomically (write tmp → fsync → rename → fsync dir), never modified in
//! place — after any crash the file is either the old frontier or the new one, whole.

use std::fs;
use std::path::Path;

use blobsitter_reference::Hash;
use serde::{Deserialize, Serialize};

use super::StoreError;

/// Everything the daemon must remember between restarts to keep ingesting correctly:
/// the next declaration nonce it owes, and the MMR state over what it holds. The peak
/// list is persisted purely to spare an O(n) rehash of the chunk file at startup — it
/// is always recomputable from the file, and conformance tests do exactly that.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Frontier {
    /// Next declaration nonce to ingest == number of declarations committed.
    pub nonce: u64,
    /// Committed chunk count; the chunk file's authoritative length.
    pub leaf_count: u64,
    /// MMR peaks at `leaf_count`, canonical (descending-height) order.
    #[serde(with = "crate::persist::serde_hex::hashes")]
    pub peaks: Vec<Hash>,
}

impl Frontier {
    /// Load the frontier, `None` if it has never been written (fresh store).
    pub fn load(path: &Path) -> Result<Option<Self>, StoreError> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io { path: path.into(), source: e }),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| StoreError::CorruptFrontier(e.to_string()))
    }

    /// Publish this frontier durably. The rename is the commit point.
    pub fn store_atomic(&self, path: &Path) -> Result<(), StoreError> {
        crate::persist::write_atomic(
            path,
            &serde_json::to_vec_pretty(self).expect("frontier always serializes"),
        )
        .map_err(|e| StoreError::Io { path: path.into(), source: e })
    }
}

