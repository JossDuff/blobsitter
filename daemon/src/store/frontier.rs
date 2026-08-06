//! The committed frontier: how far the store has durably ingested. One tiny JSON file,
//! replaced atomically (write tmp → fsync → rename → fsync dir), never modified in
//! place — after any crash the file is either the old frontier or the new one, whole.

use std::fs::{self, File};
use std::io::Write;
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
    #[serde(with = "hex_hashes")]
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
        let io = |e| StoreError::Io { path: path.into(), source: e };
        let tmp = path.with_extension("json.tmp");
        let mut f = File::create(&tmp).map_err(io)?;
        f.write_all(&serde_json::to_vec_pretty(self).expect("frontier always serializes"))
            .map_err(io)?;
        f.sync_all().map_err(io)?;
        fs::rename(&tmp, path).map_err(io)?;
        // fsync the directory so the rename itself survives a power cut.
        if let Some(dir) = path.parent() {
            File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
        }
        Ok(())
    }
}

/// Peaks as 0x-prefixed hex strings — the file is small and humans debug it.
mod hex_hashes {
    use blobsitter_reference::Hash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[Hash], s: S) -> Result<S::Ok, S::Error> {
        v.iter().map(|h| format!("0x{}", hex::encode(h))).collect::<Vec<_>>().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Hash>, D::Error> {
        let strings = Vec::<String>::deserialize(d)?;
        strings
            .into_iter()
            .map(|s| {
                let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(&s))
                    .map_err(serde::de::Error::custom)?;
                Hash::try_from(bytes.as_slice())
                    .map_err(|_| serde::de::Error::custom("peak is not 32 bytes"))
            })
            .collect()
    }
}
