//! Shared persistence primitives for the daemon's small state files (the store
//! frontier, the challenge ledger): ONE atomic-write routine and ONE hash wire
//! format, so every file gets the same durability and the same encoding.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

/// Durably replace `path` with `bytes`: write a temp file, fsync it, rename over
/// the target, fsync the parent directory (the rename itself must survive a power
/// cut). After any crash the file is either the old content or the new — whole.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// 32-byte hashes as 0x-prefixed hex in JSON — the state files are small and humans
/// debug them. `hash` for a single value, `hashes` for a list.
pub mod serde_hex {
    use blobsitter_reference::Hash;
    use serde::{Deserialize, Deserializer, Serializer};

    fn decode_one<E: serde::de::Error>(s: &str) -> Result<Hash, E> {
        let bytes =
            hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(serde::de::Error::custom)?;
        Hash::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("hash is not 32 bytes"))
    }

    pub mod hash {
        use super::*;

        pub fn serialize<S: Serializer>(h: &Hash, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&format!("0x{}", hex::encode(h)))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Hash, D::Error> {
            super::decode_one(&String::deserialize(d)?)
        }
    }

    pub mod hashes {
        use super::*;
        use serde::Serialize;

        pub fn serialize<S: Serializer>(v: &[Hash], s: S) -> Result<S::Ok, S::Error> {
            v.iter().map(|h| format!("0x{}", hex::encode(h))).collect::<Vec<_>>().serialize(s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Hash>, D::Error> {
            Vec::<String>::deserialize(d)?.iter().map(|s| super::decode_one(s)).collect()
        }
    }
}
