//! The flat chunk file: chunk `i` lives at byte offset `31·i`, nothing else in the
//! file. Append-only in normal operation; the only truncation is crash recovery
//! discarding a tail that was never committed.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use blobsitter_reference::Chunk;

use super::StoreError;

pub const CHUNK_BYTES: u64 = 31;

pub struct ChunkFile {
    file: File,
    path: PathBuf,
}

impl ChunkFile {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| StoreError::Io { path: path.into(), source: e })?;
        Ok(Self { file, path: path.into() })
    }

    fn io(&self, source: std::io::Error) -> StoreError {
        StoreError::Io { path: self.path.clone(), source }
    }

    /// File length in bytes. Whole chunks are `len / 31`; any remainder is a torn
    /// trailing fragment that recovery trims away.
    pub fn len_bytes(&self) -> Result<u64, StoreError> {
        Ok(self.file.metadata().map_err(|e| self.io(e))?.len())
    }

    /// Crash recovery: cut the file back to exactly `leaf_count` chunks.
    pub fn truncate_to(&mut self, leaf_count: u64) -> Result<(), StoreError> {
        self.file.set_len(leaf_count * CHUNK_BYTES).map_err(|e| self.io(e))?;
        self.file.sync_data().map_err(|e| self.io(e))?;
        Ok(())
    }

    /// Write `chunks` starting at chunk index `first`, then fsync. The caller (the
    /// store) always passes the committed frontier as `first`, so repeating the same
    /// append after a crash lands on the same offsets — idempotence by positioned
    /// writes rather than bookkeeping.
    pub fn append(&mut self, first: u64, chunks: &[Chunk]) -> Result<(), StoreError> {
        // One contiguous buffer: a declaration is at most a few blobs (~half a MiB),
        // and a single write keeps the torn-write window as small as the OS allows.
        let mut buf = Vec::with_capacity(chunks.len() * CHUNK_BYTES as usize);
        for c in chunks {
            buf.extend_from_slice(c);
        }
        self.file.write_all_at(&buf, first * CHUNK_BYTES).map_err(|e| self.io(e))?;
        self.file.sync_data().map_err(|e| self.io(e))?;
        Ok(())
    }

    pub fn read(&self, index: u64) -> Result<Chunk, StoreError> {
        let mut chunk = [0u8; 31];
        self.file.read_exact_at(&mut chunk, index * CHUNK_BYTES).map_err(|e| self.io(e))?;
        Ok(chunk)
    }

    /// A second, independent handle onto the same file (positioned reads only), for
    /// readers that outlive a borrow of the store.
    pub fn try_clone_handle(&self) -> Result<(File, PathBuf), StoreError> {
        let file = self.file.try_clone().map_err(|e| self.io(e))?;
        Ok((file, self.path.clone()))
    }
}
