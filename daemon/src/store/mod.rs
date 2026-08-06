//! The canonical local store: a flat file with chunk `i` at byte offset `31·i`, plus a
//! committed frontier. Custody proving needs random reads of thousands of arbitrary
//! chunks and full sequential hash passes, which is exactly what a flat file is good at.
//!
//! Crash-safety protocol (the whole design in four lines):
//!
//! 1. New chunk bytes are appended to `chunks.dat` and fsynced.
//! 2. Only then is the frontier file atomically replaced (tmp + fsync + rename).
//! 3. Reads are bounded by the committed frontier, so a torn append past it is
//!    invisible — no partial blob can ever be observed as store content.
//! 4. On open, anything past `31·leafCount` is truncated away and ingest resumes from
//!    the committed nonce; re-ingesting a declaration is therefore idempotent.

mod chunks;
mod frontier;

pub use chunks::ChunkFile;
pub use frontier::Frontier;

use std::path::{Path, PathBuf};

use blobsitter_reference::{Chunk, Mmr};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("frontier file is corrupt: {0}")]
    CorruptFrontier(String),
    #[error(
        "chunk file holds {found} committed chunks but the frontier commits {committed}; \
         committed data is missing — refusing to run on a damaged store"
    )]
    MissingCommittedData { found: u64, committed: u64 },
    #[error(
        "no frontier file, but the chunk file holds {bytes} bytes; a lost frontier next \
         to real data is damage (treating it as a fresh store would truncate everything) \
         — restore frontier.json or move the data aside to start fresh"
    )]
    OrphanedChunkData { bytes: u64 },
    #[error("another daemon instance holds the store at {0} (directory lock is taken)")]
    Locked(PathBuf),
    #[error("chunk index {index} is at or past the committed frontier {leaf_count}")]
    OutOfBounds { index: u64, leaf_count: u64 },
    #[error("frontier state is internally inconsistent: {0}")]
    InconsistentFrontier(&'static str),
}

/// The store a daemon owns: chunk file + committed frontier, opened from a data
/// directory. All mutation goes through [`Store::commit_declaration`], which enforces
/// the crash-safety protocol; there is no other write path.
pub struct Store {
    chunks: ChunkFile,
    frontier_path: PathBuf,
    frontier: Frontier,
    /// Held for its flock: released only when the process (or this Store) goes away.
    _lock: std::fs::File,
}

impl Store {
    /// Open (or initialize) the store in `dir`. Recovers from a torn append by
    /// truncating the chunk file back to the committed frontier; refuses to open if
    /// committed data is missing or the frontier is missing beside real data (both
    /// are damage, not crash artifacts), or if another daemon holds the store.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir).map_err(|e| StoreError::Io { path: dir.into(), source: e })?;

        // One daemon per store, enforced with an advisory lock: a second opener's
        // recovery truncation would amputate a first daemon's in-flight append and
        // turn a benign restart race into committed-data loss.
        let lock = std::fs::File::create(dir.join(".lock"))
            .map_err(|e| StoreError::Io { path: dir.join(".lock"), source: e })?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| StoreError::Locked(dir.into()))?;

        let frontier_path = dir.join("frontier.json");
        let loaded = Frontier::load(&frontier_path)?;
        let fresh = loaded.is_none();
        let frontier = loaded.unwrap_or_default();
        // Rehydrating proves the persisted peak list matches the leaf count.
        Mmr::from_state(frontier.leaf_count, &frontier.peaks)
            .map_err(StoreError::InconsistentFrontier)?;

        let mut chunks = ChunkFile::open(&dir.join("chunks.dat"))?;
        let committed = frontier.leaf_count;
        let found_bytes = chunks.len_bytes()?;
        if fresh && found_bytes > 0 {
            // No frontier but a populated chunk file: a lost frontier, not a fresh
            // store. Defaulting to leaf count 0 here would truncate the entire
            // dataset — possibly past blob retention, unrecoverable.
            return Err(StoreError::OrphanedChunkData { bytes: found_bytes });
        }
        if found_bytes / 31 < committed {
            return Err(StoreError::MissingCommittedData {
                found: found_bytes / 31,
                committed,
            });
        }
        if found_bytes > committed * 31 {
            // A crash between the chunk append and the frontier commit; the tail
            // (whole chunks or a torn fragment) was never committed, so discard it
            // and let ingest redo the declaration.
            chunks.truncate_to(committed)?;
        }
        Ok(Self { chunks, frontier_path, frontier, _lock: lock })
    }

    pub fn frontier(&self) -> &Frontier {
        &self.frontier
    }

    /// The verifier-state MMR at the committed frontier.
    pub fn mmr(&self) -> Mmr {
        Mmr::from_state(self.frontier.leaf_count, &self.frontier.peaks)
            .expect("frontier was validated at open and on every commit")
    }

    /// Commit one fully verified declaration: append its chunks, fsync, then publish
    /// the new frontier atomically. `mmr` must already have the update applied (the
    /// ingest pipeline does that as part of verification).
    pub fn commit_declaration(
        &mut self,
        next_nonce: u64,
        chunks: &[Chunk],
        mmr: &Mmr,
    ) -> Result<(), StoreError> {
        debug_assert_eq!(
            mmr.leaf_count(),
            self.frontier.leaf_count + chunks.len() as u64,
            "commit must advance exactly by the declaration's chunks"
        );
        self.chunks.append(self.frontier.leaf_count, chunks)?;
        let next = Frontier {
            nonce: next_nonce,
            leaf_count: mmr.leaf_count(),
            peaks: mmr.peaks(),
        };
        next.store_atomic(&self.frontier_path)?;
        self.frontier = next;
        Ok(())
    }

    /// Read one committed chunk. Bounded by the frontier: bytes past it (torn appends,
    /// in-flight declarations) do not exist as far as readers are concerned.
    pub fn chunk(&self, index: u64) -> Result<Chunk, StoreError> {
        if index >= self.frontier.leaf_count {
            return Err(StoreError::OutOfBounds { index, leaf_count: self.frontier.leaf_count });
        }
        self.chunks.read(index)
    }
}
