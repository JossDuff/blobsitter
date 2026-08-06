//! Shared machinery for the daemon behavior tests: pattern-chunk declarations packed
//! into real canonical blobs (real KZG versioned hashes), configurable mock blob
//! sources, and an ingestor on a temp-dir store with a capturing alarm.

// Compiled once per test binary; not every binary uses every helper.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use blobsitter_daemon::alarm::CapturingAlarm;
use blobsitter_daemon::ingest::{DeclaredEvent, Ingestor};
use blobsitter_daemon::source::{BlobContext, BlobSource, SourceChain, SourceError};
use blobsitter_daemon::store::Store;
use blobsitter_daemon::verify;
use blobsitter_daemon::{Hash, RawBlob};
use blobsitter_reference::{blob, testvec, update_subtree_roots, Chunk};

/// The reference packing, boxed into the daemon's `RawBlob` shape.
pub fn pack_blobs(chunks: &[Chunk]) -> Vec<RawBlob> {
    blob::pack(chunks)
        .into_iter()
        .map(|raw| RawBlob::try_from(raw.into_boxed_slice()).unwrap())
        .collect()
}

/// A well-formed declaration of `m` pattern chunks on top of leaf count `n0`:
/// the event as the follower would deliver it, plus the real blobs carrying it.
pub fn declaration(nonce: u64, n0: u64, m: u64) -> (DeclaredEvent, Vec<RawBlob>) {
    let chunks: Vec<Chunk> = (n0..n0 + m).map(testvec::chunk).collect();
    let blobs = pack_blobs(&chunks);
    let event = DeclaredEvent {
        nonce,
        new_leaf_count: n0 + m,
        blob_versioned_hashes: blobs
            .iter()
            .map(|b| verify::versioned_hash(b).expect("canonical blob"))
            .collect(),
        new_subtree_peaks: update_subtree_roots(n0, &chunks),
        block_number: 1_000 + nonce,
        block_timestamp: 1_700_000_000 + 12 * nonce,
    };
    (event, blobs)
}

/// A mock source: serves whatever verified-or-not bytes it was loaded with, keyed by
/// the versioned hash it CLAIMS they answer (the ingest side never trusts the claim).
pub struct MockSource {
    pub name: String,
    blobs: HashMap<Hash, RawBlob>,
    fail_hard: bool,
    calls: Arc<AtomicUsize>,
}

impl MockSource {
    pub fn serving(name: &str, entries: impl IntoIterator<Item = (Hash, RawBlob)>) -> Self {
        Self {
            name: name.into(),
            blobs: entries.into_iter().collect(),
            fail_hard: false,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn empty(name: &str) -> Self {
        Self::serving(name, [])
    }

    /// A source that errors outright on every fetch (endpoint down).
    pub fn failing(name: &str) -> Self {
        let mut s = Self::serving(name, []);
        s.fail_hard = true;
        s
    }

    pub fn call_counter(&self) -> Arc<AtomicUsize> {
        self.calls.clone()
    }
}

#[async_trait::async_trait]
impl BlobSource for MockSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn fetch(&self, _ctx: &BlobContext, wanted: &[Hash]) -> Result<Vec<RawBlob>, SourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_hard {
            return Err(SourceError("simulated endpoint failure".into()));
        }
        Ok(wanted.iter().filter_map(|vh| self.blobs.get(vh).cloned()).collect())
    }
}

/// Corrupt a blob in a way that keeps it a valid field-element array (low byte flip),
/// so it survives parsing and dies only by hash identity.
pub fn corrupted(blob: &RawBlob) -> RawBlob {
    let mut c = blob.clone();
    c[31] ^= 0x01;
    c
}

pub struct Rig {
    pub ingestor: Ingestor,
    pub alarm: Arc<CapturingAlarm>,
}

pub fn rig(dir: &Path, sources: Vec<Box<dyn BlobSource>>) -> Rig {
    let alarm = Arc::new(CapturingAlarm::new());
    let store = Store::open(dir).expect("store opens");
    let ingestor = Ingestor::new(store, SourceChain::new(sources), alarm.clone());
    Rig { ingestor, alarm }
}

/// The common happy path: a rig whose single source serves the declaration's blobs.
pub fn rig_serving(dir: &Path, declarations: &[(DeclaredEvent, Vec<RawBlob>)]) -> Rig {
    let entries = declarations.iter().flat_map(|(e, blobs)| {
        e.blob_versioned_hashes.iter().copied().zip(blobs.iter().cloned())
    });
    rig(dir, vec![Box::new(MockSource::serving("primary", entries))])
}
