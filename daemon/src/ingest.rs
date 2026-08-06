//! The ingest pipeline: finalized `Declared` events in, committed store state out.
//!
//! Ordering discipline: declarations are processed exactly once, in nonce order. An
//! already-committed nonce is a harmless redelivery (restarts rescan old blocks); a
//! FUTURE nonce, or a declaration whose blobs cannot be obtained, halts ingest at the
//! gap and alarms — the daemon never skips ahead, because a hole in the chunk stream
//! would silently poison every later inclusion proof and challenge response.
//!
//! Everything is verified in memory before anything is written: blob identity against
//! the declared versioned hashes (in the source chain), then the recomputed subtree
//! roots against the event's — proving the bytes in hand are bit-for-bit the bytes
//! the contract merged into its MMR. Only then does the store commit.

use std::sync::Arc;

use blobsitter_reference::update_subtree_roots;

use crate::alarm::{AlarmSink, Severity};
use crate::source::{BlobContext, SourceChain};
use crate::store::{Store, StoreError};
use crate::verify::{self, VerifyError};
use crate::Hash;

/// A finalized `Declared` event plus where its blobs live — everything ingest needs,
/// already detached from any particular chain client.
#[derive(Debug, Clone)]
pub struct DeclaredEvent {
    pub nonce: u64,
    pub new_leaf_count: u64,
    pub blob_versioned_hashes: Vec<Hash>,
    pub new_subtree_peaks: Vec<Hash>,
    pub block_number: u64,
    pub block_timestamp: u64,
}

/// Why ingest stopped. Every variant except the store errors means the stream is
/// blocked at this declaration; the caller retries the same event after the operator
/// (or a healthier source) resolves the condition.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("declaration nonce {got} arrived but the store owes nonce {expected}; \
             the event stream has a gap")]
    NonceGap { expected: u64, got: u64 },
    #[error("could not obtain blobs for declaration {nonce}: {source}")]
    BlobsUnavailable {
        nonce: u64,
        #[source]
        source: crate::source::SourcesExhausted,
    },
    #[error("declaration {nonce} contradicts the chain: {detail}")]
    ProtocolContradiction { nonce: u64, detail: String },
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub struct Ingestor {
    store: Store,
    sources: SourceChain,
    alarm: Arc<dyn AlarmSink>,
}

impl Ingestor {
    pub fn new(store: Store, sources: SourceChain, alarm: Arc<dyn AlarmSink>) -> Self {
        Self { store, sources, alarm }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Ingest one finalized declaration. `Ok(false)` = redelivery of an
    /// already-committed nonce, ignored; `Ok(true)` = committed.
    pub async fn ingest(&mut self, event: &DeclaredEvent) -> Result<bool, IngestError> {
        let expected = self.store.frontier().nonce;
        if event.nonce < expected {
            return Ok(false);
        }
        if event.nonce > expected {
            self.critical(format!(
                "HALT: declaration nonce {} observed but nonce {} was never ingested — \
                 refusing to skip (a hole would break every later proof)",
                event.nonce, expected
            ));
            return Err(IngestError::NonceGap { expected, got: event.nonce });
        }

        let n0 = self.store.frontier().leaf_count;
        let m = event.new_leaf_count.checked_sub(n0).filter(|m| *m >= 1).ok_or_else(|| {
            self.contradiction(event.nonce, format!(
                "newLeafCount {} does not extend committed leafCount {n0}",
                event.new_leaf_count
            ))
        })?;

        // Fetch and verify (identity-by-hash) every blob before touching the store.
        let ctx = BlobContext {
            block_number: event.block_number,
            block_timestamp: event.block_timestamp,
        };
        let blobs = self
            .sources
            .acquire(&ctx, &event.blob_versioned_hashes, self.alarm.as_ref())
            .await
            .map_err(|source| {
                self.critical(format!(
                    "HALT: blobs for declaration {} (block {}) unavailable from every \
                     configured source ({} of {} missing) — ingest is stopped until a \
                     source can serve them",
                    event.nonce, event.block_number, source.missing, source.wanted
                ));
                IngestError::BlobsUnavailable { nonce: event.nonce, source }
            })?;
        // Lookup, not removal: a declaration may legally repeat a versioned hash
        // (identical blob content twice), and one verified blob serves every copy.
        let ordered: Vec<_> = event
            .blob_versioned_hashes
            .iter()
            .map(|vh| blobs.get(vh).cloned().expect("acquire returned complete or errored"))
            .collect();

        // Unpack chunks and prove they are THE committed bytes: the subtree roots
        // recomputed from them must equal the ones the contract merged.
        let chunks = verify::chunks_from_blobs(&ordered, m)
            .map_err(|e: VerifyError| self.contradiction(event.nonce, e.to_string()))?;
        let recomputed = update_subtree_roots(n0, &chunks);
        if recomputed != event.new_subtree_peaks {
            return Err(self.contradiction(
                event.nonce,
                "subtree roots recomputed from verified blob bytes do not match the \
                 declared newSubtreePeaks"
                    .into(),
            ));
        }

        let mut mmr = self.store.mmr();
        mmr.apply_update(&event.new_subtree_peaks, m)
            .map_err(|e| self.contradiction(event.nonce, e.into()))?;
        debug_assert_eq!(mmr.leaf_count(), event.new_leaf_count);

        self.store.commit_declaration(event.nonce + 1, &chunks, &mmr)?;
        tracing::info!(
            nonce = event.nonce,
            leaf_count = event.new_leaf_count,
            blobs = ordered.len(),
            "declaration ingested"
        );
        Ok(true)
    }

    fn critical(&self, msg: String) {
        self.alarm.alarm(Severity::Critical, &msg);
    }

    /// A declaration that the chain accepted but whose data doesn't add up is not bad
    /// input to skip — it means our view of the protocol disagrees with L1, which is
    /// the loudest possible condition.
    fn contradiction(&self, nonce: u64, detail: String) -> IngestError {
        self.critical(format!(
            "HALT: declaration {nonce} contradicts on-chain state: {detail}"
        ));
        IngestError::ProtocolContradiction { nonce, detail }
    }
}
