//! Blob acquisition: an ordered chain of untrusted sources behind one trait. Near-head
//! ingest walks configured beacon-API endpoints (self-hosted node, hosted provider, or
//! a beacon-shaped archiver — one adapter covers all three), then archive adapters as
//! last resort; a provider bootstrapping after the retention window may run on archive
//! sources alone.
//!
//! Sources return CANDIDATE bytes only. Identification and admission both happen in
//! the acquisition loop by recomputing each candidate's versioned hash — a source
//! cannot mislabel a blob any more than it can corrupt one, and unverified bytes have
//! no path to the caller.

pub mod beacon;
pub mod blobscan;

use std::collections::HashMap;

use blobsitter_reference::Hash;

use crate::alarm::{AlarmSink, Severity};
use crate::verify;
use crate::RawBlob;

/// Where the wanted blobs live on chain — enough for any adapter style: beacon APIs
/// locate by slot (derived from the execution timestamp), archives by versioned hash.
#[derive(Debug, Clone, Copy)]
pub struct BlobContext {
    pub block_number: u64,
    pub block_timestamp: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SourceError(pub String);

#[async_trait::async_trait]
pub trait BlobSource: Send + Sync {
    /// Human-readable name for alarms and logs.
    fn name(&self) -> &str;

    /// Return whatever candidates this source has for `wanted` (any subset, any
    /// order, mislabeled or corrupt allowed — the caller verifies everything).
    async fn fetch(
        &self,
        ctx: &BlobContext,
        wanted: &[Hash],
    ) -> Result<Vec<RawBlob>, SourceError>;
}

/// Every blob obtained, or a hard error — there is no partial success: a declaration
/// missing even one blob cannot be ingested (a hole would break every later proof).
#[derive(Debug, thiserror::Error)]
#[error("blob sources exhausted; still missing {missing} of {wanted} blobs")]
pub struct SourcesExhausted {
    pub wanted: usize,
    pub missing: usize,
}

/// The ordered fallback chain. Walks sources in configured order, verifying every
/// candidate, until all wanted blobs are in hand or the chain is exhausted.
pub struct SourceChain {
    sources: Vec<Box<dyn BlobSource>>,
}

impl SourceChain {
    pub fn new(sources: Vec<Box<dyn BlobSource>>) -> Self {
        Self { sources }
    }

    /// Acquire verified blobs for `wanted`, keyed by versioned hash. Duplicate wanted
    /// hashes are fine (one verified blob serves all copies). Warning alarms mark
    /// sources that failed or fell short while a later source saved the declaration;
    /// exhaustion is the CALLER's alarm to raise, with ingest context attached.
    pub async fn acquire(
        &self,
        ctx: &BlobContext,
        wanted: &[Hash],
        alarm: &dyn AlarmSink,
    ) -> Result<HashMap<Hash, RawBlob>, SourcesExhausted> {
        let mut have: HashMap<Hash, RawBlob> = HashMap::new();
        for (i, source) in self.sources.iter().enumerate() {
            let missing: Vec<Hash> =
                wanted.iter().filter(|vh| !have.contains_key(*vh)).copied().collect();
            if missing.is_empty() {
                break;
            }
            if i > 0 {
                alarm.alarm(
                    Severity::Warning,
                    &format!(
                        "falling back to blob source '{}' for block {} ({} blob(s) still missing)",
                        source.name(),
                        ctx.block_number,
                        missing.len()
                    ),
                );
            }
            let candidates = match source.fetch(ctx, &missing).await {
                Ok(c) => c,
                Err(e) => {
                    alarm.alarm(
                        Severity::Warning,
                        &format!("blob source '{}' failed for block {}: {e}", source.name(), ctx.block_number),
                    );
                    continue;
                }
            };
            for candidate in candidates {
                // Admission = identification: a candidate is only ever stored under
                // the versioned hash recomputed from its own bytes.
                match verify::versioned_hash(&candidate) {
                    Ok(vh) if missing.contains(&vh) => {
                        have.insert(vh, candidate);
                    }
                    Ok(_) => {} // not one we asked for; harmless
                    Err(e) => alarm.alarm(
                        Severity::Warning,
                        &format!(
                            "blob source '{}' returned an invalid blob for block {}: {e}",
                            source.name(),
                            ctx.block_number
                        ),
                    ),
                }
            }
        }
        let missing = wanted.iter().filter(|vh| !have.contains_key(*vh)).count();
        if missing > 0 {
            return Err(SourcesExhausted { wanted: wanted.len(), missing });
        }
        Ok(have)
    }
}
