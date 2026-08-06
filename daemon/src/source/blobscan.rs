//! The Blobscan-style archive adapter: per-blob lookup by versioned hash via
//! `GET /blobs/{versioned_hash}/data` (verified live against api.blobscan.com,
//! 2026-08-06: returns the 131072-byte blob as a JSON hex string). The archive's role
//! is repair and bootstrap — the blobs the p2p network no longer serves — so it sits
//! last in the near-head chain and may be the ONLY source for a provider joining
//! after the retention window. Donation-funded public infrastructure: treat it as a
//! verifiable fallback, never as the availability guarantee.

use blobsitter_reference::Hash;

use super::{beacon::parse_blob_hex, BlobContext, BlobSource, SourceError};
use crate::RawBlob;

pub struct BlobscanSource {
    /// API base, e.g. `https://api.blobscan.com`.
    base: String,
    client: reqwest::Client,
}

impl BlobscanSource {
    pub fn new(base: String) -> Self {
        Self { base, client: reqwest::Client::new() }
    }
}

#[async_trait::async_trait]
impl BlobSource for BlobscanSource {
    fn name(&self) -> &str {
        "blobscan"
    }

    async fn fetch(
        &self,
        _ctx: &BlobContext,
        wanted: &[Hash],
    ) -> Result<Vec<RawBlob>, SourceError> {
        let mut blobs = Vec::with_capacity(wanted.len());
        let mut errors = Vec::new();
        for vh in wanted {
            let url = format!(
                "{}/blobs/0x{}/data",
                self.base.trim_end_matches('/'),
                hex::encode(vh)
            );
            let result = async {
                let resp = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("{}", resp.status()));
                }
                // The body is a JSON string literal holding 0x-prefixed hex.
                let hex_string: String =
                    resp.json().await.map_err(|e| format!("bad response body: {e}"))?;
                parse_blob_hex(&hex_string)
            }
            .await;
            match result {
                Ok(blob) => blobs.push(blob),
                // Keep going: partial results are useful (the chain fills the rest).
                Err(e) => errors.push(format!("0x{}: {e}", hex::encode(vh))),
            }
        }
        if blobs.is_empty() && !errors.is_empty() {
            return Err(SourceError(format!("all lookups failed: {}", errors.join("; "))));
        }
        Ok(blobs)
    }
}
