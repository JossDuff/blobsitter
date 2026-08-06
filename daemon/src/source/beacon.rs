//! The beacon-API adapter: `GET /eth/v1/beacon/blobs/{block_id}` (beacon-APIs v4, the
//! post-Fusaka replacement for the deprecated `blob_sidecars`), filtered by the
//! versioned hashes we want. One adapter, N endpoints in priority order — a
//! self-hosted node (must be at least a semi-supernode to serve full blobs
//! post-PeerDAS), hosted providers, and any beacon-shaped archiver all look identical
//! from here.

use blobsitter_reference::Hash;
use serde::Deserialize;

use super::{BlobContext, BlobSource, SourceError};
use crate::{RawBlob, BLOB_BYTES};

pub struct BeaconSource {
    /// Endpoints tried in order within this adapter; the first that answers for the
    /// block wins. (Cross-ADAPTER fallback is the source chain's job.)
    endpoints: Vec<String>,
    /// Beacon genesis time — blob queries go by slot, and an execution block's slot
    /// is exactly `(timestamp − genesis_time) / seconds_per_slot`.
    genesis_time: u64,
    seconds_per_slot: u64,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct BlobsResponse {
    data: Vec<String>,
}

impl BeaconSource {
    pub fn new(endpoints: Vec<String>, genesis_time: u64, seconds_per_slot: u64) -> Self {
        Self { endpoints, genesis_time, seconds_per_slot, client: reqwest::Client::new() }
    }

    fn slot_for(&self, block_timestamp: u64) -> Result<u64, SourceError> {
        let elapsed = block_timestamp.checked_sub(self.genesis_time).ok_or_else(|| {
            SourceError(format!(
                "beacon genesis_time {} is after block timestamp {block_timestamp} — the \
                 beacon config points at a different chain than the execution RPC",
                self.genesis_time
            ))
        })?;
        // seconds_per_slot is validated nonzero at config load; max(1) keeps a
        // hand-constructed source from dividing by zero anyway.
        Ok(elapsed / self.seconds_per_slot.max(1))
    }
}

#[async_trait::async_trait]
impl BlobSource for BeaconSource {
    fn name(&self) -> &str {
        "beacon"
    }

    async fn fetch(
        &self,
        ctx: &BlobContext,
        wanted: &[Hash],
    ) -> Result<Vec<RawBlob>, SourceError> {
        let slot = self.slot_for(ctx.block_timestamp)?;
        // Repeated query params — the OpenAPI default array form. NOTE: not yet
        // exercised against a production beacon node (only against the harness stub);
        // re-verify the array style when the first real deployment is wired up.
        let query: Vec<(&str, String)> = wanted
            .iter()
            .map(|vh| ("versioned_hashes", format!("0x{}", hex::encode(vh))))
            .collect();

        // A 200 is not an answer — a node that pruned the slot (or, post-PeerDAS,
        // custodies too few columns) replies 200 with fewer blobs than asked, and
        // the whole point of multiple endpoints is to keep going in that case.
        // Candidates accumulate across endpoints until the COUNT covers the request
        // (identity is the caller's verify step); partial beats empty at the end.
        let mut collected: Vec<RawBlob> = Vec::new();
        let mut last_err = "no beacon endpoints configured".to_string();
        for endpoint in &self.endpoints {
            let url = format!("{}/eth/v1/beacon/blobs/{slot}", endpoint.trim_end_matches('/'));
            let result = async {
                let resp = self
                    .client
                    .get(&url)
                    .query(&query)
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("{} from {url}", resp.status()));
                }
                let body: BlobsResponse =
                    resp.json().await.map_err(|e| format!("bad response body: {e}"))?;
                body.data.iter().map(|s| parse_blob_hex(s)).collect::<Result<Vec<_>, _>>()
            }
            .await;
            match result {
                Ok(mut blobs) => {
                    let short = blobs.len() < wanted.len();
                    collected.append(&mut blobs);
                    if collected.len() >= wanted.len() {
                        return Ok(collected);
                    }
                    if short {
                        tracing::warn!(
                            endpoint,
                            slot,
                            "beacon endpoint answered with fewer blobs than requested; \
                             trying the next endpoint"
                        );
                        last_err = format!("{url} served a partial or empty blob set");
                    }
                }
                Err(e) => {
                    tracing::warn!(endpoint, slot, "beacon endpoint failed: {e}");
                    last_err = e;
                }
            }
        }
        if !collected.is_empty() {
            return Ok(collected);
        }
        Err(SourceError(format!("all beacon endpoints failed for slot {slot}: {last_err}")))
    }
}

pub(crate) fn parse_blob_hex(s: &str) -> Result<RawBlob, String> {
    let stripped = s.strip_prefix("0x").ok_or("blob hex missing 0x prefix")?;
    let bytes = hex::decode(stripped).map_err(|e| format!("blob is not hex: {e}"))?;
    let arr: Box<[u8; BLOB_BYTES]> =
        bytes.into_boxed_slice().try_into().map_err(|_| "blob is not 131072 bytes")?;
    Ok(arr)
}
