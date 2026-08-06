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

    fn slot_for(&self, block_timestamp: u64) -> u64 {
        (block_timestamp - self.genesis_time) / self.seconds_per_slot
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
        let slot = self.slot_for(ctx.block_timestamp);
        // Repeated query params — the OpenAPI default array form. NOTE: not yet
        // exercised against a production beacon node (only against the harness stub);
        // re-verify the array style when the first real deployment is wired up.
        let query: Vec<(&str, String)> = wanted
            .iter()
            .map(|vh| ("versioned_hashes", format!("0x{}", hex::encode(vh))))
            .collect();

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
                Ok(blobs) => return Ok(blobs),
                Err(e) => {
                    tracing::warn!(endpoint, slot, "beacon endpoint failed: {e}");
                    last_err = e;
                }
            }
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
