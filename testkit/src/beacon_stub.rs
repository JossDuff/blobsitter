//! A beacon-shaped blob server: `GET /eth/v1/beacon/blobs/{block_id}` with the
//! `versioned_hashes` filter, exactly the beacon-APIs v4 surface the daemon's
//! production adapter speaks — so integration tests exercise the REAL adapter, and
//! the same shape a self-hosted blob archiver would present is what gets tested.
//! Slots here are execution-block timestamps: the harness config gives the daemon
//! `genesis_time = 0, seconds_per_slot = 1`, making its slot arithmetic the identity.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use axum::Router;

use blobsitter_reference::Hash;

type Slots = Arc<Mutex<HashMap<u64, Vec<(Hash, Vec<u8>)>>>>;

pub struct BeaconStub {
    slots: Slots,
    pub url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for BeaconStub {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl BeaconStub {
    pub async fn spawn() -> Self {
        let slots: Slots = Arc::new(Mutex::new(HashMap::new()));
        let app = Router::new()
            .route("/eth/v1/beacon/blobs/{block_id}", get(serve_blobs))
            .with_state(slots.clone());
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { slots, url, handle }
    }

    /// Make `blobs` available at `slot` (appending: several execution blocks may map
    /// to one slot under compressed test time).
    pub fn register(&self, slot: u64, blobs: Vec<(Hash, Vec<u8>)>) {
        self.slots.lock().unwrap().entry(slot).or_default().extend(blobs);
    }

    /// Drop everything at `slot` — simulates a node that pruned past retention.
    pub fn forget(&self, slot: u64) {
        self.slots.lock().unwrap().remove(&slot);
    }
}

async fn serve_blobs(
    State(slots): State<Slots>,
    Path(block_id): Path<String>,
    RawQuery(query): RawQuery,
) -> axum::response::Response {
    let Ok(slot) = block_id.parse::<u64>() else {
        return (StatusCode::BAD_REQUEST, "unsupported block_id").into_response();
    };
    let Some(entries) = slots.lock().unwrap().get(&slot).cloned() else {
        return (StatusCode::NOT_FOUND, "block not found").into_response();
    };

    // versioned_hashes filter: repeated query params, hex values.
    let wanted: Vec<String> = query
        .unwrap_or_default()
        .split('&')
        .filter_map(|kv| kv.strip_prefix("versioned_hashes="))
        .map(|v| v.to_ascii_lowercase())
        .collect();
    let data: Vec<String> = entries
        .iter()
        .filter(|(vh, _)| {
            wanted.is_empty() || wanted.contains(&format!("0x{}", hex::encode(vh)))
        })
        .map(|(_, blob)| format!("0x{}", hex::encode(blob)))
        .collect();

    Json(serde_json::json!({
        "execution_optimistic": false,
        "finalized": true,
        "data": data,
    }))
    .into_response()
}
