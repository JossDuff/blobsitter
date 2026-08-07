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

/// A handle for feeding a [`MockSource`] after construction (long-lived rigs whose
/// declarations arrive over time).
pub type SharedBlobs = Arc<std::sync::Mutex<HashMap<Hash, RawBlob>>>;

/// A mock source: serves whatever verified-or-not bytes it was loaded with, keyed by
/// the versioned hash it CLAIMS they answer (the ingest side never trusts the claim).
pub struct MockSource {
    pub name: String,
    blobs: SharedBlobs,
    fail_hard: bool,
    calls: Arc<AtomicUsize>,
}

impl MockSource {
    pub fn serving(name: &str, entries: impl IntoIterator<Item = (Hash, RawBlob)>) -> Self {
        Self {
            name: name.into(),
            blobs: Arc::new(std::sync::Mutex::new(entries.into_iter().collect())),
            fail_hard: false,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A source plus the live handle to keep loading it.
    pub fn shared(name: &str) -> (Self, SharedBlobs) {
        let source = Self::serving(name, []);
        let handle = source.blobs.clone();
        (source, handle)
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
        let blobs = self.blobs.lock().unwrap();
        Ok(wanted.iter().filter_map(|vh| blobs.get(vh).cloned()).collect())
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

/// Deterministic, dependency-free xorshift64* — the tests' index-pick PRNG. One
/// definition so a mistyped shift can't quietly shrink a differential test's space.
pub fn xorshift(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed;
    move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// The common happy path: a rig whose single source serves the declaration's blobs.
pub fn rig_serving(dir: &Path, declarations: &[(DeclaredEvent, Vec<RawBlob>)]) -> Rig {
    let entries = declarations.iter().flat_map(|(e, blobs)| {
        e.blob_versioned_hashes.iter().copied().zip(blobs.iter().cloned())
    });
    rig(dir, vec![Box::new(MockSource::serving("primary", entries))])
}

/// Layer-2 helpers: spawning the real daemon binary against the anvil harness.
pub mod l2 {
    use std::path::Path;

    use blobsitter_testkit::anvil::Harness;
    use blobsitter_testkit::beacon_stub::BeaconStub;

    /// The anvil-preconditions gate every L2 suite shares. Self-skip is for
    /// developer machines; CI sets BLOBSITTER_REQUIRE_L2=1 so a broken artifact
    /// path can never silently zero out end-to-end coverage.
    pub fn skip_or_fail() -> bool {
        if blobsitter_testkit::anvil::preconditions_met() {
            return false;
        }
        if std::env::var_os("BLOBSITTER_REQUIRE_L2").is_some() {
            panic!("BLOBSITTER_REQUIRE_L2 is set but anvil/forge artifacts are unavailable");
        }
        eprintln!("skipping: anvil or forge artifacts unavailable");
        true
    }

    pub struct Daemon {
        child: std::process::Child,
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Spawn `blobsitterd` against the harness. `provider` = (providerId, operator
    /// key hex) switches on enforcement duties; the key travels via the environment,
    /// exactly like production.
    pub fn spawn_daemon(
        dir: &Path,
        harness: &Harness,
        stub: &BeaconStub,
        provider: Option<(u64, &str)>,
    ) -> Daemon {
        let data_dir = dir.join("data");
        let mut config = format!(
            r#"
instance = "{instance}"
execution_rpc = "{rpc}"
data_dir = "{data}"
deployment_block = {deploy}
poll_interval_secs = 1

[beacon]
endpoints = ["{stub}"]
genesis_time = 0
seconds_per_slot = 1
"#,
            instance = harness.instance,
            rpc = harness.endpoint,
            data = data_dir.display(),
            deploy = harness.instance_deploy_block,
            stub = stub.url,
        );
        if let Some((id, _)) = provider {
            config.push_str(&format!(
                "\n[provider]\nid = {id}\nconfirm_timeout_secs = 5\nescape_threshold_secs = 5\n"
            ));
        }
        let config_path = dir.join("blobsitterd.toml");
        std::fs::write(&config_path, config).unwrap();

        let log = std::fs::File::create(dir.join("daemon.log")).unwrap();
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_blobsitterd"));
        command.arg(&config_path).stdout(log.try_clone().unwrap()).stderr(log);
        match provider {
            Some((_, key)) => command.env("BLOBSITTER_OPERATOR_KEY", key),
            None => command.env_remove("BLOBSITTER_OPERATOR_KEY"),
        };
        Daemon { child: command.spawn().expect("daemon binary spawns") }
    }

    pub fn frontier(dir: &Path) -> Option<blobsitter_daemon::store::Frontier> {
        let raw = std::fs::read(dir.join("data/frontier.json")).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    pub async fn wait_for_nonce(dir: &Path, nonce: u64) -> blobsitter_daemon::store::Frontier {
        for _ in 0..120 {
            if let Some(f) = frontier(dir) {
                if f.nonce >= nonce {
                    return f;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        let log = std::fs::read_to_string(dir.join("daemon.log")).unwrap_or_default();
        panic!("daemon never reached nonce {nonce}; log:\n{log}");
    }

    pub fn daemon_log(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("daemon.log")).unwrap_or_default()
    }
}
