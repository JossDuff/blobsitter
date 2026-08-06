//! The challenge responder (test plan D7–D10): every challenge against this provider
//! gets a confirmed, contract-accepted response inside its window, whatever it takes.
//!
//! The challenge LEDGER is persistent state, not memory (D10): a challenge's index
//! set exists ONLY in its `ChallengeOpened` event, so it is written to disk before
//! the scan cursor moves past that event, and a restarted daemon resumes every open
//! obligation from the file. Resolution truth comes back from chain events (and a
//! startup reconciliation), never from our own optimism about a submitted tx.
//!
//! This path is SNARK-free forever (protocol invariant): chunks, keccak paths, and
//! calldata — nothing here may ever grow a circuit dependency.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, FixedBytes, B256};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use serde::{Deserialize, Serialize};

use crate::abi::Blobsitter;
use crate::alarm::{AlarmSink, Severity};
use crate::proofs::build_proof_set;
use crate::store::Reader;
use crate::tx::TxSender;
use crate::Hash;

/// One open obligation, exactly as the event declared it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenChallenge {
    pub challenge_id: u64,
    pub indices: Vec<u64>,
    #[serde(with = "hex_hash")]
    pub pinned_root: Hash,
    pub pinned_leaf_count: u64,
    /// Chain-time instant the window closes.
    pub deadline: u64,
    /// Set once a response tx confirmed; cleared entries leave the ledger entirely
    /// when the resolution EVENT arrives.
    pub responded_tx: Option<String>,
}

mod hex_hash {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(h: &super::Hash, s: S) -> Result<S::Ok, S::Error> {
        format!("0x{}", hex::encode(h)).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<super::Hash, D::Error> {
        let raw = String::deserialize(d)?;
        let bytes =
            hex::decode(raw.strip_prefix("0x").unwrap_or(&raw)).map_err(serde::de::Error::custom)?;
        super::Hash::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("hash is not 32 bytes"))
    }
}

/// The persistent ledger: every mutation lands on disk (tmp + rename, same pattern
/// as the store frontier) before it counts.
pub struct Ledger {
    path: PathBuf,
    entries: BTreeMap<u64, OpenChallenge>,
}

impl Ledger {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let path = data_dir.join("challenges.json");
        let entries = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("corrupt challenge ledger {}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        Ok(Self { path, entries })
    }

    fn persist(&self) -> Result<(), String> {
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&self.entries).expect("ledger serializes");
        std::fs::write(&tmp, &bytes)
            .and_then(|()| std::fs::File::open(&tmp)?.sync_all())
            .and_then(|()| std::fs::rename(&tmp, &self.path))
            .map_err(|e| format!("cannot persist challenge ledger: {e}"))
    }

    pub fn entries(&self) -> impl Iterator<Item = &OpenChallenge> {
        self.entries.values()
    }

    pub fn insert(&mut self, challenge: OpenChallenge) -> Result<(), String> {
        self.entries.insert(challenge.challenge_id, challenge);
        self.persist()
    }

    pub fn mark_responded(&mut self, id: u64, tx_hash: String) -> Result<(), String> {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.responded_tx = Some(tx_hash);
            return self.persist();
        }
        Ok(())
    }

    pub fn remove(&mut self, id: u64) -> Result<(), String> {
        if self.entries.remove(&id).is_some() {
            return self.persist();
        }
        Ok(())
    }
}

pub struct Responder {
    provider_id: u64,
    instance: Address,
    response_window: u64,
    ledger: Arc<Mutex<Ledger>>,
    sender: Arc<TxSender>,
    alarm: Arc<dyn AlarmSink>,
    jobs: HashMap<u64, tokio::task::JoinHandle<()>>,
}

impl Responder {
    pub fn new(
        provider_id: u64,
        instance: Address,
        response_window: u64,
        ledger: Ledger,
        sender: Arc<TxSender>,
        alarm: Arc<dyn AlarmSink>,
    ) -> Self {
        Self {
            provider_id,
            instance,
            response_window,
            ledger: Arc::new(Mutex::new(ledger)),
            sender,
            alarm,
            jobs: HashMap::new(),
        }
    }

    /// A finalized `ChallengeOpened` against this provider. MUST succeed before the
    /// follower advances its cursor past the event — the index set exists nowhere
    /// else.
    pub fn on_opened(&mut self, challenge: OpenChallenge) -> Result<(), String> {
        self.alarm.alarm(
            Severity::Warning,
            &format!(
                "challenge {} opened against provider {} ({} indices, deadline {})",
                challenge.challenge_id,
                self.provider_id,
                challenge.indices.len(),
                challenge.deadline
            ),
        );
        self.ledger.lock().unwrap().insert(challenge)
    }

    /// Any challenge resolution (answered / refunded / timed out). Unknown ids are
    /// other providers' challenges and ignored.
    pub fn on_resolved(&mut self, challenge_id: u64, timed_out: bool) -> Result<(), String> {
        let known = {
            let mut ledger = self.ledger.lock().unwrap();
            let known = ledger.entries.contains_key(&challenge_id);
            ledger.remove(challenge_id)?;
            known
        };
        if known && timed_out {
            self.alarm.alarm(
                Severity::Critical,
                &format!(
                    "challenge {challenge_id} TIMED OUT — this provider has been slashed"
                ),
            );
        }
        Ok(())
    }

    /// Startup reconciliation: drop ledger entries the chain already resolved while
    /// the daemon was down (their resolution events are behind the cursor).
    pub async fn reconcile(
        &mut self,
        contract: &Blobsitter::BlobsitterInstance<alloy::providers::DynProvider>,
    ) -> Result<(), String> {
        let ids: Vec<u64> =
            self.ledger.lock().unwrap().entries().map(|c| c.challenge_id).collect();
        for id in ids {
            let on_chain =
                contract.getChallenge(id).call().await.map_err(|e| e.to_string())?;
            if on_chain.resolved {
                self.ledger.lock().unwrap().remove(id)?;
            }
        }
        Ok(())
    }

    /// One tick: spawn response jobs for every open, un-answered, un-jobbed entry,
    /// and raise deadline alarms.
    pub fn drive(&mut self, chain_now: u64, reader: &Reader) {
        self.jobs.retain(|_, handle| !handle.is_finished());

        let entries: Vec<OpenChallenge> =
            self.ledger.lock().unwrap().entries().cloned().collect();
        for entry in entries {
            let id = entry.challenge_id;
            if chain_now >= entry.deadline {
                if entry.responded_tx.is_none() {
                    self.alarm.alarm(
                        Severity::Critical,
                        &format!(
                            "challenge {id} window EXPIRED without a confirmed response — \
                             resolveTimeout will slash this provider"
                        ),
                    );
                }
                continue;
            }
            if entry.responded_tx.is_some() || self.jobs.contains_key(&id) {
                // Confirmed (awaiting the resolution event) or already being handled.
                if entry.responded_tx.is_none()
                    && entry.deadline.saturating_sub(chain_now) < self.response_window / 4
                {
                    self.alarm.alarm(
                        Severity::Critical,
                        &format!(
                            "challenge {id} still unconfirmed with under a quarter of the \
                             response window left"
                        ),
                    );
                }
                continue;
            }
            self.jobs.insert(id, self.spawn_response(entry, reader.clone()));
        }
    }

    fn spawn_response(
        &self,
        entry: OpenChallenge,
        reader: Reader,
    ) -> tokio::task::JoinHandle<()> {
        let sender = self.sender.clone();
        let alarm = self.alarm.clone();
        let ledger = self.ledger.clone();
        let instance = self.instance;
        tokio::spawn(async move {
            let id = entry.challenge_id;
            let indices = entry.indices.clone();
            let n = entry.pinned_leaf_count;
            let pinned_root = entry.pinned_root;
            let set = match tokio::task::spawn_blocking(move || {
                build_proof_set(&reader, &indices, n, &pinned_root)
            })
            .await
            {
                Ok(Ok(set)) => set,
                Ok(Err(e)) => {
                    // Retried on a later tick (the job registry forgets finished
                    // jobs); BeyondFrontier in particular clears once ingest
                    // catches up to the pinned state.
                    alarm.alarm(
                        Severity::Critical,
                        &format!("cannot build response for challenge {id}: {e}"),
                    );
                    return;
                }
                Err(join_err) => {
                    alarm.alarm(
                        Severity::Critical,
                        &format!("response construction task died for challenge {id}: {join_err}"),
                    );
                    return;
                }
            };

            let tx = TransactionRequest::default().with_to(instance).with_input(Bytes::from(
                Blobsitter::respondCall {
                    challengeId: id,
                    indices: entry.indices.clone(),
                    n: set.n,
                    pinnedPeaks: set.peaks.iter().map(|p| B256::from(*p)).collect(),
                    proofs: set
                        .proven
                        .iter()
                        .map(|pc| Blobsitter::ChunkProof {
                            chunk: FixedBytes::<31>::from(pc.chunk),
                            path: pc.path.iter().map(|h| B256::from(*h)).collect(),
                        })
                        .collect(),
                }
                .abi_encode(),
            ));
            match sender.send_until(tx, &format!("respond({id})"), Some(entry.deadline)).await {
                Ok(hash) => {
                    tracing::info!(challenge = id, %hash, "challenge response confirmed");
                    if let Err(e) =
                        ledger.lock().unwrap().mark_responded(id, format!("{hash}"))
                    {
                        alarm.alarm(Severity::Warning, &e);
                    }
                }
                Err(e) => alarm.alarm(
                    Severity::Critical,
                    &format!("response submission for challenge {id} failed: {e}"),
                ),
            }
        })
    }
}
