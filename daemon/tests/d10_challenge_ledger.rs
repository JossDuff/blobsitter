//! D10 — pending-obligation recovery: the challenge ledger is persistent state, not
//! memory. A challenge's index set exists only in its ChallengeOpened event, so the
//! ledger must survive any restart with every open obligation intact. (The full
//! restart-and-respond scenario runs against anvil in the L2 suite; this pins the
//! persistence layer itself.)

mod common;

use std::sync::Arc;

use alloy::providers::Provider;
use blobsitter_daemon::alarm::{CapturingAlarm, Severity};
use blobsitter_daemon::responder::{Ledger, OpenChallenge, Responder};
use blobsitter_daemon::tx::TxSender;

fn challenge(id: u64) -> OpenChallenge {
    OpenChallenge {
        challenge_id: id,
        indices: vec![0, 5, 5, 12],
        pinned_root: [id as u8; 32],
        pinned_leaf_count: 40,
        deadline: 1_700_000_000 + id,
        responded_tx: None,
    }
}

#[test]
fn d10_ledger_survives_restart() {
    let dir = tempfile::tempdir().unwrap();

    let mut ledger = Ledger::open(dir.path()).unwrap();
    ledger.insert(challenge(1)).unwrap();
    ledger.insert(challenge(2)).unwrap();
    ledger.mark_responded(1, "0xabc".into()).unwrap();
    drop(ledger);

    // Every mutation was durable: a fresh open sees exactly the same obligations.
    let ledger = Ledger::open(dir.path()).unwrap();
    let entries: Vec<_> = ledger.entries().cloned().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].challenge_id, 1);
    assert_eq!(entries[0].responded_tx.as_deref(), Some("0xabc"));
    assert_eq!(entries[1].challenge_id, 2);
    assert_eq!(entries[1].indices, vec![0, 5, 5, 12], "the index set is the whole point");
    drop(ledger);

    let mut ledger = Ledger::open(dir.path()).unwrap();
    ledger.remove(1).unwrap();
    drop(ledger);
    let ledger = Ledger::open(dir.path()).unwrap();
    assert_eq!(ledger.entries().count(), 1);
}

#[test]
fn d10_corrupt_ledger_refuses_to_open() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("challenges.json"), b"{ not json").unwrap();
    assert!(Ledger::open(dir.path()).is_err(), "silent loss of obligations is not an option");
}

/// The responder's event intake: an opened challenge is durably recorded (and
/// alarmed) before the caller may advance its cursor; a timeout resolution against
/// this provider is the loudest alarm there is.
#[tokio::test]
async fn d10_responder_intake_is_durable_and_loud() {
    let dir = tempfile::tempdir().unwrap();
    let alarm = Arc::new(CapturingAlarm::new());
    let provider = alloy::providers::ProviderBuilder::new()
        .connect_http("http://127.0.0.1:1".parse().unwrap())
        .erased();
    let sender = Arc::new(TxSender::new(
        provider,
        alloy::primitives::Address::ZERO,
        alarm.clone(),
        std::time::Duration::from_secs(1),
    ));
    let ledger = Ledger::open(dir.path()).unwrap();
    let mut responder = Responder::new(1, alloy::primitives::Address::ZERO, 60, ledger, sender, alarm.clone());

    responder.on_opened(challenge(7)).unwrap();
    assert!(
        alarm.entries().iter().any(|(s, m)| *s == Severity::Warning && m.contains("challenge 7")),
        "an opened challenge is announced"
    );
    // Durable before cursor advance: a brand-new ledger sees it.
    assert_eq!(Ledger::open(dir.path()).unwrap().entries().count(), 1);

    // Resolution removes it; a TIMEOUT against us means slashed — Critical.
    responder.on_resolved(7, true).unwrap();
    assert_eq!(Ledger::open(dir.path()).unwrap().entries().count(), 0);
    assert!(alarm.criticals().iter().any(|m| m.contains("TIMED OUT")));

    // Unknown ids (other providers' challenges) are silently ignored.
    responder.on_resolved(99, true).unwrap();
    assert_eq!(alarm.criticals().len(), 1);
}
