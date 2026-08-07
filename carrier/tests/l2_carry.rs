//! Layer 2 — carriage against the REAL contract on anvil: packages built by the
//! harness's publisher side, carried by a fresh EOA through the full verify →
//! simulate → submit pipeline. Covers C2–C6 end to end and one binary run (C7).

use std::process::Command;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;

use blobsitter_carrier::carry::{carry, CarryError, CarryOptions};
use blobsitter_carrier::claim::claim_all;
use blobsitter_carrier::preflight::PreflightError;
use blobsitter_intents::IntentBody;
use blobsitter_testkit::anvil::{preconditions_met, Harness};
use blobsitter_testkit::declare::{build_app_pointer_package, build_declaration_package};

fn skip_or_fail() -> bool {
    if preconditions_met() {
        return false;
    }
    if std::env::var_os("BLOBSITTER_REQUIRE_L2").is_some() {
        panic!("BLOBSITTER_REQUIRE_L2 is set but anvil/forge artifacts are unavailable");
    }
    eprintln!("skipping: anvil or forge artifacts unavailable");
    true
}

const ETH: u128 = 1_000_000_000_000_000_000;

struct CarrierRig {
    harness: Harness,
    provider: DynProvider,
    carrier: Address,
}

async fn rig() -> CarrierRig {
    let harness = Harness::spawn().await.unwrap();
    let key = PrivateKeySigner::random();
    let carrier = key.address();
    harness.fund(carrier, U256::from(10u128 * ETH)).await.unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(key))
        .connect_http(harness.endpoint.parse().unwrap())
        .erased();
    CarrierRig { harness, provider, carrier }
}

fn options() -> CarryOptions {
    CarryOptions { dry_run: false, force_insolvent: false }
}

/// C4+C6 — a two-blob declaration carried end to end: declared on chain, and the
/// carrier's balance GROWS (reimbursement covered gas and paid the tip on top).
#[tokio::test(flavor = "multi_thread")]
async fn c4_carry_declaration_end_to_end() {
    if skip_or_fail() {
        return;
    }
    let r = rig().await;
    r.harness.fund_paymaster(U256::from(5u128 * ETH)).await.unwrap();
    let package = build_declaration_package(&r.harness, 4_097, Address::ZERO).await.unwrap();

    let before = r.provider.get_balance(r.carrier).await.unwrap();
    let report = carry(&r.provider, &package, r.carrier, &options()).await.unwrap();
    let after = r.provider.get_balance(r.carrier).await.unwrap();

    assert!(report.solvency.covered);
    let reimbursed = report.reimbursed.expect("paymaster reimbursed");
    assert!(report.skipped.is_none());
    let contract = r.harness.instance_contract();
    assert_eq!(contract.leafCount().call().await.unwrap(), 4_097);
    assert_eq!(contract.declarationNonce().call().await.unwrap(), 1);
    // Carriage is self-incentivized: net balance change is positive (≥ part of the
    // tip; priority fees are the carrier's own cost and anvil's are tiny).
    assert!(after > before, "carriage must profit: {before} -> {after} (reimbursed {reimbursed})");
}

/// C2 — every preflight refusal names its check, and NOTHING is submitted: the
/// carrier account's nonce never moves.
#[tokio::test(flavor = "multi_thread")]
async fn c2_preflight_refusals_send_nothing() {
    if skip_or_fail() {
        return;
    }
    let r = rig().await;
    r.harness.fund_paymaster(U256::from(5u128 * ETH)).await.unwrap();
    let nonce_before = r.provider.get_transaction_count(r.carrier).await.unwrap();

    // Stale nonce: someone else declares between packaging and carriage.
    let stale = build_declaration_package(&r.harness, 40, Address::ZERO).await.unwrap();
    let stub = blobsitter_testkit::beacon_stub::BeaconStub::spawn().await;
    blobsitter_testkit::declare::declare_pattern(&r.harness, &stub, 40).await.unwrap();
    match carry(&r.provider, &stale, r.carrier, &options()).await {
        Err(CarryError::Preflight(PreflightError::NonceMismatch { intent: 0, contract: 1 })) => {}
        other => panic!("expected NonceMismatch, got {other:?}"),
    }

    // Designated to someone else.
    let designated =
        build_declaration_package(&r.harness, 12, Address::repeat_byte(0x77)).await.unwrap();
    match carry(&r.provider, &designated, r.carrier, &options()).await {
        Err(CarryError::Preflight(PreflightError::NotDesignated { .. })) => {}
        other => panic!("expected NotDesignated, got {other:?}"),
    }

    // Expired deadline (warp past it).
    let expired = build_declaration_package(&r.harness, 12, Address::ZERO).await.unwrap();
    r.harness.warp(7_200).await.unwrap();
    match carry(&r.provider, &expired, r.carrier, &options()).await {
        Err(CarryError::Preflight(PreflightError::Expired { .. })) => {}
        other => panic!("expected Expired, got {other:?}"),
    }

    // A corrupt blob dies in STATIC validation, before even preflight.
    let mut corrupt = build_declaration_package(&r.harness, 12, Address::ZERO).await.unwrap();
    if let IntentBody::Declaration { blobs, .. } = &mut corrupt.body {
        blobs[0][35] ^= 0x01;
    }
    match carry(&r.provider, &corrupt, r.carrier, &options()).await {
        Err(CarryError::Invalid(_)) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }

    // A tampered signature is caught by the wallet staticcall.
    let mut forged = build_declaration_package(&r.harness, 12, Address::ZERO).await.unwrap();
    forged.signature[10] ^= 0x01;
    match carry(&r.provider, &forged, r.carrier, &options()).await {
        Err(CarryError::Preflight(PreflightError::SignatureRejected)) => {}
        other => panic!("expected SignatureRejected, got {other:?}"),
    }

    assert_eq!(
        r.provider.get_transaction_count(r.carrier).await.unwrap(),
        nonce_before,
        "no refusal may have sent a transaction"
    );
}

/// C3 — an unfunded paymaster is a refusal; --force carries anyway and the receipt
/// shows the skip. A dry run submits nothing either way.
#[tokio::test(flavor = "multi_thread")]
async fn c3_insolvency_refusal_force_and_dry_run() {
    if skip_or_fail() {
        return;
    }
    let r = rig().await;
    // Deliberately NO paymaster funding.
    let package = build_declaration_package(&r.harness, 100, Address::ZERO).await.unwrap();

    match carry(&r.provider, &package, r.carrier, &options()).await {
        Err(CarryError::Insolvent { available: 0, .. }) => {}
        other => panic!("expected Insolvent, got {other:?}"),
    }

    // Dry run: full verification, zero transactions (even with force).
    let dry = CarryOptions { dry_run: true, force_insolvent: true };
    let nonce_before = r.provider.get_transaction_count(r.carrier).await.unwrap();
    let report = carry(&r.provider, &package, r.carrier, &dry).await.unwrap();
    assert!(!report.solvency.covered);
    assert!(report.gas_used > 0, "dry run still simulated");
    assert_eq!(r.provider.get_transaction_count(r.carrier).await.unwrap(), nonce_before);
    assert_eq!(r.harness.instance_contract().leafCount().call().await.unwrap(), 0);

    // Forced: carried for free, and the report says so from the receipt.
    let forced = CarryOptions { dry_run: false, force_insolvent: true };
    let report = carry(&r.provider, &package, r.carrier, &forced).await.unwrap();
    assert!(report.reimbursed.is_none());
    let skip = report.skipped.expect("the skip is visible, not silent");
    assert_eq!(skip.available, 0, "the event carries what the paymaster actually had");
    assert!(skip.requested > 0);
    assert_eq!(r.harness.instance_contract().leafCount().call().await.unwrap(), 100);
}

/// C5 — a setAppPointer package carries as a plain transaction (tip-only
/// reimbursement) through the same pipeline.
#[tokio::test(flavor = "multi_thread")]
async fn c5_set_app_pointer_carriage() {
    if skip_or_fail() {
        return;
    }
    let r = rig().await;
    r.harness.fund_paymaster(U256::from(ETH)).await.unwrap();
    let pointer = [0xAB; 32];
    let package = build_app_pointer_package(&r.harness, pointer).await.unwrap();

    let report = carry(&r.provider, &package, r.carrier, &options()).await.unwrap();
    let reimbursed = report.reimbursed.expect("tip-only reimbursement");
    assert!(reimbursed > 0);
    let contract = r.harness.instance_contract();
    assert_eq!(contract.appPointerNonce().call().await.unwrap(), 1);

    // The tip-only amount excludes the proving subsidy: it must be smaller than a
    // declaration's floor (tip + subsidy).
    let tip: u128 = contract.carrierTipWei().call().await.unwrap().try_into().unwrap();
    let subsidy: u128 = contract.provingSubsidyWei().call().await.unwrap().try_into().unwrap();
    assert!(reimbursed >= tip && reimbursed < tip + subsidy + ETH / 100);
}

/// C6 — the claim path: with nothing parked, claim_all reports zeros and sends
/// nothing (an EOA's pushes always succeed; the parked path belongs to contract
/// recipients, asserted at the unit level by the payout-sink forge suite).
#[tokio::test(flavor = "multi_thread")]
async fn c6_claim_reports_parked_balances() {
    if skip_or_fail() {
        return;
    }
    let r = rig().await;
    let report = claim_all(&r.provider, r.harness.instance, r.carrier).await.unwrap();
    assert!(report.claimed.is_empty());
    assert_eq!(report.paymaster_claimable, 0);
    assert_eq!(report.instance_claimable, 0);
}

/// C7 + the binary end to end: package on disk, key via environment, carried by the
/// real CLI process.
#[tokio::test(flavor = "multi_thread")]
async fn c7_binary_carries_a_package() {
    if skip_or_fail() {
        return;
    }
    let r = rig().await;
    r.harness.fund_paymaster(U256::from(5u128 * ETH)).await.unwrap();
    let package = build_declaration_package(&r.harness, 60, Address::ZERO).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("package.json");
    std::fs::write(&path, package.to_json()).unwrap();

    // A fresh funded key, handed to the process via env only.
    let key = PrivateKeySigner::random();
    r.harness.fund(key.address(), U256::from(10u128 * ETH)).await.unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_blobsitter-carrier"))
        .args(["--rpc", &r.harness.endpoint, "carry"])
        .arg(&path)
        .env("BLOBSITTER_CARRIER_KEY", format!("0x{}", hex::encode(key.to_bytes())))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "carrier binary failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("reimbursed:"), "report missing: {stdout}");
    assert_eq!(r.harness.instance_contract().leafCount().call().await.unwrap(), 60);
}
