# Blob-sourcing research (2026-08-06)

Input to the daemon's blob-source decision (test-plan behavior D18). Web-researched
2026-08-06; sources inline; unverified items flagged at the end. This is a research
note, not a spec — the adopted decision lives in the daemon's design docs once made.

# Sourcing EIP-4844 Blob Contents: Research Report

## 1. Beacon API blob retrieval

### Endpoints

- **Pre-Fusaka standard**: `GET /eth/v1/beacon/blob_sidecars/{block_id}` — returns all blob sidecars for a block (blob + KZG commitment + KZG proof + inclusion proof), with an optional `indices` query param to select specific blobs. Documented per-provider, e.g. [QuickNode](https://www.quicknode.com/docs/ethereum/eth-v1-beacon-blob_sidecars-id) and [Alchemy](https://www.alchemy.com/docs/chains/ethereum/ethereum-beacon-api-endpoints/ethereum-beacon-api-endpoints/v-1-beacon-blob-sidecars-block-id).
- **Post-Fusaka (Fulu)**: blob sidecars **no longer exist as a canonical p2p object** — the network gossips **data column sidecars** (each 128 KiB blob is erasure-coded and split into 128 columns of ~2 KiB cells). The beacon-APIs spec added `GET /eth/v1/beacon/blobs/{block_id}` in **beacon-APIs v4.0.0** ([ethereum/beacon-APIs#546](https://github.com/ethereum/beacon-APIs/pull/546)), which returns **raw blobs** (ordered by the block's KZG commitments), with an optional **`versioned_hashes` filter parameter** — directly useful for a daemon keyed on versioned hashes from event logs. JSON or SSZ via `Accept` header. `blob_sidecars` is **deprecated** in favor of this ([foundry issue tracking the migration](https://github.com/foundry-rs/foundry/issues/12181)); post-Fulu, nodes serve it (where still supported) by **reconstructing blobs from stored columns**, and reconstruction behavior is implementation-specific.
- There is also spec work to serve `DataColumnSidecarsByRoot` for finalized epochs ([consensus-specs#4394](https://github.com/ethereum/consensus-specs/pull/4394)) — column-level retrieval exists on p2p, but for a blob consumer the `/eth/v1/beacon/blobs` endpoint is the intended interface.

### PeerDAS custody: node configuration now matters a lot

After Fusaka, a **default full node only custodies a small fraction of columns** (non-validating nodes participate in ~4 column subnets, ~1/32 of the data — see [Prysm issue #15852](https://github.com/OffchainLabs/prysm/issues/15852), still open without full resolution) and therefore **cannot serve complete blobs by itself**. To serve blob contents via the Beacon API you need one of:

- **Supernode**: subscribes to all 128 column subnets, custodies everything, performs reconstruction and cross-seeding. Lighthouse `--supernode` (old name `--subscribe-all-data-column-subnets` aliased) ([Lighthouse releases](https://github.com/sigp/lighthouse/releases)); Teku `--p2p-subscribe-all-custody-subnets-enabled`; Prysm `--subscribe-all-data-subnets` (per [Arbitrum's historical-blobs page](https://docs.arbitrum.io/run-arbitrum-node/beacon-nodes-historical-blobs)).
- **Semi-supernode**: custodies ~50% of erasure-coded columns — exactly enough to reconstruct any blob — at much lower bandwidth/disk. Prysm `--semi-supernode` ("custodies just enough data to serve the blobs and blob sidecars beacon API"); Lighthouse `--semi-supernode` ([Lighthouse book, Blobs page](https://lighthouse-book.sigmaprime.io/advanced_blobs.html)). Lighthouse also auto-escalates custody with attached validator stake (≥2048 ETH → semi-supernode-equivalent, ≥4096 ETH → supernode).
- Arbitrum's docs recommend **Prysm ≥7.1.0 with `--semi-supernode --enable-backfill`** for blob-serving nodes ([source](https://docs.arbitrum.io/run-arbitrum-node/beacon-nodes-historical-blobs)).

**Implication**: a daemon relying on its own beacon node **must run at least a semi-supernode**; a vanilla default node will fail to return full blobs post-Fusaka.

### Retention window on mainnet as of 2026

- **Unchanged: 4096 epochs (~18 days).** Pre-Fulu constant `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS = 4096`; Fulu's equivalent `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS = 4096` ([consensus-specs Fulu p2p interface](https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/p2p-interface.md)). Nodes MUST serve columns in `[current_epoch - 4096, current_epoch]` (bounded by the Fulu fork epoch) and MAY prune beyond it.
- **Fusaka activated on mainnet at epoch 411392, 2025-12-03** ([EF announcement](https://blog.ethereum.org/2025/11/06/fusaka-mainnet-announcement)). Throughput was then raised by **Blob-Parameter-Only forks**: **BPO1** (epoch 412672, 2025-12-09) target/max 10/15; **BPO2** (epoch 419072, 2026-01-07) target/max **14/21** (up from 6/9). BPOs change blob counts, **not** the retention window. Flag: no later 2026 BPO surfaced, but not exhaustively verified.

### Per-client retention/archival flags

Sources: [Arbitrum historical-blobs docs](https://docs.arbitrum.io/run-arbitrum-node/beacon-nodes-historical-blobs), [Lighthouse book](https://lighthouse-book.sigmaprime.io/advanced_blobs.html), [Nimbus guide](https://nimbus.guide/history.html), [OP docs](https://docs.optimism.io/operators/node-operators/management/blobs).

| Client | Extended retention | Notes |
|---|---|---|
| **Lighthouse** | `--prune-blobs false` (keep forever) or `--blob-prune-margin-epochs N` (keep 4096+N) | Experimental `--complete-blob-backfill` backfills historical blobs/columns, **only works when set at a fresh checkpoint sync** — it backfills from peers, so in practice only within what peers still serve (flag: exact reach unverified) |
| **Prysm** | `--blob-retention-epochs N` (refuses values <4096) | `--enable-backfill` backfills; ≥7.1.0 recommended with `--semi-supernode` |
| **Teku** | **No dedicated blob-retention flag** (per Arbitrum docs) | Only generic storage-mode options; has a flag for storing non-canonical blobs |
| **Nimbus** | `--history=archive` retains blobs beyond ~18 days in the Nimbus DB | Default prune mode keeps ~18 days |
| **Lodestar** | `--chain.archiveDataEpochs` (epochs to retain finalized blobs/columns; min 4096) | ([Lodestar beacon CLI](https://chainsafe.github.io/lodestar/run/beacon-management/beacon-cli/)) |

Flag: whether these flags store **blobs** vs **columns** post-Fusaka (and how extended retention interacts with semi-supernode reconstruction) is under-documented across clients.

## 2. Hosted RPC/API options

- **Alchemy** — exposes `/eth/v1/beacon/blob_sidecars/{block_id}` ([docs](https://www.alchemy.com/docs/chains/ethereum/ethereum-beacon-api-endpoints/ethereum-beacon-api-endpoints/v-1-beacon-blob-sidecars-block-id)). Historical depth not stated.
- **QuickNode** — documents both `blob_sidecars` and the new `/eth/v1/beacon/blobs/{block_id}` ([docs](https://www.quicknode.com/docs/ethereum/eth-v1-beacon-blobs-block_id)); the blob_sidecars page states **"The complete history of blob data is supported"** ([source](https://www.quicknode.com/docs/ethereum/eth-v1-beacon-blob_sidecars-id)) — i.e. archive blobs back past the retention window. Plan/pricing conditions not stated.
- **Arbitrum maintains a curated list** of beacon RPC providers with historical-blob support ([list](https://docs.arbitrum.io/run-arbitrum-node/l1-ethereum-beacon-chain-rpc-providers)): with historical blob data: **Ankr, Chainstack, Conduit, Nirvana Labs, QuickNode, dRPC**; without: Chainbase, BlastAPI, NodeReal. (Flag: Arbitrum's curation; per-provider depth/SLA unverified.)
- **Infura** — no documentation of beacon blob endpoints found; flag as unverified/likely absent.

## 3. Public blob archives

- **Blobscan** ([blobscan.com](https://docs.blobscan.com/), [GitHub](https://github.com/Blobscan/blobscan)) — the main public blob explorer + archive. Indexer pulls blobs from a CL client and persists **full blob data** to **Google Cloud Storage and Ethereum Swarm** with metadata in PostgreSQL ([indexer docs](https://docs.blobscan.com/docs/indexer), [features](https://docs.blobscan.com/docs/features)). Lookup by **versioned hash, KZG commitment, tx hash, slot, or block number**. Public REST API at [api.blobscan.com](https://api.blobscan.com/) (Swagger; public reads, JWT only for indexer writes) ([API docs](https://docs.blobscan.com/docs/api)). Flags: exact endpoint paths/rate limits/bulk export not enumerated; "from Dencun genesis" coverage not confirmed in writing. Donation-funded (Giveth) — **longevity not guaranteed**.
- **Blocknative "Ethernow" Blob Archive** — **discontinued 2025-03-01** ([docs](https://docs.blocknative.com/data-archive/blob-archive)). Cautionary example of archive-service churn.
- **base/blob-archiver** ([GitHub](https://github.com/base/blob-archiver)) — OP-stack-ecosystem service: an **archiver** that follows the beacon chain and writes blobs to **S3-compatible or file storage**, and an **API** re-serving them behind the standard **blob-sidecars Beacon API shape** (drop-in fallback for op-node etc.). Actively maintained. Its own docs note it does **not validate** the beacon node's data — validate client-side. Rust port: [optimism-java/blob-archiver-rs](https://github.com/optimism-java/blob-archiver-rs).
- **ethPandaOps** — hosts era-file history archives ([history endpoints](https://ethpandaops.io/data/history/)) but **no blob or data-column archives** listed; see also [eth-clients/history-endpoints](https://github.com/eth-clients/history-endpoints). No EF-run public blob archive found; EF history-expiry work covers pre-merge execution data, not blobs ([announcement](https://blog.ethereum.org/2025/07/08/partial-history-exp)).
- **Hemera BlobArchive (0G Labs)** — claims all post-4844 blobs on 0G storage ([announcement](https://medium.com/hemera-protocol/hemera-blobarchive-for-ethereum-permanent-data-availability-for-layer-2-11c289b20d45)). Flag: 2026 operational status unverified.
- **EIP-4444 / Portal**: partial history expiry live for **pre-merge execution data** only; **blobs are not covered** by any Portal/era distribution found. Flag: Portal Network 2026 organizational status unverified.

**Trust model (applies to everything above)**: blob contents are **trustlessly verifiable** against the versioned hash from the L1 event: compute the KZG commitment from the raw blob (deterministic, c-kzg), then check `versioned_hash == 0x01 ‖ sha256(commitment)[1:]`. Any untrusted archive (Blobscan, S3 bucket, another provider, IPFS) is usable — the only unverifiable failure mode is **withholding**, not corruption.

## 4. Prior art

- **OP Stack / op-node** ([Using blobs](https://docs.optimism.io/operators/node-operators/management/blobs), [flags.go](https://github.com/ethereum-optimism/optimism/blob/develop/op-node/flags/flags.go)):
  - `--l1.beacon`: primary L1 Beacon-API endpoint for blob fetch.
  - `--l1.beacon-archiver` → renamed **`--l1.beacon-fallbacks`**: comma-separated **fallback** Beacon-API endpoints "used to fetch blob sidecars not available at the l1.beacon (e.g. expired blobs)". Needed whenever syncing >18 days of history ([base/node issue #270](https://github.com/base/node/issues/270)).
  - Recommended archiver options, in their order: (1) Lighthouse with `--prune-blobs=false`, (2) run **base/blob-archiver** (lighter than an unpruned beacon node), (3) third-party archiver service.
  - The canonical pattern: **primary beacon endpoint + ordered archive fallbacks behind the same API shape**.
- **Arbitrum Nitro**: requires a beacon endpoint with historical blob data; no nitro-side archival — the burden sits in beacon-node config or a hosted historical provider ([docs](https://docs.arbitrum.io/run-arbitrum-node/beacon-nodes-historical-blobs)).
- **EigenDA / Celestia**: not 4844 consumers (alt-DA; only commitments go on-chain), so no blob-fetching prior art there.
- **Blob indexers**: Blobscan's indexer is the reference architecture — follow head via CL client, persist blob bodies to durable object storage immediately, metadata in SQL.
- Near-head only: Fusaka standardized `engine_getBlobsV2` (CL pulls blobs from the EL blob mempool) — intra-node, not usable by an external daemon; for completeness ([QuickNode Fusaka overview](https://www.quicknode.com/blog/ethereum-fusaka-upgrade-what-you-need-to-know); flag: not deeply verified).

## 5. Practical inputs for a never-miss daemon

- **Standard redundancy pattern** (OP Stack practice): own beacon node as primary + one or more archive fallbacks (self-hosted blob-archiver on S3, hosted historical providers) behind the same Beacon-API shape, all responses verified locally against versioned hashes.
- **Ingest-at-head, don't rely on retention**: every prior-art system that must not miss data (Blobscan, blob-archiver) persists blobs to its own durable storage within the window rather than depending on later retrieval. The 4096-epoch window is ~18 days of slack to detect and repair gaps while p2p data is still guaranteed available.
- **Post-Fusaka node requirements**: a self-hosted beacon node must be **semi-supernode or supernode** to serve/reconstruct full blobs. Semi-supernode ≈ 50% of column data, materially cheaper than supernode.
- **Storage cost of self-hosted retention** ([Lighthouse book](https://lighthouse-book.sigmaprime.io/advanced_blobs.html), pre-Fusaka rates): default rolling window ~48–100 GB; all blobs ≈158 GB/month at ~6-blob target. Post-BPO2 arithmetic (calculated, not sourced): 14 blobs × 128 KiB × ~7200 slots/day ≈ **12.9 GB/day at target** → ~390 GB per retention window, ~4.7 TB/year if fully utilized; max (21/block) ~1.5×. A full from-Dencun archive is multi-TB and growing — object storage is the prior-art answer, not beacon-node disk. (Note: these are NETWORK-total figures; this protocol's own dataset is a tiny fraction — the daemon archives only its instance's declared blobs.)
- **Hosted-API risk data points**: Blocknative's archive shut down with months of notice; Blobscan is donation-funded; "complete history" claims (QuickNode) are commercial and unversioned. Safe as *verifiable fallbacks* only — KZG verification removes the integrity trust requirement, not the availability one.

## Unverified / flagged items (summary)

- Infura beacon/blob support: not found, not conclusively absent.
- Blobscan exact API paths, rate limits, bulk export, from-Dencun coverage.
- Hemera/0G BlobArchive operational status in 2026.
- Portal Network organizational status in 2026; no blob coverage found in any era/Portal effort.
- Whether any post-BPO2 mainnet BPO exists as of Aug 2026 (none surfaced).
- Blobs-vs-columns on disk for extended-retention flags post-Fusaka.
- Per-provider historical depth on the Arbitrum list is Arbitrum's claim.
