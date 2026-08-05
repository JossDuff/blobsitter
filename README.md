# blobsitter

**Cheap(er) data storage on Ethereum, with verifiable persistence.**

Blobsitter is a protocol for publishing a dataset onto Ethereum and keeping it alive
indefinitely. It combines the cheapest way to get bytes onto Ethereum (EIP-4844 blobs, which the chain
itself deletes after a couple of weeks) with a permanent on-chain fingerprint of the
data and a bond-and-punishment scheme that makes independent storage providers
cryptographically accountable for keeping the real bytes.

It is dataset-agnostic: the protocol never interprets the data it persists. Anything
that can be serialized can be published.

## Motivation

Blobs made publishing data on Ethereum affordable, but they are deliberately ephemeral:
the chain discards blob contents after ~18 days. Anyone who wants the data after 18 days has to hope
they have access to a blob archive node.  Either running their own, paying for API access, or happening
to know someone with one.

Blobsitter adds an extra layer of data persistence.  Blobsitter allows anyone to easily host specific blob data instead of keeping all the blobs or blob contents.  These "data providers" subscribe to a certain data stream from a publisher and hold the bytes for longer term storage.  

- **Anyone can always verify data against the chain.** The contract maintains a rolling
   fingerprint of every chunk ever published. Given the data from *any* source (a provider,
   a mirror, a random torrent) anyone can check it byte-for-byte against the on-chain root.
- **Providers must keep proving they still have the bytes.**
   Random spot-checks (monthly proofs and open challenges) require
   producing real chunks at unpredictable positions. Fail, and the provider's bond is
   slashed.

## Roles

| Role | Who they are | What they do | Skin in the game |
|---|---|---|---|
| **Publisher** | The dataset's steward (typically a multisig) | Signs publication intents; controls *what* enters the dataset and nothing else | Reputation only — the publisher never holds or spends ETH |
| **Carrier** | Anyone with a wallet | Submits the publisher's signed intents to the chain as blob transactions | Fronts gas; reimbursed with a small tip by the paymaster |
| **Storage provider** | Independent operators | Keep the full dataset; answer challenges; prove custody monthly | A 2 ETH bond, slashed for failure |
| **Mirror** | Anyone | Announces "I also serve this data" — pure redundancy | None (and no protocol standing) |
| **Watchdog / challenger** | Anyone | Spot-checks a suspected provider by opening a challenge | A challenge bond, refunded (plus a slash bounty) if the suspicion was right |
| **Donor** | Anyone who wants the dataset to live | Sends ETH to the paymaster, funding carriers' costs | Reclaimable pro-rata if the dataset goes dormant |
| **Consumer** | Anyone who wants the data | Fetches from providers/mirrors and verifies against the on-chain root | None.  Verification is free reads |

## How it works, end to end

**Publishing.** The publisher signs a typed message describing an update: "append these
chunks; here are the blob fingerprints and the Merkle summaries." Any carrier wraps
that signature in a blob transaction. The contract checks the signature, checks the
transaction carries exactly the promised blobs, and verifies a succinct proof (a SNARK)
that the *blob bytes* and the *Merkle summaries* describe the same data. That proof
closes the gap between Ethereum's temporary view of the data and the contract's
permanent fingerprint: nothing can enter the dataset unless the bytes
behind both descriptions are identical. The fingerprint then updates, an event logs the
blob references for posterity, and the paymaster reimburses the carrier.

**Storing.** Providers watch the chain, pull each update's blobs during the window when
Ethereum still serves them, and keep the chunk stream forever. Staking is one
transaction: post 2 ETH, name a hot operator key (for day-to-day proving) and a cold
withdrawal address (the only place the stake can ever go — a stolen operator key can at
worst force an orderly exit, never steal the bond).

**Proving custody.** Every 30-day period, each provider commits to a fresh dose of
chain randomness, which deterministically selects 16,384 chunk positions unique to that
provider, that dataset, that month. The provider must prove possession of the real
bytes at those positions. Normally that's one small SNARK verified on-chain for cents;
if proving infrastructure is ever unavailable, a deliberately primitive **escape
hatch** accepts 32 raw chunks with plain Merkle proofs — nothing but hashes, so it
works even if every proving toolchain on earth bit-rots. Miss two consecutive months
and a grace period, and anyone may slash the provider for a bounty.

**Challenging.** Anyone who suspects a provider can post a challenge bond naming up to
32 chunk positions. The provider has 7 days to answer with the raw bytes and Merkle
proofs — keccak only, no SNARKs, forever. Answering wins the challenger's bond (it
funds the response gas); silence gets the provider slashed, with a bounty to the
challenger and the rest absorbed by the paymaster.

**Exiting.** A provider can always leave: announce unbonding, wait 14 days (during
which challenges against their *pre-exit* obligations still apply), withdraw the full
bond to the cold address. Slashing and exit are mutually exclusive by construction —
a bond is distributed exactly once.

**Funding.** The paymaster is a strictly dumb sidecar: donations in, carrier
reimbursements out (rate-limited by a spending allowance so even a catastrophic bug
can only leak slowly), slash remainders absorbed. If the dataset goes a full year
without meaningful growth, donors can reclaim their share pro-rata. It can never touch
the dataset, the stakes, or the proofs — and its failure never blocks publication.

## What you can rely on — and what you can't

**Guarantees**

- The contract is immutable: no admin keys, no upgrades, no pausing, no governance.
- Nothing enters the dataset without a validity proof tying blob bytes to the
  fingerprint.
- Data can always be verified against the chain by anyone, from any copy.
- Slashing-relevant response paths (challenge answers, the escape hatch) are plain
  keccak + calldata forever.  They cannot rot with any proving ecosystem.
- The stake only ever moves to the provider's cold withdrawal address, or through a
  slash. The publisher can never touch ETH; the paymaster can never touch the data.
- No trusted-setup ceremony was or will be run by or for this protocol — its proofs
  consume pre-existing public setups only.

**Non-guarantees:**

- A provider who passes every check might still *fetch* challenged chunks from a
  friend rather than storing them personally. The protocol proves the data is
  *retrievable and being maintained somewhere*, not who holds which disk. (This is why multiple
  independent providers and mirrors matter.)
- It is only guaranteed that providers have the data, not that they make it available.
- The protocol makes data abandonment expensive, detectable, and slow, not impossible.
- Liveness of *new* publications depends on the publisher key existing; the dataset's
  *persistence* does not.

## What's in this repo

| Path | What it is |
|---|---|
| `spec/` | The two governing documents: the design spec (*why*) and the normative spec (*exact byte-level what*), plus the contract test plan |
| `vectors/` | The byte-level ground truth vectors that every implementation (contracts, circuits, reference, generator) must reproduce independently |
| `reference/` | The Rust reference implementation of the protocol's primitives |
| `contracts/` | The Solidity contracts (Foundry): the immutable instance + its paymaster, with the full unit / invariant / fork-test suite |
| `circuits/` | The two SP1 zkVM programs (publication equivalence, custody) with native tests and measured benchmarks (`circuits/BENCHMARKS.md`) |
| `tools/` | Supporting generators (e.g. real KZG test fixtures) |

**Status:** contracts and circuits are implemented, extensively tested (golden-vector
conformance across four independent implementations, twenty named invariants in CI,
end-to-end runs with real proofs against real mainnet state on a fork), and measured —
but **not audited and not deployed**. Off-chain operational tooling (storage daemon,
carrier and publisher CLIs) is the next phase. Do not use this to persist anything you
love yet.

## Trying it

Developers can run everything locally with Rust and Foundry installed:

```bash
cargo test --workspace                          # reference implementation + vectors
cargo test --manifest-path circuits/Cargo.toml  # circuit logic, natively
cd contracts && forge test                      # full contract suite
```

## License

MIT — see `LICENSE`.
