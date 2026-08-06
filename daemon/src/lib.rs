//! The storage daemon: the provider's protocol-critical agent. It follows L1, ingests
//! every declared blob, and maintains the canonical local chunk store that challenge
//! responses and custody proofs (later milestones) are served from.
//!
//! Two rules shape everything here:
//!
//! - Every protocol primitive (hashing, MMR, proofs, indices) comes from
//!   `blobsitter-reference` — this crate never reimplements one.
//! - The daemon treats every chunk as opaque bytes. Record parsing lives only in the
//!   crash-isolated materializer, a separate process in a separate crate; nothing
//!   app-layer may ever be imported here.

pub mod abi;
pub mod alarm;
pub mod config;
pub mod follower;
pub mod ingest;
pub mod source;
pub mod store;
pub mod verify;

/// Re-exported so daemon code and tests spell protocol types one way.
pub use blobsitter_reference::blob::BLOB_BYTES;
pub use blobsitter_reference::{Chunk, Hash};

/// A raw, UNVERIFIED blob as fetched from some source. Boxed: 128 KiB doesn't belong
/// on the stack.
pub type RawBlob = Box<[u8; BLOB_BYTES]>;
