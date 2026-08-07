//! Re-export of the shared contract-ABI crate, kept at the daemon's old module path
//! so existing imports (`crate::abi::Blobsitter`) stay valid. The single
//! transcription lives in `abi/` — see that crate for why there is exactly one.

pub use blobsitter_abi::Blobsitter;
