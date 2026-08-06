//! The anvil integration harness (daemon test plan, Layer 2): anvil running the REAL
//! contract artifacts, declarations carried by REAL type-3 blob transactions, the mock
//! SP1 verifier planted at the template's pinned address (`anvil_setCode` — the same
//! trick the forge suite does with `vm.etch`), and a beacon-shaped blob server so the
//! daemon's production source adapter is what integration tests exercise. Every later
//! milestone (enforcement duties, carrier, publisher) drives its end-to-end scenarios
//! through this rig.

pub mod anvil;
pub mod beacon_stub;
pub mod declare;
