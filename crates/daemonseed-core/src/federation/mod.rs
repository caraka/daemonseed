//! Federation trust (M5) — the per-server trusted/untrusted slider and its
//! TOFU pin store.
//!
//! [`trust`] holds the pure decision core ([`trust::evaluate_trust`]) shared by
//! the client (ISC-C22) and server-to-server peering (ISC-S12). [`store`] holds
//! the [`store::TrustStore`] trait and an in-memory implementation that records
//! per-server trust mode, the TOFU pin, and the rotation-dismissal flag.
//!
//! Disk persistence of the pin store is deferred to a later client-identity
//! commit (mirrors M4b's decision D8 for the replay-counter state); M5 ships
//! the state machine the federation test matrix targets.

pub mod peering;
pub mod store;
pub mod trust;
