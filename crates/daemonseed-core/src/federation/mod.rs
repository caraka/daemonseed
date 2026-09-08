//! Federation trust — the per-server trusted/untrusted slider and its
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
//!
//! [`discovered`] (M12, gate step 6) holds the introducer-discovered peer
//! cache: candidates learned from a relay's introducer that are NEVER
//! auto-added to the active trust set — the user promotes them explicitly
//! (ISC-C22 / ISC-A-C19).

pub mod discovered;
pub mod peering;
pub mod store;
pub mod trust;
