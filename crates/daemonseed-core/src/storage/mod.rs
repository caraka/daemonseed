//! At-rest storage — the three-layer split.
//!
//! - [`seeds`] (M1, ISC-C3) — the AEAD-protected mnemonic + per-circle state
//!   blob.
//! - [`recovery_file`] (M2, ISC-C32) — the same KDF chain with a distinct
//!   HKDF info string and a cleartext header carrying the profile-id + argon2
//!   params, so recovery on a clean device works without a pre-existing
//!   `daemonseed.toml`.
//! - [`cas`] (M8) — the content-addressed chunk store: opaque encrypted
//!   chunks named by `SHA-384`, reference-counted, in an ephemeral in-memory
//!   form (the relay backing) and a persistent on-disk form (the client
//!   cache).
//!
//! The redb-backed indexed-state DB (share index, M8+) layers on top of these.

pub mod cas;
pub mod recovery_file;
pub mod seeds;
