//! At-rest storage — encrypted seeds blob (ISC-C3), recovery file
//! (ISC-C32), and (eventually) the redb-backed indexed-state DB (M8).
//!
//! M1 ships [`seeds`] (AEAD-protected mnemonic + future per-circle state).
//! M2 adds [`recovery_file`] — the same KDF chain with a distinct HKDF
//! info string and a cleartext header carrying the profile-id + argon2
//! params so recovery on a clean device works without a pre-existing
//! `daemonseed.toml`.

pub mod recovery_file;
pub mod seeds;
