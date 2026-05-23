//! At-rest storage — encrypted seeds blob (ISC-C3) and (eventually) the
//! redb-backed indexed-state DB (M8).
//!
//! M1 ships [`seeds`] only — the AEAD-protected blob holding the
//! mnemonic. Future commits expand `Seeds` to also carry circle-of-trust
//! seed material, mute/hide lists, and settings (ISC-C8, ISC-C15-C19);
//! the blob format reserves a version byte so additions land additively.

pub mod seeds;
