//! At-rest storage — the three-layer split.
//!
//! - [`atomic_file`] (Amendment A9) — the durable atomic replacement every DM
//!   record write goes through: tmp sibling → fsync → rename → fsync parent,
//!   plus the `flock` used for cross-process exclusion. Distinct from the
//!   tmp+rename idiom elsewhere in this module, which is crash-atomic but not
//!   power-loss-durable.
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
//! - [`share_index`] (M8) — the redb-backed indexed-state layer: a persistent,
//!   incremental, per-value-encrypted index of a shared folder's files
//!   (ISC-C21 / A-C6 / A-C7).
//! - [`fetched`] (M15) — the persistent landing zone for *fetched* share
//!   content: a content-addressed store plus a manifest of explicit downloads,
//!   so a fetched share can be browsed and extracted after the fetch
//!   (ISC-C63 / C64 / C65, ISC-A-C31 / A-C32).
//! - [`manifest_digest`] (download-subsystem redesign, step 8) — a profile-local
//!   redb store mapping `share_id` → the confirmed manifest's SHA-384 digest, the
//!   trusted anchor a verified resume checks the staging manifest against
//!   (DL-ISC-20).

pub mod atomic_file;
pub mod cas;
pub mod fetched;
pub mod manifest_digest;
pub mod recovery_file;
pub mod seeds;
pub mod share_index;
