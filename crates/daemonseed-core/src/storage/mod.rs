//! At-rest storage — the three-layer split.
//!
//! - `atomic_file` (Amendment A9) — the durable atomic replacement every DM
//!   record write goes through: tmp sibling → fsync → rename → fsync parent,
//!   plus the `flock` used for cross-process exclusion. Distinct from the
//!   tmp+rename idiom elsewhere in this module, which is crash-atomic but not
//!   power-loss-durable.
//! - [`dm_store`] (#286, Amendment A9) — the DM record store built over
//!   `atomic_file`: one directory per correspondence, one fixed-size sealed
//!   file per record kind, and a lock that brackets the whole read-modify-write
//!   because both halves live on the guard it hands out.
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

// The module is crate-internal — a second door onto a correspondence's directory
// with none of the store's path-derivation, lock, fixed-size or sealing discipline
// on it. The three types below are re-exported because [`dm_store::DmStoreError`]
// embeds them: a caller that receives `Write { source }` or `Lock(_)` must be able
// to name what it caught, and `FileLock` is public for the reason its own doc gives.
pub(crate) mod atomic_file;
pub use atomic_file::{AtomicReplaceError, FileLock, LockError};

pub mod cas;
pub mod dm_store;
pub mod fetched;
pub mod manifest_digest;
pub mod recovery_file;
pub mod seeds;
pub mod share_index;
