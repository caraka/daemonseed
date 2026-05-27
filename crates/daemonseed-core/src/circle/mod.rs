//! Circle-of-trust types (ISC-C8 / ISC-C9 / ISC-A-C8).
//!
//! **Scope: client-only.** Circles in daemonseed are anonymous to the
//! server per ISC-A-S2 — the federation surface never sees which circles
//! exist, who is a member, or any per-circle parameters in cleartext.
//!
//! **Circles are flat and metadata-free** (F16, resolved 2026-05-26). A
//! circle is defined solely by its shared entropy: there is no founder, no
//! signed circle-metadata record, and no per-circle minimum-suite policy.
//! The shared phrase is both the sole circle secret and the sole
//! distinguisher — see [`key::derive_cot_key`]. The suite floor is enforced
//! at the server (the S16 deprecation policy) plus the client-local
//! registry, never at circle level; a cross-family crypto change is the
//! circle-rekey / new-circle event of ISC-A-C8, expressed structurally by
//! the family-anchored key derivation rather than a stored record. Circle
//! names are client-local labels only.

pub mod key;
pub mod message;
