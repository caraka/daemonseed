//! daemonseed-core — protocol library.
//!
//! Identity primitives, profile substrate, and crypto plumbing for the
//! daemonseed client and server. M1 lands the foundational pieces — handle
//! format, BIP-39 mnemonic, HKDF-derived ML-DSA-87 / ML-KEM-1024 keypairs,
//! at-rest blob storage. M4a adds the wire-protocol negotiation policy
//! ([`version`]) and the type-state [`connection::Connection`] machine
//! that gates pre-auth traffic at compile time per ISC-C23. M6 adds
//! [`public_space`] — the signed-artifact model (content-address,
//! signer whitelist, ML-DSA-87 verification) the server and clients share
//! for the post-Authenticated public-space service. M8 adds the circle path:
//! [`circle::key`] (shared-entropy key derivation), [`cot`] (rendezvous
//! addressing), and [`storage::cas`] (the content-addressed chunk store).

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod circle;
pub mod connection;
pub mod cot;
pub mod crypto;
pub mod federation;
pub mod first_start;
pub mod handle;
pub mod identity;
pub mod identity_proof;
pub mod kdf;
pub mod passphrase;
pub mod profile;
pub mod public_space;
pub mod storage;
pub mod trust_events;
pub mod version;
