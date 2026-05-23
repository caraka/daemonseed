//! daemonseed-core — protocol library.
//!
//! Identity primitives, profile substrate, and crypto plumbing for the
//! daemonseed client and server. M1 lands the foundational pieces — handle
//! format, BIP-39 mnemonic, HKDF-derived ML-DSA-87 / ML-KEM-1024 keypairs,
//! at-rest blob storage. M4a+ adds wire-protocol surface on top.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod first_start;
pub mod handle;
pub mod identity;
pub mod kdf;
pub mod passphrase;
pub mod profile;
pub mod storage;
