//! Identity primitives — mnemonic, HKDF-rooted key derivation, identity
//! enumeration (Primary / Device / Anonymous per ISC-C13).
//!
//! M1 ships [`mnemonic`] (BIP-39); HKDF-derived ML-DSA-87 + ML-KEM-1024
//! keypairs and the `Identity` enum land in commit 5 (the kdf::info module
//! pins the load-bearing info strings first).

pub mod keys;
pub mod mnemonic;
