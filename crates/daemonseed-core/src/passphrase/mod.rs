//! Passphrase analysis + generation.
//!
//! - [`strength`]: zxcvbn-based estimator that gates session-passphrase
//!   acceptance (ISC-C12, ≥60 bits) and circle-of-trust entropy
//!   acceptance (ISC-C9, ≥128 bits) with one shared estimator and two
//!   thresholds. Includes a diceware-style generator that produces
//!   guaranteed-green session passphrases from BIP-39 wordlist sampling.
//! - [`circle_canonicalize`]: NFKC + whitespace canonicalization for
//!   circle-of-trust entropy text inputs (ISC-C9), used both before
//!   strength estimation and before HKDF salt construction so the same
//!   "looking" input produces the same key.

pub mod circle_canonicalize;
pub mod strength;
