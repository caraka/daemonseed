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

use crate::cot::AssetAddr;
use crate::handle::display_name::{DisplayNameRng, generate_display_name};

/// Derive a stable, client-local `adj-noun` display label for a circle from its
/// rendezvous [`AssetAddr`]. Deterministic — the same address always yields the same
/// label, so a re-join is recognisable — while the label never leaves the client and
/// is derived only from the public rendezvous address, never from members or the
/// secret phrase (ISC-A-S2: circles are anonymous to the server and metadata-free, F16).
///
/// This is the canonical home shared by the TUI and the GUI; neither reimplements it.
/// An `adj-noun` pair indexed by the address bytes is the default; `#circle` is the
/// fallback only if the address is empty, keeping this total without an `unwrap`.
pub fn default_circle_label(asset_addr: &AssetAddr) -> String {
    /// Deterministic index source: folds the address bytes (wrapping) so the chosen
    /// `(adjective, noun)` pair is a pure function of the rendezvous.
    struct AddrRng<'a> {
        bytes: &'a [u8],
        cursor: usize,
    }
    impl DisplayNameRng for AddrRng<'_> {
        fn random_index(&mut self, len: usize) -> usize {
            // Fold 8 address bytes into a u64, advancing the cursor; modulo the
            // wordlist length. Deterministic and stable for a given address.
            let mut acc = 0u64;
            for _ in 0..8 {
                let b = self.bytes[self.cursor % self.bytes.len()];
                self.cursor += 1;
                acc = (acc << 8) | b as u64;
            }
            (acc % len as u64) as usize
        }
    }

    let bytes = asset_addr.as_bytes();
    if bytes.is_empty() {
        return "#circle".to_owned();
    }
    let mut rng = AddrRng { bytes, cursor: 0 };
    generate_display_name(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::AssetAddr;

    #[test]
    fn default_circle_label_is_deterministic_per_address() {
        let a = AssetAddr::from_bytes([7u8; crate::cot::ASSET_ADDR_LEN]);
        let b = AssetAddr::from_bytes([7u8; crate::cot::ASSET_ADDR_LEN]);
        let c = AssetAddr::from_bytes([9u8; crate::cot::ASSET_ADDR_LEN]);
        // Same address → same label (recognisable re-join).
        assert_eq!(default_circle_label(&a), default_circle_label(&b));
        // Different addresses → (almost surely) different labels.
        assert_ne!(default_circle_label(&a), default_circle_label(&c));
        // It is an adj-noun form, not a `#hex` fallback.
        assert!(default_circle_label(&a).contains('-'));
        assert!(!default_circle_label(&a).starts_with('#'));
    }
}
