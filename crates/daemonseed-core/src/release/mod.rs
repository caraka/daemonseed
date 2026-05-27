//! Release-signing trust anchor and N-of-M multi-sig verification (ISC-S18 /
//! ISC-A-S13 / ISC-C27 / ISC-A-C11, M10).
//!
//! This module holds the **verifiable core** of the M10 release/update story:
//! the binary-bound [`ReleaseAnchor`] (the set of release-signing ML-DSA-87
//! keys + the N-of-M threshold) and [`verify_multisig`], the pure function that
//! decides whether a set of signatures over a release artifact meets the
//! anchor's threshold. The server's boot-gate (ISC-A-S13) and the client's
//! update lifecycle (ISC-C27 / ISC-A-C11) both build on this verify.
//!
//! ## What is deliberately *not* here (deferred M10-infra)
//!
//! The real release signing keys, the Sigstore co-signature check, the
//! reproducible-build pipeline, the app-store / F-Droid / OS-packager channels,
//! the N-of-M governance key-holder identities, and the live HTTPS / update-
//! relay fetch are infrastructure, accounts, and a key ceremony — not pure
//! logic — and are out of scope for this module. The anchor ships its 1-of-1
//! shape unpopulated so that landing those is additive (see
//! [`anchor`]'s pre-public-phase note).

mod anchor;
mod verify;

pub use anchor::{AnchorError, BundledReleaseAnchor, ReleaseAnchor, ReleaseKey, bundled};
pub use verify::{ReleaseVerifyError, verify_multisig};
