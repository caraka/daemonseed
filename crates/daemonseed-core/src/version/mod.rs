//! Wire-protocol version negotiation policy.
//!
//! Per ISC-S14 / A-S9 / C23, daemonseed peers exchange `APP_HELLO` /
//! `APP_HELLO_ACK` / `APP_HELLO_REJECT` after the TLS 1.3 handshake to
//! pin a SemVer MAJOR.MINOR version for the lifetime of the connection.
//! PATCH is deliberately absent from the wire — release-artifact
//! concern, not negotiation surface.
//!
//! The wire shape lives in [`daemonseed_proto::v1::ProtocolVersion`]
//! (as proto3 `uint32 major; uint32 minor`). The in-memory shape here
//! is `u16` because protocol versions never exceed 65,535 in any
//! realistic timeline and the narrower type prevents silently carrying
//! garbage from a malformed peer. The wire→core conversion via
//! [`ProtocolVersion::try_from_wire`] enforces the narrowing.
//!
//! **Invariant 2** in the daemonseed implementation plan:
//! wire in `daemonseed_proto::v1::app_hello`, **policy in
//! `daemonseed_core::version`** (this module).

use core::fmt;

use daemonseed_proto::v1 as wire;

// ── Wire-shape negotiation type ──────────────────────────────────

/// In-memory SemVer MAJOR.MINOR. The wire shape is proto3 `uint32`;
/// this narrower form is what the policy layer manipulates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProtocolVersion {
    /// SemVer MAJOR. Breaking-change bumps only.
    pub major: u16,
    /// SemVer MINOR. Additive-only bumps per ISC-S14.
    pub minor: u16,
}

impl ProtocolVersion {
    /// Construct from MAJOR + MINOR. Both must fit in `u16`.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Convert from the wire-shape proto message. Returns
    /// [`VersionError::OutOfRange`] if either field exceeds `u16::MAX`
    /// (which only a malformed peer should ever produce).
    pub fn try_from_wire(w: &wire::ProtocolVersion) -> Result<Self, VersionError> {
        let major = u16::try_from(w.major).map_err(|_| VersionError::OutOfRange {
            field: "major",
            value: w.major,
        })?;
        let minor = u16::try_from(w.minor).map_err(|_| VersionError::OutOfRange {
            field: "minor",
            value: w.minor,
        })?;
        Ok(Self { major, minor })
    }

    /// Convert to the wire-shape proto message.
    pub const fn to_wire(self) -> wire::ProtocolVersion {
        wire::ProtocolVersion {
            major: self.major as u32,
            minor: self.minor as u32,
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ── Supported set ────────────────────────────────────────────────

/// The set of wire-protocol versions this build implements. MVP ships
/// exactly one entry — `1.0`. Future MINOR bumps append new entries
/// (additive-only per ISC-S14); MAJOR bumps replace the set entirely.
pub const SUPPORTED: &[ProtocolVersion] = &[ProtocolVersion::new(1, 0)];

// ── Negotiation policy ───────────────────────────────────────────

/// Outcomes of failing to negotiate a version.
#[derive(Debug, PartialEq, Eq)]
pub enum NegotiationError {
    /// No version in the peer's offer intersects with our [`SUPPORTED`]
    /// set. Senders include the peer's full offer so the receiver can
    /// surface an actionable upgrade-or-downgrade message.
    NoCommonVersion {
        /// The peer's complete offer, exactly as received.
        peer_supported: alloc::vec::Vec<ProtocolVersion>,
    },

    /// The responder's selected version was not present in our offer
    /// — a protocol violation per ISC-A-S9 (server-side) and ISC-C23
    /// (client-side). The connection MUST close without proceeding
    /// to identity-proof.
    OutOfSetAck {
        /// The version the responder claimed to select.
        claimed: ProtocolVersion,
    },

    /// `APP_HELLO` arrived as TLS 1.3 early data. 0-RTT is structurally
    /// excluded from MVP per ISC-A-S9; surfacing this discriminator
    /// gives the responder a named close-reason.
    ZeroRttForbidden,

    /// Wire-shape narrowing failed because the peer sent a
    /// `ProtocolVersion` field larger than `u16::MAX`. Logged but
    /// otherwise treated the same as `NoCommonVersion` (a peer that
    /// can't even round-trip our type can't share a wire version).
    MalformedPeerOffer(VersionError),
}

/// Errors translating between the proto wire shape and the in-memory
/// shape. Surface in `MalformedPeerOffer`.
#[derive(Debug, PartialEq, Eq)]
pub enum VersionError {
    /// A wire-side `uint32` exceeded `u16::MAX`.
    OutOfRange {
        /// `"major"` or `"minor"`.
        field: &'static str,
        /// The offending value (proto-side, before narrowing).
        value: u32,
    },
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { field, value } => {
                write!(f, "wire ProtocolVersion.{field}={value} exceeds u16::MAX")
            }
        }
    }
}

impl core::error::Error for VersionError {}

/// Version negotiation policy. Both client and server implement it;
/// the difference is whether the local set is the initiator's *offer*
/// (client) or the responder's *supported* (server). The trait is
/// parametric in that "which set is mine" sense.
pub trait VersionNegotiator {
    /// The local supported-version set, in preference order
    /// (highest first).
    fn offer(&self) -> &[ProtocolVersion];

    /// Pick the highest version present in both `self.offer()` and the
    /// peer's `peer_offer`. Returns `NoCommonVersion` (carrying the
    /// peer's full list, exactly as received) if the intersection is
    /// empty.
    fn select(&self, peer_offer: &[ProtocolVersion]) -> Result<ProtocolVersion, NegotiationError> {
        // Iterate our offer in its declared preference order; first
        // match wins. This keeps the policy deterministic without
        // depending on the peer's preference order beyond "is the
        // version offered at all."
        for ours in self.offer() {
            if peer_offer.iter().any(|theirs| theirs == ours) {
                return Ok(*ours);
            }
        }
        Err(NegotiationError::NoCommonVersion {
            peer_supported: peer_offer.to_vec(),
        })
    }

    /// Validate a responder's selected `ack` against our offer. Used
    /// client-side (ISC-C23) and on the responder side as a sanity
    /// check before sending. Returns `OutOfSetAck` if the responder
    /// selected something we never offered.
    fn verify_ack(&self, ack: ProtocolVersion) -> Result<(), NegotiationError> {
        if self.offer().contains(&ack) {
            Ok(())
        } else {
            Err(NegotiationError::OutOfSetAck { claimed: ack })
        }
    }
}

/// The MVP negotiator — offers exactly [`SUPPORTED`]. Both client and
/// server use this until per-side preference logic (post-MVP) requires
/// custom impls.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultNegotiator;

impl VersionNegotiator for DefaultNegotiator {
    fn offer(&self) -> &[ProtocolVersion] {
        SUPPORTED
    }
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn v(major: u16, minor: u16) -> ProtocolVersion {
        ProtocolVersion::new(major, minor)
    }

    #[test]
    fn supported_has_exactly_one_version_for_mvp() {
        assert_eq!(SUPPORTED, &[v(1, 0)]);
    }

    #[test]
    fn select_picks_highest_mutual() {
        // Custom negotiator with two versions to make the "highest
        // mutual" property visible; default has only 1.0 so the choice
        // is trivial there.
        const TWO_VERSION_OFFER: &[ProtocolVersion] =
            &[ProtocolVersion::new(2, 0), ProtocolVersion::new(1, 0)];
        struct TwoVersion;
        impl VersionNegotiator for TwoVersion {
            fn offer(&self) -> &[ProtocolVersion] {
                TWO_VERSION_OFFER
            }
        }

        let chosen = TwoVersion
            .select(&[v(1, 0), v(2, 0)])
            .expect("intersection non-empty");
        assert_eq!(
            chosen,
            v(2, 0),
            "highest mutual wins regardless of peer order"
        );
    }

    #[test]
    fn select_returns_no_common_with_full_peer_list() {
        let peer = vec![v(2, 0), v(2, 1), v(3, 0)];
        let err = DefaultNegotiator
            .select(&peer)
            .expect_err("no overlap with MVP's [1.0]");
        match err {
            NegotiationError::NoCommonVersion { peer_supported } => {
                assert_eq!(peer_supported, peer, "full peer list preserved verbatim");
            }
            other => panic!("expected NoCommonVersion, got {other:?}"),
        }
    }

    #[test]
    fn verify_ack_rejects_out_of_set() {
        let err = DefaultNegotiator
            .verify_ack(v(2, 0))
            .expect_err("2.0 is not in MVP's offer");
        assert_eq!(err, NegotiationError::OutOfSetAck { claimed: v(2, 0) });
    }

    #[test]
    fn verify_ack_accepts_in_set() {
        DefaultNegotiator
            .verify_ack(v(1, 0))
            .expect("1.0 is in MVP's offer");
    }

    #[test]
    fn wire_round_trip_preserves_value() {
        let original = v(1, 0);
        let wire = original.to_wire();
        let back = ProtocolVersion::try_from_wire(&wire).expect("u16 fits in u32");
        assert_eq!(back, original);
    }

    #[test]
    fn try_from_wire_rejects_out_of_u16_range() {
        let wire = wire::ProtocolVersion {
            major: u32::from(u16::MAX) + 1,
            minor: 0,
        };
        let err = ProtocolVersion::try_from_wire(&wire).expect_err("major out of range");
        assert_eq!(
            err,
            VersionError::OutOfRange {
                field: "major",
                value: u32::from(u16::MAX) + 1,
            }
        );
    }
}
