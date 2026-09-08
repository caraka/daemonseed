//! Server-to-server peering helpers (ISC-S12).
//!
//! The trust decision itself is shared with the client via
//! [`super::trust::evaluate_trust`]. This module holds the one piece unique to
//! symmetric peering: the concurrent-TOFU tiebreaker (ISC-S12-8).
//!
//! When two servers configured to trust each other connect simultaneously,
//! both could try to TOFU-pin the other at the same instant, racing toward a
//! split-brain where each pins a different in-flight key. The tiebreaker makes
//! the race deterministic: the server whose server-id hash-prefix sorts lower
//! **initiates** the TOFU; the higher one **observes and confirms**. Exactly
//! one side initiates, so there is a single authority for the pin.

use crate::handle::HASH_PREFIX_BYTES;

/// Whether this server initiates the TOFU handshake against a peer, per the
/// tiebreaker (ISC-S12-8). The lexicographically-lower server-id hash
/// prefix initiates; the other observes-and-confirms. Deterministic and
/// antisymmetric — for two distinct prefixes exactly one side returns `true`.
pub fn initiates_peer_tofu(
    own_prefix: &[u8; HASH_PREFIX_BYTES],
    peer_prefix: &[u8; HASH_PREFIX_BYTES],
) -> bool {
    own_prefix < peer_prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOW: [u8; HASH_PREFIX_BYTES] = [0, 0, 0, 0, 0, 1];
    const HIGH: [u8; HASH_PREFIX_BYTES] = [0, 0, 0, 0, 0, 2];

    #[test]
    fn lower_prefix_initiates() {
        assert!(initiates_peer_tofu(&LOW, &HIGH));
    }

    #[test]
    fn higher_prefix_observes() {
        assert!(!initiates_peer_tofu(&HIGH, &LOW));
    }

    #[test]
    fn exactly_one_side_initiates() {
        // Antisymmetry: across the pair, exactly one initiates — no split brain.
        assert_ne!(
            initiates_peer_tofu(&LOW, &HIGH),
            initiates_peer_tofu(&HIGH, &LOW)
        );
    }

    #[test]
    fn equal_prefix_does_not_initiate() {
        // Equal prefixes mean the same server (or a 48-bit collision); neither
        // initiates against itself.
        assert!(!initiates_peer_tofu(&LOW, &LOW));
    }
}
