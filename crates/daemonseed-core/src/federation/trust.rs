//! The federation trust slider (ISC-C22, ISC-S12) — the pure decision core.
//!
//! [`evaluate_trust`] is a **total, side-effect-free** function: given a
//! server's configured trust mode and the key it just presented (proven
//! self-consistent by the identity-proof in M4b), it returns whether to
//! accept, accept-with-a-rotation-notice, or refuse. It performs no crypto and
//! touches no storage, so the same implementation backs both the client
//! (ISC-C22) and server-to-server peering (ISC-S12) — the single shared slider
//! ISC-S12 demands. The caller computes the one SHA-384 it needs
//! ([`crate::handle::Handle::from_pubkey`]) and hands the 12-hex prefix in.
//!
//! The two modes (ISC-C22):
//!
//! - **Trusted** — first contact verifies `SHA-384(presented)[:12]` against the
//!   configured server-id's hash prefix, then TOFU-pins the full key. Later
//!   connections compare against the pin; a changed key (operator rotation) is
//!   accepted but surfaces a non-blocking, per-server-dismissible notice. The
//!   first rotation always surfaces because `rotation_dismissed` starts false
//!   and can only be set after a notice has been shown.
//! - **Untrusted** — the full key must be pre-configured out-of-band and match
//!   byte-for-byte. Any mismatch — including a legitimate rotation — refuses
//!   until the user re-imports the new key. No TOFU, no rotation acceptance.
//!
//! Trust mode is local client/operator configuration; it is never transmitted,
//! so a server cannot tell which mode a peer is using (ISC-A-S6).

use crate::handle::HASH_PREFIX_BYTES;

/// Per-server federation trust mode (ISC-C22). Defaults to [`TrustMode::Trusted`]
/// for newly-added servers (ISC-C22 default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustMode {
    /// TOFU-on-first-contact against the server-id hash, accept rotation with a
    /// notice. Suitable for public community servers.
    #[default]
    Trusted,
    /// Pre-configured full key, byte-exact match required, rotation refused.
    /// Suitable for private/closed servers where MITM resistance dominates.
    Untrusted,
}

/// The outcome of [`evaluate_trust`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// Connection trusted. In trusted-mode first contact the caller must pin
    /// the presented key; a dismissed rotation also lands here and the caller
    /// still updates the pin.
    Accept,
    /// Trusted-mode operator rotation that has not been dismissed: accept and
    /// surface a non-blocking notice carrying the new key's fingerprint
    /// (ISC-C22). The caller updates the pin to the presented key.
    AcceptWithRotation {
        /// `#<12hex>` fingerprint of the newly-presented key (ISC-C22-8).
        fingerprint: String,
    },
    /// Refuse the connection: trusted-mode first-contact hash mismatch, an
    /// untrusted-mode key mismatch (including a legitimate rotation), or an
    /// untrusted entry with no pre-configured key. Fail-closed (ISC-45).
    Refuse,
}

/// Inputs to the trust slider. The caller assembles this from the configured
/// server entry plus the key the peer presented in its identity-proof.
pub struct TrustQuery<'a> {
    /// The configured trust mode for this server.
    pub mode: TrustMode,
    /// The configured server-id's 12-hex hash prefix (`SHA-384(key)[:12]`).
    pub expected_prefix: &'a [u8; HASH_PREFIX_BYTES],
    /// The full public key the peer presented (verified self-consistent by the
    /// identity-proof before trust evaluation runs).
    pub presented_pubkey: &'a [u8],
    /// `SHA-384(presented_pubkey)[:12]`, computed once by the caller.
    pub presented_prefix: &'a [u8; HASH_PREFIX_BYTES],
    /// The TOFU-pinned full key for this server, if first contact already
    /// happened (trusted mode). `None` means first contact.
    pub pinned_key: Option<&'a [u8]>,
    /// The out-of-band pre-configured full key (untrusted mode). `None` in
    /// untrusted mode is a misconfiguration and fails closed.
    pub configured_key: Option<&'a [u8]>,
    /// Whether the user has dismissed rotation notices for this server.
    pub rotation_dismissed: bool,
}

/// Decide whether to trust a peer presenting `presented_pubkey`, per ISC-C22 /
/// ISC-S12. Pure and total — see the module docs.
///
/// **This function IS the dialed-identity authority (A-C18).** First contact
/// (`pinned_key.is_none()`, trusted) binds to `expected_prefix`; an established
/// pin decides *continuity* against the pin (allowing a trusted-mode rotation,
/// which is the whole point — the identity-proof layer deliberately does NOT
/// re-gate on the server-id hash, so rotation reaches the notice path here);
/// untrusted requires the exact configured key. The caller must invoke this on
/// every connection and fail closed on `Refuse` — the identity-proof step alone
/// proves only envelope self-consistency, not "the peer I meant to reach".
pub fn evaluate_trust(q: &TrustQuery) -> TrustDecision {
    match q.mode {
        // Untrusted: the pre-configured key must match byte-for-byte. Any
        // mismatch — including a legitimate rotation — and a missing
        // configured key both fail closed (ISC-C22-12..14).
        TrustMode::Untrusted => match q.configured_key {
            Some(k) if k == q.presented_pubkey => TrustDecision::Accept,
            _ => TrustDecision::Refuse,
        },

        // Trusted: TOFU on first contact, pin-compare thereafter.
        TrustMode::Trusted => match q.pinned_key {
            // First contact: the presented key's hash prefix must match the
            // configured server-id (ISC-C22-3/4). The caller pins on Accept.
            None => {
                if q.presented_prefix == q.expected_prefix {
                    TrustDecision::Accept
                } else {
                    TrustDecision::Refuse
                }
            }
            // Established pin: accept silently when the key is unchanged or the
            // user has dismissed rotations for this server; otherwise an
            // operator rotation surfaces a notice (ISC-C22-6/7/11).
            Some(pin) => {
                if pin == q.presented_pubkey || q.rotation_dismissed {
                    TrustDecision::Accept
                } else {
                    TrustDecision::AcceptWithRotation {
                        fingerprint: fingerprint(q.presented_prefix),
                    }
                }
            }
        },
    }
}

/// Format a key's 12-hex prefix as the `#<12hex>` fingerprint used in rotation
/// notices (ISC-C22-8).
fn fingerprint(prefix: &[u8; HASH_PREFIX_BYTES]) -> String {
    format!("#{}", hex::encode(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinct fake keys. evaluate_trust does no crypto, so any byte vectors
    // work; the prefixes are independent inputs the caller would have computed.
    const KEY_A: &[u8] = &[0xAA; 32];
    const KEY_B: &[u8] = &[0xBB; 32];
    const PREFIX_A: [u8; HASH_PREFIX_BYTES] = [1, 2, 3, 4, 5, 6];
    const PREFIX_B: [u8; HASH_PREFIX_BYTES] = [7, 8, 9, 10, 11, 12];

    #[test]
    fn trusted_first_contact_matching_hash_accepts() {
        let q = TrustQuery {
            mode: TrustMode::Trusted,
            expected_prefix: &PREFIX_A,
            presented_pubkey: KEY_A,
            presented_prefix: &PREFIX_A,
            pinned_key: None,
            configured_key: None,
            rotation_dismissed: false,
        };
        assert_eq!(evaluate_trust(&q), TrustDecision::Accept);
    }

    #[test]
    fn trusted_first_contact_mismatched_hash_refuses() {
        // Presented key hashes to a prefix that is NOT the configured server-id.
        let q = TrustQuery {
            mode: TrustMode::Trusted,
            expected_prefix: &PREFIX_A,
            presented_pubkey: KEY_B,
            presented_prefix: &PREFIX_B,
            pinned_key: None,
            configured_key: None,
            rotation_dismissed: false,
        };
        assert_eq!(evaluate_trust(&q), TrustDecision::Refuse);
    }

    #[test]
    fn trusted_subsequent_matching_pin_accepts_silently() {
        let q = TrustQuery {
            mode: TrustMode::Trusted,
            expected_prefix: &PREFIX_A,
            presented_pubkey: KEY_A,
            presented_prefix: &PREFIX_A,
            pinned_key: Some(KEY_A),
            configured_key: None,
            rotation_dismissed: false,
        };
        assert_eq!(evaluate_trust(&q), TrustDecision::Accept);
    }

    #[test]
    fn trusted_rotation_not_dismissed_surfaces_notice() {
        // Pinned A, server now presents B (a different, self-consistent key).
        let q = TrustQuery {
            mode: TrustMode::Trusted,
            expected_prefix: &PREFIX_A,
            presented_pubkey: KEY_B,
            presented_prefix: &PREFIX_B,
            pinned_key: Some(KEY_A),
            configured_key: None,
            rotation_dismissed: false,
        };
        match evaluate_trust(&q) {
            TrustDecision::AcceptWithRotation { fingerprint } => {
                assert_eq!(fingerprint, format!("#{}", hex::encode(PREFIX_B)));
            }
            other => panic!("expected AcceptWithRotation, got {other:?}"),
        }
    }

    #[test]
    fn trusted_rotation_dismissed_accepts_silently() {
        let q = TrustQuery {
            mode: TrustMode::Trusted,
            expected_prefix: &PREFIX_A,
            presented_pubkey: KEY_B,
            presented_prefix: &PREFIX_B,
            pinned_key: Some(KEY_A),
            configured_key: None,
            rotation_dismissed: true,
        };
        assert_eq!(evaluate_trust(&q), TrustDecision::Accept);
    }

    #[test]
    fn untrusted_exact_match_accepts() {
        let q = TrustQuery {
            mode: TrustMode::Untrusted,
            expected_prefix: &PREFIX_A,
            presented_pubkey: KEY_A,
            presented_prefix: &PREFIX_A,
            pinned_key: None,
            configured_key: Some(KEY_A),
            rotation_dismissed: false,
        };
        assert_eq!(evaluate_trust(&q), TrustDecision::Accept);
    }

    #[test]
    fn untrusted_mismatch_refuses() {
        let q = TrustQuery {
            mode: TrustMode::Untrusted,
            expected_prefix: &PREFIX_A,
            presented_pubkey: KEY_B,
            presented_prefix: &PREFIX_B,
            pinned_key: None,
            configured_key: Some(KEY_A),
            rotation_dismissed: false,
        };
        assert_eq!(evaluate_trust(&q), TrustDecision::Refuse);
    }

    #[test]
    fn untrusted_legitimate_rotation_still_refuses() {
        // Untrusted mode refuses ANY change, even a legitimate operator
        // rotation, until the user re-imports the new key (ISC-C22-14).
        let q = TrustQuery {
            mode: TrustMode::Untrusted,
            expected_prefix: &PREFIX_A,
            presented_pubkey: KEY_B,
            presented_prefix: &PREFIX_B,
            pinned_key: None,
            configured_key: Some(KEY_A),
            rotation_dismissed: true, // even if rotation was dismissed elsewhere
        };
        assert_eq!(evaluate_trust(&q), TrustDecision::Refuse);
    }

    #[test]
    fn untrusted_without_configured_key_refuses() {
        // Untrusted requires a pre-configured key; absence fails closed.
        let q = TrustQuery {
            mode: TrustMode::Untrusted,
            expected_prefix: &PREFIX_A,
            presented_pubkey: KEY_A,
            presented_prefix: &PREFIX_A,
            pinned_key: None,
            configured_key: None,
            rotation_dismissed: false,
        };
        assert_eq!(evaluate_trust(&q), TrustDecision::Refuse);
    }

    #[test]
    fn trust_mode_default_is_trusted() {
        assert_eq!(TrustMode::default(), TrustMode::Trusted);
    }
}
