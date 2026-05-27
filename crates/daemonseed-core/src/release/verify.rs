//! N-of-M multi-sig verification of release artifacts (ISC-S18 / ISC-A-C11).
//!
//! [`verify_multisig`] accepts an artifact iff at least the anchor's threshold
//! of **distinct** anchor keys each produced a valid ML-DSA-87 signature over
//! the same signed bytes. The design enforces the A-C11 hard-refusal rules
//! structurally:
//!
//! - **No verify-bypass.** A key counts toward quorum only when
//!   [`verify_signature`] returns `Ok` for it — there is no other path to mark
//!   a key satisfied.
//! - **Each key at most once.** Satisfied keys are tracked by their anchor
//!   index in a set, so a duplicated signature (the same key signing twice)
//!   cannot inflate the count toward quorum.
//! - **No non-anchor signatures.** A supplied signature that validates under no
//!   anchor key is a hard refusal (`UnrecognizedSignature`) — not silently
//!   ignored — matching A-C11's "signatures from keys not in the trust anchor
//!   are hard-refusals".
//! - **No panics on malformed input.** A signature blob of the wrong length is
//!   rejected (`MalformedSignature`) before any verify is attempted.
//!
//! The returned error distinguishes sub-causes because the result is consumed
//! **locally** — it feeds the A-C11 failure-log `(timestamp, channel, version,
//! reason)` tuple. It is never placed on the wire.

use std::collections::BTreeSet;

use oxicrypt_ml_dsa as ml_dsa;

use crate::identity::keys::{SignatureError, verify_signature};
use crate::release::anchor::ReleaseAnchor;

/// Why a release-artifact multi-sig verification failed. Local diagnostic only
/// — never serialized to the wire (the failure reason feeds the A-C11 at-rest
/// failure log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseVerifyError {
    /// Fewer than `required` distinct anchor keys produced a valid signature.
    BelowThreshold {
        /// The anchor's N-of-M threshold.
        required: u32,
        /// Distinct anchor keys that signed validly.
        valid: u32,
    },
    /// A supplied signature validated under no anchor key — a forged, tampered,
    /// or non-anchor-key signature. A hard refusal (A-C11), uniform across the
    /// sub-causes the verifier deliberately cannot distinguish.
    UnrecognizedSignature,
    /// A supplied signature blob was not ML-DSA-87 signature length.
    MalformedSignature,
    /// The oxicrypt module was unavailable, so verification could not run.
    Module,
}

/// Verify that `signatures` meet `anchor`'s N-of-M threshold over `message`.
///
/// Returns `Ok(())` iff at least `anchor.threshold()` distinct anchor keys each
/// produced a valid signature. See the module docs for the structural
/// guarantees. Every supplied signature must validate under some anchor key;
/// one that does not is a hard refusal (`UnrecognizedSignature`).
pub fn verify_multisig(
    anchor: &ReleaseAnchor,
    message: &[u8],
    signatures: &[&[u8]],
) -> Result<(), ReleaseVerifyError> {
    let mut satisfied: BTreeSet<usize> = BTreeSet::new();

    for sig_bytes in signatures {
        let sig: &[u8; ml_dsa::SIG_LEN] = (*sig_bytes)
            .try_into()
            .map_err(|_| ReleaseVerifyError::MalformedSignature)?;

        let mut matched: Option<usize> = None;
        for (i, key) in anchor.keys().iter().enumerate() {
            match verify_signature(key.public_key(), message, sig) {
                Ok(()) => {
                    matched = Some(i);
                    break;
                }
                // The module being down is not a forgery — surface it distinctly
                // rather than mislabelling a real signer's key as unrecognized.
                Err(SignatureError::Module(_)) => return Err(ReleaseVerifyError::Module),
                Err(SignatureError::BadSignature) => continue,
            }
        }

        match matched {
            Some(i) => {
                satisfied.insert(i);
            }
            None => return Err(ReleaseVerifyError::UnrecognizedSignature),
        }
    }

    let valid = satisfied.len() as u32;
    if valid >= anchor.threshold() {
        Ok(())
    } else {
        Err(ReleaseVerifyError::BelowThreshold {
            required: anchor.threshold(),
            valid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::SignKeypair;
    use crate::release::anchor::{ReleaseAnchor, ReleaseKey};

    fn kp(seed_byte: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed_byte; 32]).unwrap()
    }

    fn anchor_of(keypairs: &[&SignKeypair], threshold: u32) -> ReleaseAnchor {
        let keys = keypairs
            .iter()
            .map(|k| ReleaseKey::new(*k.public_key()))
            .collect();
        ReleaseAnchor::new(keys, threshold).unwrap()
    }

    const MSG: &[u8] = b"daemonseed-server v0.12.0 release manifest digest";

    #[test]
    fn accepts_one_of_one_quorum() {
        let k = kp(1);
        let anchor = anchor_of(&[&k], 1);
        let sig = k.sign(MSG).unwrap();
        assert_eq!(verify_multisig(&anchor, MSG, &[&sig]), Ok(()));
    }

    #[test]
    fn accepts_two_of_three_quorum() {
        let (a, b, c) = (kp(1), kp(2), kp(3));
        let anchor = anchor_of(&[&a, &b, &c], 2);
        let sa = a.sign(MSG).unwrap();
        let sc = c.sign(MSG).unwrap();
        // Two distinct anchor keys (a, c) sign → meets 2-of-3.
        assert_eq!(verify_multisig(&anchor, MSG, &[&sa, &sc]), Ok(()));
    }

    #[test]
    fn accepts_when_more_than_threshold_sign() {
        let (a, b, c) = (kp(1), kp(2), kp(3));
        let anchor = anchor_of(&[&a, &b, &c], 2);
        let s = [
            a.sign(MSG).unwrap(),
            b.sign(MSG).unwrap(),
            c.sign(MSG).unwrap(),
        ];
        let refs: Vec<&[u8]> = s.iter().map(|x| x.as_slice()).collect();
        assert_eq!(verify_multisig(&anchor, MSG, &refs), Ok(()));
    }

    #[test]
    fn rejects_below_threshold() {
        let (a, b) = (kp(1), kp(2));
        let anchor = anchor_of(&[&a, &b], 2);
        let sa = a.sign(MSG).unwrap();
        // Only one of two required keys signed.
        assert_eq!(
            verify_multisig(&anchor, MSG, &[&sa]),
            Err(ReleaseVerifyError::BelowThreshold {
                required: 2,
                valid: 1
            })
        );
    }

    #[test]
    fn rejects_signature_from_non_anchor_key() {
        let anchor_key = kp(1);
        let stranger = kp(99); // not in the anchor
        let anchor = anchor_of(&[&anchor_key], 1);
        let bad = stranger.sign(MSG).unwrap();
        assert_eq!(
            verify_multisig(&anchor, MSG, &[&bad]),
            Err(ReleaseVerifyError::UnrecognizedSignature)
        );
    }

    #[test]
    fn counts_a_duplicated_key_only_once() {
        // The same anchor key signs twice; threshold is 2. Distinct-key counting
        // means this is still only 1 toward quorum — a duplicated signature
        // cannot manufacture a quorum (ISC-A-C11).
        let (a, b) = (kp(1), kp(2));
        let anchor = anchor_of(&[&a, &b], 2);
        let sa1 = a.sign(MSG).unwrap();
        let sa2 = a.sign(MSG).unwrap();
        assert_eq!(
            verify_multisig(&anchor, MSG, &[&sa1, &sa2]),
            Err(ReleaseVerifyError::BelowThreshold {
                required: 2,
                valid: 1
            })
        );
    }

    #[test]
    fn rejects_malformed_signature_length_without_panic() {
        let k = kp(1);
        let anchor = anchor_of(&[&k], 1);
        let too_short: &[u8] = b"not a real ml-dsa-87 signature";
        assert_eq!(
            verify_multisig(&anchor, MSG, &[too_short]),
            Err(ReleaseVerifyError::MalformedSignature)
        );
    }

    #[test]
    fn rejects_valid_signature_over_tampered_message() {
        let k = kp(1);
        let anchor = anchor_of(&[&k], 1);
        let sig = k.sign(MSG).unwrap();
        let tampered = b"daemonseed-server v0.12.0 release manifest digest (EVIL)";
        // The signature is well-formed but does not validate over the tampered
        // bytes → no anchor key matches → hard refusal.
        assert_eq!(
            verify_multisig(&anchor, tampered, &[&sig]),
            Err(ReleaseVerifyError::UnrecognizedSignature)
        );
    }

    #[test]
    fn empty_signature_set_is_below_threshold() {
        let k = kp(1);
        let anchor = anchor_of(&[&k], 1);
        assert_eq!(
            verify_multisig(&anchor, MSG, &[]),
            Err(ReleaseVerifyError::BelowThreshold {
                required: 1,
                valid: 0
            })
        );
    }
}
