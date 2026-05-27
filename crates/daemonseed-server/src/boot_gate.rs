//! Server release boot-gate (ISC-A-S13).
//!
//! [`gate_boot`] is the decision the server makes about its own binary at
//! startup: it maps the result of verifying the running binary's release
//! signatures (against the bundled [`ReleaseAnchor`], via
//! [`daemonseed_core::release::verify_multisig`]) to exactly one of two
//! outcomes — [`BootDecision::Boot`] or [`BootDecision::RefuseToBoot`].
//!
//! ## ISC-A-S13 invariants, structurally enforced
//!
//! - **No boot-with-warning.** [`BootDecision`] has no third variant. A failed
//!   verification is *always* `RefuseToBoot` — "refusal is the only acceptable
//!   response to a failed-verify binary, never boot anyway with a warning."
//! - **No server-side validation when relaying.** The optional update-relay
//!   role (ISC-S18) — when it is built — serves artifacts read-only and MUST
//!   NOT verify, gate, or refuse them: the trust anchor lives exclusively in
//!   the downloading client (ISC-A-C11). That role is **deliberately not built
//!   here**, so there is no relay-serve function that takes a verify step to
//!   accidentally gate. This boot-gate concerns *the server's own binary*, not
//!   artifacts it might relay — the two are kept apart by construction.
//! - **No self-install.** The running server never modifies its own binary on
//!   disk; upgrades are operator-initiated (package manager / container
//!   restart). There is no self-update code path in this crate to invoke.
//!
//! ## Wiring is deferred (M10-infra)
//!
//! At the pre-public phase the bundled release anchor carries no real key
//! (`daemonseed_core::release::bundled().to_anchor()` is `None`) and the binary
//! carries no embedded release signature yet — both land with the signing-key
//! ceremony and the reproducible-build pipeline. So this decision function is
//! intentionally **not** called from real startup yet; it is the logic those
//! deferred pieces will call once a binary can actually present its signatures.

use daemonseed_core::release::{ReleaseAnchor, ReleaseVerifyError, verify_multisig};

/// The startup decision for the server's own release binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootDecision {
    /// The running binary's signatures met the anchor threshold — boot.
    Boot,
    /// Verification failed — refuse to boot. The operator must explicitly
    /// install a binary whose release signature validates. There is
    /// deliberately no "boot anyway" path (ISC-A-S13). Carries the local
    /// failure reason for the operator-facing log only.
    RefuseToBoot(ReleaseVerifyError),
}

/// Map a release-signature verification result to a boot decision. `Ok` boots;
/// **any** error refuses — there is no boot-with-warning outcome (ISC-A-S13).
pub fn gate_boot(verify_result: Result<(), ReleaseVerifyError>) -> BootDecision {
    match verify_result {
        Ok(()) => BootDecision::Boot,
        Err(reason) => BootDecision::RefuseToBoot(reason),
    }
}

/// Verify the running binary's `signatures` over its signed-bytes `message`
/// against `anchor`, then gate. The digest computation and the binary-embedded
/// signatures are M10-infra; this is the decision logic they will call.
pub fn gate_boot_with(
    anchor: &ReleaseAnchor,
    message: &[u8],
    signatures: &[&[u8]],
) -> BootDecision {
    gate_boot(verify_multisig(anchor, message, signatures))
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::identity::keys::SignKeypair;
    use daemonseed_core::release::{ReleaseAnchor, ReleaseKey};

    fn kp(seed_byte: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed_byte; 32]).unwrap()
    }

    #[test]
    fn boots_on_ok() {
        assert_eq!(gate_boot(Ok(())), BootDecision::Boot);
    }

    #[test]
    fn refuses_on_every_error_variant_never_boots() {
        // ISC-A-S13: a failed verify is ALWAYS RefuseToBoot. Enumerate every
        // ReleaseVerifyError variant and confirm none yields Boot — there is no
        // boot-with-warning third outcome.
        let variants = [
            ReleaseVerifyError::BelowThreshold {
                required: 2,
                valid: 1,
            },
            ReleaseVerifyError::UnrecognizedSignature,
            ReleaseVerifyError::MalformedSignature,
            ReleaseVerifyError::Module,
        ];
        for e in variants {
            assert_eq!(gate_boot(Err(e)), BootDecision::RefuseToBoot(e));
            assert_ne!(gate_boot(Err(e)), BootDecision::Boot);
        }
    }

    #[test]
    fn gate_boot_with_boots_on_valid_signature() {
        let k = kp(1);
        let anchor = ReleaseAnchor::new(vec![ReleaseKey::new(*k.public_key())], 1).unwrap();
        let msg = b"daemonseed-server binary digest";
        let sig = k.sign(msg).unwrap();
        assert_eq!(gate_boot_with(&anchor, msg, &[&sig]), BootDecision::Boot);
    }

    #[test]
    fn gate_boot_with_refuses_tampered_binary() {
        let k = kp(1);
        let anchor = ReleaseAnchor::new(vec![ReleaseKey::new(*k.public_key())], 1).unwrap();
        let sig = k.sign(b"original binary digest").unwrap();
        // A different (tampered) digest under the same signature does not verify.
        match gate_boot_with(&anchor, b"tampered binary digest", &[&sig]) {
            BootDecision::RefuseToBoot(_) => {}
            BootDecision::Boot => panic!("a tampered binary must never boot"),
        }
    }
}
