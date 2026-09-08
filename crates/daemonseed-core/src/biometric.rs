//! Biometric / secure-enclave session-passphrase storage — **scaffold only**
//! (ISC-C7, M10-completion).
//!
//! This module defines the *abstraction* a future GUI/mobile client uses to
//! offer biometric login: a [`BiometricStore`] trait that stores and retrieves
//! the **session passphrase** — never the BIP-39 mnemonic. The passphrase
//! decrypts the at-rest seeds blob (`storage::seeds`); the mnemonic is the
//! recovery root and must never leave the user's head / `.dseed` backup, so it
//! is deliberately absent from every signature here.
//!
//! ## What is NOT here (reserved to the future GUI/mobile client)
//!
//! No platform implementation ships. iOS Keychain, Android Keystore, the
//! Linux Secret Service, and any biometric-prompt UX live with the client that
//! actually holds a session and can prompt for a fingerprint/face — there is no
//! meaning to enclave storage without one. ISC-C7 in `ISA.md` stays open until
//! one does. This crate ships the trait, the typed secret and the mandatory
//! warning so wiring a real backend later is purely additive.

use zeroize::ZeroizeOnDrop;

/// The session passphrase — the **only** secret a [`BiometricStore`] may hold.
///
/// Wrapping it in a zeroizing newtype (rather than a bare `String`) is what
/// makes ISC-C7's "never the mnemonic" guarantee a type-level property: the
/// trait surface mentions `SessionPassphrase` and nothing else, so a backend
/// physically cannot be handed the recovery seed.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionPassphrase(String);

impl SessionPassphrase {
    /// Wrap a session passphrase.
    pub fn new(passphrase: impl Into<String>) -> Self {
        Self(passphrase.into())
    }

    /// Borrow the passphrase bytes for derivation / backend hand-off.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for SessionPassphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SessionPassphrase")
            .field(&"<redacted>")
            .finish()
    }
}

/// Failure modes a secure-enclave backend can surface.
#[derive(Debug)]
pub enum BiometricError {
    /// No enclave on this platform, or biometric unlock is not enrolled.
    Unavailable,
    /// Nothing is stored for this profile.
    NotFound,
    /// The platform backend returned an error (string is backend-specific).
    Backend(String),
}

impl core::fmt::Display for BiometricError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BiometricError::Unavailable => {
                write!(
                    f,
                    "secure enclave unavailable or biometric unlock not enrolled"
                )
            }
            BiometricError::NotFound => write!(f, "no session passphrase stored in the enclave"),
            BiometricError::Backend(e) => write!(f, "secure-enclave backend error: {e}"),
        }
    }
}

impl std::error::Error for BiometricError {}

/// Stores and retrieves the **session passphrase** in a platform secure enclave
/// for biometric login (ISC-C7). Opt-in; off by default
/// (`ProfileConfig::biometric_unlock`).
///
/// Implementations are provided by the platform-holding client, not by this
/// crate. The recovery seed (BIP-39 mnemonic) is intentionally not
/// representable here.
pub trait BiometricStore {
    /// Persist the session passphrase behind the platform's biometric gate.
    fn store(&self, passphrase: &SessionPassphrase) -> Result<(), BiometricError>;
    /// Retrieve the session passphrase after a successful biometric prompt.
    fn retrieve(&self) -> Result<SessionPassphrase, BiometricError>;
    /// Remove the stored passphrase (logout / disable biometric unlock).
    fn clear(&self) -> Result<(), BiometricError>;
}

/// Mandatory warning surfaced before a user opts into biometric unlock
/// (ISC-C7). Storing the session passphrase in the platform enclave shifts the
/// recovery-risk surface: an attacker who compromises the platform account /
/// device unlock can now reach the passphrase, and a lost device that only the
/// enclave could unlock means falling back to the `.dseed` + mnemonic recovery
/// path. The mnemonic is never stored — biometric unlock is a convenience over
/// the passphrase, not a replacement for the recovery seed.
pub const RECOVERY_RISK_WARNING: &str = "\
Biometric unlock stores your session passphrase in this device's secure \
enclave. This shifts your recovery risk to platform-account / device-unlock \
compromise: anyone who can unlock this device can decrypt your profile. Your \
recovery seed (the 24-word mnemonic) is never stored here — if you lose this \
device you must recover from your written-down seed and .dseed backup.";

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// In-test fake — stands in for a platform secure-enclave backend so the
    /// trait contract can be exercised without any OS dependency. The real
    /// platform impls (iOS Keychain / Android Keystore / …) are reserved to
    /// the future GUI/mobile client (ISC-C7 Reservation).
    #[derive(Default)]
    struct FakeEnclave {
        slot: RefCell<Option<String>>,
    }

    impl BiometricStore for FakeEnclave {
        fn store(&self, passphrase: &SessionPassphrase) -> Result<(), BiometricError> {
            *self.slot.borrow_mut() = Some(passphrase.expose().to_owned());
            Ok(())
        }
        fn retrieve(&self) -> Result<SessionPassphrase, BiometricError> {
            self.slot
                .borrow()
                .clone()
                .map(SessionPassphrase::new)
                .ok_or(BiometricError::NotFound)
        }
        fn clear(&self) -> Result<(), BiometricError> {
            *self.slot.borrow_mut() = None;
            Ok(())
        }
    }

    #[test]
    fn store_then_retrieve_round_trips_the_session_passphrase() {
        let enclave = FakeEnclave::default();
        enclave
            .store(&SessionPassphrase::new("correct horse battery staple"))
            .unwrap();
        let got = enclave.retrieve().unwrap();
        assert_eq!(got.expose(), "correct horse battery staple");
    }

    #[test]
    fn retrieve_after_clear_is_not_found() {
        let enclave = FakeEnclave::default();
        enclave.store(&SessionPassphrase::new("pw")).unwrap();
        enclave.clear().unwrap();
        assert!(matches!(enclave.retrieve(), Err(BiometricError::NotFound)));
    }

    #[test]
    fn retrieve_on_empty_store_is_not_found() {
        let enclave = FakeEnclave::default();
        assert!(matches!(enclave.retrieve(), Err(BiometricError::NotFound)));
    }

    #[test]
    fn session_passphrase_debug_is_redacted() {
        let dbg = format!("{:?}", SessionPassphrase::new("super-secret"));
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn recovery_risk_warning_names_the_risk_shift() {
        // ISC-C7: the warning must make the recovery-risk shift explicit.
        assert!(!RECOVERY_RISK_WARNING.is_empty());
        let w = RECOVERY_RISK_WARNING.to_ascii_lowercase();
        assert!(w.contains("recovery"));
        assert!(w.contains("passphrase"));
    }

    #[test]
    fn trait_is_object_safe() {
        // A future client holds whichever platform backend it built behind a
        // trait object; assert object-safety so that stays possible.
        let enclave = FakeEnclave::default();
        let _dyn: &dyn BiometricStore = &enclave;
    }
}
