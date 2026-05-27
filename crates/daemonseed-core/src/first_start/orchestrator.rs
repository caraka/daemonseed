//! First-start state machine (ISC-C29 / C30 / A-C13 / A-C14 / A-C15).
//!
//! See [`super`] module docs for the phase diagram. This file holds the
//! state types and the transitions; type-back challenge logic lives in
//! [`super::verify`] to keep the orchestrator focused.

use core::marker::PhantomData;

use uuid::Uuid;

use crate::bootstrap::BootstrapAnchor;
use crate::first_start::verify::TypeBackChallenge;
use crate::handle::Handle;
use crate::handle::display_name::{DisplayNameRng, is_valid_display_name};
use crate::identity::keys::{Identity, derive_identity_keys};
use crate::identity::mnemonic::{Mnemonic, MnemonicError};
use crate::passphrase::strength::{Strength, estimate};
use crate::profile::config::{ArgonParams, ProfileConfig, ProfileConfigError};
use crate::storage::recovery_file::{self, RecoveryFileError};
use crate::storage::seeds::{self, BlobError, Seeds};

// ── Phase markers ────────────────────────────────────────────────────────

/// Initial phase — caller can drive [`FirstStart::new`] but cannot extract
/// anything until `FirstStart::<Welcome>::initialize` runs.
pub enum Welcome {}

/// Phase after passphrase + mnemonic + blob + recovery-file are all
/// sealed in memory. Caller still needs to verify backup before moving on.
pub enum Sealed {}

/// Phase after backup verification (either round-trip C33 or type-back C34)
/// has succeeded. Mnemonic has been zeroed; the recovery file is the only
/// remaining out-of-RAM copy.
pub enum BackupVerified {}

/// Terminal phase — display-name + bootstrap-relay chosen. The caller
/// extracts [`SessionMaterials`] and hands them to the wire layer (M4a+).
pub enum Ready {}

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors surfaced by first-start transitions. Each variant maps to a
/// specific phase boundary so the caller can route UX (re-prompt for
/// passphrase, re-roll mnemonic, etc.).
#[derive(Debug)]
pub enum FirstStartError {
    /// Passphrase failed the ISC-C12 strength gate. `bits` is the
    /// zxcvbn-estimated entropy; `required` is the green threshold.
    PassphraseTooWeak { bits: f64, required: f64 },
    /// BIP-39 mnemonic generation failed (CSPRNG / parsing).
    Mnemonic(MnemonicError),
    /// At-rest blob seal failed.
    BlobSeal(BlobError),
    /// Recovery file seal/open failed.
    RecoveryFile(RecoveryFileError),
    /// Deriving the identity keypair / handle from the fresh mnemonic failed.
    /// Unreachable in practice — the crypto module is operational by this point
    /// (the at-rest blob seal above already exercised it) — but the derivation
    /// returns a `Result`, so the failure is surfaced rather than unwrapped.
    IdentityDerivation(String),
    /// Round-trip backup verification (C33) failed: the saved phrase the
    /// user supplied does not match the just-generated mnemonic.
    BackupRoundTripMismatch,
    /// Type-back backup verification (C34) failed: at least one supplied
    /// word does not match the expected position.
    TypeBackMismatch,
    /// User-supplied display name failed [`is_valid_display_name`].
    InvalidDisplayName,
    /// Internal: profile config could not be (de)serialized for handoff.
    Config(ProfileConfigError),
}

impl core::fmt::Display for FirstStartError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FirstStartError::PassphraseTooWeak { bits, required } => write!(
                f,
                "passphrase entropy {bits:.1} bits below required {required:.1}"
            ),
            FirstStartError::Mnemonic(e) => write!(f, "mnemonic: {e}"),
            FirstStartError::BlobSeal(e) => write!(f, "at-rest blob: {e}"),
            FirstStartError::RecoveryFile(e) => write!(f, "recovery file: {e}"),
            FirstStartError::BackupRoundTripMismatch => write!(
                f,
                "round-trip verify: saved phrase does not match generated mnemonic"
            ),
            FirstStartError::TypeBackMismatch => {
                write!(f, "type-back verify: at least one answer is incorrect")
            }
            FirstStartError::InvalidDisplayName => {
                write!(
                    f,
                    "display name: empty, too long, or contains forbidden characters"
                )
            }
            FirstStartError::Config(e) => write!(f, "profile config: {e}"),
            FirstStartError::IdentityDerivation(e) => {
                write!(f, "identity derivation: {e}")
            }
        }
    }
}

impl std::error::Error for FirstStartError {}

// ── State container ──────────────────────────────────────────────────────

/// Materials accumulated across the phases. Held privately; per-phase
/// methods expose only what's appropriate for that phase.
struct Inner {
    profile_config: ProfileConfig,
    // None after backup verification — mnemonic zeroes when dropped.
    mnemonic: Option<Mnemonic>,
    blob_bytes: Vec<u8>,
    recovery_file_bytes: Vec<u8>,
    display_name: Option<String>,
    bootstrap: Option<BootstrapAnchor>,
    // Floor handle (no display name yet) derived from the identity key during
    // `initialize`, while the mnemonic is still present. None until then. The
    // chosen display name is attached at `into_session_materials` (the mnemonic
    // is already zeroed by that phase, so the handle cannot be re-derived later
    // — it must be computed and stashed up front).
    identity_handle: Option<Handle>,
}

/// Type-state first-start state machine. `S` is the phase marker.
pub struct FirstStart<S> {
    inner: Inner,
    _state: PhantomData<S>,
}

// ── Welcome ──────────────────────────────────────────────────────────────

impl FirstStart<Welcome> {
    /// Construct a fresh state machine. No side effects; the actual work
    /// happens in [`Self::initialize`] when the user has chosen a
    /// passphrase.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // Construct a placeholder profile_config; it gets replaced by a
        // freshly-generated one in `initialize`. We can't construct `Inner`
        // without one because `ProfileConfig` is non-optional.
        let placeholder = ProfileConfig::new_for_first_start(ArgonParams::desktop_default());
        Self {
            inner: Inner {
                profile_config: placeholder,
                mnemonic: None,
                blob_bytes: Vec::new(),
                recovery_file_bytes: Vec::new(),
                display_name: None,
                bootstrap: None,
                identity_handle: None,
            },
            _state: PhantomData,
        }
    }

    /// Execute C29 steps 1–3 atomically:
    /// - Validate passphrase against the C12 strength gate.
    /// - Generate a fresh 24-word BIP-39 mnemonic (C2).
    /// - Create a `ProfileConfig` with a fresh UUID v4 (C36) and the
    ///   supplied Argon2 params (C14).
    /// - Seal the at-rest blob (C3) and the recovery file (C32) using a
    ///   single shared Argon2id intermediate (C30).
    ///
    /// The passphrase is dropped after this method returns; it is never
    /// stored across the phase boundary.
    pub fn initialize(
        self,
        passphrase: &str,
        argon2_params: ArgonParams,
    ) -> Result<FirstStart<Sealed>, FirstStartError> {
        // (C12) strength gate.
        let strength: Strength = estimate(passphrase);
        if !strength.is_session_green() {
            return Err(FirstStartError::PassphraseTooWeak {
                bits: strength.bits,
                required: crate::passphrase::strength::SESSION_PASSPHRASE_MIN_BITS,
            });
        }

        // (C2) fresh mnemonic.
        let mnemonic = Mnemonic::generate().map_err(FirstStartError::Mnemonic)?;

        // (C4 / C2) derive the identity's floor handle now, while the mnemonic
        // is present — it is zeroed after backup verification, so the handle
        // (SHA-384 of the ML-DSA-87 public key) cannot be re-derived later. The
        // chosen display name is attached at `into_session_materials`. Uses the
        // canonical `derive_identity_keys` path so the handle matches the one
        // the rest of the system derives from the same mnemonic.
        let identity_handle = {
            let keys = derive_identity_keys(&mnemonic, Identity::Primary)
                .map_err(|e| FirstStartError::IdentityDerivation(e.to_string()))?;
            Handle::from_pubkey(None, keys.signing.public_key())
                .map_err(|e| FirstStartError::IdentityDerivation(e.to_string()))?
        };

        // (C36 / C14) fresh profile config.
        let profile_config = ProfileConfig::new_for_first_start(argon2_params);

        // (C3) at-rest blob.
        let seeds = Seeds::new(mnemonic.clone());
        let blob_bytes = seeds::seal(
            &seeds,
            passphrase,
            profile_config.profile_id,
            profile_config.argon2,
        )
        .map_err(FirstStartError::BlobSeal)?;

        // (C32 / C30) recovery file under the same passphrase, distinct
        // HKDF info string (handled by `recovery_file::seal`).
        let recovery_file_bytes = recovery_file::seal(
            &mnemonic,
            passphrase,
            profile_config.profile_id,
            profile_config.argon2,
        )
        .map_err(FirstStartError::RecoveryFile)?;

        Ok(FirstStart {
            inner: Inner {
                profile_config,
                mnemonic: Some(mnemonic),
                blob_bytes,
                recovery_file_bytes,
                display_name: None,
                bootstrap: None,
                identity_handle: Some(identity_handle),
            },
            _state: PhantomData,
        })
    }
}

// ── Sealed ───────────────────────────────────────────────────────────────

impl FirstStart<Sealed> {
    /// Return the 24-word BIP-39 mnemonic for copy-friendly display
    /// (ISC-C31). Available only in this phase — once backup-verify
    /// succeeds, the mnemonic is dropped.
    ///
    /// The returned `String` carries the same secret material as the
    /// mnemonic itself; treat it identically (no logs, no Debug output,
    /// drop the binding ASAP).
    pub fn display_phrase(&self) -> String {
        self.inner
            .mnemonic
            .as_ref()
            .expect("Sealed phase always holds the mnemonic")
            .to_phrase()
    }

    /// Build a type-back challenge for the ISC-C34 skip-recovery path.
    /// The challenge is one-shot; re-issuing produces fresh positions.
    pub fn issue_type_back_challenge<R: DisplayNameRng>(&self, rng: &mut R) -> TypeBackChallenge {
        let phrase = self.display_phrase();
        TypeBackChallenge::new(&phrase, rng)
    }

    /// Bytes the caller writes to `<profile-root>/identity.dseed` (ISC-C32).
    /// Same in `Sealed` and `BackupVerified`; exposed early so the file can
    /// be written before round-trip verify reads it back.
    pub fn recovery_file_bytes(&self) -> &[u8] {
        &self.inner.recovery_file_bytes
    }

    /// Round-trip verify (ISC-C33). The caller passes the phrase the user
    /// re-typed (or the phrase decrypted from the just-written `.dseed`
    /// file) and we compare it to the generated mnemonic. Match → advance
    /// to [`BackupVerified`]; mismatch → caller can retry from `Sealed`.
    pub fn verify_round_trip(
        self,
        saved_phrase: &str,
    ) -> Result<FirstStart<BackupVerified>, FirstStartError> {
        let expected = self
            .inner
            .mnemonic
            .as_ref()
            .expect("Sealed phase always holds the mnemonic")
            .to_phrase();
        if !phrases_match(&expected, saved_phrase) {
            return Err(FirstStartError::BackupRoundTripMismatch);
        }
        Ok(self.into_verified())
    }

    /// Type-back verify (ISC-C34). The caller answers a challenge issued
    /// by [`Self::issue_type_back_challenge`]. Match → advance to
    /// [`BackupVerified`].
    pub fn verify_type_back(
        self,
        challenge: TypeBackChallenge,
        answers: &[String],
    ) -> Result<FirstStart<BackupVerified>, FirstStartError> {
        if !challenge.matches(answers) {
            return Err(FirstStartError::TypeBackMismatch);
        }
        Ok(self.into_verified())
    }

    fn into_verified(mut self) -> FirstStart<BackupVerified> {
        // Drop the mnemonic — `Option::take` consumes it; `Mnemonic`'s
        // ZeroizeOnDrop fires when the binding goes out of scope.
        let _ = self.inner.mnemonic.take();
        FirstStart {
            inner: self.inner,
            _state: PhantomData,
        }
    }
}

// ── BackupVerified ───────────────────────────────────────────────────────

impl FirstStart<BackupVerified> {
    /// Bytes the caller writes to `<profile-root>/seeds.blob` (ISC-C3).
    pub fn at_rest_blob_bytes(&self) -> &[u8] {
        &self.inner.blob_bytes
    }

    /// Bytes the caller writes to `<profile-root>/identity.dseed` (ISC-C32),
    /// same value as in [`Sealed`].
    pub fn recovery_file_bytes(&self) -> &[u8] {
        &self.inner.recovery_file_bytes
    }

    /// Finalize first-start. Validates `display_name` against ISC-C4b
    /// rules (empty allowed → floor handle, else `is_valid_display_name`).
    /// `bootstrap` is the user's choice from the two ISC-C37 paths
    /// (canonical bundled OR manual paste); supplying `None` is forbidden
    /// per ISC-A-C19 and surfaces as a compile-time signature mismatch
    /// (the argument is non-`Option`).
    pub fn finalize(
        mut self,
        display_name: Option<String>,
        bootstrap: BootstrapAnchor,
    ) -> Result<FirstStart<Ready>, FirstStartError> {
        if let Some(name) = display_name.as_deref()
            && !is_valid_display_name(name)
        {
            return Err(FirstStartError::InvalidDisplayName);
        }
        self.inner.display_name = display_name;
        self.inner.bootstrap = Some(bootstrap);
        Ok(FirstStart {
            inner: self.inner,
            _state: PhantomData,
        })
    }
}

// ── Ready ────────────────────────────────────────────────────────────────

impl FirstStart<Ready> {
    /// Profile UUID v4 (ISC-C36).
    pub fn profile_id(&self) -> Uuid {
        self.inner.profile_config.profile_id
    }

    /// `daemonseed.toml` body the caller writes to `<profile-root>/daemonseed.toml`.
    pub fn config_toml(&self) -> Result<String, FirstStartError> {
        self.inner
            .profile_config
            .to_toml()
            .map_err(FirstStartError::Config)
    }

    /// At-rest seeds blob bytes (ISC-C3) — write to `<profile-root>/seeds.blob`.
    pub fn at_rest_blob_bytes(&self) -> &[u8] {
        &self.inner.blob_bytes
    }

    /// `.dseed` recovery file bytes (ISC-C32) — write to `<profile-root>/identity.dseed`.
    pub fn recovery_file_bytes(&self) -> &[u8] {
        &self.inner.recovery_file_bytes
    }

    /// Consume self into the materials the wire layer (M4a+) opens with.
    pub fn into_session_materials(self) -> SessionMaterials {
        // Attach the chosen display name to the handle derived during
        // `initialize` (the mnemonic is gone by now, so the hash prefix comes
        // from the stashed floor handle, never re-derived).
        let display_name = self.inner.display_name;
        let handle = self
            .inner
            .identity_handle
            .expect("initialize always derives the identity handle")
            .with_display_name(display_name.clone());
        SessionMaterials {
            profile_config: self.inner.profile_config,
            at_rest_blob_bytes: self.inner.blob_bytes,
            recovery_file_bytes: self.inner.recovery_file_bytes,
            display_name,
            handle,
            bootstrap: self
                .inner
                .bootstrap
                .expect("Ready phase always holds bootstrap"),
        }
    }
}

// ── SessionMaterials ─────────────────────────────────────────────────────

/// Outputs of a completed first-start, ready for the caller to persist to
/// the profile root and hand off to the wire layer (M4a+).
#[derive(Debug)]
pub struct SessionMaterials {
    pub profile_config: ProfileConfig,
    pub at_rest_blob_bytes: Vec<u8>,
    pub recovery_file_bytes: Vec<u8>,
    pub display_name: Option<String>,
    /// The daemon's own handle (`name#hash`), with the chosen display name
    /// attached to the hash derived from the identity key. The full handle the
    /// client uses for self-@mention detection (ISC-C17) and as its chat sender
    /// identity — distinct from `display_name`, which is just the name part.
    pub handle: Handle,
    pub bootstrap: BootstrapAnchor,
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Compare two mnemonic phrases for equality, tolerating whitespace
/// differences. Both sides are split on whitespace and lowercased.
fn phrases_match(a: &str, b: &str) -> bool {
    let a_norm: Vec<String> = a.split_whitespace().map(|w| w.to_lowercase()).collect();
    let b_norm: Vec<String> = b.split_whitespace().map(|w| w.to_lowercase()).collect();
    a_norm == b_norm
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_oxicrypt() {
        let _ = oxicrypt_module::initialize();
    }

    fn fast_params() -> ArgonParams {
        ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    const STRONG_PASSPHRASE: &str = "correct horse battery staple table mountain";

    fn placeholder_anchor() -> BootstrapAnchor {
        BootstrapAnchor {
            server_id: "test-server#aabbccddeeff".to_string(),
            address: "127.0.0.1".to_string(),
        }
    }

    // ── happy path ────────────────────────────────────────────────────────

    #[test]
    fn happy_path_round_trip_completes() {
        init_oxicrypt();
        let fs = FirstStart::<Welcome>::new();
        let sealed = fs.initialize(STRONG_PASSPHRASE, fast_params()).unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let ready = verified
            .finalize(Some("alice".to_string()), placeholder_anchor())
            .unwrap();
        let materials = ready.into_session_materials();
        assert_eq!(materials.display_name.as_deref(), Some("alice"));
        assert!(!materials.at_rest_blob_bytes.is_empty());
        assert!(!materials.recovery_file_bytes.is_empty());
    }

    #[test]
    fn happy_path_type_back_completes() {
        init_oxicrypt();
        let fs = FirstStart::<Welcome>::new();
        let sealed = fs.initialize(STRONG_PASSPHRASE, fast_params()).unwrap();

        // Build a deterministic RNG for the challenge so we can predict
        // which words will be asked for.
        struct R(Vec<usize>, usize);
        impl DisplayNameRng for R {
            fn random_index(&mut self, len: usize) -> usize {
                let v = self.0[self.1] % len;
                self.1 += 1;
                v
            }
        }
        let mut rng = R(vec![0, 5, 10], 0);
        let challenge = sealed.issue_type_back_challenge(&mut rng);

        let phrase = sealed.display_phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let answers: Vec<String> = challenge
            .positions()
            .iter()
            .map(|p| words[*p].to_string())
            .collect();

        let verified = sealed.verify_type_back(challenge, &answers).unwrap();
        let _ready = verified.finalize(None, placeholder_anchor()).unwrap();
    }

    // ── gates ────────────────────────────────────────────────────────────

    #[test]
    fn rejects_weak_passphrase() {
        init_oxicrypt();
        let fs = FirstStart::<Welcome>::new();
        match fs.initialize("password", fast_params()) {
            Err(FirstStartError::PassphraseTooWeak { .. }) => {}
            Ok(_) => panic!("expected PassphraseTooWeak, got Ok(FirstStart<Sealed>)"),
            Err(other) => panic!("expected PassphraseTooWeak, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_rejects_wrong_phrase() {
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let bogus = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        match sealed.verify_round_trip(bogus) {
            Err(FirstStartError::BackupRoundTripMismatch) => {}
            // Vanishingly small chance the random mnemonic happens to be
            // the all-zeros canonical vector — accept the happy path too.
            Ok(_) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn type_back_rejects_wrong_answers() {
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        struct R;
        impl DisplayNameRng for R {
            fn random_index(&mut self, len: usize) -> usize {
                0 % len
            }
        }
        let challenge = sealed.issue_type_back_challenge(&mut R);
        let wrong: Vec<String> = (0..challenge.len()).map(|_| "wrong".to_string()).collect();
        match sealed.verify_type_back(challenge, &wrong) {
            Err(FirstStartError::TypeBackMismatch) => {}
            Ok(_) => panic!("expected TypeBackMismatch error, got Ok"),
            Err(other) => panic!("expected TypeBackMismatch, got {other:?}"),
        }
    }

    #[test]
    fn finalize_rejects_invalid_display_name() {
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        match verified.finalize(Some("name#with#hash".to_string()), placeholder_anchor()) {
            Err(FirstStartError::InvalidDisplayName) => {}
            Ok(_) => panic!("expected InvalidDisplayName error, got Ok"),
            Err(other) => panic!("expected InvalidDisplayName, got {other:?}"),
        }
    }

    #[test]
    fn finalize_accepts_empty_display_name() {
        // Per ISC-C4b — empty display name is allowed; the daemon defaults
        // to floor-handle presentation.
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let ready = verified.finalize(None, placeholder_anchor()).unwrap();
        let m = ready.into_session_materials();
        assert!(m.display_name.is_none());
    }

    // ── invariants ───────────────────────────────────────────────────────

    #[test]
    fn recovery_file_decrypts_with_same_passphrase() {
        // The recovery file the orchestrator generates must round-trip
        // through `recovery_file::open` with the same passphrase — that's
        // the entire point of C32 / C33.
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let bytes = sealed.recovery_file_bytes().to_vec();
        let phrase = sealed.display_phrase();
        let contents = recovery_file::open(&bytes, STRONG_PASSPHRASE).unwrap();
        assert_eq!(contents.mnemonic.to_phrase(), phrase);
    }

    #[test]
    fn at_rest_blob_opens_under_same_passphrase() {
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let pid = verified.inner.profile_config.profile_id;
        let argon = verified.inner.profile_config.argon2;
        let blob = verified.at_rest_blob_bytes().to_vec();
        let opened = seeds::open(&blob, STRONG_PASSPHRASE, pid, argon).unwrap();
        assert_eq!(opened.seeds.mnemonic.to_phrase(), phrase);
    }

    #[test]
    fn ready_into_materials_carries_bootstrap() {
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let anchor = placeholder_anchor();
        let ready = verified
            .finalize(Some("alice".to_string()), anchor.clone())
            .unwrap();
        let m = ready.into_session_materials();
        assert_eq!(m.bootstrap, anchor);
    }

    /// The materials carry the daemon's own handle: the chosen display name is
    /// attached, and the hash prefix is a real (non-zero) identity-key hash
    /// derived from the mnemonic — the full `name#hash` the client uses as its
    /// chat sender identity and for self-@mention detection (ISC-C4 / C17).
    #[test]
    fn materials_carry_identity_handle_with_display_name() {
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let ready = verified
            .finalize(Some("alice".to_string()), placeholder_anchor())
            .unwrap();
        let m = ready.into_session_materials();

        assert_eq!(m.handle.display_name(), Some("alice"));
        assert!(!m.handle.is_floor(), "handle has a display name");
        // The hash prefix is a real SHA-384 of the identity pubkey, not zeros.
        assert_ne!(
            m.handle.hash_prefix(),
            &[0u8; crate::handle::HASH_PREFIX_BYTES]
        );
        // The wire form is `alice#<12hex>`.
        let wire = m.handle.to_string();
        assert!(wire.starts_with("alice#"), "wire form: {wire}");
        assert_eq!(
            wire.len(),
            "alice#".len() + crate::handle::HASH_PREFIX_HEX_CHARS
        );
    }

    /// An empty display name yields a floor handle (`#<hash>`) but still carries
    /// the real identity-key hash (ISC-C4b floor case).
    #[test]
    fn materials_floor_handle_when_no_display_name() {
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let ready = verified.finalize(None, placeholder_anchor()).unwrap();
        let m = ready.into_session_materials();
        assert!(m.handle.is_floor());
        assert!(m.handle.to_string().starts_with('#'));
    }
}
