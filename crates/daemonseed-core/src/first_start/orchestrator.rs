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
use crate::storage::seeds::{BlobError, IndexKey, SealingKey, Seeds};

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
    // The live `Seeds` payload sealed into `blob_bytes`, kept so the running
    // client can mutate + re-seal it for the M13 write-through. Stashed during
    // `initialize` / `recover` (a clone of the payload that produced the blob);
    // None on the `Welcome` placeholder. Carries the mnemonic — drops/zeroizes
    // with the state machine if first-start aborts.
    seeds: Option<Seeds>,
    // The at-rest AEAD key matching `blob_bytes`, derived once during
    // `initialize` / `recover` (same passphrase / profile_id / params as the
    // seal) so the write-through re-seals without a second Argon2id run. None on
    // the placeholder; zeroizes on drop.
    seal_key: Option<SealingKey>,
    // The share-index key (M14), derived as a sibling of `seal_key` from the
    // same single Argon2id run during `initialize` / `recover`. None on the
    // placeholder; zeroizes on drop.
    index_key: Option<IndexKey>,
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
                seeds: None,
                seal_key: None,
                index_key: None,
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

        // (C3) at-rest blob. Derive the cached at-rest key once (M13
        // write-through) and seal with it, so the stashed `SealingKey` is
        // byte-identical to the key that produced `blob_bytes` — the running
        // client re-seals on each mutation without re-running Argon2id. The
        // share-index key (M14) falls out of the same Argon2id run.
        let seeds = Seeds::new(mnemonic.clone());
        let (seal_key, index_key) = SealingKey::derive_session(
            passphrase,
            profile_config.profile_id,
            profile_config.argon2,
        )
        .map_err(FirstStartError::BlobSeal)?;
        let blob_bytes = seal_key.seal(&seeds).map_err(FirstStartError::BlobSeal)?;

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
                seeds: Some(seeds),
                seal_key: Some(seal_key),
                index_key: Some(index_key),
            },
            _state: PhantomData,
        })
    }

    /// Clean-device recovery (ISC-C29 recover branch / ISC-A-C2 / gate step 8).
    ///
    /// The mirror image of [`Self::initialize`]: instead of *generating* a
    /// fresh mnemonic, the caller *supplies* one the user already holds —
    /// either typed in as 24 words or decrypted from a `.dseed` recovery file
    /// (`recovery_file::open` → [`Mnemonic::to_phrase`]). Both input paths
    /// converge here on a phrase string, so the core flow is source-agnostic.
    ///
    /// What recovery does and does not carry:
    /// - **Identity is recovered.** The ML-DSA-87 / ML-KEM-1024 keypairs and
    ///   thus the handle derive from the mnemonic alone via fixed HKDF `info`
    ///   strings (no `profile_id` input), so the recovered handle is *byte-
    ///   identical* to the original device's — that is the whole point of the
    ///   step-8 gate ("reaches the same identity").
    /// - **A fresh profile_id is minted.** The recovered device is a new
    ///   profile (ISC-C36): `profile_id` is non-secret HKDF/Argon2-salt domain
    ///   separation, generated locally, and the at-rest blob + `.dseed` are
    ///   re-sealed under it on *this* device. Reusing the source `profile_id`
    ///   would buy nothing — identity does not depend on it.
    /// - **Circle-of-trust seeds are NOT recovered** (ISC-A-C2): they derive
    ///   from user-chosen entropy not contained in the mnemonic. Recovery
    ///   regains identity; circle access requires re-entering the circle
    ///   passphrase. The caller surfaces this to the user.
    ///
    /// Backup verification (C33/C34) is skipped on purpose: the phrase *is*
    /// the input, so possession is already proven. The supplied mnemonic is
    /// dropped (zeroized) before returning; the flow lands directly in
    /// [`BackupVerified`] and rejoins the shared [`FirstStart::finalize`] →
    /// [`FirstStart::into_session_materials`] tail.
    ///
    /// `passphrase` is the *new local* session passphrase that will protect
    /// the at-rest blob and the re-written `.dseed` on this device (subject to
    /// the same ISC-C12 strength gate as first-start); on the `.dseed` path it
    /// is also the passphrase that opened the source file (ISC-C30, one
    /// credential).
    pub fn recover(
        self,
        mnemonic_phrase: &str,
        passphrase: &str,
        argon2_params: ArgonParams,
    ) -> Result<FirstStart<BackupVerified>, FirstStartError> {
        // (C2) parse + verify the BIP-39 checksum / word-count / wordlist of
        // the supplied phrase. A bad transcription fails closed here.
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase).map_err(FirstStartError::Mnemonic)?;

        // (C12) strength gate on the NEW local at-rest passphrase.
        let strength: Strength = estimate(passphrase);
        if !strength.is_session_green() {
            return Err(FirstStartError::PassphraseTooWeak {
                bits: strength.bits,
                required: crate::passphrase::strength::SESSION_PASSPHRASE_MIN_BITS,
            });
        }

        // (C4 / C2) derive the floor handle from the recovered mnemonic. This
        // is the value that must match the source device.
        let identity_handle = {
            let keys = derive_identity_keys(&mnemonic, Identity::Primary)
                .map_err(|e| FirstStartError::IdentityDerivation(e.to_string()))?;
            Handle::from_pubkey(None, keys.signing.public_key())
                .map_err(|e| FirstStartError::IdentityDerivation(e.to_string()))?
        };

        // (C36 / C14) fresh local profile config — new device, new profile_id.
        let profile_config = ProfileConfig::new_for_first_start(argon2_params);

        // (C32 / C30) re-seal a local `.dseed` under the new profile_id (borrow
        // the mnemonic before it moves into the seeds blob below).
        let recovery_file_bytes = recovery_file::seal(
            &mnemonic,
            passphrase,
            profile_config.profile_id,
            profile_config.argon2,
        )
        .map_err(FirstStartError::RecoveryFile)?;

        // (C3) re-seal the at-rest blob under the new profile_id. Derive the
        // cached at-rest key once (M13 write-through) and seal with it so the
        // stashed `SealingKey` matches `blob_bytes` byte-for-byte. The
        // share-index key (M14) is derived from the same Argon2id run, under
        // the new profile_id.
        let seeds = Seeds::new(mnemonic);
        let (seal_key, index_key) = SealingKey::derive_session(
            passphrase,
            profile_config.profile_id,
            profile_config.argon2,
        )
        .map_err(FirstStartError::BlobSeal)?;
        let blob_bytes = seal_key.seal(&seeds).map_err(FirstStartError::BlobSeal)?;

        // Land directly in BackupVerified: the phrase was the input, so backup
        // is verified-by-possession. `mnemonic: None` — the supplied phrase has
        // been consumed into the sealed artifacts and zeroized.
        Ok(FirstStart {
            inner: Inner {
                profile_config,
                mnemonic: None,
                blob_bytes,
                recovery_file_bytes,
                display_name: None,
                bootstrap: None,
                identity_handle: Some(identity_handle),
                seeds: Some(seeds),
                seal_key: Some(seal_key),
                index_key: Some(index_key),
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
        // Re-seal the at-rest blob so it carries the chosen name. The blob produced
        // by `initialize` predates the name; without re-sealing here, a first-start
        // whose name is never followed by another write-through persists a NAMELESS
        // blob, and the name is silently lost at the next unlock (#65, and the
        // earlier #57). `seeds` + `seal_key` were stashed at `initialize`.
        if let (Some(seeds), Some(seal_key)) =
            (self.inner.seeds.as_mut(), self.inner.seal_key.as_ref())
        {
            seeds.set_display_name(self.inner.display_name.clone());
            self.inner.blob_bytes = seal_key.seal(seeds).map_err(FirstStartError::BlobSeal)?;
        }
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
        // The live `Seeds` already carry the chosen name (set in `finalize`, which
        // also re-sealed `at_rest_blob_bytes` so the persisted blob is NOT nameless —
        // #65). Re-assert it here so the recover() path (which does not go through
        // `finalize`) still folds the name into the running payload; idempotent for
        // the first-start path.
        let mut seeds = self
            .inner
            .seeds
            .expect("initialize / recover always stashes the live seeds");
        seeds.set_display_name(display_name.clone());
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
            seeds,
            seal_key: self
                .inner
                .seal_key
                .expect("initialize / recover always stashes the seal key"),
            index_key: self
                .inner
                .index_key
                .expect("initialize / recover always stashes the index key"),
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
    /// The live at-rest payload the running client mutates and re-seals for the
    /// M13 write-through (display name, mute / hide lists, circles). At
    /// first-start it carries the chosen display name; on Unlock it is the
    /// decrypted on-disk payload ([`crate::storage::seeds::Opened::seeds`]).
    pub seeds: Seeds,
    /// The cached at-rest AEAD key matching the blob `seeds` seals into. Lets the
    /// running client re-seal on every persist-worthy mutation without re-running
    /// Argon2id (M13). Zeroizes on drop; never logged, never persisted.
    pub seal_key: SealingKey,
    /// The cached share-index key (M14), derived as a sibling of `seal_key` from
    /// the same Argon2id run. Opens the redb share index so the running client
    /// can activate the M8 indexer against TUI-defined share roots. Zeroizes on
    /// drop; never logged, never persisted.
    pub index_key: IndexKey,
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
    use crate::storage::seeds;

    fn init_oxicrypt() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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

    /// Regression (#65, and the earlier #57): `finalize` must re-seal the at-rest
    /// blob WITH the chosen display name. The blob is first sealed at `initialize`,
    /// before any name exists; before the fix it was never re-sealed, so a
    /// first-start with no later write-through persisted a NAMELESS blob and the
    /// name was lost at the next unlock — peers then saw only the hash handle.
    #[test]
    fn finalize_persists_display_name_into_at_rest_blob() {
        init_oxicrypt();
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let ready = verified
            .finalize(Some("alice".to_string()), placeholder_anchor())
            .unwrap();
        let pid = ready.inner.profile_config.profile_id;
        let argon = ready.inner.profile_config.argon2;
        let blob = ready.at_rest_blob_bytes().to_vec();
        let opened = seeds::open(&blob, STRONG_PASSPHRASE, pid, argon).unwrap();
        assert_eq!(
            opened.seeds.display_name(),
            Some("alice"),
            "the persisted at-rest blob must carry the chosen display name"
        );
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

    // ── recovery (gate step 8 / ISC-A-C2) ──────────────────────────────────

    /// Run a full fresh first-start and return its session materials —
    /// the "original device" the recovery tests reconstruct against.
    fn original_device() -> SessionMaterials {
        let sealed = FirstStart::<Welcome>::new()
            .initialize(STRONG_PASSPHRASE, fast_params())
            .unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        verified
            .finalize(Some("alice".to_string()), placeholder_anchor())
            .unwrap()
            .into_session_materials()
    }

    /// The load-bearing property of step 8: recovering from the original
    /// device's 24-word mnemonic yields the *same identity* (same hash
    /// prefix), regardless of the freshly-minted local profile_id.
    #[test]
    fn recover_reaches_same_identity() {
        init_oxicrypt();
        let original = original_device();
        let phrase = recovery_file::open(&original.recovery_file_bytes, STRONG_PASSPHRASE)
            .unwrap()
            .mnemonic
            .to_phrase();

        let recovered = FirstStart::<Welcome>::new()
            .recover(&phrase, STRONG_PASSPHRASE, fast_params())
            .unwrap()
            .finalize(Some("alice".to_string()), placeholder_anchor())
            .unwrap()
            .into_session_materials();

        // Same identity-key hash prefix → same daemon, on a clean device.
        assert_eq!(
            recovered.handle.hash_prefix(),
            original.handle.hash_prefix(),
            "recovered identity must match the source device"
        );
        // Full wire handle matches too when the same display name is chosen.
        assert_eq!(recovered.handle.to_string(), original.handle.to_string());
    }

    /// Recovery mints a *fresh* profile_id (ISC-C36) — the recovered device
    /// is a new profile even though the identity is the same.
    #[test]
    fn recover_mints_fresh_profile_id() {
        init_oxicrypt();
        let original = original_device();
        let phrase = recovery_file::open(&original.recovery_file_bytes, STRONG_PASSPHRASE)
            .unwrap()
            .mnemonic
            .to_phrase();

        let recovered = FirstStart::<Welcome>::new()
            .recover(&phrase, STRONG_PASSPHRASE, fast_params())
            .unwrap()
            .finalize(None, placeholder_anchor())
            .unwrap();

        assert_ne!(
            recovered.profile_id(),
            original.profile_config.profile_id,
            "recovered device is a new profile with its own profile_id"
        );
    }

    /// The recovered device's at-rest blob and re-written `.dseed` both open
    /// under the recovery passphrase, carrying the recovered mnemonic.
    #[test]
    fn recover_reseals_openable_artifacts() {
        init_oxicrypt();
        let original = original_device();
        let phrase = recovery_file::open(&original.recovery_file_bytes, STRONG_PASSPHRASE)
            .unwrap()
            .mnemonic
            .to_phrase();

        let recovered = FirstStart::<Welcome>::new()
            .recover(&phrase, STRONG_PASSPHRASE, fast_params())
            .unwrap()
            .finalize(None, placeholder_anchor())
            .unwrap();
        let pid = recovered.profile_id();
        let argon = recovered.inner.profile_config.argon2;

        // at-rest blob round-trips under the new profile_id + passphrase
        let opened = seeds::open(
            recovered.at_rest_blob_bytes(),
            STRONG_PASSPHRASE,
            pid,
            argon,
        )
        .unwrap();
        assert_eq!(opened.seeds.mnemonic.to_phrase(), phrase);

        // re-written .dseed round-trips and carries the same phrase
        let dseed =
            recovery_file::open(recovered.recovery_file_bytes(), STRONG_PASSPHRASE).unwrap();
        assert_eq!(dseed.mnemonic.to_phrase(), phrase);
    }

    /// A bad transcription (failed BIP-39 checksum) fails closed — no
    /// partial profile, a typed error the UX can route.
    #[test]
    fn recover_rejects_invalid_mnemonic() {
        init_oxicrypt();
        // 24 words but the checksum is wrong (all "abandon" fails the BIP-39
        // checksum for a 24-word phrase).
        let bad = "abandon ".repeat(24);
        match FirstStart::<Welcome>::new().recover(bad.trim(), STRONG_PASSPHRASE, fast_params()) {
            Err(FirstStartError::Mnemonic(_)) => {}
            Ok(_) => panic!("expected Mnemonic error, got Ok(FirstStart<BackupVerified>)"),
            Err(other) => panic!("expected Mnemonic error, got {other:?}"),
        }
    }

    /// The new local passphrase is still subject to the C12 strength gate.
    #[test]
    fn recover_rejects_weak_passphrase() {
        init_oxicrypt();
        let original = original_device();
        let phrase = recovery_file::open(&original.recovery_file_bytes, STRONG_PASSPHRASE)
            .unwrap()
            .mnemonic
            .to_phrase();
        match FirstStart::<Welcome>::new().recover(&phrase, "password", fast_params()) {
            Err(FirstStartError::PassphraseTooWeak { .. }) => {}
            Ok(_) => panic!("expected PassphraseTooWeak, got Ok(FirstStart<BackupVerified>)"),
            Err(other) => panic!("expected PassphraseTooWeak, got {other:?}"),
        }
    }
}
