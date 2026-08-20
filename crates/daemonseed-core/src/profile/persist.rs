//! Profile-root persistence (ISC-C32 / ISC-C49..C51 / ISC-A-C28 — Item D/E).
//!
//! First-start (`first_start::orchestrator`) is filesystem-free by design: it
//! returns the at-rest blob and `.dseed` recovery bytes plus a
//! [`ProfileConfig`], and *callers take the returned blob/recovery bytes and
//! write them to the profile root*. This module is that caller-side write path,
//! plus the reciprocal load path the daily-login Unlock flow (ISC-C3) uses.
//!
//! Files written under the profile root (ISC-C35), all with uniform names:
//! - `daemonseed.toml` — the [`ProfileConfig`] (profile-id + Argon2 params).
//! - `seeds.blob` — the AES-256-GCM at-rest identity blob (ISC-C3).
//! - `identity.dseed` — the encrypted recovery file (ISC-C32). Default path is
//!   the profile root; the user may override the destination (the override is
//!   handled at the call site by passing an explicit `dseed_path`).
//!
//! No network, no telemetry (ISC-A-C14): this is local file I/O only.

use std::io;
use std::path::{Path, PathBuf};

use crate::bootstrap::BootstrapAnchor;
use crate::first_start::SessionMaterials;
use crate::handle::Handle;
use crate::identity::keys::{Identity, derive_identity_keys};
use crate::profile::config::{ProfileConfig, ProfileConfigError};
use crate::storage::seeds::{IndexKey, SealingKey, Seeds};

/// Uniform at-rest seeds-blob filename at the profile root (ISC-C3).
pub const BLOB_FILENAME: &str = "seeds.blob";

/// Uniform `.dseed` recovery-file filename at the profile root (ISC-C32).
pub const DSEED_FILENAME: &str = "identity.dseed";

/// `seeds.blob` path for a profile root.
pub fn blob_path(profile_root: &Path) -> PathBuf {
    profile_root.join(BLOB_FILENAME)
}

/// `identity.dseed` path for a profile root (the default backup destination).
pub fn dseed_path(profile_root: &Path) -> PathBuf {
    profile_root.join(DSEED_FILENAME)
}

/// `daemonseed.toml` path for a profile root.
pub fn config_path(profile_root: &Path) -> PathBuf {
    profile_root.join(crate::profile::resolve::CONFIG_FILENAME)
}

/// Whether a profile blob already exists at `profile_root` (ISC-C3). Drives the
/// daily-login routing decision (existing blob → Unlock, not enrollment) and
/// the no-clobber guard (ISC-A-C28): first-start must not silently overwrite an
/// existing profile blob.
pub fn blob_exists(profile_root: &Path) -> bool {
    blob_path(profile_root).is_file()
}

/// Errors from the persistence path.
#[derive(Debug)]
pub enum PersistError {
    /// A filesystem write/read failed; carries the offending path.
    Io { path: PathBuf, source: io::Error },
    /// Serializing the [`ProfileConfig`] to TOML failed.
    Config(ProfileConfigError),
    /// First-start would overwrite an existing profile blob without explicit
    /// confirmation (ISC-A-C28). The caller must surface a confirm before
    /// re-running first-start against this root.
    WouldClobber { blob: PathBuf },
}

impl core::fmt::Display for PersistError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PersistError::Io { path, source } => {
                write!(f, "profile I/O on {}: {source}", path.display())
            }
            PersistError::Config(e) => write!(f, "profile config: {e}"),
            PersistError::WouldClobber { blob } => write!(
                f,
                "an identity already exists at {} — re-running first-start would overwrite it; \
                 confirm explicitly or choose a different profile root",
                blob.display()
            ),
        }
    }
}

impl std::error::Error for PersistError {}

/// Write a completed first-start's artifacts to the profile root (Item D).
///
/// Writes `daemonseed.toml`, `seeds.blob`, and the `.dseed` recovery file. The
/// `.dseed` lands at the profile root by default (ISC-C32); pass an explicit
/// `dseed_override` to honour a user-chosen destination.
///
/// `allow_clobber` is the no-clobber guard (ISC-A-C28): when `false` (the
/// default for a fresh enrollment) an existing `seeds.blob` causes
/// [`PersistError::WouldClobber`] rather than a silent overwrite. The caller
/// flips it to `true` only after an explicit user confirm.
pub fn write_first_start(
    profile_root: &Path,
    materials: &SessionMaterials,
    dseed_override: Option<&Path>,
    allow_clobber: bool,
) -> Result<PathBuf, PersistError> {
    if !allow_clobber && blob_exists(profile_root) {
        return Err(PersistError::WouldClobber {
            blob: blob_path(profile_root),
        });
    }

    std::fs::create_dir_all(profile_root).map_err(|source| PersistError::Io {
        path: profile_root.to_path_buf(),
        source,
    })?;

    // Config first so a half-written profile still has its profile-id +
    // Argon2 params (the values needed to open the blob). Stamp the chosen
    // bootstrap relay into the persisted config (ISC-C37) so the daily-login
    // Unlock flow (ISC-C3) can reconnect without the enrollment wizard.
    let mut config = materials.profile_config.clone();
    config.bootstrap = Some(materials.bootstrap.clone());
    let toml = config.to_toml().map_err(PersistError::Config)?;
    let cfg_path = config_path(profile_root);
    std::fs::write(&cfg_path, toml.as_bytes()).map_err(|source| PersistError::Io {
        path: cfg_path.clone(),
        source,
    })?;

    let blob_p = blob_path(profile_root);
    std::fs::write(&blob_p, &materials.at_rest_blob_bytes).map_err(|source| PersistError::Io {
        path: blob_p.clone(),
        source,
    })?;

    // The `.dseed` lands at the profile root by default (ISC-C32) unless the
    // caller passed a user override.
    let dseed_p = dseed_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| dseed_path(profile_root));
    std::fs::write(&dseed_p, &materials.recovery_file_bytes).map_err(|source| {
        PersistError::Io {
            path: dseed_p.clone(),
            source,
        }
    })?;

    Ok(dseed_p)
}

/// Overwrite the at-rest seeds blob at `profile_root` (M13 write-through).
///
/// Unlike [`write_first_start`], this writes *only* `seeds.blob` and always
/// clobbers: it is the post-first-start re-seal path, where the running client
/// has mutated its [`Seeds`] (display name, mute / hide lists, circles), re-sealed
/// under the cached [`SealingKey`], and needs the refreshed blob on disk. The
/// `.dseed` recovery file and the config are deliberately left untouched — the
/// mnemonic and profile params do not change on a write-through, only the
/// settings payload. The no-clobber guard (ISC-A-C28) does not apply here: by the
/// time a write-through runs the profile already exists and the user is unlocked,
/// so overwriting their own blob with their own newer state is the intent.
pub fn write_seeds_blob(profile_root: &Path, bytes: &[u8]) -> Result<(), PersistError> {
    std::fs::create_dir_all(profile_root).map_err(|source| PersistError::Io {
        path: profile_root.to_path_buf(),
        source,
    })?;
    let blob_p = blob_path(profile_root);
    std::fs::write(&blob_p, bytes).map_err(|source| PersistError::Io {
        path: blob_p.clone(),
        source,
    })
}

/// Load `daemonseed.toml` + the raw `seeds.blob` bytes for the daily-login
/// Unlock flow (ISC-C3 / Item E). The passphrase-decrypt itself is
/// [`crate::storage::seeds::open`]; this just reads the on-disk inputs it needs
/// (the profile-id + Argon2 params from the config, and the blob bytes).
pub fn load_for_unlock(profile_root: &Path) -> Result<(ProfileConfig, Vec<u8>), PersistError> {
    let cfg_path = config_path(profile_root);
    let body = std::fs::read_to_string(&cfg_path).map_err(|source| PersistError::Io {
        path: cfg_path.clone(),
        source,
    })?;
    let config = ProfileConfig::from_toml(&body).map_err(PersistError::Config)?;

    let blob_p = blob_path(profile_root);
    let blob = std::fs::read(&blob_p).map_err(|source| PersistError::Io {
        path: blob_p.clone(),
        source,
    })?;
    Ok((config, blob))
}

/// Error reconstructing [`SessionMaterials`] from a decrypted profile (Item E).
#[derive(Debug)]
pub enum UnlockError {
    /// Deriving the identity keypair / handle from the recovered mnemonic
    /// failed (the crypto module is operational by this point, so this is
    /// surfaced rather than unwrapped).
    IdentityDerivation(String),
    /// The profile config carries no persisted bootstrap relay (a legacy
    /// pre-Item-E profile). The caller routes the user to the Servers pane to
    /// pick a relay rather than auto-connecting.
    NoBootstrap,
}

impl core::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UnlockError::IdentityDerivation(e) => write!(f, "identity derivation: {e}"),
            UnlockError::NoBootstrap => write!(
                f,
                "no bootstrap relay persisted in this profile — choose one from the Servers pane"
            ),
        }
    }
}

impl std::error::Error for UnlockError {}

/// Reconstruct [`SessionMaterials`] from a decrypted blob + profile config, for
/// the daily-login Unlock flow (ISC-C3 / Item E). The handle is re-derived from
/// the recovered mnemonic (so the hash prefix is byte-identical to enrollment);
/// the bootstrap relay comes from the persisted config (ISC-C37).
///
/// `seeds` is the decrypted at-rest payload ([`crate::storage::seeds::Opened::seeds`])
/// and `seal_key` its cached AEAD key ([`crate::storage::seeds::Opened::key`]),
/// both threaded into the returned materials so the running client can re-seal on
/// every persist-worthy mutation (M13 write-through) — and so the persisted
/// display name (ISC-C4b) is restored rather than reset each login.
///
/// The blob and recovery bytes in the returned materials are the on-disk bytes
/// the caller already holds — passed through so the type matches the cold-start
/// handoff without re-sealing. Unlock never re-writes the profile.
pub fn session_materials_from_unlock(
    seeds: Seeds,
    seal_key: SealingKey,
    index_key: IndexKey,
    config: ProfileConfig,
    blob_bytes: Vec<u8>,
    recovery_file_bytes: Vec<u8>,
) -> Result<SessionMaterials, UnlockError> {
    let bootstrap: BootstrapAnchor = config.bootstrap.clone().ok_or(UnlockError::NoBootstrap)?;
    // Re-derive the identity handle from the recovered mnemonic (the hash prefix
    // is identical to enrollment — the load-bearing identity property). The
    // persisted display name (ISC-C4b, M13) is restored from the blob and
    // attached to the handle, so the user presents under the same name across
    // daily logins instead of falling back to the floor handle.
    let keys = derive_identity_keys(&seeds.mnemonic, Identity::Primary)
        .map_err(|e| UnlockError::IdentityDerivation(e.to_string()))?;
    let display_name = seeds.display_name().map(str::to_owned);
    let handle = Handle::from_pubkey(None, keys.signing.public_key())
        .map_err(|e| UnlockError::IdentityDerivation(e.to_string()))?
        .with_display_name(display_name.clone());
    Ok(SessionMaterials {
        profile_config: config,
        at_rest_blob_bytes: blob_bytes,
        recovery_file_bytes,
        display_name,
        handle,
        bootstrap,
        seeds,
        seal_key,
        index_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::first_start::FirstStart;
    use crate::profile::config::ArgonParams;
    use crate::storage::seeds;

    fn ensure_oxicrypt() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    fn fast_params() -> ArgonParams {
        ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    const STRONG: &str = "correct horse battery staple table mountain";

    struct Tmp {
        path: PathBuf,
    }
    impl Tmp {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("ds-persist-test-{}", uuid::Uuid::new_v4()));
            Self { path }
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn enroll() -> SessionMaterials {
        ensure_oxicrypt();
        let sealed = FirstStart::new().initialize(STRONG, fast_params()).unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        verified
            .finalize(
                Some("alice".to_string()),
                crate::bootstrap::BootstrapAnchor {
                    server_id: "relay#aabbccddeeff".to_string(),
                    address: "127.0.0.1:443".to_string(),
                },
            )
            .unwrap()
            .into_session_materials()
    }

    /// ISC-C49 (D): first-start persists the at-rest blob to the profile root.
    #[test]
    fn write_first_start_persists_blob_and_config() {
        let tmp = Tmp::new();
        let m = enroll();
        write_first_start(&tmp.path, &m, None, false).unwrap();
        assert!(blob_exists(&tmp.path), "seeds.blob written to profile root");
        assert!(config_path(&tmp.path).is_file(), "daemonseed.toml written");
    }

    /// ISC-C50 (D): `.dseed` saved as the default backup at the profile root.
    #[test]
    fn write_first_start_saves_dseed_at_profile_root_by_default() {
        let tmp = Tmp::new();
        let m = enroll();
        let written = write_first_start(&tmp.path, &m, None, false).unwrap();
        assert_eq!(written, dseed_path(&tmp.path));
        assert!(dseed_path(&tmp.path).is_file(), "identity.dseed written");
    }

    /// The `.dseed` honours a user-chosen override destination (ISC-C32).
    #[test]
    fn write_first_start_honours_dseed_override() {
        let tmp = Tmp::new();
        let m = enroll();
        let override_path = tmp.path.join("custom-backup.dseed");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let written = write_first_start(&tmp.path, &m, Some(&override_path), false).unwrap();
        assert_eq!(written, override_path);
        assert!(override_path.is_file());
    }

    /// The persisted blob round-trips through `seeds::open` under the same
    /// passphrase + persisted params — the daily-login decrypt path (ISC-C3).
    #[test]
    fn persisted_blob_round_trips_under_passphrase() {
        let tmp = Tmp::new();
        let m = enroll();
        write_first_start(&tmp.path, &m, None, false).unwrap();
        let (config, blob) = load_for_unlock(&tmp.path).unwrap();
        let opened = seeds::open(&blob, STRONG, config.profile_id, config.argon2).unwrap();
        // The recovered identity matches the enrolled one.
        assert!(!opened.seeds.mnemonic.to_phrase().is_empty());
        // The bootstrap relay persisted so Unlock can reconnect (ISC-C37).
        assert_eq!(
            config.bootstrap.as_ref().map(|b| b.server_id.as_str()),
            Some("relay#aabbccddeeff")
        );
    }

    /// ISC-A-C28 (E): re-running first-start without explicit confirm must NOT
    /// clobber an existing profile blob.
    #[test]
    fn write_first_start_refuses_to_clobber_without_confirm() {
        let tmp = Tmp::new();
        let m = enroll();
        write_first_start(&tmp.path, &m, None, false).unwrap();
        // Second enrollment against the same root, no confirm → refused.
        let m2 = enroll();
        match write_first_start(&tmp.path, &m2, None, false) {
            Err(PersistError::WouldClobber { .. }) => {}
            other => panic!("expected WouldClobber, got {other:?}"),
        }
    }

    /// With an explicit confirm (`allow_clobber = true`) the overwrite proceeds.
    #[test]
    fn write_first_start_overwrites_with_explicit_confirm() {
        let tmp = Tmp::new();
        let m = enroll();
        write_first_start(&tmp.path, &m, None, false).unwrap();
        let m2 = enroll();
        write_first_start(&tmp.path, &m2, None, true).expect("confirmed overwrite succeeds");
    }

    /// ISC-C51 (E): a successful unlock reconstructs SessionMaterials reaching
    /// the SAME identity hash as enrollment, without the mnemonic being typed.
    #[test]
    fn unlock_reconstructs_same_identity() {
        let tmp = Tmp::new();
        let m = enroll();
        let enrolled_prefix = *m.handle.hash_prefix();
        write_first_start(&tmp.path, &m, None, false).unwrap();
        let (config, blob) = load_for_unlock(&tmp.path).unwrap();
        let opened = seeds::open(&blob, STRONG, config.profile_id, config.argon2).unwrap();
        let recovered = session_materials_from_unlock(
            opened.seeds,
            opened.key,
            opened.index_key,
            config,
            blob.clone(),
            vec![],
        )
        .expect("unlock reconstructs materials");
        assert_eq!(
            recovered.handle.hash_prefix(),
            &enrolled_prefix,
            "unlock reaches the same identity hash as enrollment"
        );
        assert_eq!(
            recovered.bootstrap.server_id, "relay#aabbccddeeff",
            "unlock recovers the persisted bootstrap relay (ISC-C37)"
        );
    }

    /// A profile with no persisted bootstrap (legacy) yields `NoBootstrap` so
    /// the caller routes to manual server selection instead of auto-connect.
    #[test]
    fn unlock_without_bootstrap_reports_no_bootstrap() {
        let tmp = Tmp::new();
        let m = enroll();
        write_first_start(&tmp.path, &m, None, false).unwrap();
        let (mut config, blob) = load_for_unlock(&tmp.path).unwrap();
        config.bootstrap = None; // simulate a legacy profile
        let opened = seeds::open(&blob, STRONG, config.profile_id, config.argon2).unwrap();
        match session_materials_from_unlock(
            opened.seeds,
            opened.key,
            opened.index_key,
            config,
            blob,
            vec![],
        ) {
            Err(UnlockError::NoBootstrap) => {}
            other => panic!("expected NoBootstrap, got {other:?}"),
        }
    }

    /// A wrong passphrase on the persisted blob fails closed (ISC-C3 / Unlock).
    #[test]
    fn unlock_wrong_passphrase_fails_closed() {
        let tmp = Tmp::new();
        let m = enroll();
        write_first_start(&tmp.path, &m, None, false).unwrap();
        let (config, blob) = load_for_unlock(&tmp.path).unwrap();
        match seeds::open(
            &blob,
            "wrong horse battery staple",
            config.profile_id,
            config.argon2,
        ) {
            Err(seeds::BlobError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }
}
