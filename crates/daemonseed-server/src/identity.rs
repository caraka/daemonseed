//! Long-term ML-DSA-87 server identity.
//!
//! Per ISC-S11 the server has its own long-term ML-DSA-87 keypair,
//! generated once at server bootstrap and persisted to disk under the
//! operator-supplied key path. The server-id format follows ISC-C4 /
//! ISC-S11: `<display-name>#<first-12-hex-of-SHA256(pubkey)>`.
//!
//! M4a persists the **raw 32-byte ML-DSA-87 seed**, not the full
//! expanded keypair. The pubkey + private signing material are
//! re-derived on every boot via `oxicrypt_ml_dsa::keygen(&seed)`. The
//! seed itself is what we store because:
//!
//! 1. It's the minimum information needed (the rest is a deterministic
//!    function of the seed under FIPS 204).
//! 2. The future seed-derived federated-identity path (ISC-S11
//!    post-MVP) becomes a straightforward re-derivation from the same
//!    seed plus an HKDF context.
//! 3. The on-disk shape matches `oxitls-rustls-provider`'s PKCS#8
//!    expectation (a `PrivateKeyInfo` whose `OctetString` payload is
//!    the 32-byte seed) — see `oxitls_rustls_provider::ml_dsa_87_private_key_from_seed`.
//!
//! Permissions on the seed file are the operator's responsibility (the
//! file path is operator-managed); daemonseed-server creates the file
//! with mode `0o600` (rw-------) at first boot.

use core::fmt;
use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;

use daemonseed_core::handle::Handle;
use oxicrypt_ml_dsa::keygen;
use zeroize::Zeroize;

// Re-export so external callers can reference the same constant without
// chasing through daemonseed-core. Mirrors the M1 handle module's surface.
pub use daemonseed_core::handle::HASH_PREFIX_BYTES;

/// Length of an ML-DSA-87 seed in bytes per FIPS 204 §5.1.
pub const SEED_LEN: usize = 32;

/// On-disk format prefix byte. Reserved for future versioning if the
/// seed-file shape ever needs to evolve (e.g., wrapping in a header
/// when post-MVP seed-derived identity adds context bytes).
const SEED_FILE_MAGIC: [u8; 4] = *b"dsv1";

/// Owned 32-byte ML-DSA-87 seed. Zeroized on drop.
pub struct Seed(pub [u8; SEED_LEN]);

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Seed {
    /// Borrow the underlying bytes — primarily for handing to
    /// `oxitls_rustls_provider::ml_dsa_87_private_key_from_seed` and
    /// `oxitls_webpki_mldsa::build_self_signed_ml_dsa_87_cert`.
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the seed bytes — even partially. The hash prefix
        // of the derived pubkey is the operator-friendly identifier
        // (carried by [`ServerId`]); the raw seed is sensitive.
        f.debug_struct("Seed")
            .field("len", &SEED_LEN)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// daemonseed server identifier — type alias for [`Handle`] since the
/// format (`<name>#<12hex>`) is bit-identical between client handles
/// (ISC-C4) and server identifiers (ISC-S11). The hash-prefix length
/// is the same `HASH_PREFIX_BYTES` (6 bytes / 12 hex chars).
pub type ServerId = Handle;

// ── First-boot seed generation ───────────────────────────────────

/// Generate 32 bytes of high-quality entropy for a fresh ML-DSA-87
/// seed. Uses the OS RNG via `getrandom` — same source the entire
/// daemonseed crypto stack ultimately derives from.
///
/// This is intentionally NOT routed through the
/// `oxicrypt-drbg`+module-gate path: at first-boot the module hasn't
/// even been initialized yet (the seed is what enables identity
/// generation, which is what enables knowing what to KATs-load), and
/// the OS RNG is what the DRBG itself seeds from. Adding a
/// module-gate dance here would be circular.
pub fn generate_seed() -> Result<Seed, IdentityError> {
    let mut buf = [0u8; SEED_LEN];
    // getrandom 0.3 — the function is `fill`, not the old 0.2 `getrandom`.
    getrandom::fill(&mut buf).map_err(|e| IdentityError::EntropyFailure(e.to_string()))?;
    Ok(Seed(buf))
}

// ── Persistence ──────────────────────────────────────────────────

/// Load a seed from disk, or generate + persist one if the file does
/// not exist. The first-boot path emits the new file with mode
/// `0o600` (rw-------); subsequent boots just read.
pub fn load_or_generate(path: &Path) -> Result<Seed, IdentityError> {
    match read_seed_file(path) {
        Ok(seed) => Ok(seed),
        Err(IdentityError::NotFound) => {
            let seed = generate_seed()?;
            write_seed_file(path, &seed)?;
            Ok(seed)
        }
        Err(other) => Err(other),
    }
}

fn read_seed_file(path: &Path) -> Result<Seed, IdentityError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(IdentityError::NotFound),
        Err(e) => {
            return Err(IdentityError::ReadFailed {
                path: path.display().to_string(),
                source: e,
            });
        }
    };

    if bytes.len() != SEED_FILE_MAGIC.len() + SEED_LEN {
        return Err(IdentityError::MalformedSeedFile {
            expected: SEED_FILE_MAGIC.len() + SEED_LEN,
            actual: bytes.len(),
        });
    }
    if bytes[..SEED_FILE_MAGIC.len()] != SEED_FILE_MAGIC {
        return Err(IdentityError::UnknownSeedFileMagic);
    }

    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&bytes[SEED_FILE_MAGIC.len()..]);
    Ok(Seed(seed))
}

fn write_seed_file(path: &Path, seed: &Seed) -> Result<(), IdentityError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| IdentityError::WriteFailed {
            path: parent.display().to_string(),
            source: e,
        })?;
    }

    let mut payload = Vec::with_capacity(SEED_FILE_MAGIC.len() + SEED_LEN);
    payload.extend_from_slice(&SEED_FILE_MAGIC);
    payload.extend_from_slice(seed.as_bytes());

    write_with_owner_only_permissions(path, &payload)
}

#[cfg(unix)]
fn write_with_owner_only_permissions(path: &Path, payload: &[u8]) -> Result<(), IdentityError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true) // refuse to overwrite — we got here because read returned NotFound
        .mode(0o600)
        .open(path)
        .map_err(|e| IdentityError::WriteFailed {
            path: path.display().to_string(),
            source: e,
        })?;

    io::Write::write_all(&mut f, payload).map_err(|e| IdentityError::WriteFailed {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_with_owner_only_permissions(path: &Path, payload: &[u8]) -> Result<(), IdentityError> {
    // Non-unix platforms: best-effort write without explicit mode bits.
    // Document operator-responsibility for ACL setting in a follow-up
    // platform-support doc; M4a's target deployment is Linux servers.
    fs::write(path, payload).map_err(|e| IdentityError::WriteFailed {
        path: path.display().to_string(),
        source: e,
    })
}

// ── Server-id construction ───────────────────────────────────────

/// Derive the public-key bytes from a seed, and build the canonical
/// server-id (`<display-name>#<12hex>`) per ISC-S11 / ISC-C4.
///
/// **Module-gate precondition:** `oxicrypt_ml_dsa::keygen` routes
/// through the oxicrypt-module operational gate. Callers must have
/// driven `oxicrypt_module::initialize_with_profile(&kats,
/// AlgorithmProfile::Cnsa2)` before invoking this.
pub fn derive_server_id(
    seed: &Seed,
    display_name: Option<String>,
) -> Result<ServerId, IdentityError> {
    let (pubkey, _sk) = keygen(seed.as_bytes()).map_err(IdentityError::Keygen)?;
    Handle::from_pubkey(display_name, pubkey.as_ref()).map_err(IdentityError::HandleConstruct)
}

// ── Errors ───────────────────────────────────────────────────────

/// Errors raised by the server identity module.
#[derive(Debug)]
pub enum IdentityError {
    /// `load_or_generate` discovered no existing file (internal — the
    /// public path falls through to first-boot generation on this
    /// variant, so consumers don't see it).
    NotFound,
    /// OS entropy via `getrandom` failed. Wrapped as a string because
    /// `getrandom::Error` is not `std::error::Error`-implementing in 0.3.
    EntropyFailure(String),
    /// File read failed for a reason other than "not found".
    ReadFailed { path: String, source: io::Error },
    /// File write failed (first-boot persistence path).
    WriteFailed { path: String, source: io::Error },
    /// Seed file is shorter or longer than expected.
    MalformedSeedFile { expected: usize, actual: usize },
    /// File's magic prefix didn't match `dsv1`.
    UnknownSeedFileMagic,
    /// `oxicrypt_ml_dsa::keygen` failed — typically a non-Operational
    /// module gate (caller forgot to `initialize_with_profile`).
    Keygen(oxicrypt_module::Error),
    /// `Handle::from_pubkey` failed — typically a SHA-256 module-gate
    /// failure.
    HandleConstruct(oxicrypt_module::Error),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "seed file not found"),
            Self::EntropyFailure(e) => write!(f, "OS entropy failure: {e}"),
            Self::ReadFailed { path, source } => {
                write!(f, "failed to read seed file {path}: {source}")
            }
            Self::WriteFailed { path, source } => {
                write!(f, "failed to write seed file {path}: {source}")
            }
            Self::MalformedSeedFile { expected, actual } => {
                write!(f, "seed file length is {actual} bytes; expected {expected}")
            }
            Self::UnknownSeedFileMagic => write!(f, "seed file magic prefix is not 'dsv1'"),
            Self::Keygen(e) => write!(
                f,
                "ML-DSA-87 keygen failed (oxicrypt-module not Operational?): {e}"
            ),
            Self::HandleConstruct(e) => write!(f, "ServerId construction failed: {e}"),
        }
    }
}

impl Error for IdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadFailed { source, .. } | Self::WriteFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn ensure_module() {
        // Lightweight test-only module init shim from oxitls — covers
        // the DRBG KATs (the only module-gated primitive on the test
        // hot path for our seed-driven keygen).
        oxitls_rustls_provider::testing::ensure_module_operational();
    }

    #[test]
    fn generate_seed_returns_32_bytes() {
        let s = generate_seed().unwrap();
        assert_eq!(s.as_bytes().len(), SEED_LEN);
    }

    #[test]
    fn generate_two_seeds_returns_distinct_values() {
        // Probabilistic: collisions are negligibly rare (~2^-256).
        let a = generate_seed().unwrap();
        let b = generate_seed().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes(), "OS RNG must be non-constant");
    }

    #[test]
    fn first_boot_creates_seed_file_and_round_trips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.bin");

        let seed_first = load_or_generate(&path).unwrap();
        assert!(path.exists(), "file created on first boot");

        let seed_second = load_or_generate(&path).unwrap();
        assert_eq!(
            seed_first.as_bytes(),
            seed_second.as_bytes(),
            "subsequent boot loads same seed"
        );
    }

    #[test]
    fn second_boot_does_not_regenerate() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.bin");
        let original = load_or_generate(&path).unwrap();
        let original_bytes = *original.as_bytes();

        for _ in 0..3 {
            let reload = load_or_generate(&path).unwrap();
            assert_eq!(
                *reload.as_bytes(),
                original_bytes,
                "every reload returns the same seed (no rotation)"
            );
        }
    }

    #[test]
    fn malformed_seed_file_errors_named() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.bin");
        // Magic-correct but wrong length.
        fs::write(&path, b"dsv1\x00\x01\x02").unwrap();
        let err = load_or_generate(&path).expect_err("length doesn't match");
        match err {
            IdentityError::MalformedSeedFile { actual, .. } => assert_eq!(actual, 7),
            other => panic!("expected MalformedSeedFile, got {other:?}"),
        }
    }

    #[test]
    fn unknown_magic_errors_named() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.bin");
        // Wrong magic but correct length.
        let mut bad = Vec::from(b"BAD!" as &[u8]);
        bad.extend_from_slice(&[0u8; SEED_LEN]);
        fs::write(&path, bad).unwrap();
        let err = load_or_generate(&path).expect_err("magic mismatch");
        matches!(err, IdentityError::UnknownSeedFileMagic);
    }

    #[cfg(unix)]
    #[test]
    fn first_boot_persists_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seed.bin");
        let _ = load_or_generate(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "seed file must be rw------- per ISC-S11");
    }

    #[test]
    fn derive_server_id_yields_canonical_handle_shape() {
        ensure_module();
        let seed = generate_seed().unwrap();
        let id =
            derive_server_id(&seed, Some("happy-bear".to_owned())).expect("module operational");
        // Display in Verify mode renders the full `<name>#<12hex>` form per
        // ISC-C4a.
        let s = id
            .format(daemonseed_core::handle::DisplayMode::Verify)
            .to_string();
        assert!(s.starts_with("happy-bear#"));
        let suffix = s.split_once('#').unwrap().1;
        assert_eq!(
            suffix.len(),
            HASH_PREFIX_BYTES * 2,
            "hash prefix is exactly 12 hex chars per ISC-S11 / ISC-C4"
        );
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn derive_server_id_floor_form_when_no_display_name() {
        ensure_module();
        let seed = generate_seed().unwrap();
        let id = derive_server_id(&seed, None).expect("module operational");
        let s = id
            .format(daemonseed_core::handle::DisplayMode::Default)
            .to_string();
        // Floor form is `#<12hex>` per ISC-C4b — no name segment.
        assert!(s.starts_with('#'));
    }

    #[test]
    fn derive_server_id_is_deterministic_per_seed() {
        ensure_module();
        let seed_bytes = [42u8; SEED_LEN];
        let s1 = derive_server_id(&Seed(seed_bytes), Some("x".to_owned())).unwrap();
        let s2 = derive_server_id(&Seed(seed_bytes), Some("x".to_owned())).unwrap();
        assert_eq!(
            s1.format(daemonseed_core::handle::DisplayMode::Verify)
                .to_string(),
            s2.format(daemonseed_core::handle::DisplayMode::Verify)
                .to_string(),
            "same seed + name → same server-id"
        );
    }
}
