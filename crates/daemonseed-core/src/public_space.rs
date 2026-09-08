//! Public-space signed-artifact model shared by the server and every client.
//!
//! The relay is verify-and-serve only (ISC-A-S3): it never originates a post
//! or MOTD, and a client never trusts the server's assertions about a post's
//! provenance or address. Both sides therefore run the *same* three checks
//! against an arriving `SignedArtifact`:
//!
//! 1. **Content-address** — `SHA-384(signed_payload)` (ISC-17 / ISC-S7). The
//!    address is derived, never asserted; a server-supplied address is
//!    re-derived and compared by the client.
//! 2. **Whitelist authorization** — the signer's full key must be permitted by
//!    the operator's signer whitelist (ISC-S8). A `<name>#<hash>` handle entry
//!    is matched by checking the arriving key's hash-prefix BEFORE any
//!    signature work (ISC-12) so an unknown key is rejected as cheaply as
//!    possible.
//! 3. **Signature** — a detached ML-DSA-87 signature over `signed_payload`
//!    (the exact bytes, never a re-encoding — D-M6-7 / `public_space.proto`).
//!
//! This module is intentionally proto-agnostic: it works on `&[u8]` payloads,
//! pubkeys, and signatures so `daemonseed-core` keeps no dependency on the
//! wire crate. The server and CLI adapt their `daemonseed_proto` types into
//! these calls.

use core::fmt;
use core::str::FromStr;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_module::Error as OxicryptError;
use oxicrypt_sha::sha384;
use zeroize::Zeroizing;

use crate::handle::{Handle, HandleParseError};
use crate::identity::keys::{KeyDerivationError, SignKeypair, verify_signature};
use crate::kdf::info;
use crate::presence::interval_in_band;
use crate::secret_seed::{derive_boxed_seed, redacted_secret_newtype};

/// Length of a SHA-384 content address, in bytes.
pub const CONTENT_ADDRESS_LEN: usize = 48;

/// A `SHA-384(signed_payload)` content address (ISC-17 / ISC-S7).
///
/// Posts and MOTDs are addressed by the digest of their signed payload bytes.
/// The address is *derived* from the bytes a signer produced — it is never read
/// off the wire and trusted, which is what lets a client detect a server that
/// substitutes or mutates content (ISC-A-S3).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentAddress([u8; CONTENT_ADDRESS_LEN]);

impl ContentAddress {
    /// The raw 48-byte digest.
    pub fn as_bytes(&self) -> &[u8; CONTENT_ADDRESS_LEN] {
        &self.0
    }
}

impl fmt::Display for ContentAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for ContentAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ContentAddress")
            .field(&hex::encode(self.0))
            .finish()
    }
}

/// Compute the content address of a signed payload: `SHA-384(signed_payload)`
/// (ISC-17).
///
/// Returns the underlying oxicrypt error only if SHA-384's power-up self-test
/// has not yet passed (first call in a fresh process).
pub fn content_address(signed_payload: &[u8]) -> Result<ContentAddress, OxicryptError> {
    let digest = sha384(signed_payload)?;
    let mut out = [0u8; CONTENT_ADDRESS_LEN];
    out.copy_from_slice(&digest[..CONTENT_ADDRESS_LEN]);
    Ok(ContentAddress(out))
}

// ── Signer whitelist (ISC-S8 / ISC-10 / ISC-11 / ISC-12) ─────────────────

/// One signer-whitelist entry, in the two forms an operator may write
/// (ISC-S8). Both forms ultimately authorize a *full* ML-DSA-87 key; the
/// handle form is the compact `<name>#<hash>` shorthand that pins only the
/// hash-prefix and lets the full key arrive with each signed artifact.
#[derive(Clone, PartialEq, Eq)]
pub enum WhitelistEntry {
    /// A full ML-DSA-87 public key (ISC-10). Self-contained; matched by exact
    /// bytes.
    FullKey(Box<[u8; ml_dsa::PK_LEN]>),

    /// A `<name>#<hash>` handle (ISC-11). Matched by hash-prefix against the
    /// arriving key (ISC-12); the display name is advisory.
    Handle(Handle),
}

impl fmt::Debug for WhitelistEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullKey(_) => f.write_str("WhitelistEntry::FullKey(<ML-DSA-87 pubkey>)"),
            Self::Handle(h) => f.debug_tuple("WhitelistEntry::Handle").field(h).finish(),
        }
    }
}

/// Why a single whitelist line failed to parse (ISC-10 / ISC-11). A malformed
/// entry is a hard error — never silently dropped — so an operator typo can't
/// quietly de-authorize a legitimate signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhitelistParseError {
    /// A `#`-bearing line did not parse as a `<name>#<hash>` handle.
    Handle(HandleParseError),
    /// A non-handle line was not valid hex.
    InvalidPubkeyHex,
    /// A hex line decoded to the wrong number of bytes for an ML-DSA-87 key.
    WrongPubkeyLength { found: usize, expected: usize },
}

impl fmt::Display for WhitelistParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handle(e) => write!(f, "invalid handle entry: {e}"),
            Self::InvalidPubkeyHex => write!(f, "full-key entry is not valid hex"),
            Self::WrongPubkeyLength { found, expected } => write!(
                f,
                "full-key entry is {found} bytes, expected {expected} for ML-DSA-87"
            ),
        }
    }
}

impl std::error::Error for WhitelistParseError {}

impl WhitelistEntry {
    /// Build a `FullKey` entry from raw ML-DSA-87 public-key bytes — e.g. a
    /// wire `SignerWhitelistEntry::FullPubkey` a client fetched via
    /// `GetSignerWhitelist`. Errors on the wrong length.
    pub fn from_full_key_bytes(bytes: &[u8]) -> Result<Self, WhitelistParseError> {
        let key: Box<[u8; ml_dsa::PK_LEN]> =
            bytes
                .to_vec()
                .into_boxed_slice()
                .try_into()
                .map_err(|v: Box<[u8]>| WhitelistParseError::WrongPubkeyLength {
                    found: v.len(),
                    expected: ml_dsa::PK_LEN,
                })?;
        Ok(WhitelistEntry::FullKey(key))
    }
}

impl FromStr for WhitelistEntry {
    type Err = WhitelistParseError;

    /// Parse one whitelist line. A `#` marks the handle form (ISC-11);
    /// otherwise the line is a hex-encoded full ML-DSA-87 key (ISC-10).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('#') {
            let handle = s.parse::<Handle>().map_err(WhitelistParseError::Handle)?;
            return Ok(WhitelistEntry::Handle(handle));
        }

        let bytes = hex::decode(s).map_err(|_| WhitelistParseError::InvalidPubkeyHex)?;
        Self::from_full_key_bytes(&bytes)
    }
}

// ── Project-announce signer (ISC-15) ───────────────────────────────

/// The baked ML-DSA-87 public key of the project-announce signer (ISC-15).
///
/// Held as a separate binary file rather than an array literal because it is
/// `ml_dsa::PK_LEN` bytes: the file is the artifact a reader diffs and a rotation
/// replaces, and its length is checked at compile time by this very coercion —
/// `include_bytes!` yields `&'static [u8; N]` for the file's actual `N`, so a file
/// of any other length fails to compile rather than producing a wrong key.
///
/// Baked, not derived: the seed it descends from is not in the source tree. The
/// one instance that signs — the operator — loads that seed at runtime through
/// [`ProjectAnnounceSeedSource`], and the load refuses any seed that does not derive
/// this exact key, so a client keeps only this constant and an operator cannot sign
/// under a key the fleet would reject. `current_trust_anchors_kat` pins the value.
const PROJECT_ANNOUNCE_PUBKEY: [u8; ml_dsa::PK_LEN] =
    *include_bytes!("project_announce_pubkey.bin");

/// The full ML-DSA-87 public key of the project-announce signer (ISC-15).
///
/// This entry is merged into every [`Whitelist`] regardless of the operator's
/// whitelist file, and there is no file syntax that removes it — that
/// non-removability is the whole point of (a self-host operator cannot
/// silence project announce announcements). Returns the baked
/// `PROJECT_ANNOUNCE_PUBKEY`: no derivation runs, so this needs no operational
/// oxicrypt module and cannot fail.
pub fn project_announce_pubkey() -> &'static [u8; ml_dsa::PK_LEN] {
    &PROJECT_ANNOUNCE_PUBKEY
}

/// Length of the project-announce seed — 32 bytes, an ML-DSA-87 keygen seed.
pub const PROJECT_ANNOUNCE_SEED_LEN: usize = 32;

/// Environment variable that carries the project-announce seed as 64 hex characters.
///
/// The variable is read in preference to the seed file, so a terminal launch or a
/// test rig can hand an instance the seed without touching its profile. A launcher
/// that carries no shell environment — a desktop-file or double-click launch — can
/// only supply the file.
pub const PROJECT_ANNOUNCE_SEED_ENV: &str = "DAEMONSEED_PROJECT_ANNOUNCE_SEED";

/// Name of the file, directly under the profile root, that holds the project-announce
/// seed as 64 hex characters. On Unix the file must not be readable by any user
/// other than its owner, or it is refused; other platforms do not check the mode.
pub const PROJECT_ANNOUNCE_SEED_FILENAME: &str = "project-announce.seed";

redacted_secret_newtype! {
    /// The project-announce seed: the one secret from which the project-announce
    /// signing key and the announce record's owner seed both descend (ISC-15).
    ///
    /// Held only by the operator instance, which loads it at runtime through
    /// [`ProjectAnnounceSeedSource`]; every other instance holds the two derived
    /// public keys and nothing else. The type carries the 32 bytes and their hygiene
    /// — zeroed on drop, `Debug` redacted (ISC-A-C1) — and nothing about whether
    /// they are the project's seed: that is what [`ProjectAnnounceSeedSource::load`]
    /// establishes for the value it returns, and what an operator credential checks
    /// again for both derived keys before holding one.
    boxed pub struct ProjectAnnounceSeed([u8; PROJECT_ANNOUNCE_SEED_LEN]);
}

impl ProjectAnnounceSeed {
    /// Wrap a seed already held as bytes.
    ///
    /// Only for a caller that is about to check the seed — the loader, or a test
    /// building the expectation it will check against. A shipped path holds a seed
    /// only through [`ProjectAnnounceSeedSource::load`].
    pub fn from_bytes(bytes: [u8; PROJECT_ANNOUNCE_SEED_LEN]) -> Self {
        Self(Box::new(bytes))
    }

    /// Parse the seed's 64-hex-character text form; surrounding whitespace is
    /// ignored. The error never carries the text.
    pub fn parse_hex(text: &str) -> Result<Self, SeedHexError> {
        let trimmed = text.trim();
        if trimmed.len() != 2 * PROJECT_ANNOUNCE_SEED_LEN {
            return Err(SeedHexError::Length(trimmed.len()));
        }
        let mut bytes = Box::new([0u8; PROJECT_ANNOUNCE_SEED_LEN]);
        hex::decode_to_slice(trimmed, &mut bytes[..]).map_err(|_| SeedHexError::NotHex)?;
        Ok(Self(bytes))
    }

    /// The ML-DSA-87 keypair the operator signs MOTD and announcements with. Its
    /// public key is [`project_announce_pubkey`] for a seed the loader accepted.
    /// Requires the oxicrypt module to be operational.
    pub fn signing_keypair(&self) -> Result<SignKeypair, KeyDerivationError> {
        SignKeypair::from_ml_dsa_seed(&self.0)
    }

    /// The announce record's owner seed, [`derive_project_announce_veilid_owner_seed`]
    /// over this seed.
    pub fn announce_owner_seed(
        &self,
    ) -> Result<ProjectAnnounceVeilidOwnerSeed, AnnounceOwnerError> {
        derive_project_announce_veilid_owner_seed(&self.0)
    }
}

/// Why a seed's text form did not parse. Carries the length, never the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedHexError {
    /// The value is not text at all (a variable holding bytes that are not UTF-8).
    NotText,
    /// The trimmed text is not exactly 64 characters long.
    Length(usize),
    /// A character is not a hexadecimal digit.
    NotHex,
}

impl fmt::Display for SeedHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotText => f.write_str("not valid text"),
            Self::Length(n) => write!(
                f,
                "expected {} hex characters, found {n}",
                2 * PROJECT_ANNOUNCE_SEED_LEN
            ),
            Self::NotHex => f.write_str("not hexadecimal"),
        }
    }
}

impl std::error::Error for SeedHexError {}

/// Where a loaded seed came from. Named in the operator's trace and in every
/// error, so a misconfiguration points at the thing to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedOrigin {
    /// [`PROJECT_ANNOUNCE_SEED_ENV`].
    Env,
    /// The seed file at this path.
    File(PathBuf),
}

impl fmt::Display for SeedOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env => write!(f, "environment variable {PROJECT_ANNOUNCE_SEED_ENV}"),
            Self::File(path) => write!(f, "file {}", path.display()),
        }
    }
}

/// Why an operator instance's seed could not be loaded.
///
/// Every variant is a fault in an instance that was given a seed: a source that is
/// simply absent is not an error but an ordinary reader, and
/// [`ProjectAnnounceSeedSource::load`] reports it as `Ok(None)`.
#[derive(Debug)]
pub enum ProjectAnnounceSeedError {
    /// The seed text did not parse.
    Malformed {
        /// Which source held it.
        origin: SeedOrigin,
        /// What was wrong with it.
        reason: SeedHexError,
    },
    /// The seed file exists but could not be read.
    Unreadable {
        /// The file.
        path: PathBuf,
        /// The read failure.
        source: std::io::Error,
    },
    /// The seed file is readable by a user other than its owner.
    Permissions {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The ML-DSA keygen over the seed failed.
    Derivation(KeyDerivationError),
    /// The seed parsed and derived a key, and that key is not the one this build
    /// trusts: whatever was supplied is not the project-announce seed.
    NotTheProjectSeed {
        /// Which source held it.
        origin: SeedOrigin,
    },
}

impl fmt::Display for ProjectAnnounceSeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { origin, reason } => {
                write!(
                    f,
                    "project-announce seed in {origin} is malformed: {reason}"
                )
            }
            Self::Unreadable { path, source } => write!(
                f,
                "project-announce seed file {} could not be read: {source}",
                path.display()
            ),
            Self::Permissions { path, mode } => write!(
                f,
                "project-announce seed file {} is readable by others (mode {mode:04o}); \
                 make it readable by its owner only",
                path.display()
            ),
            Self::Derivation(e) => write!(f, "project-announce key derivation failed: {e}"),
            Self::NotTheProjectSeed { origin } => write!(
                f,
                "the seed in {origin} does not derive the project-announce key this build trusts"
            ),
        }
    }
}

impl std::error::Error for ProjectAnnounceSeedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } => Some(source),
            Self::Derivation(e) => Some(e),
            Self::Malformed { reason, .. } => Some(reason),
            Self::Permissions { .. } | Self::NotTheProjectSeed { .. } => None,
        }
    }
}

/// The value of [`PROJECT_ANNOUNCE_SEED_ENV`] as it was taken out of the process
/// environment: the seed in its text form, and therefore a secret. Held in a
/// zeroed-on-drop buffer; `Clone` yields another such buffer; `Debug` is redacted.
/// Exists so a front end can carry the value from startup to the point it hands
/// it to [`ProjectAnnounceSeedSource`] without ever holding it in a plain string.
#[derive(Clone)]
pub struct ProjectAnnounceSeedText(Zeroizing<Vec<u8>>);

impl ProjectAnnounceSeedText {
    /// Take the variable's value. The `OsString` handed in is consumed; its bytes
    /// move into the zeroed-on-drop buffer.
    pub fn from_os_string(value: OsString) -> Self {
        Self(Zeroizing::new(value.into_encoded_bytes()))
    }
}

impl fmt::Debug for ProjectAnnounceSeedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProjectAnnounceSeedText(<redacted>)")
    }
}

/// Where an operator instance's seed may come from: the value of
/// [`PROJECT_ANNOUNCE_SEED_ENV`], read first, and the file
/// [`PROJECT_ANNOUNCE_SEED_FILENAME`] under the profile root.
///
/// Both inputs are handed in rather than read here, so the code under test reads
/// neither the environment nor the filesystem ambiently, and so the caller that
/// takes the variable out of the process environment can hand its value on.
///
/// The variable's value IS the seed, so this type is not `Clone` and its `Debug`
/// names whether the variable was set, never what it held.
pub struct ProjectAnnounceSeedSource {
    env: Option<ProjectAnnounceSeedText>,
    file: Option<PathBuf>,
}

impl fmt::Debug for ProjectAnnounceSeedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProjectAnnounceSeedSource")
            .field("env", &self.env.as_ref().map(|_| "<redacted>"))
            .field("file", &self.file)
            .finish()
    }
}

impl ProjectAnnounceSeedSource {
    /// A source from the variable's value, if it was set, and the seed file under
    /// `profile_root`. An instance with no profile root (an ephemeral session) can
    /// be given the seed only through the variable.
    pub fn new(env: Option<ProjectAnnounceSeedText>, profile_root: Option<&Path>) -> Self {
        Self {
            env,
            file: profile_root.map(|root| root.join(PROJECT_ANNOUNCE_SEED_FILENAME)),
        }
    }

    /// Load the seed and check it against the baked [`project_announce_pubkey`].
    ///
    /// The shipped entry point: [`Self::load_checked`] with the key this build
    /// trusts, and nothing else. It is exactly one line so that the only thing a
    /// test cannot supply — the real seed — is also the only thing it does not
    /// exercise; `load_refuses_a_seed_that_is_not_the_project_seed` pins that the
    /// expectation really is the baked key and not something derived from the seed
    /// under test.
    pub fn load(
        &self,
    ) -> Result<Option<(ProjectAnnounceSeed, SeedOrigin)>, ProjectAnnounceSeedError> {
        self.load_checked(project_announce_pubkey())
    }

    /// Load the seed and check it against `expected_pubkey`.
    ///
    /// `Ok(None)` is an instance that was given no seed — the ordinary reader.
    /// `Ok(Some)` is a seed that derived `expected_pubkey`, with where it came from.
    /// Every other outcome is an error: an instance that was given a seed and cannot
    /// use it is told so rather than silently demoted to a reader, because an
    /// operator that stops writing with nothing anywhere to say why is the failure
    /// the announce record's keep-alive exists to prevent.
    ///
    /// The variable, if set at all, is the seed; the file is consulted only when
    /// the variable is unset. A set-but-empty variable is therefore malformed, not
    /// absent. A missing file is absence; a file that exists and cannot be read, is
    /// not a regular file, or (on Unix) is readable by other users, is an error.
    ///
    /// The expected key is a parameter so that the check has a positive control: a
    /// test seed loads against its own derived key and is refused against any other.
    /// Requires the oxicrypt module to be operational.
    pub fn load_checked(
        &self,
        expected_pubkey: &[u8; ml_dsa::PK_LEN],
    ) -> Result<Option<(ProjectAnnounceSeed, SeedOrigin)>, ProjectAnnounceSeedError> {
        let Some((text, origin)) = self.read()? else {
            return Ok(None);
        };
        let seed = ProjectAnnounceSeed::parse_hex(&text).map_err(|reason| {
            ProjectAnnounceSeedError::Malformed {
                origin: origin.clone(),
                reason,
            }
        })?;
        let keypair = seed
            .signing_keypair()
            .map_err(ProjectAnnounceSeedError::Derivation)?;
        if keypair.public_key() != expected_pubkey {
            return Err(ProjectAnnounceSeedError::NotTheProjectSeed { origin });
        }
        Ok(Some((seed, origin)))
    }

    /// The seed's text and where it came from, or `None` when neither source is
    /// present. The text is zeroed when dropped.
    fn read(&self) -> Result<Option<(Zeroizing<String>, SeedOrigin)>, ProjectAnnounceSeedError> {
        if let Some(value) = &self.env {
            let text = String::from_utf8(value.0.to_vec()).map_err(|_| {
                ProjectAnnounceSeedError::Malformed {
                    origin: SeedOrigin::Env,
                    reason: SeedHexError::NotText,
                }
            })?;
            return Ok(Some((Zeroizing::new(text), SeedOrigin::Env)));
        }
        let Some(path) = &self.file else {
            return Ok(None);
        };
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ProjectAnnounceSeedError::Unreadable {
                    path: path.clone(),
                    source,
                });
            }
        };
        if !metadata.is_file() {
            return Err(ProjectAnnounceSeedError::Unreadable {
                path: path.clone(),
                source: std::io::Error::other("not a regular file"),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(ProjectAnnounceSeedError::Permissions {
                    path: path.clone(),
                    mode,
                });
            }
        }
        let text = std::fs::read_to_string(path).map_err(|source| {
            ProjectAnnounceSeedError::Unreadable {
                path: path.clone(),
                source,
            }
        })?;
        Ok(Some((Zeroizing::new(text), SeedOrigin::File(path.clone()))))
    }
}

/// Length of the project-announce Veilid rendezvous-owner seed — 32 bytes (a VLD0
/// Ed25519 secret seed).
pub const PROJECT_ANNOUNCE_VEILID_OWNER_SEED_LEN: usize = 32;

redacted_secret_newtype! {
    /// The project-announce channel's Veilid **rendezvous-owner** seed (Phase 4 A1) —
    /// the DHT write-gate for the single project announcements/MOTD channel (A0). A
    /// **sibling** of the content-signing key: both derive from the one
    /// maintainer-held project-announce seed, but the content key uses it as an ML-DSA
    /// seed directly while this HKDF-expands it under a distinct label
    /// ([`info::PROJECT_ANNOUNCE_VEILID_OWNER`]), so transport-owner and
    /// content-signing material are domain-separated — possessing one never yields the
    /// other. Held ONLY by the maintainer (the single-owner DHT constraint IS the
    /// write-gate, A1); clients hold only the derived owner PUBKEY, from which they
    /// compute the record address to read / watch / verify — they cannot write. Zeroes
    /// on drop; `Debug` is redacted (ISC-A-C1). Content NEVER derives from this.
    boxed pub struct ProjectAnnounceVeilidOwnerSeed([u8; PROJECT_ANNOUNCE_VEILID_OWNER_SEED_LEN]);
}

/// Failure deriving the project-announce Veilid rendezvous-owner seed.
#[derive(Debug)]
pub enum AnnounceOwnerError {
    /// The HKDF extract/expand step failed.
    Hkdf(oxicrypt_kdf::KdfError),
}

impl fmt::Display for AnnounceOwnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hkdf(e) => write!(f, "project-announce owner HKDF failed: {e:?}"),
        }
    }
}

impl std::error::Error for AnnounceOwnerError {}

/// Derive the project-announce channel's Veilid rendezvous-owner seed from the
/// maintainer's project-announce seed (A1 write-gate).
///
/// ```text
///   owner_seed = HKDF-SHA-384(
///       salt = PROJECT_ANNOUNCE_OWNER_SALT,
///       ikm  = project_seed,                       // maintainer-held (offline in prod)
///       info = "daemonseed/veilid/project-announce-owner")
/// ```
///
/// Domain-separated from the content-signing key (which uses `project_seed`
/// as an ML-DSA seed directly), so a holder of one cannot derive the other. The
/// project seed is not in the source tree: the operator instance loads it at
/// runtime ([`ProjectAnnounceSeedSource`]) and reaches this through
/// [`ProjectAnnounceSeed::announce_owner_seed`]; every other instance holds only the
/// derived owner PUBLIC key, baked into the transport crate.
pub fn derive_project_announce_veilid_owner_seed(
    project_seed: &[u8; 32],
) -> Result<ProjectAnnounceVeilidOwnerSeed, AnnounceOwnerError> {
    let extract = HkdfSha384::extract(Some(info::PROJECT_ANNOUNCE_OWNER_SALT), project_seed)
        .map_err(AnnounceOwnerError::Hkdf)?;
    Ok(ProjectAnnounceVeilidOwnerSeed(
        derive_boxed_seed(&extract, info::PROJECT_ANNOUNCE_VEILID_OWNER.as_bytes())
            .map_err(AnnounceOwnerError::Hkdf)?,
    ))
}

/// A uniformly random starting point in the announce record's slot key space (#238).
///
/// The keep-alive rotates a cursor over content-address slots in key order. Starting
/// every session at "no cursor" — i.e. at the numerically lowest slot — would walk the
/// SAME prefix on every launch, so an operator whose sessions are shorter than `N`
/// emissions would refresh the first few announcements forever and never reach the tail:
/// precisely the silent expiry the keep-alive exists to prevent, and worse for being
/// deterministic. Seeding from a random point makes each session start somewhere
/// different, so coverage is uniform across sessions instead of prefix-biased.
///
/// The value is compared lexicographically against `hex(content_address)` slot ids, so
/// only the leading characters decide placement and 16 hex digits is ample. An entropy
/// failure yields an empty string, which starts at the first slot — degraded to the
/// unseeded behaviour, never a failure.
pub fn random_announce_slot_cursor() -> String {
    let mut buf = [0u8; 8];
    match getrandom::fill(&mut buf) {
        Ok(()) => hex::encode(buf),
        Err(_) => String::new(),
    }
}

/// Lower bound of the jittered operator keep-alive band (#238).
///
/// Veilid has no TTL — retention is capacity-eviction only — so an announcement
/// survives exactly as long as someone re-seeds it (#141). The band is deliberately
/// slow, against measured evidence: in early manual testing announcement values survived
/// **more than 24 hours with nobody re-seeding them at all**, so eviction pressure on
/// this record is far lower than the original fixed 120 s cadence assumed.
///
/// Paired with one-slot-per-emission at the caller, this puts an operator's write rate
/// onto the announce record at roughly **one write per hour**, with each individual slot
/// refreshed every `N` hours for `N` standing announcements — an ~8x margin over the
/// observed survival floor at `N = 3`, still 4x at `N = 6`.
///
/// That is also the whole *fleet's* rate: only the instance holding the project-announce
/// seed re-seeds, in every build profile, so a fleet of any size puts one operator's
/// writes on the record.
///
/// **Tunable, and expected to be tuned.** The 24 h observation is a property of how
/// loaded the DHT was during that test, not a constant: eviction is capacity-driven, so
/// a busier network evicts sooner. Widen or narrow the band if announcements start
/// vanishing. What must NOT come back is a fast *fixed* period — see
/// [`next_operator_keepalive_interval`] for why.
pub const OPERATOR_KEEPALIVE_INTERVAL_MIN: Duration = Duration::from_secs(45 * 60);

/// Upper bound of the jittered operator keep-alive band (#238). See
/// [`OPERATOR_KEEPALIVE_INTERVAL_MIN`] for how the band was chosen.
pub const OPERATOR_KEEPALIVE_INTERVAL_MAX: Duration = Duration::from_secs(75 * 60);

/// Lower bound of the jittered delay before an operator's FIRST keep-alive emission of a
/// session (#238).
///
/// The steady band is deliberately slow, but applying it to the first emission too would
/// mean a session shorter than [`OPERATOR_KEEPALIVE_INTERVAL_MIN`] refreshes **nothing at
/// all** — and an operator that runs the client in short bursts would silently never
/// re-seed, which under operator-only keep-alive means the announcements age out with no
/// indication why. Emitting soon after start makes any session past a few minutes refresh
/// at least one slot, and a session of roughly `N` hours cycles all `N` of them.
///
/// **Known leak, not concealed by the jitter.** This band is disjoint from — and far
/// below — the steady band, so an observer watching the record sees any inter-write gap
/// under [`OPERATOR_KEEPALIVE_INTERVAL_MIN`] and knows it was a first emission, pinning
/// session start to this window. Jitter fuzzes the marker; concealment would need the
/// two bands to OVERLAP. Under operator-only keep-alive the record already leaks
/// operator liveness (every write on it is the operator's), so this sharpens an accepted
/// signal rather than opening a new class — but it IS a session-boundary marker of the
/// shape WB-1.4/1.6 forbid for presence records, and it is the price of guaranteeing a
/// short session refreshes something. Collapsing to one wide band, e.g. `[2, 75] min`,
/// removes the marker at the cost of that guarantee. Tracked in
/// `docs/design/operator-space-management.md`.
pub const OPERATOR_KEEPALIVE_FIRST_MIN: Duration = Duration::from_secs(2 * 60);

/// Upper bound of the jittered delay before an operator's first keep-alive emission. See
/// [`OPERATOR_KEEPALIVE_FIRST_MIN`].
pub const OPERATOR_KEEPALIVE_FIRST_MAX: Duration = Duration::from_secs(5 * 60);

/// Draw the jittered delay before the FIRST operator keep-alive emission of a session,
/// uniformly random in `[OPERATOR_KEEPALIVE_FIRST_MIN, OPERATOR_KEEPALIVE_FIRST_MAX]`.
/// Every emission after the first uses [`next_operator_keepalive_interval`].
pub fn first_operator_keepalive_interval() -> Duration {
    interval_in_band(
        OPERATOR_KEEPALIVE_FIRST_MIN,
        OPERATOR_KEEPALIVE_FIRST_MAX,
        crate::jitter::os_fill,
    )
}

/// Draw the next jittered operator keep-alive interval, uniformly random in
/// `[OPERATOR_KEEPALIVE_INTERVAL_MIN, OPERATOR_KEEPALIVE_INTERVAL_MAX]`.
///
/// Jitter is drawn **per emission**, never once per session — the WB-1.2 pattern, and
/// the same shape as [`crate::presence::next_keepalive_interval`]. A fixed period (the
/// `tokio::time::interval` this replaced) gives the record a recognisable cadence
/// signature and phase-locks every client that holds it into a thundering herd, which
/// WB-3 I6 forbids for exactly this kind of keepalive.
///
/// Drawn from the OS CSPRNG; an entropy failure falls back to the band midpoint — a
/// keep-alive is liveness, not a key, and the next draw recovers. Both operator bands
/// draw through the crate-internal `presence::interval_in_band`, which is the single
/// definition of this arithmetic and carries the seam the band-width and degrade
/// assertions need.
pub fn next_operator_keepalive_interval() -> Duration {
    interval_in_band(
        OPERATOR_KEEPALIVE_INTERVAL_MIN,
        OPERATOR_KEEPALIVE_INTERVAL_MAX,
        crate::jitter::os_fill,
    )
}

/// A monotonic freshness / rollback guard for an operator announce/MOTD record —
/// the **#78 replay guard applied to the operator record** (A1, "gaps closed").
/// Live-only DHT has no store-and-forward, so a client reading a stale subkey sees
/// an old roster/MOTD, and an untrusted transport could serve a stale slot to roll
/// back a revocation or a superseded MOTD. The guard holds the newest version a
/// client has accepted and rejects anything strictly older.
///
/// **The version MUST be a strictly-monotonic, operator-incremented counter —
/// NEVER a wall clock.** A `sent_unix_ms` source is unsafe *here*: an operator clock
/// step-back (NTP correction, VM drift, a same-millisecond republish) makes a
/// legitimate newer record carry a LOWER version, which the guard would then reject
/// fleet-wide with no feedback — the operator's update silently vanishes. (This is
/// why it is NOT the presence beacon's `beacon_is_fresh`, whose bounded-window,
/// self-healing check tolerates skew: a rollback guard cannot.)
///
/// Keeping `last_seen` as STATE rather than a second argument makes the guard
/// **transposition-proof** — there is no `(incoming, last_seen)` call a caller can
/// silently reverse to invert the check (an argument-order bug here would accept
/// rollbacks, the exact attack this exists to block).
#[derive(Debug, Clone, Copy, Default)]
pub struct AnnounceFreshness {
    last_seen: u64,
}

impl AnnounceFreshness {
    /// A guard with no record accepted yet (accepts any first version).
    pub fn new() -> Self {
        Self { last_seen: 0 }
    }

    /// A guard seeded from a persisted last-seen version.
    pub fn from_last_seen(last_seen: u64) -> Self {
        Self { last_seen }
    }

    /// The newest accepted version.
    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }

    /// Whether an arriving record at `incoming` is fresh (`>= last_seen`, so an
    /// idempotent re-fetch of the current version is accepted; a strictly-older slot
    /// is rejected) — a PURE check that does not advance the state.
    pub fn accepts(&self, incoming: u64) -> bool {
        incoming >= self.last_seen
    }

    /// Accept an arriving record at `incoming`: returns whether it was fresh, and on
    /// a fresh record advances `last_seen` to it (an equal re-accept is a no-op
    /// advance). A strictly-older record is rejected and leaves the state unchanged.
    pub fn accept(&mut self, incoming: u64) -> bool {
        if incoming >= self.last_seen {
            self.last_seen = incoming;
            true
        } else {
            false
        }
    }
}

/// The operator's signer whitelist (ISC-S8), plus the always-present
/// project-announce entry (ISC-15).
///
/// Authorization is the cheap gate run before any signature verification
/// (ISC-12): an unknown key never reaches the ML-DSA verify path.
#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    entries: Vec<WhitelistEntry>,
}

impl Whitelist {
    /// Build a whitelist from the operator's parsed file entries. The
    /// project-announce entry  is *not* stored here — it is checked
    /// unconditionally by [`Self::authorizes`], so no operator file content can
    /// remove it.
    pub fn from_entries(entries: Vec<WhitelistEntry>) -> Self {
        Self { entries }
    }

    /// The operator-configured entries, for publishing to clients via
    /// `GetSignerWhitelist` (ISC-S8 / ISC-6).
    pub fn entries(&self) -> &[WhitelistEntry] {
        &self.entries
    }

    /// Whether `pubkey` is authorized to sign posts / MOTDs (ISC-12 / ISC-S8).
    ///
    /// The project-announce key  is always authorized. For operator
    /// entries: a `FullKey` matches by exact bytes; a `Handle` matches by
    /// hash-prefix against the arriving key (ISC-12), which is computed without
    /// touching the signature.
    pub fn authorizes(&self, pubkey: &[u8]) -> Result<bool, OxicryptError> {
        // The project-announce signer is always authorized, regardless of
        // the operator's file (ISC-15).
        if pubkey == project_announce_pubkey().as_slice() {
            return Ok(true);
        }

        for entry in &self.entries {
            match entry {
                WhitelistEntry::FullKey(key) => {
                    if pubkey == key.as_slice() {
                        return Ok(true);
                    }
                }
                WhitelistEntry::Handle(handle) => {
                    // ISC-12: match the arriving key's hash-prefix against the
                    // entry's. SHA-384 of the key is the only work here — no
                    // signature verification.
                    let arriving = Handle::from_pubkey(None, pubkey)?;
                    if arriving.hash_prefix() == handle.hash_prefix() {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

// ── Artifact verification (ISC-A-S3 / ISC-7 / ISC-17) ────────────────────

/// Why a `SignedArtifact` failed verification. The server's `UploadPost`
/// maps both `UnknownSigner` and `BadSignature` to the same opaque gRPC
/// rejection (no oracle for which check failed); a client uses the distinction
/// to decide whether to drop a server-served artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    /// The signer's key is not authorized by the whitelist (ISC-S8).
    UnknownSigner,
    /// The detached ML-DSA-87 signature did not verify over `signed_payload`,
    /// or the key / signature was malformed.
    BadSignature,
    /// The oxicrypt module was not operational (self-test pending).
    Module(OxicryptError),
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSigner => write!(f, "signer not in whitelist"),
            Self::BadSignature => write!(f, "signature did not verify"),
            Self::Module(e) => write!(f, "crypto module not operational: {e}"),
        }
    }
}

impl std::error::Error for ArtifactError {}

/// Verify a signed artifact and return its content address (ISC-A-S3).
///
/// The pipeline, in order (ISC-12): (1) whitelist authorization — the cheap
/// gate; (2) ML-DSA-87 signature verification over the exact `signed_payload`
/// bytes (D-M6-7); (3) `SHA-384(signed_payload)` content address. Both the
/// server (verify-then-serve) and every client (re-verify what the server
/// served) call this — there is exactly one implementation of "is this artifact
/// trustworthy", so the server cannot serve content a client wouldn't accept.
pub fn verify_artifact(
    signed_payload: &[u8],
    signer_pubkey: &[u8],
    signature: &[u8],
    whitelist: &Whitelist,
) -> Result<ContentAddress, ArtifactError> {
    // (1) Cheap gate first (ISC-12): unauthorized keys never reach verify.
    if !whitelist
        .authorizes(signer_pubkey)
        .map_err(ArtifactError::Module)?
    {
        return Err(ArtifactError::UnknownSigner);
    }

    // (2) Fixed-size key/signature. A malformed key can't be a real signer;
    // a malformed signature can't verify — both fail closed.
    let pubkey: &[u8; ml_dsa::PK_LEN] = signer_pubkey
        .try_into()
        .map_err(|_| ArtifactError::UnknownSigner)?;
    let sig: &[u8; ml_dsa::SIG_LEN] = signature
        .try_into()
        .map_err(|_| ArtifactError::BadSignature)?;

    // (3) ML-DSA-87 over the exact signed bytes (D-M6-7).
    verify_signature(pubkey, signed_payload, sig).map_err(|_| ArtifactError::BadSignature)?;

    // (4) Address is derived, never asserted (ISC-17 / ISC-A-S3).
    content_address(signed_payload).map_err(ArtifactError::Module)
}

// ── MOTD plaintext rule (ISC-S9) ─────────────────────────────────────────

/// True if `text` is a valid single-line plaintext MOTD (ISC-S9 anti-injection):
/// no forbidden character (see `is_motd_forbidden_char`). This enforces a
/// single line with no embedded control / line-break / direction-spoofing
/// sequences. Markdown/HTML/link *rendering* is the client's verbatim-render
/// obligation, not server-detectable.
///
/// Shared so server-ingest (`UploadMotd`) and the client composer enforce one
/// definition of "plaintext MOTD".
pub fn motd_text_is_valid(text: &str) -> bool {
    !text.chars().any(is_motd_forbidden_char)
}

/// A character forbidden in a single-line plaintext MOTD (ISC-S9). `char::
/// is_control()` covers only C0/C1 controls, so the Unicode line/paragraph
/// separators (which DO render as line breaks) and the bidi/format controls
/// (text-direction spoofing surface) are listed explicitly — otherwise the
/// "single line, no injection" invariant is bypassable.
fn is_motd_forbidden_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{2028}' | '\u{2029}'                  // line / paragraph separator
            | '\u{200E}' | '\u{200F}' | '\u{061C}'   // LRM / RLM / ALM
            | '\u{202A}'..='\u{202E}'                // LRE RLE PDF LRO RLO
            | '\u{2066}'..='\u{2069}'                // LRI RLI FSI PDI
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #238: both keep-alive bands draw in range and actually vary. A constant interval
    /// would restore the exact fixed-period cadence signature the band exists to remove
    /// (WB-1.2 / WB-3 I6), and nothing else in the tree would notice.
    #[test]
    fn operator_keepalive_intervals_are_in_band_and_jittered() {
        let mut steady = std::collections::HashSet::new();
        let mut first = std::collections::HashSet::new();
        for _ in 0..64 {
            let d = next_operator_keepalive_interval();
            assert!(
                d >= OPERATOR_KEEPALIVE_INTERVAL_MIN && d <= OPERATOR_KEEPALIVE_INTERVAL_MAX,
                "steady interval {d:?} outside the band"
            );
            steady.insert(d.as_millis());

            let f = first_operator_keepalive_interval();
            assert!(
                f >= OPERATOR_KEEPALIVE_FIRST_MIN && f <= OPERATOR_KEEPALIVE_FIRST_MAX,
                "first interval {f:?} outside the band"
            );
            first.insert(f.as_millis());
        }
        assert!(steady.len() > 1, "steady band produced a constant interval");
        assert!(first.len() > 1, "first band produced a constant interval");
    }

    /// #238: the bands are well-formed and correctly ordered.
    ///
    /// An inverted band is silent at the call site, and ordering the constants is the
    /// only thing that catches it. The shared draw subtracts plainly behind a
    /// `debug_assert!`, so an inversion aborts a debug build, and this workspace sets
    /// `overflow-checks = true` on the release profile, so it panics there too rather
    /// than wrapping. A consumer building `daemonseed-core` under the default release
    /// profile gets the wrap instead, handing its caller an interval nowhere near
    /// either bound. The assertion has to live here, against the constants, because
    /// that is the only place the ordering is a fact rather than an argument.
    ///
    /// The first band exists only because it is shorter than the steady one; if that
    /// stops being true the short first emission is pointless and its rustdoc is false.
    #[test]
    fn operator_keepalive_bands_are_well_formed() {
        assert!(OPERATOR_KEEPALIVE_INTERVAL_MIN <= OPERATOR_KEEPALIVE_INTERVAL_MAX);
        assert!(OPERATOR_KEEPALIVE_FIRST_MIN <= OPERATOR_KEEPALIVE_FIRST_MAX);
        assert!(
            OPERATOR_KEEPALIVE_FIRST_MAX < OPERATOR_KEEPALIVE_INTERVAL_MIN,
            "the first emission must be sooner than any steady one"
        );
    }

    /// Both operator bands are reachable end to end, pinned exactly (#372).
    ///
    /// `operator_keepalive_intervals_are_in_band_and_jittered` above cannot see band
    /// WIDTH: it asserts membership of `[MIN, MAX]` and that more than one value
    /// occurred, and a draw collapsed to `% (span / 10 + 1)` satisfies both — every
    /// interval lands in the first tenth of its band, still in range, still varying. A
    /// narrowed band is a tighter cadence signature, which is the property the jitter
    /// exists to remove (WB-1.2 / WB-3 I6).
    ///
    /// Deterministic, not statistical: a fill of `span` must map to exactly `MAX`, so
    /// the collapse fails here on every run rather than with some probability.
    #[test]
    fn operator_keepalive_band_ends_are_exactly_reachable() {
        for (min, max, name) in [
            (
                OPERATOR_KEEPALIVE_INTERVAL_MIN,
                OPERATOR_KEEPALIVE_INTERVAL_MAX,
                "steady",
            ),
            (
                OPERATOR_KEEPALIVE_FIRST_MIN,
                OPERATOR_KEEPALIVE_FIRST_MAX,
                "first",
            ),
        ] {
            let span = (max.as_millis() - min.as_millis()) as u64;
            let at = |v: u64| {
                interval_in_band(min, max, move |buf| {
                    *buf = v.to_le_bytes();
                    Ok(())
                })
            };
            assert_eq!(
                at(0),
                min,
                "{name}: a zero draw must land on the band floor"
            );
            assert_eq!(
                at(span),
                max,
                "{name}: a draw of the full span must reach the band ceiling — if it \
                 does not, the reachable band is narrower than the declared one and the \
                 keep-alive carries a tighter cadence signature than intended"
            );
            assert_eq!(
                at(span / 2),
                min + Duration::from_millis(span / 2),
                "{name}: the midpoint draw must land on the midpoint"
            );
        }
    }

    /// The entropy-failure degrade lands on the band midpoint, not on an end (#372).
    ///
    /// Unreachable while these bands owned their own draw and called `getrandom`
    /// directly; the seam is the `fill` parameter [`interval_in_band`] takes. A degrade
    /// to a band END would put every operator that lost entropy onto the same extreme
    /// period, a stronger correlation signal than the fixed period the jitter replaced.
    #[test]
    fn an_operator_entropy_failure_degrades_to_the_band_midpoint() {
        for (min, max, name) in [
            (
                OPERATOR_KEEPALIVE_INTERVAL_MIN,
                OPERATOR_KEEPALIVE_INTERVAL_MAX,
                "steady",
            ),
            (
                OPERATOR_KEEPALIVE_FIRST_MIN,
                OPERATOR_KEEPALIVE_FIRST_MAX,
                "first",
            ),
        ] {
            let span = (max.as_millis() - min.as_millis()) as u64;
            let d = interval_in_band(min, max, |_| Err(()));
            assert_eq!(
                d,
                min + Duration::from_millis(span / 2),
                "{name}: an entropy failure must degrade to the midpoint"
            );
            assert!(
                d > min && d < max,
                "{name}: the degrade must not sit on an end"
            );
        }
    }

    /// The PRODUCTION source spans the steady band, in both halves, with real
    /// population and without a density tilt (#372).
    ///
    /// The deterministic tests above pin the arithmetic and would still pass if
    /// `os_fill` were swapped for something confined or skewed. This one covers the
    /// source. Run on the steady band only: both operator draws now reach the same
    /// helper with the same `fill`, so one statistical sample covers the source for
    /// both, and the deterministic tests are what pin each band's own constants.
    ///
    /// Every floor is derived from this band rather than carried over from another.
    /// Over `DRAWS` samples on a 1 800 001 ms span: missing a half has probability
    /// `2^-4095`; the expected collision count is `C(4096,2)/1800001 ≈ 4.7`, so ~4091
    /// distinct values are expected against a floor of 4050; and the upper third's
    /// share has `σ ≈ 0.74%` about 33.3%, putting the 27% floor 8.6σ down.
    ///
    /// **Range and cardinality together are not uniformity**, which is why the
    /// upper-third share is asserted separately — a draw can span the whole band with
    /// four thousand distinct values and still be twice as dense at the bottom.
    #[test]
    fn the_production_operator_keepalive_draw_spans_its_band() {
        const DRAWS: usize = 4096;
        let span_ms = (OPERATOR_KEEPALIVE_INTERVAL_MAX.as_millis()
            - OPERATOR_KEEPALIVE_INTERVAL_MIN.as_millis()) as u64;
        let mid = OPERATOR_KEEPALIVE_INTERVAL_MIN + Duration::from_millis(span_ms / 2);
        let top_third = OPERATOR_KEEPALIVE_INTERVAL_MIN + Duration::from_millis(span_ms * 2 / 3);

        let mut seen = std::collections::HashSet::new();
        let (mut lower, mut upper, mut in_top_third) = (0usize, 0usize, 0usize);
        let (mut lo, mut hi) = (
            OPERATOR_KEEPALIVE_INTERVAL_MAX,
            OPERATOR_KEEPALIVE_INTERVAL_MIN,
        );
        for _ in 0..DRAWS {
            let d = next_operator_keepalive_interval();
            seen.insert(d.as_millis());
            if d < mid {
                lower += 1;
            } else {
                upper += 1;
            }
            if d >= top_third {
                in_top_third += 1;
            }
            lo = lo.min(d);
            hi = hi.max(d);
        }

        assert!(
            lower > 0 && upper > 0,
            "every one of {DRAWS} draws fell in one half of the band \
             (lower={lower}, upper={upper}) — the draw is confined, not uniform"
        );
        // Three quarters of the span: a uniform draw covers essentially all of it at
        // this sample size, and the tenth-collapse mutation leaves 10%.
        let observed = (hi - lo).as_millis() as u64;
        assert!(
            observed * 4 >= span_ms * 3,
            "observed spread {observed} ms covers less than three quarters of the \
             {span_ms} ms band — the reachable band is narrower than the declared one"
        );
        // UNIFORMITY, which range and cardinality cannot see. The mutation that drives
        // this floor is a draw biased toward the bottom while still reaching both ends:
        // taking the MIN of two independent draws — the shape a botched clamp or a
        // mis-written rejection-sampling retry produces — leaves the top third at
        // (1/3)^2 = 11.1% while range, halves and cardinality all stay green. Note the
        // narrow-SOURCE mutation that drives the same floor on the 40 s presence band
        // (truncating the entropy read to `u16`) does not apply here: this span is
        // 1.8 M ms, so every natural truncation either falls far short of the band and
        // is caught by the spread floor above, or is wide enough to be uniform to
        // within a fraction of a σ. Floor at 27% is ~8.6σ under uniform.
        assert!(
            in_top_third * 100 >= DRAWS * 27,
            "only {in_top_third} of {DRAWS} draws landed in the band's upper third \
             ({:.1}%, uniform is 33.3%) — the draw spans its band but is denser at the \
             bottom, which is a cadence signature even though every value is in range",
            in_top_third as f64 * 100.0 / DRAWS as f64
        );
        assert!(
            seen.len() >= 4050,
            "only {} distinct values in {DRAWS} draws — a uniform draw over {} values \
             yields ~4091, so this is quantised onto a grid, which neither the spread \
             floor nor the density check above can see",
            seen.len(),
            span_ms + 1
        );
    }

    /// #238: pin the documented write rate. The band's mean sets the operator's write
    /// rate onto the announce record, and that figure is asserted in the rustdoc, the
    /// CHANGELOG, the ISA Decisions entry and `docs/design/operator-space-management.md`
    /// (~1 write/hour, each slot refreshed every `N` hours). Widening or narrowing the
    /// band silently falsifies all four; this fails first. Mirrors
    /// `dm::keyrec::reseed_cadence_matches_the_budgeted_rate`.
    #[test]
    fn operator_keepalive_cadence_matches_the_documented_rate() {
        let mean_secs = (OPERATOR_KEEPALIVE_INTERVAL_MIN.as_secs()
            + OPERATOR_KEEPALIVE_INTERVAL_MAX.as_secs()) as f64
            / 2.0;
        let writes_per_hour = 3600.0 / mean_secs;
        assert!(
            (0.8..=1.3).contains(&writes_per_hour),
            "documented as ~1 write/hour, band gives {writes_per_hour:.2}/hour — update \
             the rustdoc, CHANGELOG, ISA Decisions and the operator-space design doc"
        );
        // The margin claim: at N announcements each slot waits N × mean. Against the
        // measured >24 h retention floor, N=3 must keep a >=8x margin.
        let margin_at_3 = 24.0 * 3600.0 / (3.0 * mean_secs);
        assert!(
            margin_at_3 >= 7.5,
            "documented ~8x margin at N=3, band gives {margin_at_3:.1}x"
        );
    }

    /// #238: the random cursor seed lands in the slot key space and varies. A constant
    /// seed would put every session's rotation back at the same starting slot, which is
    /// the prefix-bias this function exists to remove.
    #[test]
    fn random_announce_slot_cursor_varies_and_is_hex() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let c = random_announce_slot_cursor();
            assert!(
                c.chars()
                    .all(|ch| ch.is_ascii_hexdigit() && !ch.is_uppercase()),
                "cursor {c} must compare against lowercase-hex slot ids"
            );
            seen.insert(c);
        }
        assert!(seen.len() > 1, "cursor seed produced a constant value");
    }

    /// ISC-S9: a normal single line is accepted; any control character
    /// (newline / CR / tab) is rejected.
    #[test]
    fn motd_text_validity_accepts_plaintext_rejects_controls() {
        // Accepted: a normal line, empty, spaces, punctuation, a URL-looking string.
        assert!(motd_text_is_valid("Welcome to the relay!"));
        assert!(motd_text_is_valid(""));
        assert!(motd_text_is_valid("   "));
        assert!(motd_text_is_valid("Maintenance 02:00-03:00 UTC; thanks."));
        assert!(motd_text_is_valid(
            "see https://example.org/news for details"
        ));
        // Rejected: embedded control characters (no single-line guarantee).
        assert!(!motd_text_is_valid("a\nb"));
        assert!(!motd_text_is_valid("a\tb"));
        assert!(!motd_text_is_valid("\r"));
        // Rejected: Unicode line/paragraph separators (render as line breaks).
        assert!(!motd_text_is_valid("a\u{2028}b"));
        assert!(!motd_text_is_valid("a\u{2029}b"));
        // Rejected: bidi/format controls (text-direction spoofing surface).
        assert!(!motd_text_is_valid("a\u{202E}b"));
        assert!(!motd_text_is_valid("a\u{2066}b"));
    }

    /// Bootstrap oxicrypt's FIPS module for SHA-384 / ML-DSA tests.
    /// `initialize` is idempotent; the `AlreadyInitialized` second call is
    /// deliberately ignored.
    fn ensure_module() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    /// ISC-17: the content address is exactly `SHA-384(signed_payload)`.
    #[test]
    fn content_address_is_sha384_of_payload() {
        ensure_module();
        let payload = b"a signed post payload";
        let addr = content_address(payload).unwrap();

        let expected = sha384(payload).unwrap();
        assert_eq!(addr.as_bytes(), &expected[..CONTENT_ADDRESS_LEN]);
    }

    /// Distinct payloads address to distinct content (collision-free at this
    /// scale) — the property that makes the address a usable post id.
    #[test]
    fn content_address_differs_for_distinct_payloads() {
        ensure_module();
        let a = content_address(b"payload one").unwrap();
        let b = content_address(b"payload two").unwrap();
        assert_ne!(a, b);
    }

    // ── WhitelistEntry parsing (ISC-10 / ISC-11) ─────────────────────────

    /// ISC-10: a hex-encoded full ML-DSA-87 key parses as a `FullKey` entry.
    #[test]
    fn parses_full_key_entry() {
        let key = [0xABu8; ml_dsa::PK_LEN];
        let line = hex::encode(key);
        match line.parse::<WhitelistEntry>().unwrap() {
            WhitelistEntry::FullKey(k) => assert_eq!(k.as_slice(), key.as_slice()),
            other => panic!("expected FullKey, got {other:?}"),
        }
    }

    /// ISC-11: a `<name>#<hash>` line parses as a `Handle` entry.
    #[test]
    fn parses_handle_entry() {
        match "relay-bear#aabbccddeeff".parse::<WhitelistEntry>().unwrap() {
            WhitelistEntry::Handle(h) => {
                assert_eq!(h.display_name(), Some("relay-bear"));
            }
            other => panic!("expected Handle, got {other:?}"),
        }
    }

    /// A hex line that decodes to the wrong byte count is a hard error, not a
    /// silently-dropped entry.
    #[test]
    fn rejects_wrong_length_pubkey_hex() {
        let line = hex::encode([0u8; 10]);
        match line.parse::<WhitelistEntry>() {
            Err(WhitelistParseError::WrongPubkeyLength { found: 10, .. }) => {}
            other => panic!("expected WrongPubkeyLength, got {other:?}"),
        }
    }

    /// A non-handle line that isn't valid hex is rejected.
    #[test]
    fn rejects_invalid_pubkey_hex() {
        assert_eq!(
            "nothex!!".parse::<WhitelistEntry>().unwrap_err(),
            WhitelistParseError::InvalidPubkeyHex
        );
    }

    /// A `#`-bearing line that isn't a valid handle surfaces the handle error.
    #[test]
    fn rejects_malformed_handle() {
        match "name#xyz".parse::<WhitelistEntry>() {
            Err(WhitelistParseError::Handle(_)) => {}
            other => panic!("expected Handle parse error, got {other:?}"),
        }
    }

    // ── Whitelist authorization (ISC-12 / ISC-15) ────────────────────────

    /// A real ML-DSA-87 keypair from a fixed seed byte.
    fn keypair(seed_byte: u8) -> SignKeypair {
        ensure_module();
        SignKeypair::from_ml_dsa_seed(&[seed_byte; 32]).unwrap()
    }

    /// A `FullKey` entry authorizes exactly its own key.
    #[test]
    fn authorizes_full_key_entry() {
        let signer = keypair(1);
        let stranger = keypair(2);
        let wl = Whitelist::from_entries(vec![WhitelistEntry::FullKey(Box::new(
            *signer.public_key(),
        ))]);

        assert!(wl.authorizes(signer.public_key()).unwrap());
        assert!(!wl.authorizes(stranger.public_key()).unwrap());
    }

    /// ISC-12: a `Handle` entry authorizes an arriving key whose hash-prefix
    /// matches, and rejects one whose prefix doesn't — the prefix check is the
    /// gate, computed without the signature.
    #[test]
    fn authorizes_handle_entry_by_hash_prefix() {
        let signer = keypair(3);
        let stranger = keypair(4);
        let entry = Handle::from_pubkey(Some("signer".to_owned()), signer.public_key()).unwrap();
        let wl = Whitelist::from_entries(vec![WhitelistEntry::Handle(entry)]);

        assert!(wl.authorizes(signer.public_key()).unwrap());
        assert!(!wl.authorizes(stranger.public_key()).unwrap());
    }

    /// ISC-15: the project-announce signer is authorized even when the
    /// operator's whitelist file is empty — it can't be removed.
    #[test]
    fn project_announce_signer_authorized_with_empty_file() {
        ensure_module();
        let wl = Whitelist::from_entries(vec![]);
        assert!(
            wl.authorizes(project_announce_pubkey().as_slice()).unwrap(),
            "F17 project-announce entry is non-removable"
        );

        let stranger = keypair(9);
        assert!(!wl.authorizes(stranger.public_key()).unwrap());
    }

    /// The former world-known dev seed `[0x5d; 32]` does not yield an authorized
    /// signer: an artifact signed under it is rejected against an empty whitelist,
    /// while the project-announce key stays non-removably authorized. The seed that
    /// replaced it is not in the tree, so the inequality is asserted on the derived
    /// keys, not on the seed itself.
    #[test]
    fn former_dev_seed_no_longer_authorized() {
        ensure_module();
        let old_dev = SignKeypair::from_ml_dsa_seed(&[0x5d; 32]).unwrap();
        assert_ne!(
            old_dev.public_key(),
            project_announce_pubkey(),
            "the baked project-announce key must not be the one the dev placeholder derives"
        );
        let wl = Whitelist::from_entries(vec![]);
        assert!(
            !wl.authorizes(old_dev.public_key()).unwrap(),
            "the former dev-seed signer must no longer authorize (old graffiti wiped)"
        );
        assert!(
            wl.authorizes(project_announce_pubkey().as_slice()).unwrap(),
            "the current project-announce key remains non-removably authorized"
        );
    }

    /// ISC-15 trust-anchor KAT: pins the project-announce pubkey clients actually
    /// trust (the whitelist anchor), by its SHA-384 since the raw key is `PK_LEN`
    /// bytes. `former_dev_seed_no_longer_authorized` catches a revert to the dev
    /// placeholder; this catches silent DRIFT to any third value — a half-done
    /// rotation that replaced `project_announce_pubkey.bin` with the wrong file. The
    /// announce owner key's pin lives with that key, in the transport crate.
    #[test]
    fn current_trust_anchors_kat() {
        ensure_module();
        assert_eq!(
            hex::encode(sha384(project_announce_pubkey().as_slice()).unwrap()),
            "3cdf6f2b9c64e032557ef4f0e3bd67eec1b1a6c5f44c73759352e08c650a5fbaba6e495437dfb5c52cceaf2e645285a7",
            "the project-announce pubkey (client whitelist anchor) changed unexpectedly"
        );
    }

    /// A retired project-announce signing key is not the baked one, so an artifact
    /// signed under a retired seed does not authorize. The retired key's digest is a
    /// public value, pinned here so a rotation cannot be half-reverted to it.
    #[test]
    fn retired_project_announce_pubkey_is_not_current() {
        ensure_module();
        assert_ne!(
            hex::encode(sha384(project_announce_pubkey().as_slice()).unwrap()),
            "9867a1eb67c3875972e475ba3c05764d1122c7500f8807b4199ae106782f3ac3f1acc8eddfe7f0983e0ea63db6469f2f"
        );
    }

    // ── the operator's runtime seed (ISC-15) ─────────────────────────

    /// A fixed test seed, its hex form, and the public key it derives — the
    /// expectation a load is checked against, built the way a rotation would build
    /// the real one.
    fn test_seed() -> (
        [u8; PROJECT_ANNOUNCE_SEED_LEN],
        String,
        [u8; ml_dsa::PK_LEN],
    ) {
        ensure_module();
        let bytes = [0x11; PROJECT_ANNOUNCE_SEED_LEN];
        let pubkey = *SignKeypair::from_ml_dsa_seed(&bytes).unwrap().public_key();
        (bytes, hex::encode(bytes), pubkey)
    }

    /// The variable's value, as the front end hands it over.
    fn env_text(value: &str) -> ProjectAnnounceSeedText {
        ProjectAnnounceSeedText::from_os_string(OsString::from(value))
    }

    /// A seed file under a fresh directory, owner-read-only.
    fn seed_file(dir: &std::path::Path, text: &str) -> PathBuf {
        let path = dir.join(PROJECT_ANNOUNCE_SEED_FILENAME);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[test]
    fn seed_hex_parses_64_characters_and_ignores_surrounding_whitespace() {
        let (bytes, hex, _) = test_seed();
        let seed = ProjectAnnounceSeed::parse_hex(&format!("  {hex}\n")).unwrap();
        assert_eq!(seed.as_bytes(), &bytes);
        assert_eq!(format!("{seed:?}"), "ProjectAnnounceSeed(<redacted>)");
    }

    #[test]
    fn seed_hex_rejects_wrong_length_and_non_hex() {
        let (_, hex, _) = test_seed();
        assert_eq!(
            ProjectAnnounceSeed::parse_hex(&hex[..62]).unwrap_err(),
            SeedHexError::Length(62)
        );
        assert_eq!(
            ProjectAnnounceSeed::parse_hex("").unwrap_err(),
            SeedHexError::Length(0)
        );
        let mut bad = hex.clone();
        bad.replace_range(0..1, "g");
        assert_eq!(
            ProjectAnnounceSeed::parse_hex(&bad).unwrap_err(),
            SeedHexError::NotHex
        );
    }

    /// No variable and no file is the ordinary reader, not an error.
    #[test]
    fn load_with_no_source_is_not_an_operator() {
        let (_, _, pubkey) = test_seed();
        let dir = tempfile::tempdir().unwrap();
        let source = ProjectAnnounceSeedSource::new(None, Some(dir.path()));
        assert!(source.load_checked(&pubkey).unwrap().is_none());
        assert!(source.load().unwrap().is_none());
        let none_at_all = ProjectAnnounceSeedSource::new(None, None);
        assert!(none_at_all.load_checked(&pubkey).unwrap().is_none());
    }

    /// The shipped entry point checks against the BAKED key and nothing derived
    /// from the seed under test: a seed that loads through `load_checked` against
    /// its own key is refused by `load`. An implementation that computed its
    /// expectation from the seed would return `Ok` here.
    #[test]
    fn load_refuses_a_seed_that_is_not_the_project_seed() {
        let (_, hex, pubkey) = test_seed();
        let source = ProjectAnnounceSeedSource::new(Some(env_text(&hex)), None);
        assert!(
            source.load_checked(&pubkey).unwrap().is_some(),
            "positive control"
        );
        assert!(matches!(
            source.load().unwrap_err(),
            ProjectAnnounceSeedError::NotTheProjectSeed {
                origin: SeedOrigin::Env
            }
        ));
    }

    /// No error text ever carries the seed: every variant's rendering, over a
    /// real 64-character input, contains no run of hex longer than a file mode or
    /// a length would produce.
    #[test]
    fn seed_errors_never_render_the_seed() {
        let (_, hex, _) = test_seed();
        let other = *SignKeypair::from_ml_dsa_seed(&[0x22; PROJECT_ANNOUNCE_SEED_LEN])
            .unwrap()
            .public_key();
        let dir = tempfile::tempdir().unwrap();
        let path = seed_file(dir.path(), &hex);
        let file_source = ProjectAnnounceSeedSource::new(None, Some(dir.path()));
        let mut bad_hex = hex.clone();
        bad_hex.replace_range(63..64, "g");
        let renderings = vec![
            format!(
                "{:?}",
                ProjectAnnounceSeedSource::new(Some(env_text(&hex)), Some(dir.path()))
            ),
            format!("{:?}", env_text(&hex)),
            file_source.load_checked(&other).unwrap_err().to_string(),
            ProjectAnnounceSeedSource::new(Some(env_text(&hex)), None)
                .load_checked(&other)
                .unwrap_err()
                .to_string(),
            ProjectAnnounceSeedSource::new(Some(env_text(&bad_hex)), None)
                .load_checked(&other)
                .unwrap_err()
                .to_string(),
            SeedHexError::Length(63).to_string(),
            ProjectAnnounceSeedError::Permissions {
                path: path.clone(),
                mode: 0o644,
            }
            .to_string(),
        ];
        let longest_hex_run = |s: &str| {
            s.chars()
                .fold((0usize, 0usize), |(best, run), c| {
                    let run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
                    (best.max(run), run)
                })
                .0
        };
        assert_eq!(longest_hex_run(&hex), 64, "the probe sees a seed");
        for text in renderings {
            assert!(
                longest_hex_run(&text) < 8,
                "an error rendered seed-like hex: {text}"
            );
        }
    }

    /// The positive control for every refusal below: the seed loads from the file
    /// when checked against the key it derives, and the origin names the file.
    #[test]
    fn load_reads_the_seed_file_and_checks_it_against_the_expected_key() {
        let (bytes, hex, pubkey) = test_seed();
        let dir = tempfile::tempdir().unwrap();
        let path = seed_file(dir.path(), &format!("{hex}\n"));
        let source = ProjectAnnounceSeedSource::new(None, Some(dir.path()));
        let (seed, origin) = source
            .load_checked(&pubkey)
            .unwrap()
            .expect("the seed loads");
        assert_eq!(seed.as_bytes(), &bytes);
        assert_eq!(origin, SeedOrigin::File(path));
        assert_eq!(seed.signing_keypair().unwrap().public_key(), &pubkey);
    }

    /// The variable is read first, and wins over a file that also exists.
    #[test]
    fn load_prefers_the_environment_variable_over_the_file() {
        let (bytes, hex, pubkey) = test_seed();
        let dir = tempfile::tempdir().unwrap();
        // A file that would be refused if it were consulted.
        seed_file(dir.path(), "not a seed");
        let source = ProjectAnnounceSeedSource::new(Some(env_text(&hex)), Some(dir.path()));
        let (seed, origin) = source
            .load_checked(&pubkey)
            .unwrap()
            .expect("the seed loads");
        assert_eq!(seed.as_bytes(), &bytes);
        assert_eq!(origin, SeedOrigin::Env);
    }

    /// The check a rotation must satisfy: the SAME seed that loads against its own
    /// key is refused against another. A rotation that baked the
    /// wrong key, or an operator handed the wrong seed, fails here rather than
    /// signing under a key the fleet rejects.
    #[test]
    fn load_refuses_a_seed_that_does_not_derive_the_expected_key() {
        let (_, hex, pubkey) = test_seed();
        let source = ProjectAnnounceSeedSource::new(Some(env_text(&hex)), None);
        assert!(
            source.load_checked(&pubkey).unwrap().is_some(),
            "positive control"
        );
        let other = *SignKeypair::from_ml_dsa_seed(&[0x22; PROJECT_ANNOUNCE_SEED_LEN])
            .unwrap()
            .public_key();
        assert!(matches!(
            source.load_checked(&other).unwrap_err(),
            ProjectAnnounceSeedError::NotTheProjectSeed {
                origin: SeedOrigin::Env
            }
        ));
    }

    /// A variable that is set is the seed; an empty or malformed one is a fault
    /// in an instance that was given a seed, never a silent reader.
    #[test]
    fn load_reports_a_malformed_variable_as_an_error_not_absence() {
        let (_, hex, pubkey) = test_seed();
        for value in ["", "   ", &hex[..10], "zz"] {
            let source = ProjectAnnounceSeedSource::new(Some(env_text(value)), None);
            assert!(
                matches!(
                    source.load_checked(&pubkey).unwrap_err(),
                    ProjectAnnounceSeedError::Malformed {
                        origin: SeedOrigin::Env,
                        ..
                    }
                ),
                "{value:?} must be an error"
            );
        }
    }

    /// A variable whose bytes are not text is a fault of its own kind, told apart
    /// from a hex error so the operator looks at the encoding, not the digits.
    #[cfg(unix)]
    #[test]
    fn load_reports_a_non_text_variable_as_its_own_fault() {
        use std::os::unix::ffi::OsStringExt;
        let (_, _, pubkey) = test_seed();
        let value = ProjectAnnounceSeedText::from_os_string(OsString::from_vec(vec![0xff; 64]));
        let source = ProjectAnnounceSeedSource::new(Some(value), None);
        assert!(matches!(
            source.load_checked(&pubkey).unwrap_err(),
            ProjectAnnounceSeedError::Malformed {
                origin: SeedOrigin::Env,
                reason: SeedHexError::NotText
            }
        ));
    }

    #[test]
    fn load_reports_a_malformed_file_as_an_error_naming_the_file() {
        let (_, _, pubkey) = test_seed();
        let dir = tempfile::tempdir().unwrap();
        let path = seed_file(dir.path(), "not a seed\n");
        let source = ProjectAnnounceSeedSource::new(None, Some(dir.path()));
        match source.load_checked(&pubkey).unwrap_err() {
            ProjectAnnounceSeedError::Malformed { origin, reason } => {
                assert_eq!(origin, SeedOrigin::File(path));
                assert!(matches!(reason, SeedHexError::Length(_)));
            }
            other => panic!("expected Malformed, got {other}"),
        }
    }

    /// A seed file another user can read is refused; the same file, owner-only,
    /// loads. The error carries the mode so the fix is obvious.
    #[cfg(unix)]
    #[test]
    fn load_refuses_a_seed_file_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let (_, hex, pubkey) = test_seed();
        let dir = tempfile::tempdir().unwrap();
        let path = seed_file(dir.path(), &hex);
        let source = ProjectAnnounceSeedSource::new(None, Some(dir.path()));
        assert!(
            source.load_checked(&pubkey).unwrap().is_some(),
            "positive control"
        );
        // Group-readable and world-readable are refused independently: a check on
        // only one of the two bit groups would pass one of these.
        for mode in [0o640, 0o604] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            match source.load_checked(&pubkey).unwrap_err() {
                ProjectAnnounceSeedError::Permissions { path: p, mode: m } => {
                    assert_eq!(p, path);
                    assert_eq!(m, mode);
                }
                other => panic!("expected Permissions for {mode:o}, got {other}"),
            }
        }
    }

    /// A seed path whose metadata cannot be read at all — the parent directory
    /// denies traversal — is an error, not absence: only a NotFound is absence.
    #[cfg(unix)]
    #[test]
    fn load_reports_an_unreachable_seed_path_as_an_error() {
        use std::os::unix::fs::PermissionsExt;
        // Root ignores directory modes, so the fixture cannot be built for it.
        if std::fs::read_dir("/root").is_ok() {
            return;
        }
        let (_, hex, pubkey) = test_seed();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        std::fs::create_dir(&root).unwrap();
        seed_file(&root, &hex);
        let source = ProjectAnnounceSeedSource::new(None, Some(&root));
        assert!(
            source.load_checked(&pubkey).unwrap().is_some(),
            "positive control"
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000)).unwrap();
        let outcome = source.load_checked(&pubkey);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            outcome.unwrap_err(),
            ProjectAnnounceSeedError::Unreadable { .. }
        ));
    }

    /// A path that exists and cannot be read as a file is an error, not absence.
    #[test]
    fn load_reports_an_unreadable_seed_path_as_an_error() {
        let (_, _, pubkey) = test_seed();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PROJECT_ANNOUNCE_SEED_FILENAME);
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let source = ProjectAnnounceSeedSource::new(None, Some(dir.path()));
        assert!(matches!(
            source.load_checked(&pubkey).unwrap_err(),
            ProjectAnnounceSeedError::Unreadable { .. }
        ));
    }

    // ── verify_artifact (ISC-A-S3 / ISC-7 / ISC-17) ──────────────────────

    /// A whitelisted signer's correctly-signed payload verifies, and the
    /// returned address is `SHA-384(signed_payload)` (ISC-17).
    #[test]
    fn verify_artifact_accepts_whitelisted_signed_payload() {
        let signer = keypair(11);
        let payload = b"announcement: relay maintenance at 02:00 UTC";
        let sig = signer.sign(payload).unwrap();
        let wl = Whitelist::from_entries(vec![WhitelistEntry::FullKey(Box::new(
            *signer.public_key(),
        ))]);

        let addr = verify_artifact(payload, signer.public_key(), &sig, &wl).unwrap();
        assert_eq!(addr, content_address(payload).unwrap());
    }

    /// ISC-7: a signer absent from the whitelist is rejected as `UnknownSigner`
    /// — before any signature work.
    #[test]
    fn verify_artifact_rejects_unknown_signer() {
        let signer = keypair(12);
        let other = keypair(13);
        let payload = b"unauthorized post";
        let sig = signer.sign(payload).unwrap();
        let wl =
            Whitelist::from_entries(vec![WhitelistEntry::FullKey(Box::new(*other.public_key()))]);

        assert_eq!(
            verify_artifact(payload, signer.public_key(), &sig, &wl),
            Err(ArtifactError::UnknownSigner)
        );
    }

    /// A tampered signature from a whitelisted signer is `BadSignature`.
    #[test]
    fn verify_artifact_rejects_tampered_signature() {
        let signer = keypair(14);
        let payload = b"legit body";
        let mut sig = signer.sign(payload).unwrap();
        sig[0] ^= 0xff;
        let wl = Whitelist::from_entries(vec![WhitelistEntry::FullKey(Box::new(
            *signer.public_key(),
        ))]);

        assert_eq!(
            verify_artifact(payload, signer.public_key(), &sig, &wl),
            Err(ArtifactError::BadSignature)
        );
    }

    /// ISC-A-S3: the signature covers the payload, so a server that mutates the
    /// served bytes (verifying a different payload than was signed) fails —
    /// content cannot be forged or altered behind a valid signer's key.
    #[test]
    fn verify_artifact_rejects_mutated_payload() {
        let signer = keypair(15);
        let signed = b"original body";
        let mutated = b"server-altered body";
        let sig = signer.sign(signed).unwrap();
        let wl = Whitelist::from_entries(vec![WhitelistEntry::FullKey(Box::new(
            *signer.public_key(),
        ))]);

        assert_eq!(
            verify_artifact(mutated, signer.public_key(), &sig, &wl),
            Err(ArtifactError::BadSignature)
        );
    }

    /// A1 — the project-announce owner seed is deterministic from the project seed
    /// (every client/maintainer derives the same record address) and per-seed
    /// (distinct project seeds → distinct channels).
    #[test]
    fn announce_owner_seed_is_deterministic_and_per_seed() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let a = derive_project_announce_veilid_owner_seed(&[0x5d; 32]).unwrap();
        let b = derive_project_announce_veilid_owner_seed(&[0x5d; 32]).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let other = derive_project_announce_veilid_owner_seed(&[0x11; 32]).unwrap();
        assert_ne!(a.as_bytes(), other.as_bytes());
    }

    /// A1 domain separation — the announce owner seed is a SIBLING of the
    /// content-signing key: derived from the SAME project seed but disjoint, so a
    /// holder of the owner seed cannot recover the content-signing key material and
    /// vice versa. (The content key uses the seed as an ML-DSA seed directly; the
    /// owner seed HKDF-expands it under a distinct label.)
    #[test]
    fn announce_owner_seed_disjoint_from_content_signing_seed() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let project_seed = [0x11; PROJECT_ANNOUNCE_SEED_LEN];
        let owner = derive_project_announce_veilid_owner_seed(&project_seed).unwrap();
        // The owner seed must not equal the raw project seed (the ML-DSA content
        // key's IKM) — else the transport owner would leak the content key's seed.
        assert_ne!(owner.as_bytes(), &project_seed);
        // And the operator's own accessor derives the identical seed.
        let held = ProjectAnnounceSeed::from_bytes(project_seed);
        assert_eq!(
            owner.as_bytes(),
            held.announce_owner_seed().unwrap().as_bytes()
        );
    }

    /// The announce owner seed is disjoint from every world-derivable rendezvous
    /// owner (circle / room / their presence siblings), so the operator channel can
    /// never share a record with an open rendezvous. Structural — asserted on a
    /// fixed seed; the baked owner KEY's disjointness is asserted where that key
    /// lives, in the transport crate.
    #[test]
    fn announce_owner_seed_disjoint_from_world_derivable_owners() {
        use crate::circle::key::{
            derive_circle_presence_veilid_owner_seed, derive_circle_veilid_owner_seed,
        };
        use crate::crypto::suite::CNSA_2_0;
        use crate::public_room::{
            derive_room_presence_veilid_owner_seed, derive_room_veilid_owner_seed,
        };
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let owner =
            derive_project_announce_veilid_owner_seed(&[0x11; PROJECT_ANNOUNCE_SEED_LEN]).unwrap();
        assert_ne!(
            owner.as_bytes(),
            derive_room_veilid_owner_seed("lobby", &CNSA_2_0)
                .unwrap()
                .as_bytes()
        );
        assert_ne!(
            owner.as_bytes(),
            derive_room_presence_veilid_owner_seed("lobby", &CNSA_2_0)
                .unwrap()
                .as_bytes()
        );
        assert_ne!(
            owner.as_bytes(),
            derive_circle_veilid_owner_seed("lobby", &CNSA_2_0)
                .unwrap()
                .as_bytes()
        );
        assert_ne!(
            owner.as_bytes(),
            derive_circle_presence_veilid_owner_seed("lobby", &CNSA_2_0)
                .unwrap()
                .as_bytes()
        );
    }

    /// `Debug` never leaks the announce owner seed (ISC-A-C1 log-surface hygiene).
    #[test]
    fn announce_owner_seed_debug_is_redacted() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let s = derive_project_announce_veilid_owner_seed(&[7; 32]).unwrap();
        assert_eq!(
            format!("{s:?}"),
            "ProjectAnnounceVeilidOwnerSeed(<redacted>)"
        );
    }

    /// A1 rollback guard (#78 pattern) — a record at/after the last-seen version is
    /// fresh (accept, incl. an idempotent re-fetch of the current version); a
    /// strictly-older version (a replayed stale slot rolling back a revocation) is
    /// rejected. `accept` advances on a fresh record and leaves state unchanged on a
    /// stale one.
    #[test]
    fn announce_freshness_rejects_rollback_accepts_forward_and_equal() {
        let g = AnnounceFreshness::from_last_seen(5);
        assert!(g.accepts(5)); // idempotent re-fetch of current
        assert!(g.accepts(6)); // a genuine newer publish
        assert!(!g.accepts(4)); // a rolled-back older slot
        assert!(!g.accepts(0)); // the empty/zero slot after having seen v5

        let mut g = AnnounceFreshness::from_last_seen(5);
        assert!(g.accept(7)); // fresh → accepted + advances
        assert_eq!(g.last_seen(), 7);
        assert!(!g.accept(6)); // stale → rejected, state unchanged
        assert_eq!(g.last_seen(), 7);
        assert!(g.accept(7)); // equal re-accept, no-op advance
        assert_eq!(g.last_seen(), 7);

        // A fresh guard starts at 0 and accepts a first record.
        let fresh = AnnounceFreshness::new();
        assert_eq!(fresh.last_seen(), 0);
        assert!(fresh.accepts(1));
    }

    /// #135 KAT — byte-identity guard for the shared boxed-seed derivation
    /// helper. A fixed input seed (the former dev placeholder `[0x5d; 32]`, kept
    /// purely as a stable KAT vector after the ISC-15 rotation — no longer the
    /// project seed) → fixed owner-seed bytes captured from the pre-refactor code;
    /// a drift in the consolidated extract/expand/zeroize/Box path fails the test.
    #[test]
    fn announce_owner_seed_kat_byte_identity() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        assert_eq!(
            hex::encode(
                derive_project_announce_veilid_owner_seed(&[0x5d; 32])
                    .unwrap()
                    .as_bytes()
            ),
            "8a91f109d3ddf7be67e9de694491f641c1a2bff408a6e08a673a235796848ba7",
        );
    }
}
