//! Public-space signed-artifact model shared by the server and every client
//! (M6).
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
use std::sync::OnceLock;

use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_module::Error as OxicryptError;
use oxicrypt_sha::sha384;

use crate::handle::{Handle, HandleParseError};
use crate::identity::keys::{SignKeypair, verify_signature};

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

// ── Project-release signer (F17 / ISC-15) ───────────────────────────────

/// Fixed seed for the **development** project-release signer (F17).
///
/// The matching secret is intentionally in-source during the private phase
/// (the 4-daemon test group): it exists so the non-removable-entry mechanism
/// is real and testable before there is a production release key. Before the
/// public repo opens this placeholder is replaced by a baked-in real release
/// public key whose secret stays offline (see ISC-15).
const PROJECT_RELEASE_SEED: [u8; 32] = [0x5d; 32];

/// The full ML-DSA-87 public key of the project-release signer (F17 / ISC-15).
///
/// This entry is merged into every [`Whitelist`] regardless of the operator's
/// whitelist file, and there is no file syntax that removes it — that
/// non-removability is the whole point of F17 (a self-host operator cannot
/// silence project release announcements). Derived once per process from
/// `PROJECT_RELEASE_SEED`; requires the oxicrypt module to be operational.
pub fn project_release_pubkey() -> &'static [u8; ml_dsa::PK_LEN] {
    static KEY: OnceLock<Box<[u8; ml_dsa::PK_LEN]>> = OnceLock::new();
    KEY.get_or_init(|| {
        let kp = SignKeypair::from_ml_dsa_seed(&PROJECT_RELEASE_SEED)
            .expect("oxicrypt module operational for project-release key derivation");
        Box::new(*kp.public_key())
    })
}

/// The operator's signer whitelist (ISC-S8), plus the always-present
/// project-release entry (F17 / ISC-15).
///
/// Authorization is the cheap gate run before any signature verification
/// (ISC-12): an unknown key never reaches the ML-DSA verify path.
#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    entries: Vec<WhitelistEntry>,
}

impl Whitelist {
    /// Build a whitelist from the operator's parsed file entries. The
    /// project-release entry (F17) is *not* stored here — it is checked
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
    /// The project-release key (F17) is always authorized. For operator
    /// entries: a `FullKey` matches by exact bytes; a `Handle` matches by
    /// hash-prefix against the arriving key (ISC-12), which is computed without
    /// touching the signature.
    pub fn authorizes(&self, pubkey: &[u8]) -> Result<bool, OxicryptError> {
        // F17: the project-release signer is always authorized, regardless of
        // the operator's file (ISC-15).
        if pubkey == project_release_pubkey().as_slice() {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Bootstrap oxicrypt's FIPS module for SHA-384 / ML-DSA tests.
    /// `initialize` is idempotent; the `AlreadyInitialized` second call is
    /// deliberately ignored.
    fn ensure_module() {
        let _ = oxicrypt_module::initialize();
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

    /// ISC-15 / F17: the project-release signer is authorized even when the
    /// operator's whitelist file is empty — it can't be removed.
    #[test]
    fn project_release_signer_authorized_with_empty_file() {
        ensure_module();
        let wl = Whitelist::from_entries(vec![]);
        assert!(
            wl.authorizes(project_release_pubkey().as_slice()).unwrap(),
            "F17 project-release entry is non-removable"
        );

        let stranger = keypair(9);
        assert!(!wl.authorizes(stranger.public_key()).unwrap());
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
}
