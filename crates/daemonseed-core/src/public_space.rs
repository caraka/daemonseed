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

use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_module::Error as OxicryptError;
use oxicrypt_sha::sha384;
use zeroize::Zeroize;

use crate::handle::{Handle, HandleParseError};
use crate::identity::keys::{KeyDerivationError, SignKeypair, verify_signature};
use crate::kdf::info;

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

/// The **development** project-release SIGNING keypair (F17), from the in-source
/// [`PROJECT_RELEASE_SEED`] — the dev analog of [`project_release_pubkey`], exposing
/// the key the dev composer signs MOTD/announcements with. Dev-only: retired when the
/// seed becomes a baked-in pubkey with an offline secret. See ISA A0/A1.
pub fn dev_project_release_keypair() -> Result<SignKeypair, KeyDerivationError> {
    SignKeypair::from_ml_dsa_seed(&PROJECT_RELEASE_SEED)
}

/// Length of the project-announce Veilid rendezvous-owner seed — 32 bytes (a VLD0
/// Ed25519 secret seed).
pub const PROJECT_ANNOUNCE_VEILID_OWNER_SEED_LEN: usize = 32;

/// The project-announce channel's Veilid **rendezvous-owner** seed (Phase 4 A1) —
/// the DHT write-gate for the single project announcements/MOTD channel (A0). A
/// **sibling** of the F17 content-signing key: both derive from the one
/// maintainer-held project-release seed, but the content key uses it as an ML-DSA
/// seed directly while this HKDF-expands it under a distinct label
/// ([`info::PROJECT_ANNOUNCE_VEILID_OWNER`]), so transport-owner and
/// content-signing material are domain-separated — possessing one never yields the
/// other. Held ONLY by the maintainer (the single-owner DHT constraint IS the
/// write-gate, A1); clients hold only the derived owner PUBKEY, from which they
/// compute the record address to read / watch / verify — they cannot write. Zeroes
/// on drop; `Debug` is redacted (ISC-A-C1). Content NEVER derives from this.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct ProjectAnnounceVeilidOwnerSeed(Box<[u8; PROJECT_ANNOUNCE_VEILID_OWNER_SEED_LEN]>);

impl ProjectAnnounceVeilidOwnerSeed {
    /// Borrow the raw seed bytes to build a VLD0 keypair. Callers must not copy
    /// these into a non-zeroizing buffer.
    pub fn as_bytes(&self) -> &[u8; PROJECT_ANNOUNCE_VEILID_OWNER_SEED_LEN] {
        &self.0
    }
}

impl fmt::Debug for ProjectAnnounceVeilidOwnerSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProjectAnnounceVeilidOwnerSeed(<redacted>)")
    }
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
/// maintainer's project-release seed (A1 write-gate).
///
/// ```text
///   owner_seed = HKDF-SHA-384(
///       salt = PROJECT_ANNOUNCE_OWNER_SALT,
///       ikm  = project_seed,                       // maintainer-held (offline in prod)
///       info = "daemonseed/veilid/project-announce-owner")
/// ```
///
/// Domain-separated from the F17 content-signing key (which uses `project_seed`
/// as an ML-DSA seed directly), so a holder of one cannot derive the other. In
/// production `project_seed` stays OFFLINE (maintainer-held) and only the derived
/// owner PUBKEY is baked into clients; the in-source [`PROJECT_RELEASE_SEED`] is a
/// dev placeholder (see [`dev_project_announce_veilid_owner_seed`]).
pub fn derive_project_announce_veilid_owner_seed(
    project_seed: &[u8; 32],
) -> Result<ProjectAnnounceVeilidOwnerSeed, AnnounceOwnerError> {
    let extract = HkdfSha384::extract(Some(info::PROJECT_ANNOUNCE_OWNER_SALT), project_seed)
        .map_err(AnnounceOwnerError::Hkdf)?;
    let mut seed = [0u8; PROJECT_ANNOUNCE_VEILID_OWNER_SEED_LEN];
    if let Err(e) = extract.expand(info::PROJECT_ANNOUNCE_VEILID_OWNER.as_bytes(), &mut seed) {
        seed.zeroize();
        return Err(AnnounceOwnerError::Hkdf(e));
    }
    let boxed = Box::new(seed);
    seed.zeroize();
    Ok(ProjectAnnounceVeilidOwnerSeed(boxed))
}

/// The **development** project-announce owner seed, derived from the in-source
/// [`PROJECT_RELEASE_SEED`] placeholder (F17). The dev analog of
/// [`project_release_pubkey`]: during the private phase the project seed is
/// in-source, so this exposes the dev channel's write-gate for the client composer
/// and felt-tests. **Dev-only** — before the public repo opens, `PROJECT_RELEASE_SEED`
/// becomes a baked-in owner PUBKEY whose secret stays offline, and this convenience
/// is retired (a client then holds only the pubkey and cannot write). The
/// dev-vs-prod owner-key custody split is the named A1/A2 accepted cost (ISA
/// Decisions).
pub fn dev_project_announce_veilid_owner_seed()
-> Result<ProjectAnnounceVeilidOwnerSeed, AnnounceOwnerError> {
    derive_project_announce_veilid_owner_seed(&PROJECT_RELEASE_SEED)
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

// ── MOTD plaintext rule (ISC-S9) ─────────────────────────────────────────

/// True if `text` is a valid single-line plaintext MOTD (ISC-S9 anti-injection):
/// no forbidden character (see [`is_motd_forbidden_char`]). This enforces a
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

    /// The dev project-release SIGNING keypair yields exactly the F17 pubkey the
    /// verify path is gated on — so a MOTD/announcement the dev composer signs with
    /// it authorizes against an empty whitelist (F17 always-authorized).
    #[test]
    fn dev_project_release_keypair_matches_project_release_pubkey() {
        ensure_module();
        let kp = dev_project_release_keypair().unwrap();
        assert_eq!(kp.public_key(), project_release_pubkey());
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
        let _ = oxicrypt_module::initialize();
        let a = derive_project_announce_veilid_owner_seed(&[0x5d; 32]).unwrap();
        let b = derive_project_announce_veilid_owner_seed(&[0x5d; 32]).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let other = derive_project_announce_veilid_owner_seed(&[0x11; 32]).unwrap();
        assert_ne!(a.as_bytes(), other.as_bytes());
    }

    /// A1 domain separation — the announce owner seed is a SIBLING of the F17
    /// content-signing key: derived from the SAME project seed but disjoint, so a
    /// holder of the owner seed cannot recover the content-signing key material and
    /// vice versa. (The content key uses the seed as an ML-DSA seed directly; the
    /// owner seed HKDF-expands it under a distinct label.)
    #[test]
    fn announce_owner_seed_disjoint_from_content_signing_seed() {
        let _ = oxicrypt_module::initialize();
        let owner = derive_project_announce_veilid_owner_seed(&PROJECT_RELEASE_SEED).unwrap();
        // The owner seed must not equal the raw project seed (the ML-DSA content
        // key's IKM) — else the transport owner would leak the content key's seed.
        assert_ne!(owner.as_bytes(), &PROJECT_RELEASE_SEED);
        // And the dev convenience derives the identical seed.
        let dev = dev_project_announce_veilid_owner_seed().unwrap();
        assert_eq!(owner.as_bytes(), dev.as_bytes());
    }

    /// The announce owner seed is disjoint from every world-derivable rendezvous
    /// owner (circle / room / their presence siblings), so the operator channel can
    /// never share a record with an open rendezvous.
    #[test]
    fn announce_owner_seed_disjoint_from_world_derivable_owners() {
        use crate::circle::key::{
            derive_circle_presence_veilid_owner_seed, derive_circle_veilid_owner_seed,
        };
        use crate::crypto::suite::CNSA_2_0;
        use crate::public_room::{
            derive_room_presence_veilid_owner_seed, derive_room_veilid_owner_seed,
        };
        let _ = oxicrypt_module::initialize();
        let owner = derive_project_announce_veilid_owner_seed(&PROJECT_RELEASE_SEED).unwrap();
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
        let _ = oxicrypt_module::initialize();
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
}
