//! Encrypted at-rest seeds blob (ISC-C3, ISC-C24).
//!
//! ## Format v2 (M3+)
//!
//! ```text
//!   [MAGIC      (19 bytes: b"daemonseed/blob/v2\0")]
//!   [SUITE_ID   ( 2 bytes: u16 big-endian, per ds-suite-registry.md)]
//!   [NONCE      (12 bytes: CSPRNG-generated)]
//!   [CIPHERTEXT (plaintext_len bytes)]
//!   [TAG        (16 bytes: AES-GCM authenticator)]
//! ```
//!
//! The `suite_id` resolves through [`crate::crypto::suite::Registry`] to the
//! concrete AEAD / KDF used for this blob. Per ISC-C24 every cryptographic
//! artifact the client authors carries a `suite_id`; the at-rest blob is the
//! first such artifact in M3.
//!
//! ## Format v1 (M1 / M2 — read-only since M3)
//!
//! ```text
//!   [MAGIC      (19 bytes: b"daemonseed/blob/v1\0")]
//!   [NONCE      (12 bytes)]
//!   [CIPHERTEXT (plaintext_len bytes)]
//!   [TAG        (16 bytes)]
//! ```
//!
//! v1 blobs are accepted by [`open`] under the implicit assumption that
//! `suite_id = 0x0001` (CNSA 2.0) — the only suite that existed at M1/M2.
//! [`seal`] always writes v2. [`touch_reseal`] is the on-touch migration
//! path per ISC-C24: decrypt under the stored suite, re-encrypt as v2
//! under the active write-suite. Read-old / write-new without a flag-day.
//!
//! ## KDF chain (unchanged from M1)
//!
//! ```text
//!   intermediate = Argon2id(
//!       passphrase = utf8(passphrase),
//!       salt       = profile_id (16-byte UUID),
//!       params     = persisted [argon2] table (ISC-C14),
//!       length     = 32,
//!   )
//!   aead_key     = HKDF-SHA384-Expand(
//!       prk  = intermediate,
//!       info = "daemonseed/at-rest/<profile-id>",
//!       length = 32,
//!   )
//!   ciphertext, tag = AES-256-GCM-seal(aead_key, nonce, plaintext, aad)
//! ```
//!
//! ## AAD binding
//!
//! v1 blobs use empty AAD (M1 / M2 contract). v2 blobs bind the `suite_id`
//! bytes into the AAD so a tamper-swap of the suite tag fails AEAD auth —
//! the receiver cannot be tricked into running a v2 blob under the wrong
//! suite's primitives without the AEAD detecting it.

use std::collections::{BTreeMap, BTreeSet};

use argon2::{Algorithm, Argon2, Params, Version};
use oxicrypt_aes::{Aes256Key, gcm_decrypt, gcm_encrypt};
use oxicrypt_kdf::HkdfSha384;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::suite::{Registry, SuiteId, SuiteIdError, WriteRefusal};
use crate::identity::mnemonic::{Mnemonic, MnemonicError};
use crate::kdf::info;
use crate::profile::config::ArgonParams;

/// Magic prefix for the **current** (v2) blob format. M3+ writes this magic
/// on every [`seal`] call. Bump the `v2` tag on any incompatible layout
/// change.
pub const MAGIC: &[u8; 19] = b"daemonseed/blob/v2\0";

/// Magic prefix for the **legacy** v1 blob format (M1 / M2). [`open`]
/// accepts blobs prefixed with this value and treats them as carrying the
/// implicit `suite_id = 0x0001` (CNSA 2.0). [`seal`] never writes this
/// magic.
pub const MAGIC_V1: &[u8; 19] = b"daemonseed/blob/v1\0";

/// Implicit suite id assumed when reading a v1 blob. v1 predates the
/// registry; only CNSA 2.0 existed when v1 blobs were written.
const V1_IMPLICIT_SUITE_RAW: u16 = 0x0001;

/// Width of the suite_id field on the v2 wire layout (big-endian u16).
pub const SUITE_ID_LEN: usize = 2;

/// AES-256-GCM nonce length (per NIST SP 800-38D §8.2.1).
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM tag length (per NIST SP 800-38D §5.2.1.2).
pub const TAG_LEN: usize = 16;

/// Argon2id intermediate output length (= AEAD key length = HKDF PRK len).
pub const ARGON2_OUTPUT_LEN: usize = 48;

/// AEAD key length (AES-256 → 32 bytes).
pub const AEAD_KEY_LEN: usize = 32;

/// Length of the share-index key (M14), derived as a sibling of the at-rest
/// key. Re-exported from the redb index module so the two stay in lockstep.
use crate::storage::share_index::INDEX_KEY_LEN;

/// Replay-protection counter state persisted alongside the mnemonic
/// (`project_clocks_freshness`).
///
/// - `send_counter` is this identity's own monotonic counter. The
///   orchestration layer calls [`next_send`](CounterState::next_send) for each
///   identity-proof envelope it builds; persisting it is what stops a restarted
///   client from re-emitting a counter value a peer has already recorded
///   (which the peer would reject as a replay). **This is the load-bearing
///   field** — ISC-33.
/// - `seen` is the highest counter accepted per target `(signer-key /
///   server-id)` — ISC-34. The verifier ([`crate::identity_proof::verify_envelope`])
///   consumes this via its `highest_seen_counter` argument. Persisting it is
///   defense-in-depth: channel binding already defeats cross-session replay,
///   so a forgotten `seen` map across restart is not a vulnerability. **A
///   *server* MUST NOT persist its per-client `seen` map** (ISC-A-S1 / A-S12,
///   RAM-only) — that is the server orchestration's responsibility; this type
///   merely makes persistence *possible* for the client's per-server map.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CounterState {
    send_counter: u64,
    seen: BTreeMap<String, u64>,
}

impl CounterState {
    /// Increment and return the next send counter (first call returns 1).
    pub fn next_send(&mut self) -> u64 {
        self.send_counter += 1;
        self.send_counter
    }

    /// The current send counter without advancing it (0 if nothing sent).
    pub fn current_send(&self) -> u64 {
        self.send_counter
    }

    /// Highest counter accepted from `target`, or `None` if never seen.
    pub fn highest_seen(&self, target: &str) -> Option<u64> {
        self.seen.get(target).copied()
    }

    /// Record `counter` as seen from `target`, keeping the maximum. Call after
    /// a successful [`verify_envelope`](crate::identity_proof::verify_envelope).
    pub fn record_seen(&mut self, target: &str, counter: u64) {
        let entry = self.seen.entry(target.to_string()).or_insert(0);
        if counter > *entry {
            *entry = counter;
        }
    }
}

/// Plaintext payload of the at-rest blob. M1 carried only the mnemonic; M4b
/// adds replay-protection [`CounterState`]; M9 adds the client-local mute and
/// hide-shares lists (ISC-C15 / C16). M5+ may extend it further with
/// circle-of-trust seed material and settings.
///
/// ## Plaintext schema (directive lines)
///
/// The decrypted payload is line-based and **backward-compatible**: line 0 is
/// always the 24-word mnemonic phrase (the entire M1/M2/M3 payload), and any
/// following lines are `directive` entries:
/// - `send-counter <n>` — the monotonic send counter (ISC-33).
/// - `seen <target> <n>` — highest accepted counter per peer (ISC-34).
/// - `mute <handle>` — a muted full wire handle (ISC-C15). The handle is the
///   entire rest of the line, so display names containing spaces survive.
/// - `hide <handle>` — a hidden-shares full wire handle (ISC-C16), same shape.
/// - `name <display>` — the user's chosen display name (ISC-C4b, M13),
///   rest-of-line; absent for the floor-handle presentation.
/// - `circle <hex(entropy)> <hex(label)>` — a remembered circle to rejoin
///   (ISC-C59 persistence, M13); both fields hex-encoded so spaces/newlines in
///   the entropy or label can never split the line.
/// - `share <hex(root)> <hex(label)>` — a remembered local share root to
///   re-index on next launch (ISC-C21 persistence, M14); both fields
///   hex-encoded (an empty label hex means "no label"). Client-local only —
///   no wire message carries it (ISC-A-C3).
///
/// A bare-phrase payload (no extra lines, the legacy form) parses with default
/// counters and empty lists, so existing blobs open without re-enrollment.
/// Default state serializes back to the bare phrase, so nothing changes until
/// a counter is used or a handle is muted/hidden. The directive scheme is
/// additive — future fields append new directive kinds without a blob-format
/// (magic) bump. Mute/hide lists are **client-local only** and never leave the
/// at-rest blob; no wire message carries them (ISC-A-C3).
///
/// `Clone` is derived so the running client can hold its own live payload to
/// mutate + re-seal (the M13 write-through) while the cold-start
/// [`SessionMaterials`](crate::first_start::SessionMaterials) keeps its copy.
/// The clone copies the mnemonic, which still zeroizes on drop.
#[derive(Clone)]
pub struct Seeds {
    pub mnemonic: Mnemonic,
    pub counters: CounterState,
    /// Full wire handles whose chat the user has muted (ISC-C15). Unilateral
    /// and silent — the muted party is never signalled.
    pub muted: BTreeSet<String>,
    /// Full wire handles whose file shares the user has hidden (ISC-C16).
    /// Independent of [`Self::muted`].
    pub hidden_shares: BTreeSet<String>,
    /// The user's chosen display name (ISC-C4b), persisted so it survives a
    /// daily-login Unlock (ISC-C51) instead of resetting each session. `None`
    /// is the floor-handle presentation (no name chosen). Mutate via
    /// [`Self::set_display_name`] (M13 persistence keystone).
    pub display_name: Option<String>,
    /// The set of circles to rejoin on next launch (ISC-C59 persistence, M13).
    /// Each entry carries the canonicalized circle entropy needed to re-derive
    /// the `cot_key` (ISC-C8) without the user re-typing the phrase, plus the
    /// client-local label (ISC-C62). Insertion order is preserved so the
    /// carousel restores in join order. Mutate via [`Self::add_circle`] /
    /// [`Self::remove_circle`] / [`Self::rename_circle`].
    ///
    /// Per the M13 "remember-all" decision (D-2026-06-05), every joined circle
    /// is persisted by default — this revises the earlier ISC-A-C2 wording that
    /// circle entropy is never persisted (see ISA Decisions). The entropy lives
    /// here encrypted under the at-rest blob's two-stage KDF; a per-circle
    /// opt-out ("ephemeral circle") is the deferred B-path.
    pub circles: Vec<PersistedCircle>,
    /// The set of local share roots to re-index on next launch (ISC-C21
    /// persistence, M14). Each entry carries the directory path plus an optional
    /// client-local label. Insertion order is preserved. Mutate via
    /// [`Self::add_share`] / [`Self::remove_share`]. Client-local only — no wire
    /// message carries it (ISC-A-C3); it is persistence of *configuration*, not
    /// of shared content, so the no-client-history invariant holds.
    pub shares: Vec<PersistedShare>,
    /// Remembered *published* share roots — the subset of [`Self::shares`] the
    /// user has published, so they auto-republish next launch (publish-intent
    /// persistence, 2026-06-13). Client-local only (ISC-A-C3). This persists the
    /// *intent* to publish, not any relay-side state: the relay stays RAM-only
    /// and reaps on disconnect (ISC-S20, "online to share"); the client simply
    /// re-asserts each published root once reconnected, so ephemerality is
    /// unchanged. Mutate via [`Self::add_published`] / [`Self::remove_published`].
    pub published: Vec<String>,
}

/// One remembered local share root in the at-rest blob (ISC-C21 persistence,
/// M14). Holds the share-root directory path and an optional client-local
/// label. Neither field ever leaves the encrypted blob (ISC-A-C3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedShare {
    /// The shared directory path, as the user entered it.
    pub root: String,
    /// Optional client-local label; `None` falls back to the path at render.
    pub label: Option<String>,
}

/// One remembered circle in the at-rest blob (ISC-C59 persistence, M13).
///
/// Holds the minimum needed to rejoin without re-typing: the canonicalized
/// circle entropy (the `cot_key` IKM, ISC-C8/C9) and the client-local display
/// label (ISC-C62). Neither field ever leaves the encrypted blob — no wire
/// message carries them (ISC-A-C3). `entropy` is the canonicalized phrase, not
/// the derived key, so a later cross-family suite change re-derives correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedCircle {
    /// Canonicalized circle entropy (NFKC + whitespace-folded, ISC-C9). This is
    /// the IKM the `cot_key` derivation (ISC-C8) re-runs on rejoin.
    pub entropy: String,
    /// Client-local circle label (ISC-C62). Never transmitted, never derived
    /// from members.
    pub label: String,
}

impl core::fmt::Debug for Seeds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Mute/hide contents are a social graph — surface only counts so a
        // stray Debug log or panic message never dumps who the user muted.
        f.debug_struct("Seeds")
            .field("mnemonic", &"<redacted>")
            .field("counters", &self.counters)
            .field("muted", &self.muted.len())
            .field("hidden_shares", &self.hidden_shares.len())
            // Display name is public (it travels on the wire), so it is safe to
            // show; circle entropy is a secret, so surface only the count.
            .field("display_name", &self.display_name)
            .field("circles", &self.circles.len())
            .field("shares", &self.shares.len())
            .field("published", &self.published.len())
            .finish()
    }
}

impl Seeds {
    /// A fresh payload wrapping `mnemonic` with empty counter state and empty
    /// mute / hide-shares lists.
    pub fn new(mnemonic: Mnemonic) -> Self {
        Self {
            mnemonic,
            counters: CounterState::default(),
            muted: BTreeSet::new(),
            hidden_shares: BTreeSet::new(),
            display_name: None,
            circles: Vec::new(),
            shares: Vec::new(),
            published: Vec::new(),
        }
    }

    /// Mute a full wire handle (ISC-C15). Returns `true` if newly added,
    /// `false` if already muted (idempotent) or rejected.
    ///
    /// Refuses any handle containing a line break: the at-rest blob plaintext
    /// is line-based, so a `\n`/`\r` in a (peer-controlled, self-asserted)
    /// handle would inject a spurious directive line and corrupt the blob on
    /// the next open. A well-formed wire handle never contains one.
    pub fn add_mute(&mut self, handle: impl Into<String>) -> bool {
        let handle = handle.into();
        if handle.contains(['\n', '\r']) {
            return false;
        }
        self.muted.insert(handle)
    }

    /// Unmute a handle. Returns `true` if it was muted, `false` otherwise.
    pub fn remove_mute(&mut self, handle: &str) -> bool {
        self.muted.remove(handle)
    }

    /// Whether `handle` is on the mute list.
    pub fn is_muted(&self, handle: &str) -> bool {
        self.muted.contains(handle)
    }

    /// Hide a handle's file shares (ISC-C16). Returns `true` if newly added,
    /// `false` if already hidden or rejected. Refuses line-break handles for
    /// the same blob-integrity reason as [`Self::add_mute`].
    pub fn add_hidden_share(&mut self, handle: impl Into<String>) -> bool {
        let handle = handle.into();
        if handle.contains(['\n', '\r']) {
            return false;
        }
        self.hidden_shares.insert(handle)
    }

    /// Un-hide a handle's shares. Returns `true` if it was hidden.
    pub fn remove_hidden_share(&mut self, handle: &str) -> bool {
        self.hidden_shares.remove(handle)
    }

    /// Whether `handle`'s shares are hidden.
    pub fn is_share_hidden(&self, handle: &str) -> bool {
        self.hidden_shares.contains(handle)
    }

    /// The persisted display name (ISC-C4b), or `None` for the floor handle.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Set (or clear, with `None`) the persisted display name (ISC-C4b, M13).
    /// Returns `true` if the value changed. Refuses a name containing a line
    /// break: the `name` directive is rest-of-line, so a `\n`/`\r` would inject
    /// a spurious directive and corrupt the blob on the next open — same
    /// integrity rule as [`Self::add_mute`].
    pub fn set_display_name(&mut self, name: Option<String>) -> bool {
        if let Some(n) = &name
            && n.contains(['\n', '\r'])
        {
            return false;
        }
        if self.display_name == name {
            return false;
        }
        self.display_name = name;
        true
    }

    /// The remembered circles, in join order (ISC-C59 persistence, M13).
    pub fn circles(&self) -> &[PersistedCircle] {
        &self.circles
    }

    /// Remember a circle so it rejoins next launch (ISC-C59, M13). `entropy`
    /// must already be canonicalized (ISC-C9). Returns `true` if newly added,
    /// `false` if a circle with the same entropy is already remembered
    /// (idempotent — re-joining a known circle does not duplicate it).
    pub fn add_circle(&mut self, entropy: impl Into<String>, label: impl Into<String>) -> bool {
        let entropy = entropy.into();
        if self.circles.iter().any(|c| c.entropy == entropy) {
            return false;
        }
        self.circles.push(PersistedCircle {
            entropy,
            label: label.into(),
        });
        true
    }

    /// Forget a remembered circle, keyed on its canonicalized entropy (M13).
    /// Returns `true` if one was removed.
    pub fn remove_circle(&mut self, entropy: &str) -> bool {
        let before = self.circles.len();
        self.circles.retain(|c| c.entropy != entropy);
        self.circles.len() != before
    }

    /// Rename a remembered circle's client-local label (ISC-C62 override, M13),
    /// keyed on its canonicalized entropy. Returns `true` if the label changed.
    pub fn rename_circle(&mut self, entropy: &str, new_label: impl Into<String>) -> bool {
        let new_label = new_label.into();
        for c in &mut self.circles {
            if c.entropy == entropy {
                if c.label == new_label {
                    return false;
                }
                c.label = new_label;
                return true;
            }
        }
        false
    }

    /// The remembered local share roots, in insertion order (ISC-C21, M14).
    pub fn shares(&self) -> &[PersistedShare] {
        &self.shares
    }

    /// Remember a local share root so it re-indexes next launch (ISC-C21, M14).
    /// Returns `true` if newly added, `false` if a share with the same `root`
    /// is already remembered (idempotent — re-defining a known root does not
    /// duplicate it). Both fields are hex-encoded at serialization, so any path
    /// or label survives the line-based blob intact.
    pub fn add_share(&mut self, root: impl Into<String>, label: Option<String>) -> bool {
        let root = root.into();
        if self.shares.iter().any(|s| s.root == root) {
            return false;
        }
        self.shares.push(PersistedShare { root, label });
        true
    }

    /// Forget a remembered share root, keyed on its path (M14). Returns `true`
    /// if one was removed.
    pub fn remove_share(&mut self, root: &str) -> bool {
        let before = self.shares.len();
        self.shares.retain(|s| s.root != root);
        self.shares.len() != before
    }

    /// The remembered *published* share roots, in publish order (publish-intent
    /// persistence). A subset of [`Self::shares`].
    pub fn published(&self) -> &[String] {
        &self.published
    }

    /// Remember that a share root is published so it auto-republishes next
    /// launch. Returns `true` if newly added, `false` if already remembered
    /// (idempotent). Hex-encoded at serialization, so any path survives the
    /// line-based blob.
    pub fn add_published(&mut self, root: impl Into<String>) -> bool {
        let root = root.into();
        if self.published.iter().any(|r| r == &root) {
            return false;
        }
        self.published.push(root);
        true
    }

    /// Forget a published share root, keyed on its path. Returns `true` if one
    /// was removed.
    pub fn remove_published(&mut self, root: &str) -> bool {
        let before = self.published.len();
        self.published.retain(|r| r != root);
        self.published.len() != before
    }

    fn to_plaintext(&self) -> String {
        let mut s = self.mnemonic.to_phrase();
        if self.counters.send_counter != 0 {
            s.push_str(&format!("\nsend-counter {}", self.counters.send_counter));
        }
        for (target, counter) in &self.counters.seen {
            s.push_str(&format!("\nseen {target} {counter}"));
        }
        for handle in &self.muted {
            s.push_str(&format!("\nmute {handle}"));
        }
        for handle in &self.hidden_shares {
            s.push_str(&format!("\nhide {handle}"));
        }
        // Display name (ISC-C4b, M13): rest-of-line value; newlines are refused
        // at the setter so this never injects a spurious directive.
        if let Some(name) = &self.display_name {
            s.push_str(&format!("\nname {name}"));
        }
        // Circles (ISC-C59 persistence, M13): both fields are hex-encoded so a
        // space- or newline-containing entropy/label can never split the line
        // or inject a directive. Layout: `circle <hex(entropy)> <hex(label)>`.
        for c in &self.circles {
            s.push_str(&format!(
                "\ncircle {} {}",
                hex::encode(c.entropy.as_bytes()),
                hex::encode(c.label.as_bytes()),
            ));
        }
        // Shares (ISC-C21 persistence, M14): both fields hex-encoded so a path
        // or label with spaces/newlines never splits the line. A `None` label
        // serializes as empty hex. Layout: `share <hex(root)> <hex(label)>`.
        for sh in &self.shares {
            s.push_str(&format!(
                "\nshare {} {}",
                hex::encode(sh.root.as_bytes()),
                hex::encode(sh.label.as_deref().unwrap_or("").as_bytes()),
            ));
        }
        // Published roots (publish-intent persistence): hex-encoded path so a
        // path with spaces/newlines never splits the line. Layout:
        // `publish <hex(root)>`.
        for root in &self.published {
            s.push_str(&format!("\npublish {}", hex::encode(root.as_bytes())));
        }
        s
    }

    fn from_plaintext(s: &str) -> Result<Self, BlobError> {
        let mut lines = s.lines();
        let phrase = lines.next().ok_or(BlobError::InvalidPlaintext)?;
        let mnemonic = Mnemonic::from_phrase(phrase).map_err(BlobError::Mnemonic)?;
        let mut counters = CounterState::default();
        let mut muted = BTreeSet::new();
        let mut hidden_shares = BTreeSet::new();
        let mut display_name: Option<String> = None;
        let mut circles: Vec<PersistedCircle> = Vec::new();
        let mut shares: Vec<PersistedShare> = Vec::new();
        let mut published: Vec<String> = Vec::new();
        for line in lines {
            // Mute / hide directives take the entire rest of the line as the
            // handle so a display name containing spaces is never truncated.
            if let Some(handle) = line.strip_prefix("mute ") {
                muted.insert(handle.to_string());
                continue;
            }
            if let Some(handle) = line.strip_prefix("hide ") {
                hidden_shares.insert(handle.to_string());
                continue;
            }
            // Display name (ISC-C4b, M13): rest-of-line value.
            if let Some(name) = line.strip_prefix("name ") {
                display_name = Some(name.to_string());
                continue;
            }
            // Circle (ISC-C59 persistence, M13): `circle <hex(entropy)> <hex(label)>`.
            if let Some(rest) = line.strip_prefix("circle ") {
                let (entropy_hex, label_hex) =
                    rest.split_once(' ').ok_or(BlobError::InvalidPlaintext)?;
                let entropy = hex::decode(entropy_hex)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or(BlobError::InvalidPlaintext)?;
                let label = hex::decode(label_hex)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or(BlobError::InvalidPlaintext)?;
                circles.push(PersistedCircle { entropy, label });
                continue;
            }
            // Share (ISC-C21 persistence, M14): `share <hex(root)> <hex(label)>`.
            // An empty label hex decodes to `None`.
            if let Some(rest) = line.strip_prefix("share ") {
                let (root_hex, label_hex) =
                    rest.split_once(' ').ok_or(BlobError::InvalidPlaintext)?;
                let root = hex::decode(root_hex)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or(BlobError::InvalidPlaintext)?;
                let label_str = hex::decode(label_hex)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or(BlobError::InvalidPlaintext)?;
                let label = (!label_str.is_empty()).then_some(label_str);
                shares.push(PersistedShare { root, label });
                continue;
            }
            // Published root (publish-intent persistence): `publish <hex(root)>`.
            if let Some(root_hex) = line.strip_prefix("publish ") {
                let root = hex::decode(root_hex)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or(BlobError::InvalidPlaintext)?;
                published.push(root);
                continue;
            }
            let mut parts = line.splitn(3, ' ');
            match parts.next() {
                Some("send-counter") => {
                    let n = parts.next().ok_or(BlobError::InvalidPlaintext)?;
                    counters.send_counter = n.parse().map_err(|_| BlobError::InvalidPlaintext)?;
                }
                Some("seen") => {
                    let target = parts.next().ok_or(BlobError::InvalidPlaintext)?;
                    let n = parts.next().ok_or(BlobError::InvalidPlaintext)?;
                    let counter = n.parse().map_err(|_| BlobError::InvalidPlaintext)?;
                    counters.seen.insert(target.to_string(), counter);
                }
                _ => return Err(BlobError::InvalidPlaintext),
            }
        }
        Ok(Self {
            mnemonic,
            counters,
            muted,
            hidden_shares,
            display_name,
            circles,
            shares,
            published,
        })
    }
}

/// Outcome of [`open`] — carries the recovered seeds plus the suite_id the
/// blob was sealed under. Callers (e.g. the orchestrator) use the
/// `suite_id` to decide whether [`touch_reseal`] is needed on the next save.
#[derive(Debug)]
pub struct Opened {
    pub seeds: Seeds,
    pub suite_id: SuiteId,
    /// `true` iff the blob was the legacy v1 format; consumers should
    /// schedule a [`touch_reseal`] on the next write to migrate the blob
    /// to v2 (ISC-C24 read-old-write-new).
    pub legacy_v1: bool,
    /// The at-rest AEAD key derived while opening, cached for the session so the
    /// write-through (M13) can re-seal on each mutation without re-running
    /// Argon2id. The Unlock path hands this straight to the running client.
    pub key: SealingKey,
    /// The share-index key (M14), derived as a sibling of `key` from the *same*
    /// Argon2id run via a second domain-separated HKDF-Expand. The Unlock path
    /// hands this to the running client to open the redb [`ShareIndex`]
    /// (`crate::storage::share_index`) for free — no extra Argon2id.
    pub index_key: IndexKey,
}

/// Errors from [`seal`] / [`open`] / [`touch_reseal`].
#[derive(Debug)]
pub enum BlobError {
    /// Argon2 KDF returned an error (bad params, etc.).
    Argon2(argon2::Error),
    /// HKDF expand or the underlying oxicrypt module gate failed.
    Hkdf(oxicrypt_kdf::KdfError),
    /// `oxicrypt-module`-gated AES key construction failed.
    AesKeyInit(oxicrypt_module::Error),
    /// AES-GCM encrypt / decrypt failed.
    AesMode(oxicrypt_aes::ModeError),
    /// Failed to fill nonce from OS CSPRNG.
    EntropySource(getrandom::Error),
    /// Blob is too short / missing magic / truncated layout.
    Malformed(&'static str),
    /// AEAD authenticator did not verify — wrong passphrase, tampered blob,
    /// or wrong KDF inputs (profile_id / argon2 params).
    AuthenticationFailed,
    /// v2 blob carried a `suite_id` whose raw value is one of the reserved
    /// sentinels (`0x0000` / `0xFFFF`).
    SuiteIdSentinel(SuiteIdError),
    /// v2 blob carried a `suite_id` not present in this build's registry.
    UnknownSuite(SuiteId),
    /// Active write-suite refused by the registry (e.g. all suites
    /// deprecated). Returned by [`seal`] and [`touch_reseal`] when no
    /// write-eligible suite exists.
    WriteRefused(WriteRefusal),
    /// Plaintext was decrypted but isn't a valid mnemonic (different blob
    /// version, corrupt content despite valid AEAD — should be impossible
    /// if MAGIC matches and AEAD passed; surfaced here for safety).
    InvalidPlaintext,
    /// Plaintext bytes weren't valid UTF-8 (paired with `InvalidPlaintext`
    /// in practice; kept distinct for diagnostics).
    Utf8(core::str::Utf8Error),
    /// Inner mnemonic-parse failure (unreachable in steady state but
    /// surfaced for diagnostics).
    Mnemonic(MnemonicError),
}

impl core::fmt::Display for BlobError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlobError::Argon2(e) => write!(f, "argon2: {e}"),
            BlobError::Hkdf(e) => write!(f, "HKDF: {e:?}"),
            BlobError::AesKeyInit(e) => write!(f, "AES-256 key init: {e:?}"),
            BlobError::AesMode(e) => write!(f, "AES-GCM mode error: {e:?}"),
            BlobError::EntropySource(e) => write!(f, "OS CSPRNG: {e}"),
            BlobError::Malformed(s) => write!(f, "malformed at-rest blob: {s}"),
            BlobError::AuthenticationFailed => {
                write!(
                    f,
                    "at-rest blob: authentication failed (wrong passphrase or tampered blob)"
                )
            }
            BlobError::SuiteIdSentinel(e) => write!(f, "at-rest blob suite_id: {e}"),
            BlobError::UnknownSuite(id) => {
                write!(f, "at-rest blob references unknown suite {id}")
            }
            BlobError::WriteRefused(r) => write!(f, "at-rest blob write refused: {r}"),
            BlobError::InvalidPlaintext => write!(f, "at-rest blob: plaintext failed schema check"),
            BlobError::Utf8(e) => write!(f, "at-rest blob plaintext is not UTF-8: {e}"),
            BlobError::Mnemonic(e) => write!(f, "mnemonic in at-rest blob: {e}"),
        }
    }
}

impl std::error::Error for BlobError {}

/// A cached at-rest AEAD key for the session write-through (M13).
///
/// Holds the 32-byte key derived once at unlock ([`Opened::key`]) or first-start
/// ([`SealingKey::derive`]) so the running client can re-seal the blob on every
/// persist-worthy mutation (mute, hide, circle join/leave, rename, display-name
/// change) **without** re-running Argon2id — which on the Pi-4 floor target would
/// otherwise stall the UI for a second or more per action. The key zeroizes on
/// drop. It is the session's most sensitive in-RAM secret: never log it, never
/// persist it, and drop the [`SealingKey`] at logout.
#[derive(Clone)]
pub struct SealingKey(Zeroizing<[u8; AEAD_KEY_LEN]>);

impl SealingKey {
    /// Derive the at-rest AEAD key from the passphrase (one Argon2id run) and
    /// cache it for the session. Used at first-start; the Unlock path gets the
    /// key for free from [`open`] via [`Opened::key`] instead of calling this.
    pub fn derive(
        passphrase: &str,
        profile_id: Uuid,
        params: ArgonParams,
    ) -> Result<Self, BlobError> {
        let mut key_bytes = derive_aead_key(passphrase, profile_id, params)?;
        let sk = Self(Zeroizing::new(key_bytes));
        key_bytes.zeroize();
        Ok(sk)
    }

    /// Re-seal `seeds` under the active write-suite using the cached key — no
    /// Argon2id. This is what the session calls on every persist-worthy change.
    pub fn seal(&self, seeds: &Seeds) -> Result<Vec<u8>, BlobError> {
        seal_with_key(seeds, &self.0, Registry::default_write_suite())
    }

    /// Derive BOTH session keys — the at-rest [`SealingKey`] and the share-index
    /// [`IndexKey`] — from a single Argon2id run (M14). The index key falls out
    /// of the same high-entropy intermediate as the at-rest key via a second
    /// domain-separated HKDF-Expand, so activating the share indexer costs no
    /// extra Argon2id work on the Pi-4 floor. Used at first-start; the Unlock
    /// path gets both keys for free from [`open`] via [`Opened`].
    pub fn derive_session(
        passphrase: &str,
        profile_id: Uuid,
        params: ArgonParams,
    ) -> Result<(Self, IndexKey), BlobError> {
        let (mut at_rest, mut index) = derive_session_keys(passphrase, profile_id, params)?;
        let sk = Self(Zeroizing::new(at_rest));
        let ik = IndexKey(Zeroizing::new(index));
        at_rest.zeroize();
        index.zeroize();
        Ok((sk, ik))
    }
}

impl core::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The key is the session's most sensitive secret — never render it.
        f.write_str("SealingKey(<redacted>)")
    }
}

/// A cached share-index key (M14) derived as a sibling of the at-rest
/// [`SealingKey`] from the *same* single Argon2id run — one expensive KDF, two
/// domain-separated HKDF-Expand outputs. Opens the redb
/// [`ShareIndex`](crate::storage::share_index::ShareIndex). Zeroizes on drop; it
/// is a session secret on par with the at-rest key — never log or persist it.
#[derive(Clone)]
pub struct IndexKey(Zeroizing<[u8; INDEX_KEY_LEN]>);

impl IndexKey {
    /// The raw key bytes for
    /// [`ShareIndex::open`](crate::storage::share_index::ShareIndex::open),
    /// which takes the key by value. The returned copy is the caller's to
    /// zeroize after use.
    pub fn to_bytes(&self) -> [u8; INDEX_KEY_LEN] {
        *self.0
    }
}

impl core::fmt::Debug for IndexKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IndexKey(<redacted>)")
    }
}

/// Encrypt a [`Seeds`] payload into the canonical v2 blob layout under the
/// active write-suite resolved from [`Registry::default_write_suite`].
///
/// The suite_id is embedded in the v2 header **and** bound into the AEAD
/// AAD so a tamper-swap of the suite tag fails authentication.
pub fn seal(
    seeds: &Seeds,
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Vec<u8>, BlobError> {
    let suite_id = Registry::default_write_suite();
    seal_under(seeds, passphrase, profile_id, params, suite_id)
}

/// Encrypt a [`Seeds`] payload under an explicit `suite_id`. Used by
/// [`touch_reseal`] and by tests that need to write a non-default suite.
/// The registry MUST contain `suite_id` and it MUST be write-eligible.
pub fn seal_under(
    seeds: &Seeds,
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
    suite_id: SuiteId,
) -> Result<Vec<u8>, BlobError> {
    let mut key = derive_aead_key(passphrase, profile_id, params)?;
    let result = seal_with_key(seeds, &key, suite_id);
    key.zeroize();
    result
}

/// Encrypt a [`Seeds`] payload under a pre-derived 32-byte AEAD `key`, skipping
/// the Argon2id KDF. This is the hot path for the session write-through (M13):
/// the client derives the key once at unlock/first-start, caches it in a
/// [`SealingKey`], and re-seals on every persist-worthy mutation without paying
/// Argon2id again. The registry MUST contain `suite_id` and it MUST be
/// write-eligible. Layout and AAD binding are identical to [`seal_under`].
pub fn seal_with_key(
    seeds: &Seeds,
    key: &[u8; AEAD_KEY_LEN],
    suite_id: SuiteId,
) -> Result<Vec<u8>, BlobError> {
    Registry::resolve_for_write(suite_id).map_err(BlobError::WriteRefused)?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(BlobError::EntropySource)?;

    let aes = Aes256Key::new(key).map_err(BlobError::AesKeyInit)?;

    let plaintext_str = seeds.to_plaintext();
    let plaintext = plaintext_str.as_bytes();

    let suite_bytes = suite_id.get().to_be_bytes();

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    gcm_encrypt(
        &aes,
        &nonce,
        &suite_bytes,
        plaintext,
        &mut ciphertext,
        &mut tag,
    )
    .map_err(BlobError::AesMode)?;

    let mut blob =
        Vec::with_capacity(MAGIC.len() + SUITE_ID_LEN + NONCE_LEN + ciphertext.len() + TAG_LEN);
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&suite_bytes);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob.extend_from_slice(&tag);
    Ok(blob)
}

/// Decrypt a v2 (or legacy v1) blob. Fails closed on wrong passphrase /
/// tampered blob / schema mismatch / unknown suite — no information leaks
/// about which check failed beyond the variant boundary.
///
/// Returns an [`Opened`] carrying both the recovered [`Seeds`] and the
/// `suite_id` the blob was sealed under, plus a `legacy_v1` flag so the
/// caller can schedule a [`touch_reseal`] on the next write.
pub fn open(
    blob: &[u8],
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Opened, BlobError> {
    if blob.len() < MAGIC.len() {
        return Err(BlobError::Malformed("blob shorter than magic prefix"));
    }
    let magic = &blob[..MAGIC.len()];
    if magic == MAGIC {
        open_v2(&blob[MAGIC.len()..], passphrase, profile_id, params)
    } else if magic == MAGIC_V1 {
        open_v1(&blob[MAGIC_V1.len()..], passphrase, profile_id, params)
    } else {
        Err(BlobError::Malformed("magic prefix mismatch"))
    }
}

fn open_v2(
    rest: &[u8],
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Opened, BlobError> {
    if rest.len() < SUITE_ID_LEN + NONCE_LEN + TAG_LEN {
        return Err(BlobError::Malformed(
            "v2 blob shorter than minimum header+tag",
        ));
    }
    let suite_bytes: [u8; SUITE_ID_LEN] = rest[..SUITE_ID_LEN].try_into().unwrap();
    let suite_raw = u16::from_be_bytes(suite_bytes);
    let suite_id = SuiteId::try_new(suite_raw).map_err(BlobError::SuiteIdSentinel)?;
    if Registry::lookup(suite_id).is_none() {
        return Err(BlobError::UnknownSuite(suite_id));
    }

    let after_suite = &rest[SUITE_ID_LEN..];
    let nonce: &[u8; NONCE_LEN] = after_suite[..NONCE_LEN].try_into().unwrap();
    let after_nonce = &after_suite[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..].try_into().unwrap();

    // Derive both session keys from the single Argon2id run: the at-rest key
    // decrypts the blob, the index key rides out in `Opened` for the running
    // client (M14) — no second KDF on the Unlock path.
    let (mut key_bytes, mut index_bytes) = derive_session_keys(passphrase, profile_id, params)?;
    let aes = Aes256Key::new(&key_bytes).map_err(BlobError::AesKeyInit)?;
    let key = SealingKey(Zeroizing::new(key_bytes));
    let index_key = IndexKey(Zeroizing::new(index_bytes));
    key_bytes.zeroize();
    index_bytes.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    gcm_decrypt(&aes, nonce, &suite_bytes, ciphertext, tag, &mut plaintext).map_err(
        |e| match e {
            oxicrypt_aes::ModeError::TagMismatch => BlobError::AuthenticationFailed,
            other => BlobError::AesMode(other),
        },
    )?;

    let plaintext_str = core::str::from_utf8(&plaintext).map_err(BlobError::Utf8)?;
    let seeds = Seeds::from_plaintext(plaintext_str)?;
    plaintext.zeroize();
    Ok(Opened {
        seeds,
        suite_id,
        legacy_v1: false,
        key,
        index_key,
    })
}

fn open_v1(
    rest: &[u8],
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Opened, BlobError> {
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err(BlobError::Malformed(
            "v1 blob shorter than minimum header+tag",
        ));
    }
    let nonce: &[u8; NONCE_LEN] = rest[..NONCE_LEN].try_into().unwrap();
    let after_nonce = &rest[NONCE_LEN..];
    let ciphertext_len = after_nonce.len() - TAG_LEN;
    let ciphertext = &after_nonce[..ciphertext_len];
    let tag: &[u8; TAG_LEN] = after_nonce[ciphertext_len..].try_into().unwrap();

    let (mut key_bytes, mut index_bytes) = derive_session_keys(passphrase, profile_id, params)?;
    let aes = Aes256Key::new(&key_bytes).map_err(BlobError::AesKeyInit)?;
    let key = SealingKey(Zeroizing::new(key_bytes));
    let index_key = IndexKey(Zeroizing::new(index_bytes));
    key_bytes.zeroize();
    index_bytes.zeroize();

    let mut plaintext = vec![0u8; ciphertext.len()];
    // v1 used empty AAD — preserve that contract or M2 blobs fail to open.
    gcm_decrypt(&aes, nonce, b"", ciphertext, tag, &mut plaintext).map_err(|e| match e {
        oxicrypt_aes::ModeError::TagMismatch => BlobError::AuthenticationFailed,
        other => BlobError::AesMode(other),
    })?;

    let plaintext_str = core::str::from_utf8(&plaintext).map_err(BlobError::Utf8)?;
    let seeds = Seeds::from_plaintext(plaintext_str)?;
    plaintext.zeroize();
    // V1 predates the registry; the only suite that existed is 0x0001.
    let implicit = SuiteId::try_new(V1_IMPLICIT_SUITE_RAW)
        .expect("V1_IMPLICIT_SUITE_RAW is a valid non-sentinel id");
    Ok(Opened {
        seeds,
        suite_id: implicit,
        legacy_v1: true,
        key,
        index_key,
    })
}

/// Decrypt under the stored suite, re-encrypt as v2 under the active
/// write-suite. ISC-C24 "read-old, write-new on touch" — every save migrates
/// the blob to the current write-suite without flag-day coordination.
///
/// If the blob is already at the active write-suite, the function still
/// returns a re-sealed v2 blob (new nonce, same payload); callers may
/// short-circuit if `Opened::legacy_v1 == false` and `Opened::suite_id ==
/// Registry::default_write_suite()`. The function intentionally does no
/// short-circuit itself so the caller decides the policy.
pub fn touch_reseal(
    blob: &[u8],
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<Vec<u8>, BlobError> {
    let opened = open(blob, passphrase, profile_id, params)?;
    let write_suite = Registry::default_write_suite();
    seal_under(&opened.seeds, passphrase, profile_id, params, write_suite)
}

/// Run the two-stage Argon2id + HKDF KDF and produce the 32-byte at-rest AEAD
/// key. Thin wrapper over [`derive_session_keys`] that discards the share-index
/// sibling — used by the seal-only paths ([`seal_under`], legacy v1 open) that
/// never touch the index. The at-rest output is byte-identical to the pre-M14
/// single-key derivation, so existing blobs open unchanged.
fn derive_aead_key(
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<[u8; AEAD_KEY_LEN], BlobError> {
    let (at_rest, mut index) = derive_session_keys(passphrase, profile_id, params)?;
    index.zeroize();
    Ok(at_rest)
}

/// Run the expensive Argon2id KDF **once** and derive both session keys from the
/// single high-entropy intermediate via domain-separated HKDF-Expand: the
/// at-rest AEAD key (`info = at_rest`) and the share-index key
/// (`info = share_index`). One Argon2id run preserves the Pi-4 floor; the
/// share-index key is one extra HKDF-Expand off the same PRK. Domain separation
/// (distinct info strings already pinned in [`crate::kdf::info`]) makes the two
/// keys independent. The at-rest output is byte-identical to the pre-M14
/// single-key derivation — existing at-rest blobs open unchanged.
fn derive_session_keys(
    passphrase: &str,
    profile_id: Uuid,
    params: ArgonParams,
) -> Result<([u8; AEAD_KEY_LEN], [u8; INDEX_KEY_LEN]), BlobError> {
    // Stage 1: Argon2id (passphrase, salt=profile_id) → high-entropy intermediate.
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::default(),
        Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(BlobError::Argon2)?,
    );
    let mut intermediate = [0u8; ARGON2_OUTPUT_LEN];
    let salt: [u8; 16] = *profile_id.as_bytes();
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut intermediate)
        .map_err(BlobError::Argon2)?;

    // Stage 2: HKDF-Expand the intermediate twice under distinct info strings
    // (intermediate is already a high-entropy secret — no extract needed; that's
    // what `from_prk` is for). The `at_rest` expand is identical to the pre-M14
    // derivation; the `share_index` expand is the additive M14 sibling.
    let pid = profile_id.to_string();
    let hkdf = HkdfSha384::from_prk(&intermediate).map_err(BlobError::Hkdf)?;
    intermediate.zeroize();

    let mut at_rest_key = [0u8; AEAD_KEY_LEN];
    hkdf.expand(info::at_rest(&pid).as_bytes(), &mut at_rest_key)
        .map_err(BlobError::Hkdf)?;

    let mut index_key = [0u8; INDEX_KEY_LEN];
    hkdf.expand(info::share_index(&pid).as_bytes(), &mut index_key)
        .map_err(BlobError::Hkdf)?;

    Ok((at_rest_key, index_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_oxicrypt_initialized() {
        let _ = oxicrypt_module::initialize();
    }

    fn test_params() -> ArgonParams {
        // 8 KiB memory, t=1, p=1 — completes in single-digit ms so the test
        // suite doesn't bog. NEVER suitable for production deployment.
        ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn fresh_seeds() -> Seeds {
        Seeds::new(Mnemonic::generate().unwrap())
    }

    #[test]
    fn fresh_seeds_have_default_counters() {
        let seeds = Seeds::new(Mnemonic::generate().unwrap());
        assert_eq!(seeds.counters.current_send(), 0);
        assert_eq!(seeds.counters.highest_seen("anything"), None);
    }

    #[test]
    fn counter_state_round_trips_through_blob() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = Seeds::new(Mnemonic::generate().unwrap());
        assert_eq!(seeds.counters.next_send(), 1);
        assert_eq!(seeds.counters.next_send(), 2);
        seeds.counters.record_seen("srv#aabbccddeeff", 7);
        seeds.counters.record_seen("peer#001122334455", 3);

        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.counters.current_send(), 2);
        assert_eq!(recovered.counters.highest_seen("srv#aabbccddeeff"), Some(7));
        assert_eq!(
            recovered.counters.highest_seen("peer#001122334455"),
            Some(3)
        );
        assert_eq!(recovered.counters.highest_seen("unknown"), None);
    }

    #[test]
    fn legacy_bare_phrase_blob_opens_with_default_counters() {
        // Default-counter seeds serialize to the bare-phrase plaintext (the
        // M1/M2/M3 form), so this exercises the backward-compatible read path:
        // an existing test-group blob must still open with no re-enrollment.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = Seeds::new(Mnemonic::generate().unwrap());
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.counters.current_send(), 0);
    }

    #[test]
    fn record_seen_keeps_the_highest() {
        let mut cs = CounterState::default();
        cs.record_seen("t", 5);
        cs.record_seen("t", 3); // lower — must be ignored
        assert_eq!(cs.highest_seen("t"), Some(5));
        cs.record_seen("t", 8);
        assert_eq!(cs.highest_seen("t"), Some(8));
    }

    // ── mute / hide-shares lists (ISC-C15 / C16 / A-C3) ────────────────────

    #[test]
    fn mute_list_round_trips_through_blob() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        assert!(seeds.add_mute("brave-otter#aabbccddeeff"));
        assert!(seeds.add_mute("#001122334455")); // floor handle
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert!(recovered.is_muted("brave-otter#aabbccddeeff"));
        assert!(recovered.is_muted("#001122334455"));
        assert!(!recovered.is_muted("someone-else#ffffffffffff"));
    }

    #[test]
    fn hide_shares_list_round_trips_through_blob() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        assert!(seeds.add_hidden_share("noisy-sharer#0a0b0c0d0e0f"));
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert!(recovered.is_share_hidden("noisy-sharer#0a0b0c0d0e0f"));
        assert!(!recovered.is_share_hidden("brave-otter#aabbccddeeff"));
    }

    #[test]
    fn mute_add_is_idempotent() {
        let mut seeds = fresh_seeds();
        assert!(seeds.add_mute("x#aabbccddeeff")); // newly inserted → true
        assert!(!seeds.add_mute("x#aabbccddeeff")); // already present → false
        assert_eq!(seeds.muted.len(), 1);
    }

    #[test]
    fn mute_remove_works_and_reports() {
        let mut seeds = fresh_seeds();
        seeds.add_mute("x#aabbccddeeff");
        assert!(seeds.remove_mute("x#aabbccddeeff")); // was present → true
        assert!(!seeds.is_muted("x#aabbccddeeff"));
        assert!(!seeds.remove_mute("x#aabbccddeeff")); // already gone → false
    }

    #[test]
    fn mute_and_hide_are_independent() {
        // ISC-C16: a user may mute someone's chat but still see their shares,
        // or hide shares while still reading chat. The two lists never alias.
        let mut seeds = fresh_seeds();
        seeds.add_mute("a#aabbccddeeff");
        seeds.add_hidden_share("b#001122334455");
        assert!(seeds.is_muted("a#aabbccddeeff"));
        assert!(!seeds.is_share_hidden("a#aabbccddeeff"));
        assert!(seeds.is_share_hidden("b#001122334455"));
        assert!(!seeds.is_muted("b#001122334455"));
    }

    #[test]
    fn mute_handle_with_space_round_trips() {
        // Defensive: today's display names are adjective-noun (no spaces), but
        // a mute key stores whatever wire handle was observed. The directive
        // serialization parses the handle as rest-of-line, so a space-bearing
        // display name must survive a seal/open round-trip without truncation.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        seeds.add_mute("two words#aabbccddeeff");
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert!(recovered.is_muted("two words#aabbccddeeff"));
    }

    #[test]
    fn mute_rejects_handles_with_line_breaks_to_protect_blob_integrity() {
        // A wire handle never contains a line break, but a *malicious peer*
        // controls its own self-asserted display name. If a crafted handle
        // carrying an embedded newline were stored, it would inject a second
        // directive line into the line-based blob plaintext and corrupt the
        // blob on the next open — locking the victim out of their own identity.
        // add_mute / add_hidden_share must refuse such handles.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        assert!(!seeds.add_mute("evil\nsend-counter 999#aabbccddeeff"));
        assert!(!seeds.add_hidden_share("x\rmore#aabbccddeeff"));
        assert!(seeds.muted.is_empty());
        assert!(seeds.hidden_shares.is_empty());
        // The blob still round-trips cleanly — no injected directive line.
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        assert!(open(&blob, pp, pid, test_params()).is_ok());
    }

    // ── display name + circle persistence (ISC-C4b / C59 / C62, M13) ───────

    #[test]
    fn display_name_round_trips_through_blob() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        assert!(seeds.set_display_name(Some("brave otter".to_owned())));
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.display_name(), Some("brave otter"));
    }

    #[test]
    fn fresh_seeds_have_no_display_name_and_no_circles() {
        let seeds = fresh_seeds();
        assert_eq!(seeds.display_name(), None);
        assert!(seeds.circles().is_empty());
        // Default state still serializes to the bare phrase (no directive lines).
        assert_eq!(seeds.to_plaintext(), seeds.mnemonic.to_phrase());
    }

    #[test]
    fn set_display_name_refuses_line_breaks() {
        let mut seeds = fresh_seeds();
        assert!(!seeds.set_display_name(Some("evil\nname x".to_owned())));
        assert_eq!(seeds.display_name(), None);
        // Idempotent: setting the same value twice reports no-change the 2nd time.
        assert!(seeds.set_display_name(Some("ok".to_owned())));
        assert!(!seeds.set_display_name(Some("ok".to_owned())));
    }

    #[test]
    fn circles_round_trip_through_blob_with_spaces() {
        // Entropy and label both carry spaces; the hex encoding must keep them
        // intact and in join order across a seal/open round-trip.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        assert!(seeds.add_circle("correct horse battery staple", "Book Club"));
        assert!(seeds.add_circle("another shared secret phrase", "Ops Room"));
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        let circles = recovered.circles();
        assert_eq!(circles.len(), 2);
        assert_eq!(circles[0].entropy, "correct horse battery staple");
        assert_eq!(circles[0].label, "Book Club");
        assert_eq!(circles[1].entropy, "another shared secret phrase");
        assert_eq!(circles[1].label, "Ops Room");
    }

    #[test]
    fn shares_round_trip_through_blob_with_spaces_and_optional_label() {
        // A path with spaces + a labelled and an unlabelled share must survive a
        // seal/open round-trip intact, in insertion order (ISC-C21, M14). The
        // empty-label entry must come back as `None`, not `Some("")`.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        assert!(seeds.add_share("/home/me/My Documents", Some("Docs".to_owned())));
        assert!(seeds.add_share("/srv/shared photos", None));
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        let shares = recovered.shares();
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].root, "/home/me/My Documents");
        assert_eq!(shares[0].label.as_deref(), Some("Docs"));
        assert_eq!(shares[1].root, "/srv/shared photos");
        assert_eq!(shares[1].label, None);
    }

    #[test]
    fn published_roots_round_trip_and_are_idempotent() {
        // Published roots survive a seal/open round-trip in publish order, paths
        // with spaces intact; add is idempotent and remove is keyed on the path.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        assert!(seeds.add_published("/home/me/My Music"));
        assert!(seeds.add_published("/srv/docs"));
        assert!(
            !seeds.add_published("/home/me/My Music"),
            "add_published is idempotent on the root"
        );
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let mut recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.published(), ["/home/me/My Music", "/srv/docs"]);
        assert!(recovered.remove_published("/home/me/My Music"));
        assert!(!recovered.remove_published("/home/me/My Music"));
        assert_eq!(recovered.published(), ["/srv/docs"]);
    }

    #[test]
    fn add_share_is_idempotent_on_root_and_remove_works() {
        let mut seeds = fresh_seeds();
        assert!(seeds.add_share("/data/share", Some("One".to_owned())));
        // Same root → no duplicate, even with a different label.
        assert!(!seeds.add_share("/data/share", Some("Two".to_owned())));
        assert_eq!(seeds.shares().len(), 1);
        assert_eq!(seeds.shares()[0].label.as_deref(), Some("One"));
        assert!(seeds.remove_share("/data/share"));
        assert!(!seeds.remove_share("/data/share")); // already gone
        assert!(seeds.shares().is_empty());
    }

    #[test]
    fn add_circle_is_idempotent_on_entropy() {
        let mut seeds = fresh_seeds();
        assert!(seeds.add_circle("shared secret", "First Label"));
        // Same entropy → no duplicate, even with a different label.
        assert!(!seeds.add_circle("shared secret", "Other Label"));
        assert_eq!(seeds.circles().len(), 1);
        assert_eq!(seeds.circles()[0].label, "First Label");
    }

    #[test]
    fn remove_and_rename_circle_work() {
        let mut seeds = fresh_seeds();
        seeds.add_circle("phrase a", "A");
        seeds.add_circle("phrase b", "B");
        // Rename keyed on entropy (ISC-C62 override).
        assert!(seeds.rename_circle("phrase a", "Renamed A"));
        assert!(!seeds.rename_circle("phrase a", "Renamed A")); // no-op 2nd time
        assert!(!seeds.rename_circle("missing", "x")); // unknown entropy
        assert_eq!(seeds.circles()[0].label, "Renamed A");
        // Remove keyed on entropy.
        assert!(seeds.remove_circle("phrase a"));
        assert!(!seeds.remove_circle("phrase a")); // already gone
        assert_eq!(seeds.circles().len(), 1);
        assert_eq!(seeds.circles()[0].entropy, "phrase b");
    }

    #[test]
    fn cached_key_reseals_without_passphrase() {
        // The write-through keystone (M13): open a blob once, then re-seal a
        // mutated Seeds using only the cached SealingKey — no passphrase, no
        // second Argon2id run — and confirm the mutation persists on re-open.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();

        let opened = open(&blob, pp, pid, test_params()).unwrap();
        let mut live = opened.seeds;
        let key = opened.key; // cached — no passphrase from here on

        live.set_display_name(Some("brave otter".to_owned()));
        live.add_circle("shared secret phrase", "Book Club");
        let resealed = key.seal(&live).unwrap();

        let recovered = open(&resealed, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.display_name(), Some("brave otter"));
        assert_eq!(recovered.circles().len(), 1);
        assert_eq!(recovered.circles()[0].label, "Book Club");
    }

    #[test]
    fn sealing_key_derive_matches_seal() {
        // SealingKey::derive (first-start path) must produce the same key the
        // passphrase-based seal uses, so a blob sealed via derive opens normally.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        let key = SealingKey::derive(pp, pid, test_params()).unwrap();
        let blob = key.seal(&seeds).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.mnemonic.to_phrase(), seeds.mnemonic.to_phrase());
    }

    #[test]
    fn index_key_is_sibling_distinct_deterministic_and_free_on_unlock() {
        // M14 D2: the share-index key is derived as a sibling of the at-rest key
        // from the SAME Argon2id run. Properties that must hold:
        //   1. the at-rest half is byte-identical to the pre-M14 single-key
        //      derivation (no existing blob breaks);
        //   2. the index key is distinct from the at-rest key (domain separated);
        //   3. derivation is deterministic for the same (passphrase, profile_id);
        //   4. the Unlock path (`open`) recovers the SAME index key for free.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let p = test_params();
        let seeds = fresh_seeds();

        let (seal_key, index_key) = SealingKey::derive_session(pp, pid, p).unwrap();
        // (1) at-rest half unchanged vs. the solo derivation.
        let solo = derive_aead_key(pp, pid, p).unwrap();
        assert_eq!(*seal_key.0, solo, "at-rest key must be byte-identical");
        // (2) index distinct from at-rest.
        assert_ne!(
            index_key.to_bytes(),
            solo,
            "index key must be domain-separated"
        );
        // (3) deterministic.
        let (_, index_key2) = SealingKey::derive_session(pp, pid, p).unwrap();
        assert_eq!(index_key.to_bytes(), index_key2.to_bytes());
        // (4) the Unlock path yields the same index key, no second Argon2id run.
        let blob = seal_key.seal(&seeds).unwrap();
        let opened = open(&blob, pp, pid, p).unwrap();
        assert_eq!(opened.index_key.to_bytes(), index_key.to_bytes());
        // A different profile_id derives a different index key (salt separation).
        let (_, other) = SealingKey::derive_session(pp, Uuid::new_v4(), p).unwrap();
        assert_ne!(other.to_bytes(), index_key.to_bytes());
    }

    #[test]
    fn fresh_seeds_have_empty_mute_and_hide_lists() {
        let seeds = fresh_seeds();
        assert!(seeds.muted.is_empty());
        assert!(seeds.hidden_shares.is_empty());
    }

    #[test]
    fn round_trip() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        let original_phrase = seeds.mnemonic.to_phrase();

        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap();
        assert_eq!(recovered.seeds.mnemonic.to_phrase(), original_phrase);
        assert_eq!(recovered.suite_id.get(), 0x0001);
        assert!(!recovered.legacy_v1);
    }

    #[test]
    fn open_with_wrong_passphrase_fails_closed() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let blob = seal(
            &fresh_seeds(),
            "correct horse battery staple table mountain",
            pid,
            test_params(),
        )
        .unwrap();
        match open(
            &blob,
            "wrong horse battery staple table mountain",
            pid,
            test_params(),
        ) {
            Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_with_wrong_profile_id_fails_closed() {
        ensure_oxicrypt_initialized();
        let pid_a = Uuid::new_v4();
        let pid_b = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let blob = seal(&fresh_seeds(), pp, pid_a, test_params()).unwrap();
        match open(&blob, pp, pid_b, test_params()) {
            Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_with_wrong_argon_params_fails_closed() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        let different = ArgonParams {
            memory_kib: 16,
            iterations: 1,
            parallelism: 1,
        };
        match open(&blob, pp, pid, different) {
            Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_truncated_blob() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let blob = seal(&fresh_seeds(), "passphrase x", pid, test_params()).unwrap();
        let truncated = &blob[..MAGIC.len() + SUITE_ID_LEN + NONCE_LEN + 1];
        match open(truncated, "passphrase x", pid, test_params()) {
            Err(BlobError::Malformed(_)) | Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected Malformed or AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_bad_magic() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        blob[0] = b'X'; // flip magic
        match open(&blob, pp, pid, test_params()) {
            Err(BlobError::Malformed(_)) => {}
            other => panic!("expected Malformed (magic), got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        // Flip a byte in the ciphertext (middle of the blob).
        let mid = blob.len() / 2;
        blob[mid] ^= 0x01;
        match open(&blob, pp, pid, test_params()) {
            Err(BlobError::AuthenticationFailed) => {}
            other => panic!("expected AuthenticationFailed on tamper, got {other:?}"),
        }
    }

    #[test]
    fn blob_magic_v2_is_pinned() {
        // Spec contract — bumping this is a format-incompatible change.
        assert_eq!(MAGIC, b"daemonseed/blob/v2\0");
    }

    #[test]
    fn blob_magic_v1_legacy_is_pinned() {
        // The v1 magic is the read-fallback anchor and must stay byte-stable
        // for as long as we ship code that accepts M1/M2 enrollments.
        assert_eq!(MAGIC_V1, b"daemonseed/blob/v1\0");
    }

    #[test]
    fn debug_redacts_seeds() {
        let s = fresh_seeds();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn two_seals_of_same_seeds_produce_different_blobs() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let seeds = fresh_seeds();
        let a = seal(&seeds, pp, pid, test_params()).unwrap();
        let b = seal(&seeds, pp, pid, test_params()).unwrap();
        // Distinct nonces → distinct ciphertexts despite identical inputs.
        assert_ne!(a, b);
    }

    /// Hand-build a v1 blob (M2 wire shape) and confirm `open` recovers
    /// it under the implicit `suite_id = 0x0001`. Without this test the
    /// v1→v2 migration claim is just words.
    #[test]
    fn open_accepts_legacy_v1_blob() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        let phrase = seeds.mnemonic.to_phrase();

        // Construct a v1 blob by hand using the same KDF chain seal() uses
        // but with the v1 layout: magic | nonce | ct | tag, AAD=b"".
        let mut key = derive_aead_key(pp, pid, test_params()).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let aes = Aes256Key::new(&key).unwrap();
        key.zeroize();
        let pt = phrase.as_bytes();
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, b"", pt, &mut ct, &mut tag).unwrap();
        let mut v1_blob = Vec::with_capacity(MAGIC_V1.len() + NONCE_LEN + ct.len() + TAG_LEN);
        v1_blob.extend_from_slice(MAGIC_V1);
        v1_blob.extend_from_slice(&nonce);
        v1_blob.extend_from_slice(&ct);
        v1_blob.extend_from_slice(&tag);

        let opened = open(&v1_blob, pp, pid, test_params()).unwrap();
        assert_eq!(opened.seeds.mnemonic.to_phrase(), phrase);
        assert_eq!(opened.suite_id.get(), 0x0001);
        assert!(opened.legacy_v1);
    }

    /// touch_reseal migrates a v1 blob to v2 preserving payload — the
    /// ISC-C24 read-old / write-new property end-to-end.
    #[test]
    fn touch_reseal_migrates_v1_to_v2() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        let phrase = seeds.mnemonic.to_phrase();

        // Forge a v1 blob the same way as the prior test.
        let mut key = derive_aead_key(pp, pid, test_params()).unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).unwrap();
        let aes = Aes256Key::new(&key).unwrap();
        key.zeroize();
        let pt = phrase.as_bytes();
        let mut ct = vec![0u8; pt.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, b"", pt, &mut ct, &mut tag).unwrap();
        let mut v1_blob = Vec::with_capacity(MAGIC_V1.len() + NONCE_LEN + ct.len() + TAG_LEN);
        v1_blob.extend_from_slice(MAGIC_V1);
        v1_blob.extend_from_slice(&nonce);
        v1_blob.extend_from_slice(&ct);
        v1_blob.extend_from_slice(&tag);

        // Migrate.
        let v2_blob = touch_reseal(&v1_blob, pp, pid, test_params()).unwrap();
        assert_eq!(&v2_blob[..MAGIC.len()], MAGIC);
        assert_eq!(
            &v2_blob[MAGIC.len()..MAGIC.len() + SUITE_ID_LEN],
            &0x0001u16.to_be_bytes()
        );

        // Round-trip the migrated blob.
        let recovered = open(&v2_blob, pp, pid, test_params()).unwrap();
        assert_eq!(recovered.seeds.mnemonic.to_phrase(), phrase);
        assert_eq!(recovered.suite_id.get(), 0x0001);
        assert!(!recovered.legacy_v1);
    }

    /// AAD binding: flipping the suite_id byte in a v2 blob must fail
    /// authentication, because the suite_id is part of the AAD covered by
    /// the AEAD tag.
    #[test]
    fn v2_suite_id_tamper_fails_auth() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        // Tamper a suite_id byte while keeping the value within the
        // non-sentinel range — flip the low byte from 0x01 → 0x02.
        let suite_lo = MAGIC.len() + 1;
        assert_eq!(blob[suite_lo], 0x01);
        blob[suite_lo] = 0x02;
        match open(&blob, pp, pid, test_params()) {
            Err(BlobError::UnknownSuite(id)) => assert_eq!(id.get(), 0x0002),
            other => panic!("expected UnknownSuite, got {other:?}"),
        }
    }

    /// A v2 blob whose suite_id field encodes a reserved sentinel
    /// (`0x0000` / `0xFFFF`) is rejected as malformed before any AEAD work.
    #[test]
    fn v2_suite_id_sentinel_rejected() {
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "passphrase x";
        let mut blob = seal(&fresh_seeds(), pp, pid, test_params()).unwrap();
        let suite_hi = MAGIC.len();
        let suite_lo = MAGIC.len() + 1;
        // Force the suite bytes to 0x0000 (invalid sentinel).
        blob[suite_hi] = 0x00;
        blob[suite_lo] = 0x00;
        match open(&blob, pp, pid, test_params()) {
            Err(BlobError::SuiteIdSentinel(_)) => {}
            other => panic!("expected SuiteIdSentinel, got {other:?}"),
        }
    }
}
