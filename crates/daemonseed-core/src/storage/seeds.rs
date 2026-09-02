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

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};

use argon2::{Algorithm, Argon2, Params, Version};
use oxicrypt_aes::{Aes256Key, gcm_decrypt, gcm_encrypt};
use oxicrypt_kdf::HkdfSha384;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::suite::{Registry, SuiteId, SuiteIdError, WriteRefusal};
use crate::identity::mnemonic::{MAX_PHRASE_LEN, Mnemonic, MnemonicError};
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
/// - `announce-seen <server_id> <marker>` — the per-relay announcements/MOTD seen
///   marker (#93 unread-gating), OPAQUE to this store; the client owns its encoding.
///   Both tokens are whitespace-free, so the two-token split is unambiguous; a
///   malformed line is skipped. Client-local only — no wire message carries it
///   (ISC-A-C3).
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
    pub published: Vec<PublishedShare>,
    /// Per-relay announcements/MOTD seen marker (#93 unread-gating), keyed by
    /// `server_id` → a client-derived, whitespace-free value this store treats as
    /// OPAQUE. The client compares the content on display against it to decide
    /// whether the announcements tab shows an unread dot (#142 — the #93
    /// connect-time auto-open it originally gated was retired in favour of the
    /// dot). Default empty. Client-local only — no wire message carries it
    /// (ISC-A-C3); it is persistence of read-state, not of content.
    /// Mutate via [`Self::set_announce_seen`] / read via [`Self::announce_seen`].
    pub announce_seen: BTreeMap<String, String>,
    /// Per-circle read high-water mark (#107), keyed by the canonicalized circle
    /// entropy → the newest `sent_unix_ms` the user has seen in that circle. On
    /// restore each circle's in-RAM high-water is seeded from this, so a relaunch's
    /// backlog re-delivery does NOT re-trip the unread dot for already-seen messages
    /// (a genuinely newer message still does). Advanced via [`Self::set_circle_seen`]
    /// (monotonic) / read via [`Self::circle_seen`]. Client-local only (ISC-A-C3) —
    /// persistence of read-state, not of message content.
    ///
    /// Private, and keyed on [`CircleSeenKey`] rather than `String`, because the
    /// key IS a secret — see that type. Privacy is what makes the wrapper
    /// load-bearing instead of decorative: a `pub` map would let any caller lift
    /// an owned `String` copy of the phrase straight back out of a key, and
    /// bypass [`Self::set_circle_seen`]'s monotonic guard on the way.
    circle_seen: BTreeMap<CircleSeenKey, i64>,
}

/// The key of [`Seeds::circle_seen`] — a circle's canonicalized entropy, which is
/// the very same `cot_key` IKM (ISC-C8) that [`PersistedCircle`] holds in a
/// private [`Zeroizing`] `String`.
///
/// A newtype because **the key of a map is a place a secret can hide**. Before
/// this type the identical value was protected in one field of [`Seeds`] and held
/// in the clear in another, released unwiped on every drop and copied unwiped by
/// every `Clone` (#358).
///
/// ## Why not a struct-level derive, or a `Zeroizing` key
///
/// Both are the obvious shapes, and neither compiles against `zeroize` 1.8:
///
/// - `#[derive(Zeroize, ZeroizeOnDrop)]` on [`Seeds`] cannot reach a map at all,
///   and does not stop there: **eight of that struct's ten fields have no
///   `Zeroize` impl**, and the crate defines no manual ones. Four are the
///   collection shapes the crate has no impl for (`muted`, `hidden_shares`,
///   `announce_seen`, `circle_seen`); the other four are types that simply do not
///   derive it — `mnemonic` (`Clone` only), `counters`, and `shares` / `published`
///   whose element structs derive `Debug, Clone, PartialEq, Eq`. Only
///   `display_name` and `circles` would satisfy a derive. Making it build would
///   take `#[zeroize(skip)]` on eight of ten, which manufactures exactly the false
///   safety the derive exists to prevent: the next secret-bearing field would land
///   in a struct where skipping is already the house habit. [`PersistedCircle`]'s
///   derive works because both of its fields are `Zeroize`-able; [`Seeds`] is not
///   that shape.
/// - `BTreeMap<Zeroizing<String>, i64>` cannot compile either: a `BTreeMap` key
///   must be `Ord`, and `Zeroizing` does not implement it. (It implements plenty
///   else — `Clone`, `Deref`, `AsRef`, `Zeroize`, `ZeroizeOnDrop`, `Drop`, and
///   derives `Debug`, `Default`, `Eq`, `PartialEq` — but `Ord` is not among them.)
///
/// ## What wipes it
///
/// The `Drop` on the inner [`Zeroizing`], not a derive on any struct. Dropping the
/// map drops each key, which wipes the phrase — so the guarantee covers the
/// ordinary drop of a [`Seeds`], every early return of [`Seeds::from_plaintext`]
/// taken after a `circle-seen` line was read, and every clone, without [`Seeds`]
/// needing a derive it cannot have. `ZeroizeOnDrop` is derived alongside so the
/// property is legible to a reader and to the compile-time bound assertion in
/// [`crate::secret_seed`], and so a containing struct that later grows a derive
/// finds this field already satisfying it.
///
/// ## Why `Ord` and `Debug` are written out
///
/// `Ord`/`PartialOrd` cannot be derived through [`Zeroizing`], which implements
/// neither; delegating to the inner `str` is also what makes the `Borrow<str>`
/// impl below sound, since `Borrow` requires the borrowed and owned orderings to
/// agree. That impl is what lets [`Seeds::circle_seen`] look up by `&str` without
/// allocating a key to throw away.
///
/// `Debug` is written out because the derived one would print the phrase:
/// [`Zeroizing`] derives `Debug` and forwards to the inner value, so a secret
/// newtype that derives `Debug` publishes its secret to every log line and panic
/// message that touches it.
#[derive(Clone, PartialEq, Eq, Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct CircleSeenKey(Zeroizing<String>);

impl CircleSeenKey {
    /// Wrap a canonicalized circle entropy.
    ///
    /// Takes the [`Zeroizing`] wrapper rather than a bare `String` so a caller
    /// that already holds one — which [`Seeds::from_plaintext`] does, from the
    /// moment `decode_hex_secret` returns (#343) — moves it in instead of copying
    /// the phrase back out into an unprotected buffer first. That copy was the
    /// escape this type closes, and it is easier to not write than to remember.
    fn new(entropy: Zeroizing<String>) -> Self {
        Self(entropy)
    }

    /// Borrow the phrase. A borrow, never a copy: an owned `String` taken from
    /// here has escaped the wrapper and will release its buffer with the phrase
    /// still in it.
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for CircleSeenKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Ord for CircleSeenKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for CircleSeenKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::fmt::Debug for CircleSeenKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CircleSeenKey(<redacted>)")
    }
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

/// One remembered *published* share root in the at-rest blob (publish-intent
/// persistence). Holds the share-root path and an optional **wire-facing** share
/// name.
///
/// The `name` is deliberately a distinct field from [`PersistedShare::label`]: the
/// label is a *client-local-only* display string (ISC-A-C3, never transmitted),
/// whereas the published name is the name a fetching peer sees, so it travels on
/// the wire when the share is (re)asserted to the relay. `None` falls back to the
/// share root's basename at republish — today's behavior, and the value stored for
/// every share until a name-a-share UI exists. The blob layout stays additive: a
/// legacy one-field `publish <hex(root)>` line parses as `name = None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedShare {
    /// The published share-root directory path, as the user entered it.
    pub root: String,
    /// Optional wire-facing share name; `None` ⇒ the root's basename at republish.
    pub name: Option<String>,
}

/// The at-rest payload's line prefixes, including the leading newline.
///
/// Named because each is used twice — once by [`Seeds::plaintext_capacity`] to
/// size the buffer and once by [`Seeds::to_plaintext`] to write the line — and a
/// prefix that grew in the writer without growing in the sizer is exactly the
/// under-reservation that brings back the reallocation residue #263 is about.
/// Sharing the constant makes that particular drift impossible rather than
/// merely unlikely.
///
/// The reader in [`Seeds::from_plaintext`] does NOT share these: it matches
/// against a `&str` already split on newlines, so its prefixes have no leading
/// `\n` and are a different set of strings. The round-trip tests are what hold
/// the two halves together.
mod line {
    pub const SEND_COUNTER: &str = "\nsend-counter ";
    pub const SEEN: &str = "\nseen ";
    pub const MUTE: &str = "\nmute ";
    pub const HIDE: &str = "\nhide ";
    pub const NAME: &str = "\nname ";
    pub const CIRCLE: &str = "\ncircle ";
    pub const SHARE: &str = "\nshare ";
    pub const PUBLISH: &str = "\npublish ";
    pub const ANNOUNCE_SEEN: &str = "\nannounce-seen ";
    pub const CIRCLE_SEEN: &str = "\ncircle-seen ";
}

/// Append `bytes` to `out` as lowercase hex, allocating nothing.
///
/// Replaces `hex::encode` at every site in [`Seeds::to_plaintext`], secret or
/// not. `hex::encode` returns an owned `String` which is then copied into the
/// payload and dropped with its contents intact — for a circle entropy that is a
/// freed buffer holding the hex of the `cot_key` IKM (#263). Writing into the
/// caller's buffer produces no such transient. Byte-for-byte identical to
/// `hex::encode` for the same input, which is what lets `from_plaintext`'s
/// `hex::decode` keep reading it.
fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
}

/// Decode one hex-encoded **secret** field of the payload, wrapped from the
/// moment its bytes exist (#343).
///
/// The read-side counterpart of [`push_hex`], and it exists for the same reason:
/// the obvious call leaves the secret in a buffer nothing wipes. `hex::decode`
/// hands back a bare `Vec<u8>` that is already the plaintext secret, and
/// `String::from_utf8` moves that same allocation into a bare `String` — so
/// between the decode and whatever finally takes ownership, every `?` in the
/// parser drops key material intact. That window is not hypothetical: it is the
/// recovery path, reached exactly when a blob is corrupt or truncated and some
/// *later* field fails to parse.
///
/// [`hex::decode_to_slice`] writes into a buffer this function owns, so no
/// allocation is ever made outside the [`Zeroizing`] wrapper — including on
/// `hex`'s own error return, where `hex::decode`'s partially-filled buffer would
/// otherwise be dropped by a crate we do not control.
///
/// **That buys more than one buffer, which is the part worth stating.**
/// `hex::decode` collects through a `Result` adapter whose `size_hint` lower
/// bound is 0, so it does not reserve once — it grows the buffer geometrically.
/// Measured: 137 bytes decode into a 256-byte allocation, 3 001 into a 4 096-byte
/// one. Every one of those growth steps copies the partially-decoded secret into
/// a new block and releases the old one **with the secret still in it**, so the
/// residue was a ladder of stranded copies rather than the single final buffer
/// the issue described. Decoding into a right-sized buffer removes the ladder
/// along with its last rung.
///
/// The one copy — `str::to_owned` after the UTF-8 check — is deliberate and is
/// not residue. Taking the `Vec<u8>` back out of `Zeroizing` to hand it to
/// `String::from_utf8` is the thing being avoided, and validating on a borrow
/// keeps every early return covered by a wrapper rather than by an author
/// remembering to wipe. The source buffer is zeroized when it drops at the end
/// of this function.
///
/// **Secrets only.** Share roots and published-share names are ordinary
/// filesystem paths and wire-facing names, held in plain `String` fields
/// everywhere else in the crate; decoding those through here would claim a
/// secrecy the rest of the code does not honour.
fn decode_hex_secret(src: &str) -> Result<Zeroizing<String>, BlobError> {
    // Checked here as well as by `decode_to_slice` because it is what sizes the
    // buffer: integer division would silently under-allocate on an odd length,
    // and `decode_to_slice` would then report a length mismatch rather than the
    // odd input that caused it.
    if !src.len().is_multiple_of(2) {
        return Err(BlobError::InvalidPlaintext);
    }
    let mut bytes = Zeroizing::new(vec![0u8; src.len() / 2]);
    hex::decode_to_slice(src, bytes.as_mut_slice()).map_err(|_| BlobError::InvalidPlaintext)?;
    let text = core::str::from_utf8(&bytes).map_err(|_| BlobError::InvalidPlaintext)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// One remembered circle in the at-rest blob (ISC-C59 persistence, M13).
///
/// Holds the minimum needed to rejoin without re-typing: the canonicalized
/// circle entropy (the `cot_key` IKM, ISC-C8/C9) and the client-local display
/// label (ISC-C62). Neither field ever leaves the encrypted blob — no wire
/// message carries them (ISC-A-C3). `entropy` is the canonicalized phrase, not
/// the derived key, so a later cross-family suite change re-derives correctly.
///
/// `entropy` is secret material, so it is **private** and held in a
/// [`Zeroizing`] `String`: the wipe is carried by the type, so it happens on
/// every path out of every scope the value reaches, including an unwind, and no
/// caller can lift the raw phrase into a container that has no `Drop` of its
/// own. Read it through [`Self::entropy`], build one with [`Self::new`].
/// `Debug` is hand-written so the phrase never reaches a log surface (ISC-A-C1).
/// `PartialEq` / `Eq` are not implemented: nothing compares whole
/// `PersistedCircle`s, and deriving equality onto a secret-bearing type invites
/// copies of the secret into comparison sites for no benefit. (#259)
///
/// **`Zeroize`/`ZeroizeOnDrop` are derived, and that is a different property from
/// the one `Zeroizing<String>` on `entropy` already gives (#267).** The field type
/// covers `entropy` and only `entropy`; a secret field added later as a bare
/// `String` would be released unwiped, and nothing would say so. The derive makes
/// the wipe the default for every field: the generated `Drop` destructures `Self`
/// with all fields bound and calls `zeroize()` on each, so a new field is wiped
/// unless someone writes an explicit `#[zeroize(skip)]` on it. There are no such
/// lines here — `label` is display text rather than a secret, but wiping it costs
/// one memset and leaving it unskipped is one less line for a future author to
/// copy onto a field that did need wiping.
///
/// The precise limit, since it is easy to overstate: a field is wiped if its type
/// has a `Zeroize` impl reachable by method resolution — `String`, `Vec<u8>`,
/// `[u8; N]`, and `Box<[u8; N]>` (no impl of its own, but it derefs to one) all
/// qualify. A field whose type has none does not compile. See the same note on
/// [`crate::dm::firstcontact::VerifiedFirstContact`].
#[derive(Clone, Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PersistedCircle {
    /// Canonicalized circle entropy (NFKC + whitespace-folded, ISC-C9). This is
    /// the IKM the `cot_key` derivation (ISC-C8) re-runs on rejoin.
    entropy: Zeroizing<String>,
    /// Client-local circle label (ISC-C62). Never transmitted, never derived
    /// from members.
    pub label: String,
}

impl PersistedCircle {
    /// Remember a circle. `entropy` MUST already be canonicalized (ISC-C9) — this
    /// only stores what the caller normalized.
    ///
    /// Takes `impl Into<Zeroizing<String>>` rather than `impl Into<String>` so a
    /// caller that already holds the entropy inside the wrapper — which
    /// `Seeds::from_plaintext` does, from the moment it decodes (#343) — can
    /// move it in rather than copying it back out. `zeroize`'s blanket
    /// `From<Z> for Zeroizing<Z>` keeps a plain `String` accepted, so this
    /// narrows nothing for existing callers; it only stops the round trip
    /// through an unprotected `String` that a `Zeroizing` caller would otherwise
    /// have to make.
    pub fn new(entropy: impl Into<Zeroizing<String>>, label: impl Into<String>) -> Self {
        Self {
            entropy: entropy.into(),
            label: label.into(),
        }
    }

    /// Borrow the canonicalized entropy — the `cot_key` IKM (ISC-C8). A borrow,
    /// never a copy: an owned `String` taken from here has escaped the zeroizing
    /// wrapper and will release its buffer with the phrase still in it.
    pub fn entropy(&self) -> &str {
        &self.entropy
    }
}

impl core::fmt::Debug for PersistedCircle {
    /// Hand-written, never derived: `entropy` is the `cot_key` IKM (ISC-C8) and
    /// [`Zeroizing`]'s own `Debug` forwards to the value it wraps, so a derived
    /// one would print the circle secret verbatim and walk straight around the
    /// redacted [`Debug for Seeds`](Seeds) below. The label is client-local
    /// display text, and is what a reader actually wants (#259).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PersistedCircle")
            .field("entropy", &"<redacted>")
            .field("label", &self.label)
            .finish()
    }
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
            .field("announce_seen", &self.announce_seen.len())
            .field("circle_seen", &self.circle_seen.len())
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
            announce_seen: BTreeMap::new(),
            circle_seen: BTreeMap::new(),
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
        // Wrapped before the duplicate check, not after it (#343). That check
        // has an early return, and on it a bare `String` holding a circle's
        // entropy — the `cot_key` IKM, ISC-C8 — would drop with the secret still
        // in it. Re-joining a circle already remembered is the ordinary case.
        //
        // The parameter stays `impl Into<String>`: what a caller held before the
        // call is the caller's business, and narrowing it would force every one
        // of them to build a wrapper for a value this function takes ownership
        // of anyway.
        let entropy = Zeroizing::new(entropy.into());
        if self.circles.iter().any(|c| c.entropy() == entropy.as_str()) {
            return false;
        }
        self.circles.push(PersistedCircle::new(entropy, label));
        true
    }

    /// Forget a remembered circle, keyed on its canonicalized entropy (M13).
    /// Returns `true` if one was removed.
    pub fn remove_circle(&mut self, entropy: &str) -> bool {
        let before = self.circles.len();
        self.circles.retain(|c| c.entropy() != entropy);
        self.circles.len() != before
    }

    /// Rename a remembered circle's client-local label (ISC-C62 override, M13),
    /// keyed on its canonicalized entropy. Returns `true` if the label changed.
    pub fn rename_circle(&mut self, entropy: &str, new_label: impl Into<String>) -> bool {
        let new_label = new_label.into();
        for c in &mut self.circles {
            if c.entropy() == entropy {
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

    /// The remembered *published* shares, in publish order (publish-intent
    /// persistence). A subset of [`Self::shares`], each with its optional
    /// wire-facing [`PublishedShare::name`].
    pub fn published(&self) -> &[PublishedShare] {
        &self.published
    }

    /// Remember that a share root is published (with an optional wire-facing
    /// `name`) so it auto-republishes next launch. Returns `true` if newly added,
    /// `false` if the root was already remembered (idempotent, keyed on the root
    /// path — re-publishing does not change a stored name). Root and name are both
    /// hex-encoded at serialization, so any path or name survives the line-based
    /// blob.
    pub fn add_published(&mut self, root: impl Into<String>, name: Option<String>) -> bool {
        let root = root.into();
        if self.published.iter().any(|p| p.root == root) {
            return false;
        }
        self.published.push(PublishedShare { root, name });
        true
    }

    /// Forget a published share, keyed on its root path. Returns `true` if one
    /// was removed.
    pub fn remove_published(&mut self, root: &str) -> bool {
        let before = self.published.len();
        self.published.retain(|p| p.root != root);
        self.published.len() != before
    }

    /// The per-relay announcements/MOTD seen marker for `server_id` (#93), or `None`
    /// if this relay was never marked seen. The value is **opaque here** — the client
    /// owns its meaning and encoding (today, the set of item content hashes the user
    /// has read); this store only guarantees it round-trips through the blob.
    pub fn announce_seen(&self, server_id: &str) -> Option<&str> {
        self.announce_seen.get(server_id).map(String::as_str)
    }

    /// Forget the announcements/MOTD seen marker for `server_id`. Returns `true` if one
    /// was removed. Used to roll the in-memory map back to disk state when a re-seal
    /// fails, so a failed write cannot masquerade as a completed one.
    pub fn clear_announce_seen(&mut self, server_id: &str) -> bool {
        self.announce_seen.remove(server_id).is_some()
    }

    /// Record `marker` as the announcements/MOTD seen marker for `server_id`
    /// (#93 unread-gating). Returns `true` if the stored value changed, `false` if
    /// unchanged (idempotent) or rejected.
    ///
    /// Refuses a `server_id` or `marker` containing whitespace or a line break: the
    /// `announce-seen <server_id> <marker>` directive is a single, two-token line, so
    /// a space would make the split ambiguous and a `\n`/`\r` would inject a
    /// spurious directive and corrupt the blob on the next open — same integrity
    /// rule as [`Self::add_mute`]. This is the ONLY constraint the marker's encoding
    /// must respect; a `name#hex` server_id and a whitespace-free marker are always
    /// accepted.
    pub fn set_announce_seen(
        &mut self,
        server_id: impl Into<String>,
        marker: impl Into<String>,
    ) -> bool {
        let server_id = server_id.into();
        let marker = marker.into();
        if server_id.contains([' ', '\t', '\n', '\r']) || marker.contains([' ', '\t', '\n', '\r']) {
            return false;
        }
        if self.announce_seen.get(&server_id).map(String::as_str) == Some(marker.as_str()) {
            return false;
        }
        self.announce_seen.insert(server_id, marker);
        true
    }

    /// The persisted read high-water (#107) for the circle keyed by canonicalized
    /// `entropy` — the newest `sent_unix_ms` the user has seen there, or `None` if
    /// the circle has no recorded mark yet.
    ///
    /// Takes `&str` and allocates nothing: the key type's `Borrow<str>` is what
    /// lets the map be queried without building a key to discard.
    pub fn circle_seen(&self, entropy: &str) -> Option<i64> {
        self.circle_seen.get(entropy).copied()
    }

    /// The live bytes of the first `circle_seen` key, for the behavioural zeroize
    /// witness in `tests/secret_zeroize_on_drop.rs`.
    ///
    /// The map is private (#358) and that harness must live outside this crate —
    /// it installs a `GlobalAlloc` hook and `daemonseed-core` is
    /// `#![forbid(unsafe_code)]` — so the witness needs a way in, exactly as
    /// `VerifiedFirstContact` does for the same reason (#265). Gated so no
    /// consumer of the crate can reach it.
    ///
    /// A borrow of the key's own buffer, which is what makes it usable as a watch
    /// address: a copy would be a different allocation and would prove nothing
    /// about the one the map releases.
    #[cfg(any(test, feature = "testing"))]
    pub fn circle_seen_first_key_bytes_for_test(&self) -> &[u8] {
        self.circle_seen
            .keys()
            .next()
            .expect("the caller inserts one entry before watching it")
            .as_str()
            .as_bytes()
    }

    /// Advance the circle read high-water (#107) for `entropy` to `ms`. Monotonic —
    /// only moves forward, so an out-of-order/older write never lowers the mark.
    /// Returns `true` if the stored value advanced, `false` if unchanged.
    ///
    /// The phrase is wrapped before anything else happens to it, and the lookup
    /// borrows rather than building a key to throw away — see the key type.
    /// `Zeroizing::new` moves the `String`, so no second copy of the buffer is
    /// made; the caller's own `&str`, if that is what it passed, remains the
    /// caller's to manage.
    pub fn set_circle_seen(&mut self, entropy: impl Into<String>, ms: i64) -> bool {
        let entropy = Zeroizing::new(entropy.into());
        if self
            .circle_seen
            .get(entropy.as_str())
            .is_some_and(|cur| *cur >= ms)
        {
            return false;
        }
        self.circle_seen.insert(CircleSeenKey::new(entropy), ms);
        true
    }

    /// An upper bound on the byte length of [`Self::to_plaintext`]'s output.
    ///
    /// An upper bound, not the exact length: integers are sized at their widest
    /// decimal form and the mnemonic at [`MAX_PHRASE_LEN`], so a real payload is
    /// shorter by a few hundred bytes at most. That is the right trade — the
    /// reservation only has to be large enough that the buffer never grows, and
    /// computing exact decimal widths would add arithmetic that could itself be
    /// wrong in the under-counting direction.
    ///
    /// Every line's own prefix is measured from the same [`line`] constant the
    /// writer uses, so a prefix that changes length cannot leave the reservation
    /// behind. What this function does NOT protect against is a *new* line kind
    /// added to the writer and not to this function; the reallocation assertion in
    /// `to_plaintext` is what catches that, and it is why the assertion is there
    /// rather than being left as a comment.
    fn plaintext_capacity(&self) -> usize {
        // Widest decimal renderings: `u64::MAX` is 20 digits, and `i64::MIN` is 19
        // digits plus a sign, also 20.
        const MAX_U64_DIGITS: usize = 20;
        const MAX_I64_DIGITS: usize = 20;

        let mut cap = MAX_PHRASE_LEN;
        if self.counters.send_counter != 0 {
            cap += line::SEND_COUNTER.len() + MAX_U64_DIGITS;
        }
        for target in self.counters.seen.keys() {
            cap += line::SEEN.len() + target.len() + 1 + MAX_U64_DIGITS;
        }
        for handle in &self.muted {
            cap += line::MUTE.len() + handle.len();
        }
        for handle in &self.hidden_shares {
            cap += line::HIDE.len() + handle.len();
        }
        if let Some(name) = &self.display_name {
            cap += line::NAME.len() + name.len();
        }
        for c in &self.circles {
            cap += line::CIRCLE.len() + 2 * c.entropy().len() + 1 + 2 * c.label.len();
        }
        for sh in &self.shares {
            cap += line::SHARE.len()
                + 2 * sh.root.len()
                + 1
                + 2 * sh.label.as_deref().unwrap_or("").len();
        }
        for ps in &self.published {
            cap += line::PUBLISH.len() + 2 * ps.root.len();
            if let Some(name) = &ps.name {
                cap += 1 + 2 * name.len();
            }
        }
        for (server_id, marker) in &self.announce_seen {
            cap += line::ANNOUNCE_SEEN.len() + server_id.len() + 1 + marker.len();
        }
        for entropy in self.circle_seen.keys() {
            cap += line::CIRCLE_SEEN.len() + 2 * entropy.as_str().len() + 1 + MAX_I64_DIGITS;
        }
        cap
    }

    /// Serialize the whole at-rest payload into one buffer that is reserved once
    /// and wipes itself.
    ///
    /// **What the shape of this function is for (#263).** The payload is the
    /// 24-word mnemonic plus every circle entropy — secret from its first line
    /// onward. The earlier version grew a `String` by `push_str`, so each
    /// reallocation `memcpy`d the accumulated secret into a new block and released
    /// the old one untouched, and each hex-encoded field spent two short-lived
    /// `String`s (`hex::encode`, then `format!`) that were also dropped with
    /// secret bytes in them. A final `zeroize()` reaches none of that; it reaches
    /// the last buffer only. So: the capacity is computed first and reserved once
    /// so the buffer never moves, the phrase is written straight in rather than
    /// built and copied, integers go through `fmt::Write` (which writes into the
    /// buffer and allocates nothing), and hex goes through [`push_hex`] instead of
    /// `hex::encode` + `format!`.
    ///
    /// **What that does and does not achieve.** It removes the copies *this
    /// function* would otherwise leave in freed heap. It does not make the
    /// operation copy-free in any absolute sense, and nothing here should be read
    /// as claiming so: the returned buffer is still handed to the AEAD and lives
    /// as long as the caller keeps it, the allocator may hand a freed block to an
    /// unrelated caller that only partly overwrites it, the page may be swapped,
    /// and an SSD's FTL can remap a block out of reach of any process. Registers
    /// and stack spills are outside safe Rust's reach entirely. The achievable bar
    /// is that our own code leaves no un-zeroized copy on the normal path, and
    /// that is the bar this meets.
    ///
    /// The return type carries the wipe rather than leaving it to a call the
    /// caller might skip on an early return, and it covers an unwind out of the
    /// assembly below.
    fn to_plaintext(&self) -> Zeroizing<String> {
        use core::fmt::Write as _;

        let cap = self.plaintext_capacity();
        let mut buf = Zeroizing::new(String::with_capacity(cap));
        {
            let s: &mut String = &mut buf;
            // The address of the reservation. If any write below overruns `cap`,
            // `String` reallocates and this pointer stops matching — which is the
            // one observable difference between the fixed code and the bug.
            let reserved = s.as_ptr();

            self.mnemonic.write_phrase_into(s);
            if self.counters.send_counter != 0 {
                s.push_str(line::SEND_COUNTER);
                let _ = write!(s, "{}", self.counters.send_counter);
            }
            for (target, counter) in &self.counters.seen {
                s.push_str(line::SEEN);
                s.push_str(target);
                s.push(' ');
                let _ = write!(s, "{counter}");
            }
            for handle in &self.muted {
                s.push_str(line::MUTE);
                s.push_str(handle);
            }
            for handle in &self.hidden_shares {
                s.push_str(line::HIDE);
                s.push_str(handle);
            }
            // Display name (ISC-C4b, M13): rest-of-line value; newlines are refused
            // at the setter so this never injects a spurious directive.
            if let Some(name) = &self.display_name {
                s.push_str(line::NAME);
                s.push_str(name);
            }
            // Circles (ISC-C59 persistence, M13): both fields are hex-encoded so a
            // space- or newline-containing entropy/label can never split the line
            // or inject a directive. Layout: `circle <hex(entropy)> <hex(label)>`.
            for c in &self.circles {
                s.push_str(line::CIRCLE);
                push_hex(s, c.entropy().as_bytes());
                s.push(' ');
                push_hex(s, c.label.as_bytes());
            }
            // Shares (ISC-C21 persistence, M14): both fields hex-encoded so a path
            // or label with spaces/newlines never splits the line. A `None` label
            // serializes as empty hex. Layout: `share <hex(root)> <hex(label)>`.
            for sh in &self.shares {
                s.push_str(line::SHARE);
                push_hex(s, sh.root.as_bytes());
                s.push(' ');
                push_hex(s, sh.label.as_deref().unwrap_or("").as_bytes());
            }
            // Published shares (publish-intent persistence): hex-encoded path so a
            // path with spaces/newlines never splits the line. Layout is additive —
            // `publish <hex(root)>` when there is no wire-facing name (legacy form),
            // `publish <hex(root)> <hex(name)>` when there is. A reader of either form
            // round-trips (see `from_plaintext`).
            for ps in &self.published {
                s.push_str(line::PUBLISH);
                push_hex(s, ps.root.as_bytes());
                if let Some(name) = &ps.name {
                    s.push(' ');
                    push_hex(s, name.as_bytes());
                }
            }
            // Per-relay announcements/MOTD seen marker (#93): one line per entry,
            // `announce-seen <server_id> <marker>`. Both tokens are whitespace-free
            // (guarded at the setter), so a two-token split round-trips; the BTreeMap
            // iterates in deterministic key order. Client-local only (ISC-A-C3).
            for (server_id, marker) in &self.announce_seen {
                s.push_str(line::ANNOUNCE_SEEN);
                s.push_str(server_id);
                s.push(' ');
                s.push_str(marker);
            }
            // Per-circle read high-water (#107): `circle-seen <hex(entropy)> <ms>`. The
            // entropy is hex-encoded (it is a phrase with spaces); `ms` is a plain i64.
            // Additive — an older blob with no such line parses to an empty map.
            for (entropy, ms) in &self.circle_seen {
                s.push_str(line::CIRCLE_SEEN);
                push_hex(s, entropy.as_str().as_bytes());
                s.push(' ');
                let _ = write!(s, "{ms}");
            }

            // `debug_assert`, not `assert`: an under-reservation is a hygiene
            // failure, not a correctness one — the payload is still right and still
            // seals — so panicking here in release would turn a residue into a lost
            // persist, which is the worse outcome. Debug is where it needs to fire,
            // because that is where the tests run: `to_plaintext_reserves_once…`
            // exercises every line kind, so a new line kind added without a matching
            // term in `plaintext_capacity` trips this rather than silently
            // reintroducing the reallocation. The capacity assertion in that test is
            // the half that still holds in a release build.
            debug_assert_eq!(
                s.as_ptr(),
                reserved,
                "the payload buffer was reallocated, so `plaintext_capacity` \
                 under-counted and the secret was copied into freed heap (#263)"
            );
            debug_assert!(
                s.len() <= cap,
                "payload of {} bytes exceeds the reserved {cap}",
                s.len()
            );
        }
        buf
    }

    /// Parse a decrypted payload directly, for the zeroization witness only.
    ///
    /// [`Self::from_plaintext`] is private and there is no public route to it
    /// carrying a *malformed* payload: sealing takes a `Seeds`, so a bad line
    /// cannot be constructed through [`open`], and corrupting the ciphertext
    /// fails the GCM tag long before the parser runs. The error paths this
    /// exists to observe are therefore unreachable from outside the crate — and
    /// they are exactly the paths that run when an at-rest blob is corrupt,
    /// which is when recovery happens.
    ///
    /// The observation needs the pass-through allocator in
    /// `tests/secret_zeroize_on_drop.rs`, which is its own binary, so a unit
    /// test cannot substitute. Gated behind `testing`, enabled only by this
    /// crate's dev-dependency on itself, exactly as
    /// [`crate::dm::firstcontact::VerifiedFirstContact`]'s accessors are.
    #[cfg(feature = "testing")]
    pub fn parse_plaintext_for_witness(s: &str) -> Result<Self, BlobError> {
        Self::from_plaintext(s)
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
        let mut published: Vec<PublishedShare> = Vec::new();
        let mut announce_seen: BTreeMap<String, String> = BTreeMap::new();
        let mut circle_seen: BTreeMap<CircleSeenKey, i64> = BTreeMap::new();
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
                // The entropy goes through `decode_hex_secret` and the label does
                // not: the entropy is the `cot_key` IKM (ISC-C8) and the label is
                // client-local display text, held in a plain `String` on
                // `PersistedCircle` itself. Note the ordering hazard the helper
                // closes — a malformed *label* returns below while the entropy is
                // still live, so before #343 the secret was dropped intact by the
                // `?` on the next line.
                let entropy = decode_hex_secret(entropy_hex)?;
                let label = hex::decode(label_hex)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or(BlobError::InvalidPlaintext)?;
                circles.push(PersistedCircle::new(entropy, label));
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
            // Published share (publish-intent persistence). Additive layout:
            // `publish <hex(root)>` (legacy, name = None) or
            // `publish <hex(root)> <hex(name)>` (named). An empty name hex (or no
            // second field) decodes to `None`.
            if let Some(rest) = line.strip_prefix("publish ") {
                let (root_hex, name) = match rest.split_once(' ') {
                    Some((root_hex, name_hex)) => {
                        let name_str = hex::decode(name_hex)
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                            .ok_or(BlobError::InvalidPlaintext)?;
                        (root_hex, (!name_str.is_empty()).then_some(name_str))
                    }
                    None => (rest, None),
                };
                let root = hex::decode(root_hex)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or(BlobError::InvalidPlaintext)?;
                published.push(PublishedShare { root, name });
                continue;
            }
            // Per-relay announcements/MOTD seen marker (#93):
            // `announce-seen <server_id> <marker>`. A malformed line (missing the
            // second token) is SKIPPED, not fatal — matching the directive scheme's
            // additive tolerance; an older blob with no such line parses to empty.
            if let Some(rest) = line.strip_prefix("announce-seen ") {
                if let Some((server_id, marker)) = rest.split_once(' ') {
                    announce_seen.insert(server_id.to_string(), marker.to_string());
                }
                continue;
            }
            // Per-circle read high-water (#107): `circle-seen <hex(entropy)> <ms>`. A
            // malformed line is SKIPPED, not fatal (additive tolerance); an older blob
            // with no such line parses to an empty map.
            if let Some(rest) = line.strip_prefix("circle-seen ") {
                // Same secret as the `circle` arm — this key IS a circle's
                // entropy — so it decodes through the same helper (#343). The
                // two fallible steps that follow the decode each dropped a bare
                // `Vec<u8>` of the `cot_key` IKM before that.
                //
                // The success path is closed too (#358): the decoded value moves
                // into a `CircleSeenKey` still inside the `Zeroizing` wrapper
                // `decode_hex_secret` returned it in, so the phrase is never
                // copied back out into an unprotected buffer and the map holds no
                // cleartext IKM for the struct's lifetime.
                if let Some((entropy_hex, ms_str)) = rest.split_once(' ')
                    && let (Ok(entropy), Ok(ms)) =
                        (decode_hex_secret(entropy_hex), ms_str.parse::<i64>())
                {
                    circle_seen.insert(CircleSeenKey::new(entropy), ms);
                }
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
            announce_seen,
            circle_seen,
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
    /// hands this to the running client to open the redb `ShareIndex`
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

    /// The raw at-rest key, for the record stores that take it by reference
    /// rather than through this type — currently
    /// [`DmPersist::open`](crate::dm::persist::DmPersist::open), which protects
    /// the DM records under the same profile key as the at-rest blob.
    ///
    /// Returned inside [`Zeroizing`] rather than bare: a copy of the session's
    /// most sensitive secret must not depend on each caller remembering to wipe
    /// it. Exposing it at all is what keeps the DM store on the profile's own
    /// key instead of inventing a second derivation for it.
    pub fn to_bytes(&self) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
        Zeroizing::new(*self.0)
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
/// `ShareIndex`(crate::storage::share_index::ShareIndex). Zeroizes on drop; it
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
///
/// The serialized plaintext buffer is held in [`Zeroizing`], so it is wiped on
/// every path out of this function — the success path, the AEAD error path, and an
/// unwind out of either. That wipe now covers the whole buffer's history rather
/// than only its final state: `Seeds::to_plaintext` reserves its capacity up
/// front and writes into it, so the payload is never copied to a second block and
/// the per-field `hex::encode` + `format!` transients are gone (#263). What
/// remains outside its reach is stated on `to_plaintext` itself — the ciphertext
/// and tag buffers below are not secret, but pages, the allocator's reuse of freed
/// blocks, and register spills are beyond any of this.
pub fn seal_with_key(
    seeds: &Seeds,
    key: &[u8; AEAD_KEY_LEN],
    suite_id: SuiteId,
) -> Result<Vec<u8>, BlobError> {
    Registry::resolve_for_write(suite_id).map_err(BlobError::WriteRefused)?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(BlobError::EntropySource)?;

    let aes = Aes256Key::new(key).map_err(BlobError::AesKeyInit)?;

    // The serialized payload is the 24-word mnemonic plus every circle entropy in
    // one `String`. `to_plaintext` hands it back already in `Zeroizing`, so the
    // wipe is carried by the type rather than by a positional `zeroize()` call and
    // covers an unwind out of the window below — `vec![0u8; len]` can panic on
    // capacity overflow, and `gcm_encrypt` asserts on its own buffer lengths.
    // (#259, #263)
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

    // `Zeroizing` rather than a `plaintext.zeroize()` at the end (#343): this
    // buffer holds the ENTIRE decrypted profile — mnemonic, every circle
    // entropy, every share root — and two fallible steps stand between the
    // decryption and that call. A trailing wipe runs on the success path only,
    // so a corrupt blob (the case this path exists to survive) returned with
    // the whole plaintext intact in freed heap. Carrying the wipe on the type
    // covers both returns and every one added later.
    let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
    gcm_decrypt(&aes, nonce, &suite_bytes, ciphertext, tag, &mut plaintext).map_err(
        |e| match e {
            oxicrypt_aes::ModeError::TagMismatch => BlobError::AuthenticationFailed,
            other => BlobError::AesMode(other),
        },
    )?;

    let plaintext_str = core::str::from_utf8(&plaintext).map_err(BlobError::Utf8)?;
    let seeds = Seeds::from_plaintext(plaintext_str)?;
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

    // `Zeroizing` rather than a `plaintext.zeroize()` at the end (#343): this
    // buffer holds the ENTIRE decrypted profile — mnemonic, every circle
    // entropy, every share root — and two fallible steps stand between the
    // decryption and that call. A trailing wipe runs on the success path only,
    // so a corrupt blob (the case this path exists to survive) returned with
    // the whole plaintext intact in freed heap. Carrying the wipe on the type
    // covers both returns and every one added later.
    let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
    // v1 used empty AAD — preserve that contract or M2 blobs fail to open.
    gcm_decrypt(&aes, nonce, b"", ciphertext, tag, &mut plaintext).map_err(|e| match e {
        oxicrypt_aes::ModeError::TagMismatch => BlobError::AuthenticationFailed,
        other => BlobError::AesMode(other),
    })?;

    let plaintext_str = core::str::from_utf8(&plaintext).map_err(BlobError::Utf8)?;
    let seeds = Seeds::from_plaintext(plaintext_str)?;
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
        let _ = crate::kats::initialize_module_unsigned_test_binary();
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
        assert_eq!(*seeds.to_plaintext(), seeds.mnemonic.to_phrase());
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
        assert_eq!(circles[0].entropy(), "correct horse battery staple");
        assert_eq!(circles[0].label, "Book Club");
        assert_eq!(circles[1].entropy(), "another shared secret phrase");
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
        assert!(seeds.add_published("/home/me/My Music", None));
        assert!(seeds.add_published("/srv/docs", None));
        assert!(
            !seeds.add_published("/home/me/My Music", None),
            "add_published is idempotent on the root"
        );
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let mut recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        let roots: Vec<&str> = recovered
            .published()
            .iter()
            .map(|p| p.root.as_str())
            .collect();
        assert_eq!(roots, ["/home/me/My Music", "/srv/docs"]);
        assert!(recovered.remove_published("/home/me/My Music"));
        assert!(!recovered.remove_published("/home/me/My Music"));
        let roots: Vec<&str> = recovered
            .published()
            .iter()
            .map(|p| p.root.as_str())
            .collect();
        assert_eq!(roots, ["/srv/docs"]);
    }

    #[test]
    fn published_share_name_round_trips_and_legacy_form_stays_none() {
        // Item-4 core oracle. A published share's optional wire-facing name must
        // survive a seal/open round-trip; an unnamed share must serialize in the
        // legacy one-field `publish <hex(root)>` form (additive — no blob-version
        // bump) and read back as `name = None` (the basename fallback at republish
        // lives in the net layer, unchanged).
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        assert!(seeds.add_published("/srv/holiday pics", Some("Summer 2026".to_owned())));
        assert!(seeds.add_published("/srv/docs", None));

        // The unnamed share serializes WITHOUT a second field (legacy-compatible);
        // the named share carries a hex name field.
        let plain = seeds.to_plaintext();
        assert!(
            plain.contains(&format!(
                "publish {}\n",
                hex::encode("/srv/docs".as_bytes())
            )) || plain.ends_with(&format!("publish {}", hex::encode("/srv/docs".as_bytes()))),
            "unnamed share must serialize as the one-field legacy form: {plain:?}"
        );
        assert!(
            plain.contains(&format!(
                "publish {} {}",
                hex::encode("/srv/holiday pics".as_bytes()),
                hex::encode("Summer 2026".as_bytes()),
            )),
            "named share must serialize root + name: {plain:?}"
        );

        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        let pubs = recovered.published();
        assert_eq!(pubs.len(), 2);
        assert_eq!(pubs[0].root, "/srv/holiday pics");
        assert_eq!(pubs[0].name.as_deref(), Some("Summer 2026"));
        assert_eq!(pubs[1].root, "/srv/docs");
        assert_eq!(pubs[1].name, None);
    }

    #[test]
    fn clear_announce_seen_removes_the_entry() {
        // #217: the rollback path in `Profile::persist_announce_seen` needs to restore
        // "no entry at all" — distinct from an empty marker, which would round-trip
        // through the blob as a real entry that covers nothing.
        ensure_oxicrypt_initialized();
        let mut seeds = fresh_seeds();
        assert!(
            !seeds.clear_announce_seen("fra1#06177b08dc06"),
            "nothing to clear"
        );
        assert!(seeds.set_announce_seen("fra1#06177b08dc06", "aaaa,bbbb"));
        assert!(seeds.clear_announce_seen("fra1#06177b08dc06"));
        assert_eq!(seeds.announce_seen("fra1#06177b08dc06"), None);
        assert!(
            !seeds.clear_announce_seen("fra1#06177b08dc06"),
            "idempotent"
        );
    }

    #[test]
    fn announce_seen_round_trips_through_blob() {
        // #93 oracle. A per-relay announcements/MOTD seen marker survives a
        // seal/open round-trip, the setter is idempotent on an unchanged value,
        // and whitespace/line-break inputs are refused (blob-integrity).
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        assert_eq!(seeds.announce_seen("fra1#06177b08dc06"), None);
        assert!(seeds.set_announce_seen("fra1#06177b08dc06", "deadbeefcafe"));
        // Idempotent: re-setting the same value reports no change.
        assert!(!seeds.set_announce_seen("fra1#06177b08dc06", "deadbeefcafe"));
        // A new value for the same relay overwrites.
        assert!(seeds.set_announce_seen("fra1#06177b08dc06", "00112233"));
        // A second relay is tracked independently.
        assert!(seeds.set_announce_seen("nyc1#aabbccdd0011", "feedface"));
        // Whitespace / line breaks in either token are rejected (would break the
        // single-line two-token directive).
        assert!(!seeds.set_announce_seen("srv#x", "bad hash"));
        assert!(!seeds.set_announce_seen("srv\n#x", "abcd"));

        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(
            recovered.announce_seen("fra1#06177b08dc06"),
            Some("00112233")
        );
        assert_eq!(
            recovered.announce_seen("nyc1#aabbccdd0011"),
            Some("feedface")
        );
        assert_eq!(recovered.announce_seen("unknown#relay"), None);
    }

    /// The `circle_seen` map key renders a redacted `Debug`.
    ///
    /// `CircleSeenKey`'s `Debug` is hand-written, and this is what stops it being
    /// "simplified" back to a derive. The failure that would cause is total:
    /// `Zeroizing` derives `Debug` and forwards to the inner value, so a derived
    /// `Debug` on the newtype prints the circle phrase — the `cot_key` IKM (ISC-C8)
    /// — into every log line and panic message that formats a key.
    ///
    /// Exact-string equality plus an explicit control that the phrase is absent,
    /// matching the house pattern in `secret_seed.rs`: a substring check for
    /// `<redacted>` alone would pass on `CircleSeenKey(<redacted>, "correct …")`.
    #[test]
    fn circle_seen_key_renders_a_redacted_debug() {
        const PHRASE: &str = "correct horse battery staple";
        let key = CircleSeenKey::new(Zeroizing::new(PHRASE.to_owned()));

        let rendered = format!("{key:?}");
        assert_eq!(rendered, "CircleSeenKey(<redacted>)");
        assert!(
            !rendered.contains(PHRASE),
            "the map key's Debug leaks the circle phrase: {rendered}"
        );
    }

    /// The key orders and compares by its phrase, which is what `Borrow<str>`
    /// requires and what the `&str` lookup on [`Seeds::circle_seen`] relies on.
    ///
    /// `Borrow`'s contract is that the borrowed and owned forms agree on `Eq` and
    /// `Ord`. Nothing enforces that at compile time, so a hand-written `Ord` that
    /// drifted — comparing by length, say — would leave every lookup silently
    /// missing while the whole suite stayed green. This is the assertion that
    /// fails instead.
    #[test]
    fn circle_seen_key_orders_and_borrows_as_its_phrase() {
        fn key(s: &str) -> CircleSeenKey {
            CircleSeenKey::new(Zeroizing::new(s.to_owned()))
        }

        // Every pair that must agree with `str`'s own ordering, chosen so that no
        // single shortcut survives all of them. `alpha`/`alphax` share a prefix
        // and differ only past byte 4, which is what kills a first-byte compare;
        // `Alpha`/`alpha` differ only in case, which kills a case-folding one;
        // `alphabet`/`beta` is longer-but-earlier, which kills a length compare.
        let pairs = [
            ("alpha", "beta"),
            ("alpha", "alphax"),
            ("alphax", "alpha"),
            ("Alpha", "alpha"),
            ("alphabet", "beta"),
            ("alpha", "alpha"),
            ("", "alpha"),
        ];
        for (l, r) in pairs {
            assert_eq!(
                key(l).cmp(&key(r)),
                l.cmp(r),
                "ordering of {l:?} vs {r:?} disagrees with str"
            );
            // `Borrow`'s actual contract: `Eq` and `Ord` must agree. `PartialEq` is
            // derived through `Zeroizing` while `Ord` is hand-written, so nothing
            // but this assertion holds the two together.
            assert_eq!(
                key(l).cmp(&key(r)) == core::cmp::Ordering::Equal,
                key(l) == key(r),
                "Eq and Ord disagree on {l:?} vs {r:?}, which breaks Borrow<str>"
            );
        }

        // The `Borrow` view is the same string the `Ord` compares.
        assert_eq!(
            <CircleSeenKey as Borrow<str>>::borrow(&key("alpha")),
            "alpha"
        );

        // And the property that actually matters, exercised through the real map:
        // two prefix-sharing keys must be distinct entries, each retrievable by
        // `&str`. A first-byte or case-folding `Ord` collides them here.
        let mut seeds = Seeds::new(Mnemonic::generate().unwrap());
        assert!(seeds.set_circle_seen("alpha", 1));
        assert!(seeds.set_circle_seen("alphax", 2));
        assert!(seeds.set_circle_seen("Alpha", 3));
        assert_eq!(seeds.circle_seen("alpha"), Some(1));
        assert_eq!(seeds.circle_seen("alphax"), Some(2));
        assert_eq!(seeds.circle_seen("Alpha"), Some(3));
        assert_eq!(seeds.circle_seen("alph"), None);
    }

    #[test]
    fn circle_seen_round_trips_and_is_monotonic() {
        // #107 oracle. A per-circle read high-water (keyed by entropy — a phrase
        // WITH SPACES, so the directive hex-encodes it) survives a seal/open
        // round-trip, the setter only advances forward, and an absent line parses
        // to an empty map (additive / backward-compatible).
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let mut seeds = fresh_seeds();
        let entropy = "correct horse battery staple"; // a phrase with spaces
        assert_eq!(seeds.circle_seen(entropy), None);
        assert!(seeds.set_circle_seen(entropy, 100));
        // Monotonic: an equal or older write does not lower the mark.
        assert!(!seeds.set_circle_seen(entropy, 100));
        assert!(!seeds.set_circle_seen(entropy, 50));
        // A newer write advances it.
        assert!(seeds.set_circle_seen(entropy, 150));
        // A second circle is tracked independently.
        assert!(seeds.set_circle_seen("another circle phrase here", 7));

        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.circle_seen(entropy), Some(150));
        assert_eq!(recovered.circle_seen("another circle phrase here"), Some(7));
        assert_eq!(recovered.circle_seen("never seen"), None);
    }

    #[test]
    fn absent_circle_seen_directive_parses_empty() {
        // A blob with no `circle-seen` line parses with an empty map — additive.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        assert!(!seeds.to_plaintext().contains("circle-seen"));
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.circle_seen("anything"), None);
    }

    #[test]
    fn absent_announce_seen_directive_parses_empty() {
        // A blob with no `announce-seen` line (the legacy / typical form) parses
        // with an empty map — the directive is additive and backward-compatible.
        ensure_oxicrypt_initialized();
        let pid = Uuid::new_v4();
        let pp = "correct horse battery staple table mountain";
        let seeds = fresh_seeds();
        assert!(!seeds.to_plaintext().contains("announce-seen"));
        let blob = seal(&seeds, pp, pid, test_params()).unwrap();
        let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
        assert_eq!(recovered.announce_seen("anything"), None);
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
        assert_eq!(seeds.circles()[0].entropy(), "phrase b");
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

    /// A `Seeds` carrying at least one of every line kind `to_plaintext` writes.
    ///
    /// Exercising every kind is what makes the reservation tests mean anything: a
    /// capacity term can only be caught missing by a payload that contains the line
    /// it was supposed to size. Two of each, and values with awkward shapes
    /// (spaces, a `None` label, an unnamed publish, a negative timestamp), because
    /// the hex-encoded fields double in length and the legacy `publish` form takes
    /// a different branch.
    fn seeds_with_every_line_kind() -> Seeds {
        let mut seeds = fresh_seeds();
        seeds.counters.next_send();
        seeds.counters.record_seen("alpha#aabbccddeeff", u64::MAX);
        seeds.counters.record_seen("beta#001122334455", 7);
        seeds.add_mute("two words#aabbccddeeff");
        seeds.add_mute("gamma#665544332211");
        seeds.add_hidden_share("delta#001122334455");
        seeds.add_hidden_share("epsilon#ffeeddccbbaa");
        seeds.set_display_name(Some("A Display Name".to_owned()));
        seeds.add_circle("correct horse battery staple", "Book Club");
        seeds.add_circle("another shared secret phrase", "Ops Room");
        seeds.add_share("/srv/holiday pics", Some("Summer 2026".to_owned()));
        seeds.add_share("/srv/docs", None);
        seeds.add_published("/srv/holiday pics", Some("Summer 2026".to_owned()));
        seeds.add_published("/srv/docs", None);
        assert!(seeds.set_announce_seen("relay-one", "marker-one"));
        assert!(seeds.set_announce_seen("relay-two", "marker-two"));
        seeds.set_circle_seen("correct horse battery staple", i64::MAX);
        seeds.set_circle_seen("another shared secret phrase", -1);
        seeds
    }

    /// The payload buffer is reserved once and never grows (#263).
    ///
    /// The property is that the secret is assembled in ONE allocation, so no freed
    /// block is left holding a partial copy of it. Two independent halves:
    ///
    /// - `to_plaintext`'s own `debug_assert` compares the buffer's address before
    ///   and after assembly, so it fires on any reallocation. Removing the
    ///   `String::with_capacity` reservation, or under-counting a term in
    ///   `plaintext_capacity`, makes this test panic there.
    /// - the returned buffer's capacity is still the reserved one, asserted here.
    ///   This is the half that survives a release build, where `debug_assert` is
    ///   compiled out — verified by running this test under `--release` against a
    ///   build with the reservation removed, where it fails on `left: 1024` (a
    ///   grown buffer) against `right: 1057` (the reservation).
    ///
    /// Both halves need a payload that actually contains every line kind, which is
    /// what `seeds_with_every_line_kind` is for — a fresh `Seeds` serializes to the
    /// bare phrase and would exercise one term out of ten.
    ///
    /// What this does NOT assert: that no allocation happens anywhere during the
    /// call. It asserts that the buffer holding the secret is not among them.
    #[test]
    fn to_plaintext_reserves_once_and_never_reallocates() {
        let seeds = seeds_with_every_line_kind();
        let cap = seeds.plaintext_capacity();
        let plain = seeds.to_plaintext();

        // Control. If the payload were the bare phrase — or empty — the capacity
        // assertions below would hold while proving nothing about the line kinds.
        assert!(
            plain.len() > MAX_PHRASE_LEN,
            "the payload is no longer than a bare phrase, so no directive line was \
             written and this test proves nothing: {} bytes",
            plain.len()
        );
        for prefix in [
            line::SEND_COUNTER,
            line::SEEN,
            line::MUTE,
            line::HIDE,
            line::NAME,
            line::CIRCLE,
            line::SHARE,
            line::PUBLISH,
            line::ANNOUNCE_SEEN,
            line::CIRCLE_SEEN,
        ] {
            assert!(
                plain.contains(prefix),
                "no {prefix:?} line in the payload, so its capacity term is untested"
            );
        }

        assert!(
            plain.len() <= cap,
            "payload of {} bytes overran the {cap}-byte reservation",
            plain.len()
        );
        assert_eq!(
            plain.capacity(),
            cap,
            "the payload buffer is not the one that was reserved — it either grew \
             or was never reserved (#263)"
        );
    }

    /// The reservation is an upper bound with real slack, not an accident of the
    /// values this suite happens to use.
    ///
    /// `to_plaintext_reserves_once_and_never_reallocates` would still pass if
    /// `plaintext_capacity` returned exactly the payload length by luck. This pins
    /// the intent: integers are sized at their widest form and the mnemonic at
    /// `MAX_PHRASE_LEN`, so the bound sits above the payload rather than on it.
    #[test]
    fn plaintext_capacity_is_an_upper_bound_not_an_exact_length() {
        let seeds = seeds_with_every_line_kind();
        let cap = seeds.plaintext_capacity();
        let len = seeds.to_plaintext().len();

        assert!(len < cap, "capacity {cap} is not above the payload {len}");
        // And not absurdly above it — a bound that over-reserved by kilobytes per
        // circle would pass the line above while wasting the buffer.
        assert!(
            cap - len < 512,
            "capacity {cap} overshoots the payload {len} by {} bytes",
            cap - len
        );
    }

    /// `push_hex` is byte-identical to `hex::encode`, which is what lets
    /// `from_plaintext`'s `hex::decode` keep reading what it writes (#263).
    ///
    /// Round-trip tests elsewhere would catch a mismatch, but only through a seal
    /// and an open; this states the property directly and fails at the one line
    /// that is wrong. The empty input matters — an unlabelled share serializes as
    /// empty hex.
    #[test]
    fn push_hex_matches_hex_encode() {
        for input in [
            b"".as_slice(),
            b"\x00".as_slice(),
            b"\xff".as_slice(),
            b"correct horse battery staple".as_slice(),
            b"\x00\x01\x0f\x10\x7f\x80\xfe\xff".as_slice(),
        ] {
            let mut out = String::new();
            push_hex(&mut out, input);
            assert_eq!(out, hex::encode(input), "diverged on {input:?}");
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

    /// `PersistedCircle`'s `Debug` is hand-written, so pin the exact rendering the
    /// way `circle::key::CircleKey` and `dm::ack` pin theirs. `debug_redacts_seeds`
    /// above does not reach here: `Debug for Seeds` prints only a circle COUNT, so
    /// it would stay green if this rendering leaked the phrase.
    #[test]
    fn debug_redacts_persisted_circle_entropy_and_keeps_the_label() {
        let c = PersistedCircle::new("correct horse battery staple".to_string(), "Book Club");
        let dbg = format!("{c:?}");
        assert_eq!(
            dbg,
            r#"PersistedCircle { entropy: "<redacted>", label: "Book Club" }"#
        );
        assert!(
            !dbg.contains("correct horse"),
            "the circle phrase reached a Debug surface: {dbg}"
        );
        assert!(
            dbg.contains("Book Club"),
            "the label is not a secret: {dbg}"
        );
    }

    /// `Seeds` derives `Clone` and is cloned on the TUI's session-adopt path, so a
    /// clone that dropped or blanked `entropy` would silently blank every circle
    /// secret in the held copy — compiling, and invisible to every other test.
    /// `PersistedCircle`'s `Clone` is derived (over a `Zeroizing<String>` field,
    /// which is itself `Clone`) precisely so that slip is unavailable; this holds
    /// the behaviour regardless of how the impl is spelled.
    #[test]
    fn cloning_a_persisted_circle_preserves_both_fields() {
        let c = PersistedCircle::new("correct horse battery staple".to_string(), "Book Club");
        let copy = c.clone();
        assert_eq!(copy.entropy(), "correct horse battery staple");
        assert_eq!(copy.label, "Book Club");
        // Independent storage, so the clone's own wipe cannot reach the original.
        assert_ne!(
            copy.entropy().as_ptr(),
            c.entropy().as_ptr(),
            "the clone shares the original's buffer"
        );
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
