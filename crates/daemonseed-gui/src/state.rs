//! Plain-Rust, RAM-only per-circle state layer (round 2 + round 4).
//!
//! No `slint` import: this module is the in-memory model of the GUI's circles and
//! their per-circle scroll/draft state, kept Slint-free so it is unit-testable in
//! isolation. Each circle remembers its own half-typed draft and scroll position
//! across rail switches; everything resets on relaunch (no persistence).
//!
//! **Round 4 adds the net contract.** A circle can now be *materialized at
//! runtime* from a shared phrase (join / new-circle flows), and a materialized
//! circle carries the [`CircleNet`] contract — the originating phrase, its derived
//! [`CircleKey`] (`daemonseed_core::circle::key::derive_cot_key`), and a rendezvous
//! slot — so Round 5's circle networking plugs in without reworking this layer.
//! This is why the module now depends on `daemonseed-core` (it did not in round 2);
//! it stays Slint-free and network-free. Materialized circles are RAM-only and
//! gone on relaunch — config persistence is a separate milestone.

use daemonseed_core::circle::key::{CircleKey, CircleKeyError, circle_fingerprint, derive_cot_key};
use daemonseed_core::cot::AssetAddr;
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::{ShareRootIkm, SignKeypair};

use crate::net::RosterEntry;
use daemonseed_core::passphrase::strength::{self, DicewareError};

use crate::profile::Profile;

/// Generate a circle phrase that clears the SAME `is_circle_green` floor the join
/// gate enforces (D3). Thin delegate to the canonical home,
/// [`daemonseed_core::passphrase::strength::generate_circle_phrase`] — the
/// rejection-sampling loop (which keeps a generated phrase from ever scoring below the
/// floor on a duplicate-word draw) lives in core so the GUI and the TUI share one
/// implementation rather than each carrying a copy that can drift.
pub fn generate_circle_phrase() -> Result<String, DicewareError> {
    strength::generate_circle_phrase()
}

// ── Announcements + MOTD display model (#91) ─────────────────────────────────

/// One verified announcement row for the GUI announcements pane (#91 / ISC-S7).
/// Built from a served `wire::Post` that PASSED client re-verification
/// against the published signer whitelist (`verify_served_post`); an
/// unverifiable post never becomes a row. The fields are the inert
/// `post_render_fields` decode — `topic`/`body` render verbatim, `sent_unix_ms`
/// is the signer's advisory signing wall-clock (ISC-S7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnouncementRow {
    pub topic: String,
    pub body: String,
    pub sent_unix_ms: i64,
}

/// The verified display model for the announcements/MOTD pane (#91). `motd` is the
/// connected relay's inert verbatim MOTD ([`daemonseed_cli::public_space::render_motd`]) and is `None` both when
/// the relay serves no MOTD AND when a served MOTD fails re-verification (display
/// only what verifies, ISC-A-S3). `posts` are the verified announcement rows, in
/// served order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnouncementsView {
    pub motd: Option<String>,
    pub posts: Vec<AnnouncementRow>,
}

// ── Unread-gated landing (#93 / D5) ──────────────────────────────────────────

/// Domain-separation prefix for the #93 combined content hash. Bump the tag on
/// any change to the canonical encoding in [`combined_content_hash`].
const ANNOUNCE_HASH_DOMAIN: &[u8] = b"daemonseed/announce-hash/v1\0";

/// Compute the single combined content hash of a verified announcements/MOTD
/// view (#93) — the client-derived unread marker.
///
/// Deterministic and server-order-independent: the MOTD (the empty string when
/// `None`) and the posts in a **canonical sort order** (`(topic, sent_unix_ms,
/// body)`) are folded into a length-prefixed, domain-separated buffer so no field
/// concatenation is ambiguous, then hashed with SHA-384
/// ([`content_address`](daemonseed_core::public_space::content_address)) and
/// rendered as lowercase hex. Identical content ⇒ identical hash; any change — a
/// MOTD edit, a post added / removed / edited — ⇒ a different hash; a reorder of
/// the relay's served posts ⇒ the **same** hash. The value is a stable,
/// collision-resistant local marker only, never a wire artifact: it is compared
/// solely to the per-relay marker persisted in
/// [`Seeds`](daemonseed_core::storage::seeds::Seeds).
pub fn combined_content_hash(view: &AnnouncementsView) -> String {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(ANNOUNCE_HASH_DOMAIN);

    // MOTD: length-prefixed so an empty MOTD and an empty first post can't alias.
    let motd = view.motd.as_deref().unwrap_or("");
    buf.extend_from_slice(&(motd.len() as u64).to_le_bytes());
    buf.extend_from_slice(motd.as_bytes());

    // Posts in canonical order: the relay's served order must not change the hash.
    let mut rows: Vec<&AnnouncementRow> = view.posts.iter().collect();
    rows.sort_by(|a, b| {
        a.topic
            .cmp(&b.topic)
            .then(a.sent_unix_ms.cmp(&b.sent_unix_ms))
            .then(a.body.cmp(&b.body))
    });
    buf.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    for r in rows {
        buf.extend_from_slice(&(r.topic.len() as u64).to_le_bytes());
        buf.extend_from_slice(r.topic.as_bytes());
        buf.extend_from_slice(&r.sent_unix_ms.to_le_bytes());
        buf.extend_from_slice(&(r.body.len() as u64).to_le_bytes());
        buf.extend_from_slice(r.body.as_bytes());
    }

    // `content_address` = SHA-384(buf); its `Display` is lowercase hex. The only
    // error path is SHA-384's power-up self-test not having passed yet (the first
    // crypto call in a fresh process) — unreachable once the client has initialized
    // oxicrypt at startup. The empty fallback only appears pre-init and never
    // collides with a real digest in practice.
    daemonseed_core::public_space::content_address(&buf)
        .map(|a| a.to_string())
        .unwrap_or_default()
}

/// #142: whether the Announcements tab should show an unread dot — the verified content
/// is non-empty AND `current_hash` (the caller's `combined_content_hash(view)`) differs
/// from what was last seen (or was never seen). The caller passes the current hash in so
/// it is computed once per snapshot (it also needs it for the seen-hash persist). The
/// empty-view guard means an unconverged / genuinely-empty view never trips a spurious
/// dot. Replaces the #93 connect-time auto-landing: the client NEVER force-opens the
/// pane (a rude yank for rare operator content, and it could land on a not-yet-converged
/// blank view); the dot is a non-intrusive indicator that behaves identically on connect
/// and mid-session, mirroring the room unread dot (#64).
pub fn announcements_unread(
    view: &AnnouncementsView,
    current_hash: &str,
    stored_hash: Option<&str>,
) -> bool {
    if view.motd.is_none() && view.posts.is_empty() {
        return false; // empty-view guard — nothing to be unread about
    }
    match stored_hash {
        Some(h) => h != current_hash,
        None => true, // never seen → unread
    }
}

/// One chat message in a circle's stub transcript.
#[derive(Clone, Debug)]
pub struct Msg {
    pub who: String,
    pub text: String,
    pub mine: bool,
    /// Best-effort sender wall-clock (ms since epoch). DEDUP + display key. Untrusted
    /// on the open lobby, so it is NOT used directly for ordering — see `order_ms`.
    pub sent_unix_ms: i64,
    /// The ORDERING + high-water key: `sent_unix_ms` clamped to the trust window
    /// (`transcript::clamp_order_ms`) ONCE at insert time (#131). Stored (not
    /// recomputed) so the transcript stays a stably-sorted Vec — a forged future
    /// stamp that later re-enters the window as the clock advances cannot silently
    /// re-sort past inserts and corrupt `partition_point`. In-window traffic has
    /// `order_ms == sent_unix_ms`, so honest ordering is exact.
    pub order_ms: i64,
}

/// Outcome of [`GuiState::push_message`]: two orthogonal facts about what happened to
/// the transcript, so a caller can react precisely. `inserted` gates re-render + scroll
/// — a deduped no-op must NOT disturb the reader's scroll position (#143 scroll-yank);
/// `unread_raised` gates the background rail rebuild (#64). `unread_raised` always
/// implies `inserted` (a deduped message returns before the dot logic).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PushOutcome {
    /// A new line was inserted (i.e. NOT a dedup no-op).
    pub inserted: bool,
    /// This call newly raised the unread dot: a non-own message, into a non-active room,
    /// newer than the read high-water.
    pub unread_raised: bool,
}

/// Wall-clock now in unix milliseconds — the reference for the #131 transcript
/// ordering clamp (`transcript::clamp_order_ms`). Falls back to 0 only if the system
/// clock predates the epoch (never in practice).
fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Format a message's age (its `sent_unix_ms`) relative to `now_ms` as a short
/// transcript label: "just now", "2m ago", "3h ago", "sitting 3 days". Pure +
/// clock-injected (both args passed) so it is deterministically unit-testable.
/// Especially valuable for a Veilid bounded-backlog message that is genuinely old
/// — a swept days-old line must read as stale, not live (#100). A future timestamp
/// (peers have no shared clock) reads as "just now" rather than a negative age.
///
/// The transcript-row render consumes this via `messages_model` (#100): each rebuild
/// recomputes the label against the current wall-clock, and a ~30s repaint tick
/// rebuilds the active circle's model so ages advance without a new message.
pub(crate) fn format_relative_age(sent_unix_ms: i64, now_ms: i64) -> String {
    let age_ms = now_ms.saturating_sub(sent_unix_ms);
    // Under a minute (including a future timestamp from clock skew) → "just now".
    if age_ms < 60_000 {
        return "just now".to_owned();
    }
    let mins = age_ms / 60_000;
    if mins < 60 {
        return format!("{mins}m ago");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h ago");
    }
    let days = hours / 24;
    if days == 1 {
        "sitting 1 day".to_owned()
    } else {
        format!("sitting {days} days")
    }
}

/// A share you published this session — one entry in the Publish overlay's "Your
/// live shares" list (each removable via Unpublish). The `root` directory path is
/// the M16 persistence key: it is remembered in the profile blob so the share
/// auto-republishes next launch, and it is the key Unpublish forgets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyShare {
    /// Server-assigned opaque share id — the Unpublish key, set on `PublishStarted`.
    pub id: String,
    /// The share's display name (a user-chosen name, else the folder basename).
    pub name: String,
    /// File count from the published manifest.
    pub files: usize,
    /// The published directory path — the M16 persistence key (so Unpublish can
    /// forget the right persisted root). Carried back on `PublishStarted`.
    pub root: String,
    /// #117: true while a (re)publish is in flight (the slow Veilid serve+advert
    /// window) — drives the per-share "republishing…" tag. Cleared to `false` when the
    /// share confirms live (the second `PublishStarted`).
    pub republishing: bool,
}

/// The Round-5 **net contract** carried by a materialized circle (refinement #1).
///
/// Holding the phrase + derived [`CircleKey`] + a rendezvous slot here is the single
/// most important thing Round 4 gets right: Round 5's `NetCommand::JoinCircle`
/// takes the phrase (the net actor derives its own key, mirroring the public-room
/// name path), and seal/open needs the `cot_key` + `rendezvous` — so the net path
/// plugs into an already-materialized circle with no rework.
///
/// `Debug` is hand-rolled to REDACT the phrase (the circle's whole secret) and
/// defer to [`CircleKey`]'s own redacted `Debug` — neither ever lands on a log
/// surface (mirrors the `CircleKey` / circle-key hygiene, ISC-A-C1).
pub struct CircleNet {
    /// Stable per-session id assigned at materialize. The GUI's routing key:
    /// passed to `NetCommand::JoinCircle`/`SendCircle` and echoed back on
    /// `NetEvent::CircleMessage` so an inbound frame lands in the right circle's
    /// RAM state. The GUI owns circle identity, so it assigns the id (the actor
    /// uses it only as an opaque tag) — unlike the TUI, where the actor hands it out.
    pub circle_id: u64,
    /// The originating shared phrase. RAM-only secret (like the TUI's
    /// `pending_join`); handed to `NetCommand::JoinCircle{phrase}` so the actor
    /// re-derives the same key (Round-5 circle net path).
    pub phrase: String,
    /// The derived circle-of-trust key. The net contract's keystone — proves the
    /// phrase derives now, so Round 5's seal/open reuses it directly.
    pub cot_key: CircleKey,
    /// The circle's rendezvous address on a connected relay. `None` pre-net —
    /// Round 5 fills it (`daemonseed_core::cot::asset_address(cot_key, server_id)`)
    /// once a relay/server-id is in hand.
    pub rendezvous: Option<AssetAddr>,
}

impl core::fmt::Debug for CircleNet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CircleNet")
            .field("phrase", &"<redacted>")
            .field("cot_key", &self.cot_key)
            .field("rendezvous", &self.rendezvous.is_some())
            .finish()
    }
}

/// A single circle and its retained, per-circle UI state.
///
/// **No longer `Clone`** (round 4): it now holds a [`CircleNet`] whose [`CircleKey`]
/// is a zeroizing secret that must not be silently copied. The render path borrows
/// `&CircleState` and applies it; it never clones.
#[derive(Debug)]
pub struct CircleState {
    pub name: String,
    pub sub: String,
    pub initial: String,
    pub pinned: bool,
    pub header_sub: String,
    pub messages: Vec<Msg>,
    /// Half-typed composer text, retained across switches (reset on relaunch).
    pub draft: String,
    /// Flickable `viewport-y` for this circle. NEGATIVE when scrolled down
    /// (Slint sign convention); retained across switches.
    pub scroll_y: f32,
    /// The net contract — `Some` for a materialized circle, `None` for the public
    /// Lobby (which derives its room key from the room name, not a phrase). Round 5
    /// reads it to drive `JoinCircle`/`SendCircle` and to route inbound frames.
    pub net: Option<CircleNet>,
    /// #64: client-side unread (new-message) dot. Set when a non-own message lands
    /// in this room while it is NOT the active room; cleared the moment it gains
    /// focus. Chat-only (driven by `push_message`); shares ride a separate path.
    pub unread: bool,
    /// #107: per-circle read high-water mark — the newest `sent_unix_ms` the user
    /// has already seen in this room (advanced when the room is active and when it
    /// gains focus). A message at or below it is BACKLOG the user already caught up
    /// on, so it never re-trips the unread dot — the login/reconnect ring sweep
    /// re-delivers old messages into a RAM transcript that may be fresh (relaunch)
    /// or already-pruned, so the exact-match dedup alone can't suppress them.
    /// RAM-only like the transcript; a first-ever load this session may still trip
    /// once (genuinely new to the session), but a reconnect after catching up will
    /// not. Lobby keeps it at 0 (the public room has no per-circle dot semantics).
    pub high_water_ms: i64,
    /// Option A HERE-NOW cache (#77 follow-up): the last roster the net layer surfaced
    /// for THIS room. `NetEvent::Roster` folds every room's roster here — active or not —
    /// so a rail switch repaints the people column from the destination's snapshot
    /// immediately. A beacon repaint only fires on a content change for the *active*
    /// room, so a switch alone never updated the pane. Plain data (a `net` domain type,
    /// no live-networking coupling); RAM-only like the rest of this layer.
    pub roster: Vec<RosterEntry>,
}

/// First circle id handed out (0 is reserved/unused so a missing id is obvious).
const FIRST_CIRCLE_ID: u64 = 1;

/// The whole GUI state: the circles, which one is active, and — round 6 — the
/// unlocked [`Profile`] (when present) that persists circle membership + the
/// display handle across relaunches. The circles/draft/scroll layer stays RAM-only
/// (no message history is ever persisted); only the at-rest settings payload the
/// `Profile` owns survives.
pub struct GuiState {
    circles: Vec<CircleState>,
    active: usize,
    /// Monotonic source of per-circle ids handed out at materialize; never reused
    /// within a session, so an id always names the same circle (the net routing key).
    next_circle_id: u64,
    /// The unlocked profile, once first-start / Unlock produces it. `None` on the
    /// ephemeral path (shell works; nothing survives relaunch).
    profile: Option<Profile>,
    /// Shares published this session (commit 3), keyed off `PublishStarted` /
    /// `PublishStopped`. Drives the Publish overlay's "Your live shares" list and the
    /// Unpublish affordance. RAM-only; cleared on relaunch.
    my_shares: Vec<MyShare>,
}

impl GuiState {
    /// The binary's seed (round 4): **Lobby only.** Per the design brief's
    /// empty-state lean — the rail starts with just the pinned, real public Lobby
    /// (rail index 0, the round-3 networked room); circles are then *materialized*
    /// by the user via the join / new-circle flows. No fake demo circles: a mute
    /// placeholder circle would muddy the felt-test. The Lobby's transcript fills
    /// from the relay at runtime (empty until connected).
    pub fn lobby_only() -> GuiState {
        let circles = vec![CircleState {
            name: "Lobby".into(),
            sub: "public lobby · amazon-fra1".into(),
            initial: "L".into(),
            pinned: true,
            header_sub: "public lobby · open · amazon-fra1".into(),
            messages: Vec::new(),
            draft: String::new(),
            scroll_y: 0.0,
            net: None,
            unread: false,
            high_water_ms: 0,
            roster: Vec::new(),
        }];
        GuiState {
            circles,
            active: 0,
            next_circle_id: FIRST_CIRCLE_ID,
            profile: None,
            my_shares: Vec::new(),
        }
    }

    /// Adopt an unlocked [`Profile`] (round 6) and restore its persisted circles
    /// into the rail. Each stored phrase is re-materialized (a fresh per-session
    /// `circle_id`, the key re-derived — never a persisted key); a stored phrase
    /// that no longer derives is skipped so one bad entry can't block startup.
    /// Restoration does NOT re-persist (the circles are already in the blob).
    /// Call once, right after auth succeeds, before [`GuiState::persisted_rejoins`].
    pub fn set_profile(&mut self, profile: Profile) {
        for (phrase, _label) in profile.circles() {
            if let Ok(idx) = self.materialize_from_phrase(&phrase) {
                // #107: seed the circle's read high-water from the blob so a relaunch's
                // backlog re-delivery does NOT re-trip the unread dot for already-seen
                // messages (a genuinely newer message still does). `circle_seen` is
                // keyed by the same canonicalized entropy `profile.circles()` returns.
                if let Some(ms) = profile.circle_seen(&phrase)
                    && let Some(c) = self.circles.get_mut(idx)
                {
                    c.high_water_ms = ms;
                }
            }
        }
        self.profile = Some(profile);
    }

    /// #107: persist every circle's current read high-water into the profile blob.
    /// Called on graceful close (the common restart path) so a relaunch seeds each
    /// circle's mark and does not re-trip the unread dot for already-seen messages.
    /// Best-effort + monotonic: a circle with no net contract (the Lobby) or no
    /// profile is skipped, and a re-seal failure is swallowed (the mark is
    /// non-critical — a miss only re-trips the dot once after a restart).
    // Driven by the desktop windowed close handler; the base offscreen build never
    // builds that path, so the method reads as dead there (the tests still use it).
    #[cfg_attr(not(feature = "desktop"), allow(dead_code))]
    pub fn persist_all_circle_seen(&mut self) {
        let marks: Vec<(String, i64)> = self
            .circles
            .iter()
            .filter_map(|c| c.net.as_ref().map(|n| (n.phrase.clone(), c.high_water_ms)))
            .filter(|(_, ms)| *ms > 0)
            .collect();
        if let Some(p) = self.profile.as_mut() {
            for (entropy, ms) in marks {
                let _ = p.persist_circle_seen(&entropy, ms);
            }
        }
    }

    /// The unlocked profile's stable display handle, or `None` on the ephemeral
    /// path. Passed to `NetCommand::Connect` so the user presents under it.
    pub fn display_handle(&self) -> Option<String> {
        self.profile.as_ref().map(|p| p.display_handle().to_owned())
    }

    /// (download-subsystem redesign, step 8b / DL-ISC-20) The unlocked profile's
    /// on-disk ROOT (the client's own trusted state dir), or `None` on the ephemeral
    /// path. Passed to `NetCommand::Connect` so the net actor anchors each fetch's
    /// confirmed-manifest digest there for verified resume.
    pub fn profile_root(&self) -> Option<std::path::PathBuf> {
        self.profile.as_ref().map(|p| p.root().to_path_buf())
    }

    /// (#92) The unlocked profile's STABLE persistent identity signing key
    /// (`Profile::stable_signing_key`), or `None` on the ephemeral / no-profile
    /// path or if derivation fails. Passed to `NetCommand::Connect` so the net
    /// actor can gate the composer and sign MOTD/announcements under the persistent
    /// identity (the key behind the whitelisted `name#hash` handle), NOT the
    /// ephemeral connection key. Derived once here per connect.
    pub fn stable_signing_key(&self) -> Option<SignKeypair> {
        self.profile
            .as_ref()
            .and_then(|p| p.stable_signing_key().ok())
    }

    /// (#156) The unlocked profile's share-root IKM
    /// (`Profile::stable_share_root_ikm`), or `None` on the ephemeral / no-profile
    /// path or if derivation fails. Passed to `NetCommand::Connect` so the net
    /// actor derives a receiver-verifiable `share_id` for any published share.
    /// Derived once here per connect (same derivation as the signing key).
    pub fn stable_share_root_ikm(&self) -> Option<ShareRootIkm> {
        self.profile
            .as_ref()
            .and_then(|p| p.stable_share_root_ikm().ok())
    }

    /// (#93) The per-relay last-seen announcements/MOTD content hash for
    /// `server_id`, read from the unlocked profile's blob. `None` on the ephemeral
    /// (no-profile) path or when this relay has never been marked seen. Returns an
    /// owned `String` so the caller does not hold a borrow across the subsequent
    /// `persist_announce_seen` write-through.
    pub fn announce_seen_hash(&self, server_id: &str) -> Option<String> {
        self.profile
            .as_ref()
            .and_then(|p| p.announce_seen(server_id).map(str::to_owned))
    }

    /// (#93) Write-through: record `hash` as the last-seen announcements/MOTD
    /// content hash for `server_id` and re-seal the blob, so the unread gate
    /// bypasses this exact content next connect. A no-op (`Ok`) on the ephemeral
    /// (no-profile) path or when the value is unchanged; a disk / seal failure is
    /// surfaced as `Err(reason)`.
    pub fn persist_announce_seen(&mut self, server_id: &str, hash: &str) -> Result<(), String> {
        match self.profile.as_mut() {
            Some(p) => p.persist_announce_seen(server_id, hash).map(|_| ()),
            None => Ok(()),
        }
    }

    /// #66: rename the unlocked identity — set a new display name and re-seal the
    /// at-rest blob (write-through) so it persists across unlock; also the recovery
    /// path for a profile created nameless before #65. Returns the new display
    /// handle, or `Err` for an invalid name, no unlocked profile, or a disk-seal
    /// failure. The cryptographic identity (handle hash) is unchanged. Driven by the
    /// Ctrl-K "Rename identity" command-palette entry (`on_submit_rename`), which
    /// validates the name and pushes the new handle to the net actor for a live
    /// update; the core path is also exercised by the `rename_identity_*` unit tests.
    pub fn rename_identity(&mut self, new_name: &str) -> Result<String, String> {
        match self.profile.as_mut() {
            Some(p) => p.rename(new_name).map(str::to_owned),
            None => Err("no unlocked profile to rename".into()),
        }
    }

    /// Record a share that just started serving this session (commit 3, on
    /// `PublishStarted`). Replaces any existing entry with the same id so a relay
    /// re-list can't double it. `republishing` (#117) flags an in-flight (re)publish —
    /// the same id is re-pushed with `false` once it confirms live.
    pub fn add_my_share(
        &mut self,
        id: String,
        name: String,
        files: usize,
        root: String,
        republishing: bool,
    ) {
        self.my_shares.retain(|s| s.id != id);
        self.my_shares.push(MyShare {
            id,
            name,
            files,
            root,
            republishing,
        });
    }

    /// Drop a share that stopped serving (on `PublishStopped` — Unpublish, session
    /// end, or relay reap). Returns the dropped share's `root` directory path so the
    /// caller can forget it from the M16 persistence set; `None` if it was already
    /// gone.
    pub fn remove_my_share(&mut self, id: &str) -> Option<String> {
        let root = self
            .my_shares
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.root.clone());
        self.my_shares.retain(|s| s.id != id);
        root
    }

    /// The persisted published shares the net actor must silently re-publish on
    /// connect — `(root, optional wire-facing name)` read from the unlocked profile
    /// blob. The republish path uses the name when present, else the root basename.
    /// Empty on the no-profile (ephemeral) path.
    pub fn persisted_published(&self) -> Vec<(String, Option<String>)> {
        self.profile
            .as_ref()
            .map(Profile::published)
            .unwrap_or_default()
    }

    /// Write-through (M16): remember a published share root with its optional
    /// wire-facing `name` in the unlocked profile blob so it auto-republishes next
    /// launch (#41). `Some(name)` is a user-typed custom name; `None` defaults to
    /// the root basename at republish. No-op (returns `Ok`) on the ephemeral
    /// (no-profile) path; a disk / seal failure is surfaced as `Err`.
    pub fn persist_published(&mut self, root: &str, name: Option<&str>) -> Result<(), String> {
        match self.profile.as_mut() {
            Some(p) => p.persist_published(root, name).map(|_| ()),
            None => Ok(()),
        }
    }

    /// Write-through (M16): forget a published share root from the profile blob.
    pub fn unpersist_published(&mut self, root: &str) -> Result<(), String> {
        match self.profile.as_mut() {
            Some(p) => p.unpersist_published(root).map(|_| ()),
            None => Ok(()),
        }
    }

    /// The shares published this session, in publish order — the Publish overlay's
    /// "Your live shares" list.
    pub fn my_shares(&self) -> &[MyShare] {
        &self.my_shares
    }

    /// The published directory path for a session share, keyed on its `share_id` —
    /// the M16 persistence key the explicit Unpublish action forgets. `None` if no
    /// session share has that id.
    pub fn share_root(&self, id: &str) -> Option<String> {
        self.my_shares
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.root.clone())
    }

    /// The `(circle_id, phrase)` set the net actor must silently re-join on connect
    /// — every materialized circle currently in the rail. At startup (right after
    /// [`GuiState::set_profile`]) these are exactly the restored persisted circles;
    /// empty on the no-profile path.
    pub fn persisted_rejoins(&self) -> Vec<(u64, String)> {
        self.circles
            .iter()
            .filter_map(|c| c.net.as_ref().map(|n| (n.circle_id, n.phrase.clone())))
            .collect()
    }

    /// Write-through (round 6): record circle `idx`'s phrase into the unlocked
    /// profile's blob so it silently re-joins next launch. A no-op (returns `Ok`)
    /// when there is no profile (ephemeral session) or the circle has no net
    /// contract (the Lobby). A disk / seal failure is surfaced as `Err(reason)` —
    /// the circle still works in RAM this session regardless.
    pub fn persist_circle(&mut self, idx: usize) -> Result<(), String> {
        let Some((phrase, label)) = self
            .circles
            .get(idx)
            .and_then(|c| c.net.as_ref().map(|n| (n.phrase.clone(), c.name.clone())))
        else {
            return Ok(());
        };
        match self.profile.as_mut() {
            Some(p) => p.persist_circle(&phrase, &label).map(|_| ()),
            None => Ok(()),
        }
    }

    /// #115: the join phrase (the circle's shared secret) for circle `idx`, for the
    /// passphrase-gated reveal/export affordance. `None` for the Lobby (no net
    /// contract) or an unknown index. Callers gate the actual reveal on
    /// [`Self::verify_passphrase`] — this accessor itself does not.
    pub fn circle_phrase(&self, idx: usize) -> Option<String> {
        self.circles
            .get(idx)
            .and_then(|c| c.net.as_ref().map(|n| n.phrase.clone()))
    }

    /// #115: verify the user's unlock passphrase (gates the circle-phrase reveal — an
    /// evil-maid guard on an unlocked client). `false` on the ephemeral no-profile
    /// path: there is no passphrase to check, so reveal is a profile-only affordance.
    pub fn verify_passphrase(&self, passphrase: &str) -> bool {
        self.profile
            .as_ref()
            .is_some_and(|p| p.verify_passphrase(passphrase))
    }

    /// #115: leave a circle — remove it from the rail AND drop its phrase from the
    /// profile blob (so it does not silently re-join next launch). The pinned Lobby
    /// (index 0, no net contract) and an out-of-range index are no-ops. The circle is
    /// always removed from the rail this session; a profile re-seal failure is
    /// surfaced (the circle would otherwise re-join next launch) but does not block
    /// the in-session removal. `active` is shifted so it stays on the same circle.
    pub fn forget_circle(&mut self, idx: usize) -> Result<(), String> {
        let Some(phrase) = self
            .circles
            .get(idx)
            .and_then(|c| c.net.as_ref().map(|n| n.phrase.clone()))
        else {
            return Ok(()); // Lobby or unknown index — nothing to forget.
        };
        let result = match self.profile.as_mut() {
            Some(p) => p.forget_circle(&phrase).map(|_| ()),
            None => Ok(()),
        };
        self.circles.remove(idx);
        // Keep `active` pointing at the same circle: shift back if we removed the
        // active circle or one before it. `idx >= 1` here (the Lobby is never
        // forgotten), so this never underflows.
        if self.active >= idx && self.active > 0 {
            self.active -= 1;
        }
        if self.active >= self.circles.len() {
            self.active = self.circles.len().saturating_sub(1);
        }
        result
    }

    /// Materialize a circle from a shared phrase and append it to the rail
    /// (ISC-20). Derives the circle-of-trust key (`derive_cot_key`, ISC-21) and
    /// stores it + the phrase + an empty rendezvous slot as the [`CircleNet`]
    /// contract (ISC-22/23). Returns the new circle's rail index on success.
    ///
    /// The caller is responsible for the ISC-C9 ≥128-bit strength gate BEFORE
    /// calling this (the join flow blocks a weak phrase; the new-circle flow
    /// generates a 132-bit one) — derivation itself is unconditional, mirroring
    /// `derive_cot_key`'s contract.
    ///
    /// **Founderless** (ISC-18): the creator is simply the first member; there is
    /// no role, owner, or signed metadata — the phrase is the sole distinguisher.
    pub fn materialize_from_phrase(&mut self, phrase: &str) -> Result<usize, CircleKeyError> {
        let cot_key = derive_cot_key(phrase, &CNSA_2_0)?;
        let circle_id = self.next_circle_id;
        self.next_circle_id += 1;
        // PLACEHOLDER display name: the relay-independent `#<12hex>` circle
        // fingerprint (ISC-C62, explicitly reserved "for the GUI era") stands in
        // until Round 5's relay-derived adj-noun label (which needs a server_id).
        // No new naming scheme invented.
        let fp = circle_fingerprint(phrase);
        let initial = fp
            .chars()
            .nth(1)
            .map(|c| c.to_ascii_uppercase().to_string())
            .unwrap_or_else(|| "●".to_owned());
        let circle = CircleState {
            name: fp,
            // Operator-facing trust copy (brief refinement #3, D6). No bit numbers
            // (ISC-45). The old "· not yet connected" was a placeholder that never got
            // the live-state wiring (felt-test 2026-06-21: it contradicted the live
            // header status on a circle whose chat works) — dropped. Live per-circle
            // connection state is the Round-5 item; the header `connection-status`
            // property already carries the truthful live state.
            sub: "end-to-end encrypted".to_owned(),
            initial,
            pinned: false,
            header_sub: "end-to-end encrypted".to_owned(),
            messages: Vec::new(),
            draft: String::new(),
            scroll_y: 0.0,
            net: Some(CircleNet {
                circle_id,
                phrase: phrase.to_owned(),
                cot_key,
                rendezvous: None,
            }),
            unread: false,
            high_water_ms: 0,
            roster: Vec::new(),
        };
        self.circles.push(circle);
        Ok(self.circles.len() - 1)
    }

    /// Apply a circle's relay rendezvous address once it is joined (ISC-C62): fill the
    /// net contract's `rendezvous` slot and upgrade the display name from the pre-join
    /// `#<12hex>` fingerprint placeholder to the relay-derived adj-noun label
    /// ([`daemonseed_core::circle::default_circle_label`], the canonical home shared
    /// with the TUI). Deterministic per address — a re-join shows the same label.
    /// No-op for an unknown `circle_id` or the Lobby. Returns the rail index updated.
    pub fn set_circle_rendezvous(
        &mut self,
        circle_id: u64,
        asset_addr: AssetAddr,
    ) -> Option<usize> {
        let idx = self.index_of_circle_id(circle_id)?;
        let label = daemonseed_core::circle::default_circle_label(&asset_addr);
        let initial = label
            .chars()
            .next()
            .map(|c| c.to_ascii_uppercase().to_string())
            .unwrap_or_else(|| "●".to_owned());
        let circle = &mut self.circles[idx];
        if let Some(net) = circle.net.as_mut() {
            net.rendezvous = Some(asset_addr);
        }
        circle.name = label;
        circle.initial = initial;
        Some(idx)
    }

    /// The client-local `#<12hex>` fingerprint of circle `idx`, derived on demand from
    /// its retained phrase (ISC-C62 / Demonsaw handle-UX precedent — the hash is hidden
    /// behind the friendly label and surfaced only on demand, e.g. hover/detail). `None`
    /// for the Lobby (no net contract).
    ///
    /// Surfaced by the #36 circle-detail sheet (`main::apply_circle_detail`) as the
    /// universal out-of-band verification vector.
    pub fn circle_fingerprint_of(&self, idx: usize) -> Option<String> {
        self.circles
            .get(idx)
            .and_then(|c| c.net.as_ref())
            .map(|n| circle_fingerprint(&n.phrase))
    }

    /// #36: the deterministic display name of circle `idx` — the second
    /// out-of-band compare vector alongside [`Self::circle_fingerprint_of`].
    /// Derived from the **net contract**, NOT from `circle.name` (which becomes the
    /// user's chosen-name override once rename lands, #66): once the relay
    /// rendezvous is known it is the adj-noun label
    /// ([`daemonseed_core::circle::default_circle_label`]). That label is
    /// relay-DEPENDENT (rendezvous = `SHA-384(cot_key ‖ server_id)`), so it
    /// compares only between members on the SAME relay — distinct from the
    /// relay-INDEPENDENT phrase-keyed fingerprint. Pre-join (no rendezvous yet) it
    /// falls back to that fingerprint, so the line only diverges once connected.
    /// `None` for the Lobby (no net contract). Surfaced by the #36 circle-detail
    /// sheet (`main::apply_circle_detail`) as the relay-scoped compare vector.
    pub fn circle_deterministic_label_of(&self, idx: usize) -> Option<String> {
        let net = self.circles.get(idx)?.net.as_ref()?;
        Some(match &net.rendezvous {
            Some(addr) => daemonseed_core::circle::default_circle_label(addr),
            None => circle_fingerprint(&net.phrase),
        })
    }

    /// Index of the currently active circle.
    pub fn active(&self) -> usize {
        self.active
    }

    /// Number of circles. Used by the state unit tests; `#[allow(dead_code)]`
    /// because the binary reaches for [`GuiState::only_lobby`]/[`GuiState::metas`]
    /// instead.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.circles.len()
    }

    /// True if there are no circles (clippy-required companion to `len`).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.circles.is_empty()
    }

    /// True when only the pinned Lobby exists — drives the rail empty-state
    /// ("No circles yet — Join or New", ISC-31).
    pub fn only_lobby(&self) -> bool {
        self.circles.len() <= 1
    }

    /// The active circle's net `circle_id`, or `None` for the Lobby (no net
    /// contract). Drives composer Send routing — `Some(id)` → `SendCircle{id}`,
    /// `None` → the Lobby's `SendRoom`.
    pub fn active_circle_id(&self) -> Option<u64> {
        self.circles[self.active].net.as_ref().map(|n| n.circle_id)
    }

    /// Rail index of the circle with net `circle_id`, or `None`. The inverse of the
    /// routing tag: an inbound `CircleMessage{circle_id}` is folded into this index.
    pub fn index_of_circle_id(&self, circle_id: u64) -> Option<usize> {
        self.circles
            .iter()
            .position(|c| c.net.as_ref().is_some_and(|n| n.circle_id == circle_id))
    }

    /// Option A (#77 follow-up): cache the roster the net layer surfaced for
    /// `circle_id`'s room. `None` is the pinned Lobby (index 0); `Some(id)` maps via
    /// [`Self::index_of_circle_id`]. Called for EVERY `NetEvent::Roster` — active room
    /// or not — so a later rail switch can repaint the people column from the snapshot.
    /// A roster for an unknown id (a circle already left the rail) is dropped.
    pub fn set_room_roster(&mut self, circle_id: Option<u64>, roster: Vec<RosterEntry>) {
        let idx = match circle_id {
            None => 0,
            Some(id) => match self.index_of_circle_id(id) {
                Some(i) => i,
                None => return,
            },
        };
        if let Some(c) = self.circles.get_mut(idx) {
            c.roster = roster;
        }
    }

    /// The active room's cached HERE-NOW roster (option A) — repainted into the people
    /// column on every rail switch so the pane follows the switch.
    pub fn active_roster(&self) -> &[RosterEntry] {
        &self.circles[self.active].roster
    }

    /// The currently active circle's state.
    pub fn current(&self) -> &CircleState {
        &self.circles[self.active]
    }

    /// All circle metas, for building the rail model.
    pub fn metas(&self) -> &[CircleState] {
        &self.circles
    }

    /// Append a message to circle `idx` (no-op if out of range). Used by the
    /// real-net event drain to fold inbound/echoed Lobby messages into the RAM
    /// transcript, and by the non-Lobby local stub (the Round-5 `SendCircle` seam).
    /// Returns a [`PushOutcome`]: `inserted` is false on a dedup no-op (so the caller
    /// skips re-render + scroll — #143 scroll-yank), true on a genuine insert;
    /// `unread_raised` is true only when this newly raised circle `idx`'s unread dot
    /// (#64) — a non-own message, into a non-active room, newer than the read
    /// high-water. Own echoes (`mine`) and messages into the active room never raise it.
    pub fn push_message(
        &mut self,
        idx: usize,
        who: String,
        text: String,
        mine: bool,
        sent_unix_ms: i64,
    ) -> PushOutcome {
        let active = self.active;
        // #131: order + high-water on the CLAMPED timestamp, never the raw untrusted
        // one. Real backlog is inside the window so it is unclamped and orders exactly;
        // only a forged/broken stamp is pulled to a window edge (bounded influence).
        let now = now_unix_ms();
        let order = daemonseed_core::transcript::clamp_order_ms(sent_unix_ms, now);
        if let Some(c) = self.circles.get_mut(idx) {
            // Dedup on the ORIGINAL sent_unix_ms: the login backlog sweep and the live
            // watch can both deliver the SAME message, and dedup must key on a value
            // stable across re-sweeps (the clamp is time-relative, so a re-swept forged
            // frame would not dedup on the clamped value). An exact (sender, body,
            // sent_unix_ms) match already present is skipped. Two genuinely distinct
            // sends colliding on the same ms + identical text from the same sender is
            // vanishingly unlikely and harmless to coalesce.
            if c.messages.iter().any(|m| {
                m.sent_unix_ms == sent_unix_ms && m.mine == mine && m.who == who && m.text == text
            }) {
                return PushOutcome::default(); // dedup no-op: nothing inserted, no dot
            }
            // #105/#131: insert in CLAMPED-order so a late-arriving (older) message
            // slots chronologically while a forged extreme can't pin the transcript.
            // Compare against each element's STORED `order_ms` (clamped once at its own
            // insert), NOT a re-clamp against the current `now` — re-clamping would let a
            // future forgery that has since re-entered the window silently re-sort past
            // inserts and break `partition_point`'s sorted invariant (xhigh review).
            let pos = c.messages.partition_point(|m| m.order_ms <= order);
            c.messages.insert(
                pos,
                Msg {
                    who,
                    text,
                    mine,
                    sent_unix_ms,
                    order_ms: order,
                },
            );
            // #131: high-water tracks the clamped order but never advances past `now`,
            // so a far-future forged stamp cannot push the mark ahead and suppress
            // genuine unreads.
            let hw_input = order.min(now);
            let unread_raised = if idx == active {
                // The user is looking at this room, so every message here is seen:
                // keep the read high-water current so a later reconnect re-delivering
                // these same messages cannot re-trip the unread dot (#107).
                c.high_water_ms = c.high_water_ms.max(hw_input);
                false
            } else if !mine && order > c.high_water_ms && !c.unread {
                // #107: only a message NEWER (by clamped order) than what the user has
                // caught up on raises the dot — re-delivered backlog (order <=
                // high_water) is folded in silently, no dot.
                c.unread = true;
                true
            } else {
                false
            };
            return PushOutcome {
                inserted: true,
                unread_raised,
            };
        }
        PushOutcome::default()
    }

    /// Set circle `idx`'s retained draft (no-op if out of range). Used to persist
    /// a cleared composer into the active circle's RAM state after a send.
    pub fn set_draft(&mut self, idx: usize, draft: String) {
        if let Some(c) = self.circles.get_mut(idx) {
            c.draft = draft;
        }
    }

    /// Set circle `idx`'s retained `scroll_y` (no-op if out of range). #84: used on a
    /// new message to pin the transcript to the bottom (a large-negative sentinel that
    /// the Flickable clamps to the true bottom) or to hold the reader's live position.
    pub fn set_scroll(&mut self, idx: usize, scroll_y: f32) {
        if let Some(c) = self.circles.get_mut(idx) {
            c.scroll_y = scroll_y;
        }
    }

    /// Switch the active circle to `target`.
    ///
    /// FIRST persist the caller-supplied live `draft`/`scroll` into the
    /// CURRENTLY-active circle (capturing the user's in-progress edits), THEN set
    /// `active = target` iff `target` is in range. An out-of-range `target` is a
    /// no-op on `active` but the live edits are still captured.
    pub fn switch_to(&mut self, target: usize, live_draft: String, live_scroll: f32) {
        let cur = &mut self.circles[self.active];
        cur.draft = live_draft;
        cur.scroll_y = live_scroll;
        if target < self.circles.len() {
            self.active = target;
            // #64: focusing a room clears its unread dot.
            let c = &mut self.circles[self.active];
            c.unread = false;
            // #107: the user has now seen everything currently loaded, so advance the
            // read high-water to the newest message in the transcript (messages are kept
            // in `order_ms` order, so the last is the max). #131: advance from the
            // CLAMPED `order_ms` capped at `now` — NOT the raw `sent_unix_ms` — so a
            // forged far-future stamp cannot push the mark ahead and permanently suppress
            // unreads (the xhigh-review hole). A later reconnect re-delivering this
            // backlog then falls at/below the mark and won't re-trip.
            if let Some(latest) = c.messages.last().map(|m| m.order_ms) {
                c.high_water_ms = c.high_water_ms.max(latest.min(now_unix_ms()));
            }
        }
    }

    /// #70: the room the active view should follow to when the **Public Shares**
    /// tab is opened. Returns `Some(0)` (the Lobby) when a circle is the active
    /// room, so the highlighted room matches the public context being shown; `None`
    /// when the pinned Lobby (index 0) is already active — a no-op. The Lobby is
    /// invariantly the pinned index-0 room, so `active != 0` ⟺ a circle is active
    /// (equivalently `current().net.is_some()` in the live app). Deliberately NOT
    /// symmetric: opening the Circle-shares tab from the Lobby has no single target
    /// circle, so that direction is left untouched.
    pub fn public_shares_target_room(&self) -> Option<usize> {
        (self.active != 0).then_some(0)
    }
}

#[cfg(test)]
impl GuiState {
    /// Round-2 demo fixture — >=4 circles, a pinned "Lobby" first, the active one
    /// (index 1) scroll-rich. Round 4 retired it from the binary seed (the app
    /// uses [`GuiState::lobby_only`]); it is kept **test-only** so the round-2
    /// retention/perf unit tests below stay intact with zero churn. Materialized
    /// circles carry no net contract here (`net: None`) — these tests exercise the
    /// pure draft/scroll/switch state, not the crypto.
    pub fn demo() -> GuiState {
        fn first_msg(circle: &str, who: &str) -> Msg {
            Msg {
                who: who.into(),
                text: format!("welcome to {circle} — this circle is {circle}"),
                mine: false,
                sent_unix_ms: 0,
                order_ms: 0,
            }
        }
        fn fill(name: &str, n: usize, owner: &str) -> Vec<Msg> {
            let mut msgs = vec![first_msg(name, owner)];
            for i in 1..n {
                let mine = i % 3 == 0;
                msgs.push(Msg {
                    who: if mine {
                        owner.into()
                    } else {
                        format!("daemon-{i:02}")
                    },
                    text: format!("{name} line {i} — lorem ipsum dolor sit amet"),
                    mine,
                    sent_unix_ms: i as i64,
                    order_ms: i as i64,
                });
            }
            msgs
        }
        let mk = |name: &str, sub: &str, initial: &str, pinned: bool, header_sub: &str, msgs| {
            CircleState {
                name: name.into(),
                sub: sub.into(),
                initial: initial.into(),
                pinned,
                header_sub: header_sub.into(),
                messages: msgs,
                draft: String::new(),
                scroll_y: 0.0,
                net: None,
                unread: false,
                high_water_ms: 0,
                roster: Vec::new(),
            }
        };
        let circles = vec![
            mk(
                "Lobby",
                "public lobby · amazon-fra1",
                "L",
                true,
                "public lobby · open · amazon-fra1",
                fill("Lobby", 6, "amazon-fra1"),
            ),
            mk(
                "midnight-signal",
                "4 here · encrypted",
                "m",
                false,
                "4 here · end-to-end encrypted",
                fill("midnight-signal", 24, "wandering-otter"),
            ),
            mk(
                "garden-fence",
                "2 here · encrypted",
                "g",
                false,
                "2 here · encrypted · neighbours",
                fill("garden-fence", 5, "quiet-sparrow"),
            ),
            mk(
                "harbor-lights",
                "3 here · encrypted",
                "h",
                false,
                "3 here · encrypted · waterfront",
                fill("harbor-lights", 4, "dock-keeper"),
            ),
        ];
        GuiState {
            circles,
            active: 1,
            next_circle_id: FIRST_CIRCLE_ID,
            profile: None,
            my_shares: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // ── #93 unread-gated landing (ISC-C93) ───────────────────────────────────

    fn ann_view(motd: Option<&str>, posts: &[(&str, &str, i64)]) -> AnnouncementsView {
        AnnouncementsView {
            motd: motd.map(str::to_owned),
            posts: posts
                .iter()
                .map(|(topic, body, ts)| AnnouncementRow {
                    topic: (*topic).to_owned(),
                    body: (*body).to_owned(),
                    sent_unix_ms: *ts,
                })
                .collect(),
        }
    }

    #[test]
    fn announcements_unread_covers_all_cases() {
        let _ = oxicrypt_module::initialize();
        let empty = ann_view(None, &[]);
        let empty_hash = combined_content_hash(&empty);
        let content = ann_view(Some("relay is up"), &[("a", "x", 1)]);
        let content_hash = combined_content_hash(&content);
        // Empty view → never unread (empty-view guard), even with no stored hash — an
        // unconverged/blank view must not trip a spurious dot.
        assert!(!announcements_unread(&empty, &empty_hash, None));
        // Non-empty, never seen → unread.
        assert!(announcements_unread(&content, &content_hash, None));
        // Non-empty, stored != current → unread.
        assert!(announcements_unread(&content, &content_hash, Some("stale")));
        // Non-empty, stored == current (already seen) → not unread.
        assert!(!announcements_unread(
            &content,
            &content_hash,
            Some(&content_hash)
        ));
    }

    #[test]
    fn viewing_updates_stored_hash_then_clears_unread() {
        // Mirrors the GUI write-through: a first arrival is unread; once the current
        // hash is stored (the "viewing updates the stored hash" step), the SAME content
        // is no longer unread (the dot clears).
        let _ = oxicrypt_module::initialize();
        let view = ann_view(Some("relay is up"), &[("announcements", "v2", 5)]);
        let current = combined_content_hash(&view);

        let mut seeds = daemonseed_core::storage::seeds::Seeds::new(
            daemonseed_core::identity::mnemonic::Mnemonic::generate().unwrap(),
        );
        assert!(
            announcements_unread(&view, &current, seeds.announce_seen("fra1#abc")),
            "first arrival is unread"
        );
        assert!(seeds.set_announce_seen("fra1#abc", current.clone()));
        assert!(
            !announcements_unread(&view, &current, seeds.announce_seen("fra1#abc")),
            "after viewing, the same content is no longer unread"
        );
    }

    #[test]
    fn combined_content_hash_is_stable_order_independent_and_change_sensitive() {
        let _ = oxicrypt_module::initialize();
        let base = ann_view(Some("relay is up"), &[("a", "x", 1)]);
        let h0 = combined_content_hash(&base);
        // Same content (rebuilt) → identical hash.
        assert_eq!(h0, combined_content_hash(&base.clone()));

        // MOTD edit → different hash.
        let motd_edit = ann_view(Some("maintenance soon"), &[("a", "x", 1)]);
        assert_ne!(h0, combined_content_hash(&motd_edit));
        // MOTD removed → different hash.
        let motd_gone = ann_view(None, &[("a", "x", 1)]);
        assert_ne!(h0, combined_content_hash(&motd_gone));

        // A post added → different hash.
        let added = ann_view(Some("relay is up"), &[("a", "x", 1), ("b", "y", 2)]);
        assert_ne!(h0, combined_content_hash(&added));
        // A post removed → different hash.
        let removed = ann_view(Some("relay is up"), &[]);
        assert_ne!(h0, combined_content_hash(&removed));
        // A post edited → different hash.
        let edited = ann_view(Some("relay is up"), &[("a", "x!", 1)]);
        assert_ne!(h0, combined_content_hash(&edited));

        // Reordered served posts (same set) → SAME hash (canonical sort).
        let ordered = ann_view(Some("relay is up"), &[("a", "x", 1), ("b", "y", 2)]);
        let reversed = ann_view(Some("relay is up"), &[("b", "y", 2), ("a", "x", 1)]);
        assert_eq!(
            combined_content_hash(&ordered),
            combined_content_hash(&reversed),
            "server post order must not change the unread marker"
        );
    }

    #[test]
    fn public_shares_opening_follows_a_circle_to_the_lobby() {
        // #70: with a circle active (demo seeds active = 1), opening the Public
        // Shares tab follows the room to the Lobby (index 0); a no-op on the Lobby.
        let mut st = GuiState::demo();
        assert_ne!(st.active(), 0, "demo fixture seeds a circle active");
        assert_eq!(st.public_shares_target_room(), Some(0));
        st.switch_to(0, String::new(), 0.0);
        assert_eq!(st.public_shares_target_room(), None);
    }

    #[test]
    fn my_shares_add_replace_remove() {
        let mut st = GuiState::lobby_only();
        assert!(st.my_shares().is_empty());
        // #117: id-a starts in-flight (republishing), id-b live.
        st.add_my_share(
            "id-a".into(),
            "alpha".into(),
            3,
            "/shares/alpha".into(),
            true,
        );
        st.add_my_share(
            "id-b".into(),
            "beta".into(),
            1,
            "/shares/beta".into(),
            false,
        );
        assert_eq!(st.my_shares().len(), 2);
        assert!(
            st.my_shares()
                .iter()
                .find(|s| s.id == "id-a")
                .unwrap()
                .republishing,
            "#117: id-a is flagged republishing while in flight"
        );
        // share_root keys the M16 persistence by id → published directory path.
        assert_eq!(st.share_root("id-b").as_deref(), Some("/shares/beta"));
        assert_eq!(st.share_root("id-zzz"), None);
        // Re-publish (same id) replaces, not duplicates — a relay re-list is idempotent.
        // #117: the live confirmation re-pushes id-a with republishing=false (tag clears).
        st.add_my_share(
            "id-a".into(),
            "alpha-renamed".into(),
            9,
            "/shares/alpha".into(),
            false,
        );
        assert_eq!(st.my_shares().len(), 2);
        let a = st.my_shares().iter().find(|s| s.id == "id-a").unwrap();
        assert_eq!(a.name, "alpha-renamed");
        assert_eq!(a.files, 9);
        assert_eq!(a.root, "/shares/alpha");
        assert!(
            !a.republishing,
            "#117: the live confirmation clears the tag"
        );
        // Unpublish drops by id; unknown id is a no-op. (remove returns the dropped root.)
        assert_eq!(st.remove_my_share("id-a").as_deref(), Some("/shares/alpha"));
        assert_eq!(st.remove_my_share("id-zzz"), None);
        assert_eq!(st.my_shares().len(), 1);
        assert_eq!(st.my_shares()[0].id, "id-b");
    }

    // ── round-2 retention/perf (unchanged behavior; demo fixture) ────────────

    #[test]
    fn draft_retained_per_circle() {
        let mut st = GuiState::demo();
        assert_eq!(st.active(), 1);
        st.switch_to(2, "hello on one".into(), 0.0);
        st.switch_to(1, String::new(), 0.0);
        assert_eq!(st.current().draft, "hello on one");
    }

    #[test]
    fn scroll_retained_per_circle() {
        let mut st = GuiState::demo();
        assert_eq!(st.active(), 1);
        st.switch_to(3, String::new(), -120.0);
        st.switch_to(1, String::new(), 0.0);
        assert_eq!(st.current().scroll_y, -120.0);
    }

    #[test]
    fn drafts_independent() {
        let mut st = GuiState::demo();
        st.switch_to(2, "draft-for-one".into(), 0.0);
        st.switch_to(1, "draft-for-two".into(), 0.0);
        assert_eq!(st.current().draft, "draft-for-one");
        st.switch_to(2, String::new(), 0.0);
        assert_eq!(st.current().draft, "draft-for-two");
    }

    // ── #64 unread/new-message dot ───────────────────────────────────────────

    #[test]
    fn unread_set_on_nonactive_inbound() {
        let mut st = GuiState::demo(); // active == 1
        let raised = st
            .push_message(2, "ally".into(), "ping".into(), false, 1)
            .unread_raised;
        assert!(
            raised,
            "a non-own message into a non-active room raises unread"
        );
        assert!(st.metas()[2].unread);
        assert!(!st.metas()[1].unread, "the active room never gets a dot");
    }

    #[test]
    fn unread_not_set_for_active_room_or_own_echo() {
        let mut st = GuiState::demo(); // active == 1
        assert!(
            !st.push_message(1, "x".into(), "hi".into(), false, 1)
                .unread_raised
        );
        assert!(
            !st.metas()[1].unread,
            "message into the active room: no dot"
        );
        assert!(
            !st.push_message(2, "me".into(), "hi".into(), true, 2)
                .unread_raised
        );
        assert!(!st.metas()[2].unread, "own echo never dots");
    }

    #[test]
    fn focus_clears_unread() {
        let mut st = GuiState::demo(); // active == 1
        st.push_message(2, "ally".into(), "ping".into(), false, 1);
        assert!(st.metas()[2].unread);
        st.switch_to(2, String::new(), 0.0); // focus circle 2
        assert!(!st.metas()[2].unread, "focusing a room clears its dot");
    }

    #[test]
    fn unread_raise_is_idempotent() {
        let mut st = GuiState::demo(); // active == 1
        assert!(
            st.push_message(2, "a".into(), "1".into(), false, 1)
                .unread_raised
        );
        assert!(
            !st.push_message(2, "a".into(), "2".into(), false, 2)
                .unread_raised,
            "already-unread room does not re-raise (no spurious rail rebuilds)"
        );
        assert!(st.metas()[2].unread);
    }

    // ── #107 backlog unread high-water mark ──────────────────────────────────

    #[test]
    fn backlog_at_or_below_high_water_does_not_retrip_unread() {
        // #131: timestamps are now-relative so they sit INSIDE the ordering window
        // (unclamped) and exercise the real high-water semantics.
        let now = now_unix_ms();
        let mut st = GuiState::demo(); // active == 1
        // The user opens circle 2 and reads live messages up to now-1s.
        st.switch_to(2, String::new(), 0.0); // active == 2
        st.push_message(2, "ally".into(), "live-a".into(), false, now - 2000);
        st.push_message(2, "ally".into(), "live-b".into(), false, now - 1000);
        assert!(!st.metas()[2].unread, "no dot while the room is active");
        assert!(
            st.metas()[2].high_water_ms >= now - 1000,
            "watching live advances the read high-water"
        );
        // Switch away; a reconnect re-delivers backlog at the high-water mark into the
        // now-non-active circle 2 (distinct text, so it is NOT a dedup hit — it is a
        // genuinely new transcript entry that must still NOT raise the dot).
        st.switch_to(1, String::new(), 0.0); // active == 1
        let raised = st
            .push_message(2, "ally".into(), "re-swept".into(), false, now - 1000)
            .unread_raised;
        assert!(
            !raised,
            "backlog at the high-water mark must not re-trip unread"
        );
        assert!(!st.metas()[2].unread);
    }

    #[test]
    fn message_newer_than_high_water_still_trips_unread() {
        let now = now_unix_ms();
        let mut st = GuiState::demo(); // active == 1
        st.switch_to(2, String::new(), 0.0);
        st.push_message(2, "ally".into(), "seen".into(), false, now - 2000); // active → high_water
        st.switch_to(1, String::new(), 0.0); // active == 1
        let raised = st
            .push_message(2, "ally".into(), "fresh".into(), false, now - 1000)
            .unread_raised;
        assert!(
            raised,
            "a message newer than the high-water mark raises the dot"
        );
        assert!(st.metas()[2].unread);
    }

    #[test]
    fn forged_timestamp_is_clamped_and_cannot_pin_or_suppress() {
        // #131: an open-room peer forging extreme timestamps cannot pin the transcript
        // or suppress unreads — the clamp bounds ordering + high-water influence.
        let now = now_unix_ms();
        let mut st = GuiState::demo(); // active == 1
        st.switch_to(2, String::new(), 0.0);
        // A real recent message the user reads.
        st.push_message(2, "ally".into(), "real".into(), false, now - 1000);
        let hw_after_real = st.metas()[2].high_water_ms;
        // A far-FUTURE forgery must NOT push the high-water past ~now (no unread-suppress).
        st.push_message(2, "evil".into(), "future".into(), false, i64::MAX);
        assert!(
            st.metas()[2].high_water_ms <= now + 120_000,
            "high-water never advances past now + skew, even for i64::MAX"
        );
        assert!(st.metas()[2].high_water_ms >= hw_after_real);
        // A far-PAST forgery (i64::MIN) sorts to the window edge, NOT above every real
        // message off-screen — it lands at/after the clamp floor, not at epoch 0.
        st.push_message(2, "evil".into(), "past".into(), false, i64::MIN);
        let texts: Vec<&str> = st.circles[2]
            .messages
            .iter()
            .map(|m| m.text.as_str())
            .filter(|t| ["real", "future", "past"].contains(t))
            .collect();
        // "past" clamps to now-24h (top of the window), "real" is now-1s, "future"
        // clamps to now+skew (bottom) — a bounded, sensible order.
        assert_eq!(texts, vec!["past", "real", "future"]);
    }

    #[test]
    fn forged_future_via_switch_to_cannot_suppress_future_unreads() {
        // #131 (xhigh-review hole): the suppression path is switch_to, NOT the active
        // push. A forged i64::MAX lands in a NON-active room; focusing it must advance
        // the high-water only to ~now (clamped `order_ms`, capped), NOT to i64::MAX — so
        // a later genuine message still trips the unread dot.
        let now = now_unix_ms();
        let mut st = GuiState::demo(); // active == 1
        // Forge a far-future message into non-active circle 2, then focus it.
        st.push_message(2, "evil".into(), "future".into(), false, i64::MAX);
        st.switch_to(2, String::new(), 0.0); // focus → advances high-water
        assert!(
            st.metas()[2].high_water_ms <= now + 120_000,
            "switch_to must clamp the high-water; a forged i64::MAX cannot pin it"
        );
        // Switch away; a genuine newer message must still raise the dot. It is stamped
        // now+60s (legit clock skew, in-window) so it is strictly newer than the
        // focus-time high-water (~now) — with Bug 1 present the high-water would be
        // i64::MAX and this would NOT trip (suppressed); with the fix it trips.
        st.switch_to(1, String::new(), 0.0);
        let raised = st
            .push_message(2, "ally".into(), "genuine".into(), false, now + 60_000)
            .unread_raised;
        assert!(
            raised,
            "a real message still trips unread — suppression is closed"
        );
        assert!(st.metas()[2].unread);
    }

    #[test]
    fn focusing_a_circle_advances_high_water_to_latest() {
        let mut st = GuiState::demo(); // active == 1
        // First-load backlog into a non-active circle trips once (expected — new this
        // session); focusing then clears the dot AND catches the high-water up so the
        // NEXT reconnect's re-delivery of that backlog stays silent.
        st.push_message(2, "ally".into(), "backlog".into(), false, 7);
        assert!(st.metas()[2].unread);
        st.switch_to(2, String::new(), 0.0);
        assert!(
            st.metas()[2].high_water_ms >= 7,
            "focus catches the high-water up to the newest message in the transcript"
        );
    }

    // ── #105 transcript ordering by sent_unix_ms ─────────────────────────────

    #[test]
    fn circle_messages_insert_in_sent_unix_ms_order() {
        let now = now_unix_ms();
        let mut st = GuiState::demo(); // active == 1; circle 2 exists
        // Arrive OUT of send-order (DHT latency), now-relative so they're in-window
        // (unclamped) and order by their real timestamps.
        st.push_message(2, "a".into(), "third".into(), false, now - 1000);
        st.push_message(2, "b".into(), "first".into(), false, now - 3000);
        st.push_message(2, "c".into(), "second".into(), false, now - 2000);
        // Filter to our three (demo() seeds fixture messages) and assert they land
        // in timestamp order regardless of arrival order.
        let ours: Vec<&str> = st.circles[2]
            .messages
            .iter()
            .map(|m| m.text.as_str())
            .filter(|t| ["first", "second", "third"].contains(t))
            .collect();
        assert_eq!(
            ours,
            vec!["first", "second", "third"],
            "messages ordered by sent_unix_ms, not arrival order"
        );
    }

    #[test]
    fn format_relative_age_buckets_across_boundaries() {
        // #100: fake-clock (both args injected) across the second/minute/hour/day
        // boundaries; a days-old backlog line reads "sitting N days", not live.
        let t = 1_700_000_000_000_i64; // fixed "sent" anchor (ms)
        let m = 60_000_i64;
        let h = 60 * m;
        let d = 24 * h;
        // Under a minute — incl. a future timestamp from peer clock skew — is "just now".
        assert_eq!(format_relative_age(t, t - 5_000), "just now"); // 5s in the future
        assert_eq!(format_relative_age(t, t), "just now");
        assert_eq!(format_relative_age(t, t + 59_000), "just now");
        // Minutes.
        assert_eq!(format_relative_age(t, t + m), "1m ago");
        assert_eq!(format_relative_age(t, t + 2 * m), "2m ago");
        assert_eq!(format_relative_age(t, t + 59 * m), "59m ago");
        // Hours.
        assert_eq!(format_relative_age(t, t + h), "1h ago");
        assert_eq!(format_relative_age(t, t + 23 * h), "23h ago");
        // Days — the "sitting" framing so an old swept backlog line does not read as live.
        assert_eq!(format_relative_age(t, t + d), "sitting 1 day");
        assert_eq!(format_relative_age(t, t + 3 * d), "sitting 3 days");
    }

    #[test]
    fn duplicate_circle_message_is_coalesced() {
        let mut st = GuiState::demo(); // active == 1; circle 2 exists
        let before = st.circles[2].messages.len();
        // The same message delivered twice (sweep + watch) must land once.
        st.push_message(2, "alice".into(), "hello".into(), false, 100);
        st.push_message(2, "alice".into(), "hello".into(), false, 100);
        let hellos = st.circles[2]
            .messages
            .iter()
            .filter(|m| m.who == "alice" && m.text == "hello" && m.sent_unix_ms == 100)
            .count();
        assert_eq!(hellos, 1, "duplicate (sender, body, ms) coalesced to one");
        assert_eq!(st.circles[2].messages.len(), before + 1);
        // A distinct body at the same ms is NOT coalesced — it is inserted. (The
        // bool return is the unread-dot signal, already raised above, so it is
        // irrelevant here; the count assertion below is the real check.)
        let _ = st.push_message(2, "alice".into(), "world".into(), false, 100);
        assert_eq!(
            st.circles[2]
                .messages
                .iter()
                .filter(|m| m.who == "alice" && m.sent_unix_ms == 100)
                .count(),
            2,
            "distinct bodies at the same ms both kept"
        );
    }

    #[test]
    fn own_echo_loopback_is_deduped_and_reports_not_inserted() {
        // #143 scroll-yank: an own message (mine=true) is echoed locally on send, then
        // loops back from the DHT/relay as the SAME (who, text, sent_unix_ms). The
        // loopback must dedup and report `inserted:false` — the exact signal the Lobby /
        // Circle handlers gate the re-render + scroll on, so a deduped loopback never
        // yanks the reader's scroll to the bottom. The first delivery inserts.
        let mut st = GuiState::demo(); // active == 1; circle 2 exists
        let before = st.circles[2].messages.len();
        let first = st.push_message(2, "me".into(), "hello".into(), true, 100);
        assert!(first.inserted, "the first own delivery inserts a line");
        assert!(!first.unread_raised, "an own echo never raises the dot");
        let loopback = st.push_message(2, "me".into(), "hello".into(), true, 100);
        assert!(
            !loopback.inserted,
            "the looped-back own message dedups — inserted:false gates the scroll (#143)"
        );
        assert!(!loopback.unread_raised);
        assert_eq!(
            st.circles[2].messages.len(),
            before + 1,
            "exactly one copy after the loopback"
        );
    }

    #[test]
    fn out_of_range_target_is_noop_but_captures() {
        let mut st = GuiState::demo();
        assert_eq!(st.active(), 1);
        st.switch_to(999, "captured".into(), 0.0);
        assert_eq!(st.active(), 1);
        assert_eq!(st.current().draft, "captured");
    }

    // ── round-4: seed + materialization + net contract ───────────────────────

    /// A genuinely-strong (>=128-bit) phrase for materialization tests. 12 BIP-39
    /// words = 132 bits; this hand-picked set clears `is_circle_green`.
    const STRONG: &str =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

    #[test]
    fn lobby_only_seed_is_just_the_pinned_lobby() {
        let st = GuiState::lobby_only();
        assert_eq!(st.len(), 1);
        assert_eq!(st.active(), 0);
        assert!(st.only_lobby());
        let lobby = st.current();
        assert_eq!(lobby.name, "Lobby");
        assert!(lobby.pinned, "Lobby must stay pinned (ISC-32)");
        assert!(
            lobby.net.is_none(),
            "Lobby derives from room name, not a phrase"
        );
    }

    #[test]
    fn materialize_adds_circle_with_net_contract() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let idx = st.materialize_from_phrase(STRONG).expect("materialize");
        assert_eq!(idx, 1);
        assert_eq!(st.len(), 2);
        assert!(!st.only_lobby());
        // active does NOT auto-advance — the UI callback switches explicitly.
        assert_eq!(st.active(), 0);
        let c = &st.metas()[idx];
        assert!(!c.pinned, "a materialized circle is not pinned");
        let net = c
            .net
            .as_ref()
            .expect("materialized circle carries a net contract");
        assert_eq!(
            net.phrase, STRONG,
            "phrase stored for Round-5 JoinCircle (ISC-22)"
        );
        assert!(
            net.rendezvous.is_none(),
            "rendezvous unset pre-net (ISC-23)"
        );
        // Round-5 routing: a stable id is assigned and round-trips through lookup.
        assert_eq!(
            net.circle_id, 1,
            "first materialized circle gets FIRST_CIRCLE_ID"
        );
        assert_eq!(
            st.active_circle_id(),
            None,
            "Lobby (active) has no circle id"
        );
        assert_eq!(
            st.index_of_circle_id(1),
            Some(1),
            "circle_id 1 → rail index 1"
        );
        assert_eq!(
            st.index_of_circle_id(999),
            None,
            "unknown circle_id → nowhere"
        );
    }

    #[test]
    fn distinct_materialized_circles_get_distinct_ids() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let a = st.materialize_from_phrase(STRONG).unwrap();
        let b = st
            .materialize_from_phrase(
                "zone zoo zebra youth yellow wrong write world worth worry wonder window",
            )
            .unwrap();
        let id_a = st.metas()[a].net.as_ref().unwrap().circle_id;
        let id_b = st.metas()[b].net.as_ref().unwrap().circle_id;
        assert_ne!(id_a, id_b, "monotonic ids never collide within a session");
        assert_eq!(st.index_of_circle_id(id_a), Some(a));
        assert_eq!(st.index_of_circle_id(id_b), Some(b));
    }

    #[test]
    fn materialized_cot_key_matches_independent_derivation() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let idx = st.materialize_from_phrase(STRONG).unwrap();
        let stored = st.metas()[idx].net.as_ref().unwrap().cot_key.as_bytes();
        let independent = derive_cot_key(STRONG, &CNSA_2_0).unwrap();
        assert_eq!(
            stored,
            independent.as_bytes(),
            "stored cot_key must equal an independent derive_cot_key, byte-for-byte (ISC-24)"
        );
    }

    #[test]
    fn distinct_phrases_yield_distinct_cot_keys() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let a = st.materialize_from_phrase(STRONG).unwrap();
        let b = st
            .materialize_from_phrase(
                "zone zoo zebra youth yellow wrong write world worth worry world wonder",
            )
            .unwrap();
        let ka = st.metas()[a].net.as_ref().unwrap().cot_key.as_bytes();
        let kb = st.metas()[b].net.as_ref().unwrap().cot_key.as_bytes();
        assert_ne!(
            ka, kb,
            "distinct phrases must derive distinct keys (ISC-26)"
        );
    }

    #[test]
    fn same_phrase_yields_same_cot_key() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let a = st.materialize_from_phrase(STRONG).unwrap();
        let b = st.materialize_from_phrase(STRONG).unwrap();
        let ka = st.metas()[a].net.as_ref().unwrap().cot_key.as_bytes();
        let kb = st.metas()[b].net.as_ref().unwrap().cot_key.as_bytes();
        assert_eq!(
            ka, kb,
            "same phrase must derive the same key — seed-key model (ISC-27)"
        );
    }

    #[test]
    fn materialized_circle_has_independent_draft_state() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let idx = st.materialize_from_phrase(STRONG).unwrap();
        // Switch Lobby -> circle, type into the circle, switch away and back.
        st.switch_to(idx, String::new(), 0.0); // capture Lobby's (empty) draft, go to circle
        st.switch_to(0, "circle draft".into(), 0.0); // capture circle's draft, go to Lobby
        assert_eq!(st.current().draft, "", "Lobby draft untouched");
        st.switch_to(idx, String::new(), 0.0); // back to the circle
        assert_eq!(
            st.current().draft,
            "circle draft",
            "per-circle draft retained (ISC-25)"
        );
    }

    #[test]
    fn generated_new_phrase_is_green_and_materializes() {
        let _ = oxicrypt_module::initialize();
        // The new-circle flow uses `generate_circle_phrase` — rejection-sampled to
        // clear the floor DETERMINISTICALLY (a bare `generate_diceware(12)` is ~3%
        // flaky: a duplicate word drops the distinct-word estimate below 128 bits).
        // Run a batch so a single lucky draw can't hide a regression (ISC-13/19).
        for _ in 0..64 {
            let phrase = generate_circle_phrase().expect("generate");
            assert_eq!(
                phrase.split_whitespace().count(),
                strength::CIRCLE_DICEWARE_WORDS
            );
            assert!(
                strength::estimate_circle(&phrase).is_circle_green(),
                "a generated circle phrase must clear the floor every time (ISC-19): {phrase:?}"
            );
        }
        let phrase = generate_circle_phrase().expect("generate");
        let mut st = GuiState::lobby_only();
        let idx = st
            .materialize_from_phrase(&phrase)
            .expect("materialize generated");
        assert!(st.metas()[idx].net.is_some());
    }

    #[test]
    fn set_circle_rendezvous_swaps_to_friendly_label_and_keeps_fingerprint() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let phrase = generate_circle_phrase().expect("generate");
        let idx = st.materialize_from_phrase(&phrase).expect("materialize");
        let circle_id = st.metas()[idx].net.as_ref().unwrap().circle_id;
        // Pre-join: the name is the #<12hex> fingerprint placeholder, equal to the
        // on-demand fingerprint accessor.
        assert!(st.metas()[idx].name.starts_with('#'));
        let fp_before = st.circle_fingerprint_of(idx).unwrap();
        assert_eq!(fp_before, st.metas()[idx].name);

        // Post-join: applying the rendezvous swaps the name to the relay-derived
        // adj-noun label and fills the rendezvous slot.
        let addr = AssetAddr::from_bytes([5u8; daemonseed_core::cot::ASSET_ADDR_LEN]);
        let updated = st
            .set_circle_rendezvous(circle_id, addr)
            .expect("known circle");
        assert_eq!(updated, idx);
        let want = daemonseed_core::circle::default_circle_label(&addr);
        assert_eq!(st.metas()[idx].name, want);
        assert!(!st.metas()[idx].name.starts_with('#'));
        assert!(st.metas()[idx].net.as_ref().unwrap().rendezvous.is_some());
        // The fingerprint stays reachable on demand (hash hidden, surfaced on demand).
        assert_eq!(st.circle_fingerprint_of(idx).unwrap(), fp_before);
    }

    #[test]
    fn circle_detail_label_derives_from_net_contract_not_chosen_name() {
        // #36: the deterministic-label compare vector is derived from the net
        // contract (rendezvous → adj-noun label, else fingerprint), independent of
        // `circle.name` — so it survives a future chosen-name override (#66).
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let phrase = generate_circle_phrase().expect("generate");
        let idx = st.materialize_from_phrase(&phrase).expect("materialize");
        let circle_id = st.metas()[idx].net.as_ref().unwrap().circle_id;
        let fp = st.circle_fingerprint_of(idx).expect("fingerprint");
        // Pre-join (no rendezvous): falls back to the relay-independent fingerprint.
        assert_eq!(
            st.circle_deterministic_label_of(idx).as_deref(),
            Some(fp.as_str())
        );
        // Post-join: the relay-derived adj-noun label, distinct from the fingerprint.
        let addr = AssetAddr::from_bytes([5u8; daemonseed_core::cot::ASSET_ADDR_LEN]);
        st.set_circle_rendezvous(circle_id, addr)
            .expect("known circle");
        let want = daemonseed_core::circle::default_circle_label(&addr);
        assert_eq!(
            st.circle_deterministic_label_of(idx).as_deref(),
            Some(want.as_str())
        );
        assert_eq!(
            st.circle_fingerprint_of(idx).as_deref(),
            Some(fp.as_str()),
            "fingerprint stays phrase-keyed (relay-independent)"
        );
        assert_ne!(
            want, fp,
            "post-join the deterministic label diverges from the fingerprint"
        );
        // The Lobby has no net contract → no deterministic label.
        assert!(st.circle_deterministic_label_of(0).is_none());
    }

    #[test]
    fn set_circle_rendezvous_is_noop_for_unknown_circle() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let addr = AssetAddr::from_bytes([1u8; daemonseed_core::cot::ASSET_ADDR_LEN]);
        assert!(st.set_circle_rendezvous(999, addr).is_none());
        // The Lobby has no net contract → no fingerprint.
        assert!(st.circle_fingerprint_of(0).is_none());
    }

    #[test]
    fn materialized_switch_perf_budget() {
        // The <100ms switch op covers a RUNTIME-ADDED circle too (ISC-48): seed
        // Lobby, materialize one circle, then hammer switches between them.
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        st.materialize_from_phrase(STRONG).unwrap();
        let start = Instant::now();
        for i in 0..100_000 {
            st.switch_to(i % st.len(), "x".into(), -1.0);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 100,
            "100k state switches took {elapsed:?}, expected far under 100ms"
        );
    }

    #[test]
    fn net_contract_debug_redacts_the_phrase() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let idx = st.materialize_from_phrase(STRONG).unwrap();
        let net = st.metas()[idx].net.as_ref().unwrap();
        let dbg = format!("{net:?}");
        assert!(
            dbg.contains("<redacted>"),
            "phrase must be redacted in Debug"
        );
        assert!(
            !dbg.contains("abandon"),
            "the secret phrase must never appear in Debug"
        );
        assert!(
            dbg.contains("CircleKey(<redacted>)"),
            "cot_key Debug stays redacted"
        );
    }

    // ── round-6: persistent identity + silent circle rejoin ──────────────────

    /// The whole persistence loop, end-to-end against a real temp profile root and
    /// no relay: enroll → adopt the profile → user joins a circle (write-through) →
    /// reload the blob from disk under the passphrase → restore. The restored circle
    /// must be back in the rail and re-derive the SAME key, and the display handle
    /// must survive. This is the round-6 keystone — a tester relaunching keeps their
    /// handle + circles.
    #[test]
    fn profile_round_trips_a_circle_and_handle_across_reload() {
        use daemonseed_core::bootstrap::BootstrapAnchor;
        use daemonseed_core::first_start::FirstStart;
        use daemonseed_core::profile::config::ArgonParams;
        use daemonseed_core::profile::persist::{
            load_for_unlock, session_materials_from_unlock, write_first_start,
        };
        use daemonseed_core::storage::seeds;

        let _ = oxicrypt_module::initialize();

        // A unique temp profile root (no uuid dep — pid + nanos).
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ds-gui-profile-test-{}-{nonce}",
            std::process::id()
        ));
        // Fast Argon params for the test (production uses ArgonParams::default()).
        let fast = ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let pass = "correct horse battery staple table mountain";

        // Enroll + persist a first-start profile.
        let sealed = FirstStart::new().initialize(pass, fast).unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let materials = verified
            .finalize(
                Some("alice".to_string()),
                BootstrapAnchor {
                    server_id: "relay#aabbccddeeff".to_string(),
                    address: "127.0.0.1:443".to_string(),
                },
            )
            .unwrap()
            .into_session_materials();
        write_first_start(&root, &materials, None, false).unwrap();

        // Session 1: adopt the profile (no circles yet), join a circle, write through.
        let mut st1 = GuiState::lobby_only();
        st1.set_profile(Profile::from_materials(materials, root.clone()));
        assert_eq!(st1.display_handle().as_deref(), Some("alice"));
        assert!(
            st1.persisted_rejoins().is_empty(),
            "no circles persisted on a fresh enrollment"
        );
        let idx = st1.materialize_from_phrase(STRONG).unwrap();
        st1.persist_circle(idx)
            .expect("write-through persists the circle");
        drop(st1);

        // Session 2: reload the blob from disk under the passphrase, restore.
        let (config, blob) = load_for_unlock(&root).unwrap();
        let opened = seeds::open(&blob, pass, config.profile_id, config.argon2).unwrap();
        let materials2 = session_materials_from_unlock(
            opened.seeds,
            opened.key,
            opened.index_key,
            config,
            blob.clone(),
            vec![],
        )
        .unwrap();
        let mut st2 = GuiState::lobby_only();
        st2.set_profile(Profile::from_materials(materials2, root.clone()));

        // The circle survived relaunch: back in the rail + in the rejoin set.
        assert!(!st2.only_lobby(), "persisted circle restored into the rail");
        let rejoins = st2.persisted_rejoins();
        assert_eq!(rejoins.len(), 1, "exactly one persisted circle to rejoin");
        // The restored (canonicalized) phrase re-derives the ORIGINAL circle key.
        assert_eq!(
            derive_cot_key(&rejoins[0].1, &CNSA_2_0).unwrap().as_bytes(),
            derive_cot_key(STRONG, &CNSA_2_0).unwrap().as_bytes(),
            "the restored phrase re-derives the original circle key, byte-for-byte"
        );
        assert_eq!(
            st2.display_handle().as_deref(),
            Some("alice"),
            "the display handle survives reload"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// #115: leaving a circle drops it from the rail AND the blob (so it does not
    /// silently re-join next launch), and revealing a circle's phrase is gated on the
    /// unlock passphrase (an evil-maid guard) — the correct passphrase verifies, a
    /// wrong one fails closed.
    #[test]
    fn forget_circle_drops_it_from_disk_and_reveal_is_passphrase_gated() {
        use daemonseed_core::bootstrap::BootstrapAnchor;
        use daemonseed_core::first_start::FirstStart;
        use daemonseed_core::profile::config::ArgonParams;
        use daemonseed_core::profile::persist::{
            load_for_unlock, session_materials_from_unlock, write_first_start,
        };
        use daemonseed_core::storage::seeds;

        let _ = oxicrypt_module::initialize();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ds-gui-forget-test-{}-{nonce}", std::process::id()));
        let fast = ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let pass = "correct horse battery staple table mountain";

        let sealed = FirstStart::new().initialize(pass, fast).unwrap();
        let recovery = sealed.display_phrase();
        let materials = sealed
            .verify_round_trip(&recovery)
            .unwrap()
            .finalize(
                Some("alice".to_string()),
                BootstrapAnchor {
                    server_id: "relay#aabbccddeeff".to_string(),
                    address: "127.0.0.1:443".to_string(),
                },
            )
            .unwrap()
            .into_session_materials();
        write_first_start(&root, &materials, None, false).unwrap();

        // Session 1: join + persist a circle, inspect the gated reveal, then leave it.
        let mut st1 = GuiState::lobby_only();
        st1.set_profile(Profile::from_materials(materials, root.clone()));
        let idx = st1.materialize_from_phrase(STRONG).unwrap();
        st1.persist_circle(idx).unwrap();
        assert_eq!(
            st1.circle_phrase(idx).as_deref(),
            Some(STRONG),
            "the join phrase is reachable for export"
        );
        assert!(st1.circle_phrase(0).is_none(), "the Lobby has no phrase");
        assert!(
            st1.verify_passphrase(pass),
            "the correct passphrase verifies"
        );
        assert!(
            !st1.verify_passphrase("wrong words here please nope"),
            "a wrong passphrase fails closed (the evil-maid guard)"
        );
        st1.forget_circle(idx)
            .expect("forget drops the circle + re-seals");
        assert!(st1.only_lobby(), "the rail is back to just the Lobby");
        assert!(
            st1.persisted_rejoins().is_empty(),
            "no rejoin remains this session"
        );
        drop(st1);

        // Session 2: reload from disk — the forgotten circle does NOT come back.
        let (config, blob) = load_for_unlock(&root).unwrap();
        let opened = seeds::open(&blob, pass, config.profile_id, config.argon2).unwrap();
        let materials2 = session_materials_from_unlock(
            opened.seeds,
            opened.key,
            opened.index_key,
            config,
            blob.clone(),
            vec![],
        )
        .unwrap();
        let mut st2 = GuiState::lobby_only();
        st2.set_profile(Profile::from_materials(materials2, root.clone()));
        assert!(
            st2.only_lobby(),
            "the forgotten circle did not silently rejoin from disk"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// #107: a circle's read high-water survives a relaunch — persisted on close,
    /// seeded on restore — so backlog re-delivered after the restart does NOT
    /// re-trip the unread dot for already-seen messages, while a genuinely newer
    /// one still does.
    #[test]
    fn circle_high_water_persists_across_relaunch_and_suppresses_backlog_retrip() {
        use daemonseed_core::bootstrap::BootstrapAnchor;
        use daemonseed_core::first_start::FirstStart;
        use daemonseed_core::profile::config::ArgonParams;
        use daemonseed_core::profile::persist::{
            load_for_unlock, session_materials_from_unlock, write_first_start,
        };
        use daemonseed_core::storage::seeds;

        let _ = oxicrypt_module::initialize();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ds-gui-hw-test-{}-{nonce}", std::process::id()));
        let fast = ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let pass = "correct horse battery staple table mountain";
        let sealed = FirstStart::new().initialize(pass, fast).unwrap();
        let recovery = sealed.display_phrase();
        let materials = sealed
            .verify_round_trip(&recovery)
            .unwrap()
            .finalize(
                Some("alice".to_string()),
                BootstrapAnchor {
                    server_id: "relay#aabbccddeeff".to_string(),
                    address: "127.0.0.1:443".to_string(),
                },
            )
            .unwrap()
            .into_session_materials();
        write_first_start(&root, &materials, None, false).unwrap();

        // #131: now-relative timestamps so they're in-window (unclamped); captured once
        // so the persisted high-water survives verbatim into session 2.
        let now = now_unix_ms();
        let seen_ts = now - 2000;
        // Session 1: join + persist a circle, read it up to `seen_ts`, then close
        // (persist all circle high-waters).
        let mut st1 = GuiState::lobby_only();
        st1.set_profile(Profile::from_materials(materials, root.clone()));
        let idx = st1.materialize_from_phrase(STRONG).unwrap();
        st1.persist_circle(idx).unwrap();
        st1.switch_to(idx, String::new(), 0.0); // make it active
        st1.push_message(idx, "ally".into(), "seen".into(), false, seen_ts); // active → high_water
        assert_eq!(st1.metas()[idx].high_water_ms, seen_ts);
        st1.persist_all_circle_seen(); // the close hook
        drop(st1);

        // Session 2: reload from disk and restore — the circle's high-water is seeded.
        let (config, blob) = load_for_unlock(&root).unwrap();
        let opened = seeds::open(&blob, pass, config.profile_id, config.argon2).unwrap();
        let materials2 = session_materials_from_unlock(
            opened.seeds,
            opened.key,
            opened.index_key,
            config,
            blob.clone(),
            vec![],
        )
        .unwrap();
        let mut st2 = GuiState::lobby_only(); // active == 0 (Lobby); the circle is non-active
        st2.set_profile(Profile::from_materials(materials2, root.clone()));
        let cidx = st2
            .metas()
            .iter()
            .position(|c| c.net.is_some())
            .expect("the persisted circle restored");
        assert_eq!(
            st2.metas()[cidx].high_water_ms,
            seen_ts,
            "the read high-water was seeded from the blob on restore"
        );
        // Backlog at/below the seeded mark must NOT re-trip the dot after the restart.
        let raised = st2
            .push_message(cidx, "ally".into(), "re-swept".into(), false, seen_ts)
            .unread_raised;
        assert!(
            !raised,
            "relaunch backlog at the high-water must not re-trip unread"
        );
        assert!(!st2.metas()[cidx].unread);
        // A genuinely newer message still trips.
        let raised_new = st2
            .push_message(cidx, "ally".into(), "fresh".into(), false, now - 1000)
            .unread_raised;
        assert!(
            raised_new,
            "a message newer than the high-water still trips"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// #66: renaming an unlocked identity re-seals the at-rest blob, so the new
    /// display name persists across an unlock from disk; an invalid name is rejected
    /// and leaves the prior name intact.
    #[test]
    fn rename_identity_persists_the_new_name_across_reload() {
        use daemonseed_core::bootstrap::BootstrapAnchor;
        use daemonseed_core::first_start::FirstStart;
        use daemonseed_core::profile::config::ArgonParams;
        use daemonseed_core::profile::persist::{
            load_for_unlock, session_materials_from_unlock, write_first_start,
        };
        use daemonseed_core::storage::seeds;

        let _ = oxicrypt_module::initialize();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ds-gui-rename-test-{}-{nonce}", std::process::id()));
        let fast = ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let pass = "correct horse battery staple table mountain";

        // Enroll a NAMED profile "alice".
        let sealed = FirstStart::new().initialize(pass, fast).unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let materials = verified
            .finalize(
                Some("alice".to_string()),
                BootstrapAnchor {
                    server_id: "relay#aabbccddeeff".to_string(),
                    address: "127.0.0.1:443".to_string(),
                },
            )
            .unwrap()
            .into_session_materials();
        write_first_start(&root, &materials, None, false).unwrap();

        // Rename alice -> bob; the live handle updates.
        let mut st1 = GuiState::lobby_only();
        st1.set_profile(Profile::from_materials(materials, root.clone()));
        assert_eq!(st1.display_handle().as_deref(), Some("alice"));
        assert_eq!(st1.rename_identity("bob").unwrap(), "bob");
        assert_eq!(
            st1.display_handle().as_deref(),
            Some("bob"),
            "the live handle updates on rename"
        );
        // An invalid (line-break) name is rejected and leaves the name intact.
        assert!(st1.rename_identity("bad\nname").is_err());
        assert_eq!(st1.display_handle().as_deref(), Some("bob"));
        drop(st1);

        // Reload from disk under the passphrase: the renamed name persisted.
        let (config, blob) = load_for_unlock(&root).unwrap();
        let opened = seeds::open(&blob, pass, config.profile_id, config.argon2).unwrap();
        let materials2 = session_materials_from_unlock(
            opened.seeds,
            opened.key,
            opened.index_key,
            config,
            blob.clone(),
            vec![],
        )
        .unwrap();
        assert_eq!(
            materials2.display_name.as_deref(),
            Some("bob"),
            "the renamed display name persists across unlock"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// #66 doubles as the #65 recovery path: a profile created nameless (before the
    /// fix) can be given a name via rename, and that name then persists across unlock.
    #[test]
    fn rename_identity_names_a_nameless_pre_fix_profile() {
        use daemonseed_core::bootstrap::BootstrapAnchor;
        use daemonseed_core::first_start::FirstStart;
        use daemonseed_core::profile::config::ArgonParams;
        use daemonseed_core::profile::persist::{
            load_for_unlock, session_materials_from_unlock, write_first_start,
        };
        use daemonseed_core::storage::seeds;

        let _ = oxicrypt_module::initialize();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ds-gui-rename-nameless-{}-{nonce}",
            std::process::id()
        ));
        let fast = ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let pass = "correct horse battery staple table mountain";

        // Enroll a NAMELESS profile (finalize(None) — the pre-#65 state).
        let sealed = FirstStart::new().initialize(pass, fast).unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let materials = verified
            .finalize(
                None,
                BootstrapAnchor {
                    server_id: "relay#aabbccddeeff".to_string(),
                    address: "127.0.0.1:443".to_string(),
                },
            )
            .unwrap()
            .into_session_materials();
        assert!(
            materials.display_name.is_none(),
            "fixture: a nameless enrollment"
        );
        write_first_start(&root, &materials, None, false).unwrap();

        let mut st = GuiState::lobby_only();
        st.set_profile(Profile::from_materials(materials, root.clone()));
        // A nameless profile presents the formatted handle, not a chosen name.
        let before = st.display_handle().expect("a formatted-handle fallback");
        assert_ne!(before, "carol");
        // Recovery: set a name on the existing identity.
        assert_eq!(st.rename_identity("carol").unwrap(), "carol");
        assert_eq!(st.display_handle().as_deref(), Some("carol"));
        drop(st);

        // The recovered name persists across unlock.
        let (config, blob) = load_for_unlock(&root).unwrap();
        let opened = seeds::open(&blob, pass, config.profile_id, config.argon2).unwrap();
        let materials2 = session_materials_from_unlock(
            opened.seeds,
            opened.key,
            opened.index_key,
            config,
            blob.clone(),
            vec![],
        )
        .unwrap();
        assert_eq!(materials2.display_name.as_deref(), Some("carol"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// M16 publish-persistence round-trip: enroll → persist two published roots →
    /// reload the blob from disk → the kept root is back in `persisted_published()`
    /// (the auto-republish set) and the unpersisted one is gone. Mirrors the circle
    /// round-trip; this is the persistence half of ISC-DS5 (live restart→republish is
    /// the felt-test).
    #[test]
    fn profile_round_trips_published_shares_across_reload() {
        use daemonseed_core::bootstrap::BootstrapAnchor;
        use daemonseed_core::first_start::FirstStart;
        use daemonseed_core::profile::config::ArgonParams;
        use daemonseed_core::profile::persist::{
            load_for_unlock, session_materials_from_unlock, write_first_start,
        };
        use daemonseed_core::storage::seeds;

        let _ = oxicrypt_module::initialize();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ds-gui-pubpersist-test-{}-{nonce}",
            std::process::id()
        ));
        let fast = ArgonParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let pass = "correct horse battery staple table mountain";

        let sealed = FirstStart::new().initialize(pass, fast).unwrap();
        let phrase = sealed.display_phrase();
        let verified = sealed.verify_round_trip(&phrase).unwrap();
        let materials = verified
            .finalize(
                Some("alice".to_string()),
                BootstrapAnchor {
                    server_id: "relay#aabbccddeeff".to_string(),
                    address: "127.0.0.1:443".to_string(),
                },
            )
            .unwrap()
            .into_session_materials();
        write_first_start(&root, &materials, None, false).unwrap();

        // Session 1: adopt the profile, persist three published roots with mixed
        // name forms (#41: a custom name `Some` vs the basename default `None`),
        // re-persist one to prove the keyed idempotency leaves a stored name
        // untouched, unpersist one.
        let mut st1 = GuiState::lobby_only();
        st1.set_profile(Profile::from_materials(materials, root.clone()));
        assert!(
            st1.persisted_published().is_empty(),
            "nothing published on a fresh enrollment"
        );
        st1.persist_published("/home/alice/photos", Some("alice-photos"))
            .unwrap();
        st1.persist_published("/home/alice/docs", None).unwrap();
        st1.persist_published("/home/alice/music", Some("mixtape"))
            .unwrap();
        // Idempotent: re-publishing an existing root adds no duplicate AND does not
        // change the stored name (keyed on the root path).
        st1.persist_published("/home/alice/photos", Some("ignored-on-dup"))
            .unwrap();
        st1.unpersist_published("/home/alice/music").unwrap();
        drop(st1);

        // Session 2: reload the blob from disk under the passphrase.
        let (config, blob) = load_for_unlock(&root).unwrap();
        let opened = seeds::open(&blob, pass, config.profile_id, config.argon2).unwrap();
        let materials2 = session_materials_from_unlock(
            opened.seeds,
            opened.key,
            opened.index_key,
            config,
            blob.clone(),
            vec![],
        )
        .unwrap();
        let mut st2 = GuiState::lobby_only();
        st2.set_profile(Profile::from_materials(materials2, root.clone()));

        // The kept publishes survived relaunch with their persisted name forms
        // (#41): the custom name as `Some` (un-clobbered by the re-publish), the
        // basename default as `None`; the unpersisted root is gone.
        assert_eq!(
            st2.persisted_published(),
            vec![
                (
                    "/home/alice/photos".to_string(),
                    Some("alice-photos".to_string())
                ),
                ("/home/alice/docs".to_string(), None),
            ],
            "kept roots auto-republish with their persisted custom-name / basename-default forms"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The ephemeral path (no profile) never persists and never panics: joins work
    /// in RAM, `persist_circle` is a clean no-op, and there is nothing to rejoin.
    #[test]
    fn no_profile_means_no_persistence() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        assert_eq!(st.display_handle(), None);
        let idx = st.materialize_from_phrase(STRONG).unwrap();
        st.persist_circle(idx)
            .expect("persist is a no-op without a profile");
        // The circle is in RAM this session, but there is no persistence surface.
        assert!(!st.only_lobby());
    }

    // ── option A (#77 follow-up): per-room roster cache + repaint-on-switch ────

    #[test]
    fn set_room_roster_caches_to_the_lobby_and_active_roster_reads_it() {
        let mut st = GuiState::lobby_only();
        // The Lobby (circle_id None) is the active room at index 0.
        let roster = vec![crate::net::RosterEntry {
            handle: "alice#aabbccddeeff".into(),
            fingerprint: "#aabbccddeeff".into(),
        }];
        st.set_room_roster(None, roster.clone());
        assert_eq!(st.active_roster(), roster.as_slice());
    }

    #[test]
    fn set_room_roster_routes_to_the_matching_circle_not_the_lobby() {
        let _ = oxicrypt_module::initialize();
        let mut st = GuiState::lobby_only();
        let idx = st.materialize_from_phrase(STRONG).expect("materialize");
        st.switch_to(idx, String::new(), 0.0);
        let cid = st
            .active_circle_id()
            .expect("a materialized circle has a net id");
        let roster = vec![crate::net::RosterEntry {
            handle: "bob".into(),
            fingerprint: "#001122334455".into(),
        }];
        st.set_room_roster(Some(cid), roster.clone());
        // Active room is the circle → its cached roster is returned.
        assert_eq!(st.active_roster(), roster.as_slice());
        // A circle-scoped roster never leaked into the Lobby's cache.
        st.switch_to(0, String::new(), 0.0);
        assert!(st.active_roster().is_empty());
    }

    #[test]
    fn set_room_roster_drops_an_unknown_circle_id() {
        let mut st = GuiState::lobby_only();
        // No circle carries id 9999 — the roster is dropped (no panic), lobby untouched.
        st.set_room_roster(
            Some(9999),
            vec![crate::net::RosterEntry {
                handle: "ghost".into(),
                fingerprint: "#ffeeddccbbaa".into(),
            }],
        );
        assert!(st.active_roster().is_empty());
    }
}
