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

use std::collections::{BTreeMap, BTreeSet};

use daemonseed_core::circle::key::{CircleKey, CircleKeyError, circle_fingerprint, derive_cot_key};
use daemonseed_core::cot::AssetAddr;
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::dm::admission::AdmissionCounters;
use daemonseed_core::dm::keyrec::KemEncapsulationKey;
use daemonseed_core::dm::outbox::{Acceptance, DeliveryState};
use daemonseed_core::identity::keys::{ShareRootIkm, SignKeypair};
use daemonseed_core::trust_events::{TrustEventLog, TrustEventScope};
use daemonseed_veilid_net::SweepOutcome;
use daemonseed_veilid_net::dm::{
    CorrespondentState, DmEvent, PENDING_REQUEST_CAP, PkLt, RefusalReason, RequestId,
};

use crate::net::{DmSessionKeys, RosterEntry};
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
/// only what verifies, ISC-A-S3). `posts` are the verified announcement rows, ordered
/// newest `sent_unix_ms` first with ties broken by content-address slot key (#237) —
/// the pane renders the model in order, and the ordering is applied where the view is
/// built (`veilid_net::public_space_snapshot_event`), not here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnouncementsView {
    pub motd: Option<String>,
    pub posts: Vec<AnnouncementRow>,
}

// ── Unread-gated landing (#93 / D5, per-item marker #217) ────────────────────

/// Domain-separation prefix for a per-item announcements/MOTD content hash (#217).
/// Bump the tag on any change to the canonical encoding in [`item_content_hashes`].
const ANNOUNCE_ITEM_DOMAIN: &[u8] = b"daemonseed/announce-item/v1\0";

/// Kind tags inside the item hash, so a MOTD and a post whose rendered text happens
/// to coincide never produce the same item hash.
const ITEM_KIND_MOTD: u8 = 0;
const ITEM_KIND_POST: u8 = 1;

/// Separator between item hashes in the persisted marker. The seeds blob stores
/// `announce-seen <server_id> <value>` as a single two-token line, so the separator
/// MUST NOT be whitespace
/// ([`Seeds::set_announce_seen`](daemonseed_core::storage::seeds::Seeds::set_announce_seen)
/// rejects that outright).
const SEEN_SEPARATOR: char = ',';

/// The content hash of every item in a verified announcements/MOTD view (#217) —
/// the client-derived unread marker, one entry per displayed item, sorted and
/// deduplicated so the value is a deterministic set (the relay's served order never
/// changes it).
///
/// **Per item, not per view.** Operator content folds in ONE ITEM AT A TIME — each
/// verified announcement and the MOTD arrives as its own inbound and pushes its own
/// `PublicSpaceSnapshot` — so during the startup warmup the view is observed in a
/// sequence of partial states. A marker covering the whole view is invalidated by
/// every one of those arrivals, so marking a partial view seen guarantees the dot
/// re-trips when the next item lands (#217), and re-delivered already-read content
/// re-fires it (#158). A per-item marker is monotone instead: an item already seen
/// stays seen no matter what folds in beside it afterwards.
///
/// Each item is kind-tagged and length-prefixed inside a domain-separated buffer so
/// no field concatenation is ambiguous, then hashed with SHA-384
/// ([`content_address`](daemonseed_core::public_space::content_address)) and rendered
/// as lowercase hex. The value is a local marker only, never a wire artifact: it is
/// compared solely to the per-relay marker persisted in
/// [`Seeds`](daemonseed_core::storage::seeds::Seeds).
pub fn item_content_hashes(view: &AnnouncementsView) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(view.posts.len() + 1);
    // An empty MOTD is ABSENT, not an item. `render_motd` yields `""` when the payload
    // fails to decode or sanitizes away entirely, and `verify_served_motd` checks only
    // the signature — so `Some("")` is reachable, and `apply_announcements` hides the
    // MOTD area for it. Hashing it would raise the dot for content the pane does not
    // display.
    if let Some(motd) = view.motd.as_deref().filter(|m| !m.is_empty()) {
        out.push(item_hash(ITEM_KIND_MOTD, &[motd.as_bytes()], &[]));
    }
    for p in &view.posts {
        out.push(item_hash(
            ITEM_KIND_POST,
            &[p.topic.as_bytes(), p.body.as_bytes()],
            &[p.sent_unix_ms],
        ));
    }
    out.sort();
    out.dedup();
    out
}

/// One item's hash: domain ‖ kind ‖ each length-prefixed field ‖ each numeric field.
///
/// The empty-string fallback is the same one `content_address` has always carried —
/// its only error path is SHA-384's power-up self-test not having passed yet (the
/// first crypto call in a fresh process), unreachable once the client has initialized
/// oxicrypt at startup, and it never collides with a real digest in practice.
fn item_hash(kind: u8, fields: &[&[u8]], nums: &[i64]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(ANNOUNCE_ITEM_DOMAIN);
    buf.push(kind);
    for f in fields {
        buf.extend_from_slice(&(f.len() as u64).to_le_bytes());
        buf.extend_from_slice(f);
    }
    for n in nums {
        buf.extend_from_slice(&n.to_le_bytes());
    }
    daemonseed_core::public_space::content_address(&buf)
        .map(|a| a.to_string())
        .unwrap_or_default()
}

/// Encode a seen-item set for persistence, joined by [`SEEN_SEPARATOR`].
pub fn encode_seen<S: AsRef<str>>(items: &[S]) -> String {
    items
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(&SEEN_SEPARATOR.to_string())
}

/// The marker to persist when the user reads the pane, or `None` when nothing should
/// be written.
///
/// **Union, never replace.** Operator content folds in one item at a time, so the
/// pane is routinely read while the view is still partially converged. Persisting
/// just the items on display would then DROP items read earlier — the marker narrows,
/// and when the missing item folds back in the dot fires on content the user has
/// already read. That is the very bug this whole change exists to fix, and writing
/// the displayed set straight out reintroduced it on the write side.
///
/// **Never write an empty marker.** `refresh_public_space` emits a snapshot of
/// whatever `OperatorSpace` holds the moment the tab is opened, which during warmup is
/// nothing at all; and a pre-init crypto failure degenerates every item hash to `""`.
/// Either would otherwise persist an empty marker over a good one, wiping the
/// read-state. An empty view is not evidence that the user read nothing; it is
/// evidence of nothing.
///
/// **No ceiling.** An earlier cut capped the marker and evicted the overflow, on the
/// argument that a dropped hash must belong to content no longer served. That argument
/// is false precisely because of the partial convergence above: an item that IS served
/// but has not folded in yet is absent from `current_items` and was therefore eligible
/// for eviction, so a read during warmup could drop an already-read item and re-flag it
/// when it arrived — the bug this function exists to prevent. The cap also truncated
/// `current_items` itself once the view exceeded it, wedging the dot on permanently
/// with no error anywhere. Both failures were silent, and both were worse than the
/// growth they guarded against: the marker is bounded in practice by the number of
/// distinct operator items ever published, at 97 bytes each, and only the operator can
/// publish. If that ever becomes a real bound, the fix is to prune against a converged
/// view — never against a partial one.
pub fn merge_seen(current_items: &[String], stored: Option<&str>) -> Option<String> {
    // Drop any item whose hash could not be computed (the `item_hash` pre-init
    // fallback). An item we failed to hash is not evidence that anything was read, and
    // a marker of nothing must never overwrite a good one.
    let current_items: Vec<&str> = current_items
        .iter()
        .map(String::as_str)
        .filter(|h| !h.is_empty())
        .collect();
    if current_items.is_empty() {
        return None; // nothing verified on display — never overwrite a good marker
    }
    let carried: BTreeSet<&str> = stored.map(decode_seen).unwrap_or_default();

    // `current_items` is already sorted+deduped by `item_content_hashes`, but this is
    // `pub` and the sort below makes the result independent of that holding.
    let mut merged: Vec<&str> = current_items.clone();
    merged.extend(carried.into_iter().filter(|h| !current_items.contains(h)));
    merged.sort_unstable();
    merged.dedup();

    Some(encode_seen(&merged))
}

/// Decode a persisted seen-item marker into the set of item hashes it covers.
fn decode_seen(stored: &str) -> BTreeSet<&str> {
    stored
        .split(SEEN_SEPARATOR)
        .filter(|s| !s.is_empty())
        .collect()
}

/// #142/#217: whether the Announcements tab should show an unread dot — the verified
/// content is non-empty AND at least one item on display has not been seen. The caller
/// passes `current_items` (its own [`item_content_hashes`] of the view) in, so they are
/// computed once per snapshot — it also needs them for the seen-marker persist.
///
/// The empty-view guard means an unconverged / genuinely-empty view never trips a
/// spurious dot. Replaces the #93 connect-time auto-landing: the client NEVER
/// force-opens the pane (a rude yank for rare operator content, and it could land on a
/// not-yet-converged blank view); the dot is a non-intrusive indicator that behaves
/// identically on connect and mid-session, mirroring the room unread dot (#64).
pub fn announcements_unread(
    view: &AnnouncementsView,
    current_items: &[String],
    stored: Option<&str>,
) -> bool {
    // Empty-view guard — nothing to be unread about. An empty-string MOTD counts as
    // absent here for the same reason `item_content_hashes` skips it: the pane does not
    // display it.
    if view.motd.as_deref().unwrap_or("").is_empty() && view.posts.is_empty() {
        return false;
    }
    let Some(stored) = stored else {
        return true; // never seen → unread
    };
    let seen = decode_seen(stored);
    current_items.iter().any(|h| !seen.contains(h.as_str()))
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

/// (#339) One correspondence, as the driver has reported it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DmCorrespondence {
    /// What the driver's startup DM roster said this correspondence is.
    ///
    /// `None` until a roster names it, which is every correspondence the driver
    /// first heard of while running — an entry created by a delivery or a
    /// teardown carries no state, because nothing has said what state it is in.
    /// Absence is therefore "not stated", never a fourth state.
    pub state: Option<CorrespondentState>,
    /// The last state reported per sequence number, newest wins.
    ///
    /// A map rather than a list because `Delivery` is a *replacement*: a seq
    /// climbs `Composed → OnDht → ConfirmedCollected` and the UI shows where it
    /// is now, never the path it took.
    pub deliveries: BTreeMap<u64, DeliveryState>,
    /// Sequence numbers a loud teardown left undelivered, in arrival order.
    pub undelivered: Vec<u64>,
}

/// (#339) The DM state one session has accumulated from [`DmEvent`]s.
///
/// Deliberately a *record of what was said*, not a model of the conversation:
/// the driver owns every DM decision, and this holds only what a surface would
/// need to draw. Nothing here is persisted — the driver's own store is the
/// durable half, and a restart re-derives this from a fresh session's events.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DmState {
    /// Contact requests the driver has surfaced, keyed by [`RequestId`] — a
    /// `Vec` because `RequestId` is neither `Hash` nor `Ord`.
    ///
    /// **Capped at [`PENDING_REQUEST_CAP`], the driver's own held-request
    /// bound, and the oldest row is dropped to make room.** Nothing removes a
    /// row otherwise: there is no accept or decline event, so a request answered
    /// by the user stays here until an interface exists to retire it, and without
    /// the cap the list would grow for the life of the session. The driver
    /// cannot hold more than this many at once, so a longer list here would
    /// hold requests the driver has already forgotten.
    ///
    /// A repeat of a request already held replaces it rather than adding a
    /// second row: the driver re-surfaces an unanswered knock on every sweep.
    pub requests: Vec<DmContactRequest>,
    /// Correspondences this session has heard about, keyed by the
    /// correspondent's long-term identity key.
    pub correspondences: BTreeMap<PkLt, DmCorrespondence>,
    /// The last refusal, whole: who it was for, how far it got, and why it
    /// stopped. One slot, because a refusal is a thing the user is told once.
    pub last_refusal: Option<DmRefusal>,
    /// The last doorbell-health report — the sweep's GET accounting, admission's
    /// cumulative counters, and the slots this sweep skipped.
    pub last_doorbell_health: Option<DmDoorbellHealth>,
    /// The last per-correspondence channel-health report.
    pub last_channel_health: Option<DmChannelHealth>,
    /// How many idle ticks could not read the profile's block-list record.
    ///
    /// **Counted rather than dropped, because it is an alarm and not a
    /// counter the driver keeps.** Every other observability-only event has a
    /// second symptom somewhere — a refusal, a health counter, a request that
    /// does not arrive. This one's whole symptom is silence: the channel plane
    /// fails closed while the record is unreadable, so every conversation stops
    /// collecting and nothing else says why. Nothing renders it yet; a surface
    /// that wants to warn has the number here rather than having to re-derive
    /// it from an absence.
    pub block_list_unreadable_ticks: u64,
}

/// A correspondent's identity key, as a trace line may show it: the marker only.
/// The key itself is 2592 bytes and names a person. Mirrors the redaction
/// `daemonseed_veilid_net::dm::DmEvent` applies to the same values.
fn redacted_pk(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("PkLt(..)")
}

impl std::fmt::Debug for DmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written because the derive would print every `PkLt` map key in
        // full — the same 2592 bytes naming a person that `DmEvent`'s own
        // `Debug` redacts, arriving here by a different route.
        f.debug_struct("DmState")
            .field("requests", &self.requests)
            .field("correspondences", &self.correspondences.len())
            .field("last_refusal", &self.last_refusal)
            .field("last_doorbell_health", &self.last_doorbell_health)
            .field("last_channel_health", &self.last_channel_health)
            .field(
                "block_list_unreadable_ticks",
                &self.block_list_unreadable_ticks,
            )
            .finish()
    }
}

/// (#339) A pending contact request as the user would answer it.
#[derive(Clone, PartialEq, Eq)]
pub struct DmContactRequest {
    /// The request the accept / decline names.
    pub request: RequestId,
    /// The knocker's long-term identity key.
    pub from: PkLt,
    /// The first message body.
    pub body: String,
    /// When the knocker says it was sent, in unix milliseconds.
    pub sent_unix_ms: i64,
}

impl std::fmt::Debug for DmContactRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The body is a stranger's plaintext message and `from` names a person:
        // a trace line is the last place either belongs. Length and marker only,
        // exactly as `DmEvent::ContactRequest` prints them.
        write!(f, "DmContactRequest {{ request: {:?}, from: ", self.request)?;
        redacted_pk(f)?;
        write!(
            f,
            ", body_len: {}, sent_unix_ms: {} }}",
            self.body.len(),
            self.sent_unix_ms
        )
    }
}

/// (#339) The last refusal, held whole so a surface can say why.
#[derive(Clone, PartialEq, Eq)]
pub struct DmRefusal {
    /// The intended recipient.
    pub to: PkLt,
    /// How far the send got.
    pub acceptance: Acceptance,
    /// Where it stopped.
    pub reason: RefusalReason,
}

impl std::fmt::Debug for DmRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DmRefusal { to: ")?;
        redacted_pk(f)?;
        write!(
            f,
            ", acceptance: {:?}, reason: {:?} }}",
            self.acceptance, self.reason
        )
    }
}

/// (#339) The last [`DmEvent::DoorbellHealth`], flattened.
///
/// Derives `Debug`: every field is a counter about this side's own sweep, and
/// none of them names a correspondent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmDoorbellHealth {
    /// The sweep's GET accounting.
    pub outcome: SweepOutcome,
    /// Admission's cumulative accounting.
    pub admission: AdmissionCounters,
    /// Slots this sweep skipped because the held-request list was full.
    pub pending_full: u64,
}

/// (#339) The last [`DmEvent::ChannelHealth`], flattened.
#[derive(Clone, PartialEq, Eq)]
pub struct DmChannelHealth {
    /// The correspondent the counters belong to.
    pub with: PkLt,
    /// Sweeps refused because the transport did not read every slot.
    pub partial_sweeps: u64,
    /// Frames whose ratchet position was already consumed.
    pub already_consumed: u64,
    /// Frames that did not open or did not verify.
    pub unopenable: u64,
    /// Unsettled positions left alone for want of the peer's pseudonym key.
    pub peer_pseudonym_unknown: u64,
    /// Peer acknowledgements that would not merge.
    pub peer_acks_deferred: u64,
    /// Peer acknowledgements clipped to what this side has actually sent.
    pub peer_acks_clipped: u64,
    /// Standalone acknowledgement records that did not verify.
    pub peer_acks_unverified: u64,
    /// Receive-cursor records found unreadable and replaced.
    pub cursor_records_repaired: u64,
    /// Re-establishment legs that opened and whose fold could not finish.
    pub leg_folds_deferred: u64,
    /// Queued re-establishment legs whose record address would not derive.
    pub leg_unaddressable: u64,
}

impl std::fmt::Debug for DmChannelHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The counters are harmless; `with` is a person's identity key.
        f.write_str("DmChannelHealth { with: ")?;
        redacted_pk(f)?;
        write!(
            f,
            ", partial_sweeps: {}, already_consumed: {}, unopenable: {}, \
             peer_pseudonym_unknown: {}, peer_acks_deferred: {}, peer_acks_clipped: {}, \
             peer_acks_unverified: {}, cursor_records_repaired: {} }}",
            self.partial_sweeps,
            self.already_consumed,
            self.unopenable,
            self.peer_pseudonym_unknown,
            self.peer_acks_deferred,
            self.peer_acks_clipped,
            self.peer_acks_unverified,
            self.cursor_records_repaired
        )
    }
}

impl DmState {
    /// Fold one driver event.
    ///
    /// Observability-only variants ([`DmEvent::ContactLookupFailed`],
    /// [`DmEvent::BlockListFull`] and the rest) are accepted and dropped: no
    /// interface renders them yet, and inventing state for them here would be
    /// state no reader could check. [`DmEvent::BlockListUnreadable`] is the
    /// exception and is counted: it is an alarm whose only other symptom is a
    /// channel plane that has gone quiet, so dropping it leaves nothing to
    /// check at all.
    fn fold(&mut self, event: &DmEvent) {
        match event {
            DmEvent::ContactRequest {
                request,
                from,
                body,
                sent_unix_ms,
            } => {
                let row = DmContactRequest {
                    request: request.clone(),
                    from: from.clone(),
                    body: body.clone(),
                    sent_unix_ms: *sent_unix_ms,
                };
                match self.requests.iter_mut().find(|r| r.request == *request) {
                    Some(existing) => *existing = row,
                    None => {
                        // The driver holds at most this many, so a longer list
                        // here would show requests it has already forgotten.
                        // Oldest out, because the newest knock is the one the
                        // user has not seen.
                        if self.requests.len() >= PENDING_REQUEST_CAP {
                            self.requests.remove(0);
                        }
                        self.requests.push(row);
                    }
                }
            }
            DmEvent::Roster { correspondents } => {
                for correspondent in correspondents {
                    // Merged into the map rather than replacing it: a roster is
                    // a statement about what is on disk, and an entry this
                    // session made for a correspondence the store has not
                    // recorded yet is not something the roster contradicts.
                    self.correspondences
                        .entry(correspondent.pk_lt.clone())
                        .or_default()
                        .state = Some(correspondent.state);
                }
            }
            DmEvent::Delivery { to, seq, state } => {
                self.correspondences
                    .entry(to.clone())
                    .or_default()
                    .deliveries
                    .insert(*seq, *state);
            }
            DmEvent::Refused {
                to,
                acceptance,
                reason,
                // Matched by name rather than by `..`: a field added to
                // `Refused` must break this fold rather than be dropped
                // silently. The key is folded by the caller, which is where
                // the audit log lives.
                event: _,
            } => {
                self.last_refusal = Some(DmRefusal {
                    to: to.clone(),
                    acceptance: *acceptance,
                    reason: *reason,
                });
            }
            DmEvent::ChannelLost { with, surfaced, .. } => {
                let c = self.correspondences.entry(with.clone()).or_default();
                c.undelivered.extend(surfaced.iter().copied());
            }
            DmEvent::DoorbellHealth {
                outcome,
                admission,
                pending_full,
            } => {
                self.last_doorbell_health = Some(DmDoorbellHealth {
                    outcome: *outcome,
                    admission: *admission,
                    pending_full: *pending_full,
                });
            }
            DmEvent::ChannelHealth {
                with,
                partial_sweeps,
                already_consumed,
                unopenable,
                peer_pseudonym_unknown,
                peer_acks_deferred,
                peer_acks_clipped,
                peer_acks_unverified,
                cursor_records_repaired,
                leg_folds_deferred,
                leg_unaddressable,
            } => {
                self.last_channel_health = Some(DmChannelHealth {
                    with: with.clone(),
                    partial_sweeps: *partial_sweeps,
                    already_consumed: *already_consumed,
                    unopenable: *unopenable,
                    peer_pseudonym_unknown: *peer_pseudonym_unknown,
                    peer_acks_deferred: *peer_acks_deferred,
                    peer_acks_clipped: *peer_acks_clipped,
                    peer_acks_unverified: *peer_acks_unverified,
                    cursor_records_repaired: *cursor_records_repaired,
                    leg_folds_deferred: *leg_folds_deferred,
                    leg_unaddressable: *leg_unaddressable,
                });
            }
            DmEvent::BlockListUnreadable => {
                self.block_list_unreadable_ticks =
                    self.block_list_unreadable_ticks.saturating_add(1);
            }
            // Nothing a fold could add and no interface that renders them: an
            // accepted request stays held by the driver, a message has no view,
            // and the rest are counters the driver already keeps. The one event
            // that is an alarm rather than a counter — `BlockListUnreadable`,
            // whose only other symptom is silence — is folded above instead.
            DmEvent::Message { .. }
            | DmEvent::AcceptFailed { .. }
            | DmEvent::ChannelDirectionUnknown { .. }
            // Its audit entry is written above, where every classed key is. The
            // fold adds nothing to `dm`: recovery is under way and bounded, and
            // there is no per-correspondence state a reader could act on.
            | DmEvent::ReestablishmentAnomaly { .. }
            | DmEvent::ContactLookupFailed
            | DmEvent::BlockListFull { .. }
            | DmEvent::BlockListProvisioned
            | DmEvent::SpentTokensNotPersisted => {}
        }
    }
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
    /// The announcements/MOTD view currently ON SCREEN — the last one applied to the
    /// pane (#229). Read-state has to follow what the user actually saw, not what the
    /// network last delivered: opening the tab fires a refresh that answers with an
    /// error rather than a snapshot whenever the operator record is unsubscribed, and
    /// nothing clears the pane on disconnect, so the user reads content that no
    /// subsequent event covers. Retaining it lets the tab-open handler mark exactly
    /// what is displayed as seen, independent of whether any event arrives.
    announcements_on_screen: AnnouncementsView,
    /// (#339) What the DM driver has told this session. Folded by
    /// [`GuiState::on_dm_event`] and rendered nowhere yet: no interface draws
    /// it.
    dm: DmState,
    /// The ISC-C28 trust-event audit log: bounded, in-memory, and the sink every
    /// classed event this session raises is written to.
    ///
    /// **It exists here because ISC-A-C12 makes the entry non-optional**, not
    /// because something draws it — no interface does yet, exactly as with `dm`
    /// above. A teardown that arrived with nowhere to be recorded would be the
    /// silent loss the loud-teardown design (`docs/design/direct-messaging.md`)
    /// was written to end, so the log lands before the affordance rather than
    /// after it.
    trust_log: TrustEventLog,
    /// The project-announce seed variable's value, if this process was launched
    /// with one: taken out of the environment at startup and held here so every
    /// `Connect` can hand it to the net actor, which loads the operator credential
    /// from it (or from the seed file under the profile root). `None` on every
    /// instance that is not the operator.
    project_announce_seed: Option<daemonseed_core::public_space::ProjectAnnounceSeedText>,
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
            announcements_on_screen: AnnouncementsView::default(),
            dm: DmState::default(),
            trust_log: TrustEventLog::default(),
            project_announce_seed: None,
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

    /// Hold the project-announce seed variable's value for the session's Connects.
    pub fn set_project_announce_seed(
        &mut self,
        value: Option<daemonseed_core::public_space::ProjectAnnounceSeedText>,
    ) {
        self.project_announce_seed = value;
    }

    /// The project-announce seed variable's value, for `NetCommand::Connect`. A
    /// clone is another zeroed-on-drop buffer.
    pub fn project_announce_seed(
        &self,
    ) -> Option<daemonseed_core::public_space::ProjectAnnounceSeedText> {
        self.project_announce_seed.clone()
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

    /// (#232) The unlocked profile's STABLE ML-KEM-1024 encapsulation key — the
    /// public half the DM key record publishes (ISC-C40). `None` on the ephemeral /
    /// no-profile path: that session has no persistent identity, so it is not
    /// DM-reachable and must not publish a key record.
    pub fn stable_kem_encapsulation_key(&self) -> Option<KemEncapsulationKey> {
        self.profile
            .as_ref()
            .and_then(|p| p.stable_kem_encapsulation_key().ok())
    }

    /// (#339) Derive the secret DM halves for the driver this connect will spawn.
    /// `None` on the ephemeral / no-profile path, or if derivation fails — each of
    /// which means this session is not DM-reachable and no driver is spawned.
    pub fn dm_session_keys(&self) -> Option<Box<DmSessionKeys>> {
        self.profile.as_ref().and_then(|p| p.dm_session_keys().ok())
    }

    /// (#339) What the DM driver has told this session. Read-only; the fold is
    /// [`Self::on_dm_event`]'s.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn dm_state(&self) -> &DmState {
        &self.dm
    }

    /// The ISC-C28 trust-event audit log. Read-only; the writes are
    /// [`Self::on_dm_event`]'s.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn trust_log(&self) -> &TrustEventLog {
        &self.trust_log
    }

    /// (#339) Fold one DM driver event. Renders nothing: no interface draws it.
    ///
    /// An event carrying a classed key is the one thing that leaves a record
    /// beyond `dm`, and ISC-A-C12 forbids skipping the audit entry the taxonomy
    /// owes it. Three arrive that way — a lost channel, the refusal an
    /// introduction ends in, and A3.8's re-establishment anomalies, whose class
    /// is `PersistentNonBlocking` exactly as a teardown's is. A refusal that
    /// tore nothing down carries no key and folds nothing.
    pub fn on_dm_event(&mut self, event: &DmEvent) {
        match event {
            DmEvent::ChannelLost { event: key, .. }
            | DmEvent::ReestablishmentAnomaly { event: key, .. }
            | DmEvent::Refused {
                event: Some(key), ..
            } => self
                .trust_log
                .append(TrustEventScope::bare(*key).observed_at(now_unix_ms(), None, None)),
            _ => {}
        }
        self.dm.fold(event);
    }

    /// (#229) Record the announcements/MOTD view now rendered in the pane.
    pub fn set_announcements_on_screen(&mut self, view: AnnouncementsView) {
        self.announcements_on_screen = view;
    }

    /// (#229) Mark everything currently ON SCREEN in the announcements pane as seen,
    /// persisting the merged marker for `server_id`.
    ///
    /// This is the single place read-state is recorded, and it is driven by what is
    /// displayed rather than by an inbound event. Binding it to the event instead meant
    /// that opening the tab while the operator record was unsubscribed — a refresh that
    /// answers `PublicSpaceError`, with the pane still showing the last content it
    /// received — recorded nothing at all, and the dot re-fired later on content the
    /// user had plainly read (#229).
    ///
    /// `Ok(false)` means there was nothing to record: an empty pane, or a marker that
    /// already covers it. A persist failure is surfaced as `Err(reason)`.
    pub fn mark_announcements_seen(&mut self, server_id: &str) -> Result<bool, String> {
        let items = item_content_hashes(&self.announcements_on_screen);
        let stored = self.announce_seen_hash(server_id);
        match merge_seen(&items, stored.as_deref()) {
            // `persist_announce_seen` reports whether the stored value actually moved,
            // so an unchanged marker reports `false` and skips the re-seal — which is
            // what keeps the ~30 s poll from re-sealing the blob on every tick.
            Some(marker) => self.persist_announce_seen(server_id, &marker),
            None => Ok(false),
        }
    }

    /// (#93/#217) The per-relay seen-item marker for `server_id`, read from the
    /// unlocked profile's blob — the [`encode_seen`] set of announcements/MOTD items
    /// the user has read. `None` on the ephemeral (no-profile) path or when this relay
    /// has never been marked seen. Returns an owned `String` so the caller does not
    /// hold a borrow across the subsequent `persist_announce_seen` write-through.
    pub fn announce_seen_hash(&self, server_id: &str) -> Option<String> {
        self.profile
            .as_ref()
            .and_then(|p| p.announce_seen(server_id).map(str::to_owned))
    }

    /// (#93/#217) Write-through: record `marker` as the seen-item set for `server_id`
    /// (an [`encode_seen`] value) and re-seal the blob, so the unread gate bypasses
    /// those items next connect. `Ok(true)` when the stored value moved, `Ok(false)`
    /// when it was unchanged or there is no profile (the ephemeral path); a disk / seal
    /// failure is surfaced as `Err(reason)`. Callers want
    /// [`Self::mark_announcements_seen`], which derives the marker from what is on
    /// screen; this is the raw write-through beneath it.
    fn persist_announce_seen(&mut self, server_id: &str, marker: &str) -> Result<bool, String> {
        match self.profile.as_mut() {
            Some(p) => p.persist_announce_seen(server_id, marker),
            None => Ok(false),
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
            announcements_on_screen: AnnouncementsView::default(),
            dm: DmState::default(),
            trust_log: TrustEventLog::default(),
            project_announce_seed: None,
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let empty = ann_view(None, &[]);
        let empty_items = item_content_hashes(&empty);
        let content = ann_view(Some("relay is up"), &[("a", "x", 1)]);
        let content_items = item_content_hashes(&content);
        let content_seen = encode_seen(&content_items);
        // Empty view → never unread (empty-view guard), even with nothing stored — an
        // unconverged/blank view must not trip a spurious dot.
        assert!(!announcements_unread(&empty, &empty_items, None));
        // Non-empty, never seen → unread.
        assert!(announcements_unread(&content, &content_items, None));
        // Non-empty, stored marker covers none of the items → unread.
        assert!(announcements_unread(
            &content,
            &content_items,
            Some("stale")
        ));
        // An empty stored marker covers nothing.
        assert!(announcements_unread(&content, &content_items, Some("")));
        // Non-empty, every item seen → not unread.
        assert!(!announcements_unread(
            &content,
            &content_items,
            Some(&content_seen)
        ));
    }

    #[test]
    fn viewing_updates_the_seen_marker_then_clears_unread() {
        // Mirrors the GUI write-through: a first arrival is unread; once the displayed
        // items are stored (the "viewing marks it seen" step), the SAME content is no
        // longer unread (the dot clears).
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let view = ann_view(Some("relay is up"), &[("announcements", "v2", 5)]);
        let current = item_content_hashes(&view);

        let mut seeds = daemonseed_core::storage::seeds::Seeds::new(
            daemonseed_core::identity::mnemonic::Mnemonic::generate().unwrap(),
        );
        assert!(
            announcements_unread(&view, &current, seeds.announce_seen("fra1#abc")),
            "first arrival is unread"
        );
        assert!(seeds.set_announce_seen("fra1#abc", encode_seen(&current)));
        assert!(
            !announcements_unread(&view, &current, seeds.announce_seen("fra1#abc")),
            "after viewing, the same content is no longer unread"
        );
    }

    /// #217: the reported startup sequence. Operator content folds in one item at a
    /// time, so the pane is observed partially converged; reading it there must not
    /// arm a second dot when the remaining item lands. A marker hashing the whole view
    /// cannot express this — the posts-only and posts-plus-MOTD views hash differently
    /// by construction, so the MOTD's arrival always invalidated a marker persisted one
    /// snapshot earlier, no matter that the post itself had been read.
    #[test]
    fn reading_a_partially_converged_view_is_not_re_flagged_by_the_rest_of_the_burst() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let mut seeds = daemonseed_core::storage::seeds::Seeds::new(
            daemonseed_core::identity::mnemonic::Mnemonic::generate().unwrap(),
        );

        // Snapshot 1 — the announcement folds in; the MOTD has not arrived yet.
        let announcements_only = ann_view(None, &[("release", "v0.36.1 is out", 5)]);
        let items_1 = item_content_hashes(&announcements_only);
        assert!(
            announcements_unread(
                &announcements_only,
                &items_1,
                seeds.announce_seen("fra1#abc")
            ),
            "the first genuinely-new content raises the dot"
        );
        // The user opens the pane here — mid-convergence — so this partial view is seen.
        seeds.set_announce_seen("fra1#abc", encode_seen(&items_1));

        // Snapshot 2 — the MOTD arrives, carrying the same announcement alongside it.
        let with_motd = ann_view(
            Some("network is warming up"),
            &[("release", "v0.36.1 is out", 5)],
        );
        let items_2 = item_content_hashes(&with_motd);
        assert!(
            announcements_unread(&with_motd, &items_2, seeds.announce_seen("fra1#abc")),
            "the MOTD is genuinely unseen content, so it does raise the dot"
        );
        // ...and reading once more settles it. The already-seen announcement is NOT
        // re-flagged by the MOTD's arrival — that re-flagging is #217.
        seeds.set_announce_seen("fra1#abc", encode_seen(&items_2));
        assert!(
            !announcements_unread(&with_motd, &items_2, seeds.announce_seen("fra1#abc")),
            "the converged view settles clear"
        );

        // The whole burst arriving with the pane NEVER opened raises the dot once and
        // leaves it raised — no clear-then-re-raise flicker across the convergence.
        let mut fresh = daemonseed_core::storage::seeds::Seeds::new(
            daemonseed_core::identity::mnemonic::Mnemonic::generate().unwrap(),
        );
        for view in [&announcements_only, &with_motd] {
            let items = item_content_hashes(view);
            assert!(
                announcements_unread(view, &items, fresh.announce_seen("fra1#abc")),
                "every step of the burst reads unread — the dot never drops mid-convergence"
            );
        }
        let _ = &mut fresh;
    }

    /// The persist path must never narrow the marker. Opening the pane fires a refresh
    /// that snapshots whatever has converged so far, so a read routinely lands on a
    /// partial view; writing just those items would drop already-read ones and re-flag
    /// them when they fold back in.
    #[test]
    fn persisting_a_partial_view_keeps_items_read_earlier() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let full = ann_view(Some("motd"), &[("a", "x", 1)]);
        let stored = merge_seen(&item_content_hashes(&full), None).unwrap();

        // A new process: the MOTD has folded in, the post has not.
        let partial = ann_view(Some("motd"), &[]);
        let narrowed = merge_seen(&item_content_hashes(&partial), Some(&stored)).unwrap();

        // The post read last session survives, so its later arrival raises nothing.
        assert!(!announcements_unread(
            &full,
            &item_content_hashes(&full),
            Some(&narrowed)
        ));
    }

    /// An empty or degenerate view must never overwrite a good marker. Two ways in: the
    /// tab-open refresh snapshots an unconverged (empty) `OperatorSpace`, and a pre-init
    /// crypto failure degenerates every item hash to `""`.
    #[test]
    fn an_empty_view_never_overwrites_the_stored_marker() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let view = ann_view(Some("motd"), &[("a", "x", 1)]);
        let stored = merge_seen(&item_content_hashes(&view), None).unwrap();

        let empty = ann_view(None, &[]);
        assert_eq!(
            merge_seen(&item_content_hashes(&empty), Some(&stored)),
            None,
            "an unconverged view must decline to write"
        );
        // The degenerate all-empty-hash case reduces to the same nothing.
        assert_eq!(merge_seen(&[String::new()], Some(&stored)), None);
    }

    /// A read never narrows the marker, whatever the sizes involved. An earlier cut
    /// capped it and evicted the overflow, which silently produced two failures: a view
    /// larger than the cap had its own displayed items truncated away, wedging the dot
    /// on forever; and at the cap a partially-converged read evicted already-read items
    /// that simply had not folded in yet, re-flagging them when they arrived.
    #[test]
    fn a_read_never_drops_an_already_seen_item() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();

        // A large stored set plus a small converged view: everything survives.
        let carried: Vec<String> = (0..600).map(|i| format!("{i:096x}")).collect();
        let stored = encode_seen(&carried);
        let view = ann_view(Some("motd"), &[("a", "x", 1)]);
        let current = item_content_hashes(&view);
        let merged = merge_seen(&current, Some(&stored)).unwrap();
        let set = decode_seen(&merged);
        for h in carried
            .iter()
            .map(String::as_str)
            .chain(current.iter().map(String::as_str))
        {
            assert!(set.contains(h), "nothing already seen may be dropped");
        }
        assert!(!announcements_unread(&view, &current, Some(&merged)));

        // The partial-convergence case: read while only one of many items has folded in,
        // then let the rest arrive. None of them may re-flag.
        let full = ann_view(Some("motd"), &[("a", "x", 1), ("b", "y", 2), ("c", "z", 3)]);
        let full_items = item_content_hashes(&full);
        let settled = merge_seen(&full_items, Some(&stored)).unwrap();
        let partial = ann_view(None, &[("b", "y", 2)]);
        let after_partial_read =
            merge_seen(&item_content_hashes(&partial), Some(&settled)).unwrap();
        assert!(
            !announcements_unread(&full, &full_items, Some(&after_partial_read)),
            "a partial read must not evict the items still converging"
        );

        // A view larger than any previous cap keeps every one of its own items.
        let big: Vec<(String, String, i64)> = (0..600)
            .map(|i| (format!("t{i}"), format!("b{i}"), i as i64))
            .collect();
        let big_view = AnnouncementsView {
            motd: None,
            posts: big
                .iter()
                .map(|(t, b, ms)| AnnouncementRow {
                    topic: t.clone(),
                    body: b.clone(),
                    sent_unix_ms: *ms,
                })
                .collect(),
        };
        let big_items = item_content_hashes(&big_view);
        let big_marker = merge_seen(&big_items, None).unwrap();
        assert!(
            !announcements_unread(&big_view, &big_items, Some(&big_marker)),
            "reading a large view must actually mark it read"
        );
    }

    /// Re-reading unchanged content must produce a byte-identical marker, so
    /// `set_announce_seen` reports "unchanged" and the ~30 s poll does not re-seal the
    /// blob on every tick.
    #[test]
    fn merging_the_same_view_twice_is_idempotent() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let view = ann_view(Some("motd"), &[("a", "x", 1), ("b", "y", 2)]);
        let items = item_content_hashes(&view);
        let first = merge_seen(&items, None).unwrap();
        let second = merge_seen(&items, Some(&first)).unwrap();
        assert_eq!(first, second);

        // Unsorted / duplicated input must not change the result either — `merge_seen`
        // is `pub` and documents the invariant rather than enforcing it.
        let mut scrambled = items.clone();
        scrambled.reverse();
        scrambled.push(items[0].clone());
        assert_eq!(merge_seen(&scrambled, Some(&first)).unwrap(), first);
    }

    /// A marker written by a pre-#217 client is a single whole-view hash. It matches no
    /// item, so the pane reads unread once after upgrading; the read then carries the
    /// stale hash forward as one inert entry rather than losing the new marker.
    #[test]
    fn a_pre_217_marker_reads_unread_once_then_migrates_itself() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let view = ann_view(Some("motd"), &[("a", "x", 1)]);
        let items = item_content_hashes(&view);
        let stale = "0".repeat(96);

        assert!(announcements_unread(&view, &items, Some(&stale)));
        let migrated = merge_seen(&items, Some(&stale)).unwrap();
        assert!(!announcements_unread(&view, &items, Some(&migrated)));
        // Carried forward, not dropped: `merge_seen` unions, and cannot tell a stale
        // whole-view hash from an item hash it simply has not seen yet.
        let set = decode_seen(&migrated);
        assert!(set.contains(stale.as_str()));
        assert_eq!(set.len(), items.len() + 1);
    }

    /// An empty MOTD is absent, not an item: `render_motd` yields `""` on a payload that
    /// fails to decode, and the pane hides the MOTD area for it, so hashing it would
    /// raise the dot for content nothing displays.
    #[test]
    fn an_empty_motd_is_not_an_unread_item() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let blank = ann_view(Some(""), &[]);
        assert!(item_content_hashes(&blank).is_empty());
        assert!(!announcements_unread(&blank, &[], None));
        // And it hashes identically to an absent MOTD, so the two encodings agree.
        let with = ann_view(Some(""), &[("a", "x", 1)]);
        let without = ann_view(None, &[("a", "x", 1)]);
        assert_eq!(item_content_hashes(&with), item_content_hashes(&without));
    }

    /// Markers are per relay and must not bleed across `server_id`s.
    #[test]
    fn seen_markers_are_independent_per_server_id() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let view = ann_view(Some("motd"), &[("a", "x", 1)]);
        let items = item_content_hashes(&view);
        let mut seeds = daemonseed_core::storage::seeds::Seeds::new(
            daemonseed_core::identity::mnemonic::Mnemonic::generate().unwrap(),
        );
        seeds.set_announce_seen("fra1#abc", encode_seen(&items));
        assert!(!announcements_unread(
            &view,
            &items,
            seeds.announce_seen("fra1#abc")
        ));
        assert!(announcements_unread(
            &view,
            &items,
            seeds.announce_seen("nyc1#def")
        ));
    }

    /// A malformed marker must degrade to "unread", never to "read".
    #[test]
    fn a_malformed_marker_reads_as_unread() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let view = ann_view(Some("motd"), &[("a", "x", 1)]);
        let items = item_content_hashes(&view);
        for junk in [",", ",,", "not-hex", &format!(",{},", items[0])] {
            let unread = announcements_unread(&view, &items, Some(junk));
            // The last case legitimately covers one of the two items, so it stays unread
            // via the other; every other case covers nothing at all.
            assert!(unread, "marker {junk:?} must not mark the view read");
        }
    }

    /// #158: already-read content re-delivered by a DHT re-sweep must not re-fire the
    /// dot. Re-delivery reproduces identical items, so every one is already in the seen
    /// set.
    #[test]
    fn re_delivered_already_read_content_does_not_re_fire_unread() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let view = ann_view(Some("relay is up"), &[("a", "x", 1), ("b", "y", 2)]);
        let seen = encode_seen(&item_content_hashes(&view));
        // The re-sweep rebuilds the view from scratch, and in the relay's own order.
        let redelivered = ann_view(Some("relay is up"), &[("b", "y", 2), ("a", "x", 1)]);
        assert!(!announcements_unread(
            &redelivered,
            &item_content_hashes(&redelivered),
            Some(&seen)
        ));
    }

    #[test]
    fn item_hashes_are_stable_order_independent_and_change_sensitive() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let base = ann_view(Some("relay is up"), &[("a", "x", 1)]);
        let h0 = item_content_hashes(&base);
        // Same content (rebuilt) → identical items.
        assert_eq!(h0, item_content_hashes(&base.clone()));
        assert_eq!(h0.len(), 2, "one MOTD item + one post item");

        // A MOTD edit changes the MOTD item, an added post adds an item, and an edited
        // post replaces its own — in every case the seen set no longer covers the view.
        for changed in [
            ann_view(Some("maintenance soon"), &[("a", "x", 1)]), // MOTD edited
            ann_view(Some("relay is up"), &[("a", "x", 1), ("b", "y", 2)]), // post added
            ann_view(Some("relay is up"), &[("a", "x!", 1)]),     // post edited
        ] {
            let items = item_content_hashes(&changed);
            assert!(
                announcements_unread(&changed, &items, Some(&encode_seen(&h0))),
                "a change the user has not seen must read unread"
            );
        }

        // REMOVAL is not new content. A view that lost its MOTD, or lost a post, holds
        // only items the user already read, so it reads as read. This is the deliberate
        // difference from the whole-view marker, which treated any delta — including a
        // deletion — as something to re-flag.
        for shrunk in [
            ann_view(None, &[("a", "x", 1)]),   // MOTD removed
            ann_view(Some("relay is up"), &[]), // post removed
            ann_view(None, &[]),                // everything gone (empty-view guard)
        ] {
            let items = item_content_hashes(&shrunk);
            assert!(
                !announcements_unread(&shrunk, &items, Some(&encode_seen(&h0))),
                "losing already-read content must not raise the dot"
            );
        }

        // Reordered served posts (same set) → SAME items (sorted set).
        let ordered = ann_view(Some("relay is up"), &[("a", "x", 1), ("b", "y", 2)]);
        let reversed = ann_view(Some("relay is up"), &[("b", "y", 2), ("a", "x", 1)]);
        assert_eq!(
            item_content_hashes(&ordered),
            item_content_hashes(&reversed),
            "server post order must not change the unread marker"
        );
    }

    /// The persisted marker must survive `Seeds`' single-line `announce-seen` directive:
    /// the separator is not whitespace, so a multi-item marker is accepted, not rejected.
    #[test]
    fn a_multi_item_seen_marker_round_trips_through_seeds() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let view = ann_view(Some("relay is up"), &[("a", "x", 1), ("b", "y", 2)]);
        let items = item_content_hashes(&view);
        let marker = encode_seen(&items);
        assert_eq!(
            marker.matches(SEEN_SEPARATOR).count(),
            2,
            "3 items, 2 separators"
        );

        let mut seeds = daemonseed_core::storage::seeds::Seeds::new(
            daemonseed_core::identity::mnemonic::Mnemonic::generate().unwrap(),
        );
        assert!(
            seeds.set_announce_seen("fra1#abc", marker.clone()),
            "the marker must not be rejected as malformed"
        );
        assert_eq!(seeds.announce_seen("fra1#abc"), Some(marker.as_str()));
        assert!(!announcements_unread(
            &view,
            &items,
            seeds.announce_seen("fra1#abc")
        ));
    }

    /// A MOTD and a post whose text coincides must not alias — the kind tag separates
    /// them, so reading one does not silently mark the other seen.
    #[test]
    fn a_motd_and_a_post_with_the_same_text_do_not_alias() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let motd_only = ann_view(Some("same words"), &[]);
        let post_only = ann_view(None, &[("same words", "", 0)]);
        assert_ne!(
            item_content_hashes(&motd_only),
            item_content_hashes(&post_only)
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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

        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();

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

        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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

        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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

        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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

        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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

        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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

    /// #229: read-state follows what was DISPLAYED rather than what the network last
    /// delivered, so a read is recorded whether or not any further event arrives.
    ///
    /// This is hardening, not a live fix. The state it guards — a populated pane whose
    /// refresh answers with an error — is currently unreachable: once the operator
    /// record is recorded it is never unrecorded (`subscribe_operator_space`
    /// early-returns when set, and nothing clears it), and the pane is only ever
    /// populated by a snapshot, which requires that record. A subscribe that opened
    /// nothing leaves the field unset and so populates no pane, which is the same
    /// unreachable state by the other route. It becomes reachable the moment anything
    /// resets the record on disconnect, and the coupling it removes — read state
    /// depending on an inbound event — is worth not having regardless.
    #[test]
    fn reading_the_pane_records_what_is_on_screen_without_a_snapshot() {
        use daemonseed_core::bootstrap::BootstrapAnchor;
        use daemonseed_core::first_start::FirstStart;
        use daemonseed_core::profile::config::ArgonParams;
        use daemonseed_core::profile::persist::write_first_start;

        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ds-gui-announce-229-{}-{nonce}",
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
        let materials = sealed
            .verify_round_trip(&phrase)
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

        let mut st = GuiState::lobby_only();
        st.set_profile(Profile::from_materials(materials, root.clone()));
        let server_id = "relay#aabbccddeeff";

        // A snapshot arrives and is rendered while the user is elsewhere.
        let view = ann_view(Some("motd"), &[("release", "v0.36.2", 7)]);
        let items = item_content_hashes(&view);
        st.set_announcements_on_screen(view.clone());
        assert!(
            announcements_unread(&view, &items, st.announce_seen_hash(server_id).as_deref()),
            "unseen content raises the dot"
        );

        // The connection drops. The user opens the tab and reads what is still shown;
        // no further snapshot ever arrives.
        assert!(
            st.mark_announcements_seen(server_id).unwrap(),
            "reading the displayed pane records it"
        );
        assert!(
            !announcements_unread(&view, &items, st.announce_seen_hash(server_id).as_deref()),
            "content the user read must not re-flag when the snapshot returns"
        );

        // Re-reading unchanged content records nothing further.
        assert!(!st.mark_announcements_seen(server_id).unwrap());

        // An empty pane records nothing at all, rather than erasing the marker.
        st.set_announcements_on_screen(AnnouncementsView::default());
        assert!(!st.mark_announcements_seen(server_id).unwrap());
        assert!(!announcements_unread(
            &view,
            &items,
            st.announce_seen_hash(server_id).as_deref()
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The ephemeral path (no profile) never persists and never panics: joins work
    /// in RAM, `persist_circle` is a clean no-op, and there is nothing to rejoin.
    #[test]
    fn no_profile_means_no_persistence() {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
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

    // ── #339: DM driver events fold into DmState and drive no UI ──

    /// A distinct 2592-byte identity key, so two correspondents are separable.
    fn dm_pk(tag: u8) -> PkLt {
        Box::new([tag; daemonseed_core::identity::keys::IDENTITY_PK_LEN])
    }

    fn dm_request(slot: u16, tag: u8) -> RequestId {
        RequestId {
            slot,
            entry_hash: [tag; daemonseed_core::dm::pow::ENTRY_HASH_LEN],
        }
    }

    /// The startup roster reaches `DmState` per correspondent, each carrying
    /// the state the driver put it in.
    ///
    /// The three states are asserted separately rather than by count: a fold
    /// that recorded the right number of correspondents under one state would
    /// pass a count and be useless to a surface, which needs to know which
    /// correspondence it may write to.
    #[test]
    fn dm_roster_states_each_correspondent() {
        use daemonseed_veilid_net::dm::Correspondent;
        let mut st = GuiState::lobby_only();
        assert!(st.dm_state().correspondences.is_empty());

        st.on_dm_event(&DmEvent::Roster {
            correspondents: vec![
                Correspondent {
                    pk_lt: dm_pk(1),
                    state: CorrespondentState::Established,
                },
                Correspondent {
                    pk_lt: dm_pk(2),
                    state: CorrespondentState::Pending,
                },
                Correspondent {
                    pk_lt: dm_pk(3),
                    state: CorrespondentState::Blocked,
                },
            ],
        });

        let state_of = |tag: u8| {
            st.dm_state()
                .correspondences
                .get(&dm_pk(tag))
                .expect("the roster left out a correspondent")
                .state
        };
        assert_eq!(state_of(1), Some(CorrespondentState::Established));
        assert_eq!(state_of(2), Some(CorrespondentState::Pending));
        assert_eq!(state_of(3), Some(CorrespondentState::Blocked));
        assert_eq!(
            st.dm_state().correspondences.len(),
            3,
            "the fold invented a correspondence the roster did not name"
        );
    }

    /// A correspondence the driver reports on without a roster carries no
    /// state: absence is "not stated", and a fold that guessed would say a
    /// blocked correspondent is writable.
    #[test]
    fn a_delivery_alone_states_no_correspondent_state() {
        let mut st = GuiState::lobby_only();

        st.on_dm_event(&DmEvent::Delivery {
            to: dm_pk(4),
            seq: 0,
            state: DeliveryState::Composed,
        });

        assert_eq!(
            st.dm_state()
                .correspondences
                .get(&dm_pk(4))
                .expect("the delivery folded")
                .state,
            None
        );
    }

    /// #339: a `Refused` reaches `DmState` whole — recipient, acceptance and
    /// reason. The refusal is the one DM outcome the user must be told about,
    /// no interface draws it yet, so this field IS the delivery.
    #[test]
    fn dm_refused_event_lands_in_dm_state() {
        let mut st = GuiState::lobby_only();
        assert!(st.dm_state().last_refusal.is_none());

        st.on_dm_event(&DmEvent::Refused {
            to: dm_pk(7),
            acceptance: Acceptance::Unconfirmed,
            reason: RefusalReason::NoKeyRecord,
            event: None,
        });

        let refusal = st.dm_state().last_refusal.as_ref().expect("refusal folded");
        assert_eq!(refusal.to, dm_pk(7));
        assert_eq!(refusal.acceptance, Acceptance::Unconfirmed);
        assert_eq!(refusal.reason, RefusalReason::NoKeyRecord);
    }

    /// A torn-down channel reaches the trust-event audit log, carrying the key
    /// the driver classed it under and nothing that names the correspondent.
    ///
    /// The front-end half of the loud teardown: ISC-A-C12 forbids the client
    /// skipping the entry, and this fold is the only thing between the driver's
    /// classed key and the log. The undelivered queue is asserted alongside it,
    /// so a fold that logged the event and dropped the sequences would fail.
    /// **A re-establishment anomaly reaches the audit log too**, and its class
    /// is the same one a teardown's is.
    ///
    /// A3.8 gives every loud re-establishment state
    /// `PersistentNonBlocking`, and ISC-A-C12 forbids the client dropping a
    /// classed key on the way to the log. Nothing else about the event is folded
    /// — recovery is under way and bounded — so the log entry is the whole of
    /// what a front end owes it, and this is the only place that can be checked.
    #[test]
    fn dm_reestablishment_anomaly_is_audit_logged() {
        use daemonseed_core::trust_events::{TrustEventClass, TrustEventKey, class_of};
        let mut st = GuiState::lobby_only();
        assert_eq!(st.trust_log().len(), 0, "the fixture starts empty");

        st.on_dm_event(&DmEvent::ReestablishmentAnomaly {
            with: dm_pk(9),
            event: TrustEventKey::DmPeerStateRegressed,
        });

        let entries = st.trust_log().entries();
        assert_eq!(entries.len(), 1, "the anomaly was not logged");
        assert_eq!(entries[0].key, TrustEventKey::DmPeerStateRegressed);
        assert_eq!(
            class_of(TrustEventKey::DmPeerStateRegressed),
            TrustEventClass::PersistentNonBlocking,
            "the class the log entry is written at moved"
        );
        // ISC-C28 keeps the correspondence out of the log, exactly as it does
        // for a teardown: the key is the whole statement.
        assert!(entries[0].server_id.is_none());
        assert!(entries[0].suite_id.is_none());
        assert!(entries[0].record_kind.is_none());
        assert!(entries[0].timestamp_unix_ms > 0, "the entry has no clock");
        // And nothing else moved: the fold adds no per-correspondence state.
        assert!(
            !st.dm_state().correspondences.contains_key(&dm_pk(9)),
            "the anomaly invented correspondence state a reader cannot act on"
        );
    }

    #[test]
    fn dm_channel_lost_is_audit_logged() {
        let mut st = GuiState::lobby_only();
        assert_eq!(st.trust_log().len(), 0, "the fixture starts empty");

        st.on_dm_event(&DmEvent::ChannelLost {
            with: dm_pk(9),
            cause: daemonseed_core::dm::provisional::TeardownCause::CorrespondentStateLost,
            event: daemonseed_core::trust_events::TrustEventKey::DmCorrespondentStateLost,
            surfaced: vec![4, 5],
        });

        let entries = st.trust_log().entries();
        assert_eq!(entries.len(), 1, "the teardown was not logged");
        assert_eq!(
            entries[0].key,
            daemonseed_core::trust_events::TrustEventKey::DmCorrespondentStateLost
        );
        // ISC-C28 keeps the correspondence out of the log: the key is the whole
        // statement, and every scope field stays empty rather than being filled
        // with something that would join into a recently-contacted set.
        assert!(entries[0].server_id.is_none());
        assert!(entries[0].suite_id.is_none());
        assert!(entries[0].record_kind.is_none());
        assert!(entries[0].timestamp_unix_ms > 0, "the entry has no clock");

        assert_eq!(
            st.dm_state()
                .correspondences
                .get(&dm_pk(9))
                .expect("correspondence folded")
                .undelivered,
            vec![4, 5]
        );
    }

    /// A refusal that carries a classed key is audit-logged exactly once, and a
    /// refusal that carries none writes nothing.
    ///
    /// An introduction whose channel is torn down is stated as a refusal, so
    /// this fold is the only thing between the driver's classed key and the log
    /// — the standing ISC-A-C12 puts on a lost channel, on the event the
    /// introduce-probe path actually emits. The second half is what keeps the
    /// fold conditional: a client that logged every refusal would pass the
    /// first assertion and write an audit entry for a full outbox.
    #[test]
    fn dm_refused_carrying_a_trust_event_is_audit_logged_once() {
        let mut st = GuiState::lobby_only();
        assert_eq!(st.trust_log().len(), 0, "the fixture starts empty");

        st.on_dm_event(&DmEvent::Refused {
            to: dm_pk(9),
            acceptance: Acceptance::Unconfirmed,
            reason: RefusalReason::StoreFailure,
            event: Some(
                daemonseed_core::trust_events::TrustEventKey::DmProvisionalRecordUnreadable,
            ),
        });

        let entries = st.trust_log().entries();
        assert_eq!(
            entries.len(),
            1,
            "the refusal's key reached the log {} times",
            entries.len()
        );
        assert_eq!(
            entries[0].key,
            daemonseed_core::trust_events::TrustEventKey::DmProvisionalRecordUnreadable
        );
        // ISC-C28 again: the key is the whole statement, and no scope field is
        // filled with anything that would name the correspondent.
        assert!(entries[0].server_id.is_none());
        assert!(entries[0].suite_id.is_none());
        assert!(entries[0].record_kind.is_none());
        assert!(entries[0].timestamp_unix_ms > 0, "the entry has no clock");

        // The refusal is still a refusal to the rest of the fold.
        assert_eq!(
            st.dm_state()
                .last_refusal
                .as_ref()
                .expect("refusal folded")
                .reason,
            RefusalReason::StoreFailure
        );

        st.on_dm_event(&DmEvent::Refused {
            to: dm_pk(9),
            acceptance: Acceptance::Unconfirmed,
            reason: RefusalReason::OutboxFull { needed: 12 },
            event: None,
        });
        assert_eq!(
            st.trust_log().entries().len(),
            1,
            "a refusal that tore nothing down was audit-logged"
        );
    }

    /// #339: a `ContactRequest` adds exactly ONE row, a re-surfaced request
    /// replaces it, and a different request is its own row.
    #[test]
    fn dm_contact_request_adds_exactly_one_request() {
        let mut st = GuiState::lobby_only();
        assert_eq!(st.dm_state().requests.len(), 0);

        let event = |body: &str| DmEvent::ContactRequest {
            request: dm_request(3, 9),
            from: dm_pk(1),
            body: body.to_owned(),
            sent_unix_ms: 1_700_000_000_000,
        };
        st.on_dm_event(&event("hello"));
        assert_eq!(st.dm_state().requests.len(), 1);

        st.on_dm_event(&event("hello again"));
        assert_eq!(st.dm_state().requests.len(), 1);
        let held = &st.dm_state().requests[0];
        assert_eq!(held.request, dm_request(3, 9));
        assert_eq!(held.from, dm_pk(1));
        assert_eq!(held.body, "hello again");

        st.on_dm_event(&DmEvent::ContactRequest {
            request: dm_request(4, 9),
            from: dm_pk(2),
            body: "someone else".to_owned(),
            sent_unix_ms: 1_700_000_001_000,
        });
        assert_eq!(st.dm_state().requests.len(), 2);
    }

    /// Everything `GuiState` exposes to the view layer, in one comparable value.
    ///
    /// `circles` is the `Debug` rendering of every [`CircleState`] rather than a
    /// hand-picked field or two: `CircleState` is not `Clone` (it holds a
    /// zeroizing circle key) so it cannot be snapshotted by value, but its derived
    /// `Debug` covers every field it has — so a field added later lands in this
    /// comparison without anyone remembering to add it. A hand-picked triple is
    /// exactly what a new visible field would slip past.
    #[derive(Debug, PartialEq)]
    struct VisibleState {
        active: usize,
        circles: String,
        roster: Vec<RosterEntry>,
        announcements: AnnouncementsView,
    }

    fn visible_state(st: &GuiState) -> VisibleState {
        VisibleState {
            active: st.active(),
            circles: format!("{:?}", st.metas()),
            roster: st.active_roster().to_vec(),
            announcements: st.announcements_on_screen.clone(),
        }
    }

    /// #339: NO UI. Folding DM events changes nothing the view layer reads — no
    /// interface renders them, and this is what catches a fold reaching into the
    /// visible layer early.
    #[test]
    fn dm_events_change_no_visible_state() {
        let mut st = GuiState::demo();
        let before = visible_state(&st);
        assert!(
            !st.metas().is_empty(),
            "the fixture must have circles for the snapshot to mean anything"
        );

        st.on_dm_event(&DmEvent::ContactRequest {
            request: dm_request(1, 2),
            from: dm_pk(3),
            body: "knock".to_owned(),
            sent_unix_ms: 1_700_000_000_000,
        });
        st.on_dm_event(&DmEvent::Refused {
            to: dm_pk(3),
            acceptance: Acceptance::Unconfirmed,
            reason: RefusalReason::PublishFailed,
            event: None,
        });
        st.on_dm_event(&DmEvent::DoorbellHealth {
            outcome: SweepOutcome::default(),
            admission: AdmissionCounters::default(),
            pending_full: 3,
        });

        // The fold really happened — otherwise this proves only that three
        // no-ops leave the view alone.
        assert_eq!(st.dm_state().requests.len(), 1);
        assert!(st.dm_state().last_refusal.is_some());
        assert!(st.dm_state().last_doorbell_health.is_some());

        assert_eq!(
            visible_state(&st),
            before,
            "a DM fold changed visible state"
        );
    }

    /// #339: the held-request list is bounded by the driver's own cap. Without it
    /// the fold has no removal path at all — there is no accept or decline event —
    /// so a long session accumulates every knock it was ever told about,
    /// including ones the driver has already dropped.
    #[test]
    fn dm_requests_are_capped_at_the_drivers_own_bound() {
        let mut st = GuiState::lobby_only();
        for i in 0..(PENDING_REQUEST_CAP as u16 + 10) {
            st.on_dm_event(&DmEvent::ContactRequest {
                request: dm_request(i, (i % 251) as u8),
                from: dm_pk(1),
                body: format!("knock {i}"),
                sent_unix_ms: 1_700_000_000_000 + i as i64,
            });
        }
        assert_eq!(st.dm_state().requests.len(), PENDING_REQUEST_CAP);
        assert_eq!(
            st.dm_state().requests.last().expect("non-empty").body,
            format!("knock {}", PENDING_REQUEST_CAP + 9)
        );
    }

    /// #339: `Debug` on the DM state redacts what core's own `DmEvent::Debug`
    /// redacts. A trace line is the last place a stranger's plaintext message or
    /// a 2592-byte key naming a person belongs, and these types reach `Debug` by
    /// a different route than the event they were folded from.
    #[test]
    fn dm_state_debug_redacts_bodies_and_keys() {
        let mut st = GuiState::lobby_only();
        st.on_dm_event(&DmEvent::ContactRequest {
            request: dm_request(1, 2),
            from: dm_pk(0xAB),
            body: "meet me at the docks".to_owned(),
            sent_unix_ms: 1,
        });
        st.on_dm_event(&DmEvent::ChannelHealth {
            with: dm_pk(0xAB),
            partial_sweeps: 1,
            already_consumed: 0,
            unopenable: 0,
            peer_pseudonym_unknown: 0,
            peer_acks_deferred: 0,
            peer_acks_clipped: 0,
            peer_acks_unverified: 0,
            cursor_records_repaired: 0,
            leg_folds_deferred: 0,
            leg_unaddressable: 0,
        });
        let rendered = format!("{:?}", st.dm_state());

        assert!(
            !rendered.contains("meet me at the docks"),
            "the body reached a Debug line: {rendered}"
        );
        assert!(
            rendered.contains("body_len: 20"),
            "the length should still be there: {rendered}"
        );
        assert!(
            !rendered.contains("171, 171"),
            "the identity key reached a Debug line: {rendered}"
        );
        assert!(
            rendered.contains("PkLt(..)"),
            "expected the marker: {rendered}"
        );
    }
}
