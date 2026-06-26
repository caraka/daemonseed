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

use daemonseed_cli::public_space::{
    post_render_fields, render_motd, verify_served_motd, verify_served_post, whitelist_from_wire,
};
use daemonseed_core::circle::key::{CircleKey, CircleKeyError, circle_fingerprint, derive_cot_key};
use daemonseed_core::cot::AssetAddr;
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::passphrase::strength::{self, DicewareError};
use daemonseed_core::storage::seeds::IndexKey;
use daemonseed_proto::v1 as wire;

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
/// Built from a relay-served [`wire::Post`] that PASSED client re-verification
/// against the published signer whitelist ([`verify_served_post`]); an
/// unverifiable post never becomes a row. The fields are the inert
/// [`post_render_fields`] decode — `topic`/`body` render verbatim, `sent_unix_ms`
/// is the signer's advisory signing wall-clock (ISC-S7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnouncementRow {
    pub topic: String,
    pub body: String,
    pub sent_unix_ms: i64,
}

/// The verified display model for the announcements/MOTD pane (#91). `motd` is the
/// connected relay's inert verbatim MOTD ([`render_motd`]) and is `None` both when
/// the relay serves no MOTD AND when a served MOTD fails re-verification (display
/// only what verifies, ISC-A-S3). `posts` are the verified announcement rows, in
/// served order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnnouncementsView {
    pub motd: Option<String>,
    pub posts: Vec<AnnouncementRow>,
}

/// Build the verified announcements/MOTD display model (#91 — the testable
/// data-prep + client re-verification half, ISC-C91 / ISC-A-S3).
///
/// Trusts NOTHING the relay asserts: the published signer whitelist
/// ([`wire::GetSignerWhitelistResponse`]) is rebuilt locally, then every served
/// post is re-verified against it ([`verify_served_post`] — signature AND content
/// address) and DROPPED if it fails; the MOTD is re-verified
/// ([`verify_served_motd`]) and shown only if it passes. The MOTD whitelist
/// additionally carries the connected relay's own `server_pubkey` (a MOTD may be
/// server-signed, ISC-26); the post whitelist does NOT, so post authorship stays
/// the strict signer set (ISC-S8). A malformed published whitelist fails closed:
/// nothing is trusted, so the view is empty.
pub fn build_announcements_view(
    motd: &wire::GetMotdResponse,
    posts: &wire::ListPostsResponse,
    whitelist: &wire::GetSignerWhitelistResponse,
    server_pubkey: &[u8],
) -> AnnouncementsView {
    // Posts: the strict signer whitelist (no server key — ISC-S8 authorship).
    let post_wl = match whitelist_from_wire(&whitelist.entries, None) {
        Ok(wl) => wl,
        Err(_) => return AnnouncementsView::default(),
    };
    // MOTD: same whitelist PLUS the relay's own key (ISC-26 server-signed MOTD).
    let motd_wl = match whitelist_from_wire(&whitelist.entries, Some(server_pubkey)) {
        Ok(wl) => wl,
        Err(_) => return AnnouncementsView::default(),
    };

    let motd_text = motd
        .motd
        .as_ref()
        .filter(|m| verify_served_motd(m, &motd_wl).is_ok())
        .map(render_motd);

    let posts = posts
        .posts
        .iter()
        .filter(|p| verify_served_post(p, &post_wl).is_ok())
        .map(|p| {
            let (topic, body, sent_unix_ms) = post_render_fields(p);
            AnnouncementRow {
                topic,
                body,
                sent_unix_ms,
            }
        })
        .collect();

    AnnouncementsView {
        motd: motd_text,
        posts,
    }
}

/// One chat message in a circle's stub transcript.
#[derive(Clone, Debug)]
pub struct Msg {
    pub who: String,
    pub text: String,
    pub mine: bool,
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
            let _ = self.materialize_from_phrase(&phrase);
        }
        self.profile = Some(profile);
    }

    /// The unlocked profile's stable display handle, or `None` on the ephemeral
    /// path. Passed to `NetCommand::Connect` so the user presents under it.
    pub fn display_handle(&self) -> Option<String> {
        self.profile.as_ref().map(|p| p.display_handle().to_owned())
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

    /// #66: rename the unlocked identity — set a new display name and re-seal the
    /// at-rest blob (write-through) so it persists across unlock; also the recovery
    /// path for a profile created nameless before #65. Returns the new display
    /// handle, or `Err` for an invalid name, no unlocked profile, or a disk-seal
    /// failure. The cryptographic identity (handle hash) is unchanged. The Ctrl-K
    /// command-palette entry that drives this is felt-deferred (#66), so the binary
    /// has no caller yet — `#[allow(dead_code)]`, same convention as
    /// [`GuiState::circle_fingerprint_of`]; the core path is exercised by the
    /// `rename_identity_*` unit tests.
    #[allow(dead_code)]
    pub fn rename_identity(&mut self, new_name: &str) -> Result<String, String> {
        match self.profile.as_mut() {
            Some(p) => p.rename(new_name).map(str::to_owned),
            None => Err("no unlocked profile to rename".into()),
        }
    }

    /// Record a share that just started serving this session (commit 3, on
    /// `PublishStarted`). Replaces any existing entry with the same id so a relay
    /// re-list can't double it.
    pub fn add_my_share(&mut self, id: String, name: String, files: usize, root: String) {
        self.my_shares.retain(|s| s.id != id);
        self.my_shares.push(MyShare {
            id,
            name,
            files,
            root,
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

    /// (#81) The unlocked profile's persisted-index home + key —
    /// `(profile_root_dir, index_key)` — passed to `NetCommand::Connect` so the net
    /// actor opens a PER-SHARE index file under the dir for each published share and
    /// reuses its chunk-address cache across launches instead of re-hashing from
    /// scratch. `None` on the ephemeral (no-profile) path, where there is no profile
    /// root to persist a cache under.
    pub fn persisted_index_params(&self) -> Option<(std::path::PathBuf, IndexKey)> {
        self.profile.as_ref().map(Profile::index_params)
    }

    /// Write-through (M16): remember a published share root in the unlocked profile
    /// blob so it auto-republishes next launch. No-op (returns `Ok`) on the
    /// ephemeral (no-profile) path; a disk / seal failure is surfaced as `Err`.
    pub fn persist_published(&mut self, root: &str) -> Result<(), String> {
        match self.profile.as_mut() {
            Some(p) => p.persist_published(root).map(|_| ()),
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
    /// `#[allow(dead_code)]`: the data path is in place + unit-tested, but the
    /// hover/detail UI affordance that surfaces it is attended felt-polish (deferred),
    /// so the binary does not call it yet — same convention as [`GuiState::len`].
    #[allow(dead_code)]
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
    /// `None` for the Lobby (no net contract). `#[allow(dead_code)]`: the
    /// detail-pane affordance that surfaces it is attended felt-polish (deferred).
    #[allow(dead_code)]
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
    /// Returns `true` iff this call newly raised circle `idx`'s unread dot (#64) —
    /// a non-own message into a non-active room — so the caller knows to rebuild the
    /// rail. Own echoes (`mine`) and messages into the active room never raise it.
    pub fn push_message(&mut self, idx: usize, who: String, text: String, mine: bool) -> bool {
        let active = self.active;
        if let Some(c) = self.circles.get_mut(idx) {
            c.messages.push(Msg { who, text, mine });
            if !mine && idx != active && !c.unread {
                c.unread = true;
                return true;
            }
        }
        false
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
            self.circles[self.active].unread = false;
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

    // ── build_announcements_view (#91 / ISC-C91 / ISC-A-S3) ──────────────────
    //
    // Fixtures reuse the #90 cli authoring helpers (`sign_post`/`sign_motd`) so the
    // test stays dependency-free (the gui crate has no direct `prost`) and exercises
    // the authoring↔verify round-trip the production path relies on.

    use daemonseed_cli::public_space::{sign_motd, sign_post};
    use daemonseed_core::identity::keys::SignKeypair;

    fn ann_keypair(seed: u8) -> SignKeypair {
        let _ = oxicrypt_module::initialize();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    fn full_key_entry(signer: &SignKeypair) -> wire::SignerWhitelistEntry {
        wire::SignerWhitelistEntry {
            entry: Some(wire::signer_whitelist_entry::Entry::FullPubkey(
                signer.public_key().to_vec(),
            )),
        }
    }

    /// A served post signed by `signer` with a correctly-derived content address.
    fn served_post(signer: &SignKeypair, topic: &str, body: &str, ts: i64) -> wire::Post {
        let artifact = sign_post(signer, topic, body, ts).unwrap();
        let address =
            daemonseed_core::public_space::content_address(&artifact.signed_payload).unwrap();
        wire::Post {
            artifact: Some(artifact),
            content_address: address.as_bytes().to_vec(),
        }
    }

    fn signed_motd(signer: &SignKeypair, text: &str, ts: i64) -> wire::SignedArtifact {
        sign_motd(signer, text, ts).unwrap()
    }

    #[test]
    fn build_announcements_view_verifies_motd_and_drops_unverifiable_post() {
        let signer = ann_keypair(40);
        let stranger = ann_keypair(41);
        let server = ann_keypair(42);

        let whitelist = wire::GetSignerWhitelistResponse {
            entries: vec![full_key_entry(&signer)],
        };
        // A whitelisted signer's MOTD verifies (here signed by a whitelist member,
        // so it passes via the entry; the server key rides the MOTD whitelist too).
        let motd = wire::GetMotdResponse {
            motd: Some(signed_motd(&signer, "relay is up", 7)),
        };
        // Two posts: one by the whitelisted signer (kept), one by a stranger the
        // whitelist does not authorize (must be dropped — ISC-A-S3).
        let posts = wire::ListPostsResponse {
            posts: vec![
                served_post(&signer, "announcements", "v2 shipped", 11),
                served_post(&stranger, "announcements", "forged-by-relay", 12),
            ],
        };

        let view = build_announcements_view(&motd, &posts, &whitelist, server.public_key());

        assert_eq!(
            view.motd.as_deref(),
            Some("relay is up"),
            "a verified MOTD renders verbatim"
        );
        assert_eq!(view.posts.len(), 1, "the unverifiable post is dropped");
        assert_eq!(view.posts[0].topic, "announcements");
        assert_eq!(view.posts[0].body, "v2 shipped");
        assert_eq!(view.posts[0].sent_unix_ms, 11);
    }

    #[test]
    fn build_announcements_view_hides_unverifiable_motd() {
        // A MOTD signed by a key NOT on the whitelist and NOT the server key fails
        // re-verification → it is not displayed (display only what verifies).
        let signer = ann_keypair(43);
        let stranger = ann_keypair(44);
        let server = ann_keypair(45);
        let whitelist = wire::GetSignerWhitelistResponse {
            entries: vec![full_key_entry(&signer)],
        };
        let motd = wire::GetMotdResponse {
            motd: Some(signed_motd(&stranger, "spoofed motd", 1)),
        };
        let posts = wire::ListPostsResponse { posts: vec![] };

        let view = build_announcements_view(&motd, &posts, &whitelist, server.public_key());
        assert!(view.motd.is_none(), "an unverifiable MOTD is hidden");
        assert!(view.posts.is_empty());
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
        st.add_my_share("id-a".into(), "alpha".into(), 3, "/shares/alpha".into());
        st.add_my_share("id-b".into(), "beta".into(), 1, "/shares/beta".into());
        assert_eq!(st.my_shares().len(), 2);
        // share_root keys the M16 persistence by id → published directory path.
        assert_eq!(st.share_root("id-b").as_deref(), Some("/shares/beta"));
        assert_eq!(st.share_root("id-zzz"), None);
        // Re-publish (same id) replaces, not duplicates — a relay re-list is idempotent.
        st.add_my_share(
            "id-a".into(),
            "alpha-renamed".into(),
            9,
            "/shares/alpha".into(),
        );
        assert_eq!(st.my_shares().len(), 2);
        let a = st.my_shares().iter().find(|s| s.id == "id-a").unwrap();
        assert_eq!(a.name, "alpha-renamed");
        assert_eq!(a.files, 9);
        assert_eq!(a.root, "/shares/alpha");
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
        let raised = st.push_message(2, "ally".into(), "ping".into(), false);
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
        assert!(!st.push_message(1, "x".into(), "hi".into(), false));
        assert!(
            !st.metas()[1].unread,
            "message into the active room: no dot"
        );
        assert!(!st.push_message(2, "me".into(), "hi".into(), true));
        assert!(!st.metas()[2].unread, "own echo never dots");
    }

    #[test]
    fn focus_clears_unread() {
        let mut st = GuiState::demo(); // active == 1
        st.push_message(2, "ally".into(), "ping".into(), false);
        assert!(st.metas()[2].unread);
        st.switch_to(2, String::new(), 0.0); // focus circle 2
        assert!(!st.metas()[2].unread, "focusing a room clears its dot");
    }

    #[test]
    fn unread_raise_is_idempotent() {
        let mut st = GuiState::demo(); // active == 1
        assert!(st.push_message(2, "a".into(), "1".into(), false));
        assert!(
            !st.push_message(2, "a".into(), "2".into(), false),
            "already-unread room does not re-raise (no spurious rail rebuilds)"
        );
        assert!(st.metas()[2].unread);
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

        // Session 1: adopt the profile, persist two published roots, unpersist one.
        let mut st1 = GuiState::lobby_only();
        st1.set_profile(Profile::from_materials(materials, root.clone()));
        assert!(
            st1.persisted_published().is_empty(),
            "nothing published on a fresh enrollment"
        );
        st1.persist_published("/home/alice/photos").unwrap();
        st1.persist_published("/home/alice/docs").unwrap();
        st1.persist_published("/home/alice/photos").unwrap(); // idempotent: no dup
        st1.unpersist_published("/home/alice/docs").unwrap();
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

        // The kept publish survived relaunch; the unpersisted one did not.
        // name is None (no naming UI yet); the slot round-trips through the pair.
        assert_eq!(
            st2.persisted_published(),
            vec![("/home/alice/photos".to_string(), None)],
            "exactly the kept published root auto-republishes next launch"
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
}
