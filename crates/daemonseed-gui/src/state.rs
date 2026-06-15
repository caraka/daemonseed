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
//! [`CotKey`] (`daemonseed_core::circle::key::derive_cot_key`), and a rendezvous
//! slot — so Round 5's circle networking plugs in without reworking this layer.
//! This is why the module now depends on `daemonseed-core` (it did not in round 2);
//! it stays Slint-free and network-free. Materialized circles are RAM-only and
//! gone on relaunch — config persistence is a separate milestone.

use daemonseed_core::circle::key::{CircleKeyError, CotKey, circle_fingerprint, derive_cot_key};
use daemonseed_core::cot::AssetAddr;
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::passphrase::strength::{DicewareError, estimate_circle, generate_diceware};

use crate::profile::Profile;

/// Word count for a generated circle phrase. 12 BIP-39 words ≈ 132 bits of real
/// entropy, clearing the ≥128-bit circle floor (ISC-C9 / brief D3) — the same
/// count the TUI generates (Ctrl-G). The number is HIDDEN from the user.
pub const NEW_CIRCLE_WORDS: usize = 12;

/// Generate a circle phrase that clears the SAME estimator the join gate uses
/// (D3 — one shared estimator, so a generated phrase is never one the join flow
/// would reject).
///
/// **Why a loop, not a bare `generate_diceware(12)`:** the generator draws WITH
/// replacement, so ~3% of 12-word phrases repeat a word. `estimate_circle` credits
/// only DISTINCT words (a conservative key-space model), so a phrase with a
/// duplicate scores 11×11 = 121 bits — below the 128 floor — even though its real
/// entropy is 132 bits. Rejection-sampling until `is_circle_green` keeps the New
/// flow consistent with the Join gate and the "Looks strong" reassurance. The
/// discarded draws carry the same real entropy; excluding them costs nothing and
/// the remaining phrase space is still astronomically larger than 2¹²⁸. (Latent in
/// the TUI's Ctrl-G + its floor test too — flagged 2026-06-15.)
pub fn generate_circle_phrase() -> Result<String, DicewareError> {
    for _ in 0..32 {
        let p = generate_diceware(NEW_CIRCLE_WORDS)?;
        if estimate_circle(&p).is_circle_green() {
            return Ok(p);
        }
    }
    // Astronomically unreachable (>=32 consecutive sub-floor 12-word draws); return
    // a final attempt rather than panicking in a non-security display path.
    generate_diceware(NEW_CIRCLE_WORDS)
}

/// One chat message in a circle's stub transcript.
#[derive(Clone, Debug)]
pub struct Msg {
    pub who: String,
    pub text: String,
    pub mine: bool,
}

/// The Round-5 **net contract** carried by a materialized circle (refinement #1).
///
/// Holding the phrase + derived [`CotKey`] + a rendezvous slot here is the single
/// most important thing Round 4 gets right: Round 5's `NetCommand::JoinCircle`
/// takes the phrase (the net actor derives its own key, mirroring the public-room
/// name path), and seal/open needs the `cot_key` + `rendezvous` — so the net path
/// plugs into an already-materialized circle with no rework.
///
/// `Debug` is hand-rolled to REDACT the phrase (the circle's whole secret) and
/// defer to [`CotKey`]'s own redacted `Debug` — neither ever lands on a log
/// surface (mirrors the `CotKey` / circle-key hygiene, ISC-A-C1).
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
    pub cot_key: CotKey,
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
/// **No longer `Clone`** (round 4): it now holds a [`CircleNet`] whose [`CotKey`]
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
        }];
        GuiState {
            circles,
            active: 0,
            next_circle_id: FIRST_CIRCLE_ID,
            profile: None,
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
            // PLACEHOLDER — caraka security review: the secondary/header lines are
            // operator-facing trust copy (brief refinement #3, D6). No bit numbers
            // (ISC-45). Round 5 replaces "not yet connected" with the live state.
            sub: "sealed · not yet connected".to_owned(),
            initial,
            pinned: false,
            header_sub: "end-to-end sealed · not yet connected".to_owned(),
            messages: Vec::new(),
            draft: String::new(),
            scroll_y: 0.0,
            net: Some(CircleNet {
                circle_id,
                phrase: phrase.to_owned(),
                cot_key,
                rendezvous: None,
            }),
        };
        self.circles.push(circle);
        Ok(self.circles.len() - 1)
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
    pub fn push_message(&mut self, idx: usize, who: String, text: String, mine: bool) {
        if let Some(c) = self.circles.get_mut(idx) {
            c.messages.push(Msg { who, text, mine });
        }
    }

    /// Set circle `idx`'s retained draft (no-op if out of range). Used to persist
    /// a cleared composer into the active circle's RAM state after a send.
    pub fn set_draft(&mut self, idx: usize, draft: String) {
        if let Some(c) = self.circles.get_mut(idx) {
            c.draft = draft;
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
        }
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
                "4 here · sealed",
                "m",
                false,
                "4 here · end-to-end sealed",
                fill("midnight-signal", 24, "wandering-otter"),
            ),
            mk(
                "garden-fence",
                "2 here · sealed",
                "g",
                false,
                "2 here · sealed · neighbours",
                fill("garden-fence", 5, "quiet-sparrow"),
            ),
            mk(
                "harbor-lights",
                "3 here · sealed",
                "h",
                false,
                "3 here · sealed · waterfront",
                fill("harbor-lights", 4, "dock-keeper"),
            ),
        ];
        GuiState {
            circles,
            active: 1,
            next_circle_id: FIRST_CIRCLE_ID,
            profile: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

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
            assert_eq!(phrase.split_whitespace().count(), NEW_CIRCLE_WORDS);
            assert!(
                estimate_circle(&phrase).is_circle_green(),
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
            dbg.contains("CotKey(<redacted>)"),
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
