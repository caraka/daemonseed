//! Plain-Rust, RAM-only per-circle state layer (round 2).
//!
//! No `slint` import: this module is the in-memory model of the GUI's circles and
//! their per-circle scroll/draft state, kept Slint-free so it is unit-testable in
//! isolation. Each circle remembers its own half-typed draft and scroll position
//! across rail switches; everything resets on relaunch (no persistence, no
//! `daemonseed-core`, no network).

/// One chat message in a circle's stub transcript.
#[derive(Clone, Debug)]
pub struct Msg {
    pub who: String,
    pub text: String,
    pub mine: bool,
}

/// A single circle and its retained, per-circle UI state.
#[derive(Clone, Debug)]
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
}

/// The whole RAM-only GUI state: the circles plus which one is active.
pub struct GuiState {
    circles: Vec<CircleState>,
    active: usize,
}

impl GuiState {
    /// Seed the demo state: >=4 circles, a pinned "Lobby" first, each visually
    /// distinct (distinct `header_sub` AND a first message naming the circle, so
    /// an offscreen PNG of circle A vs B is unambiguously different). The
    /// initially-active circle (index 1, "midnight-signal") gets ~24 messages so
    /// it scrolls; others have fewer.
    pub fn demo() -> GuiState {
        fn first_msg(circle: &str, who: &str) -> Msg {
            Msg {
                who: who.into(),
                text: format!("welcome to {circle} — this circle is {circle}"),
                mine: false,
            }
        }

        // Lobby (index 0) — pinned, public, a handful of messages.
        let mut lobby_msgs = vec![first_msg("Lobby", "amazon-fra1")];
        for i in 1..6 {
            lobby_msgs.push(Msg {
                who: format!("daemon-{i:02}"),
                text: format!("Lobby line {i} — public lobby chatter"),
                mine: i % 2 == 0,
            });
        }

        // midnight-signal (index 1) — the active circle, ~24 messages so it scrolls.
        let mut signal_msgs = vec![first_msg("midnight-signal", "wandering-otter")];
        for i in 1..24 {
            let mine = i % 3 == 0;
            signal_msgs.push(Msg {
                who: if mine {
                    "wandering-otter".into()
                } else {
                    format!("daemon-{i:02}")
                },
                text: format!("midnight-signal line {i} — lorem ipsum dolor sit amet"),
                mine,
            });
        }

        // garden-fence (index 2) — fewer messages.
        let mut garden_msgs = vec![first_msg("garden-fence", "quiet-sparrow")];
        for i in 1..5 {
            garden_msgs.push(Msg {
                who: format!("daemon-{i:02}"),
                text: format!("garden-fence line {i} — neighbours only"),
                mine: i % 2 == 0,
            });
        }

        // harbor-lights (index 3) — fewer messages.
        let mut harbor_msgs = vec![first_msg("harbor-lights", "dock-keeper")];
        for i in 1..4 {
            harbor_msgs.push(Msg {
                who: format!("daemon-{i:02}"),
                text: format!("harbor-lights line {i} — lights on the water"),
                mine: i % 2 == 0,
            });
        }

        let circles = vec![
            CircleState {
                name: "Lobby".into(),
                sub: "public lobby · amazon-fra1".into(),
                initial: "L".into(),
                pinned: true,
                header_sub: "public lobby · open · amazon-fra1".into(),
                messages: lobby_msgs,
                draft: String::new(),
                scroll_y: 0.0,
            },
            CircleState {
                name: "midnight-signal".into(),
                sub: "4 here · sealed".into(),
                initial: "m".into(),
                pinned: false,
                header_sub: "4 here · end-to-end sealed".into(),
                messages: signal_msgs,
                // Optional starter draft on the active circle.
                draft: "ready when you are".into(),
                scroll_y: 0.0,
            },
            CircleState {
                name: "garden-fence".into(),
                sub: "2 here · sealed".into(),
                initial: "g".into(),
                pinned: false,
                header_sub: "2 here · sealed · neighbours".into(),
                messages: garden_msgs,
                draft: String::new(),
                scroll_y: 0.0,
            },
            CircleState {
                name: "harbor-lights".into(),
                sub: "3 here · sealed".into(),
                initial: "h".into(),
                pinned: false,
                header_sub: "3 here · sealed · waterfront".into(),
                messages: harbor_msgs,
                draft: String::new(),
                scroll_y: 0.0,
            },
        ];

        GuiState { circles, active: 1 }
    }

    /// Index of the currently active circle.
    pub fn active(&self) -> usize {
        self.active
    }

    /// Number of circles. Part of the state API (used by tests and round-3
    /// rail/model code); `#[allow(dead_code)]` because the bin doesn't call it yet.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.circles.len()
    }

    /// True if there are no circles (clippy-required companion to `len`).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.circles.is_empty()
    }

    /// The currently active circle's state.
    pub fn current(&self) -> &CircleState {
        &self.circles[self.active]
    }

    /// All circle metas, for building the rail model.
    pub fn metas(&self) -> &[CircleState] {
        &self.circles
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
mod tests {
    use super::*;
    use std::time::Instant;

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
        // active = 1. Type into circle 1, switch to 2 (captures circle 1's draft).
        st.switch_to(2, "draft-for-one".into(), 0.0);
        // now active = 2. Type into circle 2, switch back to 1.
        st.switch_to(1, "draft-for-two".into(), 0.0);
        // active = 1 — its draft is "draft-for-one".
        assert_eq!(st.current().draft, "draft-for-one");
        // switch to 2 with no further edits to 1.
        st.switch_to(2, String::new(), 0.0);
        // active = 2 — its draft is "draft-for-two", no bleed.
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

    #[test]
    fn switch_perf_budget() {
        // This test covers ONLY the state op (no Slint model build) to keep this
        // module Slint-free. The render half of the <100ms switch budget was
        // separately cleared by the perf spike. The per-call state op is
        // sub-microsecond; 100k calls must finish far under the switch budget.
        let mut st = GuiState::demo();
        let start = Instant::now();
        for i in 0..100_000 {
            let target = i % st.len();
            st.switch_to(target, "x".into(), -1.0);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 100,
            "100k state switches took {elapsed:?}, expected far under 100ms"
        );
    }
}
