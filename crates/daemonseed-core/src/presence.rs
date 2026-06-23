//! Member-plane presence tracking — the receiver-side liveness view of the
//! connected-presence heartbeat (presence superstructure; design-of-record:
//! `docs/design/presence-superstructure.md`).
//!
//! The client-side counterpart to [`crate::heartbeat`]: a client listens to a
//! room/circle stream, opens + verifies each [`wire::MemberHeartbeat`]
//! ([`crate::heartbeat::open_heartbeat`]), and folds it into a
//! [`PresenceTracker`]. The tracker is the set of currently-live members — the
//! roster the UI (#75 / #77) will render. It is deliberately tiny and
//! transport-free so the TUI and GUI net actors can hold one each and feed it
//! verified heartbeats, giving presence a single shared shape.
//!
//! ## Liveness (the Demonsaw roster model)
//!
//! A member is on the roster while its heartbeat is fresh and drops off when the
//! heartbeat lapses past a TTL — appearing and disappearing is the only
//! indication (no dots, "last seen", or join/leave events). Two motions:
//!
//! - **Fast push:** an inbound heartbeat appears/refreshes the member immediately
//!   ([`PresenceTracker::apply`]).
//! - **Slow reap:** a periodic call ([`PresenceTracker::reap`]) ages out any
//!   member not re-heard within the TTL. The TTL is measured from the **local
//!   receive time** (a monotonic [`Instant`]), never the member's advisory
//!   wall-clock — there is no global clock and the relay stamps nothing.
//!
//! ## Cadence knobs (decoupled)
//!
//! The heartbeat *interval* sets presence resolution; the *miss count × interval*
//! sets the TTL — kept separate. The defaults bias to forgiveness: a jittered
//! interval in `[HEARTBEAT_INTERVAL_MIN, HEARTBEAT_INTERVAL_MAX]` with reap only
//! after [`HEARTBEAT_MISS_COUNT`] consecutive misses, so a brief wobble
//! (≤ 2 missed beacons) never reaps a live member while a genuine departure
//! clears within the TTL. Build a tracker matched to the emit cadence with
//! [`PresenceTracker::with_cadence`].
//!
//! ## Ordering / replay
//!
//! Each heartbeat carries an advisory `sent_unix_ms` bound into its provenance
//! signature. For a member already live, a heartbeat whose `sent_unix_ms` is
//! **older** than the stored one is ignored, so a reordered or replayed stale
//! beacon cannot reset a member's liveness clock backwards.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use daemonseed_proto::v1 as wire;

/// Lower bound of the jittered heartbeat emit interval (presence resolution).
pub const HEARTBEAT_INTERVAL_MIN: Duration = Duration::from_secs(10);
/// Upper bound of the jittered heartbeat emit interval.
pub const HEARTBEAT_INTERVAL_MAX: Duration = Duration::from_secs(15);
/// Consecutive missed beacons before a member is reaped (the TTL multiplier).
pub const HEARTBEAT_MISS_COUNT: u32 = 3;

/// Draw the next heartbeat emit interval, uniformly random in
/// `[HEARTBEAT_INTERVAL_MIN, HEARTBEAT_INTERVAL_MAX]`. Jitter keeps emissions
/// from forming a fixed-period timing signature (ISC-A-S2 traffic-shape) and
/// de-synchronises many clients so roll-call/heartbeat storms spread out. Drawn
/// from the OS CSPRNG; an entropy failure falls back to the midpoint rather than
/// panicking (a heartbeat is liveness, not a key — a non-random interval leaks
/// nothing and the next draw recovers).
pub fn next_heartbeat_interval() -> Duration {
    let min_ms = HEARTBEAT_INTERVAL_MIN.as_millis() as u64;
    let max_ms = HEARTBEAT_INTERVAL_MAX.as_millis() as u64;
    let span = max_ms - min_ms; // inclusive upper bound below
    let mut buf = [0u8; 8];
    let offset = match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf) % (span + 1),
        Err(_) => span / 2,
    };
    Duration::from_millis(min_ms + offset)
}

/// One live member — a roster row built from a verified
/// [`wire::MemberHeartbeat`]. Carries `pubkey` so the UI can bind the displayed
/// handle to `SHA-384(pubkey)[:12]` (ISC-C4 / ISC-C57) rather than trusting the
/// advisory `handle`.
#[derive(Clone, Debug)]
pub struct LiveMember {
    /// The member's self-asserted display handle (`name#12hex`). Advisory —
    /// cross-check against `pubkey` before trusting it.
    pub handle: String,
    /// The member's ML-DSA-87 public key (provenance was verified when the
    /// heartbeat was opened; kept for the ISC-C4 handle binding and as the
    /// member's stable identity key).
    pub pubkey: Vec<u8>,
    /// The member's advisory wall-clock at beacon time (unix ms). Used only for
    /// ordering successive beacons of the *same* member; never for TTL.
    pub beacon_unix_ms: i64,
    /// Local monotonic receive time of the most recent beacon. TTL reaping is
    /// measured from here.
    pub last_seen: Instant,
}

/// What [`PresenceTracker::apply`] did with a heartbeat — lets a caller decide
/// whether the roster needs a redraw without diffing the whole set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceChange {
    /// A previously-absent member appeared on the roster.
    Appeared,
    /// A known member's liveness was refreshed (no roster change).
    Refreshed,
    /// The heartbeat was a no-op (stale / reordered).
    Unchanged,
}

/// The live set of members heard in ONE room/circle. The caller scopes it: feed
/// it only heartbeats opened under this room's key (it does not re-check the
/// heartbeat's `room` field — the subscription already namespaces that), and
/// filters its own beacon (own presence is implicit, not roster state).
#[derive(Debug)]
pub struct PresenceTracker {
    members: HashMap<Vec<u8>, LiveMember>,
    ttl: Duration,
}

impl PresenceTracker {
    /// A new empty tracker reaping members not re-heard within `ttl` (measured
    /// from local receive time). `ttl` MUST exceed ~2 emit intervals.
    pub fn new(ttl: Duration) -> Self {
        Self {
            members: HashMap::new(),
            ttl,
        }
    }

    /// A tracker whose TTL is `interval × miss_count` — the cadence-matched
    /// constructor that keeps the two knobs (resolution vs liveness window)
    /// explicit and decoupled. With the [`HEARTBEAT_INTERVAL_MAX`] /
    /// [`HEARTBEAT_MISS_COUNT`] defaults this is the ~45 s bias-to-forgiveness
    /// window. `miss_count` is clamped to ≥ 1.
    pub fn with_cadence(interval: Duration, miss_count: u32) -> Self {
        Self::new(interval * miss_count.max(1))
    }

    /// The TTL this tracker reaps against.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Fold a verified heartbeat into the tracker. The caller has already
    /// `open_heartbeat`'d it (so provenance is verified), confirmed it belongs to
    /// this room, and confirmed it is not the caller's own beacon. `now` is the
    /// local monotonic receive time. A beacon older than the one already held for
    /// that member is ignored (`Unchanged`).
    pub fn apply(&mut self, hb: &wire::MemberHeartbeat, now: Instant) -> PresenceChange {
        match self.members.get_mut(&hb.sender_pubkey) {
            Some(cur) if hb.sent_unix_ms < cur.beacon_unix_ms => PresenceChange::Unchanged,
            Some(cur) => {
                cur.handle = hb.sender_handle.clone();
                cur.beacon_unix_ms = hb.sent_unix_ms;
                cur.last_seen = now;
                PresenceChange::Refreshed
            }
            None => {
                self.members.insert(
                    hb.sender_pubkey.clone(),
                    LiveMember {
                        handle: hb.sender_handle.clone(),
                        pubkey: hb.sender_pubkey.clone(),
                        beacon_unix_ms: hb.sent_unix_ms,
                        last_seen: now,
                    },
                );
                PresenceChange::Appeared
            }
        }
    }

    /// Age out every member not re-heard within the TTL — the slow half of
    /// liveness, called on the periodic timer. Returns the number reaped.
    pub fn reap(&mut self, now: Instant) -> usize {
        let ttl = self.ttl;
        let before = self.members.len();
        self.members
            .retain(|_, m| now.saturating_duration_since(m.last_seen) < ttl);
        before - self.members.len()
    }

    /// The live members, sorted by display handle then pubkey for a stable roster
    /// order.
    pub fn members(&self) -> Vec<LiveMember> {
        let mut out: Vec<LiveMember> = self.members.values().cloned().collect();
        out.sort_by(|a, b| {
            a.handle
                .cmp(&b.handle)
                .then_with(|| a.pubkey.cmp(&b.pubkey))
        });
        out
    }

    /// Number of live members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the roster is empty.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heartbeat(pubkey: &[u8], handle: &str, sent_unix_ms: i64) -> wire::MemberHeartbeat {
        wire::MemberHeartbeat {
            room: "lobby".to_owned(),
            sender_pubkey: pubkey.to_vec(),
            sender_handle: handle.to_owned(),
            sent_unix_ms,
            signature: vec![9, 9, 9],
        }
    }

    #[test]
    fn appear_then_refresh() {
        let mut t = PresenceTracker::new(Duration::from_secs(45));
        let t0 = Instant::now();
        assert_eq!(
            t.apply(&heartbeat(b"pk-a", "otter#aaa", 100), t0),
            PresenceChange::Appeared
        );
        assert_eq!(t.len(), 1);
        // A newer beacon for the same member refreshes (no new row).
        assert_eq!(
            t.apply(
                &heartbeat(b"pk-a", "otter#aaa", 200),
                t0 + Duration::from_secs(1)
            ),
            PresenceChange::Refreshed
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn stale_beacon_is_ignored() {
        let mut t = PresenceTracker::new(Duration::from_secs(45));
        let t0 = Instant::now();
        t.apply(&heartbeat(b"pk-a", "otter", 200), t0);
        // An older beacon must not move the member's clock backwards.
        assert_eq!(
            t.apply(
                &heartbeat(b"pk-a", "otter", 100),
                t0 + Duration::from_secs(1)
            ),
            PresenceChange::Unchanged
        );
    }

    #[test]
    fn distinct_pubkeys_are_distinct_members() {
        let mut t = PresenceTracker::new(Duration::from_secs(45));
        let t0 = Instant::now();
        t.apply(&heartbeat(b"pk-a", "alice#aaa", 100), t0);
        t.apply(&heartbeat(b"pk-b", "bob#bbb", 100), t0);
        assert_eq!(t.len(), 2);
    }

    /// ISC-7 bias-to-forgiveness: with interval=10s, miss_count=3 (TTL=30s), a
    /// member missing ≤ 2 beacons (≤ 25s) stays live; only ≥ 3 misses reaps.
    #[test]
    fn two_missed_beacons_never_reap_three_does() {
        let mut t = PresenceTracker::with_cadence(Duration::from_secs(10), 3);
        assert_eq!(t.ttl(), Duration::from_secs(30));
        let t0 = Instant::now();
        t.apply(&heartbeat(b"pk-a", "otter", 100), t0);
        // 2.5 intervals later (25s < 30s TTL) → still live.
        assert_eq!(t.reap(t0 + Duration::from_secs(25)), 0);
        assert_eq!(t.len(), 1);
        // 3.5 intervals later (35s > 30s TTL) → reaped.
        assert_eq!(t.reap(t0 + Duration::from_secs(35)), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn reap_ages_out_only_stale_members() {
        let mut t = PresenceTracker::new(Duration::from_secs(45));
        let t0 = Instant::now();
        t.apply(&heartbeat(b"old", "old", 100), t0);
        t.apply(&heartbeat(b"new", "new", 100), t0 + Duration::from_secs(40));
        // At t0 + 50s: "old" is 50s stale (>45s), "new" is 10s (<45s).
        assert_eq!(t.reap(t0 + Duration::from_secs(50)), 1);
        assert_eq!(t.len(), 1);
        assert_eq!(t.members()[0].handle, "new");
    }

    #[test]
    fn refresh_resets_the_reap_clock() {
        let mut t = PresenceTracker::new(Duration::from_secs(45));
        let t0 = Instant::now();
        t.apply(&heartbeat(b"pk-a", "otter", 100), t0);
        // Re-beacon at +40s resets last_seen, so at +50s it is only 10s old.
        t.apply(
            &heartbeat(b"pk-a", "otter", 200),
            t0 + Duration::from_secs(40),
        );
        assert_eq!(t.reap(t0 + Duration::from_secs(50)), 0);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn members_sorted_by_handle_then_pubkey() {
        let mut t = PresenceTracker::new(Duration::from_secs(45));
        let t0 = Instant::now();
        t.apply(&heartbeat(b"z", "banana#1", 100), t0);
        t.apply(&heartbeat(b"a", "apple#1", 100), t0);
        t.apply(&heartbeat(b"m", "apple#1", 100), t0);
        let rows: Vec<_> = t
            .members()
            .into_iter()
            .map(|m| (m.handle, m.pubkey))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("apple#1".to_owned(), b"a".to_vec()),
                ("apple#1".to_owned(), b"m".to_vec()),
                ("banana#1".to_owned(), b"z".to_vec()),
            ]
        );
    }

    /// ISC-8: the jittered interval stays within the band and varies across draws
    /// (not a constant). 64 draws all in range, and at least two distinct values.
    #[test]
    fn jittered_interval_within_band_and_varies() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let d = next_heartbeat_interval();
            assert!(
                d >= HEARTBEAT_INTERVAL_MIN && d <= HEARTBEAT_INTERVAL_MAX,
                "interval {d:?} outside [{HEARTBEAT_INTERVAL_MIN:?}, {HEARTBEAT_INTERVAL_MAX:?}]"
            );
            seen.insert(d.as_millis());
        }
        assert!(seen.len() > 1, "jitter produced a constant interval");
    }

    /// ISC-A-C39: a fresh tracker is empty — liveness is never persisted, so a new
    /// process starts with an empty roster.
    #[test]
    fn fresh_tracker_is_empty() {
        let t = PresenceTracker::new(Duration::from_secs(45));
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert!(t.members().is_empty());
    }
}
