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
//! The heartbeat *interval* sets presence resolution; the TTL sets the liveness
//! window — kept separate. The legacy relay path uses a jittered interval in
//! `[HEARTBEAT_INTERVAL_MIN, HEARTBEAT_INTERVAL_MAX]` with reap after
//! [`HEARTBEAT_MISS_COUNT`] misses ([`PresenceTracker::with_cadence`]).
//!
//! ## WB-1 write-budget presence (the veilid path — design: `docs/design/veilid-write-budget.md`)
//!
//! Presence is a *read* question ("who is here") that was built as a high-frequency
//! *write*. The WB-1 model moves the intelligence to the read side under the WB-0
//! invariant (*user activity may influence only local computation, never the timing,
//! size, or existence of a presence-class network emission*). Write side: a
//! [`next_keepalive_interval`] keepalive every [180,220]s that takes no input from
//! activity, plus session-boundary join/leave writes. Read side (here, emission-free):
//! [`PresenceTracker::apply`] folds beacons (incl. leave tombstones with
//! [`PresenceTracker::apply_member_write`]-style dominance), a same-room chat write
//! advances freshness ([`PresenceTracker::apply_member_write`]), the tracker is
//! room-scoped ([`PresenceTracker::for_room`]), the TTL is [`PRESENCE_TTL`], and
//! [`PresenceTracker::reap`] suspends while the local write funnel is congested
//! ([`REAP_CONGESTION_THRESHOLD`]).
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

// ── WB-1 write-budget presence cadence (design: docs/design/veilid-write-budget.md) ──

/// Lower bound of the jittered **keepalive** interval (WB-1.2). Far slower than
/// the legacy [`HEARTBEAT_INTERVAL_MIN`]: presence is a *read* question moved to
/// the read side, so the write cadence only has to be well above the ~14.7s DHT
/// watch floor while staying under the WB-2 write ceiling. Jitter is drawn fresh
/// per emission and takes NO input from user activity (sends, reads, congestion).
pub const KEEPALIVE_INTERVAL_MIN: Duration = Duration::from_secs(180);
/// Upper bound of the jittered keepalive interval (WB-1.2).
pub const KEEPALIVE_INTERVAL_MAX: Duration = Duration::from_secs(220);
/// Presence liveness TTL (WB-1.9) — a member leaves the roster when
/// `now − freshness > PRESENCE_TTL`. = 2 × keepalive-max (220s) + 160s slack for
/// queue + write + propagation; deliberately the same constant class as the share
/// TTL backstop (one liveness doctrine). Graceful close disappears immediately via
/// the leave tombstone; this TTL is the crash/network-loss backstop only.
pub const PRESENCE_TTL: Duration = Duration::from_secs(600);
/// Enqueue-to-ack latency at/above which reaping is suspended (WB-1.10 /
/// WB-ISC-5). Presence reaping is calibrated to emit cadence, but its input
/// (keepalive arrival) is latency-dependent; under a deep local write funnel a
/// member's keepalive can sit queued past its TTL, so a receiver whose own
/// enqueue-to-ack latency is elevated suspends reaping (bias-to-forgiveness —
/// suspension only ever *delays* disappearance). Slightly below the scheduler's
/// AIMD breach threshold so reaping goes conservative before the window shrinks.
pub const REAP_CONGESTION_THRESHOLD: Duration = Duration::from_secs(8);

/// Draw the next jittered **keepalive** interval, uniformly random in
/// `[KEEPALIVE_INTERVAL_MIN, KEEPALIVE_INTERVAL_MAX]` (WB-1.2). Fresh per emission
/// so there is no fixed-period signature and no stable cross-record phase
/// relationship (WB-3.I6). Drawn from the OS CSPRNG; an entropy failure falls back
/// to the midpoint (a keepalive is liveness, not a key — the next draw recovers).
pub fn next_keepalive_interval() -> Duration {
    let min_ms = KEEPALIVE_INTERVAL_MIN.as_millis() as u64;
    let max_ms = KEEPALIVE_INTERVAL_MAX.as_millis() as u64;
    let span = max_ms - min_ms; // inclusive upper bound below
    let mut buf = [0u8; 8];
    let offset = match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf) % (span + 1),
        Err(_) => span / 2,
    };
    Duration::from_millis(min_ms + offset)
}

/// #78 replay-freshness — how far in the PAST a beacon's advisory `sent_unix_ms`
/// may be (relative to local wall-clock) and still be accepted. An untrusted
/// relay controls delivery and can replay a captured beacon to keep a departed
/// member on the roster past the presence TTL; rejecting beacons older than this
/// bounds that replay to the window instead of indefinitely. CONSERVATIVE on
/// purpose: it must exceed realistic unsynchronised-clock skew between peers
/// (daemonseed assumes no shared time source), so it errs toward accepting a
/// legitimate beacon from a skewed peer over tightening the replay bound. The
/// value (and whether to depend on loosely-synced wall clocks at all, vs a
/// nonce/sequence anti-replay) is an OPEN design call flagged for ratification —
/// see ISA Decisions (#78).
pub const REPLAY_FRESHNESS_PAST: Duration = Duration::from_secs(300);
/// #78 replay-freshness — how far in the FUTURE a beacon may be timestamped and
/// still be accepted (a small skew allowance; a beacon further ahead is a
/// fast/forged clock). Tighter than the past bound because a future timestamp has
/// no benign replay explanation.
pub const REPLAY_FRESHNESS_FUTURE: Duration = Duration::from_secs(60);

/// Whether a heartbeat's advisory `sent_unix_ms` is fresh relative to the local
/// wall-clock `now_unix_ms` — inside `[now − REPLAY_FRESHNESS_PAST, now +
/// REPLAY_FRESHNESS_FUTURE]`. The ingest path drops a non-fresh beacon (#78) so a
/// replayed/captured beacon cannot refresh presence or share-liveness for a
/// member who has actually departed. This BOUNDS replay to the window; it does not
/// eliminate replay of a still-recent beacon (that needs a nonce/sequence scheme,
/// a deferred design). Pure + clock-injected so it is unit-testable without a real
/// clock.
pub fn beacon_is_fresh(sent_unix_ms: i64, now_unix_ms: i64) -> bool {
    let past = REPLAY_FRESHNESS_PAST.as_millis() as i64;
    let future = REPLAY_FRESHNESS_FUTURE.as_millis() as i64;
    sent_unix_ms >= now_unix_ms - past && sent_unix_ms <= now_unix_ms + future
}

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
    /// A leave tombstone (WB-1.3) removed a member from the roster (a graceful
    /// departure the receiver should render immediately).
    Departed,
    /// The heartbeat was a no-op (stale / reordered / cross-room /
    /// leave-dominated).
    Unchanged,
}

/// The live set of members heard in ONE room/circle. The caller scopes it: feed
/// it only heartbeats opened under this room's key (it does not re-check the
/// heartbeat's `room` field — the subscription already namespaces that), and
/// filters its own beacon (own presence is implicit, not roster state).
#[derive(Debug)]
pub struct PresenceTracker {
    members: HashMap<Vec<u8>, LiveMember>,
    /// Recently-departed members and the advisory wall-clock at which they left
    /// (WB-1.5 leave-dominance): a leave tombstone records `leave_ms` here, and
    /// thereafter no same-room write with `sent_unix_ms ≤ leave_ms` re-freshens the
    /// member (a final chat racing the tombstone cannot flicker it back). A
    /// strictly-newer write clears the mark (a genuine rejoin). Marks are pruned
    /// after the TTL (a same-room write older than that cannot realistically still
    /// arrive). Keyed by pubkey.
    departed: HashMap<Vec<u8>, DepartedMark>,
    /// This tracker's room label (WB-1.6 same-room bound). When set, a member
    /// write tagged with a different room is refused (`Unchanged`) — a public
    /// surface must never timestamp another room's activity. `None` disables the
    /// check (the beacon path is already namespaced by its subscription/key).
    room: Option<String>,
    ttl: Duration,
}

/// A leave-dominance tombstone: the advisory leave time plus the local instant it
/// was recorded (for TTL-based pruning of the mark).
#[derive(Clone, Copy, Debug)]
struct DepartedMark {
    leave_ms: i64,
    at: Instant,
}

impl PresenceTracker {
    /// A new empty tracker reaping members not re-heard within `ttl` (measured
    /// from local receive time). `ttl` MUST exceed ~2 emit intervals. Room-agnostic
    /// (the same-room bound is off); prefer [`Self::for_room`] on the veilid path.
    pub fn new(ttl: Duration) -> Self {
        Self {
            members: HashMap::new(),
            departed: HashMap::new(),
            room: None,
            ttl,
        }
    }

    /// A tracker scoped to `room` (WB-1.6): a member write tagged with a different
    /// room is refused. Reaps against `ttl` (use [`PRESENCE_TTL`] on the veilid
    /// path).
    pub fn for_room(room: impl Into<String>, ttl: Duration) -> Self {
        Self {
            members: HashMap::new(),
            departed: HashMap::new(),
            room: Some(room.into()),
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
        if hb.is_leave {
            // WB-1.3 leave tombstone: record the leave and reap the member.
            return self.apply_leave(&hb.sender_pubkey, hb.sent_unix_ms, now);
        }
        self.fold_write(&hb.sender_pubkey, &hb.sender_handle, hb.sent_unix_ms, now)
    }

    /// Advance a member's roster freshness from a **verified same-room member
    /// write** that is NOT a presence beacon — a chat / room message (WB-1.5 /
    /// WB-ISC-4). The caller has already verified the write's provenance and knows
    /// the sender's pubkey, handle, and advisory `sent_unix_ms`. `room` is the
    /// write's room; if this tracker is scoped ([`Self::for_room`]) and `room`
    /// differs, the write is refused (WB-1.6 same-room bound / WB-ISC-2). An active
    /// member thus stays fresh from its own chat traffic — the receiver holds
    /// evidence fresher than any beacon — so a chatty member never false-reaps and
    /// no keepalive write is needed for it. This is a pure local computation: it
    /// emits nothing (WB-ISC-8).
    pub fn apply_member_write(
        &mut self,
        room: &str,
        pubkey: &[u8],
        handle: &str,
        sent_unix_ms: i64,
        now: Instant,
    ) -> PresenceChange {
        if self.room.as_deref().is_some_and(|r| r != room) {
            // Cross-room activity must never refresh this room's roster (WB-1.6).
            return PresenceChange::Unchanged;
        }
        self.fold_write(pubkey, handle, sent_unix_ms, now)
    }

    /// The shared liveness fold for any verified same-room member write (beacon or
    /// chat), applying WB-1.5 leave-dominance and same-member ordering.
    fn fold_write(
        &mut self,
        pubkey: &[u8],
        handle: &str,
        sent_unix_ms: i64,
        now: Instant,
    ) -> PresenceChange {
        // WB-1.5 leave-dominance: a write at or before a recorded leave cannot
        // re-freshen a departed member (a final chat racing the tombstone). A
        // strictly-newer write is a genuine rejoin/post-leave message → clear it.
        if let Some(mark) = self.departed.get(pubkey) {
            if sent_unix_ms <= mark.leave_ms {
                return PresenceChange::Unchanged;
            }
            self.departed.remove(pubkey);
        }
        match self.members.get_mut(pubkey) {
            Some(cur) if sent_unix_ms < cur.beacon_unix_ms => PresenceChange::Unchanged,
            Some(cur) => {
                cur.handle = handle.to_owned();
                cur.beacon_unix_ms = sent_unix_ms;
                cur.last_seen = now;
                PresenceChange::Refreshed
            }
            None => {
                self.members.insert(
                    pubkey.to_vec(),
                    LiveMember {
                        handle: handle.to_owned(),
                        pubkey: pubkey.to_vec(),
                        beacon_unix_ms: sent_unix_ms,
                        last_seen: now,
                    },
                );
                PresenceChange::Appeared
            }
        }
    }

    /// Apply a leave tombstone (WB-1.3/1.5): record `leave_ms` as a dominance mark
    /// and drop the member from the live roster. A *stale* leave (older than the
    /// member's freshest write) is ignored so a replayed leave cannot kill a live
    /// member.
    fn apply_leave(&mut self, pubkey: &[u8], leave_ms: i64, now: Instant) -> PresenceChange {
        if let Some(cur) = self.members.get(pubkey)
            && leave_ms < cur.beacon_unix_ms
        {
            return PresenceChange::Unchanged;
        }
        let entry = self
            .departed
            .entry(pubkey.to_vec())
            .or_insert(DepartedMark { leave_ms, at: now });
        if leave_ms >= entry.leave_ms {
            entry.leave_ms = leave_ms;
            entry.at = now;
        }
        if self.members.remove(pubkey).is_some() {
            PresenceChange::Departed
        } else {
            PresenceChange::Unchanged
        }
    }

    /// Age out every member not re-heard within the TTL — the slow half of
    /// liveness, called on the periodic timer. Returns the reaped members so the
    /// caller can drop their shares too (#76 prune-on-heartbeat-lapse); use
    /// `.len()` for a bare count.
    ///
    /// **Reap-in-calm (WB-1.10 / WB-ISC-5).** `congested` is the receiver's own
    /// enqueue-to-ack write-latency signal being elevated (queue wait + record-lock
    /// wait + set RTT — NOT set-RTT alone): while it is `true`, reaping is
    /// **suspended** (returns empty, mutates nothing), because a member's keepalive
    /// may simply be sitting in the local write funnel. Suspension only ever
    /// *delays* disappearance (bias-to-forgiveness). This is a pure local
    /// computation over local state — it emits nothing (WB-ISC-8).
    pub fn reap(&mut self, now: Instant, congested: bool) -> Vec<LiveMember> {
        if congested {
            return Vec::new();
        }
        let ttl = self.ttl;
        // Prune stale leave-dominance marks — a same-room write older than the TTL
        // can no longer realistically arrive to be dominated.
        self.departed
            .retain(|_, m| now.saturating_duration_since(m.at) < ttl);
        let mut reaped = Vec::new();
        self.members.retain(|_, m| {
            let alive = now.saturating_duration_since(m.last_seen) < ttl;
            if !alive {
                reaped.push(m.clone());
            }
            alive
        });
        reaped
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
            live_share_ids: vec![],
            is_leave: false,
        }
    }

    fn leave(pubkey: &[u8], handle: &str, sent_unix_ms: i64) -> wire::MemberHeartbeat {
        let mut hb = heartbeat(pubkey, handle, sent_unix_ms);
        hb.is_leave = true;
        hb
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

    /// #78 replay-freshness: a beacon within the window is fresh; one timestamped
    /// far in the past (a relay replaying a captured beacon) or far in the future
    /// (a forged/fast clock) is rejected, so the ingest path drops it before it can
    /// refresh presence for a departed member.
    #[test]
    fn beacon_freshness_accepts_recent_rejects_replayed_or_future() {
        let now = 1_000_000_000_000_i64; // arbitrary wall-clock anchor (ms)
        // In-window: current, slightly past, slightly future.
        assert!(beacon_is_fresh(now, now));
        assert!(beacon_is_fresh(now - 10_000, now)); // 10s old — a normal beacon
        assert!(beacon_is_fresh(
            now - REPLAY_FRESHNESS_PAST.as_millis() as i64,
            now
        )); // exactly at the past edge
        assert!(beacon_is_fresh(
            now + REPLAY_FRESHNESS_FUTURE.as_millis() as i64,
            now
        )); // exactly at the future edge
        // Out of window: a replayed beacon older than the past bound, and a beacon
        // dated beyond the future skew allowance.
        assert!(!beacon_is_fresh(
            now - REPLAY_FRESHNESS_PAST.as_millis() as i64 - 1,
            now
        ));
        assert!(!beacon_is_fresh(now - 3_600_000, now)); // an hour-old replay
        assert!(!beacon_is_fresh(
            now + REPLAY_FRESHNESS_FUTURE.as_millis() as i64 + 1,
            now
        ));
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
        assert_eq!(t.reap(t0 + Duration::from_secs(25), false).len(), 0);
        assert_eq!(t.len(), 1);
        // 3.5 intervals later (35s > 30s TTL) → reaped, and reap names the member.
        let reaped = t.reap(t0 + Duration::from_secs(35), false);
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].pubkey, b"pk-a".to_vec());
        assert!(t.is_empty());
    }

    #[test]
    fn reap_ages_out_only_stale_members() {
        let mut t = PresenceTracker::new(Duration::from_secs(45));
        let t0 = Instant::now();
        t.apply(&heartbeat(b"old", "old", 100), t0);
        t.apply(&heartbeat(b"new", "new", 100), t0 + Duration::from_secs(40));
        // At t0 + 50s: "old" is 50s stale (>45s), "new" is 10s (<45s).
        assert_eq!(t.reap(t0 + Duration::from_secs(50), false).len(), 1);
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
        assert_eq!(t.reap(t0 + Duration::from_secs(50), false).len(), 0);
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

    /// WB-ISC-1 (partial, timing): the keepalive interval takes no input from
    /// activity — it is a pure CSPRNG draw in the [180,220]s band and varies across
    /// draws (the dispatch-independence half is the scheduler oracle WB-ISC-1 in
    /// `daemonseed-veilid-net::schedule`).
    #[test]
    fn wb_isc_1_keepalive_interval_within_band_and_varies() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let d = next_keepalive_interval();
            assert!(
                d >= KEEPALIVE_INTERVAL_MIN && d <= KEEPALIVE_INTERVAL_MAX,
                "keepalive interval {d:?} outside [{KEEPALIVE_INTERVAL_MIN:?}, {KEEPALIVE_INTERVAL_MAX:?}]"
            );
            seen.insert(d.as_millis());
        }
        assert!(
            seen.len() > 1,
            "keepalive jitter produced a constant interval"
        );
    }

    /// WB-ISC-2 (Anti): presence state for room R never consumes input from another
    /// room. A member write tagged with a different room does not refresh a scoped
    /// tracker; only a same-room write folds.
    #[test]
    fn wb_isc_2_cross_room_write_never_refreshes() {
        let mut t = PresenceTracker::for_room("lobby", PRESENCE_TTL);
        let t0 = Instant::now();
        assert_eq!(
            t.apply_member_write("circle-secret", b"pk", "a#0", 100, t0),
            PresenceChange::Unchanged
        );
        assert!(
            t.is_empty(),
            "cross-room activity must not populate the roster"
        );
        assert_eq!(
            t.apply_member_write("lobby", b"pk", "a#0", 100, t0),
            PresenceChange::Appeared
        );
        assert_eq!(t.len(), 1);
    }

    /// WB-ISC-3: a connected-but-silent member (keepalives only, no chat) stays on
    /// the roster indefinitely while its keepalives land — a full 3×TTL horizon.
    #[test]
    fn wb_isc_3_silent_member_stays_while_keepalives_land() {
        let mut t = PresenceTracker::for_room("lobby", PRESENCE_TTL);
        let t0 = Instant::now();
        let horizon = PRESENCE_TTL * 3;
        let step = Duration::from_secs(200); // inside the [180,220]s band
        let mut now = t0;
        let mut ms = 1_000_000_000_000_i64;
        t.apply(&heartbeat(b"pk", "quiet#0", ms), now);
        while now.saturating_duration_since(t0) < horizon {
            now += step;
            ms += 200_000;
            t.apply(&heartbeat(b"pk", "quiet#0", ms), now);
            assert!(
                t.reap(now, false).is_empty(),
                "a member beaconing on time is never reaped"
            );
        }
        assert_eq!(t.len(), 1);
    }

    /// WB-ISC-4: a member's freshness advances on any verified same-room member
    /// write without a beacon — a chat-only member stays fresh well past the TTL.
    #[test]
    fn wb_isc_4_chat_only_member_stays_fresh_past_ttl() {
        let mut t = PresenceTracker::for_room("lobby", PRESENCE_TTL);
        let t0 = Instant::now();
        let mut now = t0;
        let mut ms = 1_000_000_000_000_i64;
        // Joined via one beacon, then ONLY chats — never beacons again.
        t.apply(&heartbeat(b"pk", "chatter#0", ms), now);
        let step = Duration::from_secs(300); // > half TTL: only chat keeps it alive
        for _ in 0..5 {
            now += step;
            ms += 300_000;
            assert_ne!(
                t.apply_member_write("lobby", b"pk", "chatter#0", ms, now),
                PresenceChange::Unchanged,
                "a same-room chat write advances freshness"
            );
            assert!(
                t.reap(now, false).is_empty(),
                "a chatting member stays fresh past the TTL without any beacon"
            );
        }
        assert_eq!(t.len(), 1);
    }

    /// WB-ISC-5: reaping is suspended while enqueue-to-ack latency is elevated and
    /// resumes in calm (an expired TTL is reaped only when the local write funnel
    /// is not congested — bias-to-forgiveness).
    #[test]
    fn wb_isc_5_reap_suspended_while_congested() {
        let mut t = PresenceTracker::for_room("lobby", PRESENCE_TTL);
        let t0 = Instant::now();
        t.apply(&heartbeat(b"pk", "a#0", 1_000_000_000_000), t0);
        let past_ttl = t0 + PRESENCE_TTL + Duration::from_secs(60);
        // Elevated congestion + expired TTL → NO reap.
        assert!(t.reap(past_ttl, true).is_empty());
        assert_eq!(t.len(), 1, "a congested receiver suspends reaping");
        // Calm → the same expired member reaps.
        let reaped = t.reap(past_ttl, false);
        assert_eq!(reaped.len(), 1);
        assert!(t.is_empty());
    }

    /// WB-ISC-7: a leave tombstone dominates freshness — no same-room write with
    /// `sent_unix_ms ≤ leave_ms` re-freshens a departed member (a final chat racing
    /// the tombstone cannot flicker it back), while a genuinely newer write rejoins.
    #[test]
    fn wb_isc_7_leave_tombstone_dominates_freshness() {
        let mut t = PresenceTracker::for_room("lobby", PRESENCE_TTL);
        let t0 = Instant::now();
        t.apply(&heartbeat(b"pk", "a#0", 100), t0);
        assert_eq!(t.len(), 1);
        // Leave at leave_ms = 200 → reaped.
        assert_eq!(
            t.apply(&leave(b"pk", "a#0", 200), t0 + Duration::from_secs(1)),
            PresenceChange::Departed
        );
        assert!(t.is_empty(), "a leave reaps the member");
        // A late chat AT or BEFORE the leave time must not resurrect it.
        assert_eq!(
            t.apply_member_write("lobby", b"pk", "a#0", 150, t0 + Duration::from_secs(2)),
            PresenceChange::Unchanged
        );
        assert_eq!(
            t.apply_member_write("lobby", b"pk", "a#0", 200, t0 + Duration::from_secs(2)),
            PresenceChange::Unchanged
        );
        assert!(t.is_empty(), "a same-room write ≤ leave_ms stays reaped");
        // A genuinely newer write (rejoin) re-freshens normally.
        assert_eq!(
            t.apply(&heartbeat(b"pk", "a#0", 201), t0 + Duration::from_secs(3)),
            PresenceChange::Appeared
        );
        assert_eq!(t.len(), 1);
    }

    /// A stale (replayed) leave dated before the member's freshest write must not
    /// kill a live member.
    #[test]
    fn stale_leave_does_not_kill_a_live_member() {
        let mut t = PresenceTracker::for_room("lobby", PRESENCE_TTL);
        let t0 = Instant::now();
        t.apply(&heartbeat(b"pk", "a#0", 500), t0);
        assert_eq!(
            t.apply(&leave(b"pk", "a#0", 400), t0 + Duration::from_secs(1)),
            PresenceChange::Unchanged
        );
        assert_eq!(
            t.len(),
            1,
            "a leave older than the freshest beacon is ignored"
        );
    }

    /// WB-ISC-8 (Anti): the read side is emission-free by construction — apply /
    /// apply_member_write / reap take NO network sink and yield only local data (a
    /// [`PresenceChange`] or a `Vec<LiveMember>`). There is no path from any of them
    /// to a write or fetch; the absence of any emitter parameter IS the guarantee.
    /// A full inference→reap cycle produces only that local data.
    #[test]
    fn wb_isc_8_read_side_is_emission_free() {
        let mut t = PresenceTracker::for_room("lobby", PRESENCE_TTL);
        let t0 = Instant::now();
        let _: PresenceChange = t.apply(&heartbeat(b"pk", "a#0", 100), t0);
        let _: PresenceChange = t.apply_member_write("lobby", b"pk", "a#0", 200, t0);
        let _: PresenceChange = t.apply(&leave(b"pk", "a#0", 300), t0 + Duration::from_secs(1));
        let reaped: Vec<LiveMember> = t.reap(t0 + PRESENCE_TTL * 2, false);
        assert!(reaped.is_empty() && t.is_empty());
    }
}
