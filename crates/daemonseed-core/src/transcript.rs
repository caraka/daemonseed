//! Chat-transcript ordering policy shared by the GUI + TUI surfaces (#131).
//!
//! A message's `sent_unix_ms` is an ADVISORY sender timestamp. On the open lobby
//! (world-writable) it is unauthenticated: a peer can stamp any value, and if the
//! transcript orders / high-waters directly on it, that peer can pin the view with an
//! extreme timestamp, bury (hide) a message far in the past, or suppress the unread
//! indicator with a far-future stamp. Ordering purely on *receive* time is not an
//! option either — the DHT rendezvous re-delivers real backlog after a (re)connect, and
//! receive-time would clump all of it at "now", destroying its true order.
//!
//! The resolution is a **trust window**: for ORDERING and the read high-water, clamp
//! `sent_unix_ms` into `[now − MAX_BACKLOG_AGE, now + MAX_CLOCK_SKEW]`. Real backlog
//! lives inside the window, so it is returned unchanged and orders by its exact send
//! time; only a forged / broken-clock value is pulled to a window edge, bounding a peer
//! to an honest participant's ordering influence. DEDUP must still key on the ORIGINAL
//! `sent_unix_ms` (this clamp is time-relative, so a re-swept forged frame would not
//! dedup on the clamped value). This bounds the attack; it does not authenticate the
//! timestamp — that needs signed authorship (the room↔circle authorship design), out of
//! scope here.

use std::time::Duration;

/// How far in the past an advisory `sent_unix_ms` is trusted for ORDERING. Generous —
/// it MUST exceed the longest a message legitimately lives in the DHT rendezvous ring,
/// so real backlog is never clamped (only forged / broken-clock timestamps are).
pub const TRANSCRIPT_MAX_BACKLOG_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// How far in the future an advisory `sent_unix_ms` is trusted (clock-skew tolerance).
/// Small — a timestamp beyond this is a bad clock or a forgery. Mirrors the tight
/// future bound the presence freshness check uses ([`crate::presence`]).
pub const TRANSCRIPT_MAX_CLOCK_SKEW: Duration = Duration::from_secs(120);

/// Clamp an untrusted advisory `sent_unix_ms` into the trust window for ORDERING and
/// the read high-water (#131). A value inside `[now − MAX_BACKLOG_AGE, now +
/// MAX_CLOCK_SKEW]` (all real backlog) is returned unchanged — so honest ordering is
/// exact and this is a no-op on legitimate traffic; only a forged / broken timestamp is
/// pulled to a window edge. Callers must still DEDUP on the ORIGINAL `sent_unix_ms` and
/// must not advance the high-water past `now` (clamp the high-water input with
/// `.min(now_ms)`), so a far-future stamp cannot suppress genuine unreads. Pure +
/// clock-injected for unit-testing.
pub fn clamp_order_ms(sent_unix_ms: i64, now_ms: i64) -> i64 {
    let past = TRANSCRIPT_MAX_BACKLOG_AGE.as_millis() as i64;
    let future = TRANSCRIPT_MAX_CLOCK_SKEW.as_millis() as i64;
    sent_unix_ms.clamp(now_ms - past, now_ms + future)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_window_timestamps_pass_through_unchanged() {
        // The property the ordering fix rests on: real backlog (anything within the
        // window) is NOT clamped, so it orders by its exact send time.
        let now = 1_700_000_000_000;
        for age_ms in [0i64, 1_000, 60_000, 3_600_000, 23 * 60 * 60 * 1000] {
            let sent = now - age_ms;
            assert_eq!(clamp_order_ms(sent, now), sent, "in-window is a no-op");
        }
        // A little into the future (within skew) also passes.
        assert_eq!(clamp_order_ms(now + 60_000, now), now + 60_000);
    }

    #[test]
    fn forged_extremes_clamp_to_the_window_edges() {
        let now = 1_700_000_000_000;
        let past = TRANSCRIPT_MAX_BACKLOG_AGE.as_millis() as i64;
        let future = TRANSCRIPT_MAX_CLOCK_SKEW.as_millis() as i64;
        // i64::MIN (transcript-pin / hide-in-past) clamps to the past edge, NOT 1970.
        assert_eq!(clamp_order_ms(i64::MIN, now), now - past);
        // i64::MAX (pin-to-bottom / unread-suppress) clamps to the near future.
        assert_eq!(clamp_order_ms(i64::MAX, now), now + future);
        // Just outside each edge clamps to the edge.
        assert_eq!(clamp_order_ms(now - past - 1, now), now - past);
        assert_eq!(clamp_order_ms(now + future + 1, now), now + future);
    }
}
