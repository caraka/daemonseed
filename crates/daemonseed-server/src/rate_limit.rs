//! Multi-granularity, RAM-only abuse/DoS rate limiting (ISC-S17 / ISC-A-S12).
//!
//! Three enforcement layers defend against connection-flooding,
//! bandwidth-flooding, subscription-flooding, and compute-DoS:
//!
//! 1. **OS / kernel (per-source-IP).** Enforced *outside* this binary by the
//!    operator's host firewall (nftables / conntrack). It is deliberately not
//!    code here — per ISC-A-S1's OS-layer carve-out the per-IP state lives in
//!    kernel data structures the operator owns. See [`RateLimitConfig`] docs
//!    for the recommended floor; the operator manual carries the ruleset.
//! 2. **Per-connection.** [`ConnectionLimiter`] — a request token bucket, a
//!    concurrent-subscription cap, and a signature-verify cap, all owned by the
//!    single per-connection task and dropped with it.
//! 3. **Per-identity-key.** [`PerKeyRateTable`] — a process-lifetime, RAM-only
//!    `Arc<Mutex<HashMap<pubkey, count>>>` (the same shape as the M4b
//!    [`crate::identity_proof::SeenMap`]) capping concurrent connections per
//!    signing key, GC'd to empty as connections close.
//!
//! ## RAM-only, no profiling (ISC-A-S12)
//!
//! Nothing here serializes: there is no `serde` derive, no path field, no
//! persistence method, and the per-key table holds only a live connection
//! count — never a history, never an envelope, never an IP. State is wiped on
//! restart by construction (a fresh table is empty). Aggregate counters for
//! operator telemetry, if ever wanted, are an out-of-band export the operator
//! opts into — not built in here.
//!
//! ## Uniform close (ISC-A-S12)
//!
//! [`RateLimitTrip`] is a **server-side diagnostic only**. It is never written
//! to the wire — it has no `to_wire` / reason-code method, and every variant
//! maps to the identical action: the connection is dropped (the peer sees only
//! an OS reset), exactly the silent close [`crate::runtime`] already uses for
//! an identity-proof failure (M4b / ISC-40). The connecting peer cannot tell
//! which budget it exhausted, or whether a limiter was involved at all.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Multi-granularity rate-limit thresholds. Defaults are sized to the **Pi-4
/// (4 GB) civility floor** (ISC-S17): conservative enough that a Raspberry-Pi
/// relay stays responsive under load, while not tripping well-behaved clients.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitConfig {
    /// Per-connection request token-bucket capacity (max burst).
    pub req_burst: u32,
    /// Per-connection request token refill rate, tokens per second.
    pub req_per_sec: u32,
    /// Per-connection maximum concurrent CoT subscriptions.
    pub max_subscriptions: u32,
    /// Per-connection maximum signature-verify operations charged.
    pub max_verifies: u32,
    /// Per-identity-key maximum concurrent connections. Matches the reference
    /// client's own 4-connection cap (ISC-A-C10) so a conformant client never
    /// trips it.
    pub max_conns_per_key: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            req_burst: 32,
            req_per_sec: 16,
            max_subscriptions: 64,
            max_verifies: 8,
            max_conns_per_key: 4,
        }
    }
}

/// Which budget a limiter tripped on. **Server-side diagnostic only** — never a
/// wire payload (see module docs, ISC-A-S12). Deliberately carries no data and
/// has no serialization path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitTrip {
    /// Per-connection request token bucket empty.
    RequestRate,
    /// Per-connection concurrent-subscription cap reached.
    SubscriptionCap,
    /// Per-connection signature-verify cap reached.
    VerifyCap,
    /// Per-identity-key concurrent-connection cap reached.
    PerKeyConnCap,
}

/// A leaky/token bucket: `capacity` tokens, refilled at `refill_per_sec`. Each
/// admitted request costs one token.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket as of `now`.
    pub fn new_at(capacity: u32, refill_per_sec: u32, now: Instant) -> Self {
        Self {
            capacity: f64::from(capacity),
            tokens: f64::from(capacity),
            refill_per_sec: f64::from(refill_per_sec),
            last: now,
        }
    }

    /// A full bucket as of [`Instant::now`].
    pub fn new(capacity: u32, refill_per_sec: u32) -> Self {
        Self::new_at(capacity, refill_per_sec, Instant::now())
    }

    /// Try to take one token at time `now`; `true` if admitted.
    pub fn try_take_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Try to take one token at [`Instant::now`].
    pub fn try_take(&mut self) -> bool {
        self.try_take_at(Instant::now())
    }
}

/// Per-connection limiter — request rate, subscription cap, verify cap. Owned
/// by the per-connection task; dropped (and forgotten) when the task ends.
#[derive(Debug)]
pub struct ConnectionLimiter {
    config: RateLimitConfig,
    bucket: TokenBucket,
    subscriptions: u32,
    verifies: u32,
}

impl ConnectionLimiter {
    /// New limiter with `config`, full token bucket as of `now`.
    pub fn new_at(config: RateLimitConfig, now: Instant) -> Self {
        Self {
            bucket: TokenBucket::new_at(config.req_burst, config.req_per_sec, now),
            config,
            subscriptions: 0,
            verifies: 0,
        }
    }

    /// New limiter as of [`Instant::now`].
    pub fn new(config: RateLimitConfig) -> Self {
        Self::new_at(config, Instant::now())
    }

    /// Charge one request against the token bucket at `now`.
    pub fn try_request_at(&mut self, now: Instant) -> Result<(), RateLimitTrip> {
        if self.bucket.try_take_at(now) {
            Ok(())
        } else {
            Err(RateLimitTrip::RequestRate)
        }
    }

    /// Begin one CoT subscription; trips at the concurrent cap.
    pub fn try_subscribe(&mut self) -> Result<(), RateLimitTrip> {
        if self.subscriptions >= self.config.max_subscriptions {
            return Err(RateLimitTrip::SubscriptionCap);
        }
        self.subscriptions += 1;
        Ok(())
    }

    /// End one CoT subscription (saturating at zero).
    pub fn end_subscribe(&mut self) {
        self.subscriptions = self.subscriptions.saturating_sub(1);
    }

    /// Charge one signature-verify; trips at the per-connection verify cap.
    pub fn try_verify(&mut self) -> Result<(), RateLimitTrip> {
        if self.verifies >= self.config.max_verifies {
            return Err(RateLimitTrip::VerifyCap);
        }
        self.verifies += 1;
        Ok(())
    }

    /// Current count of active subscriptions on this connection.
    pub fn active_subscriptions(&self) -> u32 {
        self.subscriptions
    }
}

/// Process-lifetime, RAM-only per-identity-key connection table (ISC-S17 /
/// ISC-A-S12). Cheaply cloneable (shares one `Arc<Mutex<…>>`) so every
/// per-connection task sees the same per-key counts within one server uptime.
/// Holds only a live connection count per key — never serialized, GC'd to empty
/// as connections close.
#[derive(Clone)]
pub struct PerKeyRateTable {
    inner: Arc<Mutex<HashMap<Vec<u8>, u32>>>,
    max_conns_per_key: u32,
}

impl PerKeyRateTable {
    /// A fresh, empty table capping each key at `max_conns_per_key`.
    pub fn new(max_conns_per_key: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_conns_per_key,
        }
    }

    /// Admit a new connection for `key`; `Err(PerKeyConnCap)` if already at the
    /// cap. On success increments the key's live count.
    pub fn admit(&self, key: &[u8]) -> Result<(), RateLimitTrip> {
        let mut map = self.inner.lock().expect("PerKeyRateTable mutex poisoned");
        let current = map.get(key).copied().unwrap_or(0);
        if current >= self.max_conns_per_key {
            return Err(RateLimitTrip::PerKeyConnCap);
        }
        map.insert(key.to_vec(), current + 1);
        Ok(())
    }

    /// Admit a connection for `key`, returning an RAII [`KeySlotGuard`] that
    /// releases the slot on drop. Prefer this over [`admit`](Self::admit) +
    /// a manual [`release`](Self::release): the guard frees the slot even if
    /// the holding task unwinds (panic), closing the slot-leak gap flagged in
    /// the M9 review. `Err(PerKeyConnCap)` at the cap — and a refused
    /// acquisition does not increment the count.
    pub fn admit_guard(&self, key: &[u8]) -> Result<KeySlotGuard, RateLimitTrip> {
        self.admit(key)?;
        Ok(KeySlotGuard {
            table: self.clone(),
            key: key.to_vec(),
        })
    }

    /// Release a connection for `key` (GC-on-disconnect): decrement and remove
    /// the key entirely at zero, so a quiet server holds no per-key state.
    pub fn release(&self, key: &[u8]) {
        let mut map = self.inner.lock().expect("PerKeyRateTable mutex poisoned");
        if let Some(count) = map.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(key);
            }
        }
    }

    /// Live connection count for `key` (test/observability helper).
    pub fn active_for(&self, key: &[u8]) -> u32 {
        self.inner
            .lock()
            .expect("PerKeyRateTable mutex poisoned")
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    /// Number of keys currently tracked. Zero on a quiet server — the GC
    /// invariant (ISC-A-S12: no lingering per-key state).
    pub fn tracked_keys(&self) -> usize {
        self.inner
            .lock()
            .expect("PerKeyRateTable mutex poisoned")
            .len()
    }
}

/// RAII guard for a per-identity-key connection slot, returned by
/// [`PerKeyRateTable::admit_guard`]. Releasing the slot in `Drop` rather than
/// via an explicit call is the defense-in-depth fix for the M9-review slot
/// leak: a panic in the per-connection serving task unwinds through this
/// guard's frame, so the slot is freed during the unwind, whereas a manual
/// post-serve `release` line is simply skipped when the future panics.
pub struct KeySlotGuard {
    table: PerKeyRateTable,
    key: Vec<u8>,
}

impl Drop for KeySlotGuard {
    fn drop(&mut self) {
        self.table.release(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn cfg() -> RateLimitConfig {
        RateLimitConfig::default()
    }

    // ── Pi-4 floor config (ISC-S17) ────────────────────────────────────────

    #[test]
    fn defaults_are_pi4_civility_floor() {
        let c = RateLimitConfig::default();
        assert_eq!(c.max_conns_per_key, 4); // matches client A-C10 cap
        assert!(c.req_burst >= c.req_per_sec);
        assert!(c.max_subscriptions > 0 && c.max_verifies > 0);
    }

    // ── token bucket (ISC-S17 per-connection request rate) ─────────────────

    #[test]
    fn token_bucket_allows_full_burst_then_refuses() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(3, 1, t0);
        assert!(b.try_take_at(t0));
        assert!(b.try_take_at(t0));
        assert!(b.try_take_at(t0));
        assert!(!b.try_take_at(t0), "4th take in same instant must refuse");
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(2, 1, t0); // 1 token/sec
        assert!(b.try_take_at(t0));
        assert!(b.try_take_at(t0));
        assert!(!b.try_take_at(t0));
        // One second later → ~1 token refilled.
        let t1 = t0 + Duration::from_secs(1);
        assert!(b.try_take_at(t1));
        assert!(!b.try_take_at(t1));
    }

    #[test]
    fn token_bucket_refill_caps_at_capacity() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new_at(2, 100, t0);
        // Drain.
        assert!(b.try_take_at(t0));
        assert!(b.try_take_at(t0));
        // A long idle would refill 100*10 tokens, but capacity caps at 2.
        let later = t0 + Duration::from_secs(10);
        assert!(b.try_take_at(later));
        assert!(b.try_take_at(later));
        assert!(!b.try_take_at(later), "refill must not exceed capacity");
    }

    // ── per-connection caps (ISC-S17) ──────────────────────────────────────

    #[test]
    fn subscription_cap_enforced_and_released() {
        let mut lim = ConnectionLimiter::new(RateLimitConfig {
            max_subscriptions: 2,
            ..cfg()
        });
        assert!(lim.try_subscribe().is_ok());
        assert!(lim.try_subscribe().is_ok());
        assert_eq!(lim.try_subscribe(), Err(RateLimitTrip::SubscriptionCap));
        lim.end_subscribe();
        assert!(lim.try_subscribe().is_ok(), "a freed slot is reusable");
        assert_eq!(lim.active_subscriptions(), 2);
    }

    #[test]
    fn end_subscribe_saturates_at_zero() {
        let mut lim = ConnectionLimiter::new(cfg());
        lim.end_subscribe(); // no active subs — must not underflow
        assert_eq!(lim.active_subscriptions(), 0);
    }

    #[test]
    fn verify_cap_enforced() {
        let mut lim = ConnectionLimiter::new(RateLimitConfig {
            max_verifies: 2,
            ..cfg()
        });
        assert!(lim.try_verify().is_ok());
        assert!(lim.try_verify().is_ok());
        assert_eq!(lim.try_verify(), Err(RateLimitTrip::VerifyCap));
    }

    #[test]
    fn request_rate_trips_with_request_rate_cause() {
        let t0 = Instant::now();
        let mut lim = ConnectionLimiter::new_at(
            RateLimitConfig {
                req_burst: 1,
                req_per_sec: 1,
                ..cfg()
            },
            t0,
        );
        assert!(lim.try_request_at(t0).is_ok());
        assert_eq!(lim.try_request_at(t0), Err(RateLimitTrip::RequestRate));
    }

    // ── per-identity-key table (ISC-S17 / A-S12) ───────────────────────────

    #[test]
    fn per_key_admits_up_to_cap_then_trips() {
        let table = PerKeyRateTable::new(2);
        let key = b"pubkey-aaaa";
        assert!(table.admit(key).is_ok());
        assert!(table.admit(key).is_ok());
        assert_eq!(table.admit(key), Err(RateLimitTrip::PerKeyConnCap));
        assert_eq!(table.active_for(key), 2);
    }

    #[test]
    fn per_key_release_gcs_to_empty() {
        let table = PerKeyRateTable::new(4);
        let key = b"pubkey-bbbb";
        table.admit(key).unwrap();
        table.admit(key).unwrap();
        assert_eq!(table.tracked_keys(), 1);
        table.release(key);
        table.release(key);
        // GC: the key is gone, not left at zero — no lingering per-key state.
        assert_eq!(table.tracked_keys(), 0);
        assert_eq!(table.active_for(key), 0);
    }

    #[test]
    fn per_key_release_saturates_and_keys_are_independent() {
        let table = PerKeyRateTable::new(2);
        let a = b"key-a";
        let b = b"key-b";
        table.admit(a).unwrap();
        table.release(b); // release a never-admitted key — must not underflow/panic
        assert_eq!(table.active_for(b), 0);
        assert_eq!(table.active_for(a), 1);
    }

    #[test]
    fn per_key_table_shares_state_across_clones() {
        // Cloning shares the inner Arc — two per-connection tasks see one count.
        let table = PerKeyRateTable::new(2);
        let clone = table.clone();
        let key = b"shared";
        table.admit(key).unwrap();
        assert_eq!(clone.active_for(key), 1);
        clone.admit(key).unwrap();
        assert_eq!(clone.admit(key), Err(RateLimitTrip::PerKeyConnCap));
        assert_eq!(table.active_for(key), 2);
    }

    #[test]
    fn fresh_table_has_no_state() {
        // RAM-only by construction: a new table (≈ a restarted server) is empty.
        assert_eq!(PerKeyRateTable::new(4).tracked_keys(), 0);
    }

    // ── RAII slot guard (M10: defense-in-depth over the manual release) ─────

    #[test]
    fn admit_guard_releases_slot_on_drop() {
        let table = PerKeyRateTable::new(2);
        let key = b"guarded";
        {
            let _g = table.admit_guard(key).unwrap();
            assert_eq!(table.active_for(key), 1);
        }
        // Guard dropped at scope end → slot freed, key GC'd to empty.
        assert_eq!(table.active_for(key), 0);
        assert_eq!(table.tracked_keys(), 0);
    }

    #[test]
    fn admit_guard_trips_at_cap_without_acquiring() {
        let table = PerKeyRateTable::new(1);
        let key = b"capped";
        let _g = table.admit_guard(key).unwrap();
        assert_eq!(
            table.admit_guard(key).err(),
            Some(RateLimitTrip::PerKeyConnCap)
        );
        // The refused acquisition must not have incremented the count.
        assert_eq!(table.active_for(key), 1);
    }

    #[test]
    fn admit_guard_releases_slot_on_panic() {
        // The slot leak the M9 review flagged: a manual post-serve release is
        // skipped when the serving task panics. The RAII guard's Drop runs
        // during unwind, so the slot is freed even then.
        let table = PerKeyRateTable::new(2);
        let key = b"panicky";
        let t = table.clone();
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silence the expected panic
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = t.admit_guard(key).unwrap();
            assert_eq!(t.active_for(key), 1);
            panic!("serving task blew up while holding the slot");
        }));
        std::panic::set_hook(prev);
        assert!(result.is_err(), "the closure must have panicked");
        assert_eq!(
            table.active_for(key),
            0,
            "Drop must release the slot during unwind"
        );
        assert_eq!(table.tracked_keys(), 0);
    }
}
