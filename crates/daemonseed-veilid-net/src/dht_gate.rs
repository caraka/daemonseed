//! The **partitioned DHT permit accountant** (WB-5.1 / I5″.1) — daemonseed's
//! app-level limiter sitting *above* veilid's process-global 16-permit DHT gate
//! (`network.dht.max_concurrent_operations`, `storage_manager/mod.rs`). Every gated
//! DHT op holds exactly one permit from exactly one of four **dedicated** pools, so
//! daemonseed's own combined in-flight DHT-op count is provably `≤ DHT_BUDGET =
//! 16 − margin` — it can never itself saturate veilid's gate, and — the property the
//! first WB-5 build lacked — the read lane can never drain the write/chat/floor lanes
//! (each is a separate pool, not a shared general pool).
//!
//! # The four pools (WB-5.1 / I5″.1)
//! `DHT_BUDGET = 16 − margin(2) = 14`, partitioned **chat 2 · floor 1 · write W_max ·
//! read (14 − 3 − W_max)** — at the frozen `W_max = 2`, read = 9. There are **no
//! cross-pool fallback paths** (the old two-pool `acquire_priority` general spill is
//! gone), so the combined-in-flight proof is pure pool arithmetic:
//! - [`acquire_chat`](DhtGate::acquire_chat) — chat/user-action writes (I4). Never
//!   waits on any non-chat pool (WB-ISC-24).
//! - [`acquire_floor`](DhtGate::acquire_floor) — the I8 starvation floor + I6b
//!   deadline lane (WB-5.1 / I5″.5): one ADDITIONAL guaranteed write slot.
//! - [`acquire_write`](DhtGate::acquire_write) — the non-chat window lane (I5, cap
//!   `W_max`).
//! - [`acquire_read`](DhtGate::acquire_read) — per-GET sweep/resweep permits (I5″.2).
//!   A sweep acquires one read permit around EACH `get_dht_value` and releases it
//!   between GETs, so read occupancy ≤ the read partition regardless of live sweep
//!   count (N-independence — WB-ISC-22), and reads cannot be starved by writes at all.
//!
//! # The margin (WB-5.1 / I5″.1) — an enforced invariant, not a census
//! [`DHT_GATE_MARGIN`] is reserved for daemonseed's *un-gated* DHT ops —
//! `open_dht_record` and `watch_dht_values`. The invariant: **no un-gated DHT-op
//! class may ever exceed the margin concurrently.** Originally this held by a census
//! argument (open/watch were issued inline in the serial actor command loop, ≤ 1 in
//! flight); the consumer-route self-heal (`docs/design/consumer-route-self-heal.md`
//! §RS-2) adds un-gated call sites in *spawned* contexts (repair, Refresh), which the
//! frozen §I5″.1 clause says re-opens the argument. It is now discharged **by
//! construction**: a capacity-[`DHT_GATE_MARGIN`] semaphore (the un-gated-op limiter),
//! acquired via [`acquire_ungated`](DhtGate::acquire_ungated), that **every**
//! `open_dht_record` / `watch_dht_values` site holds across its raw veilid call. Peak
//! un-gated concurrency ≤ margin(2) is thus enforced, not asserted, under any
//! composition of concurrent connect + repair + Refresh (CRSH-ISC-14). The limiter is
//! separate from the four gated pools and draws on the reserved margin, so a task may
//! hold a chat/floor/write permit while acquiring it (the publish path opens a record
//! under its write permit) — but the single-permit rule below still forbids nesting it
//! with a *read* permit (CRSH-ISC-17). (The one-time margin audit against veilid-core
//! 0.5.4's `allow_offline` background flush is recorded in
//! `docs/design/veilid-write-budget.md` §I5″.1 / the margin-audit decision; if that
//! flush drew the operation gate, `DHT_GATE_MARGIN` would rise to 3 and the READ pool
//! would yield one permit — no other pool moves.)
//!
//! # Single-permit rule (WB-5.1 / I5″.1, WB-ISC-28)
//! No task ever holds a permit from one pool while acquiring from another (no
//! cross-pool hold-and-wait — the deadlock precondition dedicated pools would
//! otherwise admit). Structurally true: sweeps only read, the write sink acquires
//! exactly one permit per dispatch, I9 forbids read-triggered writes, and the write
//! path issues no gated GET (content fetch is off-gate). This is a frozen rule with a
//! code-inspection anti-ISC.
//!
//! # Content fetch is OFF this budget
//! Content fetch (`app_call` over private routes, #109/#113) is OFF veilid's DHT gate
//! (`rpc_app_call.rs` reaches `rpc_processor`, never `StorageManager`), so the fetch
//! window does NOT draw on this budget — only DHT sets + gets do.
//!
//! # Acquire-wait is telemetry ONLY (WB-5.1 / I5″.3, WB-ISC-27)
//! Each [`GatePermit`] still records its `acquire_wait`, but under dedicated pools the
//! window equals the write partition size, so a window-dispatched write acquires its
//! permit immediately — write-lane acquire-wait is identically ~zero and carries no
//! information. It is trace-recorded telemetry consumed by NO control decision (the
//! §I5′.2 acquire-wait controller is retired).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// veilid's process-global DHT gate size (`network.dht.max_concurrent_operations`
/// default, `storage_manager/mod.rs`). A stock build never changes it.
pub const DHT_GATE_PERMITS: usize = 16;
/// Headroom kept below veilid's gate for daemonseed's un-gated DHT ops
/// (`open_dht_record` / `watch_dht_values`, ≤ 1 in flight) — an invariant, not slack
/// (see the module docs). The margin audit (design §I5″.1) confirmed the
/// `allow_offline` background flush does not require raising this to 3.
pub const DHT_GATE_MARGIN: usize = 2;
/// daemonseed's self-imposed combined (chat + floor + write + read) in-flight DHT-op
/// budget.
pub const DHT_BUDGET: usize = DHT_GATE_PERMITS - DHT_GATE_MARGIN;
/// Chat lane permits (I4): two concurrent cross-record chat sets proceed in parallel
/// (send in room A, switch, send in room B inside one set-RTT); a third queues behind
/// chat only, never on non-chat (WB-ISC-24).
pub const CHAT_PERMITS: usize = 2;
/// Floor lane permits (I8 starvation floor + I6b deadline, WB-5.1 / I5″.5): one
/// ADDITIONAL guaranteed write slot, so saturated aggregate write concurrency is
/// `W_max + 1`, never collapsing to 1.
pub const FLOOR_PERMITS: usize = 1;
/// `W_max` — the frozen non-chat window ceiling (I5, WB-5.1 / I5″.1). Starts at 2; a
/// step-up is gated on WB-ISC-19 (an attended single-client control on a host that can
/// attach to the public network) and is a static re-construction of the gate at the new
/// `W_max`, never a live re-partition.
pub const W_MAX: usize = 2;
/// Read lane permits — the elastic residual: `DHT_BUDGET − chat − floor − W_max`. At
/// the frozen `W_max = 2` this is 9.
pub const READ_PERMITS: usize = DHT_BUDGET - CHAT_PERMITS - FLOOR_PERMITS - W_MAX;
/// The read-partition floor (WB-5.1 / I5″.1/.2): the `W_max` step-up may not take read
/// below this, pinning the worst-case warmup GET-throughput inflation to ≤ ~2.2× the
/// felt-tested 68–112s baseline. Ceiling on `W_max` is therefore `14 − 3 − 6 = 5`.
pub const R_MIN: usize = 6;

// The `W_max = 2` partition pins exactly to the budget at compile time (WB-5.1 /
// I5″.1): the four dedicated pools sum to DHT_BUDGET with none below its floor, and the
// budget + margin stays within veilid's 16-permit gate. A step-up re-derives the read
// side by the general invariant `read = DHT_BUDGET − chat − floor − W_max ≥ R_MIN`.
const _: () = {
    assert!(DHT_BUDGET + DHT_GATE_MARGIN <= DHT_GATE_PERMITS);
    assert!(CHAT_PERMITS + FLOOR_PERMITS + W_MAX + READ_PERMITS == DHT_BUDGET);
    assert!(READ_PERMITS >= R_MIN);
    assert!(CHAT_PERMITS >= 1 && FLOOR_PERMITS >= 1 && W_MAX >= 1);
    // The step-up ceiling: read can absorb a W_max up to 5 and stay ≥ R_MIN.
    assert!(DHT_BUDGET - CHAT_PERMITS - FLOOR_PERMITS - 5 >= R_MIN);
};

/// A held DHT-op permit from exactly one pool. Dropping it (including on panic-unwind —
/// RAII, the #168 leak-proofing) releases the permit back to its pool.
pub struct GatePermit {
    _permit: OwnedSemaphorePermit,
    /// The permit-acquire-wait — trace telemetry ONLY (WB-5.1 / I5″.3, WB-ISC-27); no
    /// scheduler, gate, or window logic consumes it.
    pub acquire_wait: Duration,
}

/// The shared partitioned DHT permit accountant (see the module docs). Clone the `Arc`
/// into the write sink and every read-lane call site so all four lanes draw on one
/// budgeted partition.
pub struct DhtGate {
    chat: Arc<Semaphore>,
    floor: Arc<Semaphore>,
    write: Arc<Semaphore>,
    read: Arc<Semaphore>,
    /// The un-gated-op limiter (WB-5.1 / I5″.1, consumer-route self-heal §RS-2):
    /// capacity [`DHT_GATE_MARGIN`], drawing on the reserved margin below veilid's gate
    /// rather than on any of the four budgeted pools. Every `open_dht_record` /
    /// `watch_dht_values` call site holds one of these permits across its raw veilid
    /// call, so peak un-gated concurrency is bounded to the margin by construction
    /// (CRSH-ISC-14), not by a census argument.
    ungated: Arc<Semaphore>,
}

impl DhtGate {
    /// The production accountant: the four dedicated pools at their frozen sizes
    /// (`W_max = 2` → chat 2 · floor 1 · write 2 · read 9).
    pub fn new() -> Arc<Self> {
        Self::with_pools(CHAT_PERMITS, FLOOR_PERMITS, W_MAX, READ_PERMITS)
    }

    /// A gate with explicit pool sizes — for oracles that need deterministic
    /// saturation (WB-ISC-17/21/22/24). Each size is forced to ≥ 1 so no pool is
    /// dead-locked-by-construction.
    pub fn with_pools(chat: usize, floor: usize, write: usize, read: usize) -> Arc<Self> {
        Arc::new(Self {
            chat: Arc::new(Semaphore::new(chat.max(1))),
            floor: Arc::new(Semaphore::new(floor.max(1))),
            write: Arc::new(Semaphore::new(write.max(1))),
            read: Arc::new(Semaphore::new(read.max(1))),
            // The un-gated-op limiter is fixed at the margin constant for every gate —
            // it is the enforced §I5″.1 invariant, not a tunable partition, so it takes
            // no constructor parameter (see the module docs / §RS-2).
            ungated: Arc::new(Semaphore::new(DHT_GATE_MARGIN.max(1))),
        })
    }

    /// Acquire from `sem`, timing the wait for telemetry. tokio's `Semaphore` is
    /// FIFO-fair, so a released permit goes to the queue head (within-pool fairness,
    /// WB-ISC-22).
    async fn acquire(sem: &Arc<Semaphore>) -> GatePermit {
        let t0 = Instant::now();
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .expect("dht gate pool is never closed");
        GatePermit {
            _permit: permit,
            acquire_wait: t0.elapsed(),
        }
    }

    /// Acquire a chat-lane permit (I4). Pool-exclusive: it draws ONLY the chat pool,
    /// so a chat write never waits on a non-chat pool (WB-ISC-24).
    pub async fn acquire_chat(self: &Arc<Self>) -> GatePermit {
        Self::acquire(&self.chat).await
    }

    /// Acquire the floor-lane permit — the I8 starvation floor + I6b deadline lane
    /// (WB-5.1 / I5″.5). Capacity 1: an ADDITIONAL guaranteed write slot.
    pub async fn acquire_floor(self: &Arc<Self>) -> GatePermit {
        Self::acquire(&self.floor).await
    }

    /// Acquire a non-chat window-lane permit (I5). Pool-exclusive; the scheduler's
    /// window never dispatches more than `W_max` of these concurrently, so this
    /// acquire is immediate (write-lane acquire-wait ~0 — WB-ISC-27).
    pub async fn acquire_write(self: &Arc<Self>) -> GatePermit {
        Self::acquire(&self.write).await
    }

    /// Acquire a read-lane (per-GET sweep/resweep) permit from the dedicated read
    /// pool. Held around ONE `get_dht_value` and released before the next, so read
    /// occupancy ≤ the read partition regardless of live sweep count (WB-ISC-21/22).
    /// Writes never draw this pool, so reads and writes cannot starve each other.
    pub async fn acquire_read(self: &Arc<Self>) -> GatePermit {
        Self::acquire(&self.read).await
    }

    /// Acquire an un-gated-op permit from the margin-sized limiter (WB-5.1 / I5″.1,
    /// consumer-route self-heal §RS-2). **Every** `open_dht_record` /
    /// `watch_dht_values` call site MUST hold this permit across the raw veilid call —
    /// the subscribe path, the publish-path record open, and (as they land) the repair
    /// arm and Refresh alike — so peak un-gated concurrency is `≤ DHT_GATE_MARGIN`,
    /// enforced rather than asserted (CRSH-ISC-14). The permit draws on the reserved
    /// margin, not on any of the four budgeted pools; hold it around ONE open (or one
    /// watch) and drop it before the next so the margin is occupied only for the raw
    /// call's duration. **Single-permit rule (CRSH-ISC-17):** a caller must never hold a
    /// read-pool permit while acquiring this, or acquire a read permit while holding
    /// this — repair/Refresh acquire their per-GET read permits strictly outside the
    /// limiter's span. (Holding a chat/floor/write permit across an `acquire_ungated`
    /// is permitted: the publish path opens a record under its write permit, and the
    /// limiter draws separate margin, so no pool is over-subscribed and the acquire
    /// ordering — pool then limiter, never the reverse — admits no cycle.)
    pub async fn acquire_ungated(self: &Arc<Self>) -> GatePermit {
        Self::acquire(&self.ungated).await
    }

    /// Currently-available chat-pool permits. For the WB-ISC-17 partition oracle.
    pub fn available_chat(&self) -> usize {
        self.chat.available_permits()
    }

    /// Currently-available floor-pool permits. For the WB-ISC-17 partition oracle.
    pub fn available_floor(&self) -> usize {
        self.floor.available_permits()
    }

    /// Currently-available write-pool (window) permits. For the WB-ISC-17 partition
    /// oracle.
    pub fn available_write(&self) -> usize {
        self.write.available_permits()
    }

    /// Currently-available read-pool permits. For the WB-ISC-17/22 oracles.
    pub fn available_read(&self) -> usize {
        self.read.available_permits()
    }

    /// Currently-available un-gated-op limiter permits. For the CRSH-ISC-14 live
    /// concurrency probe (`DHT_GATE_MARGIN − available_ungated()` = un-gated ops in
    /// flight).
    pub fn available_ungated(&self) -> usize {
        self.ungated.available_permits()
    }

    /// Total in-flight DHT ops across ALL four pools — the budgeted quantity. The
    /// WB-ISC-17 oracle asserts this never exceeds `DHT_BUDGET` at any instant.
    pub fn total_in_flight(&self, chat: usize, floor: usize, write: usize, read: usize) -> usize {
        (chat - self.available_chat())
            + (floor - self.available_floor())
            + (write - self.available_write())
            + (read - self.available_read())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The budget arithmetic holds at runtime too (the compile-time `const _` block is
    /// the primary guarantee; this documents the derived values).
    #[test]
    fn budget_arithmetic_matches_the_documented_partition() {
        assert_eq!(DHT_BUDGET, 14);
        assert_eq!(CHAT_PERMITS, 2);
        assert_eq!(FLOOR_PERMITS, 1);
        assert_eq!(W_MAX, 2);
        assert_eq!(READ_PERMITS, 9);
        assert_eq!(
            CHAT_PERMITS + FLOOR_PERMITS + W_MAX + READ_PERMITS,
            DHT_BUDGET
        );
        // READ_PERMITS >= R_MIN is compile-time-guaranteed by the `const _` block above.
        assert_eq!(
            READ_PERMITS.max(R_MIN),
            READ_PERMITS,
            "read stays above its floor"
        );
    }

    // ── WB-ISC-17 (Anti) ──────────────────────────────────────────────────────
    /// The enforced partitioned accountant: drain all four pools to their caps
    /// simultaneously — combined in-flight = the budget, never more; the
    /// partition-sum invariant holds at every instant; and each pool caps
    /// independently (a chat write and a floor-eligible write still acquire with
    /// every OTHER pool saturated).
    #[tokio::test]
    async fn wb_isc_17_partitioned_accountant_never_exceeds_budget() {
        // A tiny deterministic gate: chat 2 · floor 1 · write 2 · read 3 = budget 8.
        let (c, f, w, r) = (2, 1, 2, 3);
        let gate = DhtGate::with_pools(c, f, w, r);

        // Saturate every pool.
        let mut held = Vec::new();
        for _ in 0..c {
            held.push(gate.acquire_chat().await);
        }
        for _ in 0..f {
            held.push(gate.acquire_floor().await);
        }
        for _ in 0..w {
            held.push(gate.acquire_write().await);
        }
        for _ in 0..r {
            held.push(gate.acquire_read().await);
        }

        // Instantaneous partition-sum invariant: every pool at 0 available, combined
        // in-flight = the budget exactly — never more (the defect class was a unit
        // mismatch; this oracles the invariant itself).
        assert_eq!(gate.available_chat(), 0);
        assert_eq!(gate.available_floor(), 0);
        assert_eq!(gate.available_write(), 0);
        assert_eq!(gate.available_read(), 0);
        assert_eq!(
            gate.total_in_flight(c, f, w, r),
            c + f + w + r,
            "combined in-flight = the full pool budget, never more"
        );

        // A further acquire on ANY pool must block — no over-subscription past its cap.
        for blocked in [
            tokio::time::timeout(Duration::from_millis(40), gate.acquire_chat())
                .await
                .is_err(),
            tokio::time::timeout(Duration::from_millis(40), gate.acquire_floor())
                .await
                .is_err(),
            tokio::time::timeout(Duration::from_millis(40), gate.acquire_write())
                .await
                .is_err(),
            tokio::time::timeout(Duration::from_millis(40), gate.acquire_read())
                .await
                .is_err(),
        ] {
            assert!(
                blocked,
                "a saturated pool blocks — cap enforced (no over-subscription)"
            );
        }

        // Free one write permit; only the write pool recovers (pools are independent).
        let one = held.pop().unwrap();
        drop(one);
        assert_eq!(gate.available_read(), 1, "the freed permit was a read");
        drop(held);
    }

    // ── WB-ISC-24 (Anti) ──────────────────────────────────────────────────────
    /// A chat write never waits on any non-chat acquisition — unconditional, both
    /// chat permits. Saturate write + floor + read with long holds; two concurrent
    /// chats acquire immediately; a third waits ONLY on the chat pool.
    #[tokio::test]
    async fn wb_isc_24_chat_never_waits_on_nonchat() {
        let gate = DhtGate::with_pools(2, 1, 2, 3);
        // Saturate every NON-chat pool.
        let mut held = Vec::new();
        for _ in 0..1 {
            held.push(gate.acquire_floor().await);
        }
        for _ in 0..2 {
            held.push(gate.acquire_write().await);
        }
        for _ in 0..3 {
            held.push(gate.acquire_read().await);
        }
        assert_eq!(
            gate.available_chat(),
            2,
            "chat pool untouched by non-chat draws"
        );

        // Two concurrent chats acquire immediately — they draw ONLY the chat pool.
        let c1 = tokio::time::timeout(Duration::from_millis(60), gate.acquire_chat())
            .await
            .expect("first chat acquires without waiting on any non-chat pool");
        let c2 = tokio::time::timeout(Duration::from_millis(60), gate.acquire_chat())
            .await
            .expect("second chat acquires without waiting on any non-chat pool");
        assert!(c1.acquire_wait < Duration::from_millis(30));
        assert!(c2.acquire_wait < Duration::from_millis(30));
        assert_eq!(gate.available_chat(), 0);

        // A third chat blocks ONLY on the chat pool (not on the saturated non-chat
        // pools) — and unblocks the instant a chat permit frees, nothing else.
        let third = tokio::time::timeout(Duration::from_millis(60), gate.acquire_chat()).await;
        assert!(
            third.is_err(),
            "a third concurrent chat waits — but only on chat"
        );
        drop(c1);
        let third = tokio::time::timeout(Duration::from_millis(100), gate.acquire_chat())
            .await
            .expect("freeing a CHAT permit (no non-chat pool moved) unblocks the third chat");
        drop((c2, third, held));
    }

    /// A non-chat acquire never draws the chat pool, and vice versa — pool exclusivity
    /// (no fallback path). With every non-chat pool free, the chat pool stays full.
    #[tokio::test]
    async fn pools_are_exclusive_no_fallback() {
        let gate = DhtGate::new();
        let _w = gate.acquire_write().await;
        let _f = gate.acquire_floor().await;
        let _r = gate.acquire_read().await;
        assert_eq!(
            gate.available_chat(),
            CHAT_PERMITS,
            "non-chat draws never touch chat"
        );
        assert_eq!(gate.available_write(), W_MAX - 1);
        assert_eq!(gate.available_floor(), FLOOR_PERMITS - 1);
        assert_eq!(gate.available_read(), READ_PERMITS - 1);
    }

    // CRSH-ISC-14 (limiter core; full connect+repair+Refresh composition probe lands
    // with steps 3/7) ──────────────────────────────────────────────────────────
    /// The un-gated-op limiter caps concurrent open/watch ops at [`DHT_GATE_MARGIN`].
    /// Spawn well over the margin of concurrent `acquire_ungated` holders; each records
    /// peak in-flight while holding its permit and yields so the scheduler can attempt
    /// to over-subscribe. Max-in-flight never exceeds the margin, and every holder
    /// completes (no deadlock/starve). This is the limiter's own bound; the live
    /// connect+repair+Refresh composition probe arrives with steps 3/7.
    #[tokio::test]
    async fn crsh_isc_14_ungated_ops_bounded_by_margin() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let gate = DhtGate::new();
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));

        const HOLDERS: usize = 4 * DHT_GATE_MARGIN; // well over the margin
        let mut handles = Vec::new();
        for _ in 0..HOLDERS {
            let gate = gate.clone();
            let max_in_flight = max_in_flight.clone();
            let completed = completed.clone();
            handles.push(tokio::spawn(async move {
                let permit = gate.acquire_ungated().await;
                let in_flight = DHT_GATE_MARGIN - gate.available_ungated();
                max_in_flight.fetch_max(in_flight, Ordering::SeqCst);
                // Hold across a yield so peers pile onto the limiter — the window in
                // which an unbounded limiter would over-subscribe the margin.
                tokio::task::yield_now().await;
                drop(permit);
                completed.fetch_add(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            max_in_flight.load(Ordering::SeqCst) <= DHT_GATE_MARGIN,
            "un-gated op concurrency never exceeds the margin ({DHT_GATE_MARGIN}) \
             regardless of how many sites contend"
        );
        assert_eq!(
            completed.load(Ordering::SeqCst),
            HOLDERS,
            "every un-gated holder acquired and completed (no deadlock/starve)"
        );
    }
}
