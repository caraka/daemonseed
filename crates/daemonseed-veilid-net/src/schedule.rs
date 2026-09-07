//! The **write scheduler** — WB-3's single prioritized, rate-limited funnel that
//! every `set_dht_value` in the actor passes through (design-of-record:
//! `docs/design/veilid-write-budget.md`, FROZEN 2026-07-09).
//!
//! Presence, share adverts, keepalives, and warmup republishes draw on Veilid's
//! seconds-per-write discovery primitive with no allocation mechanism; under load
//! writes backed up to 90–314s and starved chat, presence freshness, and route
//! refresh (#159). This module is the allocation mechanism: one queue in front of
//! the DHT write primitive that reorders across records by priority, coalesces
//! redundant current-state writes, bounds the in-flight non-chat set, and
//! guarantees chat and withdraw/leave semantics.
//!
//! # Invariants realized (WB-3, verbatim contract)
//! - **I1 — single funnel.** Every write enters through [`WriteSchedulerHandle::enqueue`];
//!   the actor's write commands and the advert-refresh path all funnel here, so no
//!   writer bypasses the queue. The funnel dispatches by calling an injected
//!   [`WriteSink`] — in production the existing per-record dispatch functions (which
//!   keep #131 clamp-at-insert + ring-seq-inside-`record_lock` untouched, I2/I13),
//!   in tests a counting mock (the WB-2 oracle seam).
//! - **I1 priority classes** ([`WriteClass`], highest first): chat/user-action,
//!   session-boundary (presence join/leave, share withdraw), share-advert refresh,
//!   keepalives, post-warmup republish. Reordering is ACROSS records only.
//! - **I2 — per-record FIFO.** Same-record writes dispatch in enqueue order; a record
//!   dispatches its head only when it has no write in flight (per-record single-flight),
//!   so slot/seq assignment inside the sink's `record_lock` is never concurrent for one
//!   record (I13). Cross-record reordering is safe because those guarantees are
//!   per-record.
//! - **I3 — coalescing + dominance.** A queued last-writer-wins current-state write
//!   superseded by a newer write for the same `(record, logical id)` is dropped. The
//!   key is the LOGICAL id, never the physical subkey. Tombstones/withdraws are
//!   non-coalescible and DOMINATE: a queued withdraw/leave is never superseded by any
//!   same-id current-state write, and any same-id current-state enqueued while a
//!   withdraw is pending is dropped (the #121/#118 share-resurrection guard). Chat ring
//!   writes are never coalesced or dropped.
//! - **I4 — chat latency bound (WB-5.1 / I5″.4 re-scope).** Chat writes draw the
//!   dedicated 2-permit chat pool: up to two concurrent cross-record chats dispatch
//!   ≤ 2s at any non-chat queue depth; a third waits only on chat, never on non-chat.
//!   Never counted against the window.
//! - **I5 / I5″ — partitioned lanes (WB-5.1 amendment, 2026-07-13).** The §I5′.2
//!   acquire-wait window CONTROLLER is **retired** — under the four DEDICATED
//!   [`crate::dht_gate::DhtGate`] pools (chat / floor / write / read) the window equals
//!   the write partition size, so it carries no acquire-wait signal to control on. The
//!   non-chat window is the STATIC `min(distinct pending non-chat records, W_max)` and
//!   never varies with any latency signal (WB-ISC-16). `W_max` is the frozen constant 2
//!   (a step-up is gated on WB-ISC-19). Reads never draw the write pool, so reads and
//!   writes cannot starve each other; genuine offered load stays priced by the WB-1/WB-2
//!   rate ceilings, not a controller.
//! - **I6b — deadline override (WB-5.1 / I5″.5 re-home).** A write with a hard DHT
//!   expiry (operator MOTD/announcement keepalive, #158) dispatches via the FLOOR lane
//!   ahead of all age-based floor candidates, its permit wait bounded by one in-flight
//!   floor set (`slack ≥ 660s` guarantees it lands inside the TTL).
//! - **I7 — shutdown flush + shed.** On graceful close, pending chat + tombstones/
//!   withdraws flush within the close budget; class-3/4/5 current-state writes are shed.
//! - **I8 — starvation floor (WB-5.1 / I5″.5).** I8's "escalates one class" stays the
//!   window-lane ordering rule; additionally a non-chat write whose `starved_since` age
//!   exceeds `FLOOR_AGE = 2 × age_bounds[class]` becomes eligible for the dedicated
//!   capacity-1 FLOOR lane — an ADDITIONAL guaranteed slot, so saturated aggregate write
//!   concurrency is `W_max + 1`, never 1 (bounds class-5 starvation → the #157 symptom).
//!   `starved_since` survives I3 coalescing so a cadence-refreshed id still ages.
//! - **I9 — no read-triggered writes.** The enqueue surface accepts only write intents;
//!   no read/render/reap path can reach it (WB-0's derived rule, enforced structurally
//!   by there being no write-emitting call from the read side).
//!
//! The I1 funnel also retires #154's inline-park failure mode: the actor's write
//! commands enqueue and return, so a slow DHT set never parks the command loop.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::error::{Result, VeilidNetError};

/// A DHT record's identity for FIFO + coalescing scope — the rendezvous owner seed
/// (a `set_dht_value` targets one record derived from one owner seed).
pub type RecordId = [u8; 32];

/// Which DHT-gate pool a dispatched write draws (WB-5.1 / I5″.1). The scheduler picks
/// the lane; the sink acquires the matching pool (chat → `acquire_chat`, floor →
/// `acquire_floor`, window → `acquire_write`). There is no cross-pool fallback, so the
/// combined-in-flight proof is pool arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchLane {
    /// Chat / user-action write (I4) — the 2-permit chat pool, never waits on non-chat.
    Chat,
    /// The I8 starvation-floor + I6b deadline lane (I5″.5) — the 1-permit floor pool,
    /// an ADDITIONAL guaranteed write slot.
    Floor,
    /// The non-chat window lane (I5) — the `W_max`-permit write pool.
    Window,
}

/// The result of one [`WriteSink`] dispatch: the write's outcome plus the
/// permit-acquire-wait the sink observed acquiring its [`crate::dht_gate::DhtGate`]
/// permit.
pub struct DispatchOutcome {
    /// The DHT write result.
    pub result: Result<()>,
    /// Permit-acquire-wait — the delay between requesting the DHT-gate permit and
    /// getting one. Under WB-5.1's dedicated pools the window equals the write-pool
    /// size, so a window-dispatched write acquires immediately and this is ~zero; it is
    /// **telemetry only** (WB-5.1 / I5″.3, WB-ISC-27) — the §I5′.2 acquire-wait window
    /// controller is retired, and no scheduler/gate/window logic consumes it. `None`
    /// when the transport cannot surface it.
    pub acquire_wait: Option<Duration>,
}

impl DispatchOutcome {
    /// An outcome with no acquire-wait signal (the I5′.2 fallback shape).
    pub fn bare(result: Result<()>) -> Self {
        Self {
            result,
            acquire_wait: None,
        }
    }
}

/// The future a [`WriteSink`] returns for one dispatch: owns its data so the
/// scheduler can spawn it off the driver loop.
pub type DispatchFuture = Pin<Box<dyn Future<Output = DispatchOutcome> + Send>>;

/// The seam over the physical DHT write (WB-2 oracle requirement). The scheduler
/// decides WHEN and IN WHAT ORDER to write and on WHICH [`DispatchLane`]; the sink
/// acquires the matching [`crate::dht_gate::DhtGate`] pool (chat / floor / write —
/// WB-5.1 / I5″.1), performs one write, and returns its [`DispatchOutcome`]. Production
/// wires this to the existing per-record dispatch functions (so #131 + ring-seq-in-
/// `record_lock` stay untouched); the oracle wires a counting mock with an injected
/// clock, so the whole scheduler is testable in paused time with no live DHT.
pub trait WriteSink: Send + Sync + 'static {
    /// The opaque per-write dispatch token the scheduler carries and hands back.
    type Item: Send + 'static;
    /// Perform one DHT write on `lane` — the sink acquires that pool's permit (chat
    /// draws the chat pool and never waits on non-chat, floor draws the 1-permit floor
    /// pool, window draws the `W_max` pool; no cross-pool fallback — WB-5.1 / I5″.1).
    /// The returned future is spawned off the driver loop.
    fn dispatch(&self, item: Self::Item, lane: DispatchLane) -> DispatchFuture;
}

/// Priority class (WB-3.I1), highest priority first. `rank()` is the sort key
/// (1 = highest). Reordering by class applies ACROSS records only (I2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteClass {
    /// (1) Chat / user-action append-ring writes. Reserved dispatch slot; never
    /// counted against the I5 non-chat cap; never coalesced (I3/I4).
    Chat,
    /// (2) Session-boundary writes: presence join/leave, share withdraw.
    SessionBoundary,
    /// (3) Share-advert refresh.
    AdvertRefresh,
    /// (4) Keepalives — presence beacon, operator MOTD keepalive.
    Keepalive,
    /// (5) Post-warmup republish writes.
    Republish,
}

impl WriteClass {
    /// Sort key: 1 (highest priority) .. 5 (lowest).
    pub fn rank(self) -> u8 {
        match self {
            WriteClass::Chat => 1,
            WriteClass::SessionBoundary => 2,
            WriteClass::AdvertRefresh => 3,
            WriteClass::Keepalive => 4,
            WriteClass::Republish => 5,
        }
    }
}

/// How a write interacts with coalescing + dominance (WB-3.I3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteKind {
    /// Append-ring chat/room write — NEVER coalesced or dropped (WB-ISC-11).
    Ring,
    /// Last-writer-wins current-state write, coalescible on its `logical_id`.
    CurrentState {
        /// The LOGICAL id (member id / share id / "motd") — the coalescing key.
        /// Never the physical subkey (hash collisions would starve a colliding id).
        logical_id: String,
    },
    /// Tombstone / withdraw — non-coalescible, DOMINATES same-id current-state
    /// (WB-ISC-12, the #121/#118 resurrection guard).
    Tombstone {
        /// The logical id whose current-state this tombstone suppresses.
        logical_id: String,
    },
}

impl WriteKind {
    fn logical_id(&self) -> Option<&str> {
        match self {
            WriteKind::Ring => None,
            WriteKind::CurrentState { logical_id } | WriteKind::Tombstone { logical_id } => {
                Some(logical_id)
            }
        }
    }
    fn is_tombstone(&self) -> bool {
        matches!(self, WriteKind::Tombstone { .. })
    }
}

/// One write submitted to the funnel. Carries everything the scheduler needs to
/// order/coalesce it (`record`, `class`, `kind`, `deadline`) plus the opaque
/// dispatch `item` handed to the [`WriteSink`] and an optional completion `reply`.
pub struct WriteRequest<D> {
    /// The target DHT record (FIFO + coalescing scope).
    pub record: RecordId,
    /// Priority class (I1).
    pub class: WriteClass,
    /// Coalescing / dominance behavior (I3).
    pub kind: WriteKind,
    /// Optional hard deadline (I6b): dispatch ahead of class order once passed.
    pub deadline: Option<Instant>,
    /// Opaque dispatch token handed to the sink at dispatch.
    pub item: D,
    /// Fired with the write result (or `Ok(())` when the write is coalesced/
    /// superseded by a winning same-id write — its intent is subsumed).
    pub reply: Option<oneshot::Sender<Result<()>>>,
}

/// Tunable scheduler parameters. Defaults track the WB-2/WB-5.1 freeze.
#[derive(Clone, Copy, Debug)]
pub struct SchedulerConfig {
    /// `W_max` — the frozen non-chat window ceiling (WB-5.1 / I5″.1 = 2). The window
    /// is the STATIC `min(distinct pending non-chat records, W_max)` — the §I5′.2
    /// acquire-wait controller is retired, so there is no dynamic guard state. A
    /// step-up is gated on the WB-ISC-19 single-client control; do NOT raise it
    /// here.
    pub nonchat_cap: usize,
    /// Per-class starvation age bound (I8), indexed by `rank()-1`. Used for I8 window
    /// escalation (a write older than its bound escalates one class) AND, doubled, for
    /// the floor-lane eligibility predicate `FLOOR_AGE = 2 × age_bounds[class]`
    /// (WB-5.1 / I5″.5). Both measured against `starved_since` (survives coalescing).
    pub age_bounds: [Duration; 5],
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            nonchat_cap: 2,
            // chat(unused) / session / advert / keepalive / republish.
            age_bounds: [
                Duration::from_secs(2),
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(120),
                Duration::from_secs(90),
            ],
        }
    }
}

/// A cloneable handle onto the running scheduler task.
pub struct WriteSchedulerHandle<D> {
    tx: mpsc::UnboundedSender<SchedMsg<D>>,
}

impl<D> Clone for WriteSchedulerHandle<D> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<D: Send + 'static> WriteSchedulerHandle<D> {
    /// Submit a write to the funnel (I1). Non-blocking; the result (or a
    /// coalesced-away `Ok`) is delivered via `req.reply`. This is the ONLY write
    /// entry point — reads never call it (I9).
    pub fn enqueue(&self, req: WriteRequest<D>) {
        // A closed channel means the scheduler task is gone (shutdown); surface it
        // on the reply rather than silently dropping.
        if let Err(mpsc::error::SendError(SchedMsg::Enqueue(req))) =
            self.tx.send(SchedMsg::Enqueue(req))
        {
            if let Some(reply) = req.reply {
                let _ = reply.send(Err(VeilidNetError::Actor("write scheduler is gone".into())));
            }
        }
    }

    /// Graceful-close flush (I7): dispatch pending chat writes + tombstones/
    /// withdraws within `budget`, shed pending class-3/4/5 current-state writes,
    /// then resolve. Returns when the flush completes or the budget expires.
    pub async fn shutdown(&self, budget: Duration) {
        let (done, done_rx) = oneshot::channel();
        if self.tx.send(SchedMsg::Shutdown { budget, done }).is_err() {
            return; // already gone
        }
        let _ = done_rx.await;
    }
}

enum SchedMsg<D> {
    Enqueue(WriteRequest<D>),
    Shutdown {
        budget: Duration,
        done: oneshot::Sender<()>,
    },
}

/// A dispatched write's completion, sent from the spawned dispatch task back to
/// the single-threaded driver so all state mutation stays in one place.
struct Done {
    record: RecordId,
    /// Which lane this write drew (WB-5.1 / I5″.1) — `on_done` decrements the matching
    /// counter (`window_in_flight` / `floor_in_flight`; chat draws neither).
    lane: DispatchLane,
    /// Enqueue-to-ack latency — the WB-1.10 reaper congestion signal, fed to the
    /// median-of-5 DHT-weather estimator (WB-5.1 / I5″.6) published to the reaper.
    latency: Duration,
    /// Permit-acquire-wait — telemetry ONLY (WB-5.1 / I5″.3, WB-ISC-27); no control
    /// decision consumes it. `None` when the sink could not surface it.
    acquire_wait: Option<Duration>,
}

struct Pending<D> {
    seq: u64,
    /// Enqueue instant — stays fresh on every (re)enqueue, so enqueue-to-ack latency
    /// measures the actual wait of the write that dispatched.
    enqueued: Instant,
    /// Starvation clock (WB-5.1 / I5″.5): set to `enqueued` on first enqueue, but
    /// INHERITED from the elder across I3 coalescing (`drop_same_id_current_state`) so a
    /// perpetually-refreshed id still ages to the I8 escalation and the floor lane.
    /// Distinct from `enqueued`, which resets on each coalescing supersession.
    starved_since: Instant,
    class: WriteClass,
    kind: WriteKind,
    deadline: Option<Instant>,
    item: D,
    reply: Option<oneshot::Sender<Result<()>>>,
}

/// The scheduler entry point: spawn the driver task and return a handle. `sink` is
/// the injected write seam; `cfg` tunes pacing + starvation.
pub struct WriteScheduler;

impl WriteScheduler {
    /// Spawn the driver and return a cloneable handle. The driver task lives until
    /// every handle is dropped or [`WriteSchedulerHandle::shutdown`] completes.
    pub fn spawn<S: WriteSink>(
        sink: Arc<S>,
        cfg: SchedulerConfig,
    ) -> WriteSchedulerHandle<S::Item> {
        Self::spawn_with_probe(sink, cfg, Arc::new(AtomicU64::new(0)))
    }

    /// As [`Self::spawn`], but publishes the **DHT-weather regime estimator** (WB-5.1 /
    /// I5″.6) into `latency_probe` on each non-chat completion — the MEDIAN (millis) of
    /// the last `LATENCY_WINDOW` enqueue-to-ack latencies. The presence reaper reads
    /// it (through the `ReapGate` hysteresis band + resume grace) to suspend reaping
    /// while the DHT regime is elevated (WB-1.10 / WB-ISC-5), and the UI honesty state
    /// consumes it for the "presence may be stale" signal. Observable only — no consumer
    /// enqueues writes from it (I9).
    pub fn spawn_with_probe<S: WriteSink>(
        sink: Arc<S>,
        cfg: SchedulerConfig,
        latency_probe: Arc<AtomicU64>,
    ) -> WriteSchedulerHandle<S::Item> {
        let (tx, rx) = mpsc::unbounded_channel::<SchedMsg<S::Item>>();
        let (done_tx, done_rx) = mpsc::unbounded_channel::<Done>();
        tokio::spawn(run(sink, cfg, rx, done_tx, done_rx, latency_probe));
        WriteSchedulerHandle { tx }
    }
}

struct State<D> {
    cfg: SchedulerConfig,
    /// Per-record FIFO queues (I2). A record with no queue entry has nothing pending.
    queues: HashMap<RecordId, VecDeque<Pending<D>>>,
    /// Records with a write currently in flight (per-record single-flight).
    in_flight: HashSet<RecordId>,
    /// Logical id of a TOMBSTONE currently in flight, per record (#164). Single-flight
    /// means at most one in-flight write per record, so this holds that record's
    /// in-flight tombstone id (if any) — a same-id current-state enqueued while the
    /// tombstone is mid-write is dominated exactly like a queued one (WB-ISC-12),
    /// closing the window where a keepalive resurrects a just-departed member.
    in_flight_tombstone: HashMap<RecordId, String>,
    /// Window-lane writes in flight (WB-5.1 / I5″.1): the I5 window subject, capped at
    /// `min(distinct pending non-chat records, W_max)`. Chat and floor draw their own
    /// pools and are counted separately.
    window_in_flight: usize,
    /// Floor-lane writes in flight (WB-5.1 / I5″.5): capacity 1, the ADDITIONAL
    /// guaranteed slot for deadline-due + floor-age-eligible writes. A floor dispatch
    /// neither consumes nor releases a window slot.
    floor_in_flight: usize,
    /// The published **DHT-weather regime estimator** (WB-5.1 / I5″.6): the **median**
    /// (millis) of the last `LATENCY_WINDOW` non-chat enqueue-to-ack latencies,
    /// exposed for the presence reaper (WB-1.10 reap-in-calm, via the `ReapGate`
    /// band+grace) and the UI honesty state. OBSERVABLE only — no consumer may enqueue
    /// writes from it (I9 stands). A median needs 3 of 5 recent completions on the far
    /// side to cross, so it is robust to a single outlier in both directions.
    latency_probe: Arc<AtomicU64>,
    /// The rolling window of the last `LATENCY_WINDOW` non-chat latencies behind
    /// [`Self::latency_probe`] (WB-5.1 / I5″.6 median-of-5, replacing the EMA).
    latency_ring: VecDeque<u64>,
    seq: u64,
}

/// The DHT-weather estimator window (WB-5.1 / I5″.6): the published regime signal is
/// the median of the last 5 non-chat enqueue-to-ack latencies. Replaces the §I5′.3 EMA
/// — a median-of-5 needs 3 of 5 completions on the far side to cross, so it rejects a
/// single fast straggler (the EMA-fast-exit chatter the freeze refuted) and recovers in
/// ~3 fast completions.
const LATENCY_WINDOW: usize = 5;

/// The median of the current latency window (millis). Fewer than a full window uses
/// what is present; an empty window reads 0 (no regime signal yet).
fn median_ms(ring: &VecDeque<u64>) -> u64 {
    // Median over a FULL window of LATENCY_WINDOW samples: a partial (warmup) window is
    // padded with calm (0) samples, so a single slow outlier cannot cross the band
    // before LATENCY_WINDOW real samples accumulate — the 3-of-5 robustness (WB-5.1 /
    // I5″.6) holds from the first sample, not only once the ring fills. Reaping runs
    // calm through warmup, which is safe: no member is TTL-stale (600s) that early.
    let mut v: Vec<u64> = ring.iter().copied().collect();
    v.resize(LATENCY_WINDOW.max(v.len()), 0);
    v.sort_unstable();
    v[v.len() / 2]
}

impl<D: Send + 'static> State<D> {
    fn new(cfg: SchedulerConfig, latency_probe: Arc<AtomicU64>) -> Self {
        Self {
            cfg,
            queues: HashMap::new(),
            in_flight: HashSet::new(),
            in_flight_tombstone: HashMap::new(),
            window_in_flight: 0,
            floor_in_flight: 0,
            latency_probe,
            latency_ring: VecDeque::with_capacity(LATENCY_WINDOW),
            seq: 0,
        }
    }

    /// Apply the I3 coalescing + dominance rules and enqueue (or drop) the request.
    fn enqueue(&mut self, req: WriteRequest<D>) {
        let now = Instant::now();
        // Starvation clock (WB-5.1 / I5″.5): fresh for a genuinely new write, inherited
        // from the coalesced elder for a refreshed current-state (set below).
        let mut starved_since = now;
        // Mutable because a coalescing supersession may PROMOTE it (see below).
        let mut class = req.class;
        // An in-flight tombstone dominates a same-id current-state exactly like a
        // queued one (#164 / WB-ISC-12); capture it before borrowing the record queue.
        let in_flight_tomb = self.in_flight_tombstone.get(&req.record).cloned();
        let q = self.queues.entry(req.record).or_default();
        match &req.kind {
            // Chat ring writes are never coalesced or dropped (I3/WB-ISC-11).
            WriteKind::Ring => {}
            WriteKind::CurrentState { logical_id } => {
                // Tombstone dominance (WB-ISC-12): a same-id withdraw already queued —
                // OR one in flight (#164) — suppresses this current-state write
                // entirely; it must not resurrect a withdrawn share / departed member
                // (#121/#118). Report Ok (intent deliberately superseded), do not enqueue.
                let dominated_by_queued = q.iter().any(|p| {
                    p.kind.is_tombstone() && p.kind.logical_id() == Some(logical_id.as_str())
                });
                let dominated_by_in_flight = in_flight_tomb.as_deref() == Some(logical_id.as_str());
                if dominated_by_queued || dominated_by_in_flight {
                    resolve_ok(req.reply);
                    return;
                }
                // Last-writer-wins coalescing: drop the older same-id current-state,
                // INHERITING its starvation clock (WB-5.1 / I5″.5) so a keepalive/advert
                // re-enqueued every cadence still ages to the I8 escalation + floor lane
                // instead of resetting below the bound forever.
                if let Some(elder) = drop_same_id_current_state(q, logical_id) {
                    starved_since = elder.starved_since;
                    // The survivor carries the strongest class of the set it subsumed —
                    // see `strongest_class`. Without this, a coalesced `Chat` write is
                    // shed at shutdown after its caller was already told `Ok(())`.
                    class = strongest_class(class, elder.strongest);
                }
            }
            WriteKind::Tombstone { logical_id } => {
                // A tombstone supersedes any queued same-id current-state (they must
                // not land after the withdraw), and coalesces with a prior tombstone.
                let lid = logical_id.clone();
                let mut i = 0;
                while i < q.len() {
                    let same_id = q[i].kind.logical_id() == Some(lid.as_str());
                    let is_cs = matches!(q[i].kind, WriteKind::CurrentState { .. });
                    let is_tomb = q[i].kind.is_tombstone();
                    if same_id && (is_cs || is_tomb) {
                        let dropped = q.remove(i).expect("index in range");
                        resolve_ok(dropped.reply);
                    } else {
                        i += 1;
                    }
                }
            }
        }
        let pending = Pending {
            seq: self.seq,
            enqueued: now,
            starved_since,
            class,
            kind: req.kind,
            deadline: req.deadline,
            item: req.item,
            reply: req.reply,
        };
        self.seq += 1;
        q.push_back(pending);
    }

    /// Dispatch as many eligible writes as the invariants allow across the three write
    /// lanes (WB-5.1 / I5″). Each lane draws its own DHT-gate pool; per-record
    /// single-flight (I2) is shared — a record dispatched on ANY lane leaves `in_flight`,
    /// so the other lanes will not re-pick it (selection + marking is atomic because the
    /// scheduler driver is single-threaded — `dispatch` inserts `in_flight`
    /// synchronously before spawning). Lane order per pass: floor, chat, window.
    fn try_dispatch<S: WriteSink<Item = D>>(
        &mut self,
        sink: &Arc<S>,
        done_tx: &mpsc::UnboundedSender<Done>,
    ) {
        let now = Instant::now();
        loop {
            // Floor lane (WB-5.1 / I5″.5), capacity 1 — the ADDITIONAL guaranteed slot:
            // a deadline-due write (I6b) or a non-chat write whose starved-age exceeds
            // FLOOR_AGE, from an idle record. Deadline-first, then (class rank,
            // starved-age). This is a priority dispatch path WITHIN the one funnel (I1),
            // not a second funnel.
            if self.floor_in_flight < 1 {
                if let Some(rec) = self.pick_floor(now) {
                    self.dispatch(rec, DispatchLane::Floor, sink, done_tx);
                    continue;
                }
            }
            // Chat lane (I4): an idle record whose head is chat dispatches on the chat
            // pool at any depth, never counted against the window (WB-ISC-10). Two
            // concurrent cross-record chats proceed; a third waits only on chat.
            if let Some(rec) = self.pick_chat_ready() {
                self.dispatch(rec, DispatchLane::Chat, sink, done_tx);
                continue;
            }
            // Window lane (I5): non-chat under the STATIC record-scaled window
            // min(distinct pending non-chat records, W_max) — never varies with any
            // latency signal (WB-ISC-16; the §I5′.2 acquire-wait controller is retired).
            // Floor-eligible heads remain window candidates too (dual eligibility), so
            // saturated aggregate write concurrency is W_max + 1, never 1.
            let window = self.distinct_pending_nonchat().min(self.cfg.nonchat_cap);
            if self.window_in_flight < window {
                if let Some(rec) = self.pick_best_nonchat(now) {
                    self.dispatch(rec, DispatchLane::Window, sink, done_tx);
                    continue;
                }
            }
            break;
        }
    }

    /// Distinct records that could occupy a WINDOW slot (WB-5.1 / I5″.1): idle records
    /// whose head is a non-chat write, plus the records already holding a window-lane
    /// write. `min(this, W_max)` is the window — no point widening past the number of
    /// records that can use it, and per-record single-flight (I2) caps each at one
    /// in-flight write. Floor-lane in-flight records are busy (via the floor pool), not
    /// competing for window slots, so they are NOT counted here.
    fn distinct_pending_nonchat(&self) -> usize {
        let idle_nonchat = self
            .queues
            .iter()
            .filter(|(rec, q)| {
                self.idle(rec) && q.front().is_some_and(|p| p.class != WriteClass::Chat)
            })
            .count();
        idle_nonchat + self.window_in_flight
    }

    /// A record is dispatchable only when it has no write in flight (per-record
    /// single-flight → I2 FIFO + serialized slot/seq assignment inside the sink's
    /// `record_lock`, I13).
    fn idle(&self, rec: &RecordId) -> bool {
        !self.in_flight.contains(rec)
    }

    /// FLOOR_AGE for a class (WB-5.1 / I5″.5) = 2 × its I8 age bound. A non-chat write
    /// whose starved-age exceeds this is floor-lane eligible.
    fn floor_age(&self, class: WriteClass) -> Duration {
        self.cfg.age_bounds[(class.rank() - 1) as usize] * 2
    }

    /// The floor picker (WB-5.1 / I5″.5): among IDLE records' non-chat heads (I2 — the
    /// picker skips records with a write in flight, so a busy-record elder can never
    /// head-of-line-block the floor permit), select deadline-due writes first (by
    /// deadline, then seq — I6b re-homed onto the floor lane), else floor-age-eligible
    /// writes by (class rank, oldest `starved_since`, seq): class before age, so a
    /// confidentiality-relevant class-2 withdraw is never queued behind an older cosmetic
    /// class-5 republish on the capacity-1 lane.
    fn pick_floor(&self, now: Instant) -> Option<RecordId> {
        let deadline_due = self
            .queues
            .iter()
            .filter(|(rec, q)| self.idle(rec) && !q.is_empty())
            .filter_map(|(rec, q)| {
                let head = q.front().unwrap();
                if head.class == WriteClass::Chat {
                    return None;
                }
                head.deadline
                    .filter(|d| *d <= now)
                    .map(|d| (*rec, d, head.seq))
            })
            .min_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)))
            .map(|(rec, _, _)| rec);
        if deadline_due.is_some() {
            return deadline_due;
        }
        self.queues
            .iter()
            .filter(|(rec, q)| self.idle(rec) && !q.is_empty())
            .filter_map(|(rec, q)| {
                let head = q.front().unwrap();
                if head.class == WriteClass::Chat {
                    return None;
                }
                (now.saturating_duration_since(head.starved_since) >= self.floor_age(head.class))
                    .then_some((*rec, head.class.rank(), head.starved_since, head.seq))
            })
            .min_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)).then(a.3.cmp(&b.3)))
            .map(|(rec, _, _, _)| rec)
    }

    fn pick_chat_ready(&self) -> Option<RecordId> {
        self.queues
            .iter()
            .filter(|(rec, q)| self.idle(rec) && !q.is_empty())
            .filter(|(_, q)| q.front().unwrap().class == WriteClass::Chat)
            .min_by_key(|(_, q)| q.front().unwrap().seq)
            .map(|(rec, _)| *rec)
    }

    fn pick_best_nonchat(&self, now: Instant) -> Option<RecordId> {
        self.queues
            .iter()
            .filter(|(rec, q)| self.idle(rec) && !q.is_empty())
            .filter(|(_, q)| q.front().unwrap().class != WriteClass::Chat)
            .map(|(rec, q)| {
                let head = q.front().unwrap();
                (*rec, self.effective_rank(head, now), head.seq)
            })
            .min_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)))
            .map(|(rec, _, _)| rec)
    }

    /// I8: a write whose starved-age exceeds its class's age bound escalates one class
    /// (a smaller rank sorts ahead). Measured against `starved_since` (survives
    /// coalescing — WB-5.1 / I5″.5), NOT `enqueued`, so a cadence-refreshed keepalive
    /// still escalates. Escalation only reorders the window pool; it never grants the
    /// chat lane (keyed on the original class).
    fn effective_rank(&self, p: &Pending<D>, now: Instant) -> u8 {
        let rank = p.class.rank();
        let bound = self.cfg.age_bounds[(rank - 1) as usize];
        if now.saturating_duration_since(p.starved_since) >= bound {
            rank.saturating_sub(1).max(1)
        } else {
            rank
        }
    }

    fn dispatch<S: WriteSink<Item = D>>(
        &mut self,
        rec: RecordId,
        lane: DispatchLane,
        sink: &Arc<S>,
        done_tx: &mpsc::UnboundedSender<Done>,
    ) {
        let Some(q) = self.queues.get_mut(&rec) else {
            return;
        };
        let Some(p) = q.pop_front() else { return };
        if q.is_empty() {
            self.queues.remove(&rec);
        }
        self.in_flight.insert(rec);
        // Track an in-flight tombstone so a same-id current-state enqueued before it
        // acks is dominated (#164). Cleared in `on_done`.
        if let WriteKind::Tombstone { logical_id } = &p.kind {
            self.in_flight_tombstone.insert(rec, logical_id.clone());
        }
        // Split lane counters (WB-5.1 / I5″.5): `on_done` decrements the matching one via
        // the `Done.lane` tag. A floor dispatch neither consumes nor releases a window
        // slot. Chat draws neither.
        match lane {
            DispatchLane::Window => self.window_in_flight += 1,
            DispatchLane::Floor => self.floor_in_flight += 1,
            DispatchLane::Chat => {}
        }
        let sink = sink.clone();
        let done_tx = done_tx.clone();
        let Pending {
            enqueued,
            item,
            reply,
            ..
        } = p;
        tokio::spawn(async move {
            // #168 panic supervision (WB-5.1 / I5″.8, WB-ISC-26). The sink's write future
            // is BUILT AND run in an INNER task — the `sink.dispatch(...)` construction is
            // moved INSIDE the spawn, so a SYNCHRONOUS panic during future construction is
            // caught by the join exactly like a panic in the async body. Either path
            // returns here and still sends a `Done`, so `on_done` releases the in-flight
            // slot AND the lane counter (`window_in_flight` / `floor_in_flight` → 0), and
            // the sink's RAII DHT-gate permit unwinds. Without this a panicked write never
            // sent `Done` → a leaked lane counter silently wedges the capacity-1 floor
            // lane (build-1's silent-starvation class).
            let outcome = match tokio::spawn(async move { sink.dispatch(item, lane).await }).await {
                Ok(o) => o,
                Err(_join_err) => DispatchOutcome::bare(Err(VeilidNetError::Actor(
                    "write dispatch task panicked".into(),
                ))),
            };
            // Enqueue-to-ack (queue wait + lock wait + set RTT) — the WB-1.10 reaper
            // congestion signal fed to the median estimator, NOT set-RTT alone.
            let latency = enqueued.elapsed();
            if let Some(reply) = reply {
                let _ = reply.send(outcome.result);
            }
            let _ = done_tx.send(Done {
                record: rec,
                lane,
                latency,
                acquire_wait: outcome.acquire_wait,
            });
        });
    }

    fn on_done(&mut self, d: Done) {
        self.in_flight.remove(&d.record);
        self.in_flight_tombstone.remove(&d.record);
        // Release the lane counter the write drew (WB-5.1 / I5″.5). A leaked counter
        // here silently wedges the capacity-1 floor lane — the `Done.lane` tag makes
        // decrement unambiguous even on the panic path (WB-ISC-26).
        match d.lane {
            DispatchLane::Window => self.window_in_flight = self.window_in_flight.saturating_sub(1),
            DispatchLane::Floor => self.floor_in_flight = self.floor_in_flight.saturating_sub(1),
            DispatchLane::Chat => {}
        }
        // Feed the median-of-5 DHT-weather estimator on non-chat completions (WB-5.1 /
        // I5″.6): push the enqueue-to-ack latency into the rolling window and publish the
        // MEDIAN (millis) for the presence reaper (via the `ReapGate` band+grace) and the
        // UI honesty state. Observable only — no write is enqueued from it (I9). The
        // `acquire_wait` field is telemetry only now (WB-ISC-27); no guard consumes it.
        if d.lane != DispatchLane::Chat {
            // acquire_wait is TRACE telemetry only (WB-ISC-27): recorded, never fed to a
            // control decision — the §I5′.2 window controller that consumed it is retired.
            if let Some(aw) = d.acquire_wait {
                crate::vtrace!("dispatch acquire_wait={aw:?} (telemetry only, WB-ISC-27)");
            }
            let sample = d.latency.as_millis().min(u128::from(u64::MAX)) as u64;
            self.latency_ring.push_back(sample);
            while self.latency_ring.len() > LATENCY_WINDOW {
                self.latency_ring.pop_front();
            }
            self.latency_probe
                .store(median_ms(&self.latency_ring), Ordering::Relaxed);
        }
    }

    /// The next time-based transition to wake for: the earliest deadline (I6b) or
    /// starvation-escalation crossing (I8) among idle records' heads. `None` = no
    /// time-driven work pending (park until an enqueue/done).
    fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        self.queues
            .iter()
            .filter(|(rec, q)| self.idle(rec) && !q.is_empty())
            .flat_map(|(_, q)| {
                let head = q.front().unwrap();
                // A deadline (I6b) wakes when due: `pick_floor` dispatches it on the
                // floor lane, which clears the queue — no spin. The I8 escalation
                // crossing and the FLOOR_AGE crossing are both measured from
                // `starved_since` (WB-5.1 / I5″.5). The FLOOR_AGE crossing IS actionable
                // — it makes the write floor-lane-eligible (an ADDITIONAL slot) — so we
                // must wake to dispatch it via the floor if that lane is free. Both
                // crossings are included ONLY while still future: once passed, the head
                // sorts at its escalated rank / is floor-eligible and dispatches on the
                // next `on_done`; re-arming for a past crossing was the 100% CPU
                // busy-spin (#162).
                // Include a deadline only while it is still FUTURE. A past-due deadline
                // that cannot dispatch (floor lane busy AND window full) would otherwise
                // clamp to `now` and hot-spin the driver (the #162 class the esc/floor
                // crossings below guard identically); once past, `pick_floor` dispatches
                // it deadline-first on the next lane-freeing `on_done`.
                let deadline = head.deadline.filter(|d| *d > now);
                let (esc, floor) = if head.class == WriteClass::Chat {
                    (None, None)
                } else {
                    let bound = self.cfg.age_bounds[(head.class.rank() - 1) as usize];
                    let esc = head.starved_since + bound;
                    let floor = head.starved_since + bound * 2;
                    ((esc > now).then_some(esc), (floor > now).then_some(floor))
                };
                [deadline, esc, floor].into_iter().flatten()
            })
            .min()
    }

    /// I7: flush pending chat writes + tombstones/withdraws, shed the rest. Returns
    /// the shed replies' senders are dropped (caller sees the close). Only chat +
    /// tombstone heads are dispatched here; class-3/4/5 current-state writes are
    /// removed (abandoned to the TTL backstop).
    fn drain_for_shutdown<S: WriteSink<Item = D>>(
        &mut self,
        sink: &Arc<S>,
        done_tx: &mpsc::UnboundedSender<Done>,
    ) -> bool {
        // Shed every queued class-3/4/5 current-state write (not chat, not tombstone).
        for q in self.queues.values_mut() {
            q.retain(|p| p.class == WriteClass::Chat || p.kind.is_tombstone());
        }
        self.queues.retain(|_, q| !q.is_empty());
        // Dispatch every idle chat/tombstone head, bypassing the I5 cap (we are
        // closing — flush order bounds the damage, the budget bounds the close).
        let mut dispatched = false;
        loop {
            let pick = self
                .queues
                .iter()
                .filter(|(rec, q)| self.idle(rec) && !q.is_empty())
                .min_by_key(|(_, q)| q.front().unwrap().seq)
                .map(|(rec, q)| (*rec, q.front().unwrap().class));
            match pick {
                Some((rec, class)) => {
                    // Flush order bounds the damage (I7); the shutdown budget bounds the
                    // close. Chat draws the chat pool, tombstones the window pool — the
                    // lane tag keeps `on_done`'s counter release correct.
                    let lane = if class == WriteClass::Chat {
                        DispatchLane::Chat
                    } else {
                        DispatchLane::Window
                    };
                    self.dispatch(rec, lane, sink, done_tx);
                    dispatched = true;
                }
                None => break,
            }
        }
        dispatched
    }

    /// Whether any flushable (chat/tombstone) work remains queued or in flight.
    fn shutdown_work_remaining(&self) -> bool {
        !self.in_flight.is_empty()
            || self.queues.values().any(|q| {
                q.iter()
                    .any(|p| p.class == WriteClass::Chat || p.kind.is_tombstone())
            })
    }
}

fn resolve_ok(reply: Option<oneshot::Sender<Result<()>>>) {
    if let Some(reply) = reply {
        let _ = reply.send(Ok(()));
    }
}

/// Drop the queued same-id current-state write(s) (last-writer-wins), resolving each
/// reply `Ok` — the newer write subsumes them. Returns the OLDEST dropped
/// `starved_since` (if any), so the winning write can inherit the elder's starvation
/// clock (WB-5.1 / I5″.5).
fn drop_same_id_current_state<D>(
    q: &mut VecDeque<Pending<D>>,
    logical_id: &str,
) -> Option<Coalesced> {
    let mut out: Option<Coalesced> = None;
    let mut i = 0;
    while i < q.len() {
        let matches =
            matches!(&q[i].kind, WriteKind::CurrentState { logical_id: id } if id == logical_id);
        if matches {
            let dropped = q.remove(i).expect("index in range");
            out = Some(match out {
                None => Coalesced {
                    starved_since: dropped.starved_since,
                    strongest: dropped.class,
                },
                Some(acc) => Coalesced {
                    starved_since: acc.starved_since.min(dropped.starved_since),
                    strongest: strongest_class(acc.strongest, dropped.class),
                },
            });
            resolve_ok(dropped.reply);
        } else {
            i += 1;
        }
    }
    out
}

/// What a coalescing supersession inherits from the writes it dropped.
struct Coalesced {
    /// The OLDEST dropped `starved_since`, so a cadence-refreshed write still ages to
    /// the I8 escalation instead of resetting below the bound for ever.
    starved_since: Instant,
    /// The STRONGEST class among the dropped writes.
    strongest: WriteClass,
}

/// The higher-priority (lower-rank) of two classes.
///
/// **Why a survivor inherits this, and why it is a correctness fix rather than a
/// priority tweak.** `drop_same_id_current_state` resolves each dropped write's reply
/// `Ok(())` — the caller is told its intent was carried, deliberately superseded by a
/// newer write to the same slot. That promise is only true if the survivor actually
/// reaches the wire. It does not, if the survivor is weaker: `drain_for_shutdown`
/// sheds every queued non-chat, non-tombstone write, so a `Chat` write coalesced by a
/// `Keepalive` one leaves NOTHING on the wire while its caller already holds an `Ok`.
/// Un-coalesced, that same write would have flushed. Taking the strongest class closes
/// it, and changes nothing about content: last-writer-wins is untouched — same record,
/// same logical id, the newest payload survives — only the lane it flushes in moves.
fn strongest_class(a: WriteClass, b: WriteClass) -> WriteClass {
    if a.rank() <= b.rank() {
        a
    } else {
        b
    }
}

async fn run<S: WriteSink>(
    sink: Arc<S>,
    cfg: SchedulerConfig,
    mut rx: mpsc::UnboundedReceiver<SchedMsg<S::Item>>,
    done_tx: mpsc::UnboundedSender<Done>,
    mut done_rx: mpsc::UnboundedReceiver<Done>,
    latency_probe: Arc<AtomicU64>,
) {
    let mut st = State::<S::Item>::new(cfg, latency_probe);
    loop {
        let wakeup = st.next_wakeup(Instant::now());
        let timer = async {
            match wakeup {
                Some(t) => tokio::time::sleep_until(t).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(timer);
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(SchedMsg::Enqueue(req)) => {
                    st.enqueue(req);
                    st.try_dispatch(&sink, &done_tx);
                }
                Some(SchedMsg::Shutdown { budget, done }) => {
                    shutdown_flush(&mut st, &sink, &done_tx, &mut done_rx, budget).await;
                    let _ = done.send(());
                    return;
                }
                None => return, // all handles dropped
            },
            d = done_rx.recv() => {
                if let Some(d) = d {
                    st.on_done(d);
                    st.try_dispatch(&sink, &done_tx);
                }
            }
            _ = &mut timer => {
                st.try_dispatch(&sink, &done_tx);
            }
        }
    }
}

/// I7: shed class-3/4/5, flush chat + tombstones within `budget`, drain in-flight
/// up to the deadline, then return (remaining abandoned to the TTL backstop).
async fn shutdown_flush<S: WriteSink>(
    st: &mut State<S::Item>,
    sink: &Arc<S>,
    done_tx: &mpsc::UnboundedSender<Done>,
    done_rx: &mut mpsc::UnboundedReceiver<Done>,
    budget: Duration,
) {
    let deadline = Instant::now() + budget;
    st.drain_for_shutdown(sink, done_tx);
    while st.shutdown_work_remaining() {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return,
            d = done_rx.recv() => {
                if let Some(d) = d {
                    st.on_done(d);
                    // A freed record may unblock a queued chat/tombstone behind it.
                    st.drain_for_shutdown(sink, done_tx);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    /// One recorded dispatch: the item label, the virtual instant it fired, and the
    /// [`DispatchLane`] the scheduler drew for it.
    ///
    /// **The lane is here because it is the only observable that carries the
    /// dispatched write's CLASS.** `MockItem` holds a label chosen at `req()` time, so
    /// it reports what a caller asked for and not what the scheduler decided; the lane
    /// is computed from `q.front().class` at the moment of dispatch, so it is the live
    /// value. Without it a test can assert WHICH request survived a coalescing
    /// supersession but never at what priority — and a survivor that inherited the
    /// coalesced elder's class (the shape of the `starved_since` inheritance sitting
    /// three lines away in `enqueue`) would land in the wrong lane with every existing
    /// assertion still green. `Chat` maps to `DispatchLane::Chat`; every other class
    /// maps to `Window` or `Floor`, which is exactly the distinction the DM doorbell's
    /// two dispatch classes turn on.
    #[derive(Clone)]
    struct Rec {
        label: String,
        at: Instant,
        lane: DispatchLane,
    }

    /// A counting mock sink (the WB-2 oracle seam): records every dispatched write
    /// (label + timestamp) and simulates a DHT round-trip by sleeping `latency` in
    /// paused virtual time. `acquire_wait_ms` injects the synthetic permit-acquire-wait
    /// the WB-5 guard consumes (`u64::MAX` = `None`, the I5′.2 transport-can't-surface
    /// fallback); it is settable mid-run so an oracle can switch regimes.
    struct MockSink {
        log: Arc<Mutex<Vec<Rec>>>,
        latency: Duration,
        dispatched: AtomicU64,
        acquire_wait_ms: Arc<AtomicU64>,
    }

    struct MockItem {
        label: String,
    }

    const AW_NONE: u64 = u64::MAX;

    impl MockSink {
        fn new(latency: Duration) -> Arc<Self> {
            Self::with_acquire_wait(latency, AW_NONE)
        }
        fn with_acquire_wait(latency: Duration, acquire_wait_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                log: Arc::new(Mutex::new(Vec::new())),
                latency,
                dispatched: AtomicU64::new(0),
                acquire_wait_ms: Arc::new(AtomicU64::new(acquire_wait_ms)),
            })
        }
        fn log(&self) -> Vec<Rec> {
            self.log.lock().unwrap().clone()
        }
    }

    impl WriteSink for MockSink {
        type Item = MockItem;
        fn dispatch(&self, item: MockItem, lane: DispatchLane) -> DispatchFuture {
            let log = self.log.clone();
            let latency = self.latency;
            let aw = self.acquire_wait_ms.load(Ordering::SeqCst);
            self.dispatched.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                log.lock().unwrap().push(Rec {
                    label: item.label,
                    at: Instant::now(),
                    lane,
                });
                tokio::time::sleep(latency).await;
                let acquire_wait = (aw != AW_NONE).then(|| Duration::from_millis(aw));
                DispatchOutcome {
                    result: Ok(()),
                    acquire_wait,
                }
            })
        }
    }

    fn req(
        record: RecordId,
        class: WriteClass,
        kind: WriteKind,
        label: &str,
    ) -> (WriteRequest<MockItem>, oneshot::Receiver<Result<()>>) {
        let (tx, rx) = oneshot::channel();
        (
            WriteRequest {
                record,
                class,
                kind,
                deadline: None,
                item: MockItem {
                    label: label.to_owned(),
                },
                reply: Some(tx),
            },
            rx,
        )
    }

    fn rec_id(n: u8) -> RecordId {
        [n; 32]
    }

    /// A request carrying a hard `deadline` (I6b) — dispatches via the floor lane once
    /// the deadline is due (WB-5.1 / I5″.5). For floor-lane oracles.
    fn req_deadline(
        record: RecordId,
        class: WriteClass,
        kind: WriteKind,
        label: &str,
        deadline: Instant,
    ) -> (WriteRequest<MockItem>, oneshot::Receiver<Result<()>>) {
        let (rq, rx) = req(record, class, kind, label);
        (
            WriteRequest {
                deadline: Some(deadline),
                ..rq
            },
            rx,
        )
    }

    // ── WB-ISC-9 ────────────────────────────────────────────────────────────
    /// Steady-state non-chat DHT writes ≤ 4/min per client under the WB-2 load
    /// model, AND the connect window ≤ 8 one-shot writes in the first 120s.
    #[tokio::test(start_paused = true)]
    async fn wb_isc_9_steady_state_write_budget_ceiling() {
        let sink = MockSink::new(Duration::from_secs(2));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
        let start = Instant::now();

        // Connect window: 4 room join beacons + 2 share-advert republishes = 6
        // one-shot writes (≤ rooms + persisted shares, WB-2 connect basis).
        for r in 0..4u8 {
            let (rq, _rx) = req(
                rec_id(r),
                WriteClass::SessionBoundary,
                WriteKind::CurrentState {
                    logical_id: format!("member-{r}"),
                },
                &format!("join-{r}"),
            );
            h.enqueue(rq);
        }
        for s in 0..2u8 {
            let (rq, _rx) = req(
                rec_id(100 + s),
                WriteClass::Republish,
                WriteKind::CurrentState {
                    logical_id: format!("share-{s}"),
                },
                &format!("republish-{s}"),
            );
            h.enqueue(rq);
        }

        // Steady-state cadence generators (WB-1 load model): 4 presence keepalives
        // in the [180,220]s band, 2 share-advert watchdog refreshes ~150s, 1 MOTD
        // keepalive ~120s. All non-chat. DISTINCT per-generator periods model WB-1's
        // fresh-per-emission jitter — real presence emissions do NOT phase-lock, so a
        // single 60s window never sees all four keepalives coincide. (This is input
        // jitter per record, not the cross-record phase-staggering WB-3.I6 forbids.)
        for r in 0..4u8 {
            let h = h.clone();
            // 187 / 199 / 211 / 223s — spread across the band so phases drift apart.
            let period = 187 + u64::from(r) * 12;
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(period));
                tick.tick().await; // immediate tick
                loop {
                    tick.tick().await;
                    let (rq, _rx) = req(
                        rec_id(r),
                        WriteClass::Keepalive,
                        WriteKind::CurrentState {
                            logical_id: format!("member-{r}"),
                        },
                        &format!("keepalive-{r}"),
                    );
                    h.enqueue(rq);
                }
            });
        }
        for s in 0..2u8 {
            let h = h.clone();
            let period = 149 + u64::from(s) * 13; // 149 / 162s
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(period));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let (rq, _rx) = req(
                        rec_id(100 + s),
                        WriteClass::AdvertRefresh,
                        WriteKind::CurrentState {
                            logical_id: format!("share-{s}"),
                        },
                        &format!("advert-{s}"),
                    );
                    h.enqueue(rq);
                }
            });
        }
        {
            let h = h.clone();
            tokio::spawn(async move {
                // #238 note: production no longer emits the operator announce keepalive at
                // 120 s — it is operator-only, one slot per emission, on a jittered 45-75
                // min band. This model is therefore CONSERVATIVE (it over-models real
                // load), which keeps WB-ISC-9's bound sound, so it is left as-is rather
                // than re-cut against a frozen criterion.
                let mut tick = tokio::time::interval(Duration::from_secs(120));
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let (rq, _rx) = req(
                        rec_id(200),
                        WriteClass::Keepalive,
                        WriteKind::CurrentState {
                            logical_id: "motd".into(),
                        },
                        "motd",
                    );
                    h.enqueue(rq);
                }
            });
        }

        // Drive ≥ 30 simulated minutes.
        tokio::time::sleep(Duration::from_secs(1800)).await;

        let log = sink.log();
        // Connect window: dispatches in the first 120s.
        let connect_writes = log
            .iter()
            .filter(|r| r.at.duration_since(start) < Duration::from_secs(120))
            .count();
        assert!(
            connect_writes <= 8,
            "connect window {connect_writes} must be ≤ 8 one-shot writes"
        );

        // Steady-state ceiling (WB-2): the average non-chat dispatch RATE over the
        // steady window [120s, 1800s] must be ≤ 4/min — the literal "≤ 4 non-chat DHT
        // writes/min" claim (WB-2 arithmetic targets ~2.0–2.5/min). A per-minute rate,
        // not an instantaneous cap: brief jitter coincidences are physical and do not
        // violate a steady RATE.
        let steady: Vec<&Rec> = log
            .iter()
            .filter(|r| r.at.duration_since(start) >= Duration::from_secs(120))
            .collect();
        let steady_minutes = (1800.0 - 120.0) / 60.0;
        let rate = steady.len() as f64 / steady_minutes;
        assert!(
            rate <= 4.0,
            "steady-state {rate:.2} non-chat writes/min must be ≤ 4 (n={} over {steady_minutes:.0} min)",
            steady.len()
        );
        // Burst sanity: with jittered cadence the funnel keeps any 60s window well
        // bounded (never the unbounded backlog #159 measured). A window may briefly hit
        // a jitter coincidence, but not the connect burst allowance.
        let mut worst = 0usize;
        let mut w = 120u64;
        while w < 1800 {
            let lo = start + Duration::from_secs(w);
            let hi = start + Duration::from_secs(w + 60);
            let n = log.iter().filter(|r| r.at >= lo && r.at < hi).count();
            worst = worst.max(n);
            w += 60;
        }
        assert!(
            worst <= 8,
            "steady-state worst 60s window {worst} must stay bounded (≤ 8)"
        );
    }

    // ── WB-ISC-10 ───────────────────────────────────────────────────────────
    /// A chat write to an idle record dispatches ≤ 2s after enqueue at any queue
    /// depth, with a saturated class-4 backlog present.
    #[tokio::test(start_paused = true)]
    async fn wb_isc_10_chat_latency_bound_under_saturation() {
        // Slow sink so non-chat writes stay in flight and the backlog is deep.
        let sink = MockSink::new(Duration::from_secs(30));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());

        // Saturate: many class-4 keepalives across many distinct records.
        for r in 0..50u8 {
            let (rq, _rx) = req(
                rec_id(r),
                WriteClass::Keepalive,
                WriteKind::CurrentState {
                    logical_id: format!("m-{r}"),
                },
                &format!("keepalive-{r}"),
            );
            h.enqueue(rq);
        }
        // Let the scheduler settle into its capped in-flight state.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let enqueued = Instant::now();
        let (rq, _rx) = req(
            rec_id(200), // an idle record
            WriteClass::Chat,
            WriteKind::Ring,
            "chat-1",
        );
        h.enqueue(rq);

        // Poll until the chat dispatch appears, bounded well under 2s.
        let mut dispatched_at = None;
        for _ in 0..40 {
            if let Some(r) = sink.log().into_iter().find(|r| r.label == "chat-1") {
                dispatched_at = Some(r.at);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let at = dispatched_at.expect("chat write must dispatch");
        let delay = at.duration_since(enqueued);
        assert!(
            delay <= Duration::from_secs(2),
            "chat dispatch delay {delay:?} must be ≤ 2s under a saturated class-4 backlog"
        );
    }

    // ── WB-ISC-11 (Anti) ──────────────────────────────────────────────────────
    /// No chat ring write is ever coalesced or dropped, and pending chat flushes at
    /// graceful close: every enqueued chat write reaches the sink exactly once, in
    /// per-record order, including across a close.
    #[tokio::test(start_paused = true)]
    async fn wb_isc_11_chat_never_dropped_and_flushes_at_close() {
        let sink = MockSink::new(Duration::from_millis(50));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());

        // Two records, 6 chat writes each, interleaved.
        for i in 0..6 {
            for r in 0..2u8 {
                let (rq, _rx) = req(
                    rec_id(r),
                    WriteClass::Chat,
                    WriteKind::Ring,
                    &format!("c{r}-{i}"),
                );
                h.enqueue(rq);
            }
        }
        // Graceful close with a generous budget: chat must flush.
        h.shutdown(Duration::from_secs(30)).await;

        let log = sink.log();
        // Exactly once each.
        for r in 0..2u8 {
            for i in 0..6 {
                let label = format!("c{r}-{i}");
                let n = log.iter().filter(|x| x.label == label).count();
                assert_eq!(
                    n, 1,
                    "chat {label} must reach the sink exactly once (got {n})"
                );
            }
            // Per-record FIFO order preserved.
            let seq: Vec<usize> = log
                .iter()
                .filter_map(|x| x.label.strip_prefix(&format!("c{r}-")))
                .map(|s| s.parse().unwrap())
                .collect();
            let mut sorted = seq.clone();
            sorted.sort_unstable();
            assert_eq!(
                seq, sorted,
                "record {r} chat dispatched out of enqueue order"
            );
        }
    }

    // ── #161 close flush ──────────────────────────────────────────────────────
    /// The close flush carries a queued LEAVE tombstone to the sink and sheds a queued
    /// class-4 keepalive: a graceful departure lands, a keepalive that would have
    /// resurrected the member does not.
    ///
    /// All three writes sit on ONE record so the tombstone and the keepalive are
    /// genuinely still QUEUED when the shutdown arrives (a record dispatches one write
    /// at a time), and they carry DISTINCT logical ids so the shed is the I7 predicate's
    /// doing and not enqueue-time tombstone dominance (WB-ISC-12 below).
    #[tokio::test(start_paused = true)]
    async fn issue_161_close_flush_carries_tombstone_and_sheds_keepalive() {
        let sink = MockSink::new(Duration::from_millis(50));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());

        // Occupies the record, so everything after it queues.
        let (blocker, _b_rx) = req(
            rec_id(0),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "blocker".to_owned(),
            },
            "blocker",
        );
        h.enqueue(blocker);
        tokio::time::sleep(Duration::from_millis(10)).await; // let it dispatch

        let (leave, _l_rx) = req(
            rec_id(0),
            WriteClass::SessionBoundary,
            WriteKind::Tombstone {
                logical_id: "departing-member".to_owned(),
            },
            "leave",
        );
        h.enqueue(leave);
        let (keepalive, _k_rx) = req(
            rec_id(0),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "other-member".to_owned(),
            },
            "keepalive",
        );
        h.enqueue(keepalive);

        h.shutdown(Duration::from_secs(30)).await;

        let labels: Vec<String> = sink.log().into_iter().map(|r| r.label).collect();
        assert!(
            labels.iter().any(|l| l == "leave"),
            "the queued leave tombstone must flush at close, got {labels:?}"
        );
        assert!(
            !labels.iter().any(|l| l == "keepalive"),
            "a queued class-4 keepalive must be shed at close, got {labels:?}"
        );
    }

    /// The close flush is BOUNDED by its budget: a sink that cannot finish inside the
    /// budget does not hold the close open. Both frontends await this on their shutdown
    /// path, so an unbounded flush is a hung quit — worse than the linger it fixes.
    #[tokio::test(start_paused = true)]
    async fn issue_161_close_flush_returns_within_its_budget() {
        // One write, far slower than the budget it will be flushed under.
        let sink = MockSink::new(Duration::from_secs(60));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
        let (chat, _rx) = req(rec_id(0), WriteClass::Chat, WriteKind::Ring, "slow-chat");
        h.enqueue(chat);
        tokio::time::sleep(Duration::from_millis(10)).await; // let it dispatch

        let budget = Duration::from_secs(2);
        let started = Instant::now();
        h.shutdown(budget).await;
        let elapsed = started.elapsed();

        // Bounded on both sides — the flush returns AT the budget: it spends the whole
        // budget (it does not give up early on work that might still land) and not a
        // second more (it does not run on at the sink's 60s pace).
        assert!(
            elapsed >= budget,
            "the flush must spend its whole budget before abandoning (took {elapsed:?})"
        );
        assert!(
            elapsed < budget + Duration::from_secs(1),
            "the flush must return at its budget, not at the pace of the unfinished \
             write (budget {budget:?}, took {elapsed:?})"
        );
    }

    // ── WB-ISC-12 (Anti) ──────────────────────────────────────────────────────
    /// A queued withdraw/leave is never coalesced away by a same-id current-state
    /// write: withdraw enqueued, then a watchdog refresh enqueued → withdraw
    /// dispatches, refresh dropped.
    #[tokio::test(start_paused = true)]
    async fn wb_isc_12_tombstone_dominates_same_id_current_state() {
        // Cap the window at 0 in-flight by pausing dispatch? Instead use a moderate
        // sink; enqueue both before the record can dispatch by holding the record
        // busy with a prior write.
        let sink = MockSink::new(Duration::from_secs(5));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
        let rec = rec_id(7);

        // Occupy the record with an initial current-state write so the record is
        // in-flight; the withdraw + refresh both queue behind it (same record).
        let (occupy, _rx0) = req(
            rec,
            WriteClass::AdvertRefresh,
            WriteKind::CurrentState {
                logical_id: "share-x".into(),
            },
            "occupy",
        );
        h.enqueue(occupy);
        tokio::time::sleep(Duration::from_millis(10)).await; // let it go in-flight

        // Withdraw (tombstone) then a watchdog refresh for the SAME id, both queued.
        let (withdraw, _rxw) = req(
            rec,
            WriteClass::SessionBoundary,
            WriteKind::Tombstone {
                logical_id: "share-x".into(),
            },
            "withdraw",
        );
        h.enqueue(withdraw);
        let (refresh, refresh_reply) = req(
            rec,
            WriteClass::AdvertRefresh,
            WriteKind::CurrentState {
                logical_id: "share-x".into(),
            },
            "refresh",
        );
        h.enqueue(refresh);

        // Drain everything.
        tokio::time::sleep(Duration::from_secs(20)).await;

        let labels: Vec<String> = sink.log().into_iter().map(|r| r.label).collect();
        assert!(
            labels.contains(&"withdraw".to_string()),
            "the withdraw must dispatch"
        );
        assert!(
            !labels.contains(&"refresh".to_string()),
            "the same-id refresh must be dropped, never resurrect the withdrawn share"
        );
        // The dropped refresh resolves Ok (intent deliberately suppressed).
        assert!(refresh_reply.await.unwrap().is_ok());
    }

    // ── WB-ISC-13 ─────────────────────────────────────────────────────────────
    /// Slot/seq assignment for ring writes occurs inside the record lock at dispatch:
    /// the scheduler's per-record single-flight means same-record ring writes never
    /// overlap, so the sink is called serially per record (the seq bump inside
    /// `record_lock` is thus never concurrent for one record). Complements the
    /// rendezvous `record_lock` interleaving oracle.
    #[tokio::test(start_paused = true)]
    async fn wb_isc_13_same_record_ring_writes_never_overlap() {
        // A sink that asserts it is never entered concurrently for the same record.
        struct SerialSink {
            active: Arc<Mutex<HashSet<RecordId>>>,
            order: Arc<Mutex<Vec<u64>>>,
        }
        impl WriteSink for SerialSink {
            type Item = (RecordId, u64);
            fn dispatch(&self, item: (RecordId, u64), _lane: DispatchLane) -> DispatchFuture {
                let (rec, seq) = item;
                let active = self.active.clone();
                let order = self.order.clone();
                Box::pin(async move {
                    assert!(
                        active.lock().unwrap().insert(rec),
                        "two writes to the same record overlapped in the sink — \
                         seq/slot assignment would race"
                    );
                    order.lock().unwrap().push(seq);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    active.lock().unwrap().remove(&rec);
                    DispatchOutcome::bare(Ok(()))
                })
            }
        }
        let sink = Arc::new(SerialSink {
            active: Arc::new(Mutex::new(HashSet::new())),
            order: Arc::new(Mutex::new(Vec::new())),
        });
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
        let rec = rec_id(3);
        for seq in 0..8u64 {
            h.enqueue(WriteRequest {
                record: rec,
                class: WriteClass::Chat,
                kind: WriteKind::Ring,
                deadline: None,
                item: (rec, seq),
                reply: None,
            });
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let order = sink.order.lock().unwrap().clone();
        assert_eq!(
            order,
            (0..8).collect::<Vec<_>>(),
            "ring writes dispatched in enqueue order"
        );
    }

    // ── Supporting unit coverage ──────────────────────────────────────────────
    /// I3 last-writer-wins: a queued keepalive superseded by a newer keepalive for
    /// the same member id is dropped (only the newest lands).
    #[tokio::test(start_paused = true)]
    async fn i3_current_state_coalesces_last_writer_wins() {
        let sink = MockSink::new(Duration::from_secs(5));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
        let rec = rec_id(9);
        // Occupy so the next three queue.
        let (occupy, _r0) = req(rec, WriteClass::Chat, WriteKind::Ring, "occupy");
        h.enqueue(occupy);
        tokio::time::sleep(Duration::from_millis(10)).await;
        for i in 0..3 {
            let (rq, _r) = req(
                rec,
                WriteClass::Keepalive,
                WriteKind::CurrentState {
                    logical_id: "m1".into(),
                },
                &format!("ka-{i}"),
            );
            h.enqueue(rq);
        }
        tokio::time::sleep(Duration::from_secs(20)).await;
        let kas: Vec<String> = sink
            .log()
            .into_iter()
            .map(|r| r.label)
            .filter(|l| l.starts_with("ka-"))
            .collect();
        assert_eq!(
            kas,
            vec!["ka-2".to_string()],
            "only the last-writer keepalive lands"
        );
    }

    /// **A `Chat`-class `CurrentState` write IS coalescible, and the survivor inherits
    /// the STRONGEST class of the set it subsumed.**
    ///
    /// Coalescing is keyed on `kind` alone — `enqueue` matches on `req.kind` and never
    /// reads `req.class` — so the chat lane confers priority and a reserved dispatch
    /// slot, NOT the never-coalesce property. Only `WriteKind::Ring` confers that.
    /// `docs/design/direct-messaging.md:127` describes the chat lane as "never
    /// coalesced", which is true of the writes it has in mind (all `Ring`) and not of
    /// the lane; the DM doorbell is the first `Chat`-class `CurrentState` writer, so it
    /// is the first place the distinction can bite.
    ///
    /// **This test previously pinned the survivor keeping its OWN class, and that was
    /// wrong.** A review showed the consequence: a queued `Chat` first-contact
    /// knock coalesced by its own `Keepalive` re-seed produced a `Keepalive` survivor,
    /// which `drain_for_shutdown` then SHEDS — so on quit nothing reached the wire while
    /// the coalesced caller already held an `Ok(())` from `drop_same_id_current_state`.
    /// Un-coalesced, that same knock flushes. Three legs below: the promotion, the
    /// absence of a spurious one, and the shutdown flush that is the whole reason the
    /// promotion exists.
    #[tokio::test(start_paused = true)]
    async fn a_coalesced_survivor_inherits_the_strongest_class_and_still_flushes() {
        let cs = |id: &str| WriteKind::CurrentState {
            logical_id: id.to_string(),
        };

        // ── Leg 1: Chat + Keepalive on one id → the survivor runs on the CHAT lane ──
        let sink = MockSink::new(Duration::from_secs(5));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
        let rec = rec_id(31);
        // Occupy so the next writes queue rather than dispatching immediately.
        let (occupy, _r0) = req(rec, WriteClass::Chat, WriteKind::Ring, "occupy");
        h.enqueue(occupy);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let (first, _r1) = req(rec, WriteClass::Chat, cs("dm-doorbell-6"), "first-send");
        h.enqueue(first);
        let (reseed, _r2) = req(rec, WriteClass::Keepalive, cs("dm-doorbell-6"), "reseed");
        h.enqueue(reseed);
        // A DIFFERENT logical id must NOT coalesce — the control that stops this
        // passing on a scheduler that simply dropped writes.
        let (other, _r3) = req(
            rec,
            WriteClass::Keepalive,
            cs("dm-doorbell-7"),
            "other-slot",
        );
        h.enqueue(other);

        tokio::time::sleep(Duration::from_secs(30)).await;
        let log = sink.log();
        let landed: Vec<(String, DispatchLane)> = log
            .iter()
            .filter(|r| r.label != "occupy")
            .map(|r| (r.label.clone(), r.lane))
            .collect();
        let labels: Vec<&str> = landed.iter().map(|(l, _)| l.as_str()).collect();
        assert!(
            !labels.contains(&"first-send"),
            "the chat-class current-state was NOT coalesced away — if this now holds, \
             the chat lane has gained never-coalesce semantics: {landed:?}"
        );
        assert!(
            labels.contains(&"reseed"),
            "the survivor must be the newer write — last-writer-wins on CONTENT is \
             what :128 requires and the promotion does not touch it: {landed:?}"
        );
        assert!(
            labels.contains(&"other-slot"),
            "a distinct logical id on the same record must never coalesce: {landed:?}"
        );
        let reseed_lane = landed
            .iter()
            .find(|(l, _)| l == "reseed")
            .expect("the re-seed landed")
            .1;
        assert_eq!(
            reseed_lane,
            DispatchLane::Chat,
            "the survivor of a supersession that subsumed a Chat write must carry Chat \
             — the lane is computed from `q.front().class` at dispatch, so it is the \
             live class and not a copy of what the caller asked for: {landed:?}"
        );

        // ── Leg 2: no spurious promotion. Keepalive + Keepalive stays Keepalive. ──
        let other_lane = landed
            .iter()
            .find(|(l, _)| l == "other-slot")
            .expect("the uncoalesced keepalive landed")
            .1;
        assert_ne!(
            other_lane,
            DispatchLane::Chat,
            "an uncoalesced Keepalive must not be promoted, or `strongest_class` is \
             returning Chat unconditionally and leg 1 proves nothing: {landed:?}"
        );

        let sink2 = MockSink::new(Duration::from_secs(5));
        let h2 = WriteScheduler::spawn(sink2.clone(), SchedulerConfig::default());
        let rec2 = rec_id(32);
        let (occupy2, _s0) = req(rec2, WriteClass::Chat, WriteKind::Ring, "occupy");
        h2.enqueue(occupy2);
        tokio::time::sleep(Duration::from_millis(10)).await;
        for i in 0..2 {
            let (ka, _s) = req(
                rec2,
                WriteClass::Keepalive,
                cs("ka-id"),
                &format!("ka-only-{i}"),
            );
            h2.enqueue(ka);
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
        let ka_lane = sink2
            .log()
            .into_iter()
            .find(|r| r.label == "ka-only-1")
            .expect("the surviving keepalive landed")
            .lane;
        assert_ne!(
            ka_lane,
            DispatchLane::Chat,
            "coalescing two Keepalives must yield a Keepalive — promotion must come \
             from the SET's strongest member, never from the act of coalescing"
        );

        // ── Leg 3: the promoted survivor survives the shutdown shed. ──
        // This is the leg that makes the promotion a correctness fix rather than a
        // priority tweak. `drain_for_shutdown` retains only Chat and tombstones, so an
        // unpromoted survivor is dropped here — after `drop_same_id_current_state`
        // already answered the coalesced caller `Ok(())`.
        let sink3 = MockSink::new(Duration::from_secs(2));
        let h3 = WriteScheduler::spawn(sink3.clone(), SchedulerConfig::default());
        let rec3 = rec_id(33);
        let (occupy3, _t0) = req(rec3, WriteClass::Chat, WriteKind::Ring, "occupy");
        h3.enqueue(occupy3);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let (knock, _t1) = req(rec3, WriteClass::Chat, cs("dm-doorbell-6"), "knock");
        h3.enqueue(knock);
        let (knock_reseed, _t2) = req(rec3, WriteClass::Keepalive, cs("dm-doorbell-6"), "knock-rs");
        h3.enqueue(knock_reseed);
        // A genuinely weak write on the same record, never coalesced with anything:
        // the control proving the shed still HAPPENS, so leg 3 is not passing because
        // shutdown began retaining everything.
        let (weak, _t3) = req(rec3, WriteClass::Keepalive, cs("weak-id"), "weak");
        h3.enqueue(weak);

        h3.shutdown(Duration::from_secs(60)).await;
        let flushed: Vec<String> = sink3.log().into_iter().map(|r| r.label).collect();
        assert!(
            flushed.contains(&"knock-rs".to_string()),
            "the promoted survivor must flush at shutdown: its coalesced elder's caller \
             was told Ok(()), and shedding it means that promise was never kept and \
             NOTHING reached the wire: {flushed:?}"
        );
        assert!(
            !flushed.contains(&"weak".to_string()),
            "an uncoalesced class-4 write must still be shed at shutdown, or this leg \
             passes on a drain that stopped shedding altogether: {flushed:?}"
        );
    }

    /// I6b deadline override: a class-4 write past its deadline dispatches ahead of
    /// a higher-class (session-boundary) write queued on another record.
    #[tokio::test(start_paused = true)]
    async fn i6b_deadline_overrides_class_order() {
        let sink = MockSink::new(Duration::from_millis(50));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
        // A keepalive whose deadline is already in the past.
        let (mut expired, _r0) = req(
            rec_id(1),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "motd".into(),
            },
            "expired-motd",
        );
        expired.deadline = Some(Instant::now());
        // A higher-class session-boundary write on another record.
        let (session, _r1) = req(
            rec_id(2),
            WriteClass::SessionBoundary,
            WriteKind::CurrentState {
                logical_id: "member".into(),
            },
            "session",
        );
        // Enqueue session first, then the expired-deadline keepalive.
        h.enqueue(session);
        h.enqueue(expired);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let log = sink.log();
        let motd = log.iter().find(|r| r.label == "expired-motd").unwrap();
        let session = log.iter().find(|r| r.label == "session").unwrap();
        assert!(
            motd.at <= session.at,
            "the deadline-expired write must dispatch no later than the higher class"
        );
    }

    // ── WB-ISC-1 (Anti) ───────────────────────────────────────────────────────
    /// Keepalive dispatch timing is statistically independent of other-class write
    /// load: the keepalive dispatch-delay distribution under a heavy chat burst is
    /// INDISTINGUISHABLE from the idle distribution (a KS distance of 0 — strictly
    /// stronger than "within the jitter band"). Chat holds a reserved dispatch slot
    /// and never counts against the non-chat cap (I4/I6), so chat load cannot shift
    /// when a keepalive dispatches — there is no correlated bias for a metadata
    /// observer to separate from zero-mean jitter.
    #[tokio::test(start_paused = true)]
    async fn wb_isc_1_keepalive_dispatch_timing_independent_of_chat_load() {
        async fn keepalive_delays(with_chat_burst: bool) -> Vec<Duration> {
            let sink = MockSink::new(Duration::from_millis(50));
            let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
            let start = Instant::now();
            // A fixed set of keepalives, one per record (enqueued first, so their
            // seqs — and thus tie-break order — are identical in both runs).
            for r in 0..10u8 {
                let (rq, _rx) = req(
                    rec_id(r),
                    WriteClass::Keepalive,
                    WriteKind::CurrentState {
                        logical_id: format!("m-{r}"),
                    },
                    &format!("ka-{r}"),
                );
                h.enqueue(rq);
            }
            if with_chat_burst {
                // A heavy chat burst across distinct records — the "user activity"
                // whose load must NOT couple into keepalive timing.
                for c in 0..40u8 {
                    let (rq, _rx) = req(
                        rec_id(100 + c),
                        WriteClass::Chat,
                        WriteKind::Ring,
                        &format!("chat-{c}"),
                    );
                    h.enqueue(rq);
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            let mut delays: Vec<Duration> = sink
                .log()
                .into_iter()
                .filter(|r| r.label.starts_with("ka-"))
                .map(|r| r.at.duration_since(start))
                .collect();
            delays.sort_unstable();
            delays
        }

        let idle = keepalive_delays(false).await;
        let burst = keepalive_delays(true).await;
        assert_eq!(idle.len(), 10, "all keepalives dispatched");
        assert_eq!(
            idle, burst,
            "chat-burst load shifted keepalive dispatch timing (KS distance ≠ 0):\n idle={idle:?}\nburst={burst:?}"
        );
    }

    /// The latency probe (WB-1.10 congestion signal) reflects non-chat enqueue-to-ack:
    /// after a FULL window of slow non-chat writes completes, the published median holds
    /// a latency at/above the sink's simulated RTT; chat completions never write it.
    /// (A partial window calm-pads to 0 — WB-5.1 / I5″.6 warmup robustness — so the
    /// window must be filled before the median crosses.)
    #[tokio::test(start_paused = true)]
    async fn latency_probe_tracks_nonchat_enqueue_to_ack() {
        let sink = MockSink::new(Duration::from_secs(3));
        let probe = Arc::new(AtomicU64::new(0));
        let h = WriteScheduler::spawn_with_probe(
            sink.clone(),
            SchedulerConfig::default(),
            probe.clone(),
        );
        // Fill the median window (LATENCY_WINDOW = 5) with slow non-chat writes on
        // distinct records so the padded median crosses to the true ~3s latency.
        for r in 0..5u8 {
            let (rq, _rx) = req(
                rec_id(r),
                WriteClass::Keepalive,
                WriteKind::CurrentState {
                    logical_id: format!("m-{r}"),
                },
                &format!("ka-{r}"),
            );
            h.enqueue(rq);
        }
        // 5 writes at W_max=2 concurrency = 3 waves × 3s; give ample settle time.
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert!(
            probe.load(Ordering::Relaxed) >= 3000,
            "after a full window the median reflects the ≥3s enqueue-to-ack latency"
        );
    }

    // ── #162 regression ──────────────────────────────────────────────────────
    /// A past-due starvation-escalation crossing (I8) must NOT keep re-arming the
    /// wakeup timer. `next_wakeup` returns `Some(future)` while a crossing is
    /// pending, then `None` (park until on_done/enqueue) once it has passed — the
    /// escalation already applies via `effective_rank`, so re-waking at `now` does
    /// nothing but burn 100% CPU. Pre-fix, `.map(|t| t.max(now))` returned
    /// `Some(now)` for the past-due crossing and the driver hot-spun.
    #[tokio::test(start_paused = true)]
    async fn issue_162_past_due_escalation_does_not_busy_spin() {
        let cfg = SchedulerConfig::default();
        let bound = cfg.age_bounds[WriteClass::Keepalive.rank() as usize - 1];
        let probe = Arc::new(AtomicU64::new(0));
        let mut st = State::<MockItem>::new(cfg, probe);
        let (r, _rx) = req(
            rec_id(1),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "m1".to_owned(),
            },
            "ka",
        );
        st.enqueue(r);
        // While the escalation crossing is in the future, a wakeup is armed for it.
        assert!(
            st.next_wakeup(Instant::now()).is_some(),
            "a pending escalation crossing arms a future wakeup"
        );
        // Advance past BOTH the escalation crossing (bound) and the FLOOR_AGE crossing
        // (2×bound, WB-5.1 / I5″.5) without dispatching (window stays saturated in
        // production); the record is still idle and queued. Once both are past, the head
        // is escalated + floor-eligible and dispatches on the next `on_done`/enqueue — no
        // wakeup re-arm.
        tokio::time::advance(bound * 2 + Duration::from_secs(1)).await;
        assert_eq!(
            st.next_wakeup(Instant::now()),
            None,
            "past-due escalation + floor crossings must not re-arm the timer (#162 busy-spin)"
        );
    }

    // ── #162 class — past-due DEADLINE must not busy-spin (review finding) ─────
    /// A past-due I6b deadline that cannot dispatch (floor lane busy AND window full)
    /// must NOT clamp its wakeup to `now` and hot-spin the driver — the same #162 class
    /// as the escalation/floor crossings. `next_wakeup` drops a past deadline (once due,
    /// `pick_floor` dispatches it deadline-first on the next lane-freeing `on_done`).
    #[tokio::test(start_paused = true)]
    async fn issue_162_past_due_deadline_does_not_busy_spin() {
        let cfg = SchedulerConfig::default();
        let bound = cfg.age_bounds[WriteClass::Keepalive.rank() as usize - 1];
        let probe = Arc::new(AtomicU64::new(0));
        let mut st = State::<MockItem>::new(cfg, probe);
        // A keepalive whose hard deadline is 1s out (the operator MOTD/announcement
        // class, #158) on an idle record, never dispatched (no sink runs here — as if
        // the floor lane and window were both saturated in production).
        let (rq, _rx) = req_deadline(
            rec_id(1),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "m1".into(),
            },
            "motd",
            Instant::now() + Duration::from_secs(1),
        );
        st.enqueue(rq);
        assert!(
            st.next_wakeup(Instant::now()).is_some(),
            "a future deadline arms a wakeup"
        );
        // Advance past the deadline AND both age crossings (floor = 2×bound); with the
        // deadline correctly DROPPED (not clamped to `now`), no wakeup re-arms.
        tokio::time::advance(bound * 2 + Duration::from_secs(2)).await;
        assert_eq!(
            st.next_wakeup(Instant::now()),
            None,
            "a past-due deadline must not clamp to `now` and hot-spin the driver"
        );
    }

    // ── #164 regression ──────────────────────────────────────────────────────
    /// An IN-FLIGHT tombstone dominates a same-id current-state exactly like a
    /// queued one (WB-ISC-12 only exercised the queued case). A keepalive enqueued
    /// while a leave tombstone is mid-DHT-write must be dropped, not resurrect the
    /// departed member on peers' rosters.
    #[tokio::test(start_paused = true)]
    async fn issue_164_in_flight_tombstone_dominates_same_id_current_state() {
        let sink = MockSink::new(Duration::from_secs(5));
        let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
        let rec = rec_id(9);

        // A leave tombstone on an idle record dispatches immediately and is now in
        // flight (its 5s DHT set is running); it is no longer in any queue.
        let (leave, _rxl) = req(
            rec,
            WriteClass::SessionBoundary,
            WriteKind::Tombstone {
                logical_id: "m9".into(),
            },
            "leave",
        );
        h.enqueue(leave);
        tokio::time::sleep(Duration::from_millis(10)).await; // let it go in-flight

        // A same-id keepalive enqueued WHILE the leave is in flight must be dominated.
        let (keepalive, ka_reply) = req(
            rec,
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "m9".into(),
            },
            "keepalive",
        );
        h.enqueue(keepalive);

        tokio::time::sleep(Duration::from_secs(20)).await;

        let labels: Vec<String> = sink.log().into_iter().map(|r| r.label).collect();
        assert!(
            labels.contains(&"leave".to_string()),
            "the leave tombstone must dispatch"
        );
        assert!(
            !labels.contains(&"keepalive".to_string()),
            "a same-id keepalive enqueued while the leave is in flight must be dropped"
        );
        assert!(
            ka_reply.await.unwrap().is_ok(),
            "the dominated keepalive resolves Ok (intent superseded)"
        );
    }

    // ── WB-ISC-18: median-of-5 DHT-weather estimator ─────────────────────────
    /// The published regime signal is the MEDIAN of the last `LATENCY_WINDOW` non-chat
    /// latencies (WB-5.1 / I5″.6), so a single fast (or slow) straggler amid a run cannot
    /// cross the band, and recovery takes 3 of 5 fast completions — replacing the EMA
    /// fast-exit chatter the freeze refuted.
    #[test]
    fn wb_isc_18_median_of_5_rejects_single_outlier_and_recovers_in_three() {
        fn push(ring: &mut VecDeque<u64>, v: u64) {
            ring.push_back(v);
            while ring.len() > LATENCY_WINDOW {
                ring.pop_front();
            }
        }
        assert_eq!(
            median_ms(&VecDeque::new()),
            0,
            "empty window has no signal yet"
        );

        let mut ring: VecDeque<u64> = VecDeque::new();
        // Establish an elevated regime: five slow completions → elevated median.
        for _ in 0..5 {
            push(&mut ring, 20_000);
        }
        assert_eq!(median_ms(&ring), 20_000, "five slow → elevated median");
        // One, then two fast completions amid the slow run do NOT cross to calm.
        push(&mut ring, 500);
        assert_eq!(median_ms(&ring), 20_000, "one fast of five does not cross");
        push(&mut ring, 500);
        assert_eq!(median_ms(&ring), 20_000, "two fast of five does not cross");
        // The THIRD fast completion crosses: ring = [20000,20000,500,500,500] → median 500.
        push(&mut ring, 500);
        assert_eq!(median_ms(&ring), 500, "three fast of five cross to calm");
        // A single slow straggler during recovery does NOT bounce back to elevated.
        push(&mut ring, 20_000);
        assert_eq!(
            median_ms(&ring),
            500,
            "a single slow outlier does not re-elevate"
        );

        // Warmup (partial window): the window is calm-padded to LATENCY_WINDOW, so a
        // single slow sample cannot cross the band before 3 real slow samples — the
        // 3-of-5 robustness holds from the first sample, not only once the ring fills.
        let mut warm: VecDeque<u64> = VecDeque::new();
        push(&mut warm, 20_000);
        assert_eq!(
            median_ms(&warm),
            0,
            "one slow sample of a padded window stays calm"
        );
        push(&mut warm, 20_000);
        assert_eq!(median_ms(&warm), 0, "two slow of five (padded) stays calm");
        push(&mut warm, 20_000);
        assert_eq!(
            median_ms(&warm),
            20_000,
            "three slow of five crosses to elevated even at warmup"
        );
    }

    /// Max concurrent non-chat dispatches over the log, given each write occupies
    /// `[at, at + latency]` (the MockSink's simulated DHT round-trip).
    fn max_concurrency(log: &[Rec], latency: Duration) -> usize {
        let mut events: Vec<(Instant, i32)> = Vec::new();
        for r in log {
            events.push((r.at, 1));
            events.push((r.at + latency, -1));
        }
        events.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let (mut cur, mut max) = (0i32, 0i32);
        for (_, d) in events {
            cur += d;
            max = max.max(cur);
        }
        max as usize
    }

    // ── WB-ISC-16 (sink-level): static window, invariant to latency ───────────
    /// The non-chat window equals `min(distinct pending records, W_max)` and NEVER
    /// varies with any latency signal — the §I5′.2 acquire-wait controller is retired
    /// (WB-5.1 / I5″.3). Under BOTH a fast and a slow (30s exogenous-floor) write regime
    /// the max concurrent non-chat dispatch count is W_max=2 with ≥2 pending records; it
    /// never collapses (the pre-WB-5.1 controller would have shrunk it under load).
    #[tokio::test(start_paused = true)]
    async fn wb_isc_16_window_is_static_and_never_shrinks_with_latency() {
        async fn max_nonchat_concurrency(rtt: Duration) -> usize {
            let sink = MockSink::new(rtt);
            let h = WriteScheduler::spawn(sink.clone(), SchedulerConfig::default());
            for r in 0..6u8 {
                let (rq, _rx) = req(
                    rec_id(r),
                    WriteClass::Keepalive,
                    WriteKind::CurrentState {
                        logical_id: format!("m-{r}"),
                    },
                    &format!("ka-{r}"),
                );
                h.enqueue(rq);
            }
            // Long enough for every write to dispatch (6 writes at 2-concurrency = 3
            // waves) under either regime.
            tokio::time::sleep(rtt * 10).await;
            max_concurrency(&sink.log(), rtt)
        }

        assert_eq!(
            max_nonchat_concurrency(Duration::from_millis(50)).await,
            2,
            "fast writes: the window sits at W_max=2"
        );
        assert_eq!(
            max_nonchat_concurrency(Duration::from_secs(30)).await,
            2,
            "slow (exogenous-floor) writes: the RETIRED controller must NOT collapse the \
             window — it stays static at W_max=2"
        );
    }

    // ── WB-ISC-26 (Anti): panic never wedges the funnel nor leaks a lane counter ──
    /// A panic in a dispatched write — whether a SYNCHRONOUS panic during dispatch-future
    /// CONSTRUCTION or a panic in the async body — must never wedge the scheduler nor
    /// leak a lane counter (WB-5.1 / I5″.8). The panicking write resolves `Err`, the lane
    /// counter it drew (`window_in_flight` / `floor_in_flight`) returns to 0, and
    /// subsequent writes dispatch. The sync-construction path is the new coverage: the
    /// fix moves `sink.dispatch(...)` construction INSIDE the supervised inner spawn, so a
    /// sync panic is caught by the join instead of crashing the driver. The FLOOR lane is
    /// exercised distinctly (capacity 1 — a leaked floor counter is silent starvation).
    #[tokio::test(start_paused = true)]
    async fn wb_isc_26_panic_recovers_lane_counters_sync_and_async() {
        /// Panics synchronously (before returning the future) for `"boom-sync"`; panics
        /// in the async body for `"boom-async"`; `"hold"` occupies its lane for 10s;
        /// everything else succeeds immediately.
        struct LanePanicSink {
            log: Arc<Mutex<Vec<Rec>>>,
        }
        impl WriteSink for LanePanicSink {
            type Item = MockItem;
            fn dispatch(&self, item: MockItem, lane: DispatchLane) -> DispatchFuture {
                // SYNCHRONOUS construction panic — escapes to the driver thread unless the
                // fix runs construction inside the supervised inner spawn (WB-ISC-26).
                assert_ne!(item.label, "boom-sync", "simulated sync construction panic");
                let log = self.log.clone();
                Box::pin(async move {
                    assert_ne!(item.label, "boom-async", "simulated async write-path panic");
                    if item.label == "hold" {
                        tokio::time::sleep(Duration::from_secs(10)).await; // pin the lane
                    }
                    log.lock().unwrap().push(Rec {
                        label: item.label,
                        at: Instant::now(),
                        lane,
                    });
                    DispatchOutcome::bare(Ok(()))
                })
            }
        }
        let sink = Arc::new(LanePanicSink {
            log: Arc::new(Mutex::new(Vec::new())),
        });
        // W_max = 1 so a leaked window slot wedges the window shut entirely.
        let cfg = SchedulerConfig {
            nonchat_cap: 1,
            ..SchedulerConfig::default()
        };
        let h = WriteScheduler::spawn(sink.clone(), cfg);
        let ka = |rec: u8, id: &str, label: &str| {
            req(
                rec_id(rec),
                WriteClass::Keepalive,
                WriteKind::CurrentState {
                    logical_id: id.into(),
                },
                label,
            )
        };

        // (1) Async-body panic on the WINDOW lane → reply Err; the window slot releases.
        let (boom, boom_rx) = ka(1, "m1", "boom-async");
        h.enqueue(boom);
        let r = tokio::time::timeout(Duration::from_secs(5), boom_rx)
            .await
            .expect("async panic resolves its reply, not a hang")
            .expect("reply channel intact");
        assert!(r.is_err(), "an async-body panic resolves Err");
        // A fresh window write dispatches — the window counter recovered (not wedged).
        let (ok1, ok1_rx) = ka(2, "m2", "ok1");
        h.enqueue(ok1);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), ok1_rx)
                .await
                .expect("window not wedged")
                .expect("chan")
                .is_ok(),
            "the follow-up window write dispatched (window_in_flight returned to 0)"
        );

        // (2) SYNC-construction panic → the driver must NOT crash; reply Err, and the
        // scheduler survives to dispatch the next write.
        let (bs, bs_rx) = ka(3, "m3", "boom-sync");
        h.enqueue(bs);
        let r = tokio::time::timeout(Duration::from_secs(5), bs_rx)
            .await
            .expect("driver survives a synchronous construction panic (does not crash)")
            .expect("chan");
        assert!(
            r.is_err(),
            "a sync-construction panic resolves Err, not a crash"
        );

        // (3) FLOOR-lane recovery. Pin the single window slot with a slow "hold" write,
        // then a deadline-due write dispatches via the FLOOR lane (window busy) and
        // panics; a following deadline-due write MUST still dispatch via the floor while
        // the window remains held — proving `floor_in_flight` returned to 0 (a leak would
        // block it, since the window is unavailable — the capacity-1 silent-starvation).
        let (hold, _hold_rx) = ka(4, "m4", "hold");
        h.enqueue(hold);
        tokio::time::sleep(Duration::from_millis(50)).await; // let it take the window slot
        let now = Instant::now();
        let (fboom, fboom_rx) = req_deadline(
            rec_id(5),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "m5".into(),
            },
            "boom-async",
            now,
        );
        h.enqueue(fboom);
        assert!(tokio::time::timeout(Duration::from_secs(5), fboom_rx)
            .await
            .expect("floor panic no hang")
            .expect("chan")
            .is_err());
        let (fok, fok_rx) = req_deadline(
            rec_id(6),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "m6".into(),
            },
            "ok2",
            Instant::now(),
        );
        h.enqueue(fok);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), fok_rx)
                .await
                .expect("floor lane not wedged: a deadline-due write dispatches while the window is held")
                .expect("chan")
                .is_ok(),
            "the floor lane recovered after the panic (floor_in_flight returned to 0)"
        );
    }

    // ── WB-ISC-23: floor lane — coalesced-refreshed write ages via inherited clock ──
    /// A non-chat write whose queue entry was REPLACED by I3 coalescing still ages to the
    /// floor because the winning write inherits the elder's `starved_since` (WB-5.1 /
    /// I5″.5). With the single window slot pinned by a slow write, a keepalive that is
    /// refreshed (coalesced) partway through its life still dispatches via the FLOOR lane
    /// once its INHERITED starved-age crosses FLOOR_AGE — an ADDITIONAL slot beyond the
    /// saturated window. Had `starved_since` reset on coalescing, it would never reach the
    /// floor and would starve behind the pinned window.
    #[tokio::test(start_paused = true)]
    async fn wb_isc_23_floor_dispatches_coalesced_refreshed_write_as_additional_slot() {
        struct HoldSink {
            log: Arc<Mutex<Vec<Rec>>>,
        }
        impl WriteSink for HoldSink {
            type Item = MockItem;
            fn dispatch(&self, item: MockItem, lane: DispatchLane) -> DispatchFuture {
                let log = self.log.clone();
                Box::pin(async move {
                    if item.label == "hold" {
                        tokio::time::sleep(Duration::from_secs(600)).await; // pin the window
                    }
                    log.lock().unwrap().push(Rec {
                        label: item.label,
                        at: Instant::now(),
                        lane,
                    });
                    DispatchOutcome::bare(Ok(()))
                })
            }
        }
        let sink = Arc::new(HoldSink {
            log: Arc::new(Mutex::new(Vec::new())),
        });
        let cfg = SchedulerConfig {
            nonchat_cap: 1,
            ..SchedulerConfig::default()
        };
        // FLOOR_AGE(keepalive) = 2 × age_bounds[3] = 240s.
        let floor_age = cfg.age_bounds[WriteClass::Keepalive.rank() as usize - 1] * 2;
        let h = WriteScheduler::spawn(sink.clone(), cfg);

        // Pin the single window slot for the whole test.
        let (hold, _hold_rx) = req(
            rec_id(1),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "m1".into(),
            },
            "hold",
        );
        h.enqueue(hold);
        tokio::time::sleep(Duration::from_millis(50)).await; // let it take the window slot

        // A keepalive on record 2 — window is full, not yet floor-eligible → queued. Its
        // starvation clock starts now (~t=50ms).
        let (b1, _b1_rx) = req(
            rec_id(2),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "m2".into(),
            },
            "b1",
        );
        h.enqueue(b1);

        // Halfway through its life, refresh it (I3 coalescing): a NEW entry with a fresh
        // `enqueued` but the elder's INHERITED `starved_since`.
        tokio::time::sleep(floor_age / 2).await;
        let (b2, b2_rx) = req(
            rec_id(2),
            WriteClass::Keepalive,
            WriteKind::CurrentState {
                logical_id: "m2".into(),
            },
            "b2",
        );
        h.enqueue(b2);

        // Advance just past FLOOR_AGE measured from the INHERITED clock. The window is
        // still pinned by "hold", so the ONLY path for b2 is the floor lane — and it
        // dispatches BECAUSE the inherited clock (not the fresh `enqueued`) crossed
        // FLOOR_AGE.
        tokio::time::sleep(floor_age / 2 + Duration::from_secs(1)).await;
        let r = tokio::time::timeout(Duration::from_secs(5), b2_rx)
            .await
            .expect("the coalesced-refreshed write ages to the floor via the inherited clock")
            .expect("reply channel intact");
        assert!(
            r.is_ok(),
            "b2 dispatched via the floor lane while the window was pinned"
        );
        let labels: Vec<String> = sink
            .log
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.label.clone())
            .collect();
        assert!(
            labels.contains(&"b2".to_string()),
            "the refreshed write reached the sink via the additional floor slot: {labels:?}"
        );
        assert!(
            !labels.contains(&"b1".to_string()),
            "the coalesced-away elder never dispatched (its intent was superseded)"
        );
    }
}
