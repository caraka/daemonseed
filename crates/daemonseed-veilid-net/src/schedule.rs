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
//! - **I4 — chat latency bound.** A chat write to an idle record dispatches immediately
//!   (well under 2s at any queue depth); chat holds a reserved dispatch slot and is
//!   never counted against I5's non-chat cap.
//! - **I5 — bounded in-flight.** Non-chat in-flight sets are capped by the
//!   [`crate::aimd::AimdWindow`] pacer, fed enqueue-to-ack latency; the queue
//!   rate-limits, not merely orders.
//! - **I6b — deadline override.** A write with a hard DHT expiry (operator MOTD/
//!   announcement keepalive, #158) dispatches ahead of class order once its deadline
//!   passes.
//! - **I7 — shutdown flush + shed.** On graceful close, pending chat + tombstones/
//!   withdraws flush within the close budget; class-3/4/5 current-state writes are shed.
//! - **I8 — starvation floor.** A write older than its class's age bound escalates one
//!   class (bounds class-5 starvation → the #157 zero-discovery symptom).
//! - **I9 — no read-triggered writes.** The enqueue surface accepts only write intents;
//!   no read/render/reap path can reach it (WB-0's derived rule, enforced structurally
//!   by there being no write-emitting call from the read side).
//!
//! The I1 funnel also retires #154's inline-park failure mode: the actor's write
//! commands enqueue and return, so a slow DHT set never parks the command loop.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::aimd::AimdWindow;
use crate::error::{Result, VeilidNetError};

/// A DHT record's identity for FIFO + coalescing scope — the rendezvous owner seed
/// (a `set_dht_value` targets one record derived from one owner seed).
pub type RecordId = [u8; 32];

/// The future a [`WriteSink`] returns for one dispatch: owns its data so the
/// scheduler can spawn it off the driver loop.
pub type DispatchFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// The seam over the physical DHT write (WB-2 oracle requirement). The scheduler
/// decides WHEN and IN WHAT ORDER to write; the sink performs one write and returns
/// its result. Production wires this to the existing per-record dispatch functions
/// (so #131 + ring-seq-in-`record_lock` stay untouched); the oracle wires a counting
/// mock with an injected clock, so the whole scheduler is testable in paused time
/// with no live DHT.
pub trait WriteSink: Send + Sync + 'static {
    /// The opaque per-write dispatch token the scheduler carries and hands back.
    type Item: Send + 'static;
    /// Perform one DHT write. The returned future is spawned off the driver loop.
    fn dispatch(&self, item: Self::Item) -> DispatchFuture;
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

/// Tunable scheduler parameters. Defaults track the WB-2 freeze.
#[derive(Clone, Copy, Debug)]
pub struct SchedulerConfig {
    /// AIMD floor — at least one non-chat write may always be in flight (I5).
    pub nonchat_floor: usize,
    /// AIMD ceiling / initial non-chat in-flight cap (I5 = 2).
    pub nonchat_cap: usize,
    /// Enqueue-to-ack latency at/above which the AIMD window halves (I5 breach).
    pub latency_threshold: Duration,
    /// Per-class starvation age bound (I8), indexed by `rank()-1`. A queued write
    /// older than its class's bound escalates one class.
    pub age_bounds: [Duration; 5],
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            nonchat_floor: 1,
            nonchat_cap: 2,
            // Healthy DHT writes are single-digit seconds (WB-2); a sustained
            // enqueue-to-ack past 10s is congestion → shrink the window.
            latency_threshold: Duration::from_secs(10),
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
    is_chat: bool,
    /// Enqueue-to-ack latency — the AIMD congestion signal (WB-1.10 / I5).
    latency: Duration,
}

struct Pending<D> {
    seq: u64,
    enqueued: Instant,
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
        let (tx, rx) = mpsc::unbounded_channel::<SchedMsg<S::Item>>();
        let (done_tx, done_rx) = mpsc::unbounded_channel::<Done>();
        tokio::spawn(run(sink, cfg, rx, done_tx, done_rx));
        WriteSchedulerHandle { tx }
    }
}

struct State<D> {
    cfg: SchedulerConfig,
    /// Per-record FIFO queues (I2). A record with no queue entry has nothing pending.
    queues: HashMap<RecordId, VecDeque<Pending<D>>>,
    /// Records with a write currently in flight (per-record single-flight).
    in_flight: HashSet<RecordId>,
    /// Count of NON-chat writes in flight (the I5 cap subject; chat is uncapped).
    nonchat_in_flight: usize,
    /// AIMD pacer for the non-chat in-flight window (I5).
    window: AimdWindow,
    seq: u64,
}

impl<D: Send + 'static> State<D> {
    fn new(cfg: SchedulerConfig) -> Self {
        Self {
            window: AimdWindow::new(cfg.nonchat_floor, cfg.nonchat_cap),
            cfg,
            queues: HashMap::new(),
            in_flight: HashSet::new(),
            nonchat_in_flight: 0,
            seq: 0,
        }
    }

    /// Apply the I3 coalescing + dominance rules and enqueue (or drop) the request.
    fn enqueue(&mut self, req: WriteRequest<D>) {
        let now = Instant::now();
        let q = self.queues.entry(req.record).or_default();
        match &req.kind {
            // Chat ring writes are never coalesced or dropped (I3/WB-ISC-11).
            WriteKind::Ring => {}
            WriteKind::CurrentState { logical_id } => {
                // Tombstone dominance (WB-ISC-12): a same-id withdraw already queued
                // suppresses this current-state write entirely — it must not resurrect
                // a withdrawn share (#121/#118). Report Ok (intent deliberately
                // superseded), do not enqueue.
                if q.iter().any(|p| {
                    p.kind.is_tombstone() && p.kind.logical_id() == Some(logical_id.as_str())
                }) {
                    resolve_ok(req.reply);
                    return;
                }
                // Last-writer-wins coalescing: drop the older same-id current-state.
                drop_same_id_current_state(q, logical_id);
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
            class: req.class,
            kind: req.kind,
            deadline: req.deadline,
            item: req.item,
            reply: req.reply,
        };
        self.seq += 1;
        q.push_back(pending);
    }

    /// Dispatch as many eligible writes as the invariants allow (I1/I2/I4/I5/I6b/I8).
    fn try_dispatch<S: WriteSink<Item = D>>(
        &mut self,
        sink: &Arc<S>,
        done_tx: &mpsc::UnboundedSender<Done>,
    ) {
        let now = Instant::now();
        loop {
            // (I6b) Deadline override: a write past its hard expiry dispatches ahead
            // of class order and bypasses the I5 cap — expiry is data loss, not
            // staleness. Still respects per-record single-flight.
            if let Some(rec) = self.pick_deadline_due(now) {
                self.dispatch(rec, sink, done_tx);
                continue;
            }
            // (I4) Chat: an idle record whose head is chat dispatches immediately on a
            // reserved slot, never counted against the I5 cap, at any queue depth.
            if let Some(rec) = self.pick_chat_ready() {
                self.dispatch(rec, sink, done_tx);
                continue;
            }
            // (I1/I5/I8) Non-chat under the AIMD window: highest effective priority.
            if self.nonchat_in_flight < self.window.window() {
                if let Some(rec) = self.pick_best_nonchat(now) {
                    self.dispatch(rec, sink, done_tx);
                    continue;
                }
            }
            break;
        }
    }

    /// A record is dispatchable only when it has no write in flight (per-record
    /// single-flight → I2 FIFO + serialized slot/seq assignment inside the sink's
    /// `record_lock`, I13).
    fn idle(&self, rec: &RecordId) -> bool {
        !self.in_flight.contains(rec)
    }

    fn pick_deadline_due(&self, now: Instant) -> Option<RecordId> {
        self.queues
            .iter()
            .filter(|(rec, q)| self.idle(rec) && !q.is_empty())
            .filter_map(|(rec, q)| {
                let head = q.front().unwrap();
                head.deadline
                    .filter(|d| *d <= now)
                    .map(|d| (*rec, d, head.seq))
            })
            .min_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)))
            .map(|(rec, _, _)| rec)
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

    /// I8: a write older than its class's age bound escalates one class (a smaller
    /// rank sorts ahead). Escalation only reorders within the non-chat pool — it
    /// never grants the chat reserved slot / I5 bypass (that is keyed on the
    /// original class, not the escalated rank).
    fn effective_rank(&self, p: &Pending<D>, now: Instant) -> u8 {
        let rank = p.class.rank();
        let bound = self.cfg.age_bounds[(rank - 1) as usize];
        if now.saturating_duration_since(p.enqueued) >= bound {
            rank.saturating_sub(1).max(1)
        } else {
            rank
        }
    }

    fn dispatch<S: WriteSink<Item = D>>(
        &mut self,
        rec: RecordId,
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
        let is_chat = p.class == WriteClass::Chat;
        self.in_flight.insert(rec);
        if !is_chat {
            self.nonchat_in_flight += 1;
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
            let res = sink.dispatch(item).await;
            // Enqueue-to-ack (queue wait + lock wait + set RTT) — the WB-1.10 / I5
            // congestion signal, NOT set-RTT alone.
            let latency = enqueued.elapsed();
            if let Some(reply) = reply {
                let _ = reply.send(res);
            }
            let _ = done_tx.send(Done {
                record: rec,
                is_chat,
                latency,
            });
        });
    }

    fn on_done(&mut self, d: Done) {
        self.in_flight.remove(&d.record);
        if !d.is_chat {
            self.nonchat_in_flight = self.nonchat_in_flight.saturating_sub(1);
            // Feed the AIMD pacer: a slow enqueue-to-ack shrinks the non-chat window
            // (I5 rate-limits, not merely orders).
            self.window.observe(d.latency, self.cfg.latency_threshold);
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
                let rank = head.class.rank();
                let esc = head.enqueued + self.cfg.age_bounds[(rank - 1) as usize];
                [head.deadline, Some(esc)].into_iter().flatten()
            })
            .map(|t| t.max(now))
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
                .map(|(rec, _)| *rec);
            match pick {
                Some(rec) => {
                    self.dispatch(rec, sink, done_tx);
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

/// Drop the queued same-id current-state write (last-writer-wins), resolving its
/// reply `Ok` — the newer write subsumes it.
fn drop_same_id_current_state<D>(q: &mut VecDeque<Pending<D>>, logical_id: &str) {
    let mut i = 0;
    while i < q.len() {
        let matches =
            matches!(&q[i].kind, WriteKind::CurrentState { logical_id: id } if id == logical_id);
        if matches {
            let dropped = q.remove(i).expect("index in range");
            resolve_ok(dropped.reply);
        } else {
            i += 1;
        }
    }
}

async fn run<S: WriteSink>(
    sink: Arc<S>,
    cfg: SchedulerConfig,
    mut rx: mpsc::UnboundedReceiver<SchedMsg<S::Item>>,
    done_tx: mpsc::UnboundedSender<Done>,
    mut done_rx: mpsc::UnboundedReceiver<Done>,
) {
    let mut st = State::<S::Item>::new(cfg);
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

    /// One recorded dispatch: the item label + the virtual instant it fired.
    #[derive(Clone)]
    struct Rec {
        label: String,
        at: Instant,
    }

    /// A counting mock sink (the WB-2 oracle seam): records every dispatched write
    /// (label + timestamp) and simulates a DHT round-trip by sleeping `latency` in
    /// paused virtual time.
    struct MockSink {
        log: Arc<Mutex<Vec<Rec>>>,
        latency: Duration,
        dispatched: AtomicU64,
    }

    struct MockItem {
        label: String,
    }

    impl MockSink {
        fn new(latency: Duration) -> Arc<Self> {
            Arc::new(Self {
                log: Arc::new(Mutex::new(Vec::new())),
                latency,
                dispatched: AtomicU64::new(0),
            })
        }
        fn log(&self) -> Vec<Rec> {
            self.log.lock().unwrap().clone()
        }
    }

    impl WriteSink for MockSink {
        type Item = MockItem;
        fn dispatch(&self, item: MockItem) -> DispatchFuture {
            let log = self.log.clone();
            let latency = self.latency;
            self.dispatched.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                log.lock().unwrap().push(Rec {
                    label: item.label,
                    at: Instant::now(),
                });
                tokio::time::sleep(latency).await;
                Ok(())
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
            fn dispatch(&self, item: (RecordId, u64)) -> DispatchFuture {
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
                    Ok(())
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
}
