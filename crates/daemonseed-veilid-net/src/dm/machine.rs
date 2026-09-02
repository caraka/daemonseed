//! The DM driver's decision half: pure step functions returning effects.
//!
//! The machine reads no clock and performs no I/O over the DHT. Each step takes
//! the wall time its caller read and returns what should happen, so ordering and
//! cadence decisions are checkable by value rather than by racing paused time —
//! the same split [`crate::route_budget`] and [`crate::schedule`] are built on.
//!
//! One deliberate impurity: the machine owns its [`DmPersist`], because that
//! store's mutation API is designed to be called at the mutation site and a
//! temporary directory is available to every test. The seam is over what a test
//! cannot have — the DHT — not over disk.

use std::time::Duration;

use daemonseed_core::dm::ack_record::DmAckAddress;
use daemonseed_core::dm::firstcontact::AR_FINGERPRINT_LEN;
use daemonseed_core::dm::paging::{DmPageAddress, Receiving, Sending};
use daemonseed_core::dm::persist::DmPersist;

use crate::actor::{DmPageSweep, DoorbellDispatch, DoorbellSweep};
use crate::dm::driver::DmDriverConfig;
use crate::dm::types::{DmEvent, DmIdentity};

/// One thing the shell should do as a result of a step.
// Items 2-4 construct these; item 1's machine returns no effects, so nothing in
// this crate builds one yet.
#[allow(dead_code)]
pub(crate) enum DmEffect {
    /// Spawn one DHT operation off the loop.
    Dht(DhtOp),
    /// Send one event to the front end.
    Emit(DmEvent),
}

/// What a DHT operation belongs to, carried out and handed back unchanged so the
/// machine can attribute an outcome without remembering dispatch order.
#[allow(dead_code)]
pub(crate) struct OpTag {
    /// The conversation's `AR` fingerprint, where the operation has one.
    pub conversation: Option<[u8; AR_FINGERPRINT_LEN]>,
    /// The message sequence number, where the operation has one.
    pub seq: Option<u64>,
}

/// One DHT operation, as the machine asks for it.
#[allow(dead_code)]
pub(crate) enum DhtOp {
    /// Fetch a correspondent's key record.
    FetchKeyRecord { tag: OpTag, owner_seed: [u8; 32] },
    /// Write one sealed first-contact entry into a recipient's doorbell.
    PublishDoorbell {
        tag: OpTag,
        owner_seed: [u8; 32],
        slot: u16,
        entry: Vec<u8>,
        dispatch: DoorbellDispatch,
    },
    /// Sweep our own doorbell.
    SweepDoorbell { tag: OpTag, owner_seed: [u8; 32] },
    /// Publish one sealed channel frame.
    PublishPage {
        tag: OpTag,
        address: DmPageAddress<Sending>,
        frame: Vec<u8>,
    },
    /// Sweep one receiving page.
    SweepPage {
        tag: OpTag,
        address: DmPageAddress<Receiving>,
    },
    /// Publish one direction's acknowledgement record.
    PublishAck {
        tag: OpTag,
        address: DmAckAddress,
        record: Vec<u8>,
    },
    /// Fetch the correspondent's acknowledgement.
    FetchAck { tag: OpTag, address: DmAckAddress },
}

/// What one completed DHT operation yielded.
#[allow(dead_code)]
pub(crate) enum DhtResult {
    /// A key-record fetch; `None` is the awaiting-key state.
    KeyRecord(Option<Vec<u8>>),
    /// A write completed.
    Written,
    /// A doorbell sweep.
    Doorbell(DoorbellSweep),
    /// A page sweep.
    Page(DmPageSweep),
    /// An acknowledgement fetch; `None` is no confirmation yet.
    Ack(Option<Vec<u8>>),
}

/// One completed DHT operation, tagged with what asked for it.
#[allow(dead_code)]
pub(crate) struct DhtOutcome {
    /// The tag the machine attached to the operation.
    pub tag: OpTag,
    /// The operation's result.
    pub result: crate::Result<DhtResult>,
}

/// The driver's decision half.
///
/// Item 1 holds the state items 2-4 read and decides nothing: every step returns
/// no effects and `next_due_ms` is a fixed idle cadence. Fixing the constructor
/// and the step signatures now is what lets those items add behaviour without
/// changing the shell or the front-end wiring.
pub(crate) struct DmMachine {
    // Held, not read, in item 1. Item 2 opens knocks with `identity.kem`, item 3
    // reads and writes the outbox through `persist`, item 4 reads the ack cadence
    // knobs off `cfg`.
    #[allow(dead_code)]
    identity: DmIdentity,
    #[allow(dead_code)]
    persist: DmPersist,
    cfg: DmDriverConfig,
    last_tick_ms: Option<i64>,
}

impl DmMachine {
    /// Build the machine over the state the front end constructed.
    pub(crate) fn new(identity: DmIdentity, persist: DmPersist, cfg: DmDriverConfig) -> Self {
        Self {
            identity,
            persist,
            cfg,
            last_tick_ms: None,
        }
    }

    /// Step on a front-end command.
    pub(crate) fn on_command(&mut self, _now_ms: i64, _cmd: crate::dm::DmCommand) -> Vec<DmEffect> {
        Vec::new()
    }

    /// Step on the idle cadence.
    pub(crate) fn on_tick(&mut self, now_ms: i64) -> Vec<DmEffect> {
        self.last_tick_ms = Some(now_ms);
        Vec::new()
    }

    /// Step on a completed DHT operation.
    pub(crate) fn on_outcome(&mut self, _now_ms: i64, _outcome: DhtOutcome) -> Vec<DmEffect> {
        Vec::new()
    }

    /// When the shell should next wake the machine if nothing else happens.
    pub(crate) fn next_due_ms(&self, now_ms: i64) -> i64 {
        now_ms.saturating_add(duration_as_ms(self.cfg.idle_tick))
    }

    /// The wall time of the last tick this machine saw, if it has seen one.
    ///
    /// The shell reads it back onto its probe, so the value the machine recorded
    /// is the value an oracle asserts — a probe fed the shell's own `now` instead
    /// would pass whether or not the machine ever stored anything.
    pub(crate) fn last_tick_ms(&self) -> Option<i64> {
        self.last_tick_ms
    }
}

/// A duration as milliseconds, saturating rather than wrapping. A configuration
/// large enough to overflow an `i64` of milliseconds is 292 million years out and
/// is clamped rather than folded back into the past.
pub(crate) fn duration_as_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}
