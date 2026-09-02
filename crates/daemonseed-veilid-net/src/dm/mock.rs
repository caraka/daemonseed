//! The counting [`DmDht`] mock the driver's oracles run against.
//!
//! Every method bumps its counter synchronously — before the returned future is
//! even awaited — then sleeps `latency` in paused virtual time and yields the
//! empty, successful default. Counting at call time rather than at poll time is
//! what lets an oracle assert "the driver asked for nothing" without having to
//! drive the futures it never spawned.
//!
//! The log records **non-secret projections only**. An address carries the
//! conversation's write capability as a zeroizing seed, and
//! `DmPageAddress::with_owner_seed` is the one way to reach it; nothing here calls
//! it, so a recorded call can be compared without a secret leaving the address.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use daemonseed_core::dm::ack_record::DmAckAddress;
use daemonseed_core::dm::paging::{DmPageAddress, Receiving, Sending};
use daemonseed_core::dm::ratchet::Direction;

use crate::actor::{DmPageSweep, DoorbellDispatch, DoorbellSweep};
use crate::dm::seam::{DmDht, DmDhtFuture};
use crate::SweepOutcome;

/// The seven seam methods, in trait order, as counter indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    FetchKeyRecord,
    PublishDoorbell,
    SweepDoorbell,
    PublishPage,
    SweepPage,
    PublishAck,
    FetchAck,
}

impl Method {
    /// Every method, so an oracle can assert over the whole set rather than over
    /// the ones it remembered to name.
    pub(crate) const ALL: [Method; 7] = [
        Method::FetchKeyRecord,
        Method::PublishDoorbell,
        Method::SweepDoorbell,
        Method::PublishPage,
        Method::SweepPage,
        Method::PublishAck,
        Method::FetchAck,
    ];

    fn index(self) -> usize {
        match self {
            Method::FetchKeyRecord => 0,
            Method::PublishDoorbell => 1,
            Method::SweepDoorbell => 2,
            Method::PublishPage => 3,
            Method::SweepPage => 4,
            Method::PublishAck => 5,
            Method::FetchAck => 6,
        }
    }
}

/// One recorded call, projected to what carries no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MockCall {
    /// A key-record fetch, by the record's owner seed. The key record is
    /// world-readable and its seed derives from a public identity key.
    FetchKeyRecord { owner_seed: [u8; 32] },
    /// A doorbell write. The doorbell is world-writable, so its owner seed is
    /// likewise not a capability anyone lacks.
    PublishDoorbell {
        owner_seed: [u8; 32],
        slot: u16,
        entry_len: usize,
        dispatch: DoorbellDispatch,
    },
    /// A sweep of our own doorbell.
    SweepDoorbell { owner_seed: [u8; 32] },
    /// A channel write, by the position it names and the frame's length.
    PublishPage {
        conversation: [u8; daemonseed_core::dm::firstcontact::AR_FINGERPRINT_LEN],
        page: u64,
        slot: u16,
        direction: Direction,
        frame_len: usize,
    },
    /// A channel page sweep.
    SweepPage {
        conversation: [u8; daemonseed_core::dm::firstcontact::AR_FINGERPRINT_LEN],
        page: u64,
        direction: Direction,
    },
    /// An acknowledgement write, by the direction it acknowledges.
    PublishAck {
        direction: Direction,
        record_len: usize,
    },
    /// An acknowledgement fetch.
    FetchAck { direction: Direction },
}

/// A counting [`DmDht`] with an injected latency.
pub(crate) struct MockDht {
    counts: [AtomicU64; 7],
    log: Mutex<Vec<MockCall>>,
    latency: Duration,
    /// The method whose returned future panics once its latency has elapsed, so
    /// an oracle can drive the shell's join-error path. The call is still counted
    /// and logged: a panic in the seam happens after the request was made.
    panic_on: Option<Method>,
}

impl MockDht {
    /// A mock whose every call takes `latency` of virtual time.
    pub(crate) fn new(latency: Duration) -> Self {
        Self {
            counts: Default::default(),
            log: Mutex::new(Vec::new()),
            latency,
            panic_on: None,
        }
    }

    /// A mock whose `method` panics inside the spawned operation.
    pub(crate) fn panicking(latency: Duration, method: Method) -> Self {
        Self {
            panic_on: Some(method),
            ..Self::new(latency)
        }
    }

    /// How many times `method` has been called.
    pub(crate) fn count(&self, method: Method) -> u64 {
        self.counts[method.index()].load(Ordering::SeqCst)
    }

    /// The calls so far, in call order.
    pub(crate) fn log(&self) -> Vec<MockCall> {
        self.log.lock().expect("mock log").clone()
    }

    fn record(&self, method: Method, call: MockCall) {
        self.counts[method.index()].fetch_add(1, Ordering::SeqCst);
        self.log.lock().expect("mock log").push(call);
    }

    /// Whether this call is the one scripted to panic.
    fn panics(&self, method: Method) -> bool {
        self.panic_on == Some(method)
    }
}

/// An empty sweep outcome — nothing attempted, nothing failed, nothing found.
fn empty_outcome() -> SweepOutcome {
    SweepOutcome::default()
}

impl DmDht for MockDht {
    fn fetch_dm_key_record(&self, owner_seed: [u8; 32]) -> DmDhtFuture<Option<Vec<u8>>> {
        self.record(
            Method::FetchKeyRecord,
            MockCall::FetchKeyRecord { owner_seed },
        );
        let latency = self.latency;
        let boom = self.panics(Method::FetchKeyRecord);
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            Ok(None)
        })
    }

    fn publish_doorbell_entry(
        &self,
        owner_seed: [u8; 32],
        slot: u16,
        entry: Vec<u8>,
        dispatch: DoorbellDispatch,
    ) -> DmDhtFuture<()> {
        self.record(
            Method::PublishDoorbell,
            MockCall::PublishDoorbell {
                owner_seed,
                slot,
                entry_len: entry.len(),
                dispatch,
            },
        );
        let latency = self.latency;
        let boom = self.panics(Method::PublishDoorbell);
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            Ok(())
        })
    }

    fn sweep_doorbell(&self, owner_seed: [u8; 32]) -> DmDhtFuture<DoorbellSweep> {
        self.record(
            Method::SweepDoorbell,
            MockCall::SweepDoorbell { owner_seed },
        );
        let latency = self.latency;
        let boom = self.panics(Method::SweepDoorbell);
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            Ok(DoorbellSweep {
                slots: Vec::new(),
                outcome: empty_outcome(),
            })
        })
    }

    fn publish_dm_page(&self, address: DmPageAddress<Sending>, frame: Vec<u8>) -> DmDhtFuture<()> {
        let at = address.at();
        self.record(
            Method::PublishPage,
            MockCall::PublishPage {
                conversation: *address.conversation(),
                page: at.page(),
                slot: at.slot(),
                direction: address.direction(),
                frame_len: frame.len(),
            },
        );
        let latency = self.latency;
        let boom = self.panics(Method::PublishPage);
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            Ok(())
        })
    }

    fn sweep_dm_page(&self, address: DmPageAddress<Receiving>) -> DmDhtFuture<DmPageSweep> {
        let conversation = *address.conversation();
        self.record(
            Method::SweepPage,
            MockCall::SweepPage {
                conversation,
                page: address.page(),
                direction: address.direction(),
            },
        );
        let latency = self.latency;
        let boom = self.panics(Method::SweepPage);
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            // A struct literal rather than the transport's own tagging
            // constructor, which is private to `actor`. The tag is still the
            // swept address's own conversation, which is the property a caller
            // fanning out over correspondents depends on.
            Ok(DmPageSweep {
                conversation,
                slots: Vec::new(),
                outcome: empty_outcome(),
            })
        })
    }

    fn publish_dm_ack(&self, address: DmAckAddress, record: Vec<u8>) -> DmDhtFuture<()> {
        self.record(
            Method::PublishAck,
            MockCall::PublishAck {
                direction: address.direction(),
                record_len: record.len(),
            },
        );
        let latency = self.latency;
        let boom = self.panics(Method::PublishAck);
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            Ok(())
        })
    }

    fn fetch_dm_ack(&self, address: DmAckAddress) -> DmDhtFuture<Option<Vec<u8>>> {
        self.record(
            Method::FetchAck,
            MockCall::FetchAck {
                direction: address.direction(),
            },
        );
        let latency = self.latency;
        let boom = self.panics(Method::FetchAck);
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            Ok(None)
        })
    }
}
