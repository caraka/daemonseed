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
//! `DmPageAddress::with_owner_seed` is the one way to reach it. The two calls
//! that do reach it — the page store's writer and its reader — hash the seed
//! inside the closure and key [`MockNetwork`] on the digest, so the seed never
//! leaves the address and no [`MockCall`] carries one.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use daemonseed_core::dm::ack_record::DmAckAddress;
use daemonseed_core::dm::doorbell::DOORBELL_SLOTS;
use daemonseed_core::dm::paging::{
    DmPageAddress, PagePosition, Receiving, Sending, DM_PAGE_OWNER_SEED_LEN, PAGE_SLOTS,
};
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

/// The records two mocks share, so one driver's write is another's sweep.
///
/// **A record store, not a message bus.** A slot holds whatever was last written
/// to it and holds it indefinitely, which is what a DHT record does and what
/// makes a re-seed testable: the second write of the same bytes to the same slot
/// is not distinguishable from the first, and a sweep after either returns one
/// entry rather than two.
///
/// Pages are keyed by a digest of the record-owner seed both ends derive, which
/// is the only thing that identifies one record to two parties who never
/// exchange an address. The seed is reached through
/// `DmPageAddress::with_owner_seed` and hashed inside that closure, so no plain
/// copy of it outlives the call and nothing puts one in [`MockCall`].
#[derive(Default)]
pub(crate) struct MockNetwork {
    /// Page records, keyed by a digest of the owner seed both ends derive.
    ///
    /// **The digest rather than the seed, because the seed is a zeroizing
    /// secret.** `DmPageAddress::with_owner_seed` hands it out under a closure
    /// precisely so it is not copied into a plain buffer, and a `BTreeMap` key
    /// is exactly such a buffer — it outlives every address, is never wiped,
    /// and is the conversation's write capability. Hashing inside the closure
    /// keeps the copy to a value that opens nothing. See [`page_key`].
    pages: Mutex<BTreeMap<PageKey, Slots>>,
    /// Doorbell records, by the owner seed a sender derives from a public key.
    doorbells: Mutex<BTreeMap<[u8; 32], Slots>>,
    /// Acknowledgement records, keyed by a digest of the owner seed both ends
    /// derive — the same treatment [`MockNetwork::pages`] gets, and for the same
    /// reason: the seed is the conversation's write capability and a map key is
    /// a plain buffer that outlives every address.
    ///
    /// **One record per direction, rewritten in place**, which is what an
    /// acknowledgement is: current state, not a log. A second write of the same
    /// direction replaces the first, so a fetch always sees the latest
    /// statement.
    acks: Mutex<BTreeMap<AckKey, Vec<u8>>>,
}

/// One record's populated subkeys: slot index to whatever was last written to
/// it.
type Slots = BTreeMap<u16, Vec<u8>>;

/// What [`MockNetwork::pages`] is keyed on: a digest of a page owner seed.
type PageKey = u64;

/// What [`MockNetwork::acks`] is keyed on: a digest of an ack owner seed.
type AckKey = u64;

/// Hash one page owner seed into a map key.
///
/// **A non-cryptographic hash is the right tool here and the reason is what it
/// is NOT used for.** Nothing reads this key back as a secret, derives from it,
/// or presents it as evidence — it exists so two addresses over one record land
/// in the same bucket. The property needed is that distinct seeds land in
/// distinct buckets, and `DefaultHasher` is deterministic within a process with
/// fixed keys, so an oracle holding a handful of conversations is nowhere near
/// a collision. The property deliberately NOT claimed is preimage resistance:
/// this is a test double, and a seed that must not be recoverable is one that
/// should not have been copied at all — which is the point of hashing it.
fn page_key(seed: &[u8; DM_PAGE_OWNER_SEED_LEN]) -> PageKey {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut h);
    h.finish()
}

/// Hash one acknowledgement owner seed into a map key, on exactly the terms
/// [`page_key`] states.
fn ack_key(address: &DmAckAddress) -> AckKey {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    address.owner_seed().as_bytes().hash(&mut h);
    h.finish()
}

impl MockNetwork {
    /// A network nobody has written to.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

/// A counting [`DmDht`] with an injected latency.
pub(crate) struct MockDht {
    counts: [AtomicU64; 7],
    log: Mutex<Vec<MockCall>>,
    /// Doorbell sweeps to hand back, oldest first. An exhausted queue yields the
    /// empty sweep, which is the ordinary state of a doorbell nobody knocked on
    /// — so a test that queues one sweep sees exactly one, however many times
    /// the driver's cadence fires.
    doorbell: Mutex<std::collections::VecDeque<DoorbellSweep>>,
    /// What `fetch_dm_key_record` answers. `None` is the awaiting-key state.
    key_record: Mutex<Option<Vec<u8>>>,
    /// Every doorbell entry written, in call order.
    ///
    /// Kept beside the log rather than in it: [`MockCall`] records a
    /// non-secret projection so two calls can be compared, and a whole entry is
    /// neither small nor a projection. A knock's bytes are what a recipient
    /// would actually read, which is what makes an end-to-end oracle possible
    /// at all — the entry this driver published, admitted by the identity it
    /// was addressed to.
    published: Mutex<Vec<(u16, Vec<u8>)>>,
    latency: Duration,
    /// The method whose returned future panics once its latency has elapsed, so
    /// an oracle can drive the shell's join-error path. The call is still counted
    /// and logged: a panic in the seam happens after the request was made.
    panic_on: Option<Method>,
    /// The method whose returned future yields an error once its latency has
    /// elapsed. Distinct from `panic_on`: a transport failure is an ordinary
    /// outcome the driver must handle, a panic is not.
    fail_on: Option<Method>,
    /// Whether a page sweep reports an incomplete read, in the shape the
    /// transport actually produces: fewer subkeys attempted than the record
    /// holds, and nothing failed.
    partial_sweeps: bool,
    /// Whether a served page frame has one byte flipped, so it parses and does
    /// not authenticate.
    tamper_pages: bool,
    /// Populated slots handed back by page sweeps, cumulative.
    ///
    /// The call counter cannot stand in for this: a sweep that returned nothing
    /// and a sweep that returned a frame are the same call, and an oracle
    /// asserting a driver folded nothing needs to know the bytes were actually
    /// offered to it.
    slots_served: AtomicU64,
    /// Every page frame written, in call order, as `(position, bytes)`.
    ///
    /// Beside `net.pages` rather than read from it: the record holds only the
    /// last write of a slot, and a re-seed's whole property is that the SECOND
    /// write carries the same bytes as the first.
    published_pages: Mutex<Vec<(PagePosition, Vec<u8>)>>,
    /// The records this mock reads and writes. Shared with any other mock built
    /// on the same [`MockNetwork`], which is what makes a two-driver oracle
    /// possible; private to this mock otherwise.
    net: Arc<MockNetwork>,
}

impl MockDht {
    /// A mock whose every call takes `latency` of virtual time.
    pub(crate) fn new(latency: Duration) -> Self {
        Self::on(MockNetwork::new(), latency)
    }

    /// A mock reading and writing `net`, so two drivers can see each other's
    /// writes.
    pub(crate) fn on(net: Arc<MockNetwork>, latency: Duration) -> Self {
        Self {
            counts: Default::default(),
            log: Mutex::new(Vec::new()),
            doorbell: Mutex::new(std::collections::VecDeque::new()),
            key_record: Mutex::new(None),
            published: Mutex::new(Vec::new()),
            latency,
            panic_on: None,
            fail_on: None,
            partial_sweeps: false,
            tamper_pages: false,
            slots_served: AtomicU64::new(0),
            published_pages: Mutex::new(Vec::new()),
            net,
        }
    }

    /// A mock whose `method` returns a transport error.
    pub(crate) fn failing(latency: Duration, method: Method) -> Self {
        Self {
            fail_on: Some(method),
            ..Self::new(latency)
        }
    }

    /// A mock on `net` whose page sweeps report that they did not read the whole
    /// record.
    ///
    /// The populated slots it did reach still come back, which is the case worth
    /// testing: a sweep that returned nothing would fold nothing whether or not
    /// the driver honoured the outcome.
    pub(crate) fn partial_on(net: Arc<MockNetwork>, latency: Duration) -> Self {
        Self {
            partial_sweeps: true,
            ..Self::on(net, latency)
        }
    }

    /// A mock on `net` whose `method` returns a transport error.
    pub(crate) fn failing_on(net: Arc<MockNetwork>, latency: Duration, method: Method) -> Self {
        Self {
            fail_on: Some(method),
            ..Self::on(net, latency)
        }
    }

    /// A mock on `net` that flips one byte of every page frame it serves.
    ///
    /// The frame still parses — the corruption is inside the sealed envelope —
    /// so it reaches the ratchet and fails to authenticate, which is the case
    /// worth testing: page owner-write authority is symmetric, so anyone can
    /// write a slot and the authorship signature is the only thing separating
    /// the correspondent's writes from everybody else's.
    pub(crate) fn tampering_on(net: Arc<MockNetwork>, latency: Duration) -> Self {
        Self {
            tamper_pages: true,
            ..Self::on(net, latency)
        }
    }

    /// Populated slots handed back by page sweeps so far.
    pub(crate) fn slots_served(&self) -> u64 {
        self.slots_served.load(Ordering::SeqCst)
    }

    /// Every page frame written, in call order.
    pub(crate) fn published_pages(&self) -> Vec<(PagePosition, Vec<u8>)> {
        self.published_pages
            .lock()
            .expect("mock published pages")
            .clone()
    }

    /// The doorbell entries written so far, in call order.
    pub(crate) fn published(&self) -> Vec<(u16, Vec<u8>)> {
        self.published.lock().expect("mock published").clone()
    }

    /// Queue one doorbell sweep for the driver to find.
    pub(crate) fn queue_doorbell(&self, slots: Vec<(u16, Vec<u8>)>) {
        let found = u32::try_from(slots.len()).unwrap_or(u32::MAX);
        self.doorbell
            .lock()
            .expect("mock doorbell")
            .push_back(DoorbellSweep {
                slots,
                outcome: SweepOutcome {
                    attempted: u32::from(DOORBELL_SLOTS),
                    failed: 0,
                    found,
                },
            });
    }

    /// Set what a key-record fetch answers.
    pub(crate) fn set_key_record(&self, bytes: Option<Vec<u8>>) {
        *self.key_record.lock().expect("mock key record") = bytes;
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

    /// Whether this call is the one scripted to fail.
    fn fails(&self, method: Method) -> bool {
        self.fail_on == Some(method)
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
        let dud = self.fails(Method::FetchKeyRecord);
        let record = self.key_record.lock().expect("mock key record").clone();
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            if dud {
                return Err(crate::VeilidNetError::Actor("scripted seam failure".into()));
            }
            Ok(record)
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
        self.published
            .lock()
            .expect("mock published")
            .push((slot, entry.clone()));
        let latency = self.latency;
        let boom = self.panics(Method::PublishDoorbell);
        let dud = self.fails(Method::PublishDoorbell);
        if !dud && !boom {
            self.net
                .doorbells
                .lock()
                .expect("mock doorbells")
                .entry(owner_seed)
                .or_default()
                .insert(slot, entry.clone());
        }
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            if dud {
                return Err(crate::VeilidNetError::Actor("scripted seam failure".into()));
            }
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
        let dud = self.fails(Method::SweepDoorbell);
        // A scripted sweep first, then the shared record. The queue is how a
        // single-driver oracle hands the machine one exact entry; the record is
        // how a second driver's knock arrives on its own.
        let queued = self.doorbell.lock().expect("mock doorbell").pop_front();
        let queued = queued.or_else(|| {
            let held = self
                .net
                .doorbells
                .lock()
                .expect("mock doorbells")
                .get(&owner_seed)
                .cloned()
                .unwrap_or_default();
            (!held.is_empty()).then(|| {
                let slots: Vec<(u16, Vec<u8>)> = held.into_iter().collect();
                let found = u32::try_from(slots.len()).unwrap_or(u32::MAX);
                DoorbellSweep {
                    slots,
                    outcome: SweepOutcome {
                        attempted: u32::from(DOORBELL_SLOTS),
                        failed: 0,
                        found,
                    },
                }
            })
        });
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            if dud {
                return Err(crate::VeilidNetError::Actor("scripted seam failure".into()));
            }
            Ok(queued.unwrap_or(DoorbellSweep {
                slots: Vec::new(),
                outcome: empty_outcome(),
            }))
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
        let dud = self.fails(Method::PublishPage);
        // Written at call time, like the counters, and before the scripted
        // failure below: a `fail_on` publish is a write the transport reported
        // as failed, which is exactly the case where the bytes may still have
        // landed. That is the guarantee every DM write has, so the mock offers
        // the same one.
        // Logged whatever the transport is scripted to do with it: the bytes
        // were handed over, and the re-seed property this log exists to pin is
        // about what the driver emitted, not about what landed.
        self.published_pages
            .lock()
            .expect("mock published pages")
            .push((at, frame.clone()));
        if !dud && !boom {
            address.with_owner_seed(|seed| {
                self.net
                    .pages
                    .lock()
                    .expect("mock pages")
                    .entry(page_key(seed))
                    .or_default()
                    .insert(at.slot(), frame.clone());
            });
        }
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            if dud {
                return Err(crate::VeilidNetError::Actor("scripted seam failure".into()));
            }
            Ok(())
        })
    }

    fn sweep_dm_page(&self, address: DmPageAddress<Receiving>) -> DmDhtFuture<DmPageSweep> {
        let conversation = *address.conversation();
        let page = address.page();
        self.record(
            Method::SweepPage,
            MockCall::SweepPage {
                conversation,
                page,
                direction: address.direction(),
            },
        );
        let latency = self.latency;
        let boom = self.panics(Method::SweepPage);
        let dud = self.fails(Method::SweepPage);
        let held = address.with_owner_seed(|seed| {
            self.net
                .pages
                .lock()
                .expect("mock pages")
                .get(&page_key(seed))
                .cloned()
                .unwrap_or_default()
        });
        let absent = held.is_empty();
        let tamper = self.tamper_pages;
        let slots: Vec<(PagePosition, Vec<u8>)> = held
            .into_iter()
            .filter_map(|(slot, mut bytes)| {
                if tamper {
                    if let Some(last) = bytes.last_mut() {
                        *last ^= 0xFF;
                    }
                }
                PagePosition::new(page, slot).map(|at| (at, bytes))
            })
            .collect();
        self.slots_served
            .fetch_add(slots.len() as u64, Ordering::SeqCst);
        let found = u32::try_from(slots.len()).unwrap_or(u32::MAX);
        // The three shapes the transport actually produces, and they are not
        // interchangeable. An ABSENT record is `attempted: 0` — nothing was
        // opened, so nothing was read, and there is nothing there to have
        // missed. A COMPLETE read attempted every subkey the record holds. A
        // PARTIAL one stopped part way with `failed` still zero, which is why a
        // rule reading `failed` alone cannot tell it from a complete read of an
        // emptier page.
        let outcome = if absent {
            SweepOutcome {
                attempted: 0,
                failed: 0,
                found: 0,
            }
        } else if self.partial_sweeps {
            SweepOutcome {
                attempted: u32::from(PAGE_SLOTS) - 1,
                failed: 0,
                found,
            }
        } else {
            SweepOutcome {
                attempted: u32::from(PAGE_SLOTS),
                failed: 0,
                found,
            }
        };
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            if dud {
                return Err(crate::VeilidNetError::Actor("scripted seam failure".into()));
            }
            // A struct literal rather than the transport's own tagging
            // constructor, which is private to `actor`. The tag is still the
            // swept address's own conversation, which is the property a caller
            // fanning out over correspondents depends on.
            Ok(DmPageSweep {
                conversation,
                slots,
                outcome,
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
        let dud = self.fails(Method::PublishAck);
        if !dud && !boom {
            self.net
                .acks
                .lock()
                .expect("mock acks")
                .insert(ack_key(&address), record);
        }
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            if dud {
                return Err(crate::VeilidNetError::Actor("scripted seam failure".into()));
            }
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
        let dud = self.fails(Method::FetchAck);
        let held = self
            .net
            .acks
            .lock()
            .expect("mock acks")
            .get(&ack_key(&address))
            .cloned();
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            assert!(!boom, "scripted seam panic");
            if dud {
                return Err(crate::VeilidNetError::Actor("scripted seam failure".into()));
            }
            Ok(held)
        })
    }
}
