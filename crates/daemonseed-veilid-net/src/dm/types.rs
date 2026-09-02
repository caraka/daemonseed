//! The command / event vocabulary a front end drives the DM driver with, plus the
//! identity halves and the injected clock the driver holds.
//!
//! Every payload is a `daemonseed-core` type or a `String`, with one exception:
//! [`DmEvent::DoorbellHealth`] carries this crate's own [`SweepOutcome`], because
//! record health is a transport observation and core has no type for it. No
//! front-end type crosses this boundary in either direction.

use std::sync::Arc;

use daemonseed_core::dm::admission::AdmissionCounters;
use daemonseed_core::dm::outbox::{Acceptance, DeliveryState};
use daemonseed_core::dm::pow::ENTRY_HASH_LEN;
use daemonseed_core::dm::provisional::TeardownCause;
use daemonseed_core::identity::keys::{
    DmDoorbellSlotSecret, KemKeypair, SignKeypair, IDENTITY_PK_LEN,
};

use crate::SweepOutcome;

/// A correspondent's long-term identity key — the key both suppression planes and
/// the contact lookup are keyed on. Boxed, because an ML-DSA-87 public key is
/// 2592 bytes.
pub type PkLt = Box<[u8; IDENTITY_PK_LEN]>;

/// A pending contact request: the doorbell slot it arrived in plus the entry hash.
///
/// The hash is not redundant. A slot is overwritable between the sweep that found
/// the entry and the accept that acts on it, so the slot alone names a location
/// rather than an entry; the hash pins the exact entry the user was shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId {
    /// The doorbell slot the entry was swept from.
    pub slot: u16,
    /// The hash of the entry itself.
    pub entry_hash: [u8; ENTRY_HASH_LEN],
}

/// What a front end asks the driver to do.
///
/// Its [`Debug`] prints variant names and body *lengths*: a message body is
/// plaintext and a `PkLt` identifies a correspondent, and a trace line is the
/// last place either should appear.
pub enum DmCommand {
    /// Knock on a stranger's doorbell with a first message.
    FirstContact {
        /// The recipient's long-term identity key.
        recipient: PkLt,
        /// The message body.
        body: String,
    },
    /// Send on an established channel.
    Send {
        /// The correspondent's long-term identity key.
        to: PkLt,
        /// The message body.
        body: String,
    },
    /// Accept a pending request.
    Accept {
        /// The request the user accepted.
        request: RequestId,
    },
    /// Decline a pending request.
    Decline {
        /// The request the user declined.
        request: RequestId,
    },
    /// Block a long-term identity on both suppression planes.
    Block {
        /// The identity to block.
        pk_lt: PkLt,
    },
    /// Unblock a long-term identity on both suppression planes.
    Unblock {
        /// The identity to unblock.
        pk_lt: PkLt,
    },
    /// The UI has shown these delivery states.
    Surfaced {
        /// The correspondent whose outbox the sequence numbers belong to.
        to: PkLt,
        /// The sequence numbers whose state has been shown.
        seqs: Vec<u64>,
    },
    /// Stop the driver.
    ///
    /// In-flight DHT operations are **aborted**, not drained: the driver drops
    /// its join set on the way out. A write already handed to the transport may
    /// therefore land or not, which is the same guarantee every DM write has
    /// anyway — each one is re-seeded until acknowledged.
    Shutdown,
}

/// What the driver tells a front end.
///
/// Given-up delivery is a [`DeliveryState`] on [`DmEvent::Delivery`].
///
/// Its [`Debug`] redacts the same way [`DmCommand`]'s does.
pub enum DmEvent {
    /// A verified knock awaiting accept / decline.
    ContactRequest {
        /// The request to answer.
        request: RequestId,
        /// The knocker's long-term identity key.
        from: PkLt,
        /// The first message body.
        body: String,
        /// When the knocker says it was sent, in unix milliseconds.
        sent_unix_ms: i64,
    },
    /// A collected and opened channel message.
    Message {
        /// The correspondent's long-term identity key.
        from: PkLt,
        /// The message's sequence number.
        seq: u64,
        /// The message body.
        body: String,
        /// When the sender says it was sent, in unix milliseconds.
        sent_unix_ms: i64,
    },
    /// A sent message's delivery state changed.
    Delivery {
        /// The correspondent's long-term identity key.
        to: PkLt,
        /// The message's sequence number.
        seq: u64,
        /// The state now recorded for it.
        state: DeliveryState,
    },
    /// A first contact could not proceed.
    Refused {
        /// The intended recipient's long-term identity key.
        to: PkLt,
        /// How far the first contact got.
        acceptance: Acceptance,
        /// Where it stopped.
        reason: RefusalReason,
    },
    /// An accepted request could not be established.
    ///
    /// The request is **still held**, so the user may answer it again once
    /// whatever failed is fixed. An accept that vanished with only a trace
    /// behind it would leave a request the user answered and a channel that
    /// never existed, with nothing on screen saying which.
    AcceptFailed {
        /// The request that was answered.
        request: RequestId,
        /// The knocker's long-term identity key.
        from: PkLt,
        /// Why establishment did not happen.
        reason: AcceptFailure,
    },
    /// A channel was torn down loudly.
    ChannelLost {
        /// The correspondent's long-term identity key.
        with: PkLt,
        /// Why the channel ended.
        cause: TeardownCause,
        /// The sequence numbers now
        /// [`Lifecycle::Undelivered`](daemonseed_core::dm::outbox::Lifecycle::Undelivered)
        /// and owed to the user.
        ///
        /// Carried rather than dropped: these are messages the user believed
        /// were on their way, and this event is the only place their fate is
        /// stated. Empty when the queue held nothing pending.
        surfaced: Vec<u64>,
    },
    /// A known correspondent knocked again and this side cannot say which
    /// direction its own outbox runs in.
    ///
    /// **Nothing was touched**, deliberately. Deciding state loss ends every
    /// pending message on that correspondence irreversibly, and the call that
    /// does it needs the outbox direction — which lives on the ratchet, which
    /// this session only holds for correspondences it established itself. A
    /// guess would end a healthy queue on a coin toss the user cannot see, so
    /// the queue falls back to the seven-day give-up and the user is told the
    /// question could not be answered.
    ChannelDirectionUnknown {
        /// The correspondent's long-term identity key.
        with: PkLt,
    },
    /// Our own doorbell sweep's record health, and what admission did with it.
    ///
    /// Observability, never "nobody knocked": an empty slot list alone means both
    /// "no knocks" and "every GET errored", and the outcome separates them.
    DoorbellHealth {
        /// The sweep's GET accounting.
        outcome: SweepOutcome,
        /// Admission's own accounting, accumulated across every sweep so far.
        ///
        /// Without it a drop is invisible: every refusal on the doorbell is
        /// silent by design, so `shape_rejects`, `pow_rejects` and the rest are
        /// the only statement that entries arrived and were refused rather
        /// than that nobody knocked.
        admission: AdmissionCounters,
        /// Slots this sweep skipped because the held-request list was full.
        ///
        /// Per sweep, not cumulative, because it is a statement about *now*:
        /// non-zero means somebody is knocking and the user has to answer
        /// something before the driver will look. The knocks are not lost —
        /// a skipped slot is left unverified and unrecorded, so the sender's
        /// next re-seed is read normally — but nothing else would say that
        /// first contact had stopped.
        pending_full: u64,
    },
    /// A contact lookup failed during a sweep, so knocks were dropped.
    ///
    /// Emitted at most once per sweep. The lookup fails closed — an
    /// undecodable contact record or an ambiguous identity reads as "already
    /// known", never as "a stranger" — which means a stranger's knock is
    /// dropped rather than surfaced, for as long as the store stays that way.
    /// Without this the drop is permanent and silent.
    ContactLookupFailed,
    /// The block list is full, and the identity was not blocked.
    ///
    /// The stored list is left exactly as it was — the encode refuses before
    /// the write — so this is a ceiling reached rather than a list damaged. It
    /// is an event rather than a panic because the only remedy is the user's:
    /// nothing here can choose which of 512 blocks to give up.
    BlockListFull {
        /// How many identities the refused list would have held.
        count: usize,
    },
    /// The profile's block-list record was absent at startup and was re-created
    /// empty.
    ///
    /// **Loud, not silent.** The store creates the record at every open, so an
    /// absent one means either that creation was skipped in its documented race
    /// window or the record was removed — and the second reads as silent
    /// unblocking. The user is entitled to know their block list may have been
    /// reset.
    BlockListProvisioned,
    /// A consumed invite-token nonce did not reach the disk.
    ///
    /// The set in memory is correct for this run; the file is not. A grant
    /// spent now is redeemable again after a restart, so this is a suppression
    /// plane that has stopped suppressing and the user has to be told.
    SpentTokensNotPersisted,
}

/// Where a first contact stopped.
///
/// [`Acceptance`] says how far the write got; this says why it went no
/// further. They are different questions and folding them loses the second:
/// an absent key record and a refused doorbell write are both
/// [`Acceptance::Unconfirmed`], and only one of them is worth retrying now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    /// The recipient publishes no key record, or it has been evicted or wiped.
    /// The awaiting-key state: nothing was composed, and retrying later may
    /// well work.
    NoKeyRecord,
    /// A key record was there and did not verify against the recipient's own
    /// identity key.
    KeyRecordInvalid,
    /// The key-record fetch or the doorbell write failed on the transport.
    PublishFailed,
    /// A local record could not be written, so nothing was published.
    StoreFailure,
    /// A correspondence with this identity already exists. First contact is for
    /// strangers; sending to a correspondent is [`DmCommand::Send`].
    AlreadyEstablished,
    /// An introduction to this recipient is already between the command and the
    /// doorbell write. Never a second [`daemonseed_core::dm::firstcontact::build`]
    /// for one introduction: each call encapsulates a fresh `ss0`, which the
    /// recipient reads as the sender having lost their at-rest state.
    AlreadyInFlight,
    /// The proof-of-work mint panicked.
    MintPanicked,
    /// A spawned task carrying this introduction panicked — a DHT operation
    /// rather than the mint. Distinct from [`Self::MintPanicked`] because the
    /// two say different things about what to retry: a mint that panicked will
    /// panic again on the same input, while a transport task that did is worth
    /// one more attempt.
    TaskPanicked,
    /// The entry could not be composed — a body over the cap, or the mint
    /// itself refusing.
    MintFailed,
    /// A derivation or a keygen failed. A condition of this machine's crypto
    /// module, not of the recipient or the network.
    Module,
}

/// Why an accepted request was not established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptFailure {
    /// A correspondence with this identity already exists, so a second one was
    /// refused — see
    /// [`DmPersistError::AlreadyEstablished`](daemonseed_core::dm::persist::DmPersistError::AlreadyEstablished).
    AlreadyEstablished,
    /// The contact record could not be written.
    StoreFailure,
}

/// A correspondent's identity key, as a trace line may show it: the marker only.
/// The key itself is 2592 bytes and names a person.
fn redacted_pk(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str("PkLt(..)")
}

impl core::fmt::Debug for DmCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DmCommand::FirstContact { body, .. } => {
                f.write_str("FirstContact { recipient: ")?;
                redacted_pk(f)?;
                write!(f, ", body_len: {} }}", body.len())
            }
            DmCommand::Send { body, .. } => {
                f.write_str("Send { to: ")?;
                redacted_pk(f)?;
                write!(f, ", body_len: {} }}", body.len())
            }
            DmCommand::Accept { request } => write!(f, "Accept {{ request: {request:?} }}"),
            DmCommand::Decline { request } => write!(f, "Decline {{ request: {request:?} }}"),
            DmCommand::Block { .. } => {
                f.write_str("Block { pk_lt: ")?;
                redacted_pk(f)?;
                f.write_str(" }")
            }
            DmCommand::Unblock { .. } => {
                f.write_str("Unblock { pk_lt: ")?;
                redacted_pk(f)?;
                f.write_str(" }")
            }
            DmCommand::Surfaced { seqs, .. } => {
                f.write_str("Surfaced { to: ")?;
                redacted_pk(f)?;
                write!(f, ", seqs: {seqs:?} }}")
            }
            DmCommand::Shutdown => f.write_str("Shutdown"),
        }
    }
}

impl core::fmt::Debug for DmEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DmEvent::ContactRequest {
                request,
                body,
                sent_unix_ms,
                ..
            } => {
                write!(f, "ContactRequest {{ request: {request:?}, from: ")?;
                redacted_pk(f)?;
                write!(
                    f,
                    ", body_len: {}, sent_unix_ms: {sent_unix_ms} }}",
                    body.len()
                )
            }
            DmEvent::Message {
                seq,
                body,
                sent_unix_ms,
                ..
            } => {
                f.write_str("Message { from: ")?;
                redacted_pk(f)?;
                write!(
                    f,
                    ", seq: {seq}, body_len: {}, sent_unix_ms: {sent_unix_ms} }}",
                    body.len()
                )
            }
            DmEvent::Delivery { seq, state, .. } => {
                f.write_str("Delivery { to: ")?;
                redacted_pk(f)?;
                write!(f, ", seq: {seq}, state: {state:?} }}")
            }
            DmEvent::Refused {
                acceptance, reason, ..
            } => {
                f.write_str("Refused { to: ")?;
                redacted_pk(f)?;
                write!(f, ", acceptance: {acceptance:?}, reason: {reason:?} }}")
            }
            DmEvent::AcceptFailed {
                request, reason, ..
            } => {
                write!(f, "AcceptFailed {{ request: {request:?}, from: ")?;
                redacted_pk(f)?;
                write!(f, ", reason: {reason:?} }}")
            }
            DmEvent::ChannelLost {
                cause, surfaced, ..
            } => {
                f.write_str("ChannelLost { with: ")?;
                redacted_pk(f)?;
                write!(f, ", cause: {cause:?}, surfaced: {surfaced:?} }}")
            }
            DmEvent::ChannelDirectionUnknown { .. } => {
                f.write_str("ChannelDirectionUnknown { with: ")?;
                redacted_pk(f)?;
                f.write_str(" }")
            }
            DmEvent::DoorbellHealth {
                outcome,
                admission,
                pending_full,
            } => {
                write!(
                    f,
                    "DoorbellHealth {{ outcome: {outcome:?}, admission: {admission:?}, \
                     pending_full: {pending_full} }}"
                )
            }
            DmEvent::ContactLookupFailed => f.write_str("ContactLookupFailed"),
            DmEvent::BlockListFull { count } => {
                write!(f, "BlockListFull {{ count: {count} }}")
            }
            DmEvent::BlockListProvisioned => f.write_str("BlockListProvisioned"),
            DmEvent::SpentTokensNotPersisted => f.write_str("SpentTokensNotPersisted"),
        }
    }
}

/// The identity halves the driver needs. The actor task never sees these.
pub struct DmIdentity {
    /// The long-term signing keypair.
    pub signing: Arc<SignKeypair>,
    /// The full KEM keypair — the decapsulation half included, because opening a
    /// knock needs it.
    pub kem: KemKeypair,
    /// The mnemonic-rooted secret selecting this identity's doorbell slot.
    pub doorbell_slot_secret: DmDoorbellSlotSecret,
}

impl core::fmt::Debug for DmIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No key material is printed, not even a projection of it.
        f.debug_struct("DmIdentity").finish_non_exhaustive()
    }
}

/// Unix milliseconds, injected.
///
/// Every core cadence takes the wall value its caller passes in, because those
/// values are persisted and span days: an outbox rung and a seven-day give-up
/// cannot be reached by advancing a monotonic `Instant`. Production reads
/// `SystemTime`; oracles hold a counter they advance alongside
/// `tokio::time::advance`.
#[derive(Clone)]
pub struct WallClock(Arc<dyn Fn() -> i64 + Send + Sync>);

impl WallClock {
    /// The production clock: `SystemTime::now()` since the unix epoch.
    ///
    /// A pre-epoch system clock reads as `0` rather than panicking; a driver is
    /// not the place a misconfigured host is discovered.
    pub fn system() -> Self {
        Self::from_fn(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0)
        })
    }

    /// A clock reading whatever `f` returns.
    pub fn from_fn(f: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// The current time, in unix milliseconds.
    pub fn now_ms(&self) -> i64 {
        (self.0)()
    }
}

impl core::fmt::Debug for WallClock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A fixed marker, not a sample: formatting must not call into the
        // injected closure, which may lock, block, or count.
        f.write_str("WallClock")
    }
}
