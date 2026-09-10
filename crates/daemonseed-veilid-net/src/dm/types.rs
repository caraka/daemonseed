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
use daemonseed_core::trust_events::TrustEventKey;

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
    /// Every correspondence on disk, stated once, before the driver's first
    /// tick.
    ///
    /// **The only statement a front end gets about a correspondence made
    /// before this process started.** Every other event here reports something
    /// that happened while the driver was running, so a correspondence
    /// established last week is invisible until its correspondent writes
    /// something — which may be never. This is the list that makes it visible
    /// anyway.
    ///
    /// One entry per correspondence, and a correspondence appears at most once:
    /// the store holds one label per identity, and [`CorrespondentState`] is
    /// the whole of what separates them. A label carrying no contact record is
    /// not listed — it names a handshake that was never established, and
    /// nothing about it could be shown.
    ///
    /// **A blocked correspondent is reported blocked whatever else its records
    /// hold**, because that is what the channel plane does with it: the block
    /// is read first and the record's own state is not consulted. Where the
    /// block-list record would not read, [`Self::BlockListUnreadable`] is
    /// emitted ahead of this event and every correspondence is stated from its
    /// own records alone — so an empty blocked set is a claim only when that
    /// event is absent. A record that will not read when the driver starts
    /// stops it starting instead, so that pairing belongs to a read that stops
    /// working later.
    Roster {
        /// Each correspondence and the state its records put it in, in the
        /// store's own enumeration order.
        correspondents: Vec<Correspondent>,
    },
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
    /// A message could not be sent — a first contact, or a channel send.
    ///
    /// **One event for both, because a front end does the same thing with
    /// either**: the body did not go, and this says how far it got and why.
    /// [`RefusalReason`] is what distinguishes them, and its variants say which
    /// plane they belong to.
    Refused {
        /// The intended recipient's long-term identity key.
        to: PkLt,
        /// How far the send got.
        acceptance: Acceptance,
        /// Where it stopped.
        reason: RefusalReason,
        /// The classed trust event this refusal is raised as, where the refusal
        /// is a channel the store would not hand back — from
        /// [`Teardown::event`](daemonseed_core::dm::provisional::Teardown::event).
        ///
        /// **Carried here rather than derived by the receiver**, for the reason
        /// [`DmEvent::ChannelLost`]'s field of the same name states: ISC-A-C12
        /// forbids a client skipping the audit entry a teardown owes, and a key
        /// a front end has to go and fetch is a key a front end can forget.
        ///
        /// `None` on a refusal that tears nothing down — a full outbox, a mint
        /// that failed, an identity already established — and a front end folds
        /// exactly what is present. `reason` stays what the user is told in
        /// words; this is what the audit log and the affordance class are keyed
        /// on.
        event: Option<TrustEventKey>,
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
        /// The classed trust event this teardown is raised as, from
        /// [`Teardown::event`](daemonseed_core::dm::provisional::Teardown::event).
        ///
        /// **Carried here rather than derived by the receiver**, and that is the
        /// whole reason the field exists: ISC-A-C12 forbids a client skipping a
        /// teardown's audit entry, and a key a front end has to go and fetch is a
        /// key a front end can forget. Pairing it with the event means a fold
        /// cannot reach the teardown without also being handed what the taxonomy
        /// owes for it — the same argument
        /// [`TrustEventScope`](daemonseed_core::trust_events::TrustEventScope)
        /// records for the record-kind it refuses to be separated from.
        ///
        /// `cause` stays beside it because they answer different questions: this
        /// is what the audit log and the affordance class are keyed on, `cause`
        /// is what the user is told in words.
        ///
        /// **The pairing guards one cause, because only one reaches this
        /// event.** `Teardown::correspondent_state_lost` is the sole teardown
        /// that arrives here, so the field's only value is
        /// [`TrustEventKey::DmCorrespondentStateLost`]. The other three causes —
        /// `NoProvisionalRecord`, `RecordUnusable`, `StoreUnreadable` — arise on
        /// three paths and have three dispositions. The introduce-probe path
        /// carries the cause's key to the client on [`DmEvent::Refused`]'s
        /// `event`. The erase path keeps its cause as a trace. The label lookup
        /// discards it: that lookup asks every stored label whether it opens for
        /// this recipient, so a teardown there is ordinarily another
        /// correspondence's record declining to open, and it cannot separate
        /// that from this recipient's own record being corrupt — it mints a
        /// fresh label and the old record stays on disk. **A cause discarded
        /// there reaches no audit entry**, and that is the accounting gap the
        /// taxonomy still owes. Core pins the cause-to-key mapping for all four.
        event: TrustEventKey,
        /// The sequence numbers now
        /// [`Lifecycle::Undelivered`](daemonseed_core::dm::outbox::Lifecycle::Undelivered)
        /// and owed to the user.
        ///
        /// Carried rather than dropped: these are messages the user believed
        /// were on their way, and this event is the only place their fate is
        /// stated. Empty when the queue held nothing pending.
        surfaced: Vec<u64>,
    },
    /// One of A3.8's loud re-establishment states, named by its classed key.
    ///
    /// **One variant for the family, because the key is the discriminator and
    /// the affordance is the same.** A3.8
    /// (`docs/design/direct-messaging.md:913`) enumerates the loud states a
    /// re-establishment can reach, gives them all one class
    /// (`PersistentNonBlocking`), and asks of every one of them only that the
    /// user be told. Four are reachable here:
    /// [`TrustEventKey::DmPeerStateRegressed`] (the divergence table's row 14 —
    /// a correspondent re-presenting an exchange this side has settled),
    /// [`TrustEventKey::DmReestablishmentFailed`] (a leg reached its give-up
    /// unanswered), [`TrustEventKey::DmReestablishmentUnconfirmed`] (the
    /// retention ceiling fired with no confirming observation) and
    /// [`TrustEventKey::DmReestablishmentBackoffEngaged`] (this side declined to
    /// answer another re-establishment in this session).
    ///
    /// **Not [`Self::ChannelLost`], and the difference is the remedy.** A
    /// teardown says the correspondence cannot carry on and offers a fresh first
    /// contact; every state here is recovering on its own, bounded by a window
    /// or a ladder, with nothing for the user to do but know.
    ReestablishmentAnomaly {
        /// The correspondent's long-term identity key.
        with: PkLt,
        /// The classed trust event, carried beside the news for the reason
        /// [`Self::ChannelLost`]'s own `event` field records: ISC-A-C12 forbids
        /// a client skipping the audit entry, and a key a front end has to fetch
        /// is a key a front end can forget.
        event: TrustEventKey,
    },
    /// A known correspondent knocked again and this side cannot say which
    /// direction its own outbox runs in.
    ///
    /// **Nothing was touched**, deliberately. Deciding state loss ends every
    /// pending message on that correspondence irreversibly, and the call that
    /// does it needs the outbox direction — which lives on the ratchet, and a
    /// correspondence seeded from the store at load has none. A guess would end
    /// a healthy queue on a coin toss, so the queue falls back to the seven-day
    /// give-up. A completed re-establishment opens a chain again, as does the
    /// re-arm of a stored handshake on a correspondence whose own first-contact
    /// entry is unanswered; from either point the question can be answered.
    ///
    /// **Nothing surfaces this.** Both front ends match it in an explicit
    /// do-nothing arm, and it carries no [`TrustEventKey`], so there is no audit
    /// entry — the unanswered question reaches neither a user nor a log.
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
    /// One correspondence's channel-plane accounting, cumulative for this
    /// session.
    ///
    /// **Observability, and every counter here is a state a silent driver would
    /// hide.** A page sweep that folds nothing looks identical whether the page
    /// was empty, unreadable, or full of frames this session cannot open — and
    /// the three demand different answers. Emitted only when a counter moved, so
    /// a healthy conversation is silent.
    ChannelHealth {
        /// The correspondent's long-term identity key.
        with: PkLt,
        /// Sweeps refused because the transport did not read every slot.
        ///
        /// Nothing was folded and nothing advanced: a partial page cannot say a
        /// position is absent, only that it was not seen, and advancing on that
        /// reading skips messages that were there. The page is re-planned on the
        /// next cadence.
        partial_sweeps: u64,
        /// Frames whose ratchet position was already consumed.
        ///
        /// **One path reaches this, and the ordinary re-seed is not it.** A
        /// sender re-seeds until acknowledged, so the same bytes sit in the same
        /// slot and come back on every sweep — but a settled position is filtered
        /// out of
        /// [`PageObservation::unsettled`](daemonseed_core::dm::collect::PageObservation)
        /// before the ratchet is ever offered the frame, so a re-seed of a
        /// collected message is silent and costs nothing.
        ///
        /// What does reach it is a position that was *opened* and could not be
        /// *acknowledged*: `Collection::collected` refuses with
        /// `AckError::TooManyRuns` when the beyond-prefix set is full, leaving
        /// the position unsettled while its message key is spent. The driver
        /// retains such a position and retries it, and the sweep in between
        /// re-offers the frame to a ratchet that has already consumed it. So a
        /// non-zero count here means the acknowledgement's run capacity is under
        /// pressure, not that the network is repeating itself.
        already_consumed: u64,
        /// Frames that did not open or did not verify.
        ///
        /// The slot is left unsettled rather than abandoned: abandonment settles
        /// a position permanently, and a frame this session cannot read is not
        /// proof that no readable frame will ever occupy that slot. Page
        /// owner-write authority is symmetric, so an unopenable frame is an
        /// ordinary input — the correspondent's own writes are what the
        /// authorship signature separates from everybody else's.
        ///
        /// **One count per refusal, not one per probe.** The driver remembers
        /// the positions it has refused and the bytes it refused there, so the
        /// same bytes at the same position are not counted again on the next
        /// probe. That memory is bounded and is dropped whenever this side could
        /// now open what it could not — a frame that opens, a key schedule, a
        /// pseudonym, a correspondent direction or a leg-scan window that moves
        /// — and a dropped entry is a position offered, and counted, again.
        unopenable: u64,
        /// Unsettled positions left alone, once each per sweep that saw them,
        /// because the correspondent's pseudonym key is not known here yet.
        ///
        /// **Per observation, not per distinct frame.** A position refused this
        /// way stays unsettled by design, so the next sweep of that page offers
        /// it again and counts it again: one stuck frame across four sweeps is
        /// four. That is the useful reading — the counter is a rate, and a
        /// rising one says how much traffic is waiting on an acceptance that
        /// has not arrived, where a de-duplicated count would flatten a
        /// conversation stalled for an hour into the same number as one stalled
        /// for a second.
        ///
        /// The acceptor learns the initiator's pseudonym from the knock; the
        /// initiator learns the acceptor's from the acceptance — the acceptor's
        /// channel sequence zero, whose sealed body carries the key and the
        /// long-term binding that vouches for it. An initiator therefore sweeps
        /// from the start, opens that one position, and refuses everything
        /// above it as *pending* until the acceptance lands: the slot is left
        /// unsettled and the next sweep retries it. This counter is what
        /// separates a conversation waiting on its acceptance from an idle one.
        peer_pseudonym_unknown: u64,
        /// Peer acknowledgements — piggybacked or standalone — that would not
        /// merge into this side's retained state.
        ///
        /// One condition reaches it: the union would exceed the ack's run
        /// capacity, which
        /// [`AckState::merge_peer_ack`](daemonseed_core::dm::ack::AckState::merge_peer_ack)
        /// refuses all-or-nothing rather than truncating. Nothing is settled and
        /// nothing is lost — the peer re-writes a monotonic statement, so a later
        /// fold carries everything this one would have — but a rising count says
        /// the conversation is fragmented enough that confirmations are stalling.
        peer_acks_deferred: u64,
        /// Peer acknowledgements claiming a sequence number above what this side
        /// has actually sent, clipped to that ceiling.
        ///
        /// **Nothing legitimate produces one**, so this is a peer-misbehaviour
        /// signal rather than a routine result: a correspondent cannot have
        /// collected what was never transmitted. The claim is clipped rather than
        /// refused, so the truthful part of the statement still settles.
        peer_acks_clipped: u64,
        /// Standalone acknowledgement records that did not decode or did not
        /// verify against the correspondent's pseudonym key.
        ///
        /// The record's address is derived from the conversation's secret
        /// address root, so a third party cannot write one — but the fetch is an
        /// ordinary read of untrusted bytes, and a record that fails here settles
        /// nothing at all. Counted rather than surfaced: the sender's own re-seed
        /// ladder and give-up already carry the user-visible consequence.
        peer_acks_unverified: u64,
        /// Fetches of the correspondent's acknowledgement record the seam
        /// answered with an error: the read errored, the read was cut off at its
        /// bound and abandoned, or the record would not open.
        ///
        /// **Counted here rather than on the doorbell's counters because the
        /// record belongs to this correspondence's acknowledgement plane.** Its
        /// address derives from the conversation's own secret address root and
        /// it is read only for a correspondence holding an unacknowledged
        /// message, so a fetch that fails names exactly one correspondent — the
        /// same one `peer_acks_unverified` and the rest are counted against. The
        /// doorbell's counters describe this identity's own inbound plane, which
        /// no correspondent's acknowledgement record is part of.
        ///
        /// **Each of those is one count, because the seam answers all of them
        /// alike.** A read cut off at its bound is reported as the transport
        /// failure an erroring read produces, and every one of them says the
        /// same thing: the record's state is unknown. `Ok(None)` — the
        /// authoritative empty slot — is a record that answered and is not
        /// counted here, and neither is a fetch whose task panicked, which
        /// reaches the driver as a panic rather than as an answer.
        ///
        /// The fetch is re-planned by every tick that still finds the outbox
        /// unacknowledged, so a correspondent whose record never answers raises
        /// this once a tick for as long as the message stands, and nothing else
        /// states an answer of this kind.
        peer_ack_fetches_failed: u64,
        /// Receive-cursor records found unreadable and replaced.
        ///
        /// A `cursor.bin` that is the wrong width, does not authenticate, or
        /// holds an interrupted erase cannot be read or written past: the read
        /// fails inside the advance's own critical section, so without the repair
        /// the record stays and no session persists that correspondence's
        /// progress again — every advance is refused at the read, permanently.
        /// The from-zero rescan at a cold start is not the tell: a healthy stored
        /// page is uncorroborated at that point too, having nothing this session
        /// has read to be believed against. The repair adopts nothing — the stored number is
        /// discarded unread and this session's own page lands instead, so the
        /// cost is one rescan — but the record was tampered with or corrupted
        /// either way, which is why it is counted rather than only traced.
        cursor_records_repaired: u64,
        /// Re-establishment legs that opened and whose fold could not finish.
        ///
        /// A store fault, a module fault or a counter that would not read, met
        /// part way through a fold. Nothing was committed and the position was
        /// left unsettled, so the correspondent's own re-seed brings the frame
        /// back and the next sweep tries again. A rising count is a store or a
        /// module in trouble, not a peer.
        leg_folds_deferred: u64,
        /// Queued re-establishment legs whose record address would not derive.
        ///
        /// The entry is not emitted and its re-seed ladder is not advanced, so a
        /// derivation that starts working again finds the leg where it was
        /// rather than at the end of a ladder it spent while nothing could be
        /// written. Non-zero means the conversation's address root or the
        /// fingerprint over it would not derive, which is a module fault.
        leg_unaddressable: u64,
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
    /// The profile's block-list record could not be read on an idle tick, so no
    /// correspondent's channel was swept and no acknowledgement was fetched.
    ///
    /// **The channel plane is blind, not quiet, and the two look identical from
    /// outside.** The plane fails closed — an unreadable revocation list must
    /// not read as "nobody is blocked" — so every established conversation
    /// stops collecting until the record can be read, and without this the only
    /// symptom is messages that never arrive. Emitted at most once per idle
    /// tick, and only on a tick whose correspondence list is non-empty — the
    /// gate is that list, not whether any of them holds a live channel, so a
    /// session whose every correspondence is awaiting its acceptance still
    /// reports the blindness.
    BlockListUnreadable,
    /// A consumed invite-token nonce did not reach the disk.
    ///
    /// The set in memory is correct for this run; the file is not. A grant
    /// spent now is redeemable again after a restart, so this is a suppression
    /// plane that has stopped suppressing and the user has to be told.
    SpentTokensNotPersisted,
}

/// One correspondence on [`DmEvent::Roster`], and the state it is in.
///
/// Its [`Debug`] redacts `pk_lt` the way every other identity key on this
/// boundary is redacted: the key is 2592 bytes and names a person.
#[derive(Clone, PartialEq, Eq)]
pub struct Correspondent {
    /// The correspondent's long-term identity key.
    pub pk_lt: PkLt,
    /// The state the stored records and the block list put it in.
    pub state: CorrespondentState,
}

impl core::fmt::Debug for Correspondent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The state names a kind of correspondence, never a correspondent, so
        // it is printable where the identity is not.
        f.write_str("Correspondent { pk_lt: ")?;
        redacted_pk(f)?;
        write!(f, ", state: {:?} }}", self.state)
    }
}

/// What a stored correspondence is, as far as this side is concerned.
///
/// Three states, and every correspondence on disk is in exactly one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrespondentState {
    /// The contact record names the correspondent's pseudonym key, so the
    /// correspondence was established and its channel is the ordinary one.
    ///
    /// It does not follow that a message can be sent right now. A ratchet has
    /// no at-rest record, so a correspondence established before this process
    /// began is refused with [`RefusalReason::NotEstablishedThisSession`] until
    /// re-establishment mints one.
    Established,
    /// The contact record names no pseudonym key: a first contact was sent and
    /// no acceptance has verified.
    ///
    /// Nothing can be sent on it and nothing but the acceptance can be opened.
    Pending,
    /// The correspondent is on the block list, so neither plane carries
    /// anything either way.
    ///
    /// Reported ahead of the two above rather than beside them, because the
    /// block is what decides the outcome: a blocked correspondence's channel is
    /// not swept and its knock is not admitted, whichever of the two its
    /// records would otherwise say.
    Blocked,
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
    /// A key record was there, verified, and named a `version` below the highest
    /// already verified for that identity — the rollback the design's M1 names.
    ///
    /// **Authentic and refused anyway**, which is the whole of the signal: the
    /// record is world-writable, so an old blob the owner really did sign can be
    /// replayed over a newer one. Sealing to it would encapsulate to a key its
    /// owner has rotated away from. Distinct from
    /// [`Self::KeyRecordInvalid`] because it says something different about the
    /// correspondent — not that their record is broken, but that someone is
    /// writing to their address.
    KeyRecordRollback,
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
    /// The correspondence's outbox cannot hold another message (#339).
    ///
    /// **Nothing was spent finding this out**, and that is the point. The
    /// refusal is priced before the ratchet takes its step, so no sequence
    /// number was consumed and no frame was sealed: the user may send the same
    /// message again once the queue has drained. A refusal taken *after* the
    /// mint would burn a position the correspondent's contiguous prefix then
    /// waits on for the seven-day give-up.
    ///
    /// This is expected in ordinary use rather than exceptional — the record is
    /// a fixed size and holds on the order of a hundred *owed* messages against
    /// a seven-day window.
    OutboxFull {
        /// Bytes the record would have needed, against a capacity it names
        /// itself in
        /// [`OutboxError::Full`](daemonseed_core::dm::outbox::OutboxError::Full).
        needed: usize,
    },
    /// There is no live channel with this correspondent in this process.
    ///
    /// Either no correspondence exists at all, or one exists on disk and its key
    /// schedule does not: a ratchet has no at-rest record, and the pseudonym
    /// pair is homed in a resume record that cannot be written until the channel
    /// has re-established once. So a correspondence established before a restart
    /// is on disk, is listed, and cannot be spoken on until re-establishment —
    /// a documented limit, not a transient condition, and the user is told
    /// rather than left with a message that silently never moves.
    NotEstablishedThisSession,
    /// The channel was re-established from this side answering, and the
    /// correspondent has not yet written a frame under the re-rooted chain.
    ///
    /// **A real state of a live channel, and a short one.** The party that asked
    /// for the re-establishment owns the first chain under the new root, so the
    /// party that answered holds a receiving chain and nothing to send on until
    /// that first frame arrives with the ephemeral its own chain steps off.
    /// Everything else is in place — the root is committed, the channel
    /// identifier is known, the correspondent is addressable — so this is
    /// distinct from [`Self::NotEstablishedThisSession`], which says the key
    /// schedule is absent altogether.
    ///
    /// **Nothing was spent**: the refusal is taken at the command, before the
    /// outbox is asked and before the ratchet steps, so the same message may be
    /// sent again once the correspondent has written.
    AwaitingCorrespondentsFirstFrame,
    /// The body is over the channel cap.
    BodyTooLarge,
    /// The frame would not seal. A crypto-module or signing condition on this
    /// machine, and nothing was queued.
    SealFailed,
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
            DmEvent::Roster { correspondents } => {
                // Counts, not rows: a full list would print every
                // correspondent's identity key, and how many are in each state
                // is what a trace line is read for.
                let count = |want: CorrespondentState| {
                    correspondents.iter().filter(|c| c.state == want).count()
                };
                write!(
                    f,
                    "Roster {{ established: {}, pending: {}, blocked: {} }}",
                    count(CorrespondentState::Established),
                    count(CorrespondentState::Pending),
                    count(CorrespondentState::Blocked)
                )
            }
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
                acceptance,
                reason,
                event,
                ..
            } => {
                f.write_str("Refused { to: ")?;
                redacted_pk(f)?;
                // The key names a kind of ending, never a correspondent, so it
                // is printable where the identity above is not (ISC-C28).
                write!(
                    f,
                    ", acceptance: {acceptance:?}, reason: {reason:?}, event: {event:?} }}"
                )
            }
            DmEvent::AcceptFailed {
                request, reason, ..
            } => {
                write!(f, "AcceptFailed {{ request: {request:?}, from: ")?;
                redacted_pk(f)?;
                write!(f, ", reason: {reason:?} }}")
            }
            DmEvent::ChannelLost {
                cause,
                event,
                surfaced,
                ..
            } => {
                f.write_str("ChannelLost { with: ")?;
                redacted_pk(f)?;
                // The key names a kind of ending, never a correspondent, so it
                // is printable where the identity above is not (ISC-C28).
                write!(
                    f,
                    ", cause: {cause:?}, event: {event:?}, surfaced: {surfaced:?} }}"
                )
            }
            DmEvent::ReestablishmentAnomaly { event, .. } => {
                f.write_str("ReestablishmentAnomaly { with: ")?;
                redacted_pk(f)?;
                // The key names a kind of anomaly, never a correspondent, so it
                // is printable where the identity above is not (ISC-C28).
                write!(f, ", event: {event:?} }}")
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
            DmEvent::ChannelHealth {
                partial_sweeps,
                already_consumed,
                unopenable,
                peer_pseudonym_unknown,
                peer_acks_deferred,
                peer_acks_clipped,
                peer_acks_unverified,
                peer_ack_fetches_failed,
                leg_folds_deferred,
                leg_unaddressable,
                ..
            } => {
                f.write_str("ChannelHealth { with: ")?;
                redacted_pk(f)?;
                write!(
                    f,
                    ", partial_sweeps: {partial_sweeps}, already_consumed: {already_consumed}, \
                     unopenable: {unopenable}, peer_pseudonym_unknown: {peer_pseudonym_unknown}, \
                     peer_acks_deferred: {peer_acks_deferred}, \
                     peer_acks_clipped: {peer_acks_clipped}, \
                     peer_acks_unverified: {peer_acks_unverified}, \
                     peer_ack_fetches_failed: {peer_ack_fetches_failed}, \
                     leg_folds_deferred: {leg_folds_deferred}, \
                     leg_unaddressable: {leg_unaddressable} }}"
                )
            }
            DmEvent::ContactLookupFailed => f.write_str("ContactLookupFailed"),
            DmEvent::BlockListFull { count } => {
                write!(f, "BlockListFull {{ count: {count} }}")
            }
            DmEvent::BlockListProvisioned => f.write_str("BlockListProvisioned"),
            DmEvent::BlockListUnreadable => f.write_str("BlockListUnreadable"),
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
