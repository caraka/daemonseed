//! First contact and the ordinary message and cursor paths, driving
//! [`advert`], [`drop_plane`], [`channel`], [`chain`] and [`Store`] over a
//! record store.
//!
//! Serves FC4.
//!
//! `docs/design/direct-messaging.md` § Flows gives the step order, § Records
//! the four record shapes, § Write budget the ceilings and § Abuse the rule
//! for a hello from a blocked identity.
//!
//! [`Records`] is the whole of this module's contact with the network: seven
//! methods over the three distributed-hash-table record kinds the flow
//! touches. Nothing here opens a socket, reads a clock or draws entropy of its
//! own — the current time is a parameter and entropy arrives as a fill
//! function — so the flow runs identically against a transport and against a
//! counting fake.
//!
//! An advert and a drop are addressed by the owner seed derived from the
//! identity that owns them, which is public information every party can
//! compute; a channel is addressed by the lookup key its hello discloses. A
//! record's subkey count is part of its identity, so every method that
//! addresses a record by owner seed takes that count rather than assuming one.
//!
//! Two hello shared secrets live in the conversation record. The one this
//! side's own hello established seals this side's control subkey; the one the
//! correspondent's hello established opens the correspondent's. **Neither ever
//! touches a message body** — bodies are sealed under message keys the ratchet
//! derives and deletes. Both are persisted because a control record is
//! rewritten for the lifetime of the conversation and neither secret can be
//! re-derived from anything else the record holds.

use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;

use crate::dm::advert::{self, AdvertError, AdvertKeys, AdvertOwnerSeed, AdvertSharedSecret};
use crate::dm::chain::{self, ChainError, Conversation};
use crate::dm::channel::{
    self, ChannelError, ChannelOpening, ChannelOwnerSeed, Control, OPENING_LEN, Ring,
};
use crate::dm::drop as drop_plane;
use crate::dm::drop::{
    DropError, DropOwnerSeed, HELLO_LEN, HELLO_LOOKUP_KEY_LEN, HelloAttempt, ReadBack,
};
use crate::dm::store::{ConvState, OutstandingHello, Store, StoreError};
use crate::identity::keys::{ML_DSA_SEED_LEN, SignKeypair};
use crate::storage::dm_store::CorrespondenceLabel;

/// The conversation generation a first contact opens at.
///
/// A generation is turned over by the delete flow, which treats a later hello
/// from the same correspondent as a new first contact under the next one.
pub const FIRST_GENERATION: u64 = 0;

/// How many times a hello re-picks its slot after a clobbered read-back.
///
/// One, which is the fourth write of § Write budget's four. A second clobber
/// is a drop an attacker is keeping full (§ Abuse); the hello stays persisted
/// and the poller retries rather than the flow writing without bound.
pub const MAX_REPICKS: u32 = 1;

/// A transport's own failure, carried through the flow without the flow
/// naming any transport's error type.
#[derive(Debug)]
pub struct RecordError(Box<dyn core::error::Error + Send + Sync + 'static>);

impl RecordError {
    /// Wrap a transport error.
    pub fn new(source: impl Into<Box<dyn core::error::Error + Send + Sync + 'static>>) -> Self {
        Self(source.into())
    }

    /// The wrapped error.
    pub fn inner(&self) -> &(dyn core::error::Error + Send + Sync + 'static) {
        self.0.as_ref()
    }
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "record store: {}", self.0)
    }
}

impl core::error::Error for RecordError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// The reads and writes the flow performs against the record store.
///
/// A method that writes performs exactly one write, so a caller counting calls
/// counts the write budget of § Write budget. `subkeys` is the record's subkey
/// count, which is part of the record's identity and so of the address: a
/// transport must be told it rather than guess it.
pub trait Records {
    /// Subkey 0 of the advert the seed owns, or `None` where the record holds
    /// nothing there.
    fn read_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
    ) -> Result<Option<Vec<u8>>, RecordError>;

    /// One slot of the drop the seed owns.
    fn read_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
    ) -> Result<Option<Vec<u8>>, RecordError>;

    /// Write one slot of the drop the seed owns. One write.
    fn write_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError>;

    /// Erase one slot of the drop the seed owns. One write.
    fn erase_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
    ) -> Result<(), RecordError>;

    /// The lookup key of the channel record the seed owns, opening or creating
    /// the record as the transport requires. No value is written.
    fn open_channel(
        &mut self,
        owner: &ChannelOwnerSeed,
        subkeys: u16,
    ) -> Result<[u8; HELLO_LOOKUP_KEY_LEN], RecordError>;

    /// One subkey of the channel at `lookup_key`: the control subkey at
    /// [`channel::CONTROL_SUBKEY`], a message otherwise.
    fn read_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
    ) -> Result<Option<Vec<u8>>, RecordError>;

    /// Write one subkey of the channel at `lookup_key`. One write.
    fn write_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError>;
}

/// Why a flow stopped.
#[derive(Debug)]
pub enum FlowError {
    /// An advert would not build, verify or encapsulate.
    Advert(AdvertError),
    /// A hello would not seal, open or place.
    Drop(DropError),
    /// A channel record would not seal, open or verify.
    Channel(ChannelError),
    /// A key-schedule step failed.
    Chain(ChainError),
    /// The on-disk state refused.
    Store(StoreError),
    /// The record store refused.
    Records(RecordError),
    /// The correspondent's advert record holds nothing at subkey 0.
    NoAdvert,
    /// The channel a hello named holds no opening in its control subkey.
    NoOpening,
    /// The correspondence holds no outstanding hello, so there is nothing an
    /// acceptance can complete.
    NotOutstanding,
    /// A conversation with this correspondent is already established. Starting
    /// over is the delete flow's business, not first contact's.
    AlreadyEstablished,
    /// This side's own first contact has not been accepted, so there is no
    /// established conversation to send an ordinary message on.
    AwaitingAcceptance,
    /// Every slot this hello picked was taken. The hello stays persisted and
    /// the poller retries.
    DropFull,
    /// The correspondence holds none of the state a resumed or rewritten
    /// record needs.
    Incomplete(&'static str),
    /// A hello was sealed to a length other than [`HELLO_LEN`].
    HelloLength(usize),
}

impl core::fmt::Display for FlowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Advert(e) => write!(f, "advert: {e}"),
            Self::Drop(e) => write!(f, "drop: {e}"),
            Self::Channel(e) => write!(f, "channel: {e}"),
            Self::Chain(e) => write!(f, "key schedule: {e}"),
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Records(e) => write!(f, "{e}"),
            Self::NoAdvert => f.write_str("the correspondent publishes no advert"),
            Self::NoOpening => f.write_str("the channel holds no opening"),
            Self::NotOutstanding => f.write_str("no outstanding hello for this correspondent"),
            Self::AlreadyEstablished => {
                f.write_str("a conversation with this correspondent is established")
            }
            Self::AwaitingAcceptance => {
                f.write_str("this side's first contact has not been accepted")
            }
            Self::DropFull => f.write_str("every slot the hello picked was taken"),
            Self::Incomplete(what) => write!(f, "the conversation record holds no {what}"),
            Self::HelloLength(n) => write!(f, "a hello sealed to {n} bytes"),
        }
    }
}

impl core::error::Error for FlowError {}

impl From<AdvertError> for FlowError {
    fn from(e: AdvertError) -> Self {
        Self::Advert(e)
    }
}

impl From<DropError> for FlowError {
    fn from(e: DropError) -> Self {
        Self::Drop(e)
    }
}

impl From<ChannelError> for FlowError {
    fn from(e: ChannelError) -> Self {
        Self::Channel(e)
    }
}

impl From<ChainError> for FlowError {
    fn from(e: ChainError) -> Self {
        Self::Chain(e)
    }
}

impl From<StoreError> for FlowError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<RecordError> for FlowError {
    fn from(e: RecordError) -> Self {
        Self::Records(e)
    }
}

/// This side's identity, as the two halves the flow needs of it.
///
/// The seed derives channel owner keypairs and the keypair signs adverts and
/// openings. Both are borrowed: neither is copied into this type.
pub struct Me<'a> {
    /// The identity signing keypair.
    pub signer: &'a SignKeypair,
    /// The ML-DSA seed the identity was derived from.
    pub identity_seed: &'a [u8; ML_DSA_SEED_LEN],
}

impl core::fmt::Debug for Me<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Me(<redacted>)")
    }
}

/// What a call to [`first_contact`] settled.
#[derive(Debug, PartialEq, Eq)]
pub enum FirstContact {
    /// A fresh first contact, or a previous run's carried to completion.
    Opened {
        /// The correspondence the conversation record lives under.
        peer: CorrespondenceLabel,
        /// The lookup key of the channel this side writes.
        outgoing_lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
        /// The drop slot the hello landed in.
        hello_slot: u16,
        /// How many times the hello re-picked its slot.
        repicks: u32,
    },
    /// A previous run's hello was still outstanding and has been rewritten
    /// unchanged.
    Rewrote {
        /// The correspondence the conversation record lives under.
        peer: CorrespondenceLabel,
        /// The slot the hello was rewritten into.
        hello_slot: u16,
    },
}

/// Open a conversation with a correspondent who is offline — steps 1 to 5 of
/// § Flows, *First contact*.
///
/// One conversation per correspondent identity: a correspondent this side has
/// already reached is resumed rather than opened again, because both channels'
/// owner seeds are derived from the two identities and a generation, so a
/// second correspondence would write the same records under a second label. A
/// correspondent whose conversation is established is
/// [`FlowError::AlreadyEstablished`]; starting over is the delete flow's.
///
/// Every persist precedes the write it enables: the conversation record is
/// created before any write to the record store, the outbox entry before the
/// channel writes, and the outstanding hello before the drop write. A run that
/// stops between any two of them resumes here, from the state on disk.
///
/// At most four writes: the channel opening, the first message slot, the hello
/// and one re-pick of the hello.
pub fn first_contact<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    peer_identity_pk: &[u8; ml_dsa::PK_LEN],
    body: &[u8],
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    now: u64,
) -> Result<FirstContact, FlowError> {
    if let Some(peer) = correspondence_for(store, peer_identity_pk)? {
        let state = load(store, &peer)?;
        if !state.awaiting_acceptance {
            return Err(FlowError::AlreadyEstablished);
        }
        if state.outstanding_hello.is_some() {
            let slot = match resume_first_contact(store, records, &peer)? {
                Resumed::Rewrote(slot) => slot,
                Resumed::Nothing => return Err(FlowError::NotOutstanding),
            };
            return Ok(FirstContact::Rewrote {
                peer,
                hello_slot: slot,
            });
        }
        return finish_first_contact(store, records, peer, state, body, &mut fill);
    }

    // 1. The advert, verified under the identity the caller named.
    let advert_owner = advert::derive_owner_seed(peer_identity_pk)?;
    let bytes = records
        .read_advert(&advert_owner, advert::ADVERT_SUBKEYS)?
        .ok_or(FlowError::NoAdvert)?;
    let advert = advert::verify(peer_identity_pk, &bytes)?;

    // 2. The key schedule and the conversation record, before any write to the
    //    record store. The channel's lookup key is not known yet, because
    //    naming the record to the transport may create it.
    let encapsulation = advert::encapsulate_to(&advert, now, &mut fill)?;
    let opened = chain::initiate(&encapsulation.shared_secret, &mut fill)?;
    let opening = ChannelOpening::build(
        me.signer,
        peer_identity_pk,
        &opened.ratchet_pk,
        encapsulation.serial,
    )?;
    let opening_bytes: Box<[u8; OPENING_LEN]> = opening
        .encode()
        .as_slice()
        .try_into()
        .map(Box::new)
        .expect("an opening encodes to OPENING_LEN bytes");
    let peer = CorrespondenceLabel::mint().map_err(|e| FlowError::Store(StoreError::Store(e)))?;
    store.create_conv(
        &peer,
        &ConvState {
            peer_identity_pk: Box::new(*peer_identity_pk),
            outgoing_lookup_key: [0u8; HELLO_LOOKUP_KEY_LEN],
            incoming_lookup_key: [0u8; HELLO_LOOKUP_KEY_LEN],
            generation: FIRST_GENERATION,
            conversation: opened.conversation.snapshot(),
            send_seq: 0,
            peer_collected: 0,
            my_collected: 0,
            cursor_published: 0,
            awaiting_acceptance: true,
            outstanding_hello: None,
            own_hello_secret: Some(encapsulation.shared_secret),
            own_hello_kem_ct: Some(encapsulation.ciphertext),
            peer_hello_secret: None,
            peer_advert_serial: None,
            own_opening: Some(opening_bytes),
        },
    )?;

    let channel_owner =
        channel::derive_owner_seed(me.identity_seed, peer_identity_pk, FIRST_GENERATION)?;
    let outgoing_lookup_key = records.open_channel(&channel_owner, channel::CHANNEL_SUBKEYS)?;
    store.update_conv(&peer, |state| {
        state.outgoing_lookup_key = outgoing_lookup_key;
    })?;

    let state = load(store, &peer)?;
    finish_first_contact(store, records, peer, state, body, &mut fill)
}

/// Steps 3 to 5 over a conversation record that already exists: seal and
/// commit message 0 where it is not committed yet, write the opening and the
/// slot, then place the hello.
fn finish_first_contact<R: Records>(
    store: &Store,
    records: &mut R,
    peer: CorrespondenceLabel,
    state: ConvState,
    body: &[u8],
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<FirstContact, FlowError> {
    let outgoing_lookup_key = state.outgoing_lookup_key;
    let peer_identity_pk = state.peer_identity_pk.clone();
    let own_secret = state
        .own_hello_secret
        .as_ref()
        .ok_or(FlowError::Incomplete("hello secret of its own"))?;
    let opening_bytes = state
        .own_opening
        .as_ref()
        .ok_or(FlowError::Incomplete("channel opening of its own"))?;
    let own_kem_ct = state
        .own_hello_kem_ct
        .as_ref()
        .ok_or(FlowError::Incomplete("hello encapsulation of its own"))?;
    let opening = ChannelOpening::decode(opening_bytes.as_slice())?;
    let advert_serial = opening.advert_serial;

    // 3. The first message. A run that died before its conversation record
    //    committed left no sequence 0 to rewrite, so it is sealed here from the
    //    persisted key schedule; one that got past it rewrites the bytes on
    //    disk.
    let slot_bytes = match outstanding_zero(store, &peer)? {
        Some(bytes) => bytes,
        None => {
            let mut conversation = Conversation::restore(state.conversation);
            let mut ring = Ring::new();
            let seq = ring.reserve()?;
            let (header, sealed) =
                conversation.seal(body, channel::DEVICE_ID_SINGLE_DEVICE, &mut *fill)?;
            let mut bytes = header.encode();
            bytes.extend_from_slice(&sealed);
            store.persist_outbox(&peer, seq, &bytes)?;
            store.update_conv(&peer, |state| {
                state.conversation = conversation.snapshot();
                state.send_seq = ring.send_seq();
            })?;
            bytes
        }
    };
    let control = channel::seal_control(
        own_secret,
        &Control {
            opening: Some(opening),
            collected_cursor: 0,
            closed: false,
        },
    )?;
    records.write_channel(&outgoing_lookup_key, channel::CONTROL_SUBKEY, &control)?;
    records.write_channel(&outgoing_lookup_key, channel::slot_for(0), &slot_bytes)?;

    // 4. The hello.
    let attempt = place_hello(
        store,
        records,
        &peer,
        &peer_identity_pk,
        &outgoing_lookup_key,
        own_secret,
        own_kem_ct,
        advert_serial,
        fill,
    )?;
    Ok(FirstContact::Opened {
        peer,
        outgoing_lookup_key,
        hello_slot: attempt.slot(),
        repicks: attempt.repicks(),
    })
}

/// Seal a hello, persist it whole, write it and read it back once, re-picking
/// at most [`MAX_REPICKS`] times.
///
/// The hello is persisted before every write, so a stop at any point leaves
/// the bytes the drop slot must hold on disk. A second clobber is
/// [`FlowError::DropFull`] with the hello still persisted: the poller rewrites
/// it, rather than this call contending with an attacker for slots.
#[allow(clippy::too_many_arguments)]
fn place_hello<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
    peer_identity_pk: &[u8; ml_dsa::PK_LEN],
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    shared_secret: &AdvertSharedSecret,
    kem_ct: &[u8; ml_kem::CT_LEN],
    advert_serial: u64,
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<HelloAttempt, FlowError> {
    let drop_owner = drop_plane::derive_owner_seed(peer_identity_pk)?;
    let mut attempt = HelloAttempt::new(drop_plane::repick(&mut *fill)?)?;
    loop {
        let hello = seal_outstanding(
            shared_secret,
            kem_ct,
            advert_serial,
            lookup_key,
            peer_identity_pk,
            &attempt,
        )?;
        let written = *hello.sealed;
        store.update_conv(peer, |state| {
            state.outstanding_hello = Some(hello);
        })?;
        records.write_drop_slot(
            &drop_owner,
            drop_plane::DROP_SUBKEYS,
            attempt.slot(),
            &written,
        )?;
        let found =
            records.read_drop_slot(&drop_owner, drop_plane::DROP_SUBKEYS, attempt.slot())?;
        if attempt.read_back(&written, found.as_deref(), &mut *fill)? == ReadBack::Landed {
            return Ok(attempt);
        }
        if attempt.repicks() > MAX_REPICKS {
            return Err(FlowError::DropFull);
        }
    }
}

/// The hello for one attempt, as the record the conversation persists.
fn seal_outstanding(
    shared_secret: &AdvertSharedSecret,
    kem_ct: &[u8; ml_kem::CT_LEN],
    advert_serial: u64,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    peer_identity_pk: &[u8; ml_dsa::PK_LEN],
    attempt: &HelloAttempt,
) -> Result<OutstandingHello, FlowError> {
    let encapsulation = advert::HelloEncapsulation {
        serial: advert_serial,
        shared_secret: AdvertSharedSecret::from_bytes(shared_secret.as_bytes()),
        ciphertext: Box::new(*kem_ct),
    };
    let sealed = drop_plane::seal_hello(&encapsulation, lookup_key, attempt.r(), peer_identity_pk)?;
    let sealed: [u8; HELLO_LEN] = sealed
        .as_slice()
        .try_into()
        .map_err(|_| FlowError::HelloLength(sealed.len()))?;
    Ok(OutstandingHello {
        slot: attempt.slot(),
        r: *attempt.r(),
        kem_ct: encapsulation.ciphertext,
        sealed: Box::new(sealed),
        advert_serial,
    })
}

/// The correspondence holding a conversation with this identity, if any.
fn correspondence_for(
    store: &Store,
    peer_identity_pk: &[u8; ml_dsa::PK_LEN],
) -> Result<Option<CorrespondenceLabel>, FlowError> {
    Ok(store
        .load()?
        .convs
        .into_iter()
        .find(|c| c.state.peer_identity_pk.as_slice() == peer_identity_pk.as_slice())
        .map(|c| c.peer))
}

/// One correspondence's state, or [`StoreError::MissingConversation`].
fn load(store: &Store, peer: &CorrespondenceLabel) -> Result<ConvState, FlowError> {
    store
        .load_conv(peer)?
        .ok_or(FlowError::Store(StoreError::MissingConversation))
}

/// The bytes sequence 0 owes, where a previous run committed them.
fn outstanding_zero(
    store: &Store,
    peer: &CorrespondenceLabel,
) -> Result<Option<Vec<u8>>, FlowError> {
    Ok(store
        .load()?
        .convs
        .into_iter()
        .find(|c| &c.peer == peer)
        .and_then(|c| {
            c.outstanding_outbox
                .into_iter()
                .find(|e| e.seq == 0)
                .map(|e| e.ciphertext)
        }))
}

/// What a relaunch found to do for one correspondence.
#[derive(Debug, PartialEq, Eq)]
pub enum Resumed {
    /// The correspondence holds no outstanding hello.
    Nothing,
    /// The persisted hello was rewritten, byte for byte, into this slot.
    Rewrote(u16),
}

/// Rewrite an outstanding hello from the state a previous run left on disk.
///
/// The bytes written are the persisted `sealed` bytes, so a relaunch at any
/// step boundary after the hello was persisted rewrites the same hello rather
/// than minting a second one: the encapsulation is fixed, and `kem_ct` is
/// unchanged across every rewrite. This is also the poller's rewrite of a slot
/// the network has evicted.
pub fn resume_first_contact<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
) -> Result<Resumed, FlowError> {
    let state = load(store, peer)?;
    let Some(hello) = state.outstanding_hello else {
        return Ok(Resumed::Nothing);
    };
    let drop_owner = drop_plane::derive_owner_seed(&state.peer_identity_pk)?;
    records.write_drop_slot(
        &drop_owner,
        drop_plane::DROP_SUBKEYS,
        hello.slot,
        hello.sealed.as_slice(),
    )?;
    Ok(Resumed::Rewrote(hello.slot))
}

/// Re-encapsulate an outstanding hello to a rotated advert key — § Flows,
/// *First contact*, step 5.
///
/// A hello encapsulated to a serial its owner has already retired can never be
/// opened, so a poller that finds the correspondent's advert past that serial
/// re-encapsulates, re-seals the opening, sequence 0 and the hello under the
/// new secret, persists all three, and rewrites them. Nothing happens where
/// the serial is unchanged or lower: an authentic older advert can be replayed
/// over the record by anyone.
pub fn refresh_first_contact<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    peer: &CorrespondenceLabel,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    now: u64,
) -> Result<bool, FlowError> {
    let state = load(store, peer)?;
    let hello = state
        .outstanding_hello
        .as_ref()
        .ok_or(FlowError::NotOutstanding)?;
    let peer_identity_pk = state.peer_identity_pk.clone();
    let advert_owner = advert::derive_owner_seed(&peer_identity_pk)?;
    let bytes = records
        .read_advert(&advert_owner, advert::ADVERT_SUBKEYS)?
        .ok_or(FlowError::NoAdvert)?;
    let advert = advert::verify(&peer_identity_pk, &bytes)?;
    if !advert::hello_needs_rewrite(hello.advert_serial, &advert) {
        return Ok(false);
    }

    let outgoing_lookup_key = state.outgoing_lookup_key;
    let old_slot = hello.slot;
    let encapsulation = advert::encapsulate_to(&advert, now, &mut fill)?;
    let opened = chain::initiate(&encapsulation.shared_secret, &mut fill)?;
    let opening = ChannelOpening::build(
        me.signer,
        &peer_identity_pk,
        &opened.ratchet_pk,
        encapsulation.serial,
    )?;
    let opening_bytes: Box<[u8; OPENING_LEN]> = opening
        .encode()
        .as_slice()
        .try_into()
        .map(Box::new)
        .expect("an opening encodes to OPENING_LEN bytes");
    let serial = encapsulation.serial;

    // Sequence 0 is re-sealed under the new schedule, because the old one was
    // rooted in the secret the retired key established.
    let mut conversation = opened.conversation;
    let mut ring = Ring::new();
    let previous_opening = ChannelOpening::decode(
        state
            .own_opening
            .as_ref()
            .ok_or(FlowError::Incomplete("channel opening of its own"))?
            .as_slice(),
    )?;
    let body = first_message_body(store, peer, &state, &previous_opening)?;
    let seq = ring.reserve()?;
    let (header, sealed) = conversation.seal(&body, channel::DEVICE_ID_SINGLE_DEVICE, &mut fill)?;
    let mut slot_bytes = header.encode();
    slot_bytes.extend_from_slice(&sealed);
    store.persist_outbox(peer, seq, &slot_bytes)?;

    let secret_bytes = *encapsulation.shared_secret.as_bytes();
    let kem_ct = encapsulation.ciphertext.clone();
    store.update_conv(peer, |state| {
        state.conversation = conversation.snapshot();
        state.send_seq = ring.send_seq();
        state.own_hello_secret = Some(AdvertSharedSecret::from_bytes(&secret_bytes));
        state.own_hello_kem_ct = Some(kem_ct.clone());
        state.own_opening = Some(opening_bytes.clone());
    })?;

    let control = channel::seal_control(
        &encapsulation.shared_secret,
        &Control {
            opening: Some(opening),
            collected_cursor: state.my_collected,
            closed: false,
        },
    )?;
    records.write_channel(&outgoing_lookup_key, channel::CONTROL_SUBKEY, &control)?;
    records.write_channel(&outgoing_lookup_key, channel::slot_for(0), &slot_bytes)?;

    let drop_owner = drop_plane::derive_owner_seed(&peer_identity_pk)?;
    records.erase_drop_slot(&drop_owner, drop_plane::DROP_SUBKEYS, old_slot)?;
    place_hello(
        store,
        records,
        peer,
        &peer_identity_pk,
        &outgoing_lookup_key,
        &encapsulation.shared_secret,
        &kem_ct,
        serial,
        &mut fill,
    )?;
    Ok(true)
}

/// The body of sequence 0, opened from the outbox entry that still owes it.
///
/// A refresh re-seals under a new key schedule, and the plaintext exists only
/// inside the ciphertext the outbox holds, so it is recovered the way the
/// correspondent would have: the acceptor's reading half over the same hello
/// secret and the same first ratchet key the published opening names.
fn first_message_body(
    store: &Store,
    peer: &CorrespondenceLabel,
    state: &ConvState,
    opening: &ChannelOpening,
) -> Result<Vec<u8>, FlowError> {
    let bytes = outstanding_zero(store, peer)?
        .ok_or(FlowError::Incomplete("outbox entry for sequence 0"))?;
    let (header, sealed) = channel::MessageHeader::decode(&bytes)?;
    let secret = state
        .own_hello_secret
        .as_ref()
        .ok_or(FlowError::Incomplete("hello secret of its own"))?;
    let mut mirror = chain::accept(secret, &opening.first_ratchet_pk)?;
    Ok(mirror.open(&header, sealed)?)
}

/// A verified hello and everything an [`accept`] needs from it.
pub struct ContactRequest {
    /// The identity that signed the channel opening.
    pub identity: Box<[u8; ml_dsa::PK_LEN]>,
    /// The channel the hello named — the record this side reads.
    pub lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
    /// The writer's first ratchet public key, from the verified opening.
    pub first_ratchet_pk: Box<[u8; ml_kem::EK_LEN]>,
    /// The drop slot the hello occupies.
    pub slot: u16,
    /// The advert serial the opening binds — the serial of this side's own
    /// advert the correspondent encapsulated to.
    pub advert_serial: u64,
    /// The secret the correspondent's hello established. It opens the
    /// correspondent's control subkey and seals nothing this side writes.
    pub shared_secret: AdvertSharedSecret,
}

impl core::fmt::Debug for ContactRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContactRequest")
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

/// What one verified hello turned out to be.
pub enum Surfaced {
    /// From a blocked identity. Nothing was written and no record was created.
    Dropped {
        /// The identity that signed the opening.
        identity: Box<[u8; ml_dsa::PK_LEN]>,
    },
    /// From an identity an established conversation already exists with. It is
    /// surfaced for explicit accept and nothing else was done.
    StartedOver {
        /// The identity that signed the opening.
        identity: Box<[u8; ml_dsa::PK_LEN]>,
    },
    /// The acceptance of this side's own outstanding first contact, completed
    /// by [`recognise_acceptance`].
    Accepted(Acceptance),
    /// From an unknown identity. It is surfaced for explicit accept, carrying
    /// the verified material [`accept`] proceeds from.
    ContactRequest(ContactRequest),
    /// A verified hello this scan could not settle. The correspondent is named
    /// so the caller can act on it; the scan carried on past it.
    Failed {
        /// The identity that signed the opening.
        identity: Box<[u8; ml_dsa::PK_LEN]>,
        /// What stopped it.
        error: FlowError,
    },
    /// A rewrite of a hello this side has already collected. The slot was
    /// erased and nothing else was done.
    AlreadyCollected {
        /// The identity that signed the opening.
        identity: Box<[u8; ml_dsa::PK_LEN]>,
    },
}

impl core::fmt::Debug for Surfaced {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dropped { .. } => f.write_str("Dropped"),
            Self::StartedOver { .. } => f.write_str("StartedOver"),
            Self::Accepted(a) => f.debug_tuple("Accepted").field(a).finish(),
            Self::ContactRequest(r) => f.debug_tuple("ContactRequest").field(r).finish(),
            Self::Failed { error, .. } => f.debug_tuple("Failed").field(error).finish(),
            Self::AlreadyCollected { .. } => f.write_str("AlreadyCollected"),
        }
    }
}

/// Scan the drop and settle every hello in it — § Flows, *Collection*, steps 1
/// and 2, and *A hello from a known identity*.
///
/// A slot the record store will not read, that does not decapsulate under
/// either advert secret, or whose opening does not verify against this
/// identity and the serial it was encapsulated to, is skipped silently and the
/// scan continues: the drop is world-writable, a failure there carries no
/// information about a correspondent, and one unreadable slot must not hide
/// every hello after it. Only a failure of this side's own store stops the
/// scan.
pub fn collect<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    advert_keys: &AdvertKeys,
    is_blocked: impl Fn(&[u8; ml_dsa::PK_LEN]) -> bool,
) -> Result<Vec<Surfaced>, FlowError> {
    let my_pk = me.signer.public_key();
    let drop_owner = drop_plane::derive_owner_seed(my_pk)?;
    let mut surfaced = Vec::new();

    for slot in 0..drop_plane::DROP_SUBKEYS {
        let Ok(Some(bytes)) = records.read_drop_slot(&drop_owner, drop_plane::DROP_SUBKEYS, slot)
        else {
            continue;
        };
        let Some((hello, shared_secret, serial)) =
            open_against_either(advert_keys, &bytes, my_pk, slot)
        else {
            continue;
        };
        let Some(opening) = read_opening(records, &shared_secret, &hello.lookup_key) else {
            continue;
        };
        if opening.verify(my_pk, serial).is_err() {
            continue;
        }
        let identity = opening.writer_identity_pk.clone();

        if is_blocked(&identity) {
            surfaced.push(Surfaced::Dropped { identity });
            continue;
        }

        // Read afresh for each hello: an acceptance settled earlier in this
        // scan changes what the next one is. A failure that belongs to one
        // correspondent is carried as a result rather than returned, so one
        // unsettleable hello cannot hide every hello after it; only a failure
        // of this side's own store stops the scan.
        let settled = settle(
            store,
            records,
            me,
            &identity,
            &hello,
            opening,
            shared_secret,
            slot,
        );
        surfaced.push(match settled {
            Ok(settled) => settled,
            Err(FlowError::Store(e)) => return Err(FlowError::Store(e)),
            Err(error) => Surfaced::Failed { identity, error },
        });
    }
    Ok(surfaced)
}

/// Settle one verified hello against what this side already holds for the
/// identity that signed it — § Flows, *A hello from a known identity*.
#[allow(clippy::too_many_arguments)]
fn settle<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    identity: &[u8; ml_dsa::PK_LEN],
    hello: &drop_plane::Hello,
    opening: ChannelOpening,
    shared_secret: AdvertSharedSecret,
    slot: u16,
) -> Result<Surfaced, FlowError> {
    let Some(peer) = correspondence_for(store, identity)? else {
        return Ok(Surfaced::ContactRequest(ContactRequest {
            identity: Box::new(*identity),
            lookup_key: hello.lookup_key,
            first_ratchet_pk: opening.first_ratchet_pk,
            slot,
            advert_serial: opening.advert_serial,
            shared_secret,
        }));
    };
    let state = load(store, &peer)?;
    if state.awaiting_acceptance {
        return Ok(Surfaced::Accepted(recognise_acceptance(
            store,
            records,
            me,
            &peer,
            &hello.lookup_key,
            shared_secret,
            slot,
        )?));
    }
    // A hello naming the channel this side already reads is the correspondent
    // rewriting the hello that opened this conversation, which it does until
    // it learns the hello was collected. Erasing the slot is what tells it.
    if hello.lookup_key == state.incoming_lookup_key {
        let my_drop = drop_plane::derive_owner_seed(me.signer.public_key())?;
        records.erase_drop_slot(&my_drop, drop_plane::DROP_SUBKEYS, slot)?;
        return Ok(Surfaced::AlreadyCollected {
            identity: Box::new(*identity),
        });
    }
    Ok(Surfaced::StartedOver {
        identity: Box::new(*identity),
    })
}

/// Try the current advert secret and then the retained one.
///
/// The serial selects the key, so both are tried in turn and the hello's own
/// authenticated encryption is the failure signal: implicit rejection means a
/// decapsulation under the wrong key yields a pseudorandom secret rather than
/// an error, and only the sealed hello refuses it. Every failure is `None`:
/// the design discards a slot that will not open without saying why.
fn open_against_either(
    advert_keys: &AdvertKeys,
    bytes: &[u8],
    my_pk: &[u8; ml_dsa::PK_LEN],
    slot: u16,
) -> Option<(drop_plane::Hello, AdvertSharedSecret, u64)> {
    let prefix = bytes.get(..ml_kem::CT_LEN)?;
    let ciphertext: &[u8; ml_kem::CT_LEN] = prefix.try_into().expect("checked length");
    let serials = [Some(advert_keys.serial()), advert_keys.previous_serial()];
    for serial in serials.into_iter().flatten() {
        let Ok(Some(shared_secret)) = advert_keys.decapsulate(serial, ciphertext) else {
            continue;
        };
        if let Ok(hello) = drop_plane::open_hello(&shared_secret, bytes, my_pk, slot) {
            return Some((hello, shared_secret, serial));
        }
    }
    None
}

/// The opening in a channel's control subkey, or `None` where the record store
/// will not read it, the subkey holds nothing, or it will not open under this
/// secret.
fn read_opening<R: Records>(
    records: &mut R,
    shared_secret: &AdvertSharedSecret,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
) -> Option<ChannelOpening> {
    let bytes = records
        .read_channel(lookup_key, channel::CONTROL_SUBKEY)
        .ok()??;
    channel::open_control(shared_secret, &bytes).ok()?.opening
}

/// The cursor the correspondent publishes, from the control subkey of the
/// channel this side reads.
///
/// The secret that opens it is the one the correspondent's hello established,
/// read from the conversation record rather than supplied by the caller: a
/// conversation outlives the collection that established it.
pub fn peer_cursor<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
) -> Result<Option<u64>, FlowError> {
    let state = load(store, peer)?;
    let secret = state
        .peer_hello_secret
        .as_ref()
        .ok_or(FlowError::Incomplete("hello secret of the correspondent"))?;
    let Some(bytes) = records.read_channel(&state.incoming_lookup_key, channel::CONTROL_SUBKEY)?
    else {
        return Ok(None);
    };
    let control = channel::open_control(secret, &bytes)?;
    Ok(Some(control.collected_cursor))
}

/// What an [`accept`] left behind.
#[derive(Debug)]
pub struct Accepted {
    /// The correspondence the conversation record was created under.
    pub peer: CorrespondenceLabel,
    /// The lookup key of the channel this side writes.
    pub outgoing_lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
    /// The bodies read from the correspondent's ring.
    pub bodies: Vec<Vec<u8>>,
    /// The drop slot the hello back landed in.
    pub hello_slot: u16,
    /// How many times that hello re-picked its slot.
    pub repicks: u32,
}

/// Accept a contact request — § Flows, *Collection*, steps 3 to 5.
///
/// The conversation record is created before the ring is read, the hello slot
/// is erased once it has been, and the acceptance is a hello back naming this
/// side's channel, encapsulated to the correspondent's advert key. `reply` is
/// turn 0 of this side's direction, and its ratchet public key is the one the
/// opening publishes: the acceptor's first ratchet key comes into existence
/// when its first message is sealed, so an opening written without one would
/// name a key no message is encapsulated to.
///
/// One conversation per correspondent identity, as first contact holds: a
/// correspondent whose record exists resumes from it — an acceptance the
/// previous run left half-done is carried to completion, one whose hello back
/// is already placed is [`FlowError::AlreadyEstablished`].
///
/// One channel opening and one hello back, the hello read back once and
/// re-picked at most [`MAX_REPICKS`] times, plus the reply's own slot and the
/// erase of the collected hello.
#[allow(clippy::too_many_arguments)]
pub fn accept<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    request: &ContactRequest,
    reply: &[u8],
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    now: u64,
) -> Result<Accepted, FlowError> {
    if let Some(peer) = correspondence_for(store, &request.identity)? {
        let state = load(store, &peer)?;
        if state.outstanding_hello.is_some() {
            return Err(FlowError::AlreadyEstablished);
        }
        return finish_accept(
            store,
            records,
            me,
            peer,
            state,
            Some(request.slot),
            reply,
            &mut fill,
            now,
        );
    }

    let conversation = chain::accept(&request.shared_secret, &request.first_ratchet_pk)?;
    let peer = CorrespondenceLabel::mint().map_err(|e| FlowError::Store(StoreError::Store(e)))?;
    store.create_conv(
        &peer,
        &ConvState {
            peer_identity_pk: request.identity.clone(),
            outgoing_lookup_key: [0u8; HELLO_LOOKUP_KEY_LEN],
            incoming_lookup_key: request.lookup_key,
            generation: FIRST_GENERATION,
            conversation: conversation.snapshot(),
            send_seq: 0,
            peer_collected: 0,
            my_collected: 0,
            cursor_published: 0,
            awaiting_acceptance: false,
            outstanding_hello: None,
            own_hello_secret: None,
            own_hello_kem_ct: None,
            peer_hello_secret: Some(AdvertSharedSecret::from_bytes(
                request.shared_secret.as_bytes(),
            )),
            peer_advert_serial: Some(request.advert_serial),
            own_opening: None,
        },
    )?;

    let state = load(store, &peer)?;
    finish_accept(
        store,
        records,
        me,
        peer,
        state,
        Some(request.slot),
        reply,
        &mut fill,
        now,
    )
}

/// Steps 3 to 5 over an acceptance's conversation record, performing only what
/// the record shows is not done yet — the acceptor's counterpart of
/// [`finish_first_contact`].
///
/// Everything it needs is in the record: the correspondent's channel, the
/// secret its hello established, and the serial its opening binds. That
/// opening is re-read and re-verified here rather than taken on trust, so a
/// resumed acceptance is bound to the same advert serial the first run
/// verified.
#[allow(clippy::too_many_arguments)]
fn finish_accept<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    peer: CorrespondenceLabel,
    state: ConvState,
    slot: Option<u16>,
    reply: &[u8],
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), ()>,
    now: u64,
) -> Result<Accepted, FlowError> {
    let identity = state.peer_identity_pk.clone();
    let incoming = state.incoming_lookup_key;
    let peer_secret = state
        .peer_hello_secret
        .as_ref()
        .ok_or(FlowError::Incomplete("hello secret of the correspondent"))?;
    let peer_serial = state
        .peer_advert_serial
        .ok_or(FlowError::Incomplete("advert serial of the correspondent"))?;
    read_opening(records, peer_secret, &incoming)
        .ok_or(FlowError::NoOpening)?
        .verify(me.signer.public_key(), peer_serial)?;

    let mut conversation = Conversation::restore(state.conversation);
    let mut ring = Ring::restore(state.send_seq, state.peer_collected)?;

    let outgoing_lookup_key = if state.outgoing_lookup_key == [0u8; HELLO_LOOKUP_KEY_LEN] {
        let channel_owner =
            channel::derive_owner_seed(me.identity_seed, &identity, FIRST_GENERATION)?;
        let key = records.open_channel(&channel_owner, channel::CHANNEL_SUBKEYS)?;
        store.update_conv(&peer, |state| state.outgoing_lookup_key = key)?;
        key
    } else {
        state.outgoing_lookup_key
    };

    // The correspondent's ring from where this side left off.
    let read = read_ring(
        records,
        &mut conversation,
        &mut ring,
        &incoming,
        state.my_collected,
    )?;
    store.update_conv(&peer, |state| {
        state.conversation = conversation.snapshot();
        state.my_collected = read.collected;
        state.peer_collected = ring.peer_collected();
    })?;
    if let Some(slot) = slot {
        let my_drop = drop_plane::derive_owner_seed(me.signer.public_key())?;
        records.erase_drop_slot(&my_drop, drop_plane::DROP_SUBKEYS, slot)?;
    }

    // The reply, turn 0 of this side's direction, carrying the ratchet key the
    // opening publishes. A run that committed it already rewrites those bytes.
    let slot_bytes = match outstanding_zero(store, &peer)? {
        Some(bytes) => bytes,
        None => {
            let seq = ring.reserve()?;
            let (header, sealed) =
                conversation.seal(reply, channel::DEVICE_ID_SINGLE_DEVICE, &mut *fill)?;
            let mut bytes = header.encode();
            bytes.extend_from_slice(&sealed);
            store.persist_outbox(&peer, seq, &bytes)?;
            store.update_conv(&peer, |state| {
                state.conversation = conversation.snapshot();
                state.send_seq = ring.send_seq();
            })?;
            bytes
        }
    };
    let (reply_header, _) = channel::MessageHeader::decode(&slot_bytes)?;
    let first_ratchet_pk = reply_header
        .kem_pk
        .clone()
        .ok_or(FlowError::Chain(ChainError::NoTurn))?;
    let reply_seq = reply_header.seq;

    // The acceptance: this side's opening and cursor, then the hello back. The
    // encapsulation is minted once and persisted, so a resumed run publishes
    // the opening the correspondent has already been told to expect.
    let state = load(store, &peer)?;
    let (own_secret, own_kem_ct, opening_bytes) = match (
        state.own_hello_secret,
        state.own_hello_kem_ct,
        state.own_opening,
    ) {
        (Some(secret), Some(kem_ct), Some(opening)) => (secret, kem_ct, opening),
        _ => {
            let advert_owner = advert::derive_owner_seed(&identity)?;
            let bytes = records
                .read_advert(&advert_owner, advert::ADVERT_SUBKEYS)?
                .ok_or(FlowError::NoAdvert)?;
            let advert = advert::verify(&identity, &bytes)?;
            let encapsulation = advert::encapsulate_to(&advert, now, &mut *fill)?;
            let opening = ChannelOpening::build(
                me.signer,
                &identity,
                &first_ratchet_pk,
                encapsulation.serial,
            )?;
            let opening_bytes: Box<[u8; OPENING_LEN]> = opening
                .encode()
                .as_slice()
                .try_into()
                .map(Box::new)
                .expect("an opening encodes to OPENING_LEN bytes");
            let secret_bytes = *encapsulation.shared_secret.as_bytes();
            let kem_ct = encapsulation.ciphertext.clone();
            let carried = opening_bytes.clone();
            store.update_conv(&peer, |state| {
                state.cursor_published = read.collected;
                state.own_hello_secret = Some(AdvertSharedSecret::from_bytes(&secret_bytes));
                state.own_hello_kem_ct = Some(kem_ct.clone());
                state.own_opening = Some(carried.clone());
            })?;
            (encapsulation.shared_secret, kem_ct, opening_bytes)
        }
    };

    // Sealed under the secret *this* side's hello established, which is the
    // one the correspondent recovers by decapsulating that hello. The
    // correspondent's own secret belongs to its channel and opens nothing
    // here.
    let opening = ChannelOpening::decode(opening_bytes.as_slice())?;
    let advert_serial = opening.advert_serial;
    let control = channel::seal_control(
        &own_secret,
        &Control {
            opening: Some(opening),
            collected_cursor: read.collected,
            closed: false,
        },
    )?;
    records.write_channel(&outgoing_lookup_key, channel::CONTROL_SUBKEY, &control)?;
    records.write_channel(
        &outgoing_lookup_key,
        channel::slot_for(reply_seq),
        &slot_bytes,
    )?;

    let attempt = place_hello(
        store,
        records,
        &peer,
        &identity,
        &outgoing_lookup_key,
        &own_secret,
        &own_kem_ct,
        advert_serial,
        fill,
    )?;

    Ok(Accepted {
        peer,
        outgoing_lookup_key,
        bodies: read.bodies,
        hello_slot: attempt.slot(),
        repicks: attempt.repicks(),
    })
}

/// What this side's own first contact being accepted left behind.
#[derive(Debug)]
pub struct Acceptance {
    /// The correspondence the acceptance belongs to.
    pub peer: CorrespondenceLabel,
    /// The channel the correspondent named, now this side's incoming channel.
    pub lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
    /// The correspondent's published cursor, where its control subkey carried
    /// one.
    pub peer_cursor: Option<u64>,
    /// Any reply already in the correspondent's ring.
    pub bodies: Vec<Vec<u8>>,
}

/// Complete this side's own first contact — § Flows, *A hello from a known
/// identity*, the outstanding-first-contact case.
///
/// The correspondent's channel lookup key and hello secret are recorded, its
/// cursor and any reply are read, this side stops awaiting an acceptance, and
/// the slot is erased. One write.
pub fn recognise_acceptance<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    peer: &CorrespondenceLabel,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    peer_secret: AdvertSharedSecret,
    slot: u16,
) -> Result<Acceptance, FlowError> {
    let state = load(store, peer)?;
    if !state.awaiting_acceptance {
        return Err(FlowError::NotOutstanding);
    }
    let secret_bytes = *peer_secret.as_bytes();
    store.update_conv(peer, |state| {
        state.incoming_lookup_key = *lookup_key;
        state.peer_hello_secret = Some(AdvertSharedSecret::from_bytes(&secret_bytes));
    })?;

    let mut conversation = Conversation::restore(state.conversation);
    let mut ring = Ring::restore(state.send_seq, state.peer_collected)?;
    let cursor = peer_cursor(store, records, peer)?;
    if let Some(cursor) = cursor {
        ring.advance_peer_collected(cursor);
    }
    let read = read_ring(
        records,
        &mut conversation,
        &mut ring,
        lookup_key,
        state.my_collected,
    )?;
    store.update_conv(peer, |state| {
        state.conversation = conversation.snapshot();
        state.my_collected = read.collected;
        state.peer_collected = ring.peer_collected();
        state.outstanding_hello = None;
        state.awaiting_acceptance = false;
    })?;
    let my_drop = drop_plane::derive_owner_seed(me.signer.public_key())?;
    records.erase_drop_slot(&my_drop, drop_plane::DROP_SUBKEYS, slot)?;
    Ok(Acceptance {
        peer: *peer,
        lookup_key: *lookup_key,
        peer_cursor: cursor,
        bodies: read.bodies,
    })
}

/// What one pass over a correspondent's ring read.
struct RingRead {
    bodies: Vec<Vec<u8>>,
    collected: u64,
}

/// Read a correspondent's ring from `from`, opening each message in turn and
/// stopping at the first sequence the record store does not hold.
fn read_ring<R: Records>(
    records: &mut R,
    conversation: &mut Conversation,
    ring: &mut Ring,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    from: u64,
) -> Result<RingRead, FlowError> {
    let mut bodies = Vec::new();
    let mut collected = from;
    loop {
        let Some(raw) = records.read_channel(lookup_key, channel::slot_for(collected))? else {
            break;
        };
        let Ok((header, sealed)) = channel::MessageHeader::decode(&raw) else {
            break;
        };
        if header.seq != collected {
            break;
        }
        let body = conversation.open(&header, sealed)?;
        ring.advance_peer_collected(header.cursor);
        bodies.push(body);
        collected += 1;
    }
    Ok(RingRead { bodies, collected })
}

/// Send one ordinary message — § Flows, *Ordinary message*.
///
/// The ciphertext reaches disk, then the state that commits it, then the slot.
/// Exactly one write.
///
/// Refused with [`FlowError::AwaitingAcceptance`] while this side's own first
/// contact is unaccepted. First contact carries message 0 and nothing else,
/// and until it is accepted the correspondent may still rotate the advert it
/// was encapsulated to, which re-roots this direction's chain from sequence 0
/// — so a message sent in between would be sealed under a root no longer in
/// use.
pub fn send_message<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
    body: &[u8],
    fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<u64, FlowError> {
    let state = load(store, peer)?;
    if state.awaiting_acceptance {
        return Err(FlowError::AwaitingAcceptance);
    }
    let lookup_key = state.outgoing_lookup_key;
    let mut conversation = Conversation::restore(state.conversation);
    let mut ring = Ring::restore(state.send_seq, state.peer_collected)?;
    let seq = ring.reserve()?;
    let (header, sealed) = conversation.seal(body, channel::DEVICE_ID_SINGLE_DEVICE, fill)?;
    let mut slot_bytes = header.encode();
    slot_bytes.extend_from_slice(&sealed);
    store.persist_outbox(peer, seq, &slot_bytes)?;
    store.update_conv(peer, |state| {
        state.conversation = conversation.snapshot();
        state.send_seq = ring.send_seq();
    })?;
    records.write_channel(&lookup_key, channel::slot_for(seq), &slot_bytes)?;
    Ok(seq)
}

/// What one collection batch read and published.
#[derive(Debug)]
pub struct Batch {
    /// The bodies read, in sequence order.
    pub bodies: Vec<Vec<u8>>,
    /// This side's cursor after the batch.
    pub my_collected: u64,
    /// Whether the cursor was published to this side's control subkey.
    pub cursor_published: bool,
}

/// Read everything the correspondent has written since this side's cursor and
/// publish the new cursor — § Flows, *Ordinary message*, the recipient half.
///
/// At most one write: the cursor, as a control record, and only where the
/// published cursor is behind the collection cursor. The two are separate
/// fields of the conversation record, so a stop between recording a collection
/// and publishing it leaves work the next batch performs, rather than a cursor
/// that is never published because the collection is already recorded.
///
/// The record is sealed under the secret this side's own hello established and
/// carries this side's own opening, both read from the conversation record: a
/// control write without the opening erases it from the channel, and the
/// signature is randomized, so it cannot be rebuilt to the same bytes.
pub fn collect_batch<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
) -> Result<Batch, FlowError> {
    let state = load(store, peer)?;
    let incoming = state.incoming_lookup_key;
    let outgoing = state.outgoing_lookup_key;
    let mut conversation = Conversation::restore(state.conversation);
    let mut ring = Ring::restore(state.send_seq, state.peer_collected)?;
    let read = read_ring(
        records,
        &mut conversation,
        &mut ring,
        &incoming,
        state.my_collected,
    )?;
    store.update_conv(peer, |state| {
        state.conversation = conversation.snapshot();
        state.my_collected = read.collected;
        state.peer_collected = ring.peer_collected();
    })?;
    store.delete_outbox_through(peer, ring.peer_collected())?;

    if read.collected <= state.cursor_published {
        return Ok(Batch {
            bodies: read.bodies,
            my_collected: read.collected,
            cursor_published: false,
        });
    }
    let secret = state
        .own_hello_secret
        .as_ref()
        .ok_or(FlowError::Incomplete("hello secret of its own"))?;
    let opening_bytes = state
        .own_opening
        .as_ref()
        .ok_or(FlowError::Incomplete("channel opening of its own"))?;
    let control = channel::seal_control(
        secret,
        &Control {
            opening: Some(ChannelOpening::decode(opening_bytes.as_slice())?),
            collected_cursor: read.collected,
            closed: false,
        },
    )?;
    records.write_channel(&outgoing, channel::CONTROL_SUBKEY, &control)?;
    store.update_conv(peer, |state| {
        state.cursor_published = read.collected;
    })?;
    Ok(Batch {
        bodies: read.bodies,
        my_collected: read.collected,
        cursor_published: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    use oxicrypt_sha::sha384;

    use crate::dm::store::encode_conv;
    use crate::storage::seeds::AEAD_KEY_LEN;

    /// A moment inside every advert's usability window.
    const NOW: u64 = 1_700_000_000;

    /// A seeded fill. Deterministic, so a failing run replays from the source
    /// alone, and never constant, so two keypairs from one instance differ.
    struct Seeded(u64);

    impl Seeded {
        fn at(seed: u64) -> Self {
            Self(seed)
        }

        fn fill(&mut self, buf: &mut [u8]) -> Result<(), ()> {
            for b in buf.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *b = (self.0 >> 33) as u8;
            }
            Ok(())
        }
    }

    /// A record store's refusal, for the fault-injection runs.
    #[derive(Debug)]
    struct Refused;

    impl core::fmt::Display for Refused {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("the record store refused this operation")
        }
    }

    impl core::error::Error for Refused {}

    /// What one run wrote, counted per record kind.
    ///
    /// The kinds are separated because the budgets are: § Write budget gives
    /// first contact four writes across three kinds, an ordinary message one,
    /// and a cursor at most one per collection batch, and a single total
    /// cannot tell those apart.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct Writes {
        hello: usize,
        erase: usize,
        control: usize,
        ring: usize,
        bytes: usize,
    }

    impl Writes {
        fn total(&self) -> usize {
            self.hello + self.erase + self.control + self.ring
        }
    }

    /// The network: adverts and drops addressed by owner seed, channels by
    /// lookup key, and a count of everything written into it.
    #[derive(Default)]
    struct Net {
        adverts: HashMap<[u8; 32], Vec<u8>>,
        drops: HashMap<([u8; 32], u16), Vec<u8>>,
        channels: HashMap<([u8; HELLO_LOOKUP_KEY_LEN], u16), Vec<u8>>,
        writes: Writes,
        /// The subkey count every addressed record was named with, tagged by
        /// record kind: two kinds share a count, so the tag is what makes a
        /// caller that named the wrong one visible.
        shapes: Vec<(&'static str, u16)>,
        /// Every ciphertext prefix a hello was written with, so a run that
        /// minted a second hello is visible as a second distinct value.
        minted: Vec<[u8; ml_kem::CT_LEN]>,
        /// Every hello body written, so a rewrite can be compared with what it
        /// rewrites.
        hellos_written: Vec<Vec<u8>>,
        /// Count every write twice — the mutation the budget tests must fail
        /// on.
        double: bool,
        /// Overwrite this many hello writes with another party's bytes, so the
        /// read-back is clobbered exactly that many times.
        clobber_hellos: usize,
        clobbered: usize,
        /// Refuse every write after this many have been performed.
        fail_after: Option<usize>,
        /// Refuse to read this drop slot.
        unreadable_slot: Option<u16>,
    }

    impl Net {
        /// Charge one write, or refuse where the budget for this run is spent.
        fn charge(&mut self, bytes: usize) -> Result<(), RecordError> {
            if self.fail_after.is_some_and(|n| self.writes.total() >= n) {
                return Err(RecordError::new(Refused));
            }
            self.writes.bytes += bytes;
            Ok(())
        }

        /// A channel's lookup key, as the substrate computes one: a hash of
        /// the owner, never the owner secret itself.
        fn lookup_key(owner: &ChannelOwnerSeed) -> [u8; HELLO_LOOKUP_KEY_LEN] {
            let digest = sha384(owner.as_bytes()).expect("sha384 of a fixed-length seed");
            let mut key = [0u8; HELLO_LOOKUP_KEY_LEN];
            key.copy_from_slice(&digest[..HELLO_LOOKUP_KEY_LEN]);
            key
        }

        fn publish_advert(&mut self, owner: &AdvertOwnerSeed, bytes: Vec<u8>) {
            self.adverts.insert(*owner.as_bytes(), bytes);
        }

        fn reset_writes(&mut self) {
            self.writes = Writes::default();
        }
    }

    impl Records for Net {
        fn read_advert(
            &mut self,
            owner: &AdvertOwnerSeed,
            subkeys: u16,
        ) -> Result<Option<Vec<u8>>, RecordError> {
            self.shapes.push(("advert", subkeys));
            Ok(self.adverts.get(owner.as_bytes()).cloned())
        }

        fn read_drop_slot(
            &mut self,
            owner: &DropOwnerSeed,
            subkeys: u16,
            slot: u16,
        ) -> Result<Option<Vec<u8>>, RecordError> {
            self.shapes.push(("drop", subkeys));
            if self.unreadable_slot == Some(slot) {
                return Err(RecordError::new(Refused));
            }
            Ok(self.drops.get(&(*owner.as_bytes(), slot)).cloned())
        }

        fn write_drop_slot(
            &mut self,
            owner: &DropOwnerSeed,
            subkeys: u16,
            slot: u16,
            bytes: &[u8],
        ) -> Result<(), RecordError> {
            self.shapes.push(("drop", subkeys));
            self.charge(bytes.len())?;
            self.writes.hello += if self.double { 2 } else { 1 };
            self.hellos_written.push(bytes.to_vec());
            if let Some(prefix) = bytes.get(..ml_kem::CT_LEN) {
                self.minted.push(prefix.try_into().expect("checked length"));
            }
            let landed = if self.clobbered < self.clobber_hellos {
                self.clobbered += 1;
                vec![0x5au8; bytes.len()]
            } else {
                bytes.to_vec()
            };
            self.drops.insert((*owner.as_bytes(), slot), landed);
            Ok(())
        }

        fn erase_drop_slot(
            &mut self,
            owner: &DropOwnerSeed,
            subkeys: u16,
            slot: u16,
        ) -> Result<(), RecordError> {
            self.shapes.push(("drop", subkeys));
            self.charge(0)?;
            self.writes.erase += if self.double { 2 } else { 1 };
            self.drops.remove(&(*owner.as_bytes(), slot));
            Ok(())
        }

        fn open_channel(
            &mut self,
            owner: &ChannelOwnerSeed,
            subkeys: u16,
        ) -> Result<[u8; HELLO_LOOKUP_KEY_LEN], RecordError> {
            self.shapes.push(("channel", subkeys));
            Ok(Self::lookup_key(owner))
        }

        fn read_channel(
            &mut self,
            lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
            subkey: u16,
        ) -> Result<Option<Vec<u8>>, RecordError> {
            Ok(self.channels.get(&(*lookup_key, subkey)).cloned())
        }

        fn write_channel(
            &mut self,
            lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
            subkey: u16,
            bytes: &[u8],
        ) -> Result<(), RecordError> {
            self.charge(bytes.len())?;
            let one = if self.double { 2 } else { 1 };
            if subkey == channel::CONTROL_SUBKEY {
                self.writes.control += one;
            } else {
                self.writes.ring += one;
            }
            self.channels.insert((*lookup_key, subkey), bytes.to_vec());
            Ok(())
        }
    }

    /// Bring the crypto module up.
    ///
    /// Every test here mints an identity, and a suite that depended on another
    /// module having run first would fail with `NotOperational` out of a
    /// keygen, which reads like a broken keygen.
    fn module() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    /// One identity with its own profile, advert keys and store.
    struct Party {
        signer: SignKeypair,
        seed: [u8; ML_DSA_SEED_LEN],
        advert_keys: AdvertKeys,
        root: tempfile::TempDir,
        at_rest: [u8; AEAD_KEY_LEN],
    }

    impl Party {
        fn new(byte: u8) -> Self {
            module();
            let seed = [byte; ML_DSA_SEED_LEN];
            let mut entropy = Seeded::at(u64::from(byte) * 977 + 13);
            Self {
                signer: SignKeypair::from_ml_dsa_seed(&seed).expect("derive a signer"),
                seed,
                advert_keys: AdvertKeys::new(NOW, |b| entropy.fill(b)).expect("advert keys"),
                root: tempfile::tempdir().expect("a profile directory"),
                at_rest: [byte; AEAD_KEY_LEN],
            }
        }

        fn store(&self) -> Store {
            Store::open(self.root.path(), &self.at_rest).expect("open the store")
        }

        fn me(&self) -> Me<'_> {
            Me {
                signer: &self.signer,
                identity_seed: &self.seed,
            }
        }

        fn pk(&self) -> &[u8; ml_dsa::PK_LEN] {
            self.signer.public_key()
        }

        /// Put this party's advert on the network, as its own rotation would.
        fn publish(&self, net: &mut Net) {
            let owner = advert::derive_owner_seed(self.pk()).expect("advert owner");
            let bytes = self
                .advert_keys
                .advert_bytes(&self.signer)
                .expect("advert bytes");
            net.publish_advert(&owner, bytes);
        }
    }

    /// Both parties, their adverts published, and the network between them.
    fn scene() -> (Party, Party, Net) {
        let a = Party::new(0xa1);
        let b = Party::new(0xb2);
        let mut net = Net::default();
        a.publish(&mut net);
        b.publish(&mut net);
        (a, b, net)
    }

    /// A's first contact, as the flow performs it.
    fn a_opens(a: &Party, b: &Party, net: &mut Net, body: &[u8]) -> FirstContact {
        let store = a.store();
        let mut entropy = Seeded::at(4_242);
        first_contact(&store, net, &a.me(), b.pk(), body, |x| entropy.fill(x), NOW)
            .expect("A's first contact")
    }

    /// The correspondence a first contact opened.
    fn opened_peer(outcome: &FirstContact) -> CorrespondenceLabel {
        match outcome {
            FirstContact::Opened { peer, .. } | FirstContact::Rewrote { peer, .. } => *peer,
        }
    }

    /// B's collection, with nothing blocked.
    fn b_collects(b: &Party, net: &mut Net) -> Vec<Surfaced> {
        let store = b.store();
        collect(&store, net, &b.me(), &b.advert_keys, |_| false).expect("B collects")
    }

    /// The one contact request in a collection, or a panic naming what came
    /// back instead.
    fn only_request(surfaced: Vec<Surfaced>) -> ContactRequest {
        assert_eq!(surfaced.len(), 1, "one hello, one surfaced result");
        match surfaced.into_iter().next().expect("one result") {
            Surfaced::ContactRequest(request) => request,
            other => panic!("expected a contact request, got {other:?}"),
        }
    }

    /// B accepts the one request in its drop and replies.
    fn b_accepts(b: &Party, net: &mut Net, reply: &'static [u8]) -> Accepted {
        let request = only_request(b_collects(b, net));
        let store = b.store();
        let mut entropy = Seeded::at(909);
        accept(
            &store,
            net,
            &b.me(),
            &request,
            reply,
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B accepts")
    }

    /// The whole round trip: A opens, B accepts and replies, A recognises.
    fn round_trip(a: &Party, b: &Party, net: &mut Net) -> (CorrespondenceLabel, Accepted) {
        let outcome = a_opens(a, b, net, b"the first message");
        let accepted = b_accepts(b, net, b"the reply");
        let store_a = a.store();
        collect(&store_a, net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        (opened_peer(&outcome), accepted)
    }

    // ── write budget ────────────────────────────────────────────────────────

    /// A's first contact is the channel opening, the first message slot and
    /// the hello — three writes, and four where the read-back finds another
    /// value in the slot and the hello is re-picked.
    ///
    /// Each counter is asserted non-zero before the ceiling is read: a run
    /// that wrote nothing at all satisfies every ceiling, and would pass a
    /// test that only looked at the total.
    #[test]
    fn a_first_contact_writes_an_opening_a_slot_and_a_hello() {
        let (a, b, mut net) = scene();
        net.reset_writes();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");

        assert_eq!(net.writes.control, 1, "the channel opening");
        assert_eq!(net.writes.ring, 1, "the first message slot");
        assert_eq!(net.writes.hello, 1, "the hello");
        assert_eq!(net.writes.erase, 0, "first contact erases nothing");
        assert!(net.writes.bytes > 0, "the writes carried bytes");
        assert!(
            net.writes.total() <= 4,
            "first contact is at most four writes, was {}",
            net.writes.total()
        );
        assert!(matches!(outcome, FirstContact::Opened { repicks: 0, .. }));
    }

    /// A clobbered read-back costs the one extra write the budget allows, and
    /// no more.
    #[test]
    fn a_clobbered_hello_repicks_once_and_stays_inside_four_writes() {
        let (a, b, mut net) = scene();
        net.clobber_hellos = 1;
        net.reset_writes();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");

        assert!(matches!(outcome, FirstContact::Opened { repicks: 1, .. }));
        assert_eq!(net.writes.hello, 2, "the hello and its re-pick");
        assert_eq!(
            net.writes.total(),
            4,
            "the opening, the slot, the hello and the re-pick"
        );
    }

    /// A second clobber stops the flow rather than writing without bound, and
    /// leaves the hello persisted for the poller to rewrite.
    #[test]
    fn a_second_clobber_stops_at_the_budget_and_leaves_the_hello_persisted() {
        let (a, b, mut net) = scene();
        net.clobber_hellos = usize::MAX;
        net.reset_writes();
        let store = a.store();
        let mut entropy = Seeded::at(4_242);
        let outcome = first_contact(
            &store,
            &mut net,
            &a.me(),
            b.pk(),
            b"the first message",
            |x| entropy.fill(x),
            NOW,
        );

        assert!(matches!(outcome, Err(FlowError::DropFull)));
        assert_eq!(net.writes.hello, 2, "the hello and one re-pick, then stop");
        assert_eq!(net.writes.total(), 4, "the four-write budget, and no more");
        let loaded = store.load().expect("load");
        assert_eq!(loaded.convs.len(), 1);
        assert!(
            loaded.convs[0].state.outstanding_hello.is_some(),
            "the hello stays persisted for the poller"
        );
    }

    /// B's acceptance is one hello back and one channel opening, the hello
    /// read back like any other.
    #[test]
    fn b_acceptance_writes_one_hello_back_and_one_channel_opening() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let request = only_request(b_collects(&b, &mut net));

        net.reset_writes();
        let store = b.store();
        let mut entropy = Seeded::at(909);
        let accepted = accept(
            &store,
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B accepts");

        assert_eq!(accepted.bodies, vec![b"the first message".to_vec()]);
        assert_eq!(accepted.repicks, 0);
        assert!(net.writes.bytes > 0, "the writes carried bytes");
        assert!(
            net.writes.hello >= 1 && net.writes.control >= 1,
            "the acceptance wrote something"
        );
        assert_eq!(net.writes.hello, 1, "one hello back, unclobbered");
        assert_eq!(net.writes.control, 1, "one channel opening");
        assert_eq!(net.writes.erase, 1, "the collected hello slot is erased");
        assert_eq!(net.writes.ring, 1, "the reply is turn 0 of B's direction");
    }

    /// A clobbered acceptance hello re-picks once, and no further.
    #[test]
    fn b_acceptance_hello_repicks_once_on_a_clobber() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let request = only_request(b_collects(&b, &mut net));

        net.clobber_hellos = net.clobbered + 1;
        net.reset_writes();
        let store = b.store();
        let mut entropy = Seeded::at(909);
        let accepted = accept(
            &store,
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B accepts");

        assert_eq!(accepted.repicks, 1, "one clobber, one re-pick");
        assert_eq!(net.writes.hello, 2, "the hello back and its re-pick");
        assert_eq!(net.writes.control, 1);
        assert_eq!(net.writes.ring, 1);
        assert_eq!(net.writes.erase, 1);
    }

    /// An ordinary message is exactly one write.
    #[test]
    fn an_ordinary_message_is_exactly_one_write() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);

        net.reset_writes();
        let store_a = a.store();
        let mut entropy = Seeded::at(77);
        let seq = send_message(&store_a, &mut net, &peer_a, b"an ordinary message", |x| {
            entropy.fill(x)
        })
        .expect("A sends");

        assert_eq!(seq, 1, "the second message A has sent");
        assert!(net.writes.bytes > 0, "the write carried bytes");
        assert_eq!(net.writes.ring, 1, "one ring slot");
        assert_eq!(net.writes.total(), 1, "an ordinary message is one write");
    }

    /// A collection batch publishes its cursor in at most one write, and
    /// writes nothing where the published cursor is already current.
    #[test]
    fn a_collection_batch_publishes_at_most_one_cursor_write() {
        let (a, b, mut net) = scene();
        let (peer_a, accepted) = round_trip(&a, &b, &mut net);

        // B sends one more, so A's next batch has something to read.
        let store_b = b.store();
        let mut entropy = Seeded::at(31);
        send_message(&store_b, &mut net, &accepted.peer, b"another", |x| {
            entropy.fill(x)
        })
        .expect("B sends");

        net.reset_writes();
        let store_a = a.store();
        let batch = collect_batch(&store_a, &mut net, &peer_a).expect("A collects a batch");

        assert!(!batch.bodies.is_empty(), "the batch read something");
        assert!(batch.cursor_published, "the cursor was published");
        assert!(net.writes.bytes > 0, "the write carried bytes");
        assert_eq!(
            net.writes.control, 1,
            "at most one cursor write per batch, was {}",
            net.writes.control
        );
        assert_eq!(net.writes.total(), 1, "the cursor and nothing else");

        net.reset_writes();
        let batch = collect_batch(&store_a, &mut net, &peer_a).expect("A collects an empty batch");
        assert!(batch.bodies.is_empty());
        assert!(!batch.cursor_published);
        assert_eq!(net.writes.total(), 0, "an empty batch writes nothing");
    }

    /// A batch that recorded a collection and stopped before publishing it
    /// publishes on the next batch, even though that batch reads nothing.
    #[test]
    fn an_unpublished_cursor_is_published_by_the_next_batch() {
        let (a, b, mut net) = scene();
        let (peer_a, accepted) = round_trip(&a, &b, &mut net);
        let store_b = b.store();
        let mut entropy = Seeded::at(31);
        send_message(&store_b, &mut net, &accepted.peer, b"another", |x| {
            entropy.fill(x)
        })
        .expect("B sends");

        // The stop: every write refused, so the collection is recorded and the
        // cursor is not published.
        let store_a = a.store();
        net.fail_after = Some(0);
        let stopped = collect_batch(&store_a, &mut net, &peer_a);
        assert!(stopped.is_err(), "the cursor write was refused");
        let state = store_a.load_conv(&peer_a).expect("load").expect("a record");
        assert_eq!(state.my_collected, 2, "the collection was recorded");
        assert_eq!(state.cursor_published, 0, "the cursor was not published");

        // The relaunch: nothing new to read, and the cursor still goes out.
        net.fail_after = None;
        net.reset_writes();
        let batch = collect_batch(&store_a, &mut net, &peer_a).expect("A collects");
        assert!(batch.bodies.is_empty(), "nothing new was read");
        assert!(batch.cursor_published, "the owed cursor was published");
        assert_eq!(net.writes.control, 1);
        assert_eq!(
            store_a
                .load_conv(&peer_a)
                .expect("load")
                .expect("a record")
                .cursor_published,
            2
        );
    }

    /// The control on every budget above: a record store that counts each
    /// write twice pushes first contact past its ceiling.
    #[test]
    fn a_doubled_write_fails_the_first_contact_budget() {
        let (a, b, mut net) = scene();
        net.double = true;
        net.reset_writes();
        a_opens(&a, &b, &mut net, b"the first message");

        assert!(
            net.writes.total() > 4,
            "a doubled write must exceed the four-write budget, was {}",
            net.writes.total()
        );
    }

    /// Every record addressed by owner seed is named with its own subkey
    /// count, so a transport is never left to guess the record's shape.
    #[test]
    fn every_addressed_record_names_its_subkey_count() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        b_accepts(&b, &mut net, b"the reply");

        let seen: HashSet<(&'static str, u16)> = net.shapes.iter().copied().collect();
        // Every kind was addressed at least once, so none of the three
        // assertions below is vacuous.
        assert_eq!(
            seen.len(),
            3,
            "a record kind was addressed with two different shapes, or not at all: {seen:?}"
        );
        assert!(seen.contains(&("advert", advert::ADVERT_SUBKEYS)));
        assert!(seen.contains(&("drop", drop_plane::DROP_SUBKEYS)));
        assert!(seen.contains(&("channel", channel::CHANNEL_SUBKEYS)));
    }

    // ── serialisation ───────────────────────────────────────────────────────

    /// A's conversation record holds A's own key material and none of B's
    /// owner secret.
    ///
    /// The control is the second assertion: A's own retained ratchet
    /// decapsulation key is found in the same bytes by the same search, so an
    /// absence claim cannot pass because the search does not work.
    #[test]
    fn a_conversation_record_holds_no_peer_owner_secret() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);

        let store_a = a.store();
        let state = store_a
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's conversation record");
        let own_dk = state.conversation.receiving.own_turns[0]
            .as_ref()
            .expect("A retains its turn-0 keypair")
            .keypair
            .dk
            .as_bytes()
            .to_vec();
        let image = encode_conv(&state);

        let b_owner = channel::derive_owner_seed(&b.seed, a.pk(), FIRST_GENERATION)
            .expect("B's channel owner seed");
        assert!(
            !contains(&image, b_owner.as_bytes()),
            "B's channel owner secret is in A's conversation record"
        );
        assert!(
            !contains(&image, &b.seed),
            "B's identity seed is in A's conversation record"
        );
        assert!(
            contains(&image, &own_dk),
            "A's own retained ratchet key is absent, so the search proves nothing"
        );
    }

    /// Whether `needle` appears anywhere in `haystack`.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    // ── restart ─────────────────────────────────────────────────────────────

    /// A relaunch at every step boundary of A's first contact carries the
    /// first contact to completion and mints one hello.
    ///
    /// Each run refuses the `k`th write, so the run dies at that boundary; the
    /// in-memory state is dropped with the `Store`, and the relaunch calls
    /// `first_contact` again, which finds the correspondence on disk and
    /// resumes rather than opening a second one. The assertion is on `kem_ct`:
    /// it is the encapsulation the hello carries, so two distinct values
    /// across a run would be two hellos.
    #[test]
    fn a_relaunch_at_each_step_boundary_mints_one_hello() {
        for boundary in 0..4usize {
            let (a, b, mut net) = scene();
            // Three writes is the whole of an unclobbered first contact, so
            // the fourth boundary is only reachable with a re-pick.
            net.clobber_hellos = usize::from(boundary == 3);
            net.fail_after = Some(boundary);

            let store = a.store();
            let mut entropy = Seeded::at(4_242);
            let outcome = first_contact(
                &store,
                &mut net,
                &a.me(),
                b.pk(),
                b"the first message",
                |x| entropy.fill(x),
                NOW,
            );
            assert!(
                outcome.is_err(),
                "boundary {boundary} must stop the run short"
            );
            drop(outcome);
            drop(store);

            // The relaunch: nothing of the previous run is in memory.
            net.fail_after = None;
            let store = a.store();
            assert_eq!(
                store.load().expect("load").convs.len(),
                1,
                "boundary {boundary} left exactly one correspondence"
            );
            // The hello is persisted before it is written, so a boundary at
            // or past the hello write must find one on disk. Without this a
            // flow that wrote the hello first would resume through the
            // nothing-to-do arm and look correct.
            let loaded = store.load().expect("load");
            let persisted = loaded.convs[0].state.outstanding_hello.is_some();
            assert!(
                boundary < 2 || persisted,
                "boundary {boundary} wrote a hello it had not persisted"
            );
            // Sequence 0's ciphertext is persisted before the slot that holds
            // it, so every boundary from the first channel write on owes it.
            assert_eq!(
                loaded.convs[0].outstanding_outbox.len(),
                1,
                "boundary {boundary} wrote a slot whose bytes were not on disk"
            );

            let mut entropy = Seeded::at(5_353);
            let resumed = first_contact(
                &store,
                &mut net,
                &a.me(),
                b.pk(),
                b"the first message",
                |x| entropy.fill(x),
                NOW,
            )
            .expect("the relaunch resumes");

            assert_eq!(
                store.load().expect("load").convs.len(),
                1,
                "boundary {boundary} opened a second correspondence"
            );
            let state = store
                .load_conv(&opened_peer(&resumed))
                .expect("load")
                .expect("a record");
            let sealed = state
                .outstanding_hello
                .as_ref()
                .expect("the resumed run placed a hello")
                .sealed
                .to_vec();
            assert_eq!(
                net.hellos_written.last().expect("a hello reached the drop"),
                &sealed,
                "boundary {boundary} wrote bytes other than the persisted hello"
            );

            let distinct: HashSet<[u8; ml_kem::CT_LEN]> = net.minted.iter().copied().collect();
            assert_eq!(
                distinct.len(),
                1,
                "boundary {boundary} minted {} hellos",
                distinct.len()
            );
        }
    }

    /// A second first contact to a correspondent whose hello is still
    /// outstanding rewrites that hello; one whose conversation is established
    /// is refused.
    #[test]
    fn a_second_first_contact_resumes_or_is_refused() {
        let (a, b, mut net) = scene();
        let first = a_opens(&a, &b, &mut net, b"the first message");
        let peer = opened_peer(&first);

        let store = a.store();
        let mut entropy = Seeded::at(1_234);
        let again = first_contact(
            &store,
            &mut net,
            &a.me(),
            b.pk(),
            b"a second attempt",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("the second call resumes");
        assert!(matches!(again, FirstContact::Rewrote { .. }));
        assert_eq!(opened_peer(&again), peer, "the same correspondence");
        assert_eq!(store.load().expect("load").convs.len(), 1);

        // Once the acceptance has been recognised, the conversation is
        // established and a first contact is the wrong call.
        b_accepts(&b, &mut net, b"the reply");
        collect(&store, &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        let mut entropy = Seeded::at(5_678);
        let refused = first_contact(
            &store,
            &mut net,
            &a.me(),
            b.pk(),
            b"and a third",
            |x| entropy.fill(x),
            NOW,
        );
        assert!(matches!(refused, Err(FlowError::AlreadyEstablished)));
    }

    // ── hellos from known identities ────────────────────────────────────────

    /// A hello from a blocked identity is dropped: nothing is written and no
    /// conversation record is created.
    #[test]
    fn a_blocked_identity_is_dropped_with_no_write_and_no_record() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");

        net.reset_writes();
        let store = b.store();
        let a_pk = *a.pk();
        let surfaced = collect(&store, &mut net, &b.me(), &b.advert_keys, |pk| pk == &a_pk)
            .expect("B collects");

        assert_eq!(surfaced.len(), 1, "the hello was still recognised");
        assert!(matches!(surfaced[0], Surfaced::Dropped { .. }));
        assert_eq!(net.writes.total(), 0, "a blocked hello writes nothing");
        assert!(
            store.load().expect("load").convs.is_empty(),
            "a blocked hello creates no conversation record"
        );
    }

    /// A hello from an identity an established conversation already exists
    /// with is surfaced as that correspondent having started over, and nothing
    /// else is done.
    #[test]
    fn an_established_identity_starts_over_and_writes_nothing() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);

        // A starts over: the delete flow's generation turnover is out of scope
        // here, so the second hello is placed the way a re-established one
        // would be, into the drop B reads.
        let store_a = a.store();
        let state = store_a.load_conv(&peer_a).expect("load").expect("a record");
        let mut entropy = Seeded::at(5_151);
        let hello_secret = advert::encapsulate_to(
            &advert::verify(
                b.pk(),
                &b.advert_keys.advert_bytes(&b.signer).expect("advert"),
            )
            .expect("verify"),
            NOW,
            |x| entropy.fill(x),
        )
        .expect("encapsulate");
        let opening = ChannelOpening::build(
            &a.signer,
            b.pk(),
            &[0x11u8; ml_kem::EK_LEN],
            hello_secret.serial,
        )
        .expect("an opening");
        let control = channel::seal_control(
            &hello_secret.shared_secret,
            &Control {
                opening: Some(opening),
                collected_cursor: 0,
                closed: false,
            },
        )
        .expect("seal the control");
        let restart_key = [0x9fu8; HELLO_LOOKUP_KEY_LEN];
        net.write_channel(&restart_key, channel::CONTROL_SUBKEY, &control)
            .expect("write the control");
        let r = drop_plane::repick(|x| entropy.fill(x)).expect("r");
        let sealed = drop_plane::seal_hello(&hello_secret, &restart_key, &r, b.pk())
            .expect("seal the hello");
        let drop_owner = drop_plane::derive_owner_seed(b.pk()).expect("B's drop");
        net.write_drop_slot(
            &drop_owner,
            drop_plane::DROP_SUBKEYS,
            drop_plane::slot_for(&r).expect("slot"),
            &sealed,
        )
        .expect("write the hello");
        let _ = state;

        net.reset_writes();
        let surfaced = b_collects(&b, &mut net);
        assert_eq!(surfaced.len(), 1, "one hello in B's drop");
        assert!(matches!(surfaced[0], Surfaced::StartedOver { .. }));
        assert_eq!(net.writes.total(), 0, "started over writes nothing");
        assert_eq!(
            b.store().load().expect("load").convs.len(),
            1,
            "no second conversation record was created"
        );
    }

    /// A's rewrite of its own outstanding hello is not an acceptance.
    ///
    /// Both sides of a first contact hold an outstanding hello of their own,
    /// so the presence of one cannot be the predicate: what makes a hello an
    /// acceptance is that this side is still awaiting one.
    #[test]
    fn a_rewritten_hello_is_not_read_as_an_acceptance() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let accepted = b_accepts(&b, &mut net, b"the reply");

        // A's poller rewrites its own hello into B's drop, not yet knowing the
        // acceptance is waiting.
        let store_a = a.store();
        let peer_a = store_a.load().expect("load").convs[0].peer;
        resume_first_contact(&store_a, &mut net, &peer_a).expect("A rewrites its hello");

        net.reset_writes();
        let surfaced = b_collects(&b, &mut net);
        assert_eq!(surfaced.len(), 1, "A's rewritten hello is in B's drop");
        assert!(
            matches!(surfaced[0], Surfaced::AlreadyCollected { .. }),
            "B must not read A's own hello as an acceptance, got {:?}",
            surfaced[0]
        );
        assert_eq!(
            net.writes.erase, 1,
            "the collected hello's slot is erased, which is what stops the rewrites"
        );
        assert_eq!(net.writes.total(), 1, "and nothing else is written for it");
        let b_drop = drop_plane::derive_owner_seed(b.pk()).expect("B's drop");
        assert!(
            !net.drops
                .keys()
                .any(|(owner, _)| owner == b_drop.as_bytes()),
            "the rewritten slot is gone from B's drop"
        );
        let state = b
            .store()
            .load_conv(&accepted.peer)
            .expect("load")
            .expect("B's record");
        assert!(
            state.outstanding_hello.is_some(),
            "B's own hello back is still outstanding"
        );
    }

    /// One unreadable slot does not hide the hellos after it.
    #[test]
    fn an_unreadable_slot_does_not_stop_the_scan() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let occupied: Vec<u16> = net.drops.keys().map(|(_, slot)| *slot).collect();
        assert_eq!(occupied.len(), 1, "one hello in B's drop");
        let hello_slot = occupied[0];

        // A slot before the hello's refuses to read, and a later one holds
        // junk that opens under no key.
        net.unreadable_slot = Some(hello_slot.wrapping_add(1) % drop_plane::DROP_SUBKEYS);
        let drop_owner = drop_plane::derive_owner_seed(b.pk()).expect("B's drop");
        net.drops.insert(
            (*drop_owner.as_bytes(), net.unreadable_slot.expect("a slot")),
            vec![0u8; HELLO_LEN],
        );

        let surfaced = b_collects(&b, &mut net);
        assert_eq!(
            surfaced.len(),
            1,
            "the scan completed and surfaced the readable hello"
        );
        assert!(matches!(surfaced[0], Surfaced::ContactRequest(_)));

        // The control: with the refusal lifted, the junk slot is still
        // discarded and the same one hello is surfaced.
        net.unreadable_slot = None;
        let surfaced = b_collects(&b, &mut net);
        assert_eq!(surfaced.len(), 1);
    }

    /// The whole first-contact round trip: A opens, B accepts and replies, A
    /// recognises the acceptance and reads the reply.
    #[test]
    fn a_recognises_the_acceptance_and_reads_the_reply() {
        let (a, b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let accepted = b_accepts(&b, &mut net, b"the reply");

        let store_a = a.store();
        net.reset_writes();
        let surfaced =
            collect(&store_a, &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        assert_eq!(surfaced.len(), 1);
        let acceptance = match surfaced.into_iter().next().expect("one result") {
            Surfaced::Accepted(acceptance) => acceptance,
            other => panic!("expected an acceptance, got {other:?}"),
        };

        assert_eq!(acceptance.peer, peer_a);
        assert_eq!(acceptance.lookup_key, accepted.outgoing_lookup_key);
        assert_eq!(acceptance.bodies, vec![b"the reply".to_vec()]);
        assert_eq!(acceptance.peer_cursor, Some(1), "B collected A's message");
        assert_eq!(net.writes.erase, 1, "the collected hello slot is erased");

        let state = store_a
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record");
        assert!(!state.awaiting_acceptance, "A is no longer awaiting one");
        assert!(state.outstanding_hello.is_none());
        assert_eq!(state.incoming_lookup_key, accepted.outgoing_lookup_key);
        assert_eq!(state.my_collected, 1);
        assert!(
            state.peer_hello_secret.is_some(),
            "the secret that opens B's control subkey is recorded"
        );
    }

    // ── advert rotation ─────────────────────────────────────────────────────

    /// A hello outstanding across a rotation of the correspondent's advert is
    /// re-encapsulated to the new key.
    #[test]
    fn a_refresh_re_encapsulates_to_a_rotated_advert() {
        let (a, mut b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let old_sealed = net
            .hellos_written
            .last()
            .cloned()
            .expect("the first hello was written");

        let mut entropy = Seeded::at(2_020);
        b.advert_keys
            .rotate_now(NOW + advert::ROTATION_PERIOD_SECS, |x| entropy.fill(x))
            .expect("B rotates");
        b.publish(&mut net);

        let store_a = a.store();
        let mut entropy = Seeded::at(3_030);
        let refreshed = refresh_first_contact(
            &store_a,
            &mut net,
            &a.me(),
            &peer_a,
            |x| entropy.fill(x),
            NOW + advert::ROTATION_PERIOD_SECS,
        )
        .expect("the refresh runs");
        assert!(refreshed, "the rotation was past the outstanding serial");

        // The new hello opens under the new key; the old one does not.
        let new_sealed = net
            .hellos_written
            .last()
            .cloned()
            .expect("the refreshed hello was written");
        assert_ne!(new_sealed, old_sealed, "the hello was re-sealed");
        let slot = store_a
            .load_conv(&peer_a)
            .expect("load")
            .expect("a record")
            .outstanding_hello
            .expect("an outstanding hello")
            .slot;
        assert!(
            open_against_either(&b.advert_keys, &new_sealed, b.pk(), slot).is_some(),
            "the refreshed hello does not open under the rotated key"
        );
        assert!(
            open_against_either(&b.advert_keys, &old_sealed, b.pk(), slot).is_none(),
            "the hello for the retired key still opens, so the refresh proved nothing"
        );

        // A second refresh against the same advert does nothing.
        let mut entropy = Seeded::at(4_040);
        assert!(
            !refresh_first_contact(
                &store_a,
                &mut net,
                &a.me(),
                &peer_a,
                |x| entropy.fill(x),
                NOW + advert::ROTATION_PERIOD_SECS,
            )
            .expect("the second refresh runs"),
            "an unchanged serial must not re-encapsulate"
        );
    }

    // ── mutation-driven cases ───────────────────────────────────────────────

    /// A hello encapsulated to a retired advert key is still collected.
    ///
    /// The correspondent may rotate between the hello being written and being
    /// read, so the scan tries the retained key as well as the current one.
    #[test]
    fn a_hello_under_the_previous_advert_secret_is_still_collected() {
        let (a, mut b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");

        let mut entropy = Seeded::at(6_060);
        b.advert_keys
            .rotate_now(NOW + advert::ROTATION_PERIOD_SECS, |x| entropy.fill(x))
            .expect("B rotates");
        // The control: the hello's key is now the retained one, so a scan that
        // only tried the current key would find nothing.
        assert!(
            b.advert_keys.previous_serial().is_some(),
            "the rotation retained nothing, so this proves nothing"
        );
        assert_ne!(
            b.advert_keys.serial(),
            b.advert_keys.previous_serial().expect("retained")
        );

        let surfaced = b_collects(&b, &mut net);
        assert_eq!(surfaced.len(), 1, "the hello under the retained key");
        assert!(matches!(surfaced[0], Surfaced::ContactRequest(_)));
    }

    /// An opening naming an advert serial this side never published is
    /// discarded, and the scan continues past it.
    ///
    /// The serial is what stops a hello being relayed into a channel the
    /// reader did not address.
    #[test]
    fn an_opening_bound_to_the_wrong_advert_serial_is_discarded() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");

        // Re-sign A's opening against a serial B never published, and put it
        // back under the secret the hello establishes, so only the serial
        // binding can refuse it.
        let drop_owner = drop_plane::derive_owner_seed(b.pk()).expect("B's drop");
        let (slot, bytes) = net
            .drops
            .iter()
            .find(|((owner, _), _)| owner == drop_owner.as_bytes())
            .map(|((_, slot), bytes)| (*slot, bytes.clone()))
            .expect("A's hello is in B's drop");
        let (hello, secret, serial) =
            open_against_either(&b.advert_keys, &bytes, b.pk(), slot).expect("the hello opens");
        let original = read_opening(&mut net, &secret, &hello.lookup_key).expect("the opening");
        let forged =
            ChannelOpening::build(&a.signer, b.pk(), &original.first_ratchet_pk, serial + 1)
                .expect("re-sign the opening");
        let control = channel::seal_control(
            &secret,
            &Control {
                opening: Some(forged),
                collected_cursor: 0,
                closed: false,
            },
        )
        .expect("seal the control");
        net.write_channel(&hello.lookup_key, channel::CONTROL_SUBKEY, &control)
            .expect("overwrite the control");

        net.reset_writes();
        let surfaced = b_collects(&b, &mut net);
        assert!(
            surfaced.is_empty(),
            "a hello bound to another advert serial was surfaced: {surfaced:?}"
        );
        assert_eq!(net.writes.total(), 0, "and nothing was written for it");

        // The scan still ran to the end: a second, well-formed hello placed
        // after the bad one is surfaced.
        let c = Party::new(0xc3);
        c.publish(&mut net);
        a_opens(&c, &b, &mut net, b"from a third party");
        let surfaced = b_collects(&b, &mut net);
        assert_eq!(surfaced.len(), 1, "the discarded slot stopped the scan");
    }

    /// An ordinary message's ciphertext reaches disk before its slot.
    #[test]
    fn an_ordinary_message_persists_before_it_writes() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);
        let store_a = a.store();
        let before = store_a
            .load()
            .expect("load")
            .convs
            .into_iter()
            .find(|c| c.peer == peer_a)
            .expect("a record")
            .outstanding_outbox
            .len();

        net.fail_after = Some(0);
        let mut entropy = Seeded::at(88);
        let refused = send_message(&store_a, &mut net, &peer_a, b"owed", |x| entropy.fill(x));
        // The control: the write really was refused, so the outbox assertion
        // below is about a message whose slot never reached the network.
        assert!(refused.is_err(), "the slot write was refused");
        drop(store_a);

        net.fail_after = None;
        let after = a
            .store()
            .load()
            .expect("load")
            .convs
            .into_iter()
            .find(|c| c.peer == peer_a)
            .expect("a record")
            .outstanding_outbox
            .len();
        assert_eq!(
            after,
            before + 1,
            "the slot was written before its bytes reached disk"
        );
    }

    /// The conversation record holds no owner secret at any point of a first
    /// contact, not only once it is complete.
    ///
    /// Owner keypairs are re-derived from the identity and the generation, so
    /// none is ever written down. The hello secrets the record does hold are
    /// seal secrets for control subkeys, not owner secrets: holding one
    /// confers no write authority over any record.
    #[test]
    fn no_owner_secret_is_at_rest_midway_through_a_first_contact() {
        let (a, b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);

        let store_a = a.store();
        let state = store_a.load_conv(&peer_a).expect("load").expect("a record");
        let own_owner = channel::derive_owner_seed(&a.seed, b.pk(), FIRST_GENERATION)
            .expect("A's own channel owner seed");
        let drop_owner = drop_plane::derive_owner_seed(b.pk()).expect("B's drop owner seed");
        let advert_owner = advert::derive_owner_seed(b.pk()).expect("B's advert owner seed");
        let image = encode_conv(&state);

        assert!(
            !contains(&image, own_owner.as_bytes()),
            "A's own channel owner secret is at rest in its conversation record"
        );
        assert!(!contains(&image, drop_owner.as_bytes()));
        assert!(!contains(&image, advert_owner.as_bytes()));
        // The control: the lookup key that owner names is in the record, so
        // the search reaches the bytes the owner seed would have been in.
        assert!(
            contains(&image, &state.outgoing_lookup_key),
            "the channel's lookup key is absent, so the search proves nothing"
        );
    }

    // ── residual cases ──────────────────────────────────────────────────────

    /// An acceptance the previous run left half-done is carried to completion
    /// by the next call, under the same correspondence.
    #[test]
    fn a_stopped_acceptance_is_finished_by_the_next_call() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let request = only_request(b_collects(&b, &mut net));

        // The stop: the first write an acceptance performs is refused, so the
        // conversation record exists and nothing has been published.
        let store = b.store();
        net.fail_after = Some(0);
        net.reset_writes();
        let mut entropy = Seeded::at(909);
        let stopped = accept(
            &store,
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        );
        assert!(stopped.is_err(), "the acceptance was stopped short");
        assert_eq!(net.writes.total(), 0, "and published nothing");
        assert_eq!(
            store.load().expect("load").convs.len(),
            1,
            "the conversation record is there"
        );
        drop(store);

        // The relaunch: the same request, and the acceptance completes.
        net.fail_after = None;
        let store = b.store();
        let mut entropy = Seeded::at(7_070);
        let accepted = accept(
            &store,
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("the relaunch finishes the acceptance");

        // The stopped run had already read the ring and recorded the
        // collection, so the finish reports no new bodies and the message is
        // collected exactly once.
        assert!(accepted.bodies.is_empty());
        assert_eq!(
            store
                .load_conv(&accepted.peer)
                .expect("load")
                .expect("a record")
                .my_collected,
            1,
            "the correspondent's first message is collected exactly once"
        );
        assert_eq!(
            store.load().expect("load").convs.len(),
            1,
            "the relaunch minted a second correspondence"
        );
        assert_eq!(
            net.writes.hello, 1,
            "exactly one hello back was ever written"
        );
        assert_eq!(net.writes.control, 1, "and one channel opening");

        // A third call has nothing left to do and says so.
        let mut entropy = Seeded::at(8_080);
        let again = accept(
            &store,
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        );
        assert!(matches!(again, Err(FlowError::AlreadyEstablished)));
    }

    /// An ordinary message is refused until this side's first contact has been
    /// accepted, and succeeds once it has.
    ///
    /// A message sent in between would be sealed under a root a refresh
    /// re-derives, because an unaccepted first contact may still be
    /// re-encapsulated to a rotated advert key.
    #[test]
    fn an_ordinary_message_is_refused_until_the_first_contact_is_accepted() {
        let (a, b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);

        let store_a = a.store();
        let mut entropy = Seeded::at(99);
        let refused = send_message(&store_a, &mut net, &peer_a, b"too early", |x| {
            entropy.fill(x)
        });
        assert!(matches!(refused, Err(FlowError::AwaitingAcceptance)));

        b_accepts(&b, &mut net, b"the reply");
        collect(&store_a, &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");

        let mut entropy = Seeded::at(100);
        let seq = send_message(&store_a, &mut net, &peer_a, b"now", |x| entropy.fill(x))
            .expect("the same call succeeds once the acceptance is in");
        assert_eq!(seq, 1);
    }

    /// One correspondent whose channel this side cannot read does not stop the
    /// poll: the failure is reported and the scan carries on.
    #[test]
    fn one_unsettleable_correspondent_does_not_stop_the_scan() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let accepted = b_accepts(&b, &mut net, b"the reply");

        // B's reply is corrupted in place: its header still decodes, so the
        // read reaches the open, and the open fails.
        let slot = channel::slot_for(0);
        let raw = net
            .channels
            .get_mut(&(accepted.outgoing_lookup_key, slot))
            .expect("B's reply is on the network");
        let last = raw.len() - 1;
        raw[last] ^= 0xff;

        // A third party reaches A at the same time.
        let c = Party::new(0xc3);
        c.publish(&mut net);
        a_opens(&c, &a, &mut net, b"from a third party");

        let store_a = a.store();
        let surfaced =
            collect(&store_a, &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");

        assert_eq!(surfaced.len(), 2, "both hellos were reached: {surfaced:?}");
        assert!(
            surfaced
                .iter()
                .any(|s| matches!(s, Surfaced::Failed { .. })),
            "the unsettleable correspondent was not reported: {surfaced:?}"
        );
        assert!(
            surfaced
                .iter()
                .any(|s| matches!(s, Surfaced::ContactRequest(_))),
            "the other hello was hidden by the failure: {surfaced:?}"
        );
    }
}
