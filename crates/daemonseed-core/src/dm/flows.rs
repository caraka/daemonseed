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
use zeroize::Zeroizing;

use crate::dm::advert::{self, AdvertError, AdvertKeys, AdvertOwnerSeed, AdvertSharedSecret};
use crate::dm::chain::{self, ChainError, Conversation};
use crate::dm::channel::{
    self, ChannelError, ChannelOpening, ChannelOwnerSeed, Control, ControlKey, OPENING_LEN, Ring,
};
use crate::dm::drop as drop_plane;
use crate::dm::drop::{
    DropError, DropOwnerSeed, HELLO_LEN, HELLO_LOOKUP_KEY_LEN, HelloAttempt, ReadBack,
};
use crate::dm::store::{ConvState, OutstandingHello, Store, StoreError};
use crate::identity::keys::{DmChannelRootSecret, SignKeypair};
use crate::storage::dm_store::CorrespondenceLabel;

/// The conversation generation a first contact opens at.
///
/// Every first contact and every acceptance opens at this generation, and no
/// flow turns it over, so a conversation established again after a delete
/// derives the same channel records as the one deleted.
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
    /// The conversation record's `awaiting_acceptance` is clear: this side
    /// has recognised the acceptance of its own first contact, or it is the
    /// side that accepted. [`refresh_first_contact`] refreshes only a hello
    /// that opens a first contact, so it refuses both; the accepting side's
    /// hello back is not refreshed by it.
    AlreadyAccepted,
    /// The opening the correspondent's channel holds was signed by an
    /// identity other than the one the conversation record names.
    OpeningWriter,
    /// The opening the correspondent's channel holds names a first ratchet key
    /// other than the one this side's reading half was opened with.
    OpeningRatchetKey,
    /// Every slot this hello picked was taken. The hello stays persisted and
    /// the poller retries.
    DropFull,
    /// The correspondence holds none of the state a resumed or rewritten
    /// record needs.
    Incomplete(&'static str),
    /// A hello was sealed to a length other than [`HELLO_LEN`].
    HelloLength(usize),
    /// A delete of this conversation is under way
    /// ([`crate::dm::store::ConvState::delete_pending`]), so nothing more is
    /// written for it: [`send_message`], [`collect_batch`],
    /// [`recognise_acceptance`], [`accept`] on an existing record,
    /// [`continue_acceptance`], [`continue_first_contact`] and through it
    /// [`first_contact`] to a marked identity, [`resume_first_contact`] and
    /// [`refresh_first_contact`] refuse it.
    DeletePending,
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
            Self::AlreadyAccepted => {
                f.write_str("this side is not awaiting an acceptance of a first contact")
            }
            Self::OpeningWriter => {
                f.write_str("the correspondent's opening is signed by another identity")
            }
            Self::OpeningRatchetKey => {
                f.write_str("the correspondent's opening names another first ratchet key")
            }
            Self::DropFull => f.write_str("every slot the hello picked was taken"),
            Self::Incomplete(what) => write!(f, "the conversation record holds no {what}"),
            Self::HelloLength(n) => write!(f, "a hello sealed to {n} bytes"),
            Self::DeletePending => f.write_str("a delete of this conversation is under way"),
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
/// The channel root derives channel owner keypairs and the keypair signs
/// adverts and openings. Both are borrowed: neither is copied into this type.
pub struct Me<'a> {
    /// The identity signing keypair.
    pub signer: &'a SignKeypair,
    /// The identity's channel root secret,
    /// [`crate::identity::keys::IdentityKeys::dm_channel_root`].
    pub channel_root: &'a DmChannelRootSecret,
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
        // The record already holds sequence 0, so `body` is not sealed again.
        return continue_first_contact(store, records, &peer, fill);
    }

    // 1. The advert, verified under the identity the caller named.
    let advert_owner = advert::derive_owner_seed(peer_identity_pk)?;
    let bytes = records
        .read_advert(&advert_owner, advert::ADVERT_SUBKEYS)?
        .ok_or(FlowError::NoAdvert)?;
    let advert = advert::verify(peer_identity_pk, &bytes)?;

    // 2. The channel's lookup key, which the opening signs, then the key
    //    schedule and the conversation record, before any write to the record
    //    store. Naming the channel to the transport writes no value.
    let channel_owner =
        channel::derive_owner_seed(me.channel_root, peer_identity_pk, FIRST_GENERATION)?;
    let outgoing_lookup_key = records.open_channel(&channel_owner, channel::CHANNEL_SUBKEYS)?;
    let encapsulation = advert::encapsulate_to(&advert, now, &mut fill)?;
    let opened = chain::initiate(&encapsulation.shared_secret, &mut fill)?;
    let opening = ChannelOpening::build(
        me.signer,
        peer_identity_pk,
        &outgoing_lookup_key,
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

    // 3, committed ahead of the record. Sequence 0 is sealed and its outbox
    // entry persisted before the record exists, so every record holds it and a
    // relaunch never needs the body. An outbox with no record is not loaded.
    let mut conversation = opened.conversation;
    let mut ring = Ring::new();
    let seq = ring.reserve()?;
    let (header, sealed) = conversation.seal(body, channel::DEVICE_ID_SINGLE_DEVICE, &mut fill)?;
    let mut slot_bytes = header.encode();
    slot_bytes.extend_from_slice(&sealed);
    store.persist_outbox(&peer, seq, &slot_bytes, now)?;

    store.create_conv(
        &peer,
        &ConvState {
            peer_identity_pk: Box::new(*peer_identity_pk),
            outgoing_lookup_key,
            incoming_lookup_key: [0u8; HELLO_LOOKUP_KEY_LEN],
            generation: FIRST_GENERATION,
            conversation: conversation.snapshot(),
            send_seq: ring.send_seq(),
            peer_collected: 0,
            my_collected: 0,
            cursor_published: 0,
            awaiting_acceptance: true,
            acceptance_pending: false,
            outstanding_hello: None,
            own_control_key: Some(channel::control_key(&encapsulation.shared_secret)?),
            own_hello_secret: Some(encapsulation.shared_secret),
            own_hello_kem_ct: Some(encapsulation.ciphertext),
            peer_control_key: None,
            peer_advert_serial: None,
            own_opening: Some(opening_bytes),
            delete_pending: false,
        },
    )?;

    let state = load(store, &peer)?;
    finish_first_contact(store, records, peer, state, &mut fill)
}

/// Carry on a first contact from its conversation record alone — § Flows,
/// *Restart at any point*.
///
/// For a relaunch that holds nothing of the first contact in memory. From the
/// moment the record exists it holds sequence 0's ciphertext, the
/// encapsulation, the signed opening and the channel's lookup key, so this
/// redoes only writes. Where no hello is persisted yet it writes the opening,
/// sequence 0's slot and the hello. Where one is, the opening and the slot
/// were written before it was persisted, and it writes that hello's persisted
/// bytes as [`resume_first_contact`] does. Nothing is minted or re-sealed.
///
/// [`FlowError::AlreadyEstablished`] where the first contact is no longer
/// awaiting acceptance.
pub fn continue_first_contact<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<FirstContact, FlowError> {
    let state = load(store, peer)?;
    if state.delete_pending {
        return Err(FlowError::DeletePending);
    }
    if !state.awaiting_acceptance {
        return Err(FlowError::AlreadyEstablished);
    }
    if state.outstanding_hello.is_some() {
        let slot = match resume_first_contact(store, records, peer)? {
            Resumed::Rewrote(slot) => slot,
            Resumed::Nothing => return Err(FlowError::NotOutstanding),
        };
        return Ok(FirstContact::Rewrote {
            peer: *peer,
            hello_slot: slot,
        });
    }
    finish_first_contact(store, records, *peer, state, &mut fill)
}

/// Steps 3 to 5 over a conversation record that already exists: write the
/// opening and the committed bytes of sequence 0, then place the hello.
fn finish_first_contact<R: Records>(
    store: &Store,
    records: &mut R,
    peer: CorrespondenceLabel,
    state: ConvState,
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

    // 3. The first message, committed before the record was created.
    let slot_bytes = outstanding_zero(store, &peer)?
        .ok_or(FlowError::Incomplete("outbox entry for sequence 0"))?;
    let own_control_key = state
        .own_control_key
        .as_ref()
        .ok_or(FlowError::Incomplete("control key of its own"))?;
    let control = channel::seal_control_with_key(
        own_control_key,
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
        &HelloSeal {
            shared_secret: own_secret,
            kem_ct: own_kem_ct,
            advert_serial,
            original: None,
        },
        HelloAttempt::new(drop_plane::repick(&mut *fill)?)?,
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
    seal: &HelloSeal<'_>,
    mut attempt: HelloAttempt,
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<HelloAttempt, FlowError> {
    let drop_owner = drop_plane::derive_owner_seed(peer_identity_pk)?;
    loop {
        let hello = seal_outstanding(seal, lookup_key, peer_identity_pk, &attempt)?;
        let written = *hello.sealed;
        store.update_conv(peer, |state| {
            state.outstanding_hello = Some(hello);
            // From here on the accepting side's hello back is rewritten from
            // these sealed bytes, so the secret it was sealed from goes in the
            // same write. The initiator keeps its own while a rewrite may
            // still carry it.
            if !state.awaiting_acceptance {
                state.own_hello_secret = None;
            }
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

/// What a hello is sealed from, apart from the `r` that places it.
struct HelloSeal<'a> {
    /// The secret the hello's own encapsulation established.
    shared_secret: &'a AdvertSharedSecret,
    /// The encapsulation the hello publishes.
    kem_ct: &'a [u8; ml_kem::CT_LEN],
    /// The advert serial that encapsulation was made to.
    advert_serial: u64,
    /// For a rewritten hello, the secret of the first hello for this channel,
    /// which the rewrite carries to the correspondent.
    original: Option<&'a AdvertSharedSecret>,
}

/// The hello for one attempt, as the record the conversation persists.
fn seal_outstanding(
    seal: &HelloSeal<'_>,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    peer_identity_pk: &[u8; ml_dsa::PK_LEN],
    attempt: &HelloAttempt,
) -> Result<OutstandingHello, FlowError> {
    let encapsulation = advert::HelloEncapsulation {
        serial: seal.advert_serial,
        shared_secret: AdvertSharedSecret::from_bytes(seal.shared_secret.as_bytes()),
        ciphertext: Box::new(*seal.kem_ct),
    };
    let sealed = match seal.original {
        None => drop_plane::seal_hello(&encapsulation, lookup_key, attempt.r(), peer_identity_pk)?,
        Some(original) => drop_plane::seal_rewritten_hello(
            &encapsulation,
            lookup_key,
            attempt.r(),
            original,
            peer_identity_pk,
        )?,
    };
    let sealed: [u8; HELLO_LEN] = sealed
        .as_slice()
        .try_into()
        .map_err(|_| FlowError::HelloLength(sealed.len()))?;
    Ok(OutstandingHello {
        slot: attempt.slot(),
        r: *attempt.r(),
        kem_ct: encapsulation.ciphertext,
        sealed: Box::new(sealed),
        advert_serial: seal.advert_serial,
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

/// Write an outstanding hello from the state a previous run left on disk —
/// § Flows, *Restart at any point*.
///
/// Every call writes the persisted `sealed` bytes; it reads nothing and never
/// re-encapsulates. The caller decides when a write is owed, and this flow
/// cannot decide it for the caller: a writer reading its own record is served
/// its local copy (§ Substrate facts), so a read here never shows an evicted
/// slot. A write is owed where the network reports the slot evicted or
/// changed, and where a run stopped between persisting a hello and writing it,
/// including a [`refresh_first_contact`] that persisted its rewrite and
/// stopped. The bytes written are the persisted ones, so a relaunch at any step
/// boundary writes the same hello rather than minting a second one: the
/// encapsulation is fixed, and `kem_ct` is unchanged across every rewrite.
///
/// Refused with [`FlowError::DeletePending`] for a conversation marked for
/// delete. The mark is checked at the load and the write runs outside the
/// store's lock, so a delete marked between the two does not stop the write.
pub fn resume_first_contact<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
) -> Result<Resumed, FlowError> {
    let state = load(store, peer)?;
    if state.delete_pending {
        return Err(FlowError::DeletePending);
    }
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

/// Rewrite an outstanding first-contact hello to a rotated advert key — § Flows,
/// *First contact*, step 5.
///
/// A hello encapsulated to a serial its owner no longer holds cannot be opened.
/// Where the correspondent's advert is past the serial the outstanding hello
/// was encapsulated to, the hello is re-encapsulated to the current key and
/// rewritten into the slot it already occupies, carrying the secret this side's
/// first hello established ([`drop_plane::seal_rewritten_hello`]). The channel
/// opening, sequence 0, the outbox and the key schedule stay as written: the
/// correspondent recovers the first-turn root from the carried secret, and a
/// correspondent that already collected an earlier hello keeps reading the
/// same channel. Nothing happens where the serial is unchanged or lower,
/// because an authentic older advert can be replayed over the record by anyone.
///
/// The rewritten hello is persisted before it is written, and a re-pick after a
/// clobbered read-back keeps the same encapsulation. A stop at any point
/// therefore leaves the bytes the slot must hold on disk: a later call finds
/// the serial current and returns `false`, and [`resume_first_contact`] writes
/// the persisted bytes.
///
/// **Call order.** Run [`collect`] over this side's own drop before this call,
/// in the same poll. An acceptance waiting there is recognised by it, which
/// ends the first contact, and this call then refuses with
/// [`FlowError::AlreadyAccepted`] and writes nothing. A call made out of that
/// order still changes no channel record and no key-schedule state, so a reply
/// the correspondent has sealed stays readable. Its one hello write is erased
/// by the correspondent as already collected.
///
/// One hello write, plus at most one re-pick, and no channel write.
pub fn refresh_first_contact<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    now: u64,
) -> Result<bool, FlowError> {
    let state = load(store, peer)?;
    if state.delete_pending {
        return Err(FlowError::DeletePending);
    }
    if !state.awaiting_acceptance {
        return Err(FlowError::AlreadyAccepted);
    }
    let hello = state
        .outstanding_hello
        .as_ref()
        .ok_or(FlowError::NotOutstanding)?;
    let original = state
        .own_hello_secret
        .as_ref()
        .ok_or(FlowError::Incomplete("hello secret of its own"))?;
    let advert_owner = advert::derive_owner_seed(&state.peer_identity_pk)?;
    let bytes = records
        .read_advert(&advert_owner, advert::ADVERT_SUBKEYS)?
        .ok_or(FlowError::NoAdvert)?;
    let advert = advert::verify(&state.peer_identity_pk, &bytes)?;
    if !advert::hello_needs_rewrite(hello.advert_serial, &advert) {
        return Ok(false);
    }

    let encapsulation = advert::encapsulate_to(&advert, now, &mut fill)?;
    place_hello(
        store,
        records,
        peer,
        &state.peer_identity_pk,
        &state.outgoing_lookup_key,
        &HelloSeal {
            shared_secret: &encapsulation.shared_secret,
            kem_ct: &encapsulation.ciphertext,
            advert_serial: encapsulation.serial,
            original: Some(original),
        },
        HelloAttempt::new(hello.r)?,
        &mut fill,
    )?;
    Ok(true)
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
    ///
    /// `request` is what [`accept`] proceeds from. `accept` refuses it with
    /// [`FlowError::AlreadyEstablished`] while the old conversation's record is
    /// there, and with [`FlowError::DeletePending`] while that record is marked
    /// for delete, so accepting a correspondent who started over follows the
    /// delete of the old conversation.
    StartedOver {
        /// The identity that signed the opening.
        identity: Box<[u8; ml_dsa::PK_LEN]>,
        /// The verified material an acceptance of the new first contact
        /// proceeds from.
        request: ContactRequest,
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
            Self::StartedOver { request, .. } => {
                f.debug_tuple("StartedOver").field(request).finish()
            }
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
/// either advert secret, or whose opening does not verify is skipped silently
/// and the scan continues: the drop is world-writable, a failure there carries
/// no information about a correspondent, and one unreadable slot must not hide
/// every hello after it. Only a failure of this side's own store stops the
/// scan.
///
/// An opening verifies when it names this identity, the channel the hello
/// named, and the advert serial the hello must bind. A rewritten hello is
/// opened under the secret it carries, and its opening must name an earlier
/// serial than the rewrite arrived under (§ Flows, *First contact*, step 5).
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
        let Some((mut hello, decapsulated, serial)) =
            open_against_either(advert_keys, &bytes, my_pk, slot)
        else {
            continue;
        };
        // A rewritten hello's channel is sealed under the secret it carries,
        // not under the one its own decapsulation yielded.
        let rewritten = hello.original_secret.is_some();
        let shared_secret = hello.original_secret.take().unwrap_or(decapsulated);
        let Ok(control_key) = channel::control_key(&shared_secret) else {
            continue;
        };
        let Some(opening) = read_opening(records, &control_key, &hello.lookup_key) else {
            continue;
        };
        let Some(bound) = opening_serial(rewritten, serial, &opening) else {
            continue;
        };
        if opening.verify(my_pk, &hello.lookup_key, bound).is_err() {
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
        return Ok(Surfaced::ContactRequest(contact_request(
            identity,
            hello,
            opening,
            shared_secret,
            slot,
        )));
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
        request: contact_request(identity, hello, opening, shared_secret, slot),
    })
}

/// The contact request a verified hello becomes: everything [`accept`]
/// proceeds from, whether the identity is unknown or has started over.
fn contact_request(
    identity: &[u8; ml_dsa::PK_LEN],
    hello: &drop_plane::Hello,
    opening: ChannelOpening,
    shared_secret: AdvertSharedSecret,
    slot: u16,
) -> ContactRequest {
    ContactRequest {
        identity: Box::new(*identity),
        lookup_key: hello.lookup_key,
        first_ratchet_pk: opening.first_ratchet_pk,
        slot,
        advert_serial: opening.advert_serial,
        shared_secret,
    }
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

/// The advert serial a hello's channel opening must name, or `None` where the
/// hello is refused.
///
/// An original hello was encapsulated to the serial its opening binds, so that
/// is the serial it decapsulated under. A rewritten hello was re-encapsulated
/// after this side's advert moved past the serial the opening binds, so the
/// opening names an earlier serial than the rewrite arrived under, and exactly
/// that serial is accepted. The carried secret it is paired with is
/// authenticated by the channel: the control subkey holding the opening has
/// already opened under it, and only the channel's owner writes that subkey.
/// A redirected hello is still refused by [`ChannelOpening::verify`], because
/// the opening names the identity it was addressed to. A rewrite whose opening
/// names a serial at or past the one it arrived under was not made by a
/// rotation and is refused here.
fn opening_serial(
    rewritten: bool,
    decapsulated_under: u64,
    opening: &ChannelOpening,
) -> Option<u64> {
    if !rewritten {
        return Some(decapsulated_under);
    }
    (opening.advert_serial < decapsulated_under).then_some(opening.advert_serial)
}

/// The opening in a channel's control subkey, or `None` where the record store
/// will not read it, the subkey holds nothing, or it will not open under this
/// key.
fn read_opening<R: Records>(
    records: &mut R,
    control_key: &ControlKey,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
) -> Option<ChannelOpening> {
    let bytes = records
        .read_channel(lookup_key, channel::CONTROL_SUBKEY)
        .ok()??;
    channel::open_control_with_key(control_key, &bytes)
        .ok()?
        .opening
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
    let key = state
        .peer_control_key
        .as_ref()
        .ok_or(FlowError::Incomplete("control key of the correspondent"))?;
    let Some(bytes) = records.read_channel(&state.incoming_lookup_key, channel::CONTROL_SUBKEY)?
    else {
        return Ok(None);
    };
    let control = channel::open_control_with_key(key, &bytes)?;
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
/// The channel this side writes is named to the transport, and the reply is
/// sealed and its outbox entry persisted, before the conversation record is
/// created. Every record therefore holds what a relaunch needs to finish the
/// acceptance with neither the request nor the reply in memory
/// ([`continue_acceptance`]). `reply` is turn 0 of this side's direction, and
/// its ratchet public key is the one the opening publishes: the acceptor's
/// first ratchet key comes into existence when its first message is sealed.
///
/// The acceptance is this side's opening and cursor, the reply's slot and a
/// hello back naming this side's channel, encapsulated to the correspondent's
/// advert key. The correspondent's ring is read before those writes, but the
/// bodies and the collection cursor are recorded only by the step that
/// finishes the acceptance, after the hello back is written. A run stopped
/// before then records nothing it read, and the call that finishes the
/// acceptance returns the bodies.
///
/// One conversation per correspondent identity, as first contact holds: a
/// correspondent whose record holds an unfinished acceptance is carried on
/// from it only for a request naming the channel that record reads, and any
/// other request, or any other record, is [`FlowError::AlreadyEstablished`].
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
        if state.delete_pending {
            return Err(FlowError::DeletePending);
        }
        // A pending acceptance is finished only for the request it was created
        // from. A request naming another channel is another first contact from
        // the same identity, and is not carried into this record.
        if state.acceptance_pending && request.lookup_key != state.incoming_lookup_key {
            return Err(FlowError::AlreadyEstablished);
        }
        if !state.acceptance_pending {
            return already_established(store, &peer, &state);
        }
        return finish_accept(
            store,
            records,
            me,
            peer,
            state,
            Some(request.slot),
            &mut fill,
            now,
        );
    }

    let channel_owner =
        channel::derive_owner_seed(me.channel_root, &request.identity, FIRST_GENERATION)?;
    let outgoing_lookup_key = records.open_channel(&channel_owner, channel::CHANNEL_SUBKEYS)?;
    let peer = CorrespondenceLabel::mint().map_err(|e| FlowError::Store(StoreError::Store(e)))?;

    // The reply, committed ahead of the record so that a relaunch never needs
    // it again. An outbox with no record is not loaded.
    let mut conversation = chain::accept(&request.shared_secret, &request.first_ratchet_pk)?;
    let mut ring = Ring::new();
    let seq = ring.reserve()?;
    let (header, sealed) = conversation.seal(reply, channel::DEVICE_ID_SINGLE_DEVICE, &mut fill)?;
    let mut slot_bytes = header.encode();
    slot_bytes.extend_from_slice(&sealed);
    store.persist_outbox(&peer, seq, &slot_bytes, now)?;

    store.create_conv(
        &peer,
        &ConvState {
            peer_identity_pk: request.identity.clone(),
            outgoing_lookup_key,
            incoming_lookup_key: request.lookup_key,
            generation: FIRST_GENERATION,
            conversation: conversation.snapshot(),
            send_seq: ring.send_seq(),
            peer_collected: 0,
            my_collected: 0,
            cursor_published: 0,
            awaiting_acceptance: false,
            acceptance_pending: true,
            outstanding_hello: None,
            own_hello_secret: None,
            own_hello_kem_ct: None,
            own_control_key: None,
            peer_control_key: Some(channel::control_key(&request.shared_secret)?),
            peer_advert_serial: Some(request.advert_serial),
            own_opening: None,
            delete_pending: false,
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
        &mut fill,
        now,
    )
}

/// Carry on an acceptance from its conversation record alone — § Flows,
/// *Restart at any point*.
///
/// For a relaunch that holds neither the request nor the reply. The record
/// holds the reply's ciphertext, both channels' lookup keys, the key the
/// correspondent's control subkey opens under and the advert serial its
/// opening binds. This redoes only what the record shows undone. It mints the
/// encapsulation and the opening where the record holds none, and otherwise
/// writes the persisted ones. The correspondent's collected hello slot is not
/// erased here: the correspondent rewrites that hello until it sees the
/// acceptance, and the next scan erases it as already collected.
///
/// The bodies of the correspondent's ring are returned, and recorded by the
/// same step that finishes the acceptance. [`FlowError::AlreadyEstablished`]
/// where the record holds no unfinished acceptance.
pub fn continue_acceptance<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    peer: &CorrespondenceLabel,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    now: u64,
) -> Result<Accepted, FlowError> {
    let state = load(store, peer)?;
    if state.delete_pending {
        return Err(FlowError::DeletePending);
    }
    if !state.acceptance_pending {
        return already_established(store, peer, &state);
    }
    finish_accept(store, records, me, *peer, state, None, &mut fill, now)
}

/// [`FlowError::AlreadyEstablished`] for a correspondence with no unfinished
/// acceptance.
///
/// An accepting side's record that holds its hello back and still holds the
/// secret that hello was sealed from has the secret deleted here. The
/// initiator's hello secret is left alone while it awaits acceptance, because
/// a rewrite still carries it.
fn already_established(
    store: &Store,
    peer: &CorrespondenceLabel,
    state: &ConvState,
) -> Result<Accepted, FlowError> {
    if !state.awaiting_acceptance
        && state.outstanding_hello.is_some()
        && state.own_hello_secret.is_some()
    {
        store.update_conv(peer, |state| state.own_hello_secret = None)?;
    }
    Err(FlowError::AlreadyEstablished)
}

/// Steps 3 to 5 over an acceptance's conversation record, performing only what
/// the record shows is not done yet — the acceptor's counterpart of
/// [`finish_first_contact`].
///
/// Everything it needs is in the record: the correspondent's channel, the key
/// and serial its opening is verified under, and the committed reply. That
/// opening is re-read and re-verified here rather than taken on trust. The
/// ring is read on a copy of the key schedule, and the copy, the collection
/// cursor and the end of the acceptance are persisted together, after the
/// hello back is written.
#[allow(clippy::too_many_arguments)]
fn finish_accept<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    peer: CorrespondenceLabel,
    state: ConvState,
    slot: Option<u16>,
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), ()>,
    now: u64,
) -> Result<Accepted, FlowError> {
    let identity = state.peer_identity_pk.clone();
    let incoming = state.incoming_lookup_key;
    let peer_key = state
        .peer_control_key
        .as_ref()
        .ok_or(FlowError::Incomplete("control key of the correspondent"))?;
    let peer_serial = state
        .peer_advert_serial
        .ok_or(FlowError::Incomplete("advert serial of the correspondent"))?;
    let opening = read_opening(records, peer_key, &incoming).ok_or(FlowError::NoOpening)?;
    opening.verify(me.signer.public_key(), &incoming, peer_serial)?;
    // The opening must be the one this record was created from: signed by the
    // correspondent the record names, and naming the ratchet key the reading
    // half was opened with.
    if opening.writer_identity_pk.as_slice() != identity.as_slice() {
        return Err(FlowError::OpeningWriter);
    }
    let opened_with = state
        .conversation
        .receiving
        .peer_latest
        .as_ref()
        .map(|turn| turn.pk.as_slice());
    if opened_with != Some(opening.first_ratchet_pk.as_slice()) {
        return Err(FlowError::OpeningRatchetKey);
    }

    let outgoing_lookup_key = if state.outgoing_lookup_key == [0u8; HELLO_LOOKUP_KEY_LEN] {
        let channel_owner =
            channel::derive_owner_seed(me.channel_root, &identity, FIRST_GENERATION)?;
        let key = records.open_channel(&channel_owner, channel::CHANNEL_SUBKEYS)?;
        store.update_conv(&peer, |state| state.outgoing_lookup_key = key)?;
        key
    } else {
        state.outgoing_lookup_key
    };

    // The reply, turn 0 of this side's direction, committed with the record.
    let slot_bytes = outstanding_zero(store, &peer)?
        .ok_or(FlowError::Incomplete("outbox entry for the reply"))?;
    let (reply_header, _) = channel::MessageHeader::decode(&slot_bytes)?;
    let first_ratchet_pk = reply_header
        .kem_pk
        .clone()
        .ok_or(FlowError::Chain(ChainError::NoTurn))?;
    let reply_seq = reply_header.seq;

    // The acceptance's encapsulation and opening, minted once and persisted
    // before anything they enable is written, so a resumed run publishes the
    // opening the correspondent has already been told to expect.
    if state.own_opening.is_none() {
        let advert_owner = advert::derive_owner_seed(&identity)?;
        let bytes = records
            .read_advert(&advert_owner, advert::ADVERT_SUBKEYS)?
            .ok_or(FlowError::NoAdvert)?;
        let advert = advert::verify(&identity, &bytes)?;
        let encapsulation = advert::encapsulate_to(&advert, now, &mut *fill)?;
        let opening = ChannelOpening::build(
            me.signer,
            &identity,
            &outgoing_lookup_key,
            &first_ratchet_pk,
            encapsulation.serial,
        )?;
        let opening_bytes: Box<[u8; OPENING_LEN]> = opening
            .encode()
            .as_slice()
            .try_into()
            .map(Box::new)
            .expect("an opening encodes to OPENING_LEN bytes");
        let secret_bytes = Zeroizing::new(*encapsulation.shared_secret.as_bytes());
        let control_bytes =
            Zeroizing::new(*channel::control_key(&encapsulation.shared_secret)?.as_bytes());
        let kem_ct = encapsulation.ciphertext.clone();
        store.update_conv(&peer, |state| {
            state.own_control_key = Some(ControlKey::from_bytes(&control_bytes));
            state.own_hello_secret = Some(AdvertSharedSecret::from_bytes(&secret_bytes));
            state.own_hello_kem_ct = Some(kem_ct.clone());
            state.own_opening = Some(opening_bytes.clone());
        })?;
    }

    // The correspondent's ring from where this side left off, read on a copy
    // of the key schedule. Nothing of the read is persisted until the
    // acceptance is finished.
    let loaded_forced = state.conversation.sending.force_turn;
    let mut reader = Conversation::restore(state.conversation);
    let mut ring = Ring::restore(state.send_seq, state.peer_collected)?;
    let read = read_ring(
        records,
        &mut reader,
        &mut ring,
        &incoming,
        state.my_collected,
    )?;
    if let Some(slot) = slot {
        let my_drop = drop_plane::derive_owner_seed(me.signer.public_key())?;
        records.erase_drop_slot(&my_drop, drop_plane::DROP_SUBKEYS, slot)?;
    }

    // This side's opening and cursor, sealed under the key derived from the
    // secret this side's hello establishes, then the reply's slot.
    let state = load(store, &peer)?;
    let own_control_key = state
        .own_control_key
        .as_ref()
        .ok_or(FlowError::Incomplete("control key of its own"))?;
    let opening_bytes = state
        .own_opening
        .as_ref()
        .ok_or(FlowError::Incomplete("channel opening of its own"))?;
    let opening = ChannelOpening::decode(opening_bytes.as_slice())?;
    let advert_serial = opening.advert_serial;
    let control = channel::seal_control_with_key(
        own_control_key,
        &Control {
            opening: Some(opening),
            // The cursor already on disk, never the read above. That read is
            // recorded only when the acceptance finishes, and a cursor published
            // ahead of it would let the correspondent drop a message this side
            // has not recorded. The next collection batch publishes the cursor
            // the read reached.
            collected_cursor: state.my_collected,
            closed: false,
        },
    )?;
    records.write_channel(&outgoing_lookup_key, channel::CONTROL_SUBKEY, &control)?;
    records.write_channel(
        &outgoing_lookup_key,
        channel::slot_for(reply_seq),
        &slot_bytes,
    )?;

    // The hello back: the persisted bytes where a previous run placed it, and
    // a fresh placement otherwise.
    let (hello_slot, repicks) = match &state.outstanding_hello {
        Some(hello) => {
            let drop_owner = drop_plane::derive_owner_seed(&identity)?;
            records.write_drop_slot(
                &drop_owner,
                drop_plane::DROP_SUBKEYS,
                hello.slot,
                hello.sealed.as_slice(),
            )?;
            (hello.slot, 0)
        }
        None => {
            let own_secret = state
                .own_hello_secret
                .as_ref()
                .ok_or(FlowError::Incomplete("hello secret of its own"))?;
            let own_kem_ct = state
                .own_hello_kem_ct
                .as_ref()
                .ok_or(FlowError::Incomplete("hello encapsulation of its own"))?;
            let attempt = place_hello(
                store,
                records,
                &peer,
                &identity,
                &outgoing_lookup_key,
                &HelloSeal {
                    shared_secret: own_secret,
                    kem_ct: own_kem_ct,
                    advert_serial,
                    original: None,
                },
                HelloAttempt::new(drop_plane::repick(&mut *fill)?)?,
                fill,
            )?;
            (attempt.slot(), attempt.repicks())
        }
    };

    // The end of the acceptance, recorded together with the collection it read.
    let peer_collected = ring.peer_collected();
    store.update_conv(&peer, |state| {
        write_conversation(state, &reader, loaded_forced);
        state.my_collected = read.collected;
        state.peer_collected = state.peer_collected.max(peer_collected);
        state.acceptance_pending = false;
    })?;

    Ok(Accepted {
        peer,
        outgoing_lookup_key,
        bodies: read.bodies,
        hello_slot,
        repicks,
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
    let control_bytes = Zeroizing::new(*channel::control_key(&peer_secret)?.as_bytes());
    drop(peer_secret);
    // Refused here rather than at the load: this section is the first thing
    // the recognition changes, and before it the flow has only read the record.
    store.try_update_conv(peer, |state| {
        refuse_if_marked(state)?;
        state.incoming_lookup_key = *lookup_key;
        state.peer_control_key = Some(ControlKey::from_bytes(&control_bytes));
        Ok::<_, FlowError>(())
    })??;

    let loaded_forced = state.conversation.sending.force_turn;
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
    store.try_update_conv(peer, |state| {
        refuse_if_marked(state)?;
        write_conversation(state, &conversation, loaded_forced);
        state.my_collected = read.collected;
        state.peer_collected = ring.peer_collected();
        state.outstanding_hello = None;
        state.awaiting_acceptance = false;
        // The first contact is over, so no rewrite will carry this side's
        // hello secret again, and that secret roots this side's first turn.
        state.own_hello_secret = None;
        Ok::<_, FlowError>(())
    })??;
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

/// Reset every conversation — § Keys and forward secrecy, *Reset,
/// user-triggered*.
///
/// Sets the force-turn flag in every conversation record, so the next message
/// sent in each starts a new turn whatever has been read. Then rotates the
/// advert keys now ([`AdvertKeys::rotate_now`]) where the current key has been
/// published, which is where its serial is at or below the one
/// [`Store::mark_advert_published`] recorded, in the same critical section that
/// reads that serial. Where the current key has not been published, the
/// advert keys are left as they are: rotating again would retire a key nobody
/// has been told of and drop the one hellos in flight were encapsulated to. A
/// reset repeated, or run again after a stop part way, before the rotated key
/// is published therefore rotates once.
///
/// Each flag is persisted before the message it forces, and the rotated keys
/// before any advert naming them. Publication belongs to the runner's advert
/// poll, which republishes when the network record differs from the current
/// key. The identity key is not covered.
///
/// A profile that has never minted advert keys has nothing to rotate, so its
/// reset flags every conversation and succeeds. A conversation deleted between
/// the reset's load and its flag write is skipped, and the rest are flagged.
/// Two resets that land inside one flow's gap between its load and its write
/// count as one: a send whose seal consumed the flag drops a reset that arrived
/// after its load.
pub fn reset(
    store: &Store,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    now: u64,
) -> Result<(), FlowError> {
    for loaded in store.load()?.convs {
        match store.update_conv(&loaded.peer, |state| {
            state.conversation.sending.force_turn = true;
        }) {
            Ok(()) | Err(StoreError::MissingConversation) => {}
            Err(e) => return Err(e.into()),
        }
    }
    match store.update_advert_state(|keys, published| {
        if published.is_some_and(|serial| keys.serial() <= serial) {
            keys.rotate_now(now, &mut fill)
        } else {
            Ok(())
        }
    }) {
        Ok(rotated) => rotated?,
        Err(StoreError::MissingAdvertKeys) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Write a key schedule held in memory over its conversation record, keeping a
/// force-turn flag stored after the schedule was loaded.
///
/// A [`reset`] flags the stored record while a flow holds the schedule it
/// loaded, and a whole-schedule write would erase that flag. A flag stored
/// since the load is kept. Where the schedule was loaded flagged
/// (`loaded_forced`), the written schedule already carries the flag as far as
/// it got: still set, or cleared by the seal that started the forced turn.
fn write_conversation(state: &mut ConvState, written: &Conversation, loaded_forced: bool) {
    let mut snapshot = written.snapshot();
    snapshot.sending.force_turn |= state.conversation.sending.force_turn && !loaded_forced;
    state.conversation = snapshot;
}

/// Refuse, from inside the critical section that is about to change a
/// conversation record, a conversation a delete has marked since the flow
/// loaded it.
fn refuse_if_marked(state: &ConvState) -> Result<(), FlowError> {
    if state.delete_pending {
        Err(FlowError::DeletePending)
    } else {
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    /// Run once by [`send_message`] between its load and its write, so a test
    /// can land a change in that gap.
    static BETWEEN_SEND_LOAD_AND_WRITE: core::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { core::cell::RefCell::new(None) };
}

/// Send one ordinary message — § Flows, *Ordinary message*.
///
/// The ciphertext reaches disk, then the state that commits it, then the slot.
/// Exactly one write.
///
/// Refused with [`FlowError::AwaitingAcceptance`] while this side's own first
/// contact is unaccepted, because first contact carries sequence 0 and nothing
/// else, and while this side's acceptance of the correspondent's is not
/// finished, because the step that finishes it records the key schedule.
///
/// Refused with [`FlowError::DeletePending`] for a conversation marked for
/// delete: at the load, or at the commit where the mark lands after the load,
/// before the slot is written. A send refused at its commit has already
/// persisted its outbox entry. No launch lists that entry, because its
/// sequence is at or above the unchanged `send_seq`, and the delete removes
/// it.
///
/// `now` is the caller's clock in Unix seconds, recorded with the outbox entry
/// as the time the message was sent.
pub fn send_message<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
    body: &[u8],
    fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
    now: u64,
) -> Result<u64, FlowError> {
    let state = load(store, peer)?;
    if state.delete_pending {
        return Err(FlowError::DeletePending);
    }
    if state.awaiting_acceptance || state.acceptance_pending {
        return Err(FlowError::AwaitingAcceptance);
    }
    let lookup_key = state.outgoing_lookup_key;
    let loaded_forced = state.conversation.sending.force_turn;
    let mut conversation = Conversation::restore(state.conversation);
    let mut ring = Ring::restore(state.send_seq, state.peer_collected)?;
    let seq = ring.reserve()?;
    let (header, sealed) = conversation.seal(body, channel::DEVICE_ID_SINGLE_DEVICE, fill)?;
    let mut slot_bytes = header.encode();
    slot_bytes.extend_from_slice(&sealed);
    store.persist_outbox(peer, seq, &slot_bytes, now)?;
    #[cfg(test)]
    if let Some(hook) = BETWEEN_SEND_LOAD_AND_WRITE.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
    store.try_update_conv(peer, |state| {
        refuse_if_marked(state)?;
        write_conversation(state, &conversation, loaded_forced);
        state.send_seq = ring.send_seq();
        Ok::<_, FlowError>(())
    })??;
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
///
/// Refused with [`FlowError::AwaitingAcceptance`] while this side's acceptance
/// of the correspondent's first contact is not finished. The step that finishes
/// it records the collection and the key schedule, so a batch run before it
/// would record a read that step then overwrites, or record one it cannot
/// publish.
pub fn collect_batch<R: Records>(
    store: &Store,
    records: &mut R,
    peer: &CorrespondenceLabel,
) -> Result<Batch, FlowError> {
    let state = load(store, peer)?;
    if state.delete_pending {
        return Err(FlowError::DeletePending);
    }
    if state.acceptance_pending {
        return Err(FlowError::AwaitingAcceptance);
    }
    let incoming = state.incoming_lookup_key;
    let outgoing = state.outgoing_lookup_key;
    let loaded_forced = state.conversation.sending.force_turn;
    let mut conversation = Conversation::restore(state.conversation);
    let mut ring = Ring::restore(state.send_seq, state.peer_collected)?;
    let read = read_ring(
        records,
        &mut conversation,
        &mut ring,
        &incoming,
        state.my_collected,
    )?;
    store.try_update_conv(peer, |state| {
        refuse_if_marked(state)?;
        write_conversation(state, &conversation, loaded_forced);
        state.my_collected = read.collected;
        state.peer_collected = ring.peer_collected();
        Ok::<_, FlowError>(())
    })??;
    store.delete_outbox_through(peer, ring.peer_collected())?;

    if read.collected <= state.cursor_published {
        return Ok(Batch {
            bodies: read.bodies,
            my_collected: read.collected,
            cursor_published: false,
        });
    }
    let key = state
        .own_control_key
        .as_ref()
        .ok_or(FlowError::Incomplete("control key of its own"))?;
    let opening_bytes = state
        .own_opening
        .as_ref()
        .ok_or(FlowError::Incomplete("channel opening of its own"))?;
    let control = channel::seal_control_with_key(
        key,
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
    use crate::identity::keys::ML_DSA_SEED_LEN;
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
        /// Refuse every drop and channel read once this many writes have been
        /// performed, so a run stops after a write that landed and before
        /// whatever the flow persists next.
        refuse_reads_after: Option<usize>,
        /// Refuse to read any advert.
        refuse_adverts: bool,
        /// Every value ever written to a channel subkey, in order, overwritten
        /// versions included.
        channel_log: Vec<([u8; HELLO_LOOKUP_KEY_LEN], u16, Vec<u8>)>,
        /// Every value ever written to a drop slot, in order.
        drop_log: Vec<([u8; 32], u16, Vec<u8>)>,
        /// Every advert ever published, in order, with the owner seed that
        /// addresses it.
        advert_log: Vec<([u8; 32], Vec<u8>)>,
        /// The owner seed each channel record was opened under, by lookup
        /// key. A channel value is stored only when its writer is that seed,
        /// which is the check a substrate's schema makes of a value's writer
        /// against the record's owner.
        channel_owners: HashMap<[u8; HELLO_LOOKUP_KEY_LEN], [u8; channel::CHANNEL_OWNER_SEED_LEN]>,
        /// Run once, at the next read of a message subkey, so something can
        /// land between a flow's load and its write. Control reads pass it by:
        /// a collection reads a hello's opening before the flow it hands the
        /// hello to loads its record.
        before_message_read: Option<Box<dyn FnOnce()>>,
        /// Every channel subkey read, control and message alike.
        channel_reads: usize,
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
            self.advert_log.push((*owner.as_bytes(), bytes.clone()));
            self.adverts.insert(*owner.as_bytes(), bytes);
        }

        fn reset_writes(&mut self) {
            self.writes = Writes::default();
        }

        /// Write one channel subkey as the holder of `owner`.
        fn write_channel_as(
            &mut self,
            owner: &ChannelOwnerSeed,
            lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
            subkey: u16,
            bytes: &[u8],
        ) -> Result<(), RecordError> {
            self.write_owned(owner.as_bytes(), lookup_key, subkey, bytes)
        }

        /// One channel write by `writer`, refused before anything is charged
        /// or stored where `writer` is not the seed the record was opened
        /// under.
        fn write_owned(
            &mut self,
            writer: &[u8; channel::CHANNEL_OWNER_SEED_LEN],
            lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
            subkey: u16,
            bytes: &[u8],
        ) -> Result<(), RecordError> {
            if self.channel_owners.get(lookup_key) != Some(writer) {
                return Err(RecordError::new(Refused));
            }
            self.charge(bytes.len())?;
            self.channel_log.push((*lookup_key, subkey, bytes.to_vec()));
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

    impl Records for Net {
        fn read_advert(
            &mut self,
            owner: &AdvertOwnerSeed,
            subkeys: u16,
        ) -> Result<Option<Vec<u8>>, RecordError> {
            self.shapes.push(("advert", subkeys));
            if self.refuse_adverts {
                return Err(RecordError::new(Refused));
            }
            Ok(self.adverts.get(owner.as_bytes()).cloned())
        }

        fn read_drop_slot(
            &mut self,
            owner: &DropOwnerSeed,
            subkeys: u16,
            slot: u16,
        ) -> Result<Option<Vec<u8>>, RecordError> {
            self.shapes.push(("drop", subkeys));
            if self.unreadable_slot == Some(slot)
                || self
                    .refuse_reads_after
                    .is_some_and(|n| self.writes.total() >= n)
            {
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
            self.drop_log
                .push((*owner.as_bytes(), slot, bytes.to_vec()));
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
            let key = Self::lookup_key(owner);
            self.channel_owners.insert(key, *owner.as_bytes());
            Ok(key)
        }

        fn read_channel(
            &mut self,
            lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
            subkey: u16,
        ) -> Result<Option<Vec<u8>>, RecordError> {
            self.channel_reads += 1;
            if let Some(hook) = self
                .before_message_read
                .take_if(|_| subkey != channel::CONTROL_SUBKEY)
            {
                hook();
            }
            if self
                .refuse_reads_after
                .is_some_and(|n| self.writes.total() >= n)
            {
                return Err(RecordError::new(Refused));
            }
            Ok(self.channels.get(&(*lookup_key, subkey)).cloned())
        }

        fn write_channel(
            &mut self,
            lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
            subkey: u16,
            bytes: &[u8],
        ) -> Result<(), RecordError> {
            // Written as the owner the record was opened under, so a record no
            // owner has opened takes no write.
            let owner = self
                .channel_owners
                .get(lookup_key)
                .copied()
                .ok_or_else(|| RecordError::new(Refused))?;
            self.write_owned(&owner, lookup_key, subkey, bytes)
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
        channel_root: DmChannelRootSecret,
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
                // Distinct from the signing seed, as an identity's two secrets are.
                channel_root: DmChannelRootSecret::from_bytes([!byte; 32]),
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
                channel_root: &self.channel_root,
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
        let seq = send_message(
            &store_a,
            &mut net,
            &peer_a,
            b"an ordinary message",
            |x| entropy.fill(x),
            NOW,
        )
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
        send_message(
            &store_b,
            &mut net,
            &accepted.peer,
            b"another",
            |x| entropy.fill(x),
            NOW,
        )
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
        send_message(
            &store_b,
            &mut net,
            &accepted.peer,
            b"another",
            |x| entropy.fill(x),
            NOW,
        )
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

        let b_owner = channel::derive_owner_seed(&b.channel_root, a.pk(), FIRST_GENERATION)
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
            !b.channel_root.with_bytes(|root| contains(&image, root)),
            "B's channel root is in A's conversation record"
        );
        assert!(
            contains(&image, &own_dk),
            "A's own retained ratchet key is absent, so the search proves nothing"
        );
    }

    /// Once a first contact is accepted, neither conversation record holds a
    /// hello secret. The initiator's roots its first turn, so a record that
    /// kept it would let a copy of the device derive that turn for as long as
    /// the conversation lasts. The cursor and control paths still work from
    /// the stored control keys.
    #[test]
    fn no_hello_secret_survives_an_acceptance() {
        let (a, b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let before = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record");
        let ss0 = AdvertSharedSecret::from_bytes(
            before
                .own_hello_secret
                .as_ref()
                .expect("A holds its hello secret while awaiting acceptance")
                .as_bytes(),
        );
        // The control: the same search finds the secret before acceptance.
        assert!(
            contains(&encode_conv(&before), ss0.as_bytes()),
            "A's hello secret is absent before acceptance, so the search proves nothing"
        );

        let accepted = b_accepts(&b, &mut net, b"the reply");
        // B's hello back secret, recovered the way A recovers it.
        let a_drop = drop_plane::derive_owner_seed(a.pk()).expect("A's drop");
        let (slot, hello_back) = net
            .drops
            .iter()
            .find(|((owner, _), _)| owner == a_drop.as_bytes())
            .map(|((_, slot), bytes)| (*slot, bytes.clone()))
            .expect("B's hello back is in A's drop");
        let (_, ss_b, _) = open_against_either(&a.advert_keys, &hello_back, a.pk(), slot)
            .expect("B's hello back opens");
        collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");

        let image_a = encode_conv(
            &a.store()
                .load_conv(&peer_a)
                .expect("load")
                .expect("A's record"),
        );
        let image_b = encode_conv(
            &b.store()
                .load_conv(&accepted.peer)
                .expect("load")
                .expect("B's record"),
        );
        for (side, image) in [("A", &image_a), ("B", &image_b)] {
            assert!(
                !contains(image, ss0.as_bytes()),
                "{side}'s record holds A's hello secret after acceptance"
            );
            assert!(
                !contains(image, ss_b.as_bytes()),
                "{side}'s record holds B's hello secret after acceptance"
            );
        }

        // Both control subkeys still seal and open from the stored keys.
        let mut entropy = Seeded::at(31);
        send_message(
            &b.store(),
            &mut net,
            &accepted.peer,
            b"another",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B sends");
        let batch = collect_batch(&a.store(), &mut net, &peer_a).expect("A collects a batch");
        assert!(batch.cursor_published, "A published its cursor");
        assert_eq!(
            peer_cursor(&b.store(), &mut net, &accepted.peer).expect("B reads A's cursor"),
            Some(batch.my_collected)
        );
        // B's first batch publishes the collection its acceptance recorded.
        collect_batch(&b.store(), &mut net, &accepted.peer).expect("B collects a batch");
        assert_eq!(
            peer_cursor(&a.store(), &mut net, &peer_a).expect("A reads B's cursor"),
            Some(1),
            "B's first batch published its cursor over A's first message"
        );
    }

    /// Every 32-byte window of `bytes`.
    fn windows_of(bytes: &[u8]) -> HashSet<[u8; 32]> {
        bytes
            .windows(32)
            .map(|w| <[u8; 32]>::try_from(w).expect("a 32-byte window"))
            .collect()
    }

    /// Whether any 32-byte window of `key` is among `windows`.
    fn any_window_of(key: &[u8], windows: &HashSet<[u8; 32]>) -> bool {
        key.windows(32)
            .any(|w| windows.contains(&<[u8; 32]>::try_from(w).expect("a 32-byte window")))
    }

    /// Whether `reader` opens one captured message.
    fn opens(reader: &mut Conversation, bytes: &[u8]) -> bool {
        let (header, sealed) = channel::MessageHeader::decode(bytes).expect("a message header");
        reader.open(&header, sealed).is_ok()
    }

    /// **FC5** (design § Founding claims). No record a whole conversation writes holds either identity
    /// public key or any 32-byte window of one, and a third identity opens
    /// none of them.
    ///
    /// The values scanned are every value written through `Records` by the
    /// core flows in this conversation, overwritten versions included, with
    /// the runner's writes out of scope: a first contact stopped before its
    /// hello and carried on, its hello resumed and then refreshed across a
    /// rotation, an acceptance stopped after its hello back and continued, and
    /// messages and cursors each way. To those are added a closed marker sealed
    /// the way the delete flow seals one, and each advert either party
    /// publishes. An erase writes no bytes, so it adds nothing to scan. Record
    /// addresses are hash-derived rather than written values; each advert is
    /// checked to sit at its owner's derived seed and to verify under that
    /// owner's identity key.
    #[test]
    fn no_record_a_conversation_writes_carries_an_identity_key() {
        let (a, mut b, mut net) = scene();

        // A first contact stopped before its hello, and carried on from the
        // record.
        net.fail_after = Some(2);
        let mut entropy = Seeded::at(4_242);
        assert!(
            first_contact(
                &a.store(),
                &mut net,
                &a.me(),
                b.pk(),
                b"the first message",
                |x| entropy.fill(x),
                NOW,
            )
            .is_err(),
            "the first contact must stop before its hello"
        );
        net.fail_after = None;
        let peer_a = a.store().load().expect("load").convs[0].peer;
        let mut entropy = Seeded::at(5_353);
        continue_first_contact(&a.store(), &mut net, &peer_a, |x| entropy.fill(x))
            .expect("the first contact is carried on");

        // The hello resumed, then rewritten after the correspondent rotates
        // its advert.
        assert!(
            matches!(
                resume_first_contact(&a.store(), &mut net, &peer_a).expect("A resumes"),
                Resumed::Rewrote(_)
            ),
            "the resume wrote no hello"
        );
        let at = NOW + advert::ROTATION_PERIOD_SECS;
        rotate(&mut b, &mut net, at, 2_020);
        assert!(a_refreshes(&a, &mut net, &peer_a, at, 3_030).expect("the refresh runs"));

        // The acceptance with a reply, stopped after its hello back lands and
        // continued from the record, which rewrites the persisted hello back.
        let request = only_request(b_collects(&b, &mut net));
        let store_b = b.store();
        net.reset_writes();
        net.refuse_reads_after = Some(4);
        let mut entropy = Seeded::at(909);
        assert!(
            accept(
                &store_b,
                &mut net,
                &b.me(),
                &request,
                b"the reply",
                |x| entropy.fill(x),
                NOW,
            )
            .is_err(),
            "the acceptance must stop after its hello back"
        );
        net.refuse_reads_after = None;
        let b_peer = store_b.load().expect("load").convs[0].peer;
        let mut entropy = Seeded::at(5_454);
        let accepted = continue_acceptance(
            &store_b,
            &mut net,
            &b.me(),
            &b_peer,
            |x| entropy.fill(x),
            NOW,
        )
        .expect("the acceptance is continued");
        assert_eq!(
            net.writes.hello, 2,
            "the continued acceptance did not rewrite its hello back"
        );
        let written = &net.hellos_written;
        assert_eq!(
            written[written.len() - 1],
            written[written.len() - 2],
            "the hello back was not rewritten byte for byte"
        );
        // B's reading half as the acceptance left it, before B reads any of
        // A's later messages.
        let b_after_accept = store_b
            .load_conv(&b_peer)
            .expect("load")
            .expect("B's record");

        // The acceptance recognised.
        let surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        assert!(
            matches!(surfaced.as_slice(), [Surfaced::Accepted(_)]),
            "expected one acceptance, got {surfaced:?}"
        );

        // Several messages each way, each side's cursor published by a batch.
        for round in 0..3u64 {
            let mut entropy = Seeded::at(100 + round);
            send_message(
                &a.store(),
                &mut net,
                &peer_a,
                b"from A",
                |x| entropy.fill(x),
                NOW,
            )
            .expect("A sends");
            assert!(
                collect_batch(&b.store(), &mut net, &accepted.peer)
                    .expect("B collects")
                    .cursor_published,
                "round {round}: B published no cursor"
            );
            let mut entropy = Seeded::at(200 + round);
            send_message(
                &b.store(),
                &mut net,
                &accepted.peer,
                b"from B",
                |x| entropy.fill(x),
                NOW,
            )
            .expect("B sends");
            assert!(
                collect_batch(&a.store(), &mut net, &peer_a)
                    .expect("A collects")
                    .cursor_published,
                "round {round}: A published no cursor"
            );
        }

        // A's teardown writes a closed marker into its control subkey.
        let state = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record");
        let opening =
            ChannelOpening::decode(state.own_opening.as_ref().expect("A's opening").as_slice())
                .expect("decode A's opening");
        let erase = crate::dm::delivery::prepare_delete(&a.store(), &peer_a, true)
            .expect("prepare the delete");
        let marker = channel::seal_control_with_key(
            state.own_control_key.as_ref().expect("A's control key"),
            &erase
                .marker
                .expect("a closed marker")
                .control(Some(opening.clone())),
        )
        .expect("seal the closed marker");
        net.write_channel(&erase.lookup_key, channel::CONTROL_SUBKEY, &marker)
            .expect("write the closed marker");

        let captured: Vec<(&str, &[u8])> = net
            .channel_log
            .iter()
            .map(|(_, _, v)| ("channel", v.as_slice()))
            .chain(net.drop_log.iter().map(|(_, _, v)| ("drop", v.as_slice())))
            .chain(net.advert_log.iter().map(|(_, v)| ("advert", v.as_slice())))
            .collect();
        // Non-vacuous: every kind is captured, and so are the earlier versions
        // of the subkeys that were rewritten.
        for kind in ["channel", "drop", "advert"] {
            assert!(
                captured.iter().any(|(k, _)| *k == kind),
                "no {kind} record was captured"
            );
        }
        assert!(
            net.channel_log.len() > net.channels.len(),
            "no channel subkey was rewritten, so no earlier version was captured"
        );
        assert!(
            net.drop_log.len() >= 5,
            "the hello, its resumed and refreshed rewrites, the hello back and its rewrite \
             were not all captured"
        );

        for (kind, bytes) in &captured {
            let windows = windows_of(bytes);
            for (name, identity) in [("A", a.pk()), ("B", b.pk())] {
                assert!(
                    !contains(bytes, identity),
                    "{name}'s identity key appears in a {kind} record"
                );
                assert!(
                    !any_window_of(identity, &windows),
                    "a 32-byte window of {name}'s identity key appears in a {kind} record"
                );
            }
        }

        // The control: the same two scans find A's key in A's control record
        // before it is sealed.
        let plaintext = Control {
            opening: Some(opening),
            collected_cursor: 0,
            closed: false,
        }
        .encode();
        assert!(
            contains(&plaintext, a.pk()),
            "the whole-key scan misses a key that is there"
        );
        assert!(
            any_window_of(a.pk(), &windows_of(&plaintext)),
            "the window scan misses a key that is there"
        );

        // Each advert sits at the owner seed derived from exactly one party's
        // identity key, and verifies under that key and not the other's.
        let mut published = [0usize; 2];
        for (owner, bytes) in &net.advert_log {
            let sits_at = |party: &Party| {
                advert::derive_owner_seed(party.pk())
                    .expect("an advert owner")
                    .as_bytes()
                    == owner
            };
            let (index, party, other) = match (sits_at(&a), sits_at(&b)) {
                (true, false) => (0, &a, &b),
                (false, true) => (1, &b, &a),
                found => panic!("an advert sits at the owner seeds of (A, B) = {found:?}"),
            };
            advert::verify(party.pk(), bytes)
                .expect("an advert does not verify under its owner's identity key");
            assert!(
                advert::verify(other.pk(), bytes).is_err(),
                "an advert verifies under the other party's identity key"
            );
            published[index] += 1;
        }
        assert_eq!(
            published,
            [1, 2],
            "A's advert and B's two were not all checked"
        );

        // A third identity with real keys of every kind: its own advert keys,
        // and the control keys and key schedule of a conversation it holds
        // with a fourth identity on a network of their own.
        let c = Party::new(0xc3);
        let d = Party::new(0xd4);
        let mut elsewhere = Net::default();
        c.publish(&mut elsewhere);
        d.publish(&mut elsewhere);
        let (peer_c, accepted_d) = round_trip(&c, &d, &mut elsewhere);
        let mut entropy = Seeded::at(300);
        send_message(
            &d.store(),
            &mut elsewhere,
            &accepted_d.peer,
            b"from D",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("D sends");
        collect_batch(&c.store(), &mut elsewhere, &peer_c).expect("C collects");
        let c_state = c
            .store()
            .load_conv(&peer_c)
            .expect("load")
            .expect("C's record");
        // Every hello's encapsulation decapsulated under C's own advert key,
        // which implicit rejection answers with a secret rather than an error.
        let decapsulated: Vec<ControlKey> = net
            .drop_log
            .iter()
            .filter_map(|(_, _, bytes)| {
                let ciphertext =
                    <&[u8; ml_kem::CT_LEN]>::try_from(bytes.get(..ml_kem::CT_LEN)?).ok()?;
                let secret = c
                    .advert_keys
                    .decapsulate(c.advert_keys.serial(), ciphertext)
                    .ok()??;
                channel::control_key(&secret).ok()
            })
            .collect();
        let c_keys: Vec<&ControlKey> = [&c_state.own_control_key, &c_state.peer_control_key]
            .into_iter()
            .flatten()
            .chain(&decapsulated)
            .collect();
        assert_eq!(
            c_keys.len(),
            2 + net.drop_log.len(),
            "the third identity holds fewer control keys than it should"
        );
        let b_state = b
            .store()
            .load_conv(&b_peer)
            .expect("load")
            .expect("B's record");
        let party_keys: Vec<&ControlKey> = [
            &state.own_control_key,
            &state.peer_control_key,
            &b_state.own_control_key,
            &b_state.peer_control_key,
        ]
        .into_iter()
        .flatten()
        .collect();

        let (controls, messages): (Vec<_>, Vec<_>) = net
            .channel_log
            .iter()
            .partition(|(_, subkey, _)| *subkey == channel::CONTROL_SUBKEY);
        assert!(
            !controls.is_empty() && !messages.is_empty(),
            "no control or no message was captured"
        );

        // Channel controls.
        for (_, _, control) in &controls {
            for key in &c_keys {
                assert!(
                    channel::open_control_with_key(key, control).is_err(),
                    "a control record opened with the third identity's keys"
                );
            }
        }
        assert!(
            controls.iter().any(|(_, _, control)| party_keys
                .iter()
                .any(|key| channel::open_control_with_key(key, control).is_ok())),
            "the control: no control record opened with the parties' own keys"
        );

        // Channel messages.
        for (_, _, message) in &messages {
            let (header, _) = channel::MessageHeader::decode(message).expect("a message header");
            let mut snapshot = c
                .store()
                .load_conv(&peer_c)
                .expect("load")
                .expect("C's record")
                .conversation;
            snapshot.receiving.next_seq = header.seq;
            assert!(
                !opens(&mut Conversation::restore(snapshot), message),
                "a message opened with the third identity's key schedule"
            );
        }
        let mut a_to_b = std::collections::BTreeMap::new();
        for (key, _, bytes) in &messages {
            if *key == state.outgoing_lookup_key {
                let (header, _) = channel::MessageHeader::decode(bytes).expect("a message header");
                a_to_b.entry(header.seq).or_insert_with(|| bytes.clone());
            }
        }
        let mut b_reader = Conversation::restore(b_after_accept.conversation);
        let next = b_reader.receiving().next_seq();
        let mut opened = 0;
        for bytes in a_to_b.range(next..).map(|(_, bytes)| bytes) {
            if opens(&mut b_reader, bytes) {
                opened += 1;
            }
        }
        assert!(
            opened >= 1,
            "the control: B's reading half opened none of A's messages"
        );

        // Drop hellos.
        for (_, slot, bytes) in &net.drop_log {
            for pk in [c.pk(), a.pk(), b.pk()] {
                assert!(
                    open_against_either(&c.advert_keys, bytes, pk, *slot).is_none(),
                    "a hello opened with the third identity's advert keys"
                );
            }
        }
        let b_drop = *drop_plane::derive_owner_seed(b.pk())
            .expect("B's drop")
            .as_bytes();
        assert!(
            net.drop_log.iter().any(|(owner, slot, bytes)| {
                let recipient = if *owner == b_drop { &b } else { &a };
                open_against_either(&recipient.advert_keys, bytes, recipient.pk(), *slot).is_some()
            }),
            "the control: no hello opened with its recipient's advert keys"
        );
    }

    /// A channel subkey is written only under the owner seed its record was
    /// opened with, as a substrate's schema refuses a value whose writer is
    /// not the record's owner. A write to A's channel under B's owner seed is
    /// refused and changes nothing, and so is a write to a channel no owner
    /// opened. A's own writes land.
    #[test]
    fn a_channel_write_under_another_owner_seed_is_refused() {
        let (a, b, mut net) = scene();
        let a_owner = channel::derive_owner_seed(&a.channel_root, b.pk(), FIRST_GENERATION)
            .expect("A's channel owner");
        let b_owner = channel::derive_owner_seed(&b.channel_root, a.pk(), FIRST_GENERATION)
            .expect("B's channel owner");
        let a_channel = net
            .open_channel(&a_owner, channel::CHANNEL_SUBKEYS)
            .expect("A opens its channel");
        net.open_channel(&b_owner, channel::CHANNEL_SUBKEYS)
            .expect("B opens its channel");

        assert!(
            net.write_channel_as(&b_owner, &a_channel, channel::slot_for(0), b"from B")
                .is_err(),
            "a write under B's owner seed landed in A's channel"
        );
        let unopened = [0x3cu8; HELLO_LOOKUP_KEY_LEN];
        assert!(
            net.write_channel(&unopened, channel::slot_for(0), b"from nobody")
                .is_err(),
            "a write to a channel no owner opened landed"
        );
        assert!(
            net.channels.is_empty() && net.channel_log.is_empty(),
            "a refused write changed the network"
        );
        assert_eq!(net.writes, Writes::default(), "a refused write was counted");

        // The control: A's own writes land, under its seed and through the
        // record store.
        net.write_channel_as(&a_owner, &a_channel, channel::slot_for(0), b"from A")
            .expect("A writes under its own seed");
        net.write_channel(&a_channel, channel::slot_for(1), b"from A again")
            .expect("A writes its own channel");
        assert_eq!(
            net.channels
                .get(&(a_channel, channel::slot_for(0)))
                .map(Vec::as_slice),
            Some(&b"from A"[..]),
            "A's own write did not land"
        );
        assert_eq!(
            net.channel_log.len(),
            2,
            "A's two writes were not both recorded"
        );
    }

    /// Put a party's advert keys in its store, which a reset rotates.
    fn persist_advert_keys(party: &Party) {
        party
            .store()
            .persist_advert_keys(&party.advert_keys.snapshot())
            .expect("persist the advert keys");
    }

    /// Whether the message a party's outbox holds at `seq` starts a turn.
    fn starts_turn(party: &Party, peer: &CorrespondenceLabel, seq: u64) -> bool {
        let bytes = party
            .store()
            .load()
            .expect("load")
            .convs
            .into_iter()
            .find(|c| &c.peer == peer)
            .expect("the correspondence")
            .outstanding_outbox
            .into_iter()
            .find(|e| e.seq == seq)
            .expect("the message is owed")
            .ciphertext;
        channel::MessageHeader::decode(&bytes)
            .expect("a message header")
            .0
            .starts_turn()
    }

    /// A reset — § Keys and forward secrecy, *Reset, user-triggered* — flags
    /// every conversation and rotates a published advert, both persisted. Read
    /// back from disk, the next message in each conversation starts a turn,
    /// and the correspondent opens it.
    #[test]
    fn a_reset_forces_a_turn_in_every_conversation_and_rotates_the_advert() {
        let (a, b, mut net) = scene();
        let c = Party::new(0xc3);
        c.publish(&mut net);
        persist_advert_keys(&a);

        // A opens to B, and accepts C's first contact.
        let (peer_b, accepted_b) = round_trip(&a, &b, &mut net);
        a_opens(&c, &a, &mut net, b"from C");
        let request = only_request(
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects"),
        );
        let mut entropy = Seeded::at(606);
        let peer_c = accept(
            &a.store(),
            &mut net,
            &a.me(),
            &request,
            b"to C",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A accepts C")
        .peer;
        let surfaced =
            collect(&c.store(), &mut net, &c.me(), &c.advert_keys, |_| false).expect("C collects");
        let c_peer = match surfaced.as_slice() {
            [Surfaced::Accepted(acceptance)] => acceptance.peer,
            other => panic!("expected C's acceptance, got {other:?}"),
        };

        // Without a reset, a message sent after one that started or continued
        // a turn, with nothing read in between, continues that turn.
        let send = |store: &Store, net: &mut Net, peer: &CorrespondenceLabel, seed: u64| {
            let mut entropy = Seeded::at(seed);
            send_message(store, net, peer, b"a message", |x| entropy.fill(x), NOW).expect("A sends")
        };
        send(&a.store(), &mut net, &peer_b, 700);
        let continuing_b = send(&a.store(), &mut net, &peer_b, 701);
        let continuing_c = send(&a.store(), &mut net, &peer_c, 702);
        assert!(
            !starts_turn(&a, &peer_b, continuing_b),
            "the control: with nothing read, A's second message to B continues the turn"
        );
        assert!(
            !starts_turn(&a, &peer_c, continuing_c),
            "the control: A's first message to C continues the acceptance's turn"
        );

        let serial_before = a
            .store()
            .load_advert_keys()
            .expect("load")
            .expect("A's advert keys")
            .serial;
        a.store()
            .mark_advert_published(serial_before)
            .expect("A's advert is published");
        let mut entropy = Seeded::at(808);
        reset(&a.store(), |x| entropy.fill(x), NOW + 60).expect("the reset");

        // Every step from here opens A's store afresh from its directory, and
        // no party holds a store between steps, so each reads only what the
        // reset persisted.
        let rotated = AdvertKeys::restore(
            a.store()
                .load_advert_keys()
                .expect("load")
                .expect("A's advert keys"),
        );
        assert!(
            rotated.serial() > serial_before,
            "the advert did not rotate"
        );
        assert_eq!(
            rotated.previous_serial(),
            Some(serial_before),
            "the rotation did not retain the previous key"
        );
        let forced_b = send(&a.store(), &mut net, &peer_b, 703);
        let forced_c = send(&a.store(), &mut net, &peer_c, 704);
        assert!(
            starts_turn(&a, &peer_b, forced_b),
            "the message to B continued the turn"
        );
        assert!(
            starts_turn(&a, &peer_c, forced_c),
            "the message to C continued the turn"
        );

        // The forced turn consumed each flag, so the message after it
        // continues that turn.
        assert!(
            !flagged(&a, &peer_b) && !flagged(&a, &peer_c),
            "a forced send left its record flagged"
        );
        let after_b = send(&a.store(), &mut net, &peer_b, 705);
        let after_c = send(&a.store(), &mut net, &peer_c, 706);
        assert!(
            !starts_turn(&a, &peer_b, after_b),
            "the message after the forced one to B started another turn"
        );
        assert!(
            !starts_turn(&a, &peer_c, after_c),
            "the message after the forced one to C started another turn"
        );

        // Each correspondent opens everything A sent it, the forced turn
        // included.
        let batch = collect_batch(&b.store(), &mut net, &accepted_b.peer).expect("B collects");
        assert_eq!(
            batch.bodies.len(),
            4,
            "B opened {} of A's four messages",
            batch.bodies.len()
        );
        let batch = collect_batch(&c.store(), &mut net, &c_peer).expect("C collects");
        assert_eq!(
            batch.bodies.len(),
            3,
            "C opened {} of A's three messages",
            batch.bodies.len()
        );
    }

    /// Whether a party's record for `peer` holds the force-turn flag.
    fn flagged(party: &Party, peer: &CorrespondenceLabel) -> bool {
        party
            .store()
            .load_conv(peer)
            .expect("load")
            .expect("a record")
            .conversation
            .sending
            .force_turn
    }

    /// A reset rotates the advert only once its current key has been
    /// published. Before that it flags and leaves the advert keys as they are,
    /// so a second reset before the rotated key is published keeps the key
    /// hellos in flight were encapsulated to. Once the rotated key is published,
    /// a reset rotates again.
    #[test]
    fn a_reset_rotates_only_an_advert_key_that_has_been_published() {
        let (a, b, mut net) = scene();
        persist_advert_keys(&a);
        let (peer_a, _) = round_trip(&a, &b, &mut net);
        let keys = || {
            a.store()
                .load_advert_keys()
                .expect("load")
                .expect("A's advert keys")
        };
        let clear_flag = || {
            a.store()
                .update_conv(&peer_a, |state| {
                    state.conversation.sending.force_turn = false;
                })
                .expect("clear the flag");
        };
        let mut entropy = Seeded::at(730);
        let mut reset_a = |at: u64| reset(&a.store(), |x| entropy.fill(x), at).expect("the reset");
        let first = keys().serial;

        // Never published: the reset flags and does not rotate.
        reset_a(NOW + 60);
        assert_eq!(
            keys().serial,
            first,
            "a reset rotated a key never published"
        );
        assert!(flagged(&a, &peer_a), "the reset did not flag");

        // Published: the reset rotates, retaining the published key.
        a.store().mark_advert_published(first).expect("mark");
        clear_flag();
        reset_a(NOW + 61);
        let once = keys();
        assert_eq!(once.serial, first + 1, "the published key did not rotate");
        assert_eq!(once.previous.as_ref().map(|p| p.serial), Some(first));
        assert!(flagged(&a, &peer_a), "the rotating reset did not flag");

        // Again before the rotated key is published: flagged, not rotated.
        clear_flag();
        reset_a(NOW + 62);
        let twice = keys();
        assert_eq!(twice.serial, first + 1, "a second reset rotated again");
        assert_eq!(
            twice.previous.as_ref().map(|p| p.serial),
            Some(first),
            "a second reset dropped the key hellos in flight were encapsulated to"
        );
        assert!(flagged(&a, &peer_a), "the second reset did not flag");

        // The rotated key published: the next reset rotates again.
        a.store().mark_advert_published(first + 1).expect("mark");
        reset_a(NOW + 63);
        let again = keys();
        assert_eq!(
            again.serial,
            first + 2,
            "a reset after the rotated key was published did not rotate"
        );
        assert_eq!(again.previous.as_ref().map(|p| p.serial), Some(first + 1));
    }

    /// A reset that lands while a collection batch holds the key schedule it
    /// loaded is not erased by the batch's write.
    #[test]
    fn a_reset_during_a_collection_batch_keeps_its_flag() {
        let (a, b, mut net) = scene();
        persist_advert_keys(&a);
        let (peer_a, accepted) = round_trip(&a, &b, &mut net);
        let mut entropy = Seeded::at(740);
        send_message(
            &b.store(),
            &mut net,
            &accepted.peer,
            b"from B",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B sends");
        assert!(
            !flagged(&a, &peer_a),
            "the control: nothing is flagged before the reset"
        );

        // The reset runs at the batch's first message read, after its load and
        // before its write.
        net.before_message_read = Some(Box::new(reset_of(&a, 741)));
        let batch = collect_batch(&a.store(), &mut net, &peer_a).expect("A collects");
        assert!(
            net.before_message_read.is_none(),
            "the reset did not run inside the batch"
        );
        assert_eq!(batch.bodies.len(), 1, "A read B's message");
        assert!(
            flagged(&a, &peer_a),
            "the batch's write erased the flag the reset stored"
        );
    }

    /// A reset of `party`'s store, opened afresh from its directory, to land
    /// inside another flow.
    fn reset_of(party: &Party, seed: u64) -> impl FnOnce() + 'static {
        let root = party.root.path().to_path_buf();
        let at_rest = party.at_rest;
        move || {
            let store = Store::open(root, &at_rest).expect("open the store");
            let mut entropy = Seeded::at(seed);
            reset(&store, |x| entropy.fill(x), NOW + 60).expect("the reset");
        }
    }

    /// A reset that lands while an acceptance holds the key schedule it loaded
    /// is not erased by the write that finishes the acceptance.
    #[test]
    fn a_reset_during_an_acceptance_keeps_its_flag() {
        let (a, b, mut net) = scene();
        persist_advert_keys(&b);
        a_opens(&a, &b, &mut net, b"the first message");
        let request = only_request(b_collects(&b, &mut net));

        // The reset runs at the acceptance's read of A's ring, after its load
        // and before its write.
        net.before_message_read = Some(Box::new(reset_of(&b, 760)));
        let mut entropy = Seeded::at(909);
        let accepted = accept(
            &b.store(),
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B accepts");
        assert!(
            net.before_message_read.is_none(),
            "the reset did not run inside the acceptance"
        );
        assert_eq!(accepted.bodies, vec![b"the first message".to_vec()]);
        assert!(
            flagged(&b, &accepted.peer),
            "the acceptance's write erased the flag the reset stored"
        );
    }

    /// A reset that lands while the recognition of an acceptance holds the key
    /// schedule it loaded is not erased by the recognition's write.
    #[test]
    fn a_reset_during_the_recognition_of_an_acceptance_keeps_its_flag() {
        let (a, b, mut net) = scene();
        persist_advert_keys(&a);
        let peer_a = opened_peer(&a_opens(&a, &b, &mut net, b"the first message"));
        b_accepts(&b, &mut net, b"the reply");

        // The reset runs at the recognition's read of B's ring, after its load
        // and before its write.
        net.before_message_read = Some(Box::new(reset_of(&a, 770)));
        let surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        assert!(
            net.before_message_read.is_none(),
            "the reset did not run inside the recognition"
        );
        match surfaced.as_slice() {
            [Surfaced::Accepted(acceptance)] => {
                assert_eq!(acceptance.bodies, vec![b"the reply".to_vec()]);
            }
            other => panic!("expected one acceptance, got {other:?}"),
        }
        assert!(
            flagged(&a, &peer_a),
            "the recognition's write erased the flag the reset stored"
        );
    }

    /// A reset that lands while a send holds the key schedule it loaded is not
    /// erased by the send's write, and the send after it starts a turn.
    #[test]
    fn a_reset_during_a_send_keeps_its_flag() {
        let (a, b, mut net) = scene();
        persist_advert_keys(&a);
        let (peer_a, _) = round_trip(&a, &b, &mut net);

        let hook = reset_of(&a, 780);
        BETWEEN_SEND_LOAD_AND_WRITE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        let mut entropy = Seeded::at(781);
        send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"from A",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A sends");
        assert!(
            BETWEEN_SEND_LOAD_AND_WRITE.with(|slot| slot.borrow().is_none()),
            "the reset did not run inside the send"
        );
        assert!(
            flagged(&a, &peer_a),
            "the send's write erased the flag the reset stored"
        );

        let mut entropy = Seeded::at(782);
        let next = send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"from A again",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A sends again");
        assert!(
            starts_turn(&a, &peer_a, next),
            "the send after the reset continued a turn"
        );
    }

    /// A reset in a profile that has never minted advert keys flags every
    /// conversation and succeeds, writing no advert keys.
    #[test]
    fn a_reset_without_advert_keys_flags_and_succeeds() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);
        assert!(
            a.store().load_advert_keys().expect("load").is_none(),
            "the control: A's store holds no advert keys"
        );
        let mut entropy = Seeded::at(790);
        reset(&a.store(), |x| entropy.fill(x), NOW + 60)
            .expect("a reset with nothing to rotate succeeds");
        assert!(flagged(&a, &peer_a), "the reset did not flag");
        assert!(
            a.store().load_advert_keys().expect("load").is_none(),
            "the reset wrote advert keys"
        );
    }

    /// A reset while a first contact awaits its acceptance, and while the
    /// correspondent's acceptance is not finished, flags both records. The
    /// flags survive the steps that finish the first contact, and each side's
    /// next message starts a turn, which the other opens.
    #[test]
    fn a_reset_during_a_first_contact_flags_both_sides() {
        let (a, b, mut net) = scene();
        persist_advert_keys(&a);
        persist_advert_keys(&b);
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let request = only_request(b_collects(&b, &mut net));

        // B's acceptance stops after its hello back lands.
        net.reset_writes();
        net.refuse_reads_after = Some(4);
        let mut entropy = Seeded::at(909);
        assert!(
            accept(
                &b.store(),
                &mut net,
                &b.me(),
                &request,
                b"the reply",
                |x| entropy.fill(x),
                NOW,
            )
            .is_err(),
            "the acceptance must stop after its hello back"
        );
        net.refuse_reads_after = None;
        let b_peer = b.store().load().expect("load").convs[0].peer;
        let record = |party: &Party, peer: &CorrespondenceLabel| {
            party
                .store()
                .load_conv(peer)
                .expect("load")
                .expect("a record")
        };
        assert!(
            record(&a, &peer_a).awaiting_acceptance,
            "the control: A awaits its acceptance"
        );
        assert!(
            record(&b, &b_peer).acceptance_pending,
            "the control: B's acceptance is not finished"
        );

        let mut entropy = Seeded::at(750);
        reset(&a.store(), |x| entropy.fill(x), NOW + 60).expect("A's reset");
        reset(&b.store(), |x| entropy.fill(x), NOW + 60).expect("B's reset");
        assert!(flagged(&a, &peer_a), "A's reset did not flag");
        assert!(flagged(&b, &b_peer), "B's reset did not flag");

        // B finishes its acceptance, and A recognises it.
        let mut entropy = Seeded::at(751);
        continue_acceptance(
            &b.store(),
            &mut net,
            &b.me(),
            &b_peer,
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B finishes the acceptance");
        let surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        assert!(
            matches!(surfaced.as_slice(), [Surfaced::Accepted(_)]),
            "expected one acceptance, got {surfaced:?}"
        );
        assert!(
            flagged(&a, &peer_a),
            "recognising the acceptance erased A's flag"
        );
        assert!(
            flagged(&b, &b_peer),
            "finishing the acceptance erased B's flag"
        );

        // Each side's next message starts a turn, and the other opens it.
        let mut entropy = Seeded::at(752);
        let from_b = send_message(
            &b.store(),
            &mut net,
            &b_peer,
            b"from B",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B sends");
        assert!(
            starts_turn(&b, &b_peer, from_b),
            "B's first message after its reset continued its reply's turn"
        );
        let from_a = send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"from A",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A sends");
        assert!(
            starts_turn(&a, &peer_a, from_a),
            "A's first message after its reset continued a turn"
        );
        assert_eq!(
            collect_batch(&a.store(), &mut net, &peer_a)
                .expect("A collects")
                .bodies,
            vec![b"from B".to_vec()]
        );
        assert_eq!(
            collect_batch(&b.store(), &mut net, &b_peer)
                .expect("B collects")
                .bodies,
            vec![b"from A".to_vec()]
        );
    }

    /// The core half of deleting a conversation. `prepare_delete` marks the
    /// record delete-pending and names a closed marker that carries this side's
    /// cursor and seals and opens as closed; `finish_delete` then removes the
    /// conversation record and an outbox still owing a message. Writing the
    /// marker and erasing the channel are the transport's, and are not
    /// exercised here. A later hello from the correspondent, who has started
    /// over, is a new first contact: a contact request rather than a
    /// start-over, accepted into a working conversation.
    #[test]
    fn the_core_half_of_a_delete_marks_names_the_marker_and_drops_the_records() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);

        // A message B never collects, so the outbox the delete removes still
        // owes one.
        let mut entropy = Seeded::at(918);
        let never = send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"never collected",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A sends");
        let record_file = |kind: crate::storage::dm_store::RecordKind| {
            a.store()
                .records()
                .root()
                .join(hex::encode(peer_a.as_bytes()))
                .join(kind.file_name())
        };
        let conversation_file = record_file(crate::storage::dm_store::RecordKind::Conversation);
        let outbox_file = record_file(crate::storage::dm_store::RecordKind::ConversationOutbox);
        assert!(
            conversation_file.exists() && outbox_file.exists(),
            "the control: both records are on disk"
        );
        // Two owed: A's first message, owed until A reads a cursor past it,
        // and the message B never collects.
        let owed: Vec<u64> = a.store().load().expect("load").convs[0]
            .outstanding_outbox
            .iter()
            .map(|entry| entry.seq)
            .collect();
        assert_eq!(
            owed,
            vec![0, never],
            "the control: the outbox owes the first message and the new one"
        );
        let state = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record");

        let erase = crate::dm::delivery::prepare_delete(&a.store(), &peer_a, true)
            .expect("prepare the delete");
        assert_eq!(erase.lookup_key, state.outgoing_lookup_key);
        assert!(
            a.store()
                .load_conv(&peer_a)
                .expect("load")
                .expect("A's record")
                .delete_pending,
            "prepare_delete did not mark the record"
        );
        assert_eq!(
            a.store().pending_deletes().expect("pending deletes"),
            vec![peer_a]
        );
        let own_key = state.own_control_key.as_ref().expect("A's control key");
        let opening =
            ChannelOpening::decode(state.own_opening.as_ref().expect("A's opening").as_slice())
                .expect("decode A's opening");
        let marker = channel::seal_control_with_key(
            own_key,
            &erase
                .marker
                .expect("a closed marker")
                .control(Some(opening)),
        )
        .expect("seal the closed marker");
        let sealed = channel::open_control_with_key(own_key, &marker).expect("the marker opens");
        assert!(sealed.closed, "the marker is not closed");
        assert_eq!(
            sealed.collected_cursor, state.my_collected,
            "the marker does not carry this side's cursor"
        );

        crate::dm::delivery::finish_delete(&a.store(), &peer_a).expect("drop the records");
        assert!(
            !conversation_file.exists(),
            "the conversation record survived the delete"
        );
        assert!(
            !outbox_file.exists(),
            "an outbox still owing a message survived the delete"
        );
        assert!(
            a.store().load().expect("load").convs.is_empty(),
            "a launch still reads a conversation to poll"
        );
        assert!(
            a.store()
                .pending_deletes()
                .expect("pending deletes")
                .is_empty(),
            "the mark outlived the delete"
        );

        // Re-contact derives the same channel records the deleted conversation
        // used, so both old channels are cleared here rather than left for the
        // new conversation to read.
        net.channels.retain(|(key, _), _| {
            *key != state.outgoing_lookup_key && *key != state.incoming_lookup_key
        });

        // B starts over under the same identity, and its hello reaches A as a
        // new first contact.
        let b_again = Party::new(0xb2);
        b_again.publish(&mut net);
        assert_eq!(
            b_again.pk().as_slice(),
            b.pk().as_slice(),
            "the control: B starts over under the same identity"
        );
        a_opens(&b_again, &a, &mut net, b"hello again");
        let request = only_request(
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects"),
        );
        assert_eq!(request.identity.as_slice(), b.pk().as_slice());

        let mut entropy = Seeded::at(919);
        let accepted = accept(
            &a.store(),
            &mut net,
            &a.me(),
            &request,
            b"welcome back",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A accepts the new first contact");
        assert_eq!(accepted.bodies, vec![b"hello again".to_vec()]);
        assert_eq!(
            a.store().load().expect("load").convs.len(),
            1,
            "A holds one conversation after the new first contact"
        );
        let surfaced = collect(
            &b_again.store(),
            &mut net,
            &b_again.me(),
            &b_again.advert_keys,
            |_| false,
        )
        .expect("B collects");
        match surfaced.as_slice() {
            [Surfaced::Accepted(acceptance)] => {
                assert_eq!(acceptance.bodies, vec![b"welcome back".to_vec()]);
            }
            other => panic!("expected B's acceptance, got {other:?}"),
        }
    }

    /// Collection and the published cursor stop at a slot missing from the
    /// middle of the ring, and carry on past it once it is written back.
    #[test]
    fn collection_and_the_cursor_stop_at_a_missing_slot_until_it_is_rewritten() {
        let (a, b, mut net) = scene();
        let (peer_a, accepted) = round_trip(&a, &b, &mut net);
        let mut entropy = Seeded::at(930);
        let mut seqs = Vec::new();
        for body in [b"one".as_slice(), b"two", b"three"] {
            seqs.push(
                send_message(
                    &a.store(),
                    &mut net,
                    &peer_a,
                    body,
                    |x| entropy.fill(x),
                    NOW,
                )
                .expect("A sends"),
            );
        }
        let lookup_key = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record")
            .outgoing_lookup_key;
        let gap = (lookup_key, channel::slot_for(seqs[1]));
        let held = net
            .channels
            .remove(&gap)
            .expect("the middle slot was written");

        let batch = collect_batch(&b.store(), &mut net, &accepted.peer).expect("B collects");
        assert_eq!(
            batch.bodies,
            vec![b"one".to_vec()],
            "collection went past the missing slot"
        );
        assert_eq!(
            batch.my_collected, seqs[1],
            "the cursor counted past the missing slot"
        );
        assert_eq!(
            peer_cursor(&a.store(), &mut net, &peer_a).expect("A reads B's cursor"),
            Some(seqs[1]),
            "the published cursor counted past the missing slot"
        );

        net.channels.insert(gap, held);
        let batch = collect_batch(&b.store(), &mut net, &accepted.peer).expect("B collects");
        assert_eq!(batch.bodies, vec![b"two".to_vec(), b"three".to_vec()]);
        assert_eq!(batch.my_collected, seqs[2] + 1);
        assert_eq!(
            peer_cursor(&a.store(), &mut net, &peer_a).expect("A reads B's cursor"),
            Some(seqs[2] + 1)
        );
    }

    /// A conversation marked for delete refuses a send, a collection batch
    /// and the recognition of its acceptance, and a delete that finishes takes
    /// the mark with the record.
    #[test]
    fn a_conversation_marked_for_delete_refuses_to_send_or_collect() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);
        let mut entropy = Seeded::at(940);
        send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"before",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("the control: A sends before the mark");

        crate::dm::delivery::prepare_delete(&a.store(), &peer_a, true).expect("prepare");
        let before = untouched(&a, &peer_a);
        net.reset_writes();
        net.channel_reads = 0;
        assert!(
            matches!(
                send_message(
                    &a.store(),
                    &mut net,
                    &peer_a,
                    b"after",
                    |x| entropy.fill(x),
                    NOW
                ),
                Err(FlowError::DeletePending)
            ),
            "a marked conversation took a send"
        );
        assert!(
            matches!(
                collect_batch(&a.store(), &mut net, &peer_a),
                Err(FlowError::DeletePending)
            ),
            "a marked conversation took a collection batch"
        );
        assert_eq!(net.writes.total(), 0, "a refused flow wrote");
        assert_eq!(net.channel_reads, 0, "a refused flow read the ring");
        assert_eq!(
            untouched(&a, &peer_a),
            before,
            "a refused flow changed the record or the outbox"
        );
        crate::dm::delivery::finish_delete(&a.store(), &peer_a).expect("finish");
        assert!(
            a.store()
                .pending_deletes()
                .expect("pending deletes")
                .is_empty(),
            "the mark outlived the delete"
        );

        // A first contact marked for delete before its acceptance is
        // recognised: the recognition refuses and changes nothing.
        let (c, d, mut net) = scene();
        let peer_c = opened_peer(&a_opens(&c, &d, &mut net, b"the first message"));
        b_accepts(&d, &mut net, b"the reply");
        crate::dm::delivery::prepare_delete(&c.store(), &peer_c, false).expect("prepare");
        let before = untouched(&c, &peer_c);
        net.reset_writes();
        let surfaced =
            collect(&c.store(), &mut net, &c.me(), &c.advert_keys, |_| false).expect("C collects");
        assert!(
            matches!(
                surfaced.as_slice(),
                [Surfaced::Failed {
                    error: FlowError::DeletePending,
                    ..
                }]
            ),
            "a marked first contact's acceptance was not refused: {surfaced:?}"
        );
        assert!(
            c.store()
                .load_conv(&peer_c)
                .expect("load")
                .expect("C's record")
                .awaiting_acceptance,
            "the refused recognition changed the record"
        );
        assert_eq!(net.writes.total(), 0, "the refused recognition wrote");
        assert_eq!(
            untouched(&c, &peer_c),
            before,
            "the refused recognition changed the record or the outbox"
        );
    }

    /// What a refused flow must leave as it was: the bytes on disk of the
    /// conversation record and of the outbox record. Each record is sealed
    /// under a fresh nonce whenever it is written, so a rewrite that changes no
    /// field still changes these bytes.
    type Untouched = (Option<Vec<u8>>, Option<Vec<u8>>);

    fn untouched(party: &Party, peer: &CorrespondenceLabel) -> Untouched {
        let dir = party
            .store()
            .records()
            .root()
            .join(hex::encode(peer.as_bytes()));
        let read = |kind: crate::storage::dm_store::RecordKind| {
            std::fs::read(dir.join(kind.file_name())).ok()
        };
        (
            read(crate::storage::dm_store::RecordKind::Conversation),
            read(crate::storage::dm_store::RecordKind::ConversationOutbox),
        )
    }

    /// A delete of `peer`'s conversation in `party`'s store, opened afresh from
    /// its directory, to land inside another flow.
    fn delete_of(party: &Party, peer: CorrespondenceLabel) -> impl FnOnce() + 'static {
        let root = party.root.path().to_path_buf();
        let at_rest = party.at_rest;
        move || {
            let store = Store::open(root, &at_rest).expect("open the store");
            crate::dm::delivery::prepare_delete(&store, &peer, true).expect("mark the delete");
        }
    }

    /// Every outbox entry carries the `now` the flow that sealed it was given:
    /// a first contact's first message, an acceptance's reply and an ordinary
    /// message, each read back from disk.
    #[test]
    fn each_outbox_entry_records_the_time_it_was_sent() {
        let (a, b, mut net) = scene();
        let mut entropy = Seeded::at(4_242);
        let outcome = first_contact(
            &a.store(),
            &mut net,
            &a.me(),
            b.pk(),
            b"the first message",
            |x| entropy.fill(x),
            NOW + 1,
        )
        .expect("A's first contact");
        let peer_a = opened_peer(&outcome);
        let request = only_request(b_collects(&b, &mut net));
        let mut entropy = Seeded::at(909);
        let accepted = accept(
            &b.store(),
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW + 2,
        )
        .expect("B accepts");
        let sent_at = |party: &Party, peer: &CorrespondenceLabel| -> Vec<(u64, u64)> {
            party
                .store()
                .load()
                .expect("load")
                .convs
                .into_iter()
                .find(|conv| &conv.peer == peer)
                .expect("the conversation")
                .outstanding_outbox
                .iter()
                .map(|entry| (entry.seq, entry.sent_at))
                .collect()
        };
        assert_eq!(
            sent_at(&a, &peer_a),
            vec![(0, NOW + 1)],
            "A's first message"
        );
        assert_eq!(sent_at(&b, &accepted.peer), vec![(0, NOW + 2)], "B's reply");

        collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        let mut entropy = Seeded::at(4_343);
        let seq = send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"later",
            |x| entropy.fill(x),
            NOW + 3,
        )
        .expect("A sends");
        let owed = sent_at(&a, &peer_a);
        assert!(
            owed.contains(&(seq, NOW + 3)),
            "A's ordinary message does not carry its send time: {owed:?}"
        );
    }

    /// Nothing in core tears a conversation down because a message has waited
    /// past a nudge threshold. Ten years after A's message to B was sent, every
    /// flow that takes a clock runs on A's store with that clock, beside a
    /// collection, a collection batch and a cursor read. A's conversation with
    /// B keeps its record, its owed message and no delete mark; its channel's
    /// control record and the owed message's slot are still on the network; and
    /// no control record written to that channel is a closed marker. A
    /// conversation's records are removed only by `delivery::finish_delete`,
    /// and marked only by `delivery::prepare_delete`, both of which a caller
    /// asks for.
    #[test]
    fn nothing_in_core_tears_down_a_conversation_past_the_nudge_threshold() {
        let (mut a, b, mut net) = scene();
        let mut c = Party::new(0xc3);
        let mut d = Party::new(0xd4);
        c.publish(&mut net);
        d.publish(&mut net);
        persist_advert_keys(&a);
        let (peer_b, _) = round_trip(&a, &b, &mut net);
        let mut entropy = Seeded::at(1_020);
        let owed = send_message(
            &a.store(),
            &mut net,
            &peer_b,
            b"never collected",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A sends");
        let own = a
            .store()
            .load_conv(&peer_b)
            .expect("load")
            .expect("A's record");
        let day = 24 * 60 * 60;
        let threshold = 7 * day;
        let later = NOW + 10 * 365 * day;
        let aged = a
            .store()
            .load()
            .expect("load")
            .convs
            .into_iter()
            .find(|conv| conv.peer == peer_b)
            .expect("A's conversation");
        assert!(
            crate::dm::delivery::nudge_due(
                crate::dm::delivery::oldest_uncollected_at(&aged),
                later,
                threshold,
            ),
            "the control: the message is past the threshold"
        );

        // Every advert a flow below encapsulates to is rotated at `later`, so
        // those flows run rather than stopping at an expired advert.
        rotate(&mut a, &mut net, later, 1_022);
        rotate(&mut c, &mut net, later, 1_023);
        rotate(&mut d, &mut net, later, 1_024);

        collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        collect_batch(&a.store(), &mut net, &peer_b).expect("A collects a batch");
        peer_cursor(&a.store(), &mut net, &peer_b).expect("A reads B's cursor");
        let mut entropy = Seeded::at(1_025);
        send_message(
            &a.store(),
            &mut net,
            &peer_b,
            b"still here",
            |x| entropy.fill(x),
            later,
        )
        .expect("A sends ten years on");
        reset(&a.store(), |x| entropy.fill(x), later).expect("A resets");
        let _ = crate::dm::delivery::next_poll_interval(NOW, later, |x| entropy.fill(x));

        // A first contact from A to C, and its refresh.
        let to_c = first_contact(
            &a.store(),
            &mut net,
            &a.me(),
            c.pk(),
            b"to C",
            |x| entropy.fill(x),
            later,
        )
        .expect("A's first contact to C");
        refresh_first_contact(
            &a.store(),
            &mut net,
            &opened_peer(&to_c),
            |x| entropy.fill(x),
            later,
        )
        .expect("A refreshes its first contact to C");

        // D's first contact to A, accepted by A in a run stopped at its first
        // write and continued from the record.
        let mut d_entropy = Seeded::at(1_026);
        first_contact(
            &d.store(),
            &mut net,
            &d.me(),
            a.pk(),
            b"from D",
            |x| d_entropy.fill(x),
            later,
        )
        .expect("D's first contact to A");
        let request = collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false)
            .expect("A collects D's hello")
            .into_iter()
            .find_map(|surfaced| match surfaced {
                Surfaced::ContactRequest(request) => Some(request),
                _ => None,
            })
            .expect("D's contact request");
        net.reset_writes();
        net.fail_after = Some(0);
        assert!(
            accept(
                &a.store(),
                &mut net,
                &a.me(),
                &request,
                b"to D",
                |x| entropy.fill(x),
                later,
            )
            .is_err(),
            "the acceptance must stop at its first write"
        );
        net.fail_after = None;
        let peer_d = a
            .store()
            .load()
            .expect("load")
            .convs
            .into_iter()
            .find(|conv| conv.state.peer_identity_pk.as_slice() == d.pk().as_slice())
            .expect("A's record for D")
            .peer;
        continue_acceptance(
            &a.store(),
            &mut net,
            &a.me(),
            &peer_d,
            |x| entropy.fill(x),
            later,
        )
        .expect("A continues its acceptance of D");

        let after = a
            .store()
            .load()
            .expect("load")
            .convs
            .into_iter()
            .find(|conv| conv.peer == peer_b)
            .expect("A's conversation with B survived");
        assert!(
            !after.state.delete_pending,
            "a flow marked the conversation for delete"
        );
        assert!(
            after
                .outstanding_outbox
                .iter()
                .any(|entry| entry.seq == owed),
            "the message owed past the threshold was dropped"
        );
        assert!(
            a.store()
                .pending_deletes()
                .expect("pending deletes")
                .is_empty(),
            "a delete is pending"
        );
        assert!(
            net.channels
                .contains_key(&(own.outgoing_lookup_key, channel::CONTROL_SUBKEY)),
            "A's channel to B lost its control record"
        );
        assert!(
            net.channels
                .contains_key(&(own.outgoing_lookup_key, channel::slot_for(owed))),
            "the owed message's slot left the network"
        );
        let own_key = own.own_control_key.as_ref().expect("A's control key");
        let controls: Vec<&Vec<u8>> = net
            .channel_log
            .iter()
            .filter(|(key, subkey, _)| {
                *key == own.outgoing_lookup_key && *subkey == channel::CONTROL_SUBKEY
            })
            .map(|(_, _, bytes)| bytes)
            .collect();
        assert!(
            !controls.is_empty(),
            "the control: A wrote control records to its channel to B"
        );
        for bytes in controls {
            assert!(
                !channel::open_control_with_key(own_key, bytes)
                    .expect("A's control record opens")
                    .closed,
                "a closed marker was written to A's channel to B"
            );
        }
    }

    /// A send refused at its commit and tried again later is a new message:
    /// its outbox entry takes the retry's `now`, not the refused attempt's.
    #[test]
    fn a_send_refused_at_its_commit_is_resealed_with_the_retrys_time() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);
        let hook = delete_of(&a, peer_a);
        BETWEEN_SEND_LOAD_AND_WRITE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        let mut entropy = Seeded::at(1_030);
        let refused = send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"first try",
            |x| entropy.fill(x),
            NOW + 10,
        );
        assert!(
            matches!(refused, Err(FlowError::DeletePending)),
            "the control: the first attempt was refused at its commit"
        );
        let seq = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record")
            .send_seq;
        let raw = a
            .store()
            .records()
            .critical_section::<_, crate::storage::dm_store::DmStoreError>(&peer_a, |g| {
                g.read(crate::storage::dm_store::RecordKind::ConversationOutbox)
            })
            .expect("read the outbox record")
            .expect("an outbox record");
        let table = crate::dm::store::decode_conv_outbox(&raw).expect("decode the outbox");
        assert_eq!(
            table[(seq % channel::RING_SLOTS) as usize]
                .as_ref()
                .map(|entry| (entry.seq, entry.sent_at)),
            Some((seq, NOW + 10)),
            "the control: the refused attempt persisted its entry at the sequence the retry reuses"
        );

        // The mark is cleared so the retry commits.
        a.store()
            .update_conv(&peer_a, |state| state.delete_pending = false)
            .expect("clear the mark");
        let resent = send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"second try",
            |x| entropy.fill(x),
            NOW + 500,
        )
        .expect("the retry sends");
        assert_eq!(resent, seq, "the retry did not reuse the sequence");
        let entry = a
            .store()
            .load()
            .expect("load")
            .convs
            .into_iter()
            .find(|conv| conv.peer == peer_a)
            .expect("A's conversation")
            .outstanding_outbox
            .into_iter()
            .find(|entry| entry.seq == seq)
            .expect("the retry's entry is owed");
        assert_eq!(
            entry.sent_at,
            NOW + 500,
            "the retry kept the refused attempt's send time"
        );
    }

    /// A hello from a correspondent who started over is surfaced carrying the
    /// request an acceptance proceeds from. `accept` refuses that request while
    /// the old conversation's record is there, and once the old conversation is
    /// deleted it accepts the same request into the new conversation, reading
    /// the correspondent's new first message.
    #[test]
    fn a_started_over_hello_is_accepted_once_the_old_conversation_is_deleted() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);

        // B's second hello is built by hand at the next generation, because no
        // flow turns the generation over yet; for the same reason the deleted
        // conversation's channel record is cleared below, since the new
        // conversation derives it again.
        let restart_key = plant_started_over_hello(&mut net, &b, &a, b"starting over", 6_161);

        let mut surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        assert_eq!(surfaced.len(), 1, "one hello in A's drop");
        let request = match surfaced.remove(0) {
            Surfaced::StartedOver { identity, request } => {
                assert_eq!(identity.as_slice(), b.pk().as_slice());
                request
            }
            other => panic!("expected B to have started over, got {other:?}"),
        };
        assert_eq!(request.identity.as_slice(), b.pk().as_slice());
        assert_eq!(request.lookup_key, restart_key);

        // The control: the old conversation is still there, so the request is
        // refused, nothing is written and the old record is as it was.
        let old = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record");
        let before = untouched(&a, &peer_a);
        net.reset_writes();
        let mut entropy = Seeded::at(6_262);
        assert!(
            matches!(
                accept(
                    &a.store(),
                    &mut net,
                    &a.me(),
                    &request,
                    b"welcome back",
                    |x| entropy.fill(x),
                    NOW,
                ),
                Err(FlowError::AlreadyEstablished)
            ),
            "a started-over request was accepted over the old conversation"
        );
        assert_eq!(net.writes.total(), 0, "the refused acceptance wrote");
        let kept = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record");
        assert_eq!(
            a.store().load().expect("load").convs.len(),
            1,
            "the refused acceptance created a conversation"
        );
        assert_eq!(untouched(&a, &peer_a), before);
        assert_eq!(kept.outgoing_lookup_key, old.outgoing_lookup_key);
        assert!(
            old.own_hello_secret.is_none() && kept.own_hello_secret.is_none(),
            "the control: A's record holds no hello secret before or after"
        );

        let erase = crate::dm::delivery::prepare_delete(&a.store(), &peer_a, false)
            .expect("prepare the delete");
        net.channels.retain(|(key, _), _| *key != erase.lookup_key);
        crate::dm::delivery::finish_delete(&a.store(), &peer_a).expect("finish the delete");

        let accepted = accept(
            &a.store(),
            &mut net,
            &a.me(),
            &request,
            b"welcome back",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A accepts B's new first contact");
        assert_eq!(accepted.bodies, vec![b"starting over".to_vec()]);
        let convs = a.store().load().expect("load").convs;
        assert_eq!(convs.len(), 1, "A holds one conversation with B");
        assert_eq!(convs[0].state.incoming_lookup_key, restart_key);
        let a_drop = drop_plane::derive_owner_seed(a.pk()).expect("A's drop");
        assert!(
            !net.drops.contains_key(&(*a_drop.as_bytes(), request.slot)),
            "the accepted hello's drop slot was not erased"
        );
    }

    /// Place by hand a first contact from `from` to `to` under `from`'s next
    /// channel generation, because no flow turns the generation over yet: an
    /// opening over a real first ratchet key, message 0 carrying `body`, and
    /// the hello in `to`'s drop. Returns the new channel's lookup key.
    fn plant_started_over_hello(
        net: &mut Net,
        from: &Party,
        to: &Party,
        body: &[u8],
        seed: u64,
    ) -> [u8; HELLO_LOOKUP_KEY_LEN] {
        let mut entropy = Seeded::at(seed);
        let encapsulation = advert::encapsulate_to(
            &advert::verify(
                to.pk(),
                &to.advert_keys
                    .advert_bytes(&to.signer)
                    .expect("the recipient's advert"),
            )
            .expect("verify the recipient's advert"),
            NOW,
            |x| entropy.fill(x),
        )
        .expect("encapsulate to the recipient");
        let owner = channel::derive_owner_seed(&from.channel_root, to.pk(), FIRST_GENERATION + 1)
            .expect("the next channel owner");
        let restart_key = net
            .open_channel(&owner, channel::CHANNEL_SUBKEYS)
            .expect("open the next channel");
        let opened = chain::initiate(&encapsulation.shared_secret, |x| entropy.fill(x))
            .expect("the key schedule");
        let opening = ChannelOpening::build(
            &from.signer,
            to.pk(),
            &restart_key,
            &opened.ratchet_pk,
            encapsulation.serial,
        )
        .expect("the opening");
        let control = channel::seal_control(
            &encapsulation.shared_secret,
            &Control {
                opening: Some(opening),
                collected_cursor: 0,
                closed: false,
            },
        )
        .expect("seal the control");
        net.write_channel(&restart_key, channel::CONTROL_SUBKEY, &control)
            .expect("write the control");
        let mut conversation = opened.conversation;
        let (header, sealed) = conversation
            .seal(body, channel::DEVICE_ID_SINGLE_DEVICE, |x| entropy.fill(x))
            .expect("seal message 0");
        let mut slot_bytes = header.encode();
        slot_bytes.extend_from_slice(&sealed);
        net.write_channel(&restart_key, channel::slot_for(0), &slot_bytes)
            .expect("write message 0");
        let r = drop_plane::repick(|x| entropy.fill(x)).expect("r");
        let hello = drop_plane::seal_hello(&encapsulation, &restart_key, &r, to.pk())
            .expect("seal the hello");
        let drop_owner = drop_plane::derive_owner_seed(to.pk()).expect("the recipient's drop");
        net.write_drop_slot(
            &drop_owner,
            drop_plane::DROP_SUBKEYS,
            drop_plane::slot_for(&r).expect("slot"),
            &hello,
        )
        .expect("write the hello");
        restart_key
    }

    /// A started-over request is not carried into an acceptance of the same
    /// identity that stopped part way: `accept` refuses it, writes nothing,
    /// leaves the pending record as it was, and leaves the new hello in its
    /// slot.
    #[test]
    fn a_started_over_request_is_not_finished_into_a_pending_acceptance() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let request = only_request(b_collects(&b, &mut net));
        // B's acceptance stops at its first write.
        net.reset_writes();
        net.fail_after = Some(0);
        let mut entropy = Seeded::at(909);
        assert!(
            accept(
                &b.store(),
                &mut net,
                &b.me(),
                &request,
                b"the reply",
                |x| entropy.fill(x),
                NOW,
            )
            .is_err(),
            "the acceptance must stop short"
        );
        net.fail_after = None;
        let b_peer = b.store().load().expect("load").convs[0].peer;
        let pending = b
            .store()
            .load_conv(&b_peer)
            .expect("load")
            .expect("B's record");
        assert!(
            pending.acceptance_pending,
            "the control: B's acceptance is pending"
        );

        // A's second hello is built by hand at the next generation, because no
        // flow turns the generation over yet.
        let restart_key = plant_started_over_hello(&mut net, &a, &b, b"starting over", 6_363);
        let started_over = collect(&b.store(), &mut net, &b.me(), &b.advert_keys, |_| false)
            .expect("B collects")
            .into_iter()
            .find_map(|surfaced| match surfaced {
                Surfaced::StartedOver { request, .. } => Some(request),
                _ => None,
            })
            .expect("A's second hello surfaced as started over");
        assert_eq!(started_over.lookup_key, restart_key);
        assert_ne!(started_over.lookup_key, pending.incoming_lookup_key);

        let before = untouched(&b, &b_peer);
        net.reset_writes();
        let mut entropy = Seeded::at(6_464);
        assert!(
            matches!(
                accept(
                    &b.store(),
                    &mut net,
                    &b.me(),
                    &started_over,
                    b"the reply",
                    |x| entropy.fill(x),
                    NOW,
                ),
                Err(FlowError::AlreadyEstablished)
            ),
            "a started-over request was carried into a pending acceptance"
        );
        assert_eq!(net.writes.total(), 0, "the refused acceptance wrote");
        assert_eq!(untouched(&b, &b_peer), before);
        assert!(
            b.store()
                .load_conv(&b_peer)
                .expect("load")
                .expect("B's record")
                .acceptance_pending,
            "the refused acceptance changed the pending record"
        );
        let b_drop = drop_plane::derive_owner_seed(b.pk()).expect("B's drop");
        assert!(
            net.drops
                .contains_key(&(*b_drop.as_bytes(), started_over.slot)),
            "the refused acceptance erased the new hello"
        );
    }

    /// A delete mark on one conversation refuses nothing on the others in the
    /// same store: an established one still sends and collects, and a first
    /// contact stopped part way is still carried on.
    #[test]
    fn a_delete_mark_on_one_conversation_leaves_the_others_working() {
        let (a, b, mut net) = scene();
        let c = Party::new(0xc3);
        let d = Party::new(0xd4);
        c.publish(&mut net);
        d.publish(&mut net);
        let (peer_b, accepted_b) = round_trip(&a, &b, &mut net);
        let (peer_d, _) = round_trip(&a, &d, &mut net);

        // A's first contact to C lands its opening and stops.
        net.reset_writes();
        net.fail_after = Some(1);
        let mut entropy = Seeded::at(1_010);
        assert!(
            first_contact(
                &a.store(),
                &mut net,
                &a.me(),
                c.pk(),
                b"to C",
                |x| entropy.fill(x),
                NOW,
            )
            .is_err(),
            "the first contact to C must stop short"
        );
        net.fail_after = None;
        let peer_c = a
            .store()
            .load()
            .expect("load")
            .convs
            .into_iter()
            .find(|conv| conv.state.peer_identity_pk.as_slice() == c.pk().as_slice())
            .expect("A's record for C")
            .peer;

        crate::dm::delivery::prepare_delete(&a.store(), &peer_d, true).expect("mark D's delete");
        assert_eq!(
            a.store().pending_deletes().expect("pending deletes"),
            vec![peer_d],
            "the control: exactly one conversation is marked"
        );

        let mut entropy = Seeded::at(1_011);
        send_message(
            &a.store(),
            &mut net,
            &peer_b,
            b"to B",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("a send on an unmarked conversation");
        send_message(
            &b.store(),
            &mut net,
            &accepted_b.peer,
            b"from B",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B sends");
        assert_eq!(
            collect_batch(&a.store(), &mut net, &peer_b)
                .expect("a batch on an unmarked conversation")
                .bodies,
            vec![b"from B".to_vec()]
        );
        continue_first_contact(&a.store(), &mut net, &peer_c, |x| entropy.fill(x))
            .expect("a relaunch of an unmarked first contact");
    }

    /// A first contact marked for delete before it finished is not carried on:
    /// the continuation a relaunch runs writes nothing and changes nothing.
    #[test]
    fn a_first_contact_marked_for_delete_is_not_carried_on() {
        let (a, b, mut net) = scene();
        // The opening lands and the first message slot is refused.
        net.fail_after = Some(1);
        let mut entropy = Seeded::at(950);
        assert!(
            first_contact(
                &a.store(),
                &mut net,
                &a.me(),
                b.pk(),
                b"the first message",
                |x| entropy.fill(x),
                NOW,
            )
            .is_err(),
            "the first contact must stop short"
        );
        net.fail_after = None;
        let peer_a = a.store().load().expect("load").convs[0].peer;
        crate::dm::delivery::prepare_delete(&a.store(), &peer_a, false).expect("prepare");
        let before = untouched(&a, &peer_a);
        net.reset_writes();

        let mut entropy = Seeded::at(951);
        assert!(
            matches!(
                continue_first_contact(&a.store(), &mut net, &peer_a, |x| entropy.fill(x)),
                Err(FlowError::DeletePending)
            ),
            "a marked first contact was carried on"
        );
        assert_eq!(net.writes.total(), 0, "the refused continuation wrote");
        assert_eq!(
            untouched(&a, &peer_a),
            before,
            "the refused continuation changed the record or the outbox"
        );
    }

    /// A first contact marked for delete republishes no hello: neither the
    /// rewrite of the persisted hello nor its refresh after the correspondent's
    /// advert rotates writes anything.
    #[test]
    fn a_first_contact_marked_for_delete_republishes_no_hello() {
        let (a, mut b, mut net) = scene();
        let peer_a = opened_peer(&a_opens(&a, &b, &mut net, b"the first message"));
        let at = NOW + advert::ROTATION_PERIOD_SECS;
        rotate(&mut b, &mut net, at, 2_020);
        crate::dm::delivery::prepare_delete(&a.store(), &peer_a, false).expect("prepare");
        let before = untouched(&a, &peer_a);
        net.reset_writes();

        assert!(
            matches!(
                resume_first_contact(&a.store(), &mut net, &peer_a),
                Err(FlowError::DeletePending)
            ),
            "a marked first contact's hello was rewritten"
        );
        assert!(
            matches!(
                a_refreshes(&a, &mut net, &peer_a, at, 3_030),
                Err(FlowError::DeletePending)
            ),
            "a marked first contact's hello was refreshed"
        );
        assert_eq!(net.writes.total(), 0, "a refused hello was written");
        assert_eq!(untouched(&a, &peer_a), before);
    }

    /// An acceptance marked for delete before it finished is not carried on,
    /// whether a relaunch continues it from the record or the request is
    /// accepted again.
    #[test]
    fn an_acceptance_marked_for_delete_is_not_carried_on() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let request = only_request(b_collects(&b, &mut net));
        // The acceptance stops at its first write.
        net.reset_writes();
        net.fail_after = Some(0);
        let mut entropy = Seeded::at(909);
        assert!(
            accept(
                &b.store(),
                &mut net,
                &b.me(),
                &request,
                b"the reply",
                |x| entropy.fill(x),
                NOW,
            )
            .is_err(),
            "the acceptance must stop short"
        );
        net.fail_after = None;
        let b_peer = b.store().load().expect("load").convs[0].peer;
        assert!(
            b.store()
                .load_conv(&b_peer)
                .expect("load")
                .expect("B's record")
                .acceptance_pending,
            "the control: B's acceptance is not finished"
        );
        crate::dm::delivery::prepare_delete(&b.store(), &b_peer, false).expect("prepare");
        let before = untouched(&b, &b_peer);
        net.reset_writes();

        let mut entropy = Seeded::at(960);
        assert!(
            matches!(
                accept(
                    &b.store(),
                    &mut net,
                    &b.me(),
                    &request,
                    b"the reply",
                    |x| entropy.fill(x),
                    NOW,
                ),
                Err(FlowError::DeletePending)
            ),
            "a marked acceptance was accepted again"
        );
        assert!(
            matches!(
                continue_acceptance(
                    &b.store(),
                    &mut net,
                    &b.me(),
                    &b_peer,
                    |x| entropy.fill(x),
                    NOW,
                ),
                Err(FlowError::DeletePending)
            ),
            "a marked acceptance was continued"
        );
        assert_eq!(net.writes.total(), 0, "a refused acceptance wrote");
        assert_eq!(untouched(&b, &b_peer), before);
    }

    /// A delete marked while a send holds the state it loaded stops the send at
    /// its commit, before its slot is written.
    #[test]
    fn a_delete_marked_during_a_send_stops_it_before_its_write() {
        let (a, b, mut net) = scene();
        let (peer_a, _) = round_trip(&a, &b, &mut net);
        let send_seq = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record")
            .send_seq;
        let hook = delete_of(&a, peer_a);
        BETWEEN_SEND_LOAD_AND_WRITE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        net.reset_writes();

        let mut entropy = Seeded::at(970);
        let sent = send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"too late",
            |x| entropy.fill(x),
            NOW,
        );
        assert!(
            BETWEEN_SEND_LOAD_AND_WRITE.with(|slot| slot.borrow().is_none()),
            "the delete did not run inside the send"
        );
        assert!(
            matches!(sent, Err(FlowError::DeletePending)),
            "a send committed after the delete was marked: {sent:?}"
        );
        assert_eq!(
            net.writes.total(),
            0,
            "a slot was written after the delete was marked"
        );
        let after = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record");
        assert!(after.delete_pending, "the control: the delete was marked");
        assert_eq!(
            after.send_seq, send_seq,
            "the refused send advanced the sequence"
        );
    }

    /// A delete marked while a collection batch holds the state it loaded stops
    /// the batch at its commit, before a cursor is written.
    #[test]
    fn a_delete_marked_during_a_collection_batch_stops_it_before_its_write() {
        let (a, b, mut net) = scene();
        let (peer_a, accepted) = round_trip(&a, &b, &mut net);
        let mut entropy = Seeded::at(980);
        send_message(
            &b.store(),
            &mut net,
            &accepted.peer,
            b"from B",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B sends");
        let my_collected = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record")
            .my_collected;
        net.before_message_read = Some(Box::new(delete_of(&a, peer_a)));
        net.reset_writes();

        let refused = matches!(
            collect_batch(&a.store(), &mut net, &peer_a),
            Err(FlowError::DeletePending)
        );
        assert!(
            net.before_message_read.is_none(),
            "the delete did not run inside the batch"
        );
        assert!(refused, "a batch committed after the delete was marked");
        assert_eq!(
            net.writes.total(),
            0,
            "a cursor was written after the delete was marked"
        );
        assert_eq!(
            a.store()
                .load_conv(&peer_a)
                .expect("load")
                .expect("A's record")
                .my_collected,
            my_collected,
            "the refused batch recorded a read"
        );
    }

    /// A delete marked while the recognition of an acceptance holds the state
    /// it loaded stops the recognition at its commit, before the hello slot is
    /// erased.
    #[test]
    fn a_delete_marked_during_a_recognition_stops_it_before_its_write() {
        let (a, b, mut net) = scene();
        let peer_a = opened_peer(&a_opens(&a, &b, &mut net, b"the first message"));
        b_accepts(&b, &mut net, b"the reply");
        net.before_message_read = Some(Box::new(delete_of(&a, peer_a)));
        net.reset_writes();

        let surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        assert!(
            net.before_message_read.is_none(),
            "the delete did not run inside the recognition"
        );
        assert!(
            matches!(
                surfaced.as_slice(),
                [Surfaced::Failed {
                    error: FlowError::DeletePending,
                    ..
                }]
            ),
            "a recognition committed after the delete was marked: {surfaced:?}"
        );
        assert_eq!(
            net.writes.total(),
            0,
            "the hello slot was erased after the delete was marked"
        );
        assert!(
            a.store()
                .load_conv(&peer_a)
                .expect("load")
                .expect("A's record")
                .awaiting_acceptance,
            "the refused recognition ended the first contact"
        );
    }

    /// Collection and the cursor stop at a slot that does not decode, and at a
    /// slot whose header names another sequence, and carry on past each once
    /// the right bytes are back.
    #[test]
    fn collection_stops_at_a_slot_that_does_not_decode_or_names_another_sequence() {
        let (a, b, mut net) = scene();
        let (peer_a, accepted) = round_trip(&a, &b, &mut net);
        let lookup_key = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("A's record")
            .outgoing_lookup_key;
        let mut entropy = Seeded::at(990);
        let mut send = |net: &mut Net, body: &[u8]| {
            send_message(&a.store(), net, &peer_a, body, |x| entropy.fill(x), NOW).expect("A sends")
        };

        send(&mut net, b"one");
        let two = send(&mut net, b"two");
        let held = net
            .channels
            .insert((lookup_key, channel::slot_for(two)), vec![0u8; 3])
            .expect("the second slot was written");
        let batch = collect_batch(&b.store(), &mut net, &accepted.peer).expect("B collects");
        assert_eq!(
            batch.bodies,
            vec![b"one".to_vec()],
            "collection went past a slot that does not decode"
        );
        assert_eq!(
            batch.my_collected, two,
            "the cursor counted past a slot that does not decode"
        );
        net.channels
            .insert((lookup_key, channel::slot_for(two)), held);
        let batch = collect_batch(&b.store(), &mut net, &accepted.peer).expect("B collects");
        assert_eq!(batch.bodies, vec![b"two".to_vec()]);

        let three = send(&mut net, b"three");
        let four = send(&mut net, b"four");
        let fourth = net
            .channels
            .get(&(lookup_key, channel::slot_for(four)))
            .cloned()
            .expect("the fourth slot was written");
        let held = net
            .channels
            .insert((lookup_key, channel::slot_for(three)), fourth)
            .expect("the third slot was written");
        let batch = collect_batch(&b.store(), &mut net, &accepted.peer).expect("B collects");
        assert!(
            batch.bodies.is_empty(),
            "collection opened a slot holding another sequence"
        );
        assert_eq!(
            batch.my_collected, three,
            "the cursor counted past a slot holding another sequence"
        );
        net.channels
            .insert((lookup_key, channel::slot_for(three)), held);
        let batch = collect_batch(&b.store(), &mut net, &accepted.peer).expect("B collects");
        assert_eq!(batch.bodies, vec![b"three".to_vec(), b"four".to_vec()]);
        assert_eq!(batch.my_collected, four + 1);
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
        let generation = FIRST_GENERATION + 1;
        let restart_owner = channel::derive_owner_seed(&a.channel_root, b.pk(), generation)
            .expect("A's next channel owner");
        let restart_key = net
            .open_channel(&restart_owner, channel::CHANNEL_SUBKEYS)
            .expect("A opens its next channel");
        let opening = ChannelOpening::build(
            &a.signer,
            b.pk(),
            &restart_key,
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
        assert_eq!(
            acceptance.peer_cursor,
            Some(0),
            "the acceptance publishes B's persisted cursor; its next batch publishes the collection"
        );
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
            state.peer_control_key.is_some(),
            "the key that opens B's control subkey is recorded"
        );
    }

    // ── advert rotation ─────────────────────────────────────────────────────

    /// Make a new advert key current for `b` at `at`, and publish it.
    fn rotate(b: &mut Party, net: &mut Net, at: u64, seed: u64) {
        let mut entropy = Seeded::at(seed);
        b.advert_keys
            .rotate_now(at, |x| entropy.fill(x))
            .expect("B rotates");
        b.publish(net);
    }

    /// A's refresh of its first contact at `at`.
    fn a_refreshes(
        a: &Party,
        net: &mut Net,
        peer: &CorrespondenceLabel,
        at: u64,
        seed: u64,
    ) -> Result<bool, FlowError> {
        let store = a.store();
        let mut entropy = Seeded::at(seed);
        refresh_first_contact(&store, net, peer, |x| entropy.fill(x), at)
    }

    /// The lookup key of the channel a fresh first contact opened.
    fn opened_channel(outcome: &FirstContact) -> [u8; HELLO_LOOKUP_KEY_LEN] {
        match outcome {
            FirstContact::Opened {
                outgoing_lookup_key,
                ..
            } => *outgoing_lookup_key,
            other => panic!("expected a fresh first contact, got {other:?}"),
        }
    }

    /// A channel as the network holds it: the control subkey and sequence 0's
    /// slot.
    fn channel_bytes(net: &Net, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN]) -> (Vec<u8>, Vec<u8>) {
        let at = |subkey| {
            net.channels
                .get(&(*lookup_key, subkey))
                .cloned()
                .expect("a written subkey")
        };
        (at(channel::CONTROL_SUBKEY), at(channel::slot_for(0)))
    }

    /// A conversation record's encoding without its outstanding hello, which
    /// is everything in the record a refresh must leave unchanged.
    fn record_without_hello(party: &Party, peer: &CorrespondenceLabel) -> Vec<u8> {
        let mut state = party
            .store()
            .load_conv(peer)
            .expect("load")
            .expect("a record");
        state.outstanding_hello = None;
        encode_conv(&state).to_vec()
    }

    /// The bytes one slot of a recipient's drop holds.
    fn hello_in_drop(net: &Net, recipient: &Party, slot: u16) -> Vec<u8> {
        let owner = drop_plane::derive_owner_seed(recipient.pk()).expect("the drop owner");
        net.drops
            .get(&(*owner.as_bytes(), slot))
            .cloned()
            .expect("a hello in the slot")
    }

    /// The outstanding hello a party's record holds for a correspondence.
    fn outstanding(party: &Party, peer: &CorrespondenceLabel) -> OutstandingHello {
        party
            .store()
            .load_conv(peer)
            .expect("load")
            .expect("a record")
            .outstanding_hello
            .expect("an outstanding hello")
    }

    /// A hello outstanding across a rotation of the correspondent's advert is
    /// re-encapsulated to the new key and rewritten into the slot it occupies,
    /// carrying the secret A's channel is sealed under.
    #[test]
    fn a_refresh_re_encapsulates_to_a_rotated_advert() {
        let (a, mut b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let before = outstanding(&a, &peer_a);
        let at = NOW + advert::ROTATION_PERIOD_SECS;

        rotate(&mut b, &mut net, at, 2_020);
        let refreshed = a_refreshes(&a, &mut net, &peer_a, at, 3_030).expect("the refresh runs");
        assert!(refreshed, "the rotation was past the outstanding serial");

        let after = outstanding(&a, &peer_a);
        assert_eq!(
            after.slot, before.slot,
            "the rewrite takes the hello's slot"
        );
        assert_eq!(after.advert_serial, b.advert_keys.serial());
        assert_ne!(after.sealed, before.sealed, "the hello was re-sealed");
        let found = hello_in_drop(&net, &b, after.slot);
        assert_eq!(
            found.as_slice(),
            after.sealed.as_slice(),
            "the drop holds the rewrite in place of the original"
        );

        let (hello, _, serial) = open_against_either(&b.advert_keys, &found, b.pk(), after.slot)
            .expect("the rewrite opens");
        assert_eq!(serial, b.advert_keys.serial(), "under the current key");
        let own_secret = a
            .store()
            .load_conv(&peer_a)
            .expect("load")
            .expect("a record")
            .own_hello_secret
            .expect("A's hello secret");
        assert_eq!(
            hello
                .original_secret
                .expect("a rewrite carries a secret")
                .as_bytes(),
            own_secret.as_bytes(),
            "the rewrite carries the secret A's channel is sealed under"
        );
        // The control: the original encapsulation does not open under the
        // current key, so the re-encapsulation is what makes the hello
        // readable under it.
        let stale = b
            .advert_keys
            .decapsulate(b.advert_keys.serial(), &before.kem_ct)
            .expect("decapsulate")
            .expect("the serial is current");
        assert!(
            drop_plane::open_hello(&stale, before.sealed.as_slice(), b.pk(), before.slot).is_err()
        );

        // A second refresh against the same advert does nothing.
        net.reset_writes();
        assert!(
            !a_refreshes(&a, &mut net, &peer_a, at, 4_040).expect("the second refresh runs"),
            "an unchanged serial must not re-encapsulate"
        );
        assert_eq!(net.writes.total(), 0);
    }

    /// The correspondent's advert rotates twice before it
    /// collects, so it no longer holds the key A first encapsulated to. A's
    /// refreshes rewrite only the hello. The correspondent recovers the
    /// first-turn root from the secret the rewrite carries and opens A's
    /// sequence 0 as A first wrote it.
    #[test]
    fn a_hello_rewritten_across_two_rotations_opens_the_first_message_as_written() {
        let (a, mut b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let channel = opened_channel(&outcome);
        let channel_before = channel_bytes(&net, &channel);
        let record_before = record_without_hello(&a, &peer_a);
        let outbox_before = outstanding_zero(&a.store(), &peer_a).expect("load");
        let first_serial = b.advert_keys.serial();
        let original_ct = outstanding(&a, &peer_a).kem_ct;

        net.reset_writes();
        for (turn, seed) in [(1u64, 2_020u64), (2, 2_121)] {
            let at = NOW + turn * advert::ROTATION_PERIOD_SECS;
            rotate(&mut b, &mut net, at, seed);
            assert!(
                a_refreshes(&a, &mut net, &peer_a, at, seed + 1).expect("the refresh runs"),
                "rotation {turn} was past the outstanding serial"
            );
        }
        assert_eq!(net.writes.hello, 2, "one hello write per rotation");
        assert_eq!(
            net.writes.control + net.writes.ring,
            0,
            "no channel subkey was written"
        );
        assert_eq!(
            channel_bytes(&net, &channel),
            channel_before,
            "A's channel changed"
        );
        assert_eq!(
            record_without_hello(&a, &peer_a),
            record_before,
            "A's conversation record changed beyond its outstanding hello"
        );
        assert_eq!(
            outstanding_zero(&a.store(), &peer_a).expect("load"),
            outbox_before,
            "A's outbox entry for sequence 0 changed"
        );
        assert!(
            b.advert_keys
                .decapsulate(first_serial, &original_ct)
                .expect("decapsulate")
                .is_none(),
            "B still holds the first key, so the two rotations prove nothing"
        );

        // The control: B's advert secrets alone do not open sequence 0. Every
        // encapsulation B can reach, under every key B still holds, seeds a
        // root under which A's first message does not open.
        let first_ratchet_pk = ChannelOpening::decode(
            a.store()
                .load_conv(&peer_a)
                .expect("load")
                .expect("a record")
                .own_opening
                .expect("A's opening")
                .as_slice(),
        )
        .expect("decode A's opening")
        .first_ratchet_pk;
        let (header, sealed) =
            channel::MessageHeader::decode(&channel_before.1).expect("decode sequence 0");
        let slot = outstanding(&a, &peer_a).slot;
        let rewrite = hello_in_drop(&net, &b, slot);
        let rewrite_ct: [u8; ml_kem::CT_LEN] = rewrite[..ml_kem::CT_LEN]
            .try_into()
            .expect("a ciphertext prefix");
        let mut tried = 0;
        for serial in [
            Some(b.advert_keys.serial()),
            b.advert_keys.previous_serial(),
        ]
        .into_iter()
        .flatten()
        {
            for ct in [&rewrite_ct, &*original_ct] {
                let secret = b
                    .advert_keys
                    .decapsulate(serial, ct)
                    .expect("decapsulate")
                    .expect("a held serial");
                let mut guess = chain::accept(&secret, &first_ratchet_pk).expect("a conversation");
                assert!(
                    guess.open(&header, sealed).is_err(),
                    "sequence 0 opened without the carried secret"
                );
                tried += 1;
            }
        }
        assert_eq!(tried, 4, "two held keys over two encapsulations");
        // The mirror: the secret the rewrite carries opens it.
        let (hello, _, _) =
            open_against_either(&b.advert_keys, &rewrite, b.pk(), slot).expect("the rewrite opens");
        let carried = hello.original_secret.expect("a rewrite carries a secret");
        let mut reader = chain::accept(&carried, &first_ratchet_pk).expect("a conversation");
        assert_eq!(
            reader
                .open(&header, sealed)
                .expect("the carried secret opens sequence 0"),
            b"the first message"
        );

        let request = only_request(b_collects(&b, &mut net));
        assert_eq!(
            request.advert_serial, first_serial,
            "the opening binds the serial A first encapsulated to"
        );
        let store_b = b.store();
        let mut entropy = Seeded::at(909);
        let accepted = accept(
            &store_b,
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B accepts");
        assert_eq!(accepted.bodies, vec![b"the first message".to_vec()]);

        let surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        match surfaced.as_slice() {
            [Surfaced::Accepted(acceptance)] => {
                assert_eq!(acceptance.bodies, vec![b"the reply".to_vec()]);
            }
            other => panic!("expected one acceptance, got {other:?}"),
        }
    }

    /// A refresh run after the correspondent collected and accepted the
    /// original hello, but before this side has recognised the acceptance,
    /// changes no channel subkey and no key-schedule state. The reply opens,
    /// and once the acceptance is recognised a refresh is refused.
    #[test]
    fn a_refresh_after_the_acceptance_leaves_the_conversation_readable() {
        let (a, mut b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let channel = opened_channel(&outcome);
        let at = NOW + advert::ROTATION_PERIOD_SECS;

        // B rotates, collects the original hello under the key it retained,
        // and replies to A's first ratchet key.
        rotate(&mut b, &mut net, at, 2_020);
        let accepted = b_accepts(&b, &mut net, b"the reply");
        assert_eq!(accepted.bodies, vec![b"the first message".to_vec()]);
        let channel_before = channel_bytes(&net, &channel);
        let record_before = record_without_hello(&a, &peer_a);

        // Out of order: A refreshes before collecting its own drop.
        net.reset_writes();
        assert!(
            a_refreshes(&a, &mut net, &peer_a, at, 3_030).expect("the refresh runs"),
            "the advert moved past the outstanding serial"
        );
        assert_eq!(net.writes.hello, 1, "one hello write");
        assert_eq!(net.writes.total(), 1, "and nothing else");
        assert_eq!(
            channel_bytes(&net, &channel),
            channel_before,
            "the refresh rewrote A's channel"
        );
        assert_eq!(
            record_without_hello(&a, &peer_a),
            record_before,
            "the refresh changed A's conversation record beyond its hello"
        );

        // A collects its drop, recognises the acceptance and opens B's reply.
        let surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        match surfaced.as_slice() {
            [Surfaced::Accepted(acceptance)] => {
                assert_eq!(acceptance.bodies, vec![b"the reply".to_vec()]);
            }
            other => panic!("expected one acceptance, got {other:?}"),
        }

        // In order: the refresh is refused and writes nothing.
        net.reset_writes();
        assert!(matches!(
            a_refreshes(&a, &mut net, &peer_a, at, 4_040),
            Err(FlowError::AlreadyAccepted)
        ));
        assert_eq!(net.writes.total(), 0);

        // B erases the rewrite as already collected, and reads A's next
        // message.
        let surfaced = b_collects(&b, &mut net);
        assert!(
            matches!(surfaced.as_slice(), [Surfaced::AlreadyCollected { .. }]),
            "got {surfaced:?}"
        );
        let mut entropy = Seeded::at(77);
        send_message(
            &a.store(),
            &mut net,
            &peer_a,
            b"after the acceptance",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A sends");
        let batch = collect_batch(&b.store(), &mut net, &accepted.peer).expect("B collects");
        assert_eq!(batch.bodies, vec![b"after the acceptance".to_vec()]);
    }

    /// A rewritten hello is refused anywhere but the drop it was written for.
    /// Copied into another identity's drop it does not open. A rewrite built
    /// by an identity A contacted, carrying the secret of A's hello to that
    /// identity, opens at B but its opening names that identity.
    #[test]
    fn a_rewritten_hello_relayed_to_another_identity_is_refused() {
        let (a, mut b, mut net) = scene();
        let c = Party::new(0xc3);
        c.publish(&mut net);
        let to_b = a_opens(&a, &b, &mut net, b"to B");
        let peer_b = opened_peer(&to_b);
        // A seed of its own, so the hello to C does not share the slot the
        // hello to B takes.
        let store_a = a.store();
        let mut entropy = Seeded::at(8_484);
        let to_c = first_contact(
            &store_a,
            &mut net,
            &a.me(),
            c.pk(),
            b"to C",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("A's first contact to C");
        drop(store_a);
        let c_slot = match &to_c {
            FirstContact::Opened { hello_slot, .. } => *hello_slot,
            other => panic!("expected a fresh first contact, got {other:?}"),
        };
        let at = NOW + advert::ROTATION_PERIOD_SECS;
        rotate(&mut b, &mut net, at, 2_020);
        assert!(a_refreshes(&a, &mut net, &peer_b, at, 3_030).expect("the refresh runs"));
        let slot = outstanding(&a, &peer_b).slot;
        let rewrite = hello_in_drop(&net, &b, slot);

        // C opens A's hello to C, as its recipient may.
        let to_c_bytes = hello_in_drop(&net, &c, c_slot);
        let (to_c_hello, to_c_secret, _) =
            open_against_either(&c.advert_keys, &to_c_bytes, c.pk(), c_slot)
                .expect("C opens A's hello");

        // Copied into an empty slot of C's drop, B's rewrite does not open.
        // The control: A's genuine hello to C, in the same drop, is surfaced.
        assert_ne!(slot, c_slot, "the rewrite would overwrite A's hello to C");
        let c_drop = drop_plane::derive_owner_seed(c.pk()).expect("C's drop");
        net.drops.insert((*c_drop.as_bytes(), slot), rewrite);
        let surfaced =
            collect(&c.store(), &mut net, &c.me(), &c.advert_keys, |_| false).expect("C collects");
        assert_eq!(
            only_request(surfaced).lookup_key,
            opened_channel(&to_c),
            "C surfaced something other than A's hello to C"
        );

        // C relays A's channel to C into B's drop as a rewrite.
        assert!(
            c.advert_keys.serial() < b.advert_keys.serial(),
            "C's serial is below B's, so the refusal below is the identity binding"
        );
        let mut entropy = Seeded::at(6_161);
        let advert_b = advert::verify(
            b.pk(),
            &b.advert_keys.advert_bytes(&b.signer).expect("B's advert"),
        )
        .expect("verify B's advert");
        let encap =
            advert::encapsulate_to(&advert_b, at, |x| entropy.fill(x)).expect("encapsulate");
        let r = drop_plane::repick(|x| entropy.fill(x)).expect("r");
        let relay = drop_plane::seal_rewritten_hello(
            &encap,
            &to_c_hello.lookup_key,
            &r,
            &to_c_secret,
            b.pk(),
        )
        .expect("seal the relay");
        let relay_slot = drop_plane::slot_for(&r).expect("slot");
        assert_ne!(relay_slot, slot, "the relay would overwrite A's rewrite");
        let b_drop = drop_plane::derive_owner_seed(b.pk()).expect("B's drop");
        net.drops.insert((*b_drop.as_bytes(), relay_slot), relay);

        // The control: A's genuine rewrite in the same drop is surfaced.
        let request = only_request(b_collects(&b, &mut net));
        assert_eq!(
            request.lookup_key,
            opened_channel(&to_b),
            "B surfaced a channel A opened to someone else"
        );
    }

    /// Write a copy of `opening` into the channel at `channel` under a secret
    /// the copier holds, with a message 0 of the copier's under that secret,
    /// and a hello to `recipient` naming the channel. The hello is an original
    /// when `chosen` is `None`, and a rewrite carrying `chosen` otherwise.
    /// Returns the drop slot the hello occupies.
    fn plant_copied_opening(
        net: &mut Net,
        recipient: &Party,
        opening: &ChannelOpening,
        channel: [u8; HELLO_LOOKUP_KEY_LEN],
        chosen: Option<&AdvertSharedSecret>,
        at: u64,
        seed: u64,
    ) -> u16 {
        let mut entropy = Seeded::at(seed);
        let advert = advert::verify(
            recipient.pk(),
            &recipient
                .advert_keys
                .advert_bytes(&recipient.signer)
                .expect("the recipient's advert"),
        )
        .expect("verify the advert");
        let encap = advert::encapsulate_to(&advert, at, |x| entropy.fill(x)).expect("encapsulate");
        let channel_secret = chosen.unwrap_or(&encap.shared_secret);
        let control = channel::seal_control(
            channel_secret,
            &Control {
                opening: Some(opening.clone()),
                collected_cursor: 0,
                closed: false,
            },
        )
        .expect("seal the control");
        net.write_channel(&channel, channel::CONTROL_SUBKEY, &control)
            .expect("write the control");
        let mut conversation = chain::initiate(channel_secret, |x| entropy.fill(x))
            .expect("initiate")
            .conversation;
        let (header, sealed) = conversation
            .seal(b"not from A", channel::DEVICE_ID_SINGLE_DEVICE, |x| {
                entropy.fill(x)
            })
            .expect("seal message 0");
        let mut slot_bytes = header.encode();
        slot_bytes.extend_from_slice(&sealed);
        net.write_channel(&channel, channel::slot_for(0), &slot_bytes)
            .expect("write message 0");
        let r = drop_plane::repick(|x| entropy.fill(x)).expect("r");
        let hello = match chosen {
            None => drop_plane::seal_hello(&encap, &channel, &r, recipient.pk()),
            Some(secret) => {
                drop_plane::seal_rewritten_hello(&encap, &channel, &r, secret, recipient.pk())
            }
        }
        .expect("seal the hello");
        let slot = drop_plane::slot_for(&r).expect("slot");
        let owner = drop_plane::derive_owner_seed(recipient.pk()).expect("the drop");
        net.write_drop_slot(&owner, drop_plane::DROP_SUBKEYS, slot, &hello)
            .expect("write the hello");
        slot
    }

    /// A channel record opened under an owner seed no party here holds, as a
    /// copier opens the record it writes.
    fn copier_channel(net: &mut Net, root: u8, recipient: &Party) -> [u8; HELLO_LOOKUP_KEY_LEN] {
        let owner = channel::derive_owner_seed(
            &DmChannelRootSecret::from_bytes([root; 32]),
            recipient.pk(),
            FIRST_GENERATION,
        )
        .expect("the copier's channel owner");
        net.open_channel(&owner, channel::CHANNEL_SUBKEYS)
            .expect("the copier opens its channel")
    }

    /// A's genuine opening copied into a channel somebody else writes is
    /// refused, whether the copier's hello is an original or a rewrite
    /// carrying a secret the copier chose: the opening signs the lookup key of
    /// the channel A wrote it into, and the copier's hello names another.
    #[test]
    fn a_genuine_opening_copied_into_another_channel_is_refused() {
        let (a, mut b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let genuine = opened_channel(&outcome);
        let genuine_slot = outstanding(&a, &peer_a).slot;
        // A's genuine opening, as anyone holding a snapshot of either side has
        // it.
        let opening = ChannelOpening::decode(
            a.store()
                .load_conv(&peer_a)
                .expect("load")
                .expect("a record")
                .own_opening
                .expect("A's opening")
                .as_slice(),
        )
        .expect("decode A's opening");

        // An original-shape copy, encapsulated to the key A encapsulated to.
        let first_channel = copier_channel(&mut net, 0x7e, &b);
        let first = plant_copied_opening(&mut net, &b, &opening, first_channel, None, NOW, 7_171);
        assert_ne!(first, genuine_slot, "the copy would overwrite A's hello");
        assert_eq!(
            only_request(b_collects(&b, &mut net)).lookup_key,
            genuine,
            "B surfaced a copied opening as A's request"
        );

        // A rewrite-shape copy after B rotates, carrying a secret the copier
        // chose.
        let at = NOW + advert::ROTATION_PERIOD_SECS;
        rotate(&mut b, &mut net, at, 2_020);
        let chosen = AdvertSharedSecret::from_bytes(&[0x5cu8; ml_kem::SHARED_SECRET_LEN]);
        let second_channel = copier_channel(&mut net, 0x7d, &b);
        let second = plant_copied_opening(
            &mut net,
            &b,
            &opening,
            second_channel,
            Some(&chosen),
            at,
            7_272,
        );
        assert!(
            second != genuine_slot && second != first,
            "the second copy would overwrite another hello"
        );
        // The control: A's genuine hello, in the same drop, is surfaced.
        assert_eq!(
            only_request(b_collects(&b, &mut net)).lookup_key,
            genuine,
            "B surfaced a rewritten copy as A's request"
        );
    }

    /// A rewrite whose opening names the serial the rewrite arrived under was
    /// not made by a rotation, and is refused.
    #[test]
    fn a_rewrite_not_made_by_a_rotation_is_refused() {
        let (a, b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let slot = outstanding(&a, &peer_a).slot;
        let original = hello_in_drop(&net, &b, slot);
        let (opened, ss0, serial) =
            open_against_either(&b.advert_keys, &original, b.pk(), slot).expect("A's hello opens");
        assert_eq!(serial, b.advert_keys.serial(), "B has not rotated");

        // A rewrite of A's hello, re-encapsulated to the key A first used.
        let mut entropy = Seeded::at(9_191);
        let advert_b = advert::verify(
            b.pk(),
            &b.advert_keys.advert_bytes(&b.signer).expect("B's advert"),
        )
        .expect("verify B's advert");
        let encap =
            advert::encapsulate_to(&advert_b, NOW, |x| entropy.fill(x)).expect("encapsulate");
        let rewrite =
            drop_plane::seal_rewritten_hello(&encap, &opened.lookup_key, &opened.r, &ss0, b.pk())
                .expect("seal the rewrite");
        let drop_owner = drop_plane::derive_owner_seed(b.pk()).expect("B's drop");
        net.drops.insert((*drop_owner.as_bytes(), slot), rewrite);
        let surfaced = b_collects(&b, &mut net);
        assert!(
            surfaced.is_empty(),
            "a rewrite at its own serial was surfaced: {surfaced:?}"
        );

        // The control: the original hello in the same slot is surfaced.
        net.drops.insert((*drop_owner.as_bytes(), slot), original);
        assert_eq!(
            only_request(b_collects(&b, &mut net)).lookup_key,
            opened.lookup_key
        );
    }

    /// A refresh stopped at each of its write boundaries is carried to
    /// completion by the relaunch: the persisted rewrite is written byte for
    /// byte, no second encapsulation is minted, and B opens A's first message.
    #[test]
    fn a_refresh_stopped_at_each_boundary_converges_on_one_rewrite() {
        for boundary in 0..3usize {
            let (a, mut b, mut net) = scene();
            let outcome = a_opens(&a, &b, &mut net, b"the first message");
            let peer_a = opened_peer(&outcome);
            let channel = opened_channel(&outcome);
            let at = NOW + advert::ROTATION_PERIOD_SECS;
            rotate(&mut b, &mut net, at, 2_020);
            let channel_before = channel_bytes(&net, &channel);

            // Boundary 0 stops before the first write, over a slot still
            // holding the original hello. Boundary 1 stops after a clobbered
            // write and its re-pick. Boundary 2 is a drop kept full, which
            // stops the refresh at DropFull over a slot holding another value.
            net.clobber_hellos = net.clobbered + [0, 1, 2][boundary];
            net.reset_writes();
            net.minted.clear();
            net.fail_after = [Some(0), Some(1), None][boundary];
            assert!(
                a_refreshes(&a, &mut net, &peer_a, at, 3_030).is_err(),
                "boundary {boundary} must stop the refresh short"
            );
            let persisted = outstanding(&a, &peer_a);
            assert_eq!(
                persisted.advert_serial,
                b.advert_keys.serial(),
                "boundary {boundary} wrote a rewrite it had not persisted"
            );

            // The relaunch.
            net.fail_after = None;
            assert!(
                !a_refreshes(&a, &mut net, &peer_a, at, 4_040).expect("the relaunch refresh runs"),
                "boundary {boundary}: the persisted rewrite is current, so nothing re-encapsulates"
            );
            assert_eq!(
                resume_first_contact(&a.store(), &mut net, &peer_a).expect("the relaunch rewrites"),
                Resumed::Rewrote(persisted.slot)
            );
            assert_eq!(
                net.hellos_written
                    .last()
                    .expect("a hello was written")
                    .as_slice(),
                persisted.sealed.as_slice(),
                "boundary {boundary} wrote bytes other than the persisted rewrite"
            );
            assert_eq!(
                outstanding(&a, &peer_a).sealed,
                persisted.sealed,
                "boundary {boundary}: the relaunch changed the persisted rewrite"
            );
            assert_eq!(
                hello_in_drop(&net, &b, persisted.slot).as_slice(),
                persisted.sealed.as_slice(),
                "boundary {boundary}: the slot does not hold the persisted rewrite"
            );
            let distinct: HashSet<[u8; ml_kem::CT_LEN]> = net.minted.iter().copied().collect();
            assert_eq!(
                distinct.len(),
                1,
                "boundary {boundary} minted {} encapsulations",
                distinct.len()
            );
            assert_eq!(
                channel_bytes(&net, &channel),
                channel_before,
                "boundary {boundary} changed A's channel"
            );

            let accepted = b_accepts(&b, &mut net, b"the reply");
            assert_eq!(
                accepted.bodies,
                vec![b"the first message".to_vec()],
                "boundary {boundary}"
            );
        }
    }

    /// A refresh is one hello write and nothing else, two with one re-pick,
    /// and none where the advert has not moved.
    #[test]
    fn a_refresh_is_one_hello_write_and_no_channel_write() {
        let (a, mut b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let period = advert::ROTATION_PERIOD_SECS;

        rotate(&mut b, &mut net, NOW + period, 2_020);
        net.reset_writes();
        assert!(a_refreshes(&a, &mut net, &peer_a, NOW + period, 3_030).expect("the refresh runs"));
        assert!(net.writes.bytes > 0, "the write carried bytes");
        assert_eq!(net.writes.hello, 1, "the rewritten hello");
        assert_eq!(net.writes.total(), 1, "no erase and no channel write");

        rotate(&mut b, &mut net, NOW + 2 * period, 2_121);
        net.clobber_hellos = net.clobbered + 1;
        net.reset_writes();
        assert!(
            a_refreshes(&a, &mut net, &peer_a, NOW + 2 * period, 3_131).expect("the refresh runs")
        );
        assert_eq!(net.writes.hello, 2, "the rewritten hello and its re-pick");
        assert_eq!(net.writes.total(), 2);

        net.reset_writes();
        assert!(
            !a_refreshes(&a, &mut net, &peer_a, NOW + 2 * period, 3_232).expect("the refresh runs")
        );
        assert_eq!(net.writes.total(), 0, "an unmoved advert costs no write");

        // The control: a record store that counts each write twice puts the
        // same refresh over its budget.
        rotate(&mut b, &mut net, NOW + 3 * period, 2_222);
        net.double = true;
        net.reset_writes();
        assert!(
            a_refreshes(&a, &mut net, &peer_a, NOW + 3 * period, 3_333).expect("the refresh runs")
        );
        assert!(
            net.writes.total() > 1,
            "a doubled write must exceed the one-write budget, was {}",
            net.writes.total()
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
        let original = read_opening(
            &mut net,
            &channel::control_key(&secret).expect("the control key"),
            &hello.lookup_key,
        )
        .expect("the opening");
        let forged = ChannelOpening::build(
            &a.signer,
            b.pk(),
            &hello.lookup_key,
            &original.first_ratchet_pk,
            serial + 1,
        )
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
        let refused = send_message(
            &store_a,
            &mut net,
            &peer_a,
            b"owed",
            |x| entropy.fill(x),
            NOW,
        );
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
        let own_owner = channel::derive_owner_seed(&a.channel_root, b.pk(), FIRST_GENERATION)
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

        // The stopped run recorded nothing it read, so the finish returns the
        // correspondent's first message, and it is collected exactly once.
        assert_eq!(accepted.bodies, vec![b"the first message".to_vec()]);
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

    /// An acceptance stopped after its hello back lands and before it records
    /// what it read has published only the cursor already persisted. The
    /// correspondent still owes sequence 0 until this side records the read and
    /// publishes it, and sequence 0 surfaces once.
    #[test]
    fn an_acceptance_stopped_after_its_hello_back_lands_leaves_the_first_message_owed() {
        let (a, b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let request = only_request(b_collects(&b, &mut net));
        let store_b = b.store();

        // The erase, the opening, the reply and the hello back land. The
        // read-back after the hello back is refused, so the run stops before
        // the acceptance records what it read.
        net.reset_writes();
        net.refuse_reads_after = Some(4);
        let mut entropy = Seeded::at(909);
        let stopped = accept(
            &store_b,
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        );
        assert!(stopped.is_err(), "the run must stop after the hello back");
        assert_eq!(net.writes.hello, 1, "the hello back landed");
        net.refuse_reads_after = None;
        let b_peer = store_b.load().expect("load").convs[0].peer;
        assert!(
            store_b
                .load_conv(&b_peer)
                .expect("load")
                .expect("B's record")
                .acceptance_pending,
            "the stop landed after the acceptance finished"
        );

        // A recognises the acceptance and still owes sequence 0.
        let surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        match surfaced.as_slice() {
            [Surfaced::Accepted(acceptance)] => assert_eq!(
                acceptance.peer_cursor,
                Some(0),
                "B published a collection it had not recorded"
            ),
            other => panic!("expected one acceptance, got {other:?}"),
        }
        collect_batch(&a.store(), &mut net, &peer_a).expect("A collects a batch");
        let a_owes_zero = a
            .store()
            .load()
            .expect("load")
            .convs
            .into_iter()
            .find(|c| c.peer == peer_a)
            .expect("A's record")
            .outstanding_outbox
            .iter()
            .any(|e| e.seq == 0);
        assert!(a_owes_zero, "A dropped sequence 0 before B recorded it");

        // B finishes from the record and returns sequence 0 once, and its next
        // batch publishes the collection.
        let mut entropy = Seeded::at(5_353);
        let finished = continue_acceptance(
            &store_b,
            &mut net,
            &b.me(),
            &b_peer,
            |x| entropy.fill(x),
            NOW,
        )
        .expect("B finishes the acceptance");
        assert_eq!(finished.bodies, vec![b"the first message".to_vec()]);
        let batch = collect_batch(&store_b, &mut net, &b_peer).expect("B collects a batch");
        assert!(batch.bodies.is_empty(), "sequence 0 surfaced twice");
        assert!(batch.cursor_published, "B's batch published the collection");
        assert_eq!(
            peer_cursor(&a.store(), &mut net, &peer_a).expect("A reads B's cursor"),
            Some(1)
        );
    }

    /// A collection batch is refused while this side's acceptance is not
    /// finished, whether the run stopped before or after minting the
    /// acceptance's opening, and the acceptance that finishes returns
    /// sequence 0 once.
    #[test]
    fn a_collection_batch_is_refused_while_an_acceptance_is_pending() {
        for before_mint in [true, false] {
            let (a, b, mut net) = scene();
            a_opens(&a, &b, &mut net, b"the first message");
            let request = only_request(b_collects(&b, &mut net));
            let store = b.store();
            net.reset_writes();
            if before_mint {
                net.refuse_adverts = true;
            } else {
                // The erase lands and the opening write is refused.
                net.fail_after = Some(1);
            }
            let mut entropy = Seeded::at(909);
            assert!(
                accept(
                    &store,
                    &mut net,
                    &b.me(),
                    &request,
                    b"the reply",
                    |x| entropy.fill(x),
                    NOW,
                )
                .is_err(),
                "before_mint={before_mint}: the acceptance must stop short"
            );
            net.refuse_adverts = false;
            net.fail_after = None;
            let peer = store.load().expect("load").convs[0].peer;
            let pending = store.load_conv(&peer).expect("load").expect("B's record");
            assert!(pending.acceptance_pending, "before_mint={before_mint}");
            assert_eq!(
                pending.own_opening.is_none(),
                before_mint,
                "the stop landed on the wrong side of the mint"
            );

            let refused = collect_batch(&store, &mut net, &peer);
            assert!(
                matches!(refused, Err(FlowError::AwaitingAcceptance)),
                "before_mint={before_mint}: a batch ran over a pending acceptance: {refused:?}"
            );
            assert_eq!(
                store
                    .load_conv(&peer)
                    .expect("load")
                    .expect("B's record")
                    .my_collected,
                0,
                "before_mint={before_mint}: the refused batch recorded a read"
            );

            let mut entropy = Seeded::at(5_353);
            let finished =
                continue_acceptance(&store, &mut net, &b.me(), &peer, |x| entropy.fill(x), NOW)
                    .expect("the acceptance finishes");
            assert_eq!(
                finished.bodies,
                vec![b"the first message".to_vec()],
                "before_mint={before_mint}"
            );
            let batch = collect_batch(&store, &mut net, &peer).expect("B collects a batch");
            assert!(
                batch.bodies.is_empty(),
                "before_mint={before_mint}: sequence 0 surfaced twice"
            );
        }
    }

    /// An acceptance stopped before it mints its encapsulation and opening is
    /// finished by [`continue_acceptance`], which mints them once.
    #[test]
    fn an_acceptance_stopped_before_its_mint_mints_once_when_continued() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let request = only_request(b_collects(&b, &mut net));
        let store = b.store();
        net.refuse_adverts = true;
        net.reset_writes();
        let mut entropy = Seeded::at(909);
        assert!(
            accept(
                &store,
                &mut net,
                &b.me(),
                &request,
                b"the reply",
                |x| entropy.fill(x),
                NOW,
            )
            .is_err(),
            "the acceptance must stop at the advert read"
        );
        assert_eq!(net.writes.total(), 0, "nothing is written before the mint");
        net.refuse_adverts = false;
        let peer = store.load().expect("load").convs[0].peer;
        assert!(
            store
                .load_conv(&peer)
                .expect("load")
                .expect("B's record")
                .own_opening
                .is_none(),
            "the stop landed after the mint"
        );

        let mut entropy = Seeded::at(5_353);
        let finished =
            continue_acceptance(&store, &mut net, &b.me(), &peer, |x| entropy.fill(x), NOW)
                .expect("the acceptance finishes");
        assert_eq!(finished.bodies, vec![b"the first message".to_vec()]);
        let after = store.load_conv(&peer).expect("load").expect("B's record");
        assert!(after.own_opening.is_some(), "no opening was minted");
        let hello = after
            .outstanding_hello
            .as_ref()
            .expect("the hello back is persisted");
        assert_eq!(
            after.own_hello_kem_ct.as_ref(),
            Some(&hello.kem_ct),
            "the hello back carries an encapsulation other than the one minted"
        );
        assert_eq!(net.writes.hello, 1, "one hello back");

        let surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        match surfaced.as_slice() {
            [Surfaced::Accepted(acceptance)] => {
                assert_eq!(acceptance.bodies, vec![b"the reply".to_vec()]);
            }
            other => panic!("expected one acceptance, got {other:?}"),
        }
    }

    /// An accept or a continued acceptance addressed to a correspondence this
    /// side opened is refused as established, and leaves the hello secret a
    /// rewrite of this side's hello still carries.
    #[test]
    fn an_initiators_record_keeps_its_hello_secret_through_accept_and_continue() {
        let (a, b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);
        let store = a.store();
        let secret = || {
            store
                .load_conv(&peer_a)
                .expect("load")
                .expect("A's record")
                .own_hello_secret
                .map(|s| *s.as_bytes())
        };
        let before = secret().expect("A holds its hello secret while awaiting acceptance");

        // A request naming B, as a hello from B would.
        let request = ContactRequest {
            identity: Box::new(*b.pk()),
            lookup_key: [0x21u8; HELLO_LOOKUP_KEY_LEN],
            first_ratchet_pk: Box::new([0x22u8; ml_kem::EK_LEN]),
            slot: 0,
            advert_serial: 0,
            shared_secret: AdvertSharedSecret::from_bytes(&[0x23u8; ml_kem::SHARED_SECRET_LEN]),
        };
        let mut entropy = Seeded::at(909);
        assert!(matches!(
            accept(
                &store,
                &mut net,
                &a.me(),
                &request,
                b"a reply",
                |x| entropy.fill(x),
                NOW,
            ),
            Err(FlowError::AlreadyEstablished)
        ));
        let mut entropy = Seeded::at(910);
        assert!(matches!(
            continue_acceptance(&store, &mut net, &a.me(), &peer_a, |x| entropy.fill(x), NOW),
            Err(FlowError::AlreadyEstablished)
        ));
        assert_eq!(
            secret(),
            Some(before),
            "a refused acceptance deleted the initiator's hello secret"
        );
    }

    /// An acceptance whose hello back write is refused has recorded nothing it
    /// read, so the call that finishes it returns the correspondent's first
    /// message and nothing returns that message again.
    #[test]
    fn a_refused_hello_back_surfaces_the_first_message_once() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let request = only_request(b_collects(&b, &mut net));
        let store = b.store();
        let mut surfaced: Vec<Vec<u8>> = Vec::new();

        // The erase, the opening and the reply land, and the hello back is
        // refused.
        net.reset_writes();
        net.fail_after = Some(3);
        let mut entropy = Seeded::at(909);
        let refused = accept(
            &store,
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        );
        assert!(
            matches!(refused, Err(FlowError::Records(_))),
            "the hello back write was not the refusal: {refused:?}"
        );
        assert_eq!(net.writes.hello, 0, "no hello back reached the drop");

        net.fail_after = None;
        for seed in [7_070u64, 8_080] {
            let mut entropy = Seeded::at(seed);
            match accept(
                &store,
                &mut net,
                &b.me(),
                &request,
                b"the reply",
                |x| entropy.fill(x),
                NOW,
            ) {
                Ok(accepted) => surfaced.extend(accepted.bodies),
                Err(FlowError::AlreadyEstablished) => {}
                Err(other) => panic!("a retry failed: {other:?}"),
            }
        }
        let peer = store.load().expect("load").convs[0].peer;
        surfaced.extend(
            collect_batch(&store, &mut net, &peer)
                .expect("B collects a batch")
                .bodies,
        );
        assert_eq!(
            surfaced,
            vec![b"the first message".to_vec()],
            "the first message surfaced other than exactly once"
        );
    }

    /// An acceptance stopped at each of its writes is finished by
    /// [`continue_acceptance`] from the store and the record store alone. The
    /// opening, the reply and the hello back's encapsulation are the ones the
    /// stopped run persisted, byte for byte, and the first message is returned
    /// once.
    #[test]
    fn an_acceptance_stopped_at_each_write_is_finished_from_the_record() {
        for boundary in 0..4usize {
            let (a, b, mut net) = scene();
            a_opens(&a, &b, &mut net, b"the first message");
            let request = only_request(b_collects(&b, &mut net));
            let store = b.store();
            net.minted.clear();
            net.reset_writes();
            net.fail_after = Some(boundary);
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
            assert!(
                stopped.is_err(),
                "boundary {boundary} must stop the acceptance short"
            );
            drop(request);

            let peer = store.load().expect("load").convs[0].peer;
            let before = store.load_conv(&peer).expect("load").expect("B's record");
            let kem_ct_before = before
                .own_hello_kem_ct
                .clone()
                .expect("the encapsulation is persisted before any write it enables");
            let hello_before = before.outstanding_hello.as_ref().map(|h| h.sealed.clone());
            let reply_before = outstanding_zero(&store, &peer)
                .expect("load")
                .expect("the reply is committed with the record");

            // The relaunch: nothing but the store and the record store.
            net.fail_after = None;
            let mut entropy = Seeded::at(5_353);
            let finished =
                continue_acceptance(&store, &mut net, &b.me(), &peer, |x| entropy.fill(x), NOW)
                    .expect("the relaunch finishes the acceptance");
            assert_eq!(
                finished.bodies,
                vec![b"the first message".to_vec()],
                "boundary {boundary}"
            );

            let after = store.load_conv(&peer).expect("load").expect("B's record");
            assert_eq!(
                after.outstanding_hello.as_ref().map(|h| h.kem_ct.clone()),
                Some(kem_ct_before),
                "boundary {boundary}: the hello back was encapsulated again"
            );
            assert!(
                after.own_hello_secret.is_none(),
                "boundary {boundary}: the hello secret survived the finished acceptance"
            );
            if let Some(sealed) = hello_before {
                assert_eq!(
                    after.outstanding_hello.as_ref().map(|h| h.sealed.clone()),
                    Some(sealed),
                    "boundary {boundary}: the persisted hello back was sealed again"
                );
            }
            assert_eq!(
                outstanding_zero(&store, &peer).expect("load"),
                Some(reply_before),
                "boundary {boundary}: the reply was sealed again"
            );
            assert!(!after.acceptance_pending, "boundary {boundary}");
            let mut entropy = Seeded::at(6_464);
            assert!(matches!(
                continue_acceptance(&store, &mut net, &b.me(), &peer, |x| entropy.fill(x), NOW),
                Err(FlowError::AlreadyEstablished)
            ));

            let surfaced = collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false)
                .expect("A collects");
            match surfaced.as_slice() {
                [Surfaced::Accepted(acceptance)] => {
                    assert_eq!(
                        acceptance.bodies,
                        vec![b"the reply".to_vec()],
                        "boundary {boundary}"
                    );
                }
                other => panic!("boundary {boundary}: expected one acceptance, got {other:?}"),
            }
        }
    }

    /// A first contact stopped at each of its writes is carried on by
    /// [`continue_first_contact`] from the store and the record store alone,
    /// writing the opening, sequence 0 and hello the record holds.
    #[test]
    fn a_first_contact_stopped_at_each_write_is_carried_on_from_the_record() {
        for boundary in 0..4usize {
            let (a, b, mut net) = scene();
            // The fourth boundary is reachable only through a re-pick.
            net.clobber_hellos = usize::from(boundary == 3);
            net.fail_after = Some(boundary);
            let store = a.store();
            let mut entropy = Seeded::at(4_242);
            let stopped = first_contact(
                &store,
                &mut net,
                &a.me(),
                b.pk(),
                b"the first message",
                |x| entropy.fill(x),
                NOW,
            );
            assert!(
                stopped.is_err(),
                "boundary {boundary} must stop the first contact short"
            );
            let peer = store.load().expect("load").convs[0].peer;
            let seq0 = outstanding_zero(&store, &peer)
                .expect("load")
                .expect("sequence 0 is committed with the record");

            // The relaunch: nothing but the store and the record store.
            net.fail_after = None;
            let mut entropy = Seeded::at(5_353);
            continue_first_contact(&store, &mut net, &peer, |x| entropy.fill(x))
                .expect("the relaunch carries the first contact on");

            let after = store.load_conv(&peer).expect("load").expect("A's record");
            assert_eq!(
                net.channels
                    .get(&(after.outgoing_lookup_key, channel::slot_for(0))),
                Some(&seq0),
                "boundary {boundary}: sequence 0's slot does not hold the committed bytes"
            );
            let hello = after
                .outstanding_hello
                .as_ref()
                .expect("a hello is persisted");
            assert_eq!(
                net.hellos_written.last().map(Vec::as_slice),
                Some(hello.sealed.as_slice()),
                "boundary {boundary}: the drop does not hold the persisted hello"
            );
            let accepted = b_accepts(&b, &mut net, b"the reply");
            assert_eq!(
                accepted.bodies,
                vec![b"the first message".to_vec()],
                "boundary {boundary}"
            );
        }
    }

    /// An acceptance stopped after its hello back is persisted and before that
    /// hello is written leaves no hello secret in the record, and neither does
    /// the relaunch that finds the hello back already there.
    #[test]
    fn a_stopped_hello_back_leaves_no_hello_secret() {
        let (a, b, mut net) = scene();
        a_opens(&a, &b, &mut net, b"the first message");
        let request = only_request(b_collects(&b, &mut net));

        // An acceptance writes the collected slot's erase, the control
        // subkey, the reply and the hello back, in that order. Refusing the
        // fourth stops the run after the hello back is persisted.
        let store = b.store();
        net.reset_writes();
        net.fail_after = Some(3);
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
        assert!(stopped.is_err(), "the hello back write was refused");
        assert_eq!(net.writes.hello, 0, "no hello back reached the drop");

        let peer = store.load().expect("load").convs[0].peer;
        let state = store.load_conv(&peer).expect("load").expect("B's record");
        let hello = state
            .outstanding_hello
            .as_ref()
            .expect("the hello back was persisted before its write");
        let secret = a
            .advert_keys
            .decapsulate(hello.advert_serial, &hello.kem_ct)
            .expect("decapsulate")
            .expect("A holds the key B encapsulated to");
        // The controls: the recovered secret is the hello back's, and the
        // search finds the hello's own encapsulation in the same bytes.
        assert!(
            drop_plane::open_hello(&secret, hello.sealed.as_slice(), a.pk(), hello.slot).is_ok(),
            "the recovered secret does not open the hello back"
        );
        let image = encode_conv(&state);
        assert!(
            contains(&image, hello.kem_ct.as_slice()),
            "the hello's encapsulation is absent, so the search proves nothing"
        );
        assert!(
            !contains(&image, secret.as_bytes()),
            "a stopped acceptance left its hello secret in the record"
        );

        // The relaunch finds the hello back in place and leaves no secret.
        net.fail_after = None;
        let mut entropy = Seeded::at(7_070);
        let again = accept(
            &store,
            &mut net,
            &b.me(),
            &request,
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("the relaunch finishes the acceptance");
        assert_eq!(again.bodies, vec![b"the first message".to_vec()]);
        let image = encode_conv(&store.load_conv(&peer).expect("load").expect("B's record"));
        assert!(
            !contains(&image, secret.as_bytes()),
            "the relaunch left the hello secret in the record"
        );

        // The finish wrote the persisted hello back, and A reads the reply.
        let surfaced =
            collect(&a.store(), &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");
        match surfaced.as_slice() {
            [Surfaced::Accepted(acceptance)] => {
                assert_eq!(acceptance.bodies, vec![b"the reply".to_vec()]);
            }
            other => panic!("expected one acceptance, got {other:?}"),
        }
    }

    /// An acceptance refuses a contact request whose fields do not all come
    /// from the opening its channel holds: an identity paired with another
    /// correspondent's channel, or a first ratchet key paired with a channel
    /// whose opening names another. Nothing is written for either.
    #[test]
    fn an_acceptance_refuses_a_request_its_opening_does_not_match() {
        let (a, b, mut net) = scene();
        let c = Party::new(0xc3);
        c.publish(&mut net);
        a_opens(&a, &b, &mut net, b"from A");
        let store_c = c.store();
        let mut entropy = Seeded::at(8_484);
        first_contact(
            &store_c,
            &mut net,
            &c.me(),
            b.pk(),
            b"from C",
            |x| entropy.fill(x),
            NOW,
        )
        .expect("C's first contact");
        drop(store_c);

        let requests: Vec<ContactRequest> = b_collects(&b, &mut net)
            .into_iter()
            .map(|surfaced| match surfaced {
                Surfaced::ContactRequest(request) => request,
                other => panic!("expected contact requests, got {other:?}"),
            })
            .collect();
        assert_eq!(requests.len(), 2, "A's and C's hellos are both surfaced");
        let from = |party: &Party| {
            requests
                .iter()
                .find(|r| r.identity.as_slice() == party.pk().as_slice())
                .expect("a request from that party")
        };
        let (from_a, from_c) = (from(&a), from(&c));
        let request = |identity: &ContactRequest, ratchet: &ContactRequest| ContactRequest {
            identity: identity.identity.clone(),
            lookup_key: from_c.lookup_key,
            first_ratchet_pk: ratchet.first_ratchet_pk.clone(),
            slot: from_c.slot,
            advert_serial: from_c.advert_serial,
            shared_secret: AdvertSharedSecret::from_bytes(from_c.shared_secret.as_bytes()),
        };

        let store_b = b.store();
        net.reset_writes();
        let mut entropy = Seeded::at(909);
        let as_a = accept(
            &store_b,
            &mut net,
            &b.me(),
            &request(from_a, from_c),
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        );
        assert!(
            matches!(as_a, Err(FlowError::OpeningWriter)),
            "A's identity over C's opening was not refused as another writer: {as_a:?}"
        );
        let other_key = accept(
            &store_b,
            &mut net,
            &b.me(),
            &request(from_c, from_a),
            b"the reply",
            |x| entropy.fill(x),
            NOW,
        );
        assert!(
            matches!(other_key, Err(FlowError::OpeningRatchetKey)),
            "A's ratchet key over C's opening was not refused: {other_key:?}"
        );
        assert_eq!(net.writes.total(), 0, "a refused acceptance writes nothing");
    }

    /// An ordinary message is refused until this side's first contact has been
    /// accepted, and succeeds once it has.
    #[test]
    fn an_ordinary_message_is_refused_until_the_first_contact_is_accepted() {
        let (a, b, mut net) = scene();
        let outcome = a_opens(&a, &b, &mut net, b"the first message");
        let peer_a = opened_peer(&outcome);

        let store_a = a.store();
        let mut entropy = Seeded::at(99);
        let refused = send_message(
            &store_a,
            &mut net,
            &peer_a,
            b"too early",
            |x| entropy.fill(x),
            NOW,
        );
        assert!(matches!(refused, Err(FlowError::AwaitingAcceptance)));

        b_accepts(&b, &mut net, b"the reply");
        collect(&store_a, &mut net, &a.me(), &a.advert_keys, |_| false).expect("A collects");

        let mut entropy = Seeded::at(100);
        let seq = send_message(
            &store_a,
            &mut net,
            &peer_a,
            b"now",
            |x| entropy.fill(x),
            NOW,
        )
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
