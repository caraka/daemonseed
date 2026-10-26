//! Push delivery: handing the bytes a flow writes to the record store to the
//! correspondent directly as well, and taking such bytes in.
//!
//! `docs/design/direct-messaging.md` § Delivery, *Push*. A push carries the
//! bytes the record store is written with, plus, on a message push, the
//! sender's route and its tag: a message push is one ring slot, and an
//! acceptance push is the accepting side's control subkey, its reply's slot
//! and its hello back. The record-store writes happen whether or not a push is
//! made or answered, so a push that is lost, refused or never answered leaves
//! delivery exactly as it is without push.
//!
//! A pushed message is taken only as the next sequence the conversation
//! expects, and through the same ring read and the same persist that
//! collection uses ([`crate::dm::flows::collect_batch`]); a sequence already
//! collected changes nothing and, where it is the last sequence recorded, is
//! answered as its first push was; an older one, and one ahead of the next,
//! is ignored and left to the record store. A
//! pushed acceptance runs the recognition a drop scan runs
//! ([`crate::dm::flows::collect_slot`]) over a [`ReadCache`] holding the pushed
//! bytes, so every check a scan makes is made. The collected hello back is
//! not erased by a pushed recognition: the next scan finds it and erases it as
//! already collected.
//!
//! A message push may carry the sender's current private route after the slot.
//! The route carries a tag made under the sender's control key for that
//! message ([`route_tag`]), and is handed on only where the tag matches. A
//! receiver does not take it as the sender's route: a route is taken only from
//! a control subkey, which carries the serial the route was issued at
//! ([`crate::dm::store::Store::take_reach`]), so a message pushed before the
//! sender's route changed cannot put the old route back.
//! A reach notice carries the sender's sealed control subkey alone,
//! the same bytes its channel record holds: it is opened under the control key
//! the conversation holds for the sender, so only the correspondent can make
//! one that is taken, and only the correspondent can answer one.
//!
//! A push is answered [`RECORDED`] only after what it carried has been
//! persisted. Nothing here answers anything: the caller replies.
//!
//! Serves FC7.

use crate::dm::advert::AdvertKeys;
use crate::dm::advert::AdvertOwnerSeed;
use crate::dm::channel::ChannelOwnerSeed;
use crate::dm::channel::{self, ChannelError, ControlKey};
use crate::dm::domain;
use crate::dm::drop::{self as drop_plane, DropOwnerSeed, HELLO_LOOKUP_KEY_LEN};
use crate::dm::flows::{
    self, Acceptance, BatchWrite, CachedRecords, FlowError, Me, ReadCache, ReceivedMessage,
    RecordError, Records, RingStep, Surfaced,
};
use crate::dm::store::{Store, StoreError};
use crate::identity::keys::IDENTITY_PK_LEN;
use crate::oxi::HkdfSha384;
use crate::secret_seed::derive_boxed_seed;
use crate::storage::dm_store::CorrespondenceLabel;

/// The bytes every push and every answer to one starts with. No other
/// request on the same transport starts with them.
pub const PUSH_TAG: &[u8; 8] = b"dsdmpsh1";

/// The largest push a transport carries, in bytes. A push that would be
/// larger is not made.
pub const PUSH_MAX_LEN: usize = 32 * 1024;

/// The bytes an answer to a push whose content has been persisted starts
/// with; [`ANSWER_MAC_LEN`] bytes of [`answer`] follow them.
pub const RECORDED: &[u8; 9] = b"dsdmpsh1\x01";

/// Bytes of the code an answer carries after [`RECORDED`].
pub const ANSWER_MAC_LEN: usize = 32;

/// Bytes of a whole answer.
pub const ANSWER_LEN: usize = RECORDED.len() + ANSWER_MAC_LEN;

/// The answer that reports sequence `seq` of the channel at `lookup_key`
/// persisted: [`RECORDED`] followed by `HKDF-Expand(HKDF-Extract(
/// DM_PUSH_ANSWER_SALT, control_key), DM_PUSH_ANSWER ‖ lp(lookup_key) ‖
/// lp(BE64(seq)))`.
///
/// `control_key` is the pushing side's control key: the pusher holds it as its
/// own, the receiver as its correspondent's, and no one else holds it, so an
/// answer that matches was made by the correspondent.
pub fn answer(
    control_key: &ControlKey,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    seq: u64,
) -> Result<[u8; ANSWER_LEN], FlowError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_PUSH_ANSWER_SALT), control_key.as_bytes())
        .map_err(|e| FlowError::Channel(ChannelError::Kdf(e)))?;
    let mut info = Vec::with_capacity(domain::DM_PUSH_ANSWER.len() + 16 + HELLO_LOOKUP_KEY_LEN + 8);
    info.extend_from_slice(domain::DM_PUSH_ANSWER);
    crate::dm::push_lp(&mut info, lookup_key);
    crate::dm::push_lp(&mut info, &seq.to_be_bytes());
    let mac = derive_boxed_seed::<ANSWER_MAC_LEN>(&hkdf, &info)
        .map_err(|e| FlowError::Channel(ChannelError::Kdf(e)))?;
    let mut out = [0u8; ANSWER_LEN];
    out[..RECORDED.len()].copy_from_slice(RECORDED);
    out[RECORDED.len()..].copy_from_slice(mac.as_slice());
    Ok(out)
}

/// Bytes of the tag a message push carries over the sender's route.
pub const ROUTE_TAG_LEN: usize = 32;

/// The tag over `route` carried with sequence `seq` of the channel at
/// `lookup_key`: `HKDF-Expand(HKDF-Extract(DM_PUSH_ANSWER_SALT, control_key),
/// DM_PUSH_ROUTE ‖ lp(lookup_key) ‖ BE64(seq) ‖ lp(route))`.
///
/// `control_key` is the pushing side's control key, as for [`answer`], so a
/// tag that matches was made by the correspondent, for that route and that
/// message.
pub fn route_tag(
    control_key: &ControlKey,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    seq: u64,
    route: &[u8],
) -> Result<[u8; ROUTE_TAG_LEN], FlowError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_PUSH_ANSWER_SALT), control_key.as_bytes())
        .map_err(|e| FlowError::Channel(ChannelError::Kdf(e)))?;
    let mut info =
        Vec::with_capacity(domain::DM_PUSH_ROUTE.len() + 24 + HELLO_LOOKUP_KEY_LEN + route.len());
    info.extend_from_slice(domain::DM_PUSH_ROUTE);
    crate::dm::push_lp(&mut info, lookup_key);
    info.extend_from_slice(&seq.to_be_bytes());
    crate::dm::push_lp(&mut info, route);
    let tag = derive_boxed_seed::<ROUTE_TAG_LEN>(&hkdf, &info)
        .map_err(|e| FlowError::Channel(ChannelError::Kdf(e)))?;
    let mut out = [0u8; ROUTE_TAG_LEN];
    out.copy_from_slice(tag.as_slice());
    Ok(out)
}

/// A sender's private-route blob as a message push carries it, with the tag
/// that binds it to the message ([`route_tag`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRoute {
    /// The route blob: non-empty and at most [`channel::REACH_ROUTE_MAX_LEN`]
    /// bytes.
    pub route: Vec<u8>,
    /// [`route_tag`] over `route` at the pushed message's sequence.
    pub tag: [u8; ROUTE_TAG_LEN],
}

/// A copy of a conversation's control key held to check answers with, by a
/// caller outside this crate that cannot copy the key itself.
pub struct AnswerKey(ControlKey);

impl AnswerKey {
    /// A copy of `control_key`.
    pub fn new(control_key: &ControlKey) -> Self {
        Self(ControlKey::from_bytes(control_key.as_bytes()))
    }

    /// [`answer`] under this key.
    pub fn answer(
        &self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        seq: u64,
    ) -> Result<[u8; ANSWER_LEN], FlowError> {
        answer(&self.0, lookup_key, seq)
    }

    /// [`route_tag`] under this key.
    pub fn route_tag(
        &self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        seq: u64,
        route: &[u8],
    ) -> Result<[u8; ROUTE_TAG_LEN], FlowError> {
        route_tag(&self.0, lookup_key, seq, route)
    }
}

impl core::fmt::Debug for AnswerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AnswerKey(<redacted>)")
    }
}

/// Whether `got` is `expected`, compared in time independent of where they
/// differ.
pub fn answer_matches(expected: &[u8; ANSWER_LEN], got: &[u8]) -> bool {
    same_bytes(expected, got)
}

/// Whether `got` is `expected`, compared in time independent of where they
/// differ.
fn same_bytes(expected: &[u8], got: &[u8]) -> bool {
    if got.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in expected.iter().zip(got) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

const KIND_MESSAGE: u8 = 1;
const KIND_ACCEPTANCE: u8 = 2;
const KIND_REACH: u8 = 3;
const KIND_MESSAGE_WITH_ROUTE: u8 = 4;

/// One push, as it travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Push {
    /// One ring slot of the sender's channel.
    Message {
        /// The sender's channel, which the receiver reads.
        lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
        /// The subkey the slot is written to.
        subkey: u16,
        /// The slot's bytes.
        slot: Vec<u8>,
        /// The sender's current private route, where it has one it can
        /// publish, with its tag.
        route: Option<PushRoute>,
    },
    /// The sender's sealed control subkey, sent to the route it holds for
    /// the receiver so the receiver learns the sender's reach without
    /// reading the record store.
    Reach {
        /// The sender's channel, which the receiver reads.
        lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
        /// The sealed control subkey, as the channel record holds it.
        control: Vec<u8>,
    },
    /// What an acceptance writes: the accepting side's control subkey and
    /// reply, and its hello back.
    Acceptance {
        /// The accepting side's channel.
        lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
        /// The receiver's drop slot the hello back is placed in.
        hello_slot: u16,
        /// The sealed hello back.
        hello: Vec<u8>,
        /// The accepting side's sealed control subkey.
        control: Vec<u8>,
        /// The subkey the reply is written to.
        reply_subkey: u16,
        /// The reply's slot bytes.
        reply: Vec<u8>,
    },
}

impl Push {
    /// Encode: [`PUSH_TAG`] ‖ kind ‖ lookup key, then for a message without
    /// a route, kind 1, `BE16(subkey) ‖ slot`; for a message with one, kind 4,
    /// `BE16(subkey) ‖ lp(slot) ‖ lp(route) ‖ tag`, the tag
    /// [`ROUTE_TAG_LEN`] bytes; for a reach notice, kind 3,
    /// `lp(control)`; and for an acceptance, kind 2, `BE16(hello_slot) ‖
    /// lp(hello) ‖ lp(control) ‖ BE16(reply_subkey) ‖ lp(reply)`. A route
    /// that is empty or longer than [`channel::REACH_ROUTE_MAX_LEN`] is left
    /// out. `None` where the result would exceed [`PUSH_MAX_LEN`].
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(PUSH_TAG);
        match self {
            Self::Message {
                lookup_key,
                subkey,
                slot,
                route,
            } => match route.as_ref().filter(|route| publishable(&route.route)) {
                Some(route) => {
                    out.push(KIND_MESSAGE_WITH_ROUTE);
                    out.extend_from_slice(lookup_key);
                    out.extend_from_slice(&subkey.to_be_bytes());
                    crate::dm::push_lp(&mut out, slot);
                    crate::dm::push_lp(&mut out, &route.route);
                    out.extend_from_slice(&route.tag);
                }
                None => {
                    out.push(KIND_MESSAGE);
                    out.extend_from_slice(lookup_key);
                    out.extend_from_slice(&subkey.to_be_bytes());
                    out.extend_from_slice(slot);
                }
            },
            Self::Reach {
                lookup_key,
                control,
            } => {
                out.push(KIND_REACH);
                out.extend_from_slice(lookup_key);
                crate::dm::push_lp(&mut out, control);
            }
            Self::Acceptance {
                lookup_key,
                hello_slot,
                hello,
                control,
                reply_subkey,
                reply,
            } => {
                out.push(KIND_ACCEPTANCE);
                out.extend_from_slice(lookup_key);
                out.extend_from_slice(&hello_slot.to_be_bytes());
                crate::dm::push_lp(&mut out, hello);
                crate::dm::push_lp(&mut out, control);
                out.extend_from_slice(&reply_subkey.to_be_bytes());
                crate::dm::push_lp(&mut out, reply);
            }
        }
        (out.len() <= PUSH_MAX_LEN).then_some(out)
    }

    /// Decode a push, or `None` for bytes that are not one: another tag, an
    /// unknown kind, a field that runs out, trailing bytes, a route that is
    /// empty or longer than [`channel::REACH_ROUTE_MAX_LEN`] or has no whole
    /// tag after it, or a control
    /// that is empty or longer than [`channel::SEALED_CONTROL_MAX_LEN`].
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.strip_prefix(PUSH_TAG.as_slice())?;
        let (&kind, rest) = rest.split_first()?;
        let (lookup_key, rest) = rest.split_at_checked(HELLO_LOOKUP_KEY_LEN)?;
        let lookup_key: [u8; HELLO_LOOKUP_KEY_LEN] = lookup_key.try_into().ok()?;
        match kind {
            KIND_MESSAGE => {
                let (subkey, slot) = take_u16(rest)?;
                Some(Self::Message {
                    lookup_key,
                    subkey,
                    slot: slot.to_vec(),
                    route: None,
                })
            }
            KIND_MESSAGE_WITH_ROUTE => {
                let (subkey, rest) = take_u16(rest)?;
                let (slot, rest) = take_lp(rest)?;
                let (route, rest) = take_lp(rest)?;
                let (tag, rest) = rest.split_at_checked(ROUTE_TAG_LEN)?;
                let tag: [u8; ROUTE_TAG_LEN] = tag.try_into().ok()?;
                (rest.is_empty() && publishable(route)).then(|| Self::Message {
                    lookup_key,
                    subkey,
                    slot: slot.to_vec(),
                    route: Some(PushRoute {
                        route: route.to_vec(),
                        tag,
                    }),
                })
            }
            KIND_REACH => {
                let (control, rest) = take_lp(rest)?;
                (rest.is_empty()
                    && !control.is_empty()
                    && control.len() <= channel::SEALED_CONTROL_MAX_LEN)
                    .then(|| Self::Reach {
                        lookup_key,
                        control: control.to_vec(),
                    })
            }
            KIND_ACCEPTANCE => {
                let (hello_slot, rest) = take_u16(rest)?;
                let (hello, rest) = take_lp(rest)?;
                let (control, rest) = take_lp(rest)?;
                let (reply_subkey, rest) = take_u16(rest)?;
                let (reply, rest) = take_lp(rest)?;
                rest.is_empty().then(|| Self::Acceptance {
                    lookup_key,
                    hello_slot,
                    hello: hello.to_vec(),
                    control: control.to_vec(),
                    reply_subkey,
                    reply: reply.to_vec(),
                })
            }
            _ => None,
        }
    }
}

/// Whether `bytes` start with [`PUSH_TAG`], which is how a transport tells a
/// push from every other request it carries.
pub fn is_push(bytes: &[u8]) -> bool {
    bytes.starts_with(PUSH_TAG)
}

/// Whether `route` is one a control record would carry.
fn publishable(route: &[u8]) -> bool {
    !route.is_empty() && route.len() <= channel::REACH_ROUTE_MAX_LEN
}

fn take_u16(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let (head, rest) = bytes.split_at_checked(2)?;
    Some((u16::from_be_bytes(head.try_into().ok()?), rest))
}

fn take_lp(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_at_checked(8)?;
    let len = usize::try_from(u64::from_be_bytes(len.try_into().ok()?)).ok()?;
    rest.split_at_checked(len)
}

/// What [`take_message`] did with a pushed message.
#[derive(Debug)]
pub enum Taken {
    /// Opened and persisted as the next sequence: answer with `answer`.
    Recorded {
        /// The conversation.
        peer: CorrespondenceLabel,
        /// Its sequence in the correspondent's direction.
        seq: u64,
        /// The opened message.
        message: ReceivedMessage,
        /// The answer that reports it persisted ([`answer`]).
        answer: [u8; ANSWER_LEN],
        /// The route the push carried, where its tag is [`route_tag`] at
        /// `seq` under the correspondent's control key. A route with any other
        /// tag is left out and the message is recorded all the same. It
        /// carries no reach serial, so it is not one to take as the
        /// correspondent's route.
        route: Option<Vec<u8>>,
    },
    /// From a correspondent `is_blocked` holds. Nothing was read or changed.
    Blocked {
        /// The conversation.
        peer: CorrespondenceLabel,
    },
    /// A sequence already collected. Nothing was changed.
    Duplicate {
        /// The conversation.
        peer: CorrespondenceLabel,
        /// Where the sequence is the last one recorded, the answer that
        /// reports it persisted ([`answer`]), as its first push was answered;
        /// `None` for any older sequence, which is left unanswered.
        answer: Option<[u8; ANSWER_LEN]>,
    },
    /// A sequence past the next one expected, left to the record store.
    /// Nothing was changed.
    Ahead {
        /// The conversation.
        peer: CorrespondenceLabel,
    },
    /// Not a message of any conversation this side collects: no conversation
    /// reads that channel, the conversation is not established or is being
    /// deleted, or the slot does not decode or open under its key schedule.
    /// Nothing was changed.
    Dropped,
}

/// Take a pushed ring slot in as a collection of one message would.
///
/// The conversation is the one whose incoming channel is `lookup_key`, and
/// only once it is established: a first contact awaiting acceptance learns
/// its correspondent's channel from the acceptance. The slot must name the
/// next sequence the conversation expects at `subkey`, and it is taken by
/// [`flows::collect_step`] reading it as the next slot of the ring, so a slot
/// that does not open under the conversation's key schedule changes nothing,
/// and a message this returns is persisted as read before it is returned. The
/// cursor reaches the record store with the next [`flows::publish_cursor`].
/// `route` is the route the push carried, handed back in [`Taken::Recorded`]
/// only where its tag matches. A slot naming a sequence already collected is
/// [`Taken::Duplicate`], carrying the answer that sequence's first push was
/// given where it is the last sequence recorded, and none otherwise.
///
/// Where the conversation record changes between the load and the commit
/// ([`FlowError::Conflict`]), nothing is recorded and the push is taken again
/// from a fresh load, at most [`TAKE_ATTEMPTS`] times in all; the last
/// attempt's conflict is returned.
pub fn take_message(
    store: &Store,
    is_blocked: impl Fn(&[u8; IDENTITY_PK_LEN]) -> bool,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    subkey: u16,
    slot: &[u8],
    route: Option<&PushRoute>,
) -> Result<Taken, FlowError> {
    let mut attempts = 1;
    loop {
        match take_message_once(store, &is_blocked, lookup_key, subkey, slot, route) {
            Err(FlowError::Conflict) if attempts < TAKE_ATTEMPTS => attempts += 1,
            taken => return taken,
        }
    }
}

/// How many times [`take_message`] takes one push whose commit conflicts.
pub const TAKE_ATTEMPTS: usize = 4;

fn take_message_once(
    store: &Store,
    is_blocked: &impl Fn(&[u8; IDENTITY_PK_LEN]) -> bool,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    subkey: u16,
    slot: &[u8],
    route: Option<&PushRoute>,
) -> Result<Taken, FlowError> {
    if lookup_key == &[0u8; HELLO_LOOKUP_KEY_LEN] {
        return Ok(Taken::Dropped);
    }
    let Some(conv) = store
        .load()?
        .convs
        .into_iter()
        .find(|conv| &conv.state.incoming_lookup_key == lookup_key)
    else {
        return Ok(Taken::Dropped);
    };
    let (peer, state) = (conv.peer, conv.state);
    if is_blocked(&state.peer_identity_pk) {
        return Ok(Taken::Blocked { peer });
    }
    if state.delete_pending || state.awaiting_acceptance || state.acceptance_pending {
        return Ok(Taken::Dropped);
    }
    let Some(peer_control_key) = state.peer_control_key.as_ref() else {
        return Ok(Taken::Dropped);
    };
    let Ok((header, _)) = channel::MessageHeader::decode(slot) else {
        return Ok(Taken::Dropped);
    };
    if header.seq < state.my_collected {
        return duplicate(
            peer,
            peer_control_key,
            lookup_key,
            header.seq,
            state.my_collected,
        );
    }
    if header.seq > state.my_collected {
        return Ok(Taken::Ahead { peer });
    }
    if subkey != channel::slot_for(header.seq) {
        return Ok(Taken::Dropped);
    }
    let mut one = OneSlot {
        lookup_key: *lookup_key,
        subkey,
        slot,
    };
    #[cfg(test)]
    if let Some(hook) = BEFORE_PUSHED_STEP.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
    match flows::collect_step(store, &mut one, &peer) {
        Ok(RingStep::Message { seq, message, .. }) => {
            let route = match route {
                Some(route) => {
                    let expected = route_tag(peer_control_key, lookup_key, seq, &route.route)?;
                    same_bytes(&expected, &route.tag).then(|| route.route.clone())
                }
                None => None,
            };
            Ok(Taken::Recorded {
                peer,
                seq,
                message,
                answer: answer(peer_control_key, lookup_key, seq)?,
                route,
            })
        }
        // The cursor moved past this sequence since the check above.
        Ok(RingStep::End) => {
            let collected = store
                .load_conv(&peer)?
                .map_or(header.seq, |state| state.my_collected);
            duplicate(peer, peer_control_key, lookup_key, header.seq, collected)
        }
        Ok(RingStep::Unopened(_))
        | Err(FlowError::DeletePending)
        | Err(FlowError::AwaitingAcceptance)
        | Err(FlowError::Store(StoreError::MissingConversation)) => Ok(Taken::Dropped),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
thread_local! {
    /// Run once by [`take_message`] between its check of the expected
    /// sequence and its ring read, so a test can land a recording in that gap.
    static BEFORE_PUSHED_STEP: core::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { core::cell::RefCell::new(None) };
}

/// Run `hook` once, in the next [`take_message`] on this thread, between its
/// check of the expected sequence and its ring read.
#[cfg(test)]
pub(crate) fn before_next_pushed_step(hook: impl FnOnce() + 'static) {
    BEFORE_PUSHED_STEP.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// [`Taken::Duplicate`] for a slot naming `seq`, below `collected`: answered
/// only where `seq` is the last sequence recorded, the one a push that lost a
/// race to a watched change or a ring read names. The header naming `seq` is
/// not authenticated, so the answer of an older sequence is not given.
fn duplicate(
    peer: CorrespondenceLabel,
    control_key: &ControlKey,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    seq: u64,
    collected: u64,
) -> Result<Taken, FlowError> {
    let answer = if seq.checked_add(1) == Some(collected) {
        Some(answer(control_key, lookup_key, seq)?)
    } else {
        None
    };
    Ok(Taken::Duplicate { peer, answer })
}

/// What [`take_reach`] did with a reach notice.
#[derive(Debug)]
pub enum ReachTaken {
    /// The control opened under the control key the conversation holds for
    /// its correspondent: take in its reach and cursor, and answer with
    /// `answer`.
    Applied {
        /// The conversation.
        peer: CorrespondenceLabel,
        /// The opened control subkey.
        control: channel::Control,
        /// The answer the pusher checks the notice was taken by
        /// ([`answer`] at [`reach_seq`] of the notice's control).
        answer: [u8; ANSWER_LEN],
    },
    /// From a correspondent `is_blocked` holds. Nothing was opened.
    Blocked {
        /// The conversation.
        peer: CorrespondenceLabel,
    },
    /// Not the control of any conversation this side reads: no conversation
    /// reads that channel, the conversation is not established or is being
    /// deleted, or the control does not open under its key. Not answered.
    Dropped,
}

/// The sequence a reach notice's answer is made at: the first eight bytes of
/// `SHA-384(control)`, big-endian, so an answer is bound to the one notice it
/// answers.
pub fn reach_seq(control: &[u8]) -> Result<u64, FlowError> {
    let digest =
        crate::oxi::sha384(control).map_err(|e| FlowError::Channel(ChannelError::Module(e)))?;
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&digest[..8]);
    Ok(u64::from_be_bytes(seq))
}

/// Open a reach notice: the sealed control subkey of the channel at
/// `lookup_key`, pushed by its writer.
///
/// The conversation is the one whose incoming channel is `lookup_key`, once it
/// is established. The control is opened under the control key that
/// conversation holds for its correspondent, so a notice from anyone else does
/// not open and is not answered. Nothing is persisted: the caller takes the
/// reach and cursor in as it takes a control read from the record store.
pub fn take_reach(
    store: &Store,
    is_blocked: impl Fn(&[u8; IDENTITY_PK_LEN]) -> bool,
    lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
    control: &[u8],
) -> Result<ReachTaken, FlowError> {
    if lookup_key == &[0u8; HELLO_LOOKUP_KEY_LEN] {
        return Ok(ReachTaken::Dropped);
    }
    let Some(conv) = store
        .load()?
        .convs
        .into_iter()
        .find(|conv| &conv.state.incoming_lookup_key == lookup_key)
    else {
        return Ok(ReachTaken::Dropped);
    };
    let (peer, state) = (conv.peer, conv.state);
    if is_blocked(&state.peer_identity_pk) {
        return Ok(ReachTaken::Blocked { peer });
    }
    if state.delete_pending || state.awaiting_acceptance || state.acceptance_pending {
        return Ok(ReachTaken::Dropped);
    }
    let Some(peer_control_key) = state.peer_control_key.as_ref() else {
        return Ok(ReachTaken::Dropped);
    };
    let Ok(opened) = channel::open_control_with_key(peer_control_key, control) else {
        return Ok(ReachTaken::Dropped);
    };
    Ok(ReachTaken::Applied {
        peer,
        control: opened,
        answer: answer(peer_control_key, lookup_key, reach_seq(control)?)?,
    })
}

/// Recognise a pushed acceptance of this side's own first contact.
///
/// Runs [`flows::collect_slot`] for the pushed hello's slot over a
/// [`ReadCache`] holding the pushed hello, control subkey and reply, with the
/// subkey after the reply reading empty. Every check a drop scan makes is made,
/// and a read the pushed bytes do not cover goes to `records`. The hello back's
/// erase is not made.
///
/// `Some` only where the push completed an acceptance, which has then been
/// persisted, with the answer that reports it; `None` for anything else, with
/// nothing changed. An acceptance from an identity `is_blocked` holds is
/// `None`.
pub fn recognise_acceptance<R: Records>(
    store: &Store,
    records: &mut R,
    me: &Me<'_>,
    advert_keys: &AdvertKeys,
    is_blocked: impl Fn(&[u8; IDENTITY_PK_LEN]) -> bool,
    push: &Push,
) -> Result<Option<(Acceptance, [u8; ANSWER_LEN])>, FlowError> {
    let Push::Acceptance {
        lookup_key,
        hello_slot,
        hello,
        control,
        reply_subkey,
        reply,
    } = push
    else {
        return Ok(None);
    };
    let Ok((header, _)) = channel::MessageHeader::decode(reply) else {
        return Ok(None);
    };
    if *reply_subkey != channel::slot_for(header.seq) {
        return Ok(None);
    }
    let Some(next) = header.seq.checked_add(1) else {
        return Ok(None);
    };
    let my_drop = drop_plane::derive_owner_seed(me.signer.public_key())?;
    let mut cache = ReadCache::default();
    cache.insert_drop_slot(&my_drop, *hello_slot, hello.clone());
    cache.insert_channel(lookup_key, channel::CONTROL_SUBKEY, Some(control.clone()));
    cache.insert_channel(lookup_key, *reply_subkey, Some(reply.clone()));
    cache.insert_channel(lookup_key, channel::slot_for(next), None);
    let mut no_erase = NoErase(records);
    let mut cached = CachedRecords::new(&mut no_erase, cache);
    match flows::collect_slot(store, &mut cached, me, advert_keys, is_blocked, *hello_slot)? {
        Some(Surfaced::Accepted(acceptance)) => {
            let state = store
                .load_conv(&acceptance.peer)?
                .ok_or(FlowError::Store(StoreError::MissingConversation))?;
            let key = state
                .peer_control_key
                .as_ref()
                .ok_or(FlowError::Incomplete("control key of the correspondent"))?;
            let answer = answer(key, lookup_key, header.seq)?;
            Ok(Some((acceptance, answer)))
        }
        _ => Ok(None),
    }
}

/// The record store a pushed message is read through: the one slot it
/// carries, and nothing else. Every other call is refused.
struct OneSlot<'a> {
    lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
    subkey: u16,
    slot: &'a [u8],
}

fn refused() -> RecordError {
    RecordError::new(std::io::Error::other("a pushed slot is read alone"))
}

impl Records for OneSlot<'_> {
    fn read_advert(&mut self, _: &AdvertOwnerSeed, _: u16) -> Result<Option<Vec<u8>>, RecordError> {
        Err(refused())
    }

    fn read_drop_slot(
        &mut self,
        _: &DropOwnerSeed,
        _: u16,
        _: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        Err(refused())
    }

    fn write_drop_slot(
        &mut self,
        _: &DropOwnerSeed,
        _: u16,
        _: u16,
        _: &[u8],
    ) -> Result<(), RecordError> {
        Err(refused())
    }

    fn erase_drop_slot(&mut self, _: &DropOwnerSeed, _: u16, _: u16) -> Result<(), RecordError> {
        Err(refused())
    }

    fn open_channel(
        &mut self,
        _: &ChannelOwnerSeed,
        _: u16,
    ) -> Result<[u8; HELLO_LOOKUP_KEY_LEN], RecordError> {
        Err(refused())
    }

    fn read_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        Ok((lookup_key == &self.lookup_key && subkey == self.subkey).then(|| self.slot.to_vec()))
    }

    fn write_channel(
        &mut self,
        _: &[u8; HELLO_LOOKUP_KEY_LEN],
        _: u16,
        _: &[u8],
    ) -> Result<(), RecordError> {
        Err(refused())
    }
}

/// A record store that refuses every call: what a push is taken through where
/// no network call may be made. [`recognise_acceptance`] over it recognises an
/// acceptance from the pushed bytes alone, and refuses one they do not cover.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoNetwork;

fn no_network() -> RecordError {
    RecordError::new(std::io::Error::other("no network call is made here"))
}

impl Records for NoNetwork {
    fn read_advert(&mut self, _: &AdvertOwnerSeed, _: u16) -> Result<Option<Vec<u8>>, RecordError> {
        Err(no_network())
    }

    fn read_drop_slot(
        &mut self,
        _: &DropOwnerSeed,
        _: u16,
        _: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        Err(no_network())
    }

    fn write_drop_slot(
        &mut self,
        _: &DropOwnerSeed,
        _: u16,
        _: u16,
        _: &[u8],
    ) -> Result<(), RecordError> {
        Err(no_network())
    }

    fn erase_drop_slot(&mut self, _: &DropOwnerSeed, _: u16, _: u16) -> Result<(), RecordError> {
        Err(no_network())
    }

    fn open_channel(
        &mut self,
        _: &ChannelOwnerSeed,
        _: u16,
    ) -> Result<[u8; HELLO_LOOKUP_KEY_LEN], RecordError> {
        Err(no_network())
    }

    fn read_channel(
        &mut self,
        _: &[u8; HELLO_LOOKUP_KEY_LEN],
        _: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        Err(no_network())
    }

    fn write_channel(
        &mut self,
        _: &[u8; HELLO_LOOKUP_KEY_LEN],
        _: u16,
        _: &[u8],
    ) -> Result<(), RecordError> {
        Err(no_network())
    }
}

/// `records` with the drop-slot erase left undone and reported done.
struct NoErase<'a, R>(&'a mut R);

impl<R: Records> Records for NoErase<'_, R> {
    fn read_advert(
        &mut self,
        owner: &AdvertOwnerSeed,
        subkeys: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        self.0.read_advert(owner, subkeys)
    }

    fn read_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        self.0.read_drop_slot(owner, subkeys, slot)
    }

    fn write_drop_slot(
        &mut self,
        owner: &DropOwnerSeed,
        subkeys: u16,
        slot: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        self.0.write_drop_slot(owner, subkeys, slot, bytes)
    }

    fn erase_drop_slot(&mut self, _: &DropOwnerSeed, _: u16, _: u16) -> Result<(), RecordError> {
        Ok(())
    }

    fn open_channel(
        &mut self,
        owner: &ChannelOwnerSeed,
        subkeys: u16,
    ) -> Result<[u8; HELLO_LOOKUP_KEY_LEN], RecordError> {
        self.0.open_channel(owner, subkeys)
    }

    fn read_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
    ) -> Result<Option<Vec<u8>>, RecordError> {
        self.0.read_channel(lookup_key, subkey)
    }

    fn write_channel(
        &mut self,
        lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN],
        subkey: u16,
        bytes: &[u8],
    ) -> Result<(), RecordError> {
        self.0.write_channel(lookup_key, subkey, bytes)
    }

    fn write_batch(&mut self, writes: &[BatchWrite<'_>]) -> Vec<Result<(), RecordError>> {
        let kept: Vec<BatchWrite<'_>> = writes
            .iter()
            .filter(|write| !matches!(write, BatchWrite::EraseDropSlot { .. }))
            .copied()
            .collect();
        let mut done = self.0.write_batch(&kept).into_iter();
        writes
            .iter()
            .map_while(|write| match write {
                BatchWrite::EraseDropSlot { .. } => Some(Ok(())),
                BatchWrite::Channel { .. } => done.next(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module() {
        let _ = crate::oxi::initialize_module();
    }

    /// **Known-answer vectors, computed outside this crate from the preimages
    /// [`answer`] and [`route_tag`] document.** A round trip cannot see a
    /// change that is uniformly wrong, such as a dropped length prefix or an
    /// edited label, because the pusher and the receiver would still agree
    /// with each other while agreeing with no other implementation.
    #[test]
    fn known_answer_answer_and_route_tag() {
        module();
        let key = ControlKey::from_bytes(&[0x5au8; 32]);
        let lookup_key = [0x44u8; HELLO_LOOKUP_KEY_LEN];
        let route: Vec<u8> = (1u8..=40).collect();
        assert_eq!(
            hex::encode(answer(&key, &lookup_key, 7).unwrap()),
            KAT_ANSWER
        );
        assert_eq!(
            hex::encode(route_tag(&key, &lookup_key, 7, &route).unwrap()),
            KAT_ROUTE_TAG
        );
    }

    /// `answer` under a control key of 32 `0x5a` bytes, a lookup key of 32
    /// `0x44` bytes and sequence 7: [`RECORDED`] followed by the 32-byte code.
    const KAT_ANSWER: &str =
        "6473646d7073683101d6962141e2a8e6aa2d15bd1aa40051c9fed1ad61ea932642d74ee6f4c1557780";

    /// `route_tag` under the same key, lookup key and sequence, over a route
    /// of the 40 bytes `0x01` to `0x28`.
    const KAT_ROUTE_TAG: &str = "34bb7a1894b51facf8148dbeffebaf959e36a9328085a2ad853bf3e8df5234ff";
}
