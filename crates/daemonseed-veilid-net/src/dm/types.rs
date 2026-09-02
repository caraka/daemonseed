//! The command / event vocabulary a front end drives the DM driver with, plus the
//! identity halves and the injected clock the driver holds.
//!
//! Every payload is a `daemonseed-core` type or a `String`, with one exception:
//! [`DmEvent::DoorbellHealth`] carries this crate's own [`SweepOutcome`], because
//! record health is a transport observation and core has no type for it. No
//! front-end type crosses this boundary in either direction.

use std::sync::Arc;

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
    },
    /// A channel was torn down loudly.
    ChannelLost {
        /// The correspondent's long-term identity key.
        with: PkLt,
        /// Why the channel ended.
        cause: TeardownCause,
    },
    /// Our own doorbell sweep's record health.
    ///
    /// Observability, never "nobody knocked": an empty slot list alone means both
    /// "no knocks" and "every GET errored", and the outcome separates them.
    DoorbellHealth {
        /// The sweep's GET accounting.
        outcome: SweepOutcome,
    },
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
            DmEvent::Refused { acceptance, .. } => {
                f.write_str("Refused { to: ")?;
                redacted_pk(f)?;
                write!(f, ", acceptance: {acceptance:?} }}")
            }
            DmEvent::ChannelLost { cause, .. } => {
                f.write_str("ChannelLost { with: ")?;
                redacted_pk(f)?;
                write!(f, ", cause: {cause:?} }}")
            }
            DmEvent::DoorbellHealth { outcome } => {
                write!(f, "DoorbellHealth {{ outcome: {outcome:?} }}")
            }
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
