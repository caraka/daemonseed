//! What a DM channel persists across a restart, and what it says when it cannot
//! continue (#243, ISC-C44).
//!
//! Two things survive a restart, and a running ratchet is not one of them.
//!
//! | Persisted | Shape | Frozen requirement |
//! |---|---|---|
//! | the provisional handshake record | [`ProvisionalRecord`] — sealed, fixed-size, deleted on establishment | § v4 4.1 + § v5 V4-2 |
//! | the receive cursor | [`ReceiveCursor`] — a page number, not secret | § v5 erasure caveat |
//!
//! ## Why the steady-state ratchet is not here
//!
//! The frozen design has the chains **delete on use** (`direct-messaging.md`
//! § v5), and that is the whole of DM's forward secrecy. A chain written down at
//! rest is a chain that was not deleted, so persisting one makes delete-on-use
//! false exactly where it is load-bearing. The surrounding design already accepts
//! losing a conversation — hard give-up at seven days, "no progress in 7 days →
//! both abandon (teardown)", "residual is missed backlog … not channel loss" — so
//! an established channel that cannot resume is inside the design's own
//! tolerances.
//!
//! What was **never** tolerable is the way it used to end. Both parties came back
//! at generation zero, every frame failed `UnknownEphemeral` forever, the ratchet
//! reported no losses at all, and neither the peer nor the local user was told:
//! a dead conversation that rendered as a healthy one. That is the defect, and
//! [`ChannelRestart`] is the answer to it — the channel still ends, but it ends
//! **loudly**, at a classed [`TrustEventKey`] the user sees and the audit log
//! keeps.
//!
//! ## What the record stores, and what it recomputes
//!
//! `{version, ss0, eph_ek, eph_dk}` — and **not** `AR`, **not** `chan_id`, **not**
//! the ratchet root `RK`. All three are pure functions of `ss0`:
//! [`derive_channel_roots`] HKDF-expands `ar` and `chan_id` from an extract over
//! `ss0`, and the root comes from the same extract under
//! [`domain::DM_RATCHET_ROOT`] — three siblings of one extraction, which
//! `ratchet`'s own `the_three_roots_from_ss0_are_independent` pins.
//!
//! So they are recomputed on restore rather than stored. That is not only fewer
//! secret bytes at rest and a smaller fixed-size record: it makes an
//! internally-inconsistent record **impossible to construct** instead of
//! something a validator has to catch. There is deliberately no `AR`/`RK`
//! cross-check in [`ProvisionalRecord::open`], because there is no longer a class
//! of inconsistency for one to detect.
//!
//! `chan_id` additionally must never be serialized anywhere (§ v4 minor
//! invariant) — writing it down collapses the address scatter the channel rests
//! on. Recomputing it satisfies that for free.
//!
//! ## Whose record this is
//!
//! The initiator's. § v5 (V4-2) names it verbatim — `{ss0, A's opening ephemeral
//! DK}` — and `ProvisionalRecord::into_ratchet` is the one construction path
//! from it. The recipient's half of § v4 4.1 (`PK_pc_A`, the peer pseudonym it
//! must verify frames against) is **not** here and is not recomputable from
//! `ss0`; its home is the ISC-C44 contact cache, which holds "long-term +
//! pseudonym pubkeys" per contact.
//!
//! ## At rest
//!
//! `nonce(12) ‖ AES-256-GCM(version ‖ binding ‖ ss0 ‖ eph_ek ‖ eph_dk) ‖ tag(16)`
//! — one fixed size, [`PROVISIONAL_RECORD_LEN`], for every record. The key is the
//! caller's, derived by [`derive_seal_key`] from the profile's at-rest material
//! and **never** from `ss0`: a record keyed on the secret it contains could not
//! be opened without already holding it.
//!
//! ## The two bindings, and what each one is for
//!
//! The seal key is per-**profile**, and the record's contents are three secrets
//! that only mean anything together. Two distinct confusions follow from that,
//! and each has its own binding.
//!
//! **Which channel this record is** — [`RecordContext`], bound as AAD. Without
//! it every provisional record in a profile is an interchangeable ciphertext:
//! copy channel B's record over channel A's and it opens cleanly, the version
//! matches, the halves pair, and A resumes as B — no teardown, no event, the
//! wrong correspondent. So [`ProvisionalRecord::seal`] and
//! [`ProvisionalRecord::open`] both take what the caller *expects* this record to
//! be, and a record from another channel fails to authenticate.
//! [`crate::dm::firstcontact`] binds `addr ‖ epoch` for exactly this reason; the
//! construction here is that one.
//!
//! **That the parts belong to each other** — the binding tag, carried inside the
//! sealed plaintext. [`EphemeralDecapKey::matches`] binds the two ephemeral
//! halves to each other, and nothing bound either of them to `ss0`. A record
//! splicing one channel's `ss0` onto another's ephemeral therefore passed
//! [`ProvisionalRecord::new`], [`ProvisionalRecord::open`] and
//! `ProvisionalRecord::into_ratchet`, and then failed every reply forever with
//! `UnknownEphemeral` — the silent death this module exists to abolish,
//! reintroduced by the record meant to prevent it. The tag is a short HKDF output
//! over `ss0` and the opening ephemeral under [`domain::DM_PROVISIONAL_BIND`],
//! verified on open.
//!
//! The two are not redundant. The AAD says *whose* record this is and is checked
//! by the AEAD; the tag says the contents are internally one channel's and is
//! checked after it. A splice assembled from two records of the *same* profile
//! and channel context passes the first and fails the second.
//!
//! **A fixed size is a privacy property, not tidiness.** A variable-length record
//! would leak which of its optional parts a handshake had reached, and a
//! directory of them would leak how many handshakes are pending.
//!
//! **`ss0` genuinely wants erasing.** It roots `RK0`, so a recovered `ss0`
//! reopens the early chain — the harvest-now-decrypt-later exposure § v5 exists
//! to bound. The record is therefore written to one small fixed-size file and
//! **deleted when the channel establishes**, never appended or journaled —
//! [`crate::dm::persist`] is the wiring that does both, and the deletion cannot
//! be separated from the establishment it belongs to. There is no slot pair:
//! with a loud teardown, *losing* this record is tolerable — the handshake
//! strands and we say so — so the crash-safety argument for alternating slots
//! does not apply.
//!
//! What this can honestly promise stops at the filesystem API, and the shape of
//! that limit is worth stating exactly rather than by analogy — including where
//! the two write paths differ, because they do.
//!
//! A **replacement** is committed with `rename(2)`, which does *not* overwrite
//! the bytes it supersedes: the old record's blocks are unreferenced, not
//! scrubbed. That is accepted deliberately — crash-atomic replacement and
//! in-place erasure are opposed, and a torn replacement is neither the old value
//! nor the new one. A **deletion** does overwrite: it scrubs the record in
//! place, in two fsynced phases, before unlinking. Deletion can afford it
//! because losing a record mid-delete costs nothing that losing it any other way
//! does not.
//!
//! Neither reaches the medium. An SSD's FTL remaps an overwrite onto a fresh
//! block and a copy-on-write filesystem writes a new extent by design, so an
//! adversary with the raw flash is outside what any store here can deliver. What
//! erasure buys is that `ss0` is gone from the filesystem's view, from every
//! subsequent read, and from the blocks the filesystem believes it wrote.

use oxicrypt_aes::{Aes256Key, ModeError};
use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_kem as ml_kem;
use zeroize::{Zeroize, Zeroizing};

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::circle::message::{NONCE_LEN, TAG_LEN};
use crate::dm::firstcontact::{FirstContactError, ROOT_LEN, SS0_LEN, derive_channel_roots};
use crate::dm::paging::MAX_PAGE;
use crate::dm::ratchet::{EphemeralDecapKey, Ratchet, RatchetError};
use crate::dm::{domain, keyrec, push_lp};
use crate::storage::seeds::AEAD_KEY_LEN;
use crate::trust_events::TrustEventKey;

/// Format version of a [`ProvisionalRecord`]'s plaintext.
///
/// **In the plaintext, not in the AAD** — and that placement is the whole point
/// of having it. Bound as AAD instead, a reader expecting a later version would
/// simply fail to open an earlier record, and an AEAD failure here is the uniform
/// "did not open" that corruption, a wrong key and tampering all produce. In the
/// plaintext it is read *after* the open succeeds, so a shape change reports
/// [`ProvisionalError::UnsupportedVersion`] naming the version it found. Loud is
/// not enough on its own; this makes it diagnosable.
pub const PROVISIONAL_RECORD_VERSION: u8 = 1;

/// Length of the binding tag that ties `ss0` to the opening ephemeral.
///
/// Sixteen bytes, not thirty-two. It is not a key and never leaves the sealed
/// plaintext — an attacker able to grind it already holds the AEAD key and with
/// it the whole record, so its only job is to make an *internally spliced*
/// record fail closed. Anything longer would spend record bytes on a margin
/// nothing can use.
pub const BINDING_TAG_LEN: usize = 16;

/// Plaintext length: the version byte, the binding tag, `ss0`, and both halves of
/// the opening ephemeral. Fixed — every field is fixed-width, so there are no
/// interior length prefixes able to disagree with what they describe.
pub const PROVISIONAL_PLAINTEXT_LEN: usize =
    1 + BINDING_TAG_LEN + SS0_LEN + ml_kem::EK_LEN + ml_kem::DK_LEN;

/// Sealed length: `nonce ‖ ciphertext ‖ tag`. One number for every record, which
/// is what lets the store give this kind a fixed-size bucket —
/// [`RecordKind::Provisional`](crate::storage::dm_store::RecordKind::Provisional)
/// takes it verbatim as its capacity.
pub const PROVISIONAL_RECORD_LEN: usize = NONCE_LEN + PROVISIONAL_PLAINTEXT_LEN + TAG_LEN;

/// Why a provisional record could not be built, sealed, or opened.
#[derive(Debug, PartialEq, Eq)]
pub enum ProvisionalError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf,
    /// An AES key-init or ML-KEM operation failed at the module boundary.
    Module,
    /// AES-256-GCM authentication failed. The uniform open-path failure: a wrong
    /// key, a wrong [`RecordContext`], a flipped bit and a tampered record are
    /// deliberately indistinguishable (ISC-A-C18).
    ///
    /// **Authentication failures only.** A non-authentication mode error — the
    /// crypto module not yet initialised, most plausibly, which is exactly the
    /// condition [`restart`] runs under at startup — is [`Self::Module`]. Routing
    /// it here would report a retryable module state as tampering and destroy an
    /// intact record.
    Aead,
    /// The OS entropy source failed while drawing a nonce.
    EntropySource,
    /// The record is not [`PROVISIONAL_RECORD_LEN`] bytes. Checked before the
    /// open so a truncation is diagnosable, rather than arriving as the uniform
    /// authentication failure with nothing to distinguish it.
    WrongLength { expected: usize, actual: usize },
    /// The plaintext names a format version this build does not read.
    UnsupportedVersion { found: u8, expected: u8 },
    /// The record's two ephemeral halves are not a keypair.
    MismatchedEphemeral,
    /// The record's binding tag does not match its contents: `ss0` and the
    /// opening ephemeral are not from one channel. A splice, or two records
    /// interleaved by a partial write.
    MismatchedBinding,
}

impl std::fmt::Display for ProvisionalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf => write!(f, "provisional-record key derivation failed"),
            Self::Module => write!(f, "crypto module unavailable"),
            Self::Aead => write!(f, "the provisional record did not open"),
            Self::EntropySource => write!(f, "the entropy source failed"),
            Self::WrongLength { expected, actual } => write!(
                f,
                "a provisional record is {expected} bytes, this one is {actual}"
            ),
            Self::UnsupportedVersion { found, expected } => write!(
                f,
                "the provisional record is version {found}, this build reads {expected}"
            ),
            Self::MismatchedEphemeral => {
                write!(f, "the record's ephemeral halves are not a keypair")
            }
            Self::MismatchedBinding => write!(
                f,
                "the record's secret and its opening ephemeral are not from one channel"
            ),
        }
    }
}

impl std::error::Error for ProvisionalError {}

impl From<EnvelopeError> for ProvisionalError {
    /// **Not a catch-all.** The envelope's four shapes mean three different
    /// things here, and collapsing them cost a record its life twice over.
    ///
    /// [`EnvelopeError::Decrypt`] carrying anything but [`ModeError::TagMismatch`]
    /// is the crypto module refusing to operate, not a bad record — and
    /// [`restart`] runs at startup, which is precisely when a module may not have
    /// passed its self-tests yet. Sent to [`Self::Aead`] it became a
    /// [`TeardownCause::RecordUnusable`] and an irreversible
    /// [`PersistentNonBlocking`](crate::trust_events::TrustEventClass::PersistentNonBlocking)
    /// "the introduction was lost, send it again", while the record sat intact
    /// and retryable on disk. It is [`Self::Module`], so a caller can retry.
    ///
    /// [`EnvelopeError::Encrypt`] occurs only on the SEAL path, where nothing was
    /// ever opened — yet [`Self::Aead`]'s `Display` reads "the provisional record
    /// did not open". [`Self::Module`] is its bucket, and was unreachable from
    /// the envelope until now.
    ///
    /// A tag mismatch and a short buffer stay [`Self::Aead`]: wrong key, wrong
    /// context, corrupt and tampered are one indistinguishable outcome by
    /// ISC-A-C18, and that uniformity is correct.
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(_) => Self::EntropySource,
            EnvelopeError::Decrypt(ModeError::TagMismatch) | EnvelopeError::TooShort => Self::Aead,
            EnvelopeError::Decrypt(_) | EnvelopeError::Encrypt(_) => Self::Module,
        }
    }
}

/// Derive the provisional record's at-rest seal key from the profile's at-rest
/// key material.
///
/// **Rooted outside the conversation, deliberately.** Every other DM key descends
/// from `ss0`; this one cannot, because `ss0` is what the record holds — a record
/// sealed under a key derived from its own contents is a record nothing can open
/// without already knowing the answer. `at_rest_key` is the profile's key, so the
/// record is protected by the same passphrase that protects the mnemonic and the
/// contact cache (ISC-C44).
///
/// Its own HKDF label rather than the share-index key's or the first-contact
/// seal's: one key, one purpose, so a record of one kind can never open as
/// another wherever two key inputs coincide.
pub fn derive_seal_key(at_rest_key: &[u8; AEAD_KEY_LEN]) -> Result<Aes256Key, ProvisionalError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_PROVISIONAL_SALT), at_rest_key)
        .map_err(|_| ProvisionalError::Kdf)?;
    // The transient is cleared on both paths: `[u8; N]` is `Copy` with no `Drop`,
    // so the copy that moved into `Aes256Key` is the only one anything protects
    // and the original would otherwise stay live in this frame (#135).
    let mut key = [0u8; AEAD_KEY_LEN];
    let outcome = hkdf
        .expand(domain::DM_PROVISIONAL_SEAL, &mut key)
        .map_err(|_| ProvisionalError::Kdf)
        .and_then(|()| Aes256Key::new(&key).map_err(|_| ProvisionalError::Module));
    key.zeroize();
    outcome
}

/// What a caller expects a provisional record to be.
///
/// **The record's only binding to a channel.** [`derive_seal_key`] is
/// per-*profile*, so the key alone leaves every record in a profile an
/// interchangeable ciphertext. Passing this to both [`ProvisionalRecord::seal`]
/// and [`ProvisionalRecord::open`] is what makes a record lifted from another
/// channel fail to authenticate instead of resuming as the wrong correspondent.
///
/// **The two fields are [`crate::dm::firstcontact`]'s**, deliberately rather than
/// coincidentally: that module binds the same `addr ‖ epoch` into the AAD of the
/// entry this record is the sender's half of, so the record and the knock it
/// belongs to are scoped identically. Neither field is secret — the key-record
/// address is world-derivable by design, and the epoch is public — so binding
/// them costs no confidentiality.
///
/// **Its granularity is the knock's.** Two handshakes to one correspondent in one
/// epoch share a context, and that is correct rather than a gap: a knock is
/// idempotent per (correspondent, epoch) by design — `ss0` alone re-derives the
/// channel, so a retry re-lands on the same conversation instead of forking a
/// second one — so two records that collide here are two attempts at one channel.
#[derive(Clone, Copy, Debug)]
pub struct RecordContext<'a> {
    /// The correspondent's key-record owner seed: the address the knock was sent
    /// to, which both parties derive from the same published identity key.
    pub recipient_keyrec_addr: &'a [u8; keyrec::DM_KEYREC_OWNER_SEED_LEN],
    /// The first-contact epoch the knock was sent in.
    pub fc_epoch: u64,
}

/// The AAD a provisional record binds: the domain label, then the context,
/// length-prefixed.
///
/// [`crate::dm::firstcontact::seal_aad`]'s construction, not a new one — same
/// prefix-then-length-prefixed-fields shape, so the two cannot be parsed into
/// each other and neither can be extended by an implementation that guesses. The
/// version is deliberately **not** here; see [`PROVISIONAL_RECORD_VERSION`].
fn seal_aad(ctx: &RecordContext<'_>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain::DM_PROVISIONAL_AAD.len() + 64);
    aad.extend_from_slice(domain::DM_PROVISIONAL_AAD);
    push_lp(&mut aad, ctx.recipient_keyrec_addr);
    push_lp(&mut aad, &ctx.fc_epoch.to_be_bytes());
    aad
}

/// Tie `ss0` to the opening ephemeral it was drawn alongside.
///
/// Keyed on `ss0` (as HKDF IKM) and committing to `eph_ek` (in the `info`), so a
/// record whose two halves came from different channels cannot produce a tag that
/// verifies without holding that channel's `ss0`.
///
/// **`eph_ek` and not `eph_dk`.** [`EphemeralDecapKey::matches`] already refuses a
/// public half that is not the one embedded in the secret half, so binding the
/// public half binds the pair transitively — and the whole plaintext is under the
/// AEAD regardless, so this tag's job is the *pairing*, never the bytes.
fn binding_tag(
    ss0: &[u8; SS0_LEN],
    eph_ek: &[u8; ml_kem::EK_LEN],
) -> Result<[u8; BINDING_TAG_LEN], ProvisionalError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_PROVISIONAL_BIND_SALT), ss0)
        .map_err(|_| ProvisionalError::Kdf)?;
    let mut info = Vec::with_capacity(domain::DM_PROVISIONAL_BIND.len() + ml_kem::EK_LEN + 8);
    info.extend_from_slice(domain::DM_PROVISIONAL_BIND);
    push_lp(&mut info, eph_ek);

    let mut tag = [0u8; BINDING_TAG_LEN];
    let outcome = hkdf
        .expand(&info, &mut tag)
        .map_err(|_| ProvisionalError::Kdf);
    match outcome {
        Ok(()) => Ok(tag),
        Err(e) => {
            tag.zeroize();
            Err(e)
        }
    }
}

/// Compare two binding tags without a data-dependent early return.
///
/// The same construction as [`crate::storage::cas`]'s `ct_eq` and for the same
/// reason: the tag is a function of `ss0`, so a compare that returns at the first
/// differing byte leaks how much of a guess was right. `black_box` stops the
/// optimizer reintroducing the short circuit.
fn tags_match(a: &[u8; BINDING_TAG_LEN], b: &[u8; BINDING_TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

/// The pre-establishment handshake state, as it is held in memory and written to
/// rest.
///
/// One type serves both, which is the point: the triple a store must keep is
/// exactly the triple [`Ratchet::initiator`] consumes, so there is no shape to
/// translate between and no moment where a second copy of `eph_dk` exists (#255).
///
/// **No `Drop` of its own**, and that is load-bearing rather than an oversight.
/// A container `Drop` forbids moving fields *out*, which is what forced a caller
/// to copy the decapsulation key back out of `FirstContactState` and manufacture
/// a second live copy of the one secret the newtype exists to keep down to one.
/// Every field here destroys itself — `ss0` is [`Zeroizing`], `eph_dk` is a
/// zeroize-on-drop newtype — so the container needs none, and
/// `Self::into_ratchet` moves both halves straight through.
///
/// **What that trade actually buys, stated precisely.** The old container `Drop`
/// wiped `ss0`'s slot on *every* path, because it forbade partial moves and so
/// there was no path where the slot was not still the owner. [`Zeroizing`] wipes
/// only whichever slot still owns the value when it drops, so after
/// `Self::into_ratchet` the source slot is a moved-from `[u8; N]` — `Copy`,
/// no destructor — whose bytes remain in that frame until it is reused. The trade
/// is still right, and the reason is **aliasing, not residue**: one live copy
/// that leaves a moved-from shadow is better than two live copies each wiped at
/// its own end, because the second copy is a second thing to lose. Saying it
/// "wipes on every path" would be a claim this type does not meet.
///
/// Not [`Clone`], for the same reason: a second copy of a channel's opening
/// secrets has no use that [`Self::seal`] taking `&self` does not already serve.
pub struct ProvisionalRecord {
    ss0: Zeroizing<[u8; SS0_LEN]>,
    eph_ek: Box<[u8; ml_kem::EK_LEN]>,
    eph_dk: EphemeralDecapKey,
}

impl std::fmt::Debug for ProvisionalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProvisionalRecord(<redacted>)")
    }
}

impl ProvisionalRecord {
    /// The record for a knock that has been sent and not yet answered.
    ///
    /// Refuses halves that are not a keypair, which is the same check
    /// [`Ratchet::initiator`] makes and for the same reason: ML-KEM
    /// decapsulation never fails, so a mismatched pair yields a pseudorandom
    /// secret rather than an error, and the conversation would reject every reply
    /// forever with nothing to distinguish it from tampering.
    /// `ss0` arrives already wrapped so it can be *moved* in. Taking a bare
    /// `[u8; SS0_LEN]` would copy it at the call site and leave that copy live in
    /// the caller's frame, which is the hazard the wrapper exists to close.
    pub fn new(
        ss0: Zeroizing<[u8; SS0_LEN]>,
        eph_ek: Box<[u8; ml_kem::EK_LEN]>,
        eph_dk: EphemeralDecapKey,
    ) -> Result<Self, ProvisionalError> {
        if !eph_dk.matches(&eph_ek) {
            return Err(ProvisionalError::MismatchedEphemeral);
        }
        Ok(Self {
            ss0,
            eph_ek,
            eph_dk,
        })
    }

    /// The channel's address root `AR`, recomputed.
    ///
    /// Not read back from the record — see the module docs. A caller needs `ar`
    /// to derive page addresses the moment it resumes, and that is the whole of
    /// the stated need.
    ///
    /// **`chan_id` is deliberately not returned with it.** It is the one value in
    /// the derivation that must never be serialized anywhere (§ v4 minor
    /// invariant), so handing it out beside a record's other outputs invites a
    /// caller to persist it alongside them — and a caller that genuinely needs it
    /// for a frame AAD or signature reaches [`derive_channel_roots`] directly and
    /// keeps it in memory only. Returning the smaller thing costs that caller one
    /// call and removes the invitation.
    pub fn address_root(&self) -> Result<[u8; ROOT_LEN], FirstContactError> {
        Ok(derive_channel_roots(&self.ss0)?.ar)
    }

    /// The opening ephemeral's public half, which the recipient's reply
    /// encapsulates to.
    pub fn eph_ek(&self) -> &[u8; ml_kem::EK_LEN] {
        &self.eph_ek
    }

    /// Consume the record and open the conversation's ratchet (#255).
    ///
    /// **Consuming, and that is the whole fix.** The ratchet takes the
    /// decapsulation key by value; a borrowing accessor would force the caller to
    /// copy the bytes back out, which manufactures a second live copy of exactly
    /// the secret the newtype exists to keep down to one. Both halves move
    /// through here, and the record is gone afterwards.
    ///
    /// The ratchet root is re-derived inside [`Ratchet::initiator`] from `ss0`, so
    /// nothing in this crate ever needs a byte constructor for `RootKey` — the
    /// key surface that a stored root would have had to widen.
    ///
    /// **`pub(crate)`, and that is load-bearing rather than tidiness.**
    /// Establishing a channel is the moment the stored record must stop
    /// existing, because `ss0` roots `RK0` and its erasure is the whole
    /// forward-secrecy premise for trimming the ratchet. That pairing is
    /// enforced by [`crate::dm::persist::PendingHandshake::establish`], which
    /// owns the record and performs both. Leaving this public would leave a
    /// second door: anyone holding the sealed bytes and the key could build a
    /// ratchet and never delete, and the invariant would be a convention rather
    /// than a property. Outside this crate, `establish` is the only way in.
    pub(crate) fn into_ratchet(self) -> Result<Ratchet, RatchetError> {
        // `ss0` is borrowed while the other two fields move out. That is only
        // legal because this type has no container `Drop` — the exact restriction
        // #255 was about.
        let Self {
            ss0,
            eph_ek,
            eph_dk,
        } = self;
        Ratchet::initiator(&ss0, eph_ek, eph_dk)
    }

    /// Seal the record for rest, bound to the channel `ctx` names.
    ///
    /// The plaintext is built in a [`Zeroizing`] buffer and destroyed on every
    /// path, so the one copy that outlives this call is the ciphertext. `ctx` is
    /// what [`Self::open`] must be given back; see [`RecordContext`].
    pub fn seal(
        &self,
        key: &Aes256Key,
        ctx: &RecordContext<'_>,
    ) -> Result<Vec<u8>, ProvisionalError> {
        let mut plaintext = Zeroizing::new(Vec::with_capacity(PROVISIONAL_PLAINTEXT_LEN));
        plaintext.push(PROVISIONAL_RECORD_VERSION);
        plaintext.extend_from_slice(&binding_tag(&self.ss0, &self.eph_ek)?);
        plaintext.extend_from_slice(self.ss0.as_slice());
        plaintext.extend_from_slice(self.eph_ek.as_slice());
        plaintext.extend_from_slice(self.eph_dk.as_bytes());
        debug_assert_eq!(plaintext.len(), PROVISIONAL_PLAINTEXT_LEN);

        let sealed = seal_envelope(key, &seal_aad(ctx), &plaintext)?;
        debug_assert_eq!(sealed.len(), PROVISIONAL_RECORD_LEN);
        Ok(sealed)
    }

    /// Read a sealed record back, refusing one that is not the channel `ctx`
    /// names.
    ///
    /// Four checks, and deliberately no more:
    ///
    /// 1. **The AEAD open, under `ctx`'s AAD** — integrity and authenticity of
    ///    every byte, and *which channel's* record this is. A truncated record, a
    ///    flipped bit, a tampered one and one lifted from another channel all
    ///    fail here.
    /// 2. **The version byte**, so a future shape change fails by name instead of
    ///    mis-parsing an old record as a new one.
    /// 3. **The binding tag**, so `ss0` and the opening ephemeral are one
    ///    channel's rather than two spliced together — the failure that used to
    ///    survive every check and then reject every reply forever.
    /// 4. **`eph_dk` against `eph_ek`** via [`EphemeralDecapKey::matches`]. A
    ///    record whose halves disagree is corrupt in the one way the AEAD cannot
    ///    speak to — a pairing that was already wrong when it was written.
    ///
    /// There is **no `AR`/`RK` cross-check**, and its absence is the design rather
    /// than a gap: both are recomputed from `ss0` on every restore, so a record
    /// that disagrees with them cannot be constructed. Designing an inconsistency
    /// class out is strictly better than detecting it.
    ///
    /// What none of this catches is a rollback to a wholly consistent *earlier*
    /// record, which is indistinguishable from the state it once was. What keeps
    /// such a record from existing is that there is only ever one of them: the
    /// store replaces the single slot and [`crate::dm::persist`] deletes it on
    /// establishment, so no earlier record is retained anywhere to roll back to.
    /// That is a statement about what is *referenced*, not about what is on the
    /// medium — the superseded bytes are unlinked rather than scrubbed; see the
    /// module docs for the limits of that promise.
    pub fn open(
        key: &Aes256Key,
        sealed: &[u8],
        ctx: &RecordContext<'_>,
    ) -> Result<Self, ProvisionalError> {
        if sealed.len() != PROVISIONAL_RECORD_LEN {
            return Err(ProvisionalError::WrongLength {
                expected: PROVISIONAL_RECORD_LEN,
                actual: sealed.len(),
            });
        }
        let plaintext = Zeroizing::new(open_envelope(key, &seal_aad(ctx), sealed)?);
        // The length is a function of the sealed length, which was checked above.
        debug_assert_eq!(plaintext.len(), PROVISIONAL_PLAINTEXT_LEN);

        let found = plaintext[0];
        if found != PROVISIONAL_RECORD_VERSION {
            return Err(ProvisionalError::UnsupportedVersion {
                found,
                expected: PROVISIONAL_RECORD_VERSION,
            });
        }

        let mut at = 1;
        let mut carried = [0u8; BINDING_TAG_LEN];
        carried.copy_from_slice(&plaintext[at..at + BINDING_TAG_LEN]);
        at += BINDING_TAG_LEN;
        let mut ss0 = [0u8; SS0_LEN];
        ss0.copy_from_slice(&plaintext[at..at + SS0_LEN]);
        at += SS0_LEN;
        let eph_ek = boxed_from_slice::<{ ml_kem::EK_LEN }>(&plaintext[at..at + ml_kem::EK_LEN]);
        at += ml_kem::EK_LEN;
        let eph_dk = EphemeralDecapKey::new(boxed_from_slice::<{ ml_kem::DK_LEN }>(
            &plaintext[at..at + ml_kem::DK_LEN],
        ));

        // Every exit from here on clears the bare `ss0` array: it is `Copy` with
        // no `Drop`, so the wrapper's copy is the only one anything protects and
        // this one would otherwise stay live in the frame (#135).
        let outcome = binding_tag(&ss0, &eph_ek).and_then(|expected| {
            if tags_match(&carried, &expected) {
                // The wrapper takes a copy of the bare array read above.
                Self::new(Zeroizing::new(ss0), eph_ek, eph_dk)
            } else {
                Err(ProvisionalError::MismatchedBinding)
            }
        });
        ss0.zeroize();
        carried.zeroize();
        outcome
    }
}

/// Copy `n` bytes straight into a heap allocation, with no stack-sized temporary.
///
/// `Box::new(*array)` materialises the array as a value in the caller's frame on
/// the way to the allocation and leaves it there — the hazard `expand_secret`
/// exists for. A zeroed `Vec` is allocated on the heap and written in place.
fn boxed_from_slice<const N: usize>(bytes: &[u8]) -> Box<[u8; N]> {
    let mut buf = vec![0u8; N].into_boxed_slice();
    buf.copy_from_slice(bytes);
    match buf.try_into() {
        Ok(exact) => exact,
        // Unreachable: the buffer was allocated at exactly `N`, and the caller
        // slices `N` bytes. Not `expect`, whose message would render the bytes.
        Err(_) => unreachable!("a buffer allocated at N is N long"),
    }
}

/// How far a receiver has read, as a page number.
///
/// § v5's erasure caveat asks for this and gives an efficiency reason: without it
/// "a restart forces a from-0 scan over eventually-evicted leading pages". So it
/// is a starting point for a sweep, never a correctness input — nothing derives a
/// key from it, and a receiver that has lost it reads more than it needed to
/// rather than reading wrongly.
///
/// **Not secret**, so it is not sealed. It is also not a *message* cursor: the
/// contiguous cursor over positions is the acknowledgement's
/// ([`crate::dm::collect`]), and a second copy of that fact here would be free to
/// disagree with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReceiveCursor(u64);

impl ReceiveCursor {
    /// Page zero — where a receiver with no persisted cursor begins.
    pub const START: Self = Self(0);

    /// A cursor at `page`, if that page can hold a position at all.
    ///
    /// Bounded by [`MAX_PAGE`] for the same reason
    /// [`crate::dm::paging::PagePosition::new`] is: above it
    /// `page * PAGE_SLOTS + slot` leaves the sequence space, so the page holds
    /// nothing and a sweep started there would never find a message.
    pub fn new(page: u64) -> Option<Self> {
        (page <= MAX_PAGE).then_some(Self(page))
    }

    /// Which page.
    pub fn page(self) -> u64 {
        self.0
    }

    /// Move the cursor to `page`, given that the caller has genuinely read
    /// through `read_through`. Returns whether it moved.
    ///
    /// **Forwards is the dangerous direction, not backwards.** Backwards costs a
    /// rescan — the inefficiency this type exists to avoid, and nothing worse.
    /// Forwards past what was actually read makes a sweep start beyond unread
    /// pages, and those pages are never revisited: messages that arrived are
    /// silently never delivered, with no loss reported anywhere. Since the at-rest
    /// form is **unsealed** by design, anything able to write the file can choose
    /// that number, and a cursor set to [`MAX_PAGE`] means the receiver never
    /// reads again.
    ///
    /// So both directions are refused, against different references: backwards
    /// against the cursor's own value, forwards against what the caller can vouch
    /// it has read. `read_through` is the caller's own knowledge — the last page
    /// it swept — never anything the file supplied, or the bound would be
    /// checking the untrusted value against itself.
    #[must_use = "an ignored refusal is a cursor that silently did not advance"]
    pub fn advance_to(&mut self, page: u64, read_through: u64) -> bool {
        if page <= self.0 || page > MAX_PAGE || page > read_through {
            return false;
        }
        self.0 = page;
        true
    }

    /// The at-rest form: eight big-endian bytes, unsealed.
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Read the at-rest form back, refusing a page past [`MAX_PAGE`] **or past
    /// `read_through`**.
    ///
    /// The file is unsealed, so its number is a hint and not a fact; the ceiling
    /// is what makes it safe to act on. A caller with nothing to corroborate it
    /// against passes `0` and gets [`Self::START`] or nothing — a full rescan,
    /// which is the failure this type is allowed to have.
    pub fn from_be_bytes(bytes: [u8; 8], read_through: u64) -> Option<Self> {
        Self::new(u64::from_be_bytes(bytes)).filter(|c| c.0 <= read_through)
    }
}

/// What a channel can do when the client starts again.
///
/// The whole of #243's fix is that this enum has no third arm. There is no
/// "carry on and hope" — a channel either resumes from a record that survived,
/// or it ends and says so.
#[derive(Debug)]
#[must_use = "a discarded restart decision is the silent rebuild #243 abolished"]
pub enum ChannelRestart {
    /// The record opened: the handshake carries on from where it was.
    HandshakeResumes(ProvisionalRecord),
    /// The channel is over. [`Teardown`] is the statement the user gets.
    TornDown(Teardown),
}

/// A channel that cannot continue, ending explicitly.
///
/// Constructible only by [`restart`], so holding one means the decision was
/// actually taken rather than assumed.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a teardown the user is never told about is the defect #243 closed"]
pub struct Teardown {
    cause: TeardownCause,
}

impl Teardown {
    /// Why the channel ended.
    pub fn cause(&self) -> &TeardownCause {
        &self.cause
    }

    /// The trust event this teardown must be surfaced as.
    ///
    /// The taxonomy is the loudness. Both keys are
    /// [`PersistentNonBlocking`](crate::trust_events::TrustEventClass::PersistentNonBlocking),
    /// so each reappears at every start until acted on and each is written to the
    /// audit log — and ISC-A-C12 forbids a client suppressing or down-classing
    /// either. A returned value a caller could ignore would not be a fix; a
    /// classed event it is forbidden to ignore is.
    pub fn event(&self) -> TrustEventKey {
        match self.cause {
            TeardownCause::NoProvisionalRecord => TrustEventKey::DmChannelTornDownOnRestart,
            TeardownCause::RecordUnusable(_) => TrustEventKey::DmProvisionalHandshakeLost,
            TeardownCause::StoreUnreadable(_) => TrustEventKey::DmProvisionalRecordUnreadable,
        }
    }
}

impl std::fmt::Display for Teardown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.cause {
            TeardownCause::NoProvisionalRecord => write!(
                f,
                "this conversation ended when the app restarted and cannot be resumed; \
                 messages already sent keep trying to arrive, and a new conversation \
                 has to be started to continue"
            ),
            TeardownCause::RecordUnusable(e) => write!(
                f,
                "an introduction that had not been answered yet was lost and has to be \
                 sent again: {e}"
            ),
            // Deliberately does NOT say the introduction is gone or must be
            // re-sent. Nothing was read, so nothing is known to be lost.
            TeardownCause::StoreUnreadable(e) => write!(
                f,
                "an introduction that had not been answered yet could not be read from \
                 storage, so this conversation is not open yet; it is most likely still \
                 there and will be tried again next time: {e}"
            ),
        }
    }
}

/// Why a channel was torn down.
#[derive(Debug, PartialEq, Eq)]
pub enum TeardownCause {
    /// No provisional record survived for this channel.
    ///
    /// The **ordinary** case, not an error: a channel is established, so its
    /// record was deleted on establishment and no steady-state ratchet was ever
    /// written. It also covers a record the store lost, and the two need not be
    /// distinguished — the outcome and the remedy are the same.
    NoProvisionalRecord,
    /// A record was there and could not be used. Carries the reason, which is
    /// what separates a truncated file from a tampered one from a version this
    /// build does not read.
    RecordUnusable(ProvisionalError),
    /// The store could not say whether a record exists. Carries the store's own
    /// rendered error.
    ///
    /// **Its own cause because the remedy differs.** Without it a caller holding
    /// an `EIO` or a permission error has only `None` to report it as, which
    /// renders as "a new conversation has to be started" for a record still
    /// sitting on disk — destroying a recoverable handshake over a transient
    /// filesystem fault. Here the channel still does not open, and that is
    /// honest, but nothing is declared lost and nothing is asked of the user.
    StoreUnreadable(String),
}

/// Decide what a channel does at startup, from whatever its store held for it.
///
/// This is the one place the decision is taken, so it cannot be taken differently
/// in two front-ends.
///
/// **`record` is a `Result`, and that is not ceremony.** A bare `Option` cannot
/// say "the store failed to read", so a caller holding an `EIO` or a permission
/// error had to lower it to `None` — which this function reads as *no record
/// exists* and answers with "a new conversation has to be started", destroying a
/// recoverable handshake over a transient fault. The three inputs are three
/// different facts and get three different answers.
///
/// `ctx` is what the caller expects this record to be; a record belonging to
/// another channel fails to authenticate rather than resuming as the wrong
/// correspondent. See [`RecordContext`].
///
/// Every arm that is not a resumption produces a [`Teardown`], and a `Teardown`
/// carries a [`TrustEventKey`] — so there is no path through this function that
/// leaves a channel unopened without something for the user to see.
#[must_use = "the restart decision is the whole of #243; dropping it rebuilds the defect"]
pub fn restart<E: std::fmt::Display>(
    record: Result<Option<&[u8]>, E>,
    key: &Aes256Key,
    ctx: &RecordContext<'_>,
) -> ChannelRestart {
    let cause = match record {
        Err(e) => TeardownCause::StoreUnreadable(e.to_string()),
        Ok(None) => TeardownCause::NoProvisionalRecord,
        Ok(Some(sealed)) => match ProvisionalRecord::open(key, sealed, ctx) {
            Ok(record) => return ChannelRestart::HandshakeResumes(record),
            Err(e) => TeardownCause::RecordUnusable(e),
        },
    };
    ChannelRestart::TornDown(Teardown { cause })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::ratchet::Role;

    fn key() -> Aes256Key {
        let _ = oxicrypt_module::initialize();
        derive_seal_key(&[0x5Au8; AEAD_KEY_LEN]).unwrap()
    }

    /// A distinct key, for the wrong-key path.
    fn other_key() -> Aes256Key {
        derive_seal_key(&[0xA5u8; AEAD_KEY_LEN]).unwrap()
    }

    const ADDR_A: [u8; keyrec::DM_KEYREC_OWNER_SEED_LEN] =
        [0x11u8; keyrec::DM_KEYREC_OWNER_SEED_LEN];
    const ADDR_B: [u8; keyrec::DM_KEYREC_OWNER_SEED_LEN] =
        [0x22u8; keyrec::DM_KEYREC_OWNER_SEED_LEN];

    /// The channel a record belongs to.
    fn ctx() -> RecordContext<'static> {
        RecordContext {
            recipient_keyrec_addr: &ADDR_A,
            fc_epoch: 7,
        }
    }

    /// A different correspondent, same epoch.
    fn other_ctx() -> RecordContext<'static> {
        RecordContext {
            recipient_keyrec_addr: &ADDR_B,
            fc_epoch: 7,
        }
    }

    /// The same correspondent, a different epoch.
    fn later_epoch_ctx() -> RecordContext<'static> {
        RecordContext {
            recipient_keyrec_addr: &ADDR_A,
            fc_epoch: 8,
        }
    }

    fn ephemeral() -> (Box<[u8; ml_kem::EK_LEN]>, Box<[u8; ml_kem::DK_LEN]>) {
        let (ek, dk) = ml_kem::keygen(&[0x33u8; ml_kem::SEED_LEN], &[0x44u8; ml_kem::SEED_LEN])
            .expect("keygen");
        (Box::new(ek), Box::new(dk))
    }

    /// A second, unrelated keypair — the mismatched half.
    fn other_ephemeral() -> (Box<[u8; ml_kem::EK_LEN]>, Box<[u8; ml_kem::DK_LEN]>) {
        let (ek, dk) = ml_kem::keygen(&[0x55u8; ml_kem::SEED_LEN], &[0x66u8; ml_kem::SEED_LEN])
            .expect("keygen");
        (Box::new(ek), Box::new(dk))
    }

    fn ss0() -> [u8; SS0_LEN] {
        // Byte-distinct so a derivation that transposed or mis-sliced its inputs
        // would not pass by coincidence.
        let mut out = [0u8; SS0_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0x10u8.wrapping_add(i as u8 * 7);
        }
        out
    }

    fn record() -> ProvisionalRecord {
        let (ek, dk) = ephemeral();
        ProvisionalRecord::new(Zeroizing::new(ss0()), ek, EphemeralDecapKey::new(dk))
            .expect("a matched pair")
    }

    // ---- the record round-trips ----------------------------------------------

    /// The oracle for the record: everything a handshake needs comes back, and
    /// comes back through the sealed form rather than around it.
    #[test]
    fn a_provisional_record_round_trips() {
        let key = key();
        let sealed = record().seal(&key, &ctx()).expect("seals");
        assert_eq!(sealed.len(), PROVISIONAL_RECORD_LEN, "the size is fixed");

        let reopened = ProvisionalRecord::open(&key, &sealed, &ctx()).expect("opens");

        // `ss0` came back: the address root it recomputes matches the one the
        // original computes, which is also the AR-is-a-function-of-ss0 claim.
        assert_eq!(
            record().address_root().unwrap(),
            reopened.address_root().unwrap()
        );

        // And both ephemeral halves came back, still a pair.
        let (ek, _) = ephemeral();
        assert_eq!(reopened.eph_ek(), ek.as_ref());

        // The record can still do the one thing it exists for.
        let ratchet = reopened.into_ratchet().expect("opens a ratchet");
        assert_eq!(ratchet.role(), Role::Initiator);
        assert_eq!(ratchet.generation(), 0);
    }

    /// The sealed length is one number for every record, so a store can size a
    /// fixed file and a directory of them leaks no handshake progress.
    #[test]
    fn every_record_seals_to_one_length() {
        let key = key();
        let (ek, dk) = other_ephemeral();
        let other = ProvisionalRecord::new(
            Zeroizing::new([0u8; SS0_LEN]),
            ek,
            EphemeralDecapKey::new(dk),
        )
        .unwrap();
        assert_eq!(
            record().seal(&key, &ctx()).unwrap().len(),
            other.seal(&key, &other_ctx()).unwrap().len()
        );
        assert_eq!(
            record().seal(&key, &ctx()).unwrap().len(),
            PROVISIONAL_RECORD_LEN
        );
    }

    /// A restored ratchet still talks to the peer the original would have — in
    /// **both** directions.
    ///
    /// The A→B half proves `RK` was recomputed rather than lost: the peer is
    /// built from `ss0` alone, so a different root would not open this message.
    ///
    /// The B→A half is the reason `eph_dk` is persisted at all, and it is the
    /// only thing in this crate that exercises the decapsulation key's secret
    /// interior. [`EphemeralDecapKey::matches`] compares just the `ek` slice
    /// embedded at `DK_LEN - EK_LEN - 64`, so `dk_PKE` (bytes `[0..1152)`) and the
    /// trailing `H(ek) ‖ z` are compared by nothing at all — and the initiator's
    /// opening burst carries no `eph_ct`, so the send direction never
    /// decapsulates. Without the reply below, `seal` could write a wholly zeroed
    /// `dk_PKE` and every test in this module would still pass.
    #[test]
    fn a_recomputed_root_still_meets_the_peer() {
        let key = key();
        let sealed = record().seal(&key, &ctx()).unwrap();
        let (ek, _) = ephemeral();

        let mut a = ProvisionalRecord::open(&key, &sealed, &ctx())
            .unwrap()
            .into_ratchet()
            .unwrap();
        let mut b = Ratchet::recipient(&ss0(), ek).unwrap();

        let out = a.send_next().unwrap();
        assert!(
            out.eph_ct.is_none(),
            "the opening burst hangs off ss0 directly, so it decapsulates nothing"
        );
        let opened = b
            .receive(&out.header, out.eph_ct.as_deref(), &out.eph_ek, |k| {
                Ok::<[u8; 32], ()>(*k.as_bytes())
            })
            .expect("the ratchet accepts it");
        assert_eq!(
            opened.unwrap(),
            *out.key.as_bytes(),
            "the peer derived a different message key than the restored ratchet sealed under"
        );

        // B replies, encapsulating to A's opening ephemeral. Only the RESTORED
        // secret half can take that generation step.
        let reply = b.send_next().unwrap();
        assert!(
            reply.eph_ct.is_some(),
            "the reply must carry the ciphertext that steps the ratchet"
        );
        let got = a
            .receive(&reply.header, reply.eph_ct.as_deref(), &reply.eph_ek, |k| {
                Ok::<[u8; 32], ()>(*k.as_bytes())
            })
            .expect("the restored ratchet accepts the reply");
        assert_eq!(
            got.unwrap(),
            *reply.key.as_bytes(),
            "the restored eph_dk derived a different message key than the peer sealed under"
        );
        assert_eq!(a.generation(), 1, "the reply took a generation step");
    }

    /// The record does not render its secrets, the way every other key-bearing
    /// type here does not.
    #[test]
    fn a_record_does_not_render_its_secrets() {
        let rendered = format!("{:?}", record());
        assert!(!rendered.contains(&hex::encode(ss0())));
        assert_eq!(rendered, "ProvisionalRecord(<redacted>)");
    }

    /// `chan_id` must never be serialized anywhere (§ v4 minor invariant), and
    /// `AR` beside a channel's secrets would be a second copy of a fact the
    /// record can recompute.
    ///
    /// Asserted against a **really sealed** record's plaintext. This test once
    /// hand-built the bytes it then scanned, which made it an assertion about
    /// itself: no change to `seal`'s composition could alter its verdict.
    #[test]
    fn the_record_carries_no_address_root_and_no_channel_id() {
        let key = key();
        let sealed = record().seal(&key, &ctx()).unwrap();
        let plaintext = open_envelope(&key, &seal_aad(&ctx()), &sealed).expect("opens");
        let roots = derive_channel_roots(&ss0()).unwrap();

        assert_eq!(plaintext.len(), PROVISIONAL_PLAINTEXT_LEN);
        // Positive control: this really is the record's plaintext, so a miss
        // below is an absence rather than a scan that never matched anything.
        assert!(
            plaintext.windows(SS0_LEN).any(|w| w == ss0()),
            "the scan does not see the plaintext it claims to search"
        );

        assert!(
            !plaintext.windows(roots.ar.len()).any(|w| w == roots.ar),
            "the address root is in the record"
        );
        assert!(
            !plaintext
                .windows(roots.chan_id.len())
                .any(|w| w == roots.chan_id),
            "the channel id is in the record"
        );
    }

    // ---- what a record is refused for ---------------------------------------

    /// Check 4. A pairing that was wrong when it was written is corruption the
    /// AEAD cannot speak to, because the AEAD authenticates the bytes it was
    /// given rather than their meaning.
    #[test]
    fn a_record_whose_ephemeral_halves_disagree_is_refused() {
        let (ek, _) = ephemeral();
        let (_, other_dk) = other_ephemeral();

        // At construction.
        assert_eq!(
            ProvisionalRecord::new(Zeroizing::new(ss0()), ek, EphemeralDecapKey::new(other_dk))
                .unwrap_err(),
            ProvisionalError::MismatchedEphemeral
        );

        // And on the way back in, from a record sealed with the halves swapped.
        // The binding tag is computed over the `eph_ek` the record actually
        // carries, so this reaches the pairing check rather than stopping short.
        let key = key();
        let (_, dk) = ephemeral();
        let (other_ek, _) = other_ephemeral();
        let mut plaintext = Vec::with_capacity(PROVISIONAL_PLAINTEXT_LEN);
        plaintext.push(PROVISIONAL_RECORD_VERSION);
        plaintext.extend_from_slice(&binding_tag(&ss0(), &other_ek).unwrap());
        plaintext.extend_from_slice(&ss0());
        plaintext.extend_from_slice(other_ek.as_slice());
        plaintext.extend_from_slice(dk.as_slice());
        let sealed = seal_envelope(&key, &seal_aad(&ctx()), &plaintext).unwrap();

        assert_eq!(
            ProvisionalRecord::open(&key, &sealed, &ctx()).unwrap_err(),
            ProvisionalError::MismatchedEphemeral,
            "a record whose eph_ek is not eph_dk's own half was accepted"
        );
    }

    /// **The oracle for the binding tag.** `ss0` from one channel, a whole
    /// matched ephemeral from another — every other check passes, and before the
    /// tag existed this record opened, handed over a ratchet, and then failed
    /// every reply forever with `UnknownEphemeral`.
    #[test]
    fn a_record_splicing_two_channels_halves_is_refused() {
        let key = key();
        let (a_ek, _) = ephemeral();
        let (b_ek, b_dk) = other_ephemeral();

        // Positive control on the premise: the spliced halves really are a
        // keypair, so `matches` cannot be what catches this.
        assert!(
            EphemeralDecapKey::new(b_dk.clone()).matches(&b_ek),
            "the splice was built from halves that do not pair, so it proves nothing"
        );

        let mut plaintext = Vec::with_capacity(PROVISIONAL_PLAINTEXT_LEN);
        plaintext.push(PROVISIONAL_RECORD_VERSION);
        // The tag one channel's record would carry...
        plaintext.extend_from_slice(&binding_tag(&ss0(), &a_ek).unwrap());
        plaintext.extend_from_slice(&ss0());
        // ...over another channel's ephemeral.
        plaintext.extend_from_slice(b_ek.as_slice());
        plaintext.extend_from_slice(b_dk.as_slice());
        let sealed = seal_envelope(&key, &seal_aad(&ctx()), &plaintext).unwrap();

        assert_eq!(
            ProvisionalRecord::open(&key, &sealed, &ctx()).unwrap_err(),
            ProvisionalError::MismatchedBinding,
            "a record built from two channels' halves was accepted"
        );
    }

    /// A tag that is merely wrong — not a coherent splice — is refused too, so
    /// the check is a comparison and not a shape test.
    #[test]
    fn a_record_with_a_corrupt_binding_tag_is_refused() {
        let key = key();
        let (ek, dk) = ephemeral();
        let mut tag = binding_tag(&ss0(), &ek).unwrap();
        tag[0] ^= 0x01;

        let mut plaintext = Vec::with_capacity(PROVISIONAL_PLAINTEXT_LEN);
        plaintext.push(PROVISIONAL_RECORD_VERSION);
        plaintext.extend_from_slice(&tag);
        plaintext.extend_from_slice(&ss0());
        plaintext.extend_from_slice(ek.as_slice());
        plaintext.extend_from_slice(dk.as_slice());
        let sealed = seal_envelope(&key, &seal_aad(&ctx()), &plaintext).unwrap();

        assert_eq!(
            ProvisionalRecord::open(&key, &sealed, &ctx()).unwrap_err(),
            ProvisionalError::MismatchedBinding
        );
    }

    /// **The oracle for the channel binding.** The seal key is per-profile, so
    /// without the AAD every record in a profile is an interchangeable
    /// ciphertext: copying one channel's record over another's opened cleanly and
    /// the channel resumed as the wrong correspondent, silently.
    #[test]
    fn a_record_does_not_open_under_another_channels_context() {
        let key = key();
        let sealed = record().seal(&key, &ctx()).unwrap();

        // Positive control: under its own context it opens, so a refusal below
        // is the binding and not a broken record.
        assert!(ProvisionalRecord::open(&key, &sealed, &ctx()).is_ok());

        for wrong in [other_ctx(), later_epoch_ctx()] {
            assert_eq!(
                ProvisionalRecord::open(&key, &sealed, &wrong).unwrap_err(),
                ProvisionalError::Aead,
                "a record from another channel was accepted as this one"
            );
        }
    }

    /// And the same at the decision point: a spliced record tears the channel
    /// down loudly instead of resuming it as somebody else.
    #[test]
    fn a_record_from_another_channel_tears_down_rather_than_resuming() {
        let key = key();
        let sealed = record().seal(&key, &ctx()).unwrap();
        match restart(Ok::<_, std::io::Error>(Some(&sealed)), &key, &other_ctx()) {
            ChannelRestart::TornDown(t) => {
                assert_eq!(
                    t.cause(),
                    &TeardownCause::RecordUnusable(ProvisionalError::Aead)
                );
            }
            ChannelRestart::HandshakeResumes(_) => {
                panic!("a record from another channel resumed this one")
            }
        }
    }

    /// Check 2. A version this build does not read fails **by name**, which is
    /// the reason the byte is in the plaintext rather than the AAD — in the AAD
    /// this would be indistinguishable from a wrong key.
    #[test]
    fn a_record_with_a_wrong_version_byte_is_refused() {
        let key = key();
        let (ek, dk) = ephemeral();
        let mut plaintext = Vec::with_capacity(PROVISIONAL_PLAINTEXT_LEN);
        plaintext.push(PROVISIONAL_RECORD_VERSION + 1);
        plaintext.extend_from_slice(&binding_tag(&ss0(), &ek).unwrap());
        plaintext.extend_from_slice(&ss0());
        plaintext.extend_from_slice(ek.as_slice());
        plaintext.extend_from_slice(dk.as_slice());
        let sealed = seal_envelope(&key, &seal_aad(&ctx()), &plaintext).unwrap();

        assert_eq!(
            ProvisionalRecord::open(&key, &sealed, &ctx()).unwrap_err(),
            ProvisionalError::UnsupportedVersion {
                found: PROVISIONAL_RECORD_VERSION + 1,
                expected: PROVISIONAL_RECORD_VERSION,
            }
        );
    }

    /// Check 1. Every byte is authenticated, so a flip anywhere — nonce,
    /// ciphertext or tag — is refused, and so is a wrong key.
    #[test]
    fn a_bit_flipped_or_wrongly_keyed_record_is_refused_by_the_aead() {
        let key = key();
        let sealed = record().seal(&key, &ctx()).unwrap();

        for at in [0, NONCE_LEN, PROVISIONAL_RECORD_LEN - 1] {
            let mut tampered = sealed.clone();
            tampered[at] ^= 0x01;
            assert_eq!(
                ProvisionalRecord::open(&key, &tampered, &ctx()).unwrap_err(),
                ProvisionalError::Aead,
                "a flip at byte {at} was accepted"
            );
        }

        assert_eq!(
            ProvisionalRecord::open(&other_key(), &sealed, &ctx()).unwrap_err(),
            ProvisionalError::Aead
        );
    }

    /// A truncated record is refused, and named as truncated rather than
    /// collapsing into the uniform authentication failure — the length is public,
    /// so reporting it precisely leaks nothing and saves a reader hunting for
    /// tampering that never happened.
    #[test]
    fn a_truncated_record_is_refused_by_length() {
        let key = key();
        let sealed = record().seal(&key, &ctx()).unwrap();
        for len in [0, NONCE_LEN, PROVISIONAL_RECORD_LEN - 1] {
            assert_eq!(
                ProvisionalRecord::open(&key, &sealed[..len], &ctx()).unwrap_err(),
                ProvisionalError::WrongLength {
                    expected: PROVISIONAL_RECORD_LEN,
                    actual: len,
                },
                "a {len}-byte record was not refused by length"
            );
        }
    }

    /// And an OVER-long one, which the length test used to miss entirely by only
    /// ever slicing shorter. Relaxing the pre-check from `!=` to `<` kept every
    /// other test green while a padded record fell through to the AEAD and came
    /// back as the uniform `Aead` — losing exactly the diagnosability the
    /// pre-check exists to provide.
    #[test]
    fn an_over_long_record_is_refused_by_length() {
        let key = key();
        let sealed = record().seal(&key, &ctx()).unwrap();
        for extra in [1, TAG_LEN, PROVISIONAL_RECORD_LEN] {
            let mut padded = sealed.clone();
            padded.resize(PROVISIONAL_RECORD_LEN + extra, 0);
            assert_eq!(
                ProvisionalRecord::open(&key, &padded, &ctx()).unwrap_err(),
                ProvisionalError::WrongLength {
                    expected: PROVISIONAL_RECORD_LEN,
                    actual: PROVISIONAL_RECORD_LEN + extra,
                },
                "a record {extra} bytes too long was not refused by length"
            );
        }
    }

    /// The seal is domain-separated from the first-contact entry's, so a record
    /// sealed for one purpose does not open as the other even where the key
    /// material coincides.
    #[test]
    fn the_seal_key_is_not_the_first_contact_seal_key() {
        let material = [0x77u8; AEAD_KEY_LEN];
        let ours = derive_seal_key(&material).unwrap();
        let sealed = record().seal(&ours, &ctx()).unwrap();

        // The first-contact construction over the same bytes, reached directly.
        let hkdf = HkdfSha384::extract(Some(domain::DM_FC_SALT), &material).unwrap();
        let mut theirs = [0u8; AEAD_KEY_LEN];
        hkdf.expand(domain::DM_FC_SEAL, &mut theirs).unwrap();
        let theirs = Aes256Key::new(&theirs).unwrap();

        assert_eq!(
            ProvisionalRecord::open(&theirs, &sealed, &ctx()).unwrap_err(),
            ProvisionalError::Aead
        );
    }

    // ---- error routing -------------------------------------------------------

    /// A module that has not come up is not a bad record, and a seal-path failure
    /// is not a failed open. Both used to arrive as `Aead` — the first turning a
    /// retryable startup condition into an irreversible "your introduction was
    /// lost", the second reporting "the provisional record did not open" about a
    /// record nothing had tried to open.
    #[test]
    fn a_module_failure_is_not_reported_as_a_bad_record() {
        // Authentication failures, which stay uniform by ISC-A-C18.
        assert_eq!(
            ProvisionalError::from(EnvelopeError::Decrypt(ModeError::TagMismatch)),
            ProvisionalError::Aead
        );
        assert_eq!(
            ProvisionalError::from(EnvelopeError::TooShort),
            ProvisionalError::Aead
        );

        // Everything else.
        for e in [
            EnvelopeError::Decrypt(ModeError::LengthMismatch),
            EnvelopeError::Decrypt(ModeError::InvalidIvLength),
            EnvelopeError::Encrypt(ModeError::LengthMismatch),
        ] {
            assert_eq!(
                ProvisionalError::from(e),
                ProvisionalError::Module,
                "a non-authentication mode error was reported as a bad record"
            );
        }
    }

    // ---- the loud teardown ---------------------------------------------------

    /// **The oracle for #243.** An established channel has no provisional record,
    /// and what it gets instead of a silent rebuild is a teardown that carries a
    /// classed trust event and a statement in words.
    #[test]
    fn an_established_channel_is_torn_down_loudly() {
        let torn = match restart(Ok::<_, std::io::Error>(None), &key(), &ctx()) {
            ChannelRestart::TornDown(t) => t,
            ChannelRestart::HandshakeResumes(_) => {
                panic!("an established channel must not resume")
            }
        };

        assert_eq!(torn.cause(), &TeardownCause::NoProvisionalRecord);
        assert_eq!(torn.event(), TrustEventKey::DmChannelTornDownOnRestart);

        // Loud means the taxonomy carries it, not that a caller might read it:
        // persistent-non-blocking reappears at every start and is written to the
        // audit log, and ISC-A-C12 forbids suppressing either.
        assert_eq!(
            crate::trust_events::class_of(torn.event()),
            crate::trust_events::TrustEventClass::PersistentNonBlocking
        );

        // And it says something, in words, rather than only having a name.
        let said = torn.to_string();
        assert!(said.contains("restarted"), "got {said:?}");
        assert!(!said.is_empty());
    }

    /// A record that will not open strands the handshake, and says so under its
    /// own event — the condition and the remedy differ from an established
    /// channel's, and this one can also mean tampering.
    #[test]
    fn an_unusable_record_strands_the_handshake_loudly() {
        let key = key();
        let mut sealed = record().seal(&key, &ctx()).unwrap();
        sealed[NONCE_LEN] ^= 0x01;

        let torn = match restart(Ok::<_, std::io::Error>(Some(&sealed)), &key, &ctx()) {
            ChannelRestart::TornDown(t) => t,
            ChannelRestart::HandshakeResumes(_) => panic!("a tampered record must not resume"),
        };

        assert_eq!(
            torn.cause(),
            &TeardownCause::RecordUnusable(ProvisionalError::Aead)
        );
        assert_eq!(torn.event(), TrustEventKey::DmProvisionalHandshakeLost);
        assert_eq!(
            crate::trust_events::class_of(torn.event()),
            crate::trust_events::TrustEventClass::PersistentNonBlocking
        );
        assert!(torn.to_string().contains("sent again"));
    }

    /// A store that could not be read is neither of the above. Lowered to `None`
    /// — the only thing an `Option` argument could express — it rendered as "a
    /// new conversation has to be started" for a record still sitting on disk,
    /// destroying a recoverable handshake over a transient fault.
    #[test]
    fn an_unreadable_store_does_not_declare_the_handshake_lost() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "seeds.bin");
        let rendered = err.to_string();

        let torn = match restart(Err(err), &key(), &ctx()) {
            ChannelRestart::TornDown(t) => t,
            ChannelRestart::HandshakeResumes(_) => panic!("nothing was read, so nothing resumes"),
        };

        assert_eq!(
            torn.cause(),
            &TeardownCause::StoreUnreadable(rendered.clone())
        );
        assert_eq!(torn.event(), TrustEventKey::DmProvisionalRecordUnreadable);
        assert_eq!(
            crate::trust_events::class_of(torn.event()),
            crate::trust_events::TrustEventClass::PersistentNonBlocking
        );

        // It is diagnosable: the store's own words survive.
        let said = torn.to_string();
        assert!(said.contains(&rendered), "got {said:?}");
        // And it does NOT tell the user their introduction is gone.
        assert!(
            !said.contains("sent again") && !said.contains("new conversation"),
            "an unread store was reported as a lost handshake: {said:?}"
        );
    }

    /// The other arm: a record that does open resumes, so the teardown is a
    /// decision and not a constant. Without this the tests above would pass
    /// against a function that tore every channel down.
    #[test]
    fn a_surviving_record_resumes_the_handshake() {
        let key = key();
        let sealed = record().seal(&key, &ctx()).unwrap();
        match restart(Ok::<_, std::io::Error>(Some(&sealed)), &key, &ctx()) {
            ChannelRestart::HandshakeResumes(r) => {
                r.into_ratchet().expect("resumes into a ratchet");
            }
            ChannelRestart::TornDown(t) => panic!("a good record was torn down: {t}"),
        }
    }

    /// The three teardown events are distinct keys, so a UI can tell an ended
    /// conversation from a lost introduction from a store it could not read.
    #[test]
    fn the_three_teardowns_are_different_events() {
        let all = [
            Teardown {
                cause: TeardownCause::NoProvisionalRecord,
            },
            Teardown {
                cause: TeardownCause::RecordUnusable(ProvisionalError::Aead),
            },
            Teardown {
                cause: TeardownCause::StoreUnreadable("disk on fire".into()),
            },
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.event(), b.event());
                assert_ne!(a.to_string(), b.to_string());
            }
        }
    }

    // ---- the receive cursor --------------------------------------------------

    /// It is a page number, it round-trips, and it refuses a page that holds no
    /// position.
    #[test]
    fn a_receive_cursor_round_trips_and_is_bounded() {
        assert_eq!(ReceiveCursor::START.page(), 0);

        let c = ReceiveCursor::new(42).unwrap();
        assert_eq!(ReceiveCursor::from_be_bytes(c.to_be_bytes(), 42), Some(c));

        assert_eq!(
            ReceiveCursor::new(MAX_PAGE).map(ReceiveCursor::page),
            Some(MAX_PAGE)
        );
        assert_eq!(ReceiveCursor::new(MAX_PAGE + 1), None);
        assert_eq!(
            ReceiveCursor::from_be_bytes(u64::MAX.to_be_bytes(), u64::MAX),
            None
        );
    }

    /// It does not go backwards — that costs the rescan it exists to avoid.
    #[test]
    fn a_receive_cursor_never_moves_backwards() {
        // From START, which the old test never exercised: it began at 9, so the
        // zero-to-nonzero step went untested and `advance_to` could have refused
        // it with everything still green.
        let mut c = ReceiveCursor::START;
        assert!(c.advance_to(1, 1), "the cursor would not leave START");
        assert_eq!(c.page(), 1);

        assert!(c.advance_to(10, 10));
        assert_eq!(c.page(), 10);

        assert!(!c.advance_to(9, 10), "the cursor went backwards");
        assert!(
            !c.advance_to(10, 10),
            "the cursor accepted a no-op as progress"
        );
        assert!(
            !c.advance_to(MAX_PAGE + 1, u64::MAX),
            "the cursor left the page space"
        );
        assert_eq!(c.page(), 10);
    }

    /// And it does not go forwards past what was actually read — the direction
    /// that matters. A skipped page is never revisited, so a cursor pushed ahead
    /// means messages that arrived are silently never delivered; at [`MAX_PAGE`]
    /// the receiver never reads again.
    #[test]
    fn a_receive_cursor_never_moves_past_what_was_read() {
        let mut c = ReceiveCursor::new(3).unwrap();

        assert!(!c.advance_to(9, 5), "the cursor moved past what was read");
        assert!(
            !c.advance_to(MAX_PAGE, 5),
            "the cursor jumped to the end of the page space"
        );
        assert_eq!(c.page(), 3);

        // Positive control: up to the ceiling it still moves, so the refusals
        // above are the bound and not a cursor that stopped working.
        assert!(c.advance_to(5, 5));
        assert_eq!(c.page(), 5);
    }

    /// The at-rest form is **unsealed** by design, so anything able to write the
    /// file can choose the number. It is believed only up to what the caller can
    /// corroborate.
    #[test]
    fn a_persisted_cursor_is_not_believed_past_what_was_read() {
        let tampered = ReceiveCursor::new(MAX_PAGE).unwrap().to_be_bytes();
        assert_eq!(
            ReceiveCursor::from_be_bytes(tampered, 10),
            None,
            "an unsealed cursor at MAX_PAGE was believed"
        );

        let c = ReceiveCursor::new(7).unwrap();
        assert_eq!(ReceiveCursor::from_be_bytes(c.to_be_bytes(), 10), Some(c));
        assert_eq!(ReceiveCursor::from_be_bytes(c.to_be_bytes(), 7), Some(c));
        assert_eq!(ReceiveCursor::from_be_bytes(c.to_be_bytes(), 6), None);

        // A caller with nothing to corroborate against gets START or nothing —
        // a full rescan, which is the failure this type is allowed to have.
        assert_eq!(
            ReceiveCursor::from_be_bytes(ReceiveCursor::START.to_be_bytes(), 0),
            Some(ReceiveCursor::START)
        );
        assert_eq!(ReceiveCursor::from_be_bytes(1u64.to_be_bytes(), 0), None);
    }
}
