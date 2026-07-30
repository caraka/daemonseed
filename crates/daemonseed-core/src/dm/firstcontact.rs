//! The **first-contact entry** — the knock itself (ISC-C41).
//!
//! One sealed, self-contained blob written to a slot of the recipient's doorbell
//! ([`super::doorbell`]). It carries everything the recipient needs to decide
//! whether to accept a stranger and, on accept, to start the conversation: who is
//! knocking, proof they are who they claim, the first message, and the ephemeral
//! key that makes the reply forward-secret.
//!
//! **Why it is self-contained, and why that costs 18 KB.** An earlier design put
//! a pointer here and the payload in a sender-owned record. That forced the
//! recipient to fetch before it could judge — so anyone willing to write garbage
//! could make strangers do work, a read-amplification lever aimed at exactly the
//! surface that has no authentication. Carrying the whole thing means an unwanted
//! entry costs one decapsulation and one failed AEAD open, both constant-time and
//! cheap, and nothing is ever fetched on a stranger's say-so. The size is the
//! price of that, and it is what forces the doorbell to `dflt(32)`.
//!
//! ## What protects what
//!
//! - **Confidentiality** rests on the ML-KEM encapsulation to the recipient's
//!   published static key. Nobody without `DK_lt_B` learns even who is knocking:
//!   the sender's identity is inside the seal, not beside it.
//! - **Authorship** rests on `msg_sig` under the per-contact pseudonym key, and
//!   on `bind_lt` under the long-term key tying that pseudonym to an identity.
//!   `msg_sig` is the SOLE proof-of-possession path — an earlier draft carried a
//!   separate `bind_pop`, folded in here to save 4627 bytes — so it is mandatory
//!   and always verified, and any future frame type must carry one or
//!   proof-of-possession silently vanishes there.
//! - **Misdirection** is caught by the hashed intended recipient inside the seal.
//!   Honest scope: the recipient reads it only AFTER decapsulating, so a holder of
//!   a substituted encapsulation key still reads the plaintext before rejecting.
//!   That is the accepted consequence of having no proof of decapsulation-key
//!   possession, which the frozen design decided against for alpha.
//! - **Replay** is caught by `fc_epoch` in the AAD. Both parties derive it from
//!   the wall clock, so there is no recipient-side state, no restart coupling, and
//!   no seen-set to persist. The recipient accepts the current and previous epoch;
//!   anything older will not open.
//!
//! ## What is NOT forward-secret, and why the UI must say so
//!
//! `ss0` is encapsulated to the recipient's **static** key, because one-time
//! prekeys were dropped for alpha. So every message the sender writes before the
//! recipient's first reply is recoverable by anyone who captured the entry and
//! later compromises `DK_lt_B` — harvest-now-decrypt-later, against the opening
//! burst only. Forward secrecy begins at the recipient's reply, which
//! encapsulates to `eph_ek` and forks the ratchet onto fresh entropy.
//!
//! The mitigation is not cryptographic, it is honesty: the first message is
//! **hello-grade**, and the UI has to say so (ISC-C45). "Say hello here, hand over
//! secrets once they have replied" is the actual security control, and it fits
//! the bootstrap use case exactly.
//!
//! This module is the entry's crypto core — build, seal, open, verify, pad. The
//! admission checks (proof-of-work, invite token) and the transport that writes
//! and sweeps the doorbell land alongside it.

use oxicrypt_aes::Aes256Key;
use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use oxicrypt_sha::sha384;
use prost::Message;
use zeroize::{Zeroize, Zeroizing};

use daemonseed_proto::v1 as wire;

use crate::aead_envelope::{EnvelopeError, open_envelope, seal_envelope};
use crate::dm::LEN_PREFIX;
use crate::dm::domain;
use crate::dm::keyrec;
use crate::dm::ratchet;
use crate::identity::keys::{SignKeypair, SignatureError, verify_signature};

/// Length of an ML-KEM-1024 ciphertext.
pub const CT0_LEN: usize = ml_kem::CT_LEN;

/// Length of the encapsulated shared secret `ss0`.
pub const SS0_LEN: usize = ml_kem::SHARED_SECRET_LEN;

/// Length of the hashed intended recipient (SHA-384).
pub const RECIPIENT_HASH_LEN: usize = 48;

/// Length of the derived roots (`AR`, `chan_id`).
pub const ROOT_LEN: usize = 32;

/// Largest first-message body, in bytes.
///
/// Deliberately far below the padding headroom: the entry has ~16 KB of fixed
/// cryptographic material before a single character of message, and the whole
/// thing plus an invite token must still fit a `dflt(32)` subkey.
pub const DM_BODY_CAP: usize = 8192;

/// The plaintext padding ladder. A body is padded up to the smallest bucket that
/// holds it, so the sealed length reveals a coarse size class and nothing finer.
///
/// Two buckets rather than many: each additional bucket is another distinguishable
/// class, and with a fixed ~16 KB floor the marginal privacy of finer buckets is
/// small. The top bucket is chosen so that a padded, token-bearing entry still
/// fits the 32768-byte subkey (frozen build-contract item (iv)); the test
/// `a_maximal_entry_fits_the_doorbell_subkey` is what actually holds that line.
pub const PAD_BUCKETS: &[usize] = &[20480, 25600];

/// Hard ceiling on an assembled entry — the `dflt(32)` per-subkey cap.
pub const MAX_ENTRY_LEN: usize = 32768;

/// Bytes reserved for a proof-of-work the admission slice has yet to define.
///
/// The frozen design specifies the PoW preimage but never its encoded size, so
/// the headroom it will need is budgeted here rather than discovered when a write
/// is refused. `a_maximal_entry_fits_the_doorbell_subkey` asserts against it.
pub const POW_RESERVE: usize = 64;

/// The direction label bound into `msg_sig`. First contact is always
/// initiator-to-recipient.
///
/// Taken from [`ratchet::Direction`] rather than spelled out here: these are
/// frozen wire bytes inside a signature preimage, so a second definition is a
/// drift that would surface only as a signature two versions of this client
/// could not verify for each other.
const DIR_A2B: &[u8] = ratchet::Direction::AToB.label();

/// The frame-kind label bound into `msg_sig`.
///
/// Present so the first-contact preimage can never be mistaken for an
/// ongoing-channel one. Both frame kinds sign under the same `DM_MSG_SIG` domain
/// and share most of their fields, so without a discriminator a first-contact
/// signature would be a byte-valid channel-frame signature for the same tuple —
/// and the channel frame binds a generation ciphertext this one does not.
/// Cheaper to add now than after the vectors harden.
pub const FRAME_KIND_FIRST_CONTACT: &[u8] = b"fc";

/// The two roots every conversation derives from `ss0`.
///
/// `ar` addresses the channel and is **retained** for its life — which is exactly
/// why addressing is not forward-secret even though content is. `chan_id`
/// identifies the conversation inside signatures and AAD and is **never
/// serialized**: a receiver recomputes it from the record it derived. Putting it
/// on the wire would collapse the address scatter it exists to protect.
#[derive(Clone, Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ChannelRoots {
    pub ar: [u8; ROOT_LEN],
    pub chan_id: [u8; ROOT_LEN],
}

impl std::fmt::Debug for ChannelRoots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelRoots(<redacted>)")
    }
}

/// Anything that can go wrong building or opening a first-contact entry.
#[derive(Debug)]
pub enum FirstContactError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf(oxicrypt_kdf::KdfError),
    /// An ML-KEM or SHA-384 operation failed at the module boundary.
    Module(oxicrypt_module::Error),
    /// A local signing operation failed while BUILDING an entry. Carries the
    /// cause: there is no adversary on this path, and a policy refusal reported as
    /// "signature did not verify" would send a reader hunting for tampering that
    /// never happened.
    Signing(SignatureError),
    /// AEAD seal or open failed. On the open path this is the uniform
    /// authentication failure — wrong key, wrong AAD, wrong epoch, or tampered
    /// bytes are indistinguishable, deliberately (ISC-A-C18).
    Aead,
    /// A signature inside the entry did not verify. Uniform for the same reason.
    Signature,
    /// The bytes are not a decodable entry or body. The doorbell is
    /// world-writable, so arbitrary bytes in a slot are an expected input rather
    /// than an exceptional one, and are rejected exactly as a bad signature is.
    Malformed,
    /// A length-gated field was absent or the wrong size. Carries what was
    /// expected and what arrived, so a truncation is diagnosable.
    FieldLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// The body exceeds [`DM_BODY_CAP`], or the padded entry would exceed
    /// [`MAX_ENTRY_LEN`]. A local compose-time refusal, never a network condition.
    TooLarge { got: usize, max: usize },
    /// The entry is addressed to a different identity. Read only after
    /// decapsulating — see the module docs.
    WrongRecipient,
    /// The entry binds a first-contact epoch outside the accepted window (current
    /// or previous), so it is a stale replay.
    StaleEpoch,
    /// The OS entropy source failed.
    EntropySource,
}

impl std::fmt::Display for FirstContactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "first-contact key derivation failed: {e}"),
            Self::Module(e) => write!(f, "crypto module unavailable: {e:?}"),
            Self::Signing(e) => write!(f, "could not sign the first-contact entry: {e}"),
            Self::Aead => write!(f, "the first-contact entry did not open"),
            Self::Signature => write!(f, "signature verification failed"),
            Self::Malformed => write!(f, "not a decodable first-contact entry"),
            Self::FieldLength {
                field,
                expected,
                actual,
            } => write!(f, "{field} must be {expected} bytes, got {actual}"),
            Self::TooLarge { got, max } => write!(f, "entry is {got} bytes, cap is {max}"),
            Self::WrongRecipient => write!(f, "the entry is addressed to another identity"),
            Self::StaleEpoch => write!(f, "the entry's first-contact epoch is stale"),
            Self::EntropySource => write!(f, "the entropy source failed"),
        }
    }
}

impl std::error::Error for FirstContactError {}

impl From<EnvelopeError> for FirstContactError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::EntropySource(_) => Self::EntropySource,
            _ => Self::Aead,
        }
    }
}

/// Derive `AR` and `chan_id` from the encapsulated secret.
///
/// Both parties reach the same roots — the sender at compose time, the recipient
/// after decapsulating — which is what lets them meet on a channel whose address
/// no third party can derive.
pub fn derive_channel_roots(ss0: &[u8; SS0_LEN]) -> Result<ChannelRoots, FirstContactError> {
    let hkdf =
        HkdfSha384::extract(Some(domain::DM_ROOT_SALT), ss0).map_err(FirstContactError::Kdf)?;
    // Both transients are cleared on every path: `[u8; N]` is `Copy` with no
    // `Drop`, so the struct's `ZeroizeOnDrop` covers only the copies that moved
    // into it and the originals would otherwise stay live in this frame (#135).
    let mut ar = [0u8; ROOT_LEN];
    let mut chan_id = [0u8; ROOT_LEN];
    let outcome = hkdf
        .expand(domain::DM_ADDR_ROOT, &mut ar)
        .and_then(|()| hkdf.expand(domain::DM_CHAN_ID, &mut chan_id))
        .map(|()| ChannelRoots { ar, chan_id })
        .map_err(FirstContactError::Kdf);
    ar.zeroize();
    chan_id.zeroize();
    outcome
}

use crate::dm::push_lp;

/// The preimage binding a per-contact pseudonym to the long-term identity that
/// vouches for it. Signed under the LONG-TERM key.
pub fn bind_lt_input(pk_lt: &[u8; ml_dsa::PK_LEN], pk_pc: &[u8; ml_dsa::PK_LEN]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(domain::DM_BIND_LT.len() + 2 * ml_dsa::PK_LEN + 16);
    buf.extend_from_slice(domain::DM_BIND_LT);
    push_lp(&mut buf, pk_lt);
    push_lp(&mut buf, pk_pc);
    buf
}

/// The preimage for a frame's authorship signature. Signed under the PSEUDONYM key.
///
/// It binds, in order and each length-prefixed: the frame kind, the conversation
/// (`chan_id`), the direction, the sequence number, the ephemeral ratchet key, the
/// hashed recipient, BOTH of the sender's public keys, the timestamp, and the body.
///
/// Every one of those is load-bearing. `chan_id` and `dir` stop a frame being
/// replayed into another conversation or the reverse direction; `seq` stops it
/// being replayed within one. `eph_ek` is signed because an unauthenticated
/// ephemeral would let an active attacker substitute their own and defeat the
/// post-compromise heal the ratchet exists to provide. The recipient hash stops a
/// frame being redirected. And both public keys are here because this signature
/// absorbed the separate pseudonym proof-of-possession: signing `pk_pc` under
/// `pk_pc` proves possession, and covering `pk_lt` ties that proof to the
/// identity `bind_lt` vouches for.
#[allow(clippy::too_many_arguments)]
pub fn msg_sig_input(
    frame_kind: &[u8],
    chan_id: &[u8; ROOT_LEN],
    dir: &[u8],
    seq: u64,
    eph_ek: &[u8; ml_kem::EK_LEN],
    recipient_hash: &[u8; RECIPIENT_HASH_LEN],
    pk_pc: &[u8; ml_dsa::PK_LEN],
    pk_lt: &[u8; ml_dsa::PK_LEN],
    sent_unix_ms: i64,
    body: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        domain::DM_MSG_SIG.len() + 2 * ml_dsa::PK_LEN + ml_kem::EK_LEN + body.len() + 128,
    );
    buf.extend_from_slice(domain::DM_MSG_SIG);
    push_lp(&mut buf, frame_kind);
    push_lp(&mut buf, chan_id);
    push_lp(&mut buf, dir);
    push_lp(&mut buf, &seq.to_be_bytes());
    push_lp(&mut buf, eph_ek);
    push_lp(&mut buf, recipient_hash);
    push_lp(&mut buf, pk_pc);
    push_lp(&mut buf, pk_lt);
    push_lp(&mut buf, &sent_unix_ms.to_be_bytes());
    push_lp(&mut buf, body.as_bytes());
    buf
}

/// The AAD binding a sealed entry to one recipient and one epoch.
///
/// The recipient's key-record owner seed stands in for its identity here: both
/// parties derive it from the same public key, and it is already the address the
/// sender fetched the encapsulation key from.
fn seal_aad(
    recipient_keyrec_addr: &[u8; keyrec::DM_KEYREC_OWNER_SEED_LEN],
    fc_epoch: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain::DM_FC_AAD.len() + 64);
    aad.extend_from_slice(domain::DM_FC_AAD);
    push_lp(&mut aad, recipient_keyrec_addr);
    push_lp(&mut aad, &fc_epoch.to_be_bytes());
    aad
}

/// A key-record owner-seed derivation is a LOCAL KDF over our own public key, so
/// its only failure is the crypto module being non-operational. Reporting that as
/// the AEAD authentication failure would tell an operator their inbound knocks
/// were tampered with when the real cause is a self-test that has not passed.
fn owner_seed_err(e: keyrec::DmKeyRecordError) -> FirstContactError {
    match e {
        keyrec::DmKeyRecordError::Kdf(k) => FirstContactError::Kdf(k),
        _ => FirstContactError::Malformed,
    }
}

/// Derive the AES-256-GCM seal key from `ss0`.
fn seal_key(ss0: &[u8; SS0_LEN]) -> Result<Aes256Key, FirstContactError> {
    let hkdf =
        HkdfSha384::extract(Some(domain::DM_FC_SALT), ss0).map_err(FirstContactError::Kdf)?;
    let mut key = [0u8; 32];
    hkdf.expand(domain::DM_FC_SEAL, &mut key)
        .map_err(FirstContactError::Kdf)?;
    let aes = Aes256Key::new(&key).map_err(FirstContactError::Module)?;
    key.zeroize();
    Ok(aes)
}

/// SHA-384 of an identity's public key — the hashed intended recipient.
pub fn recipient_hash(
    pk_lt: &[u8; ml_dsa::PK_LEN],
) -> Result<[u8; RECIPIENT_HASH_LEN], FirstContactError> {
    let digest = sha384(pk_lt).map_err(FirstContactError::Module)?;
    let mut out = [0u8; RECIPIENT_HASH_LEN];
    out.copy_from_slice(&digest[..RECIPIENT_HASH_LEN]);
    Ok(out)
}

/// Pad an encoded body to the smallest bucket that holds it. See
/// [`crate::dm::pad_to_bucket`] — the ladder is this module's, the scheme is
/// shared with every other DM frame kind.
fn pad_plaintext(encoded: &[u8]) -> Result<Vec<u8>, FirstContactError> {
    crate::dm::pad_to_bucket(encoded, PAD_BUCKETS).ok_or(FirstContactError::TooLarge {
        got: LEN_PREFIX.saturating_add(encoded.len()),
        max: *PAD_BUCKETS.last().expect("ladder is never empty"),
    })
}

/// Recover the encoded body from a padded plaintext. Fails closed on a corrupt or
/// oversized length rather than slicing past the buffer.
fn unpad_plaintext(padded: &[u8]) -> Result<&[u8], FirstContactError> {
    crate::dm::unpad(padded).ok_or(FirstContactError::Malformed)
}

fn exact<const N: usize>(field: &'static str, bytes: &[u8]) -> Result<[u8; N], FirstContactError> {
    bytes
        .try_into()
        .map_err(|_| FirstContactError::FieldLength {
            field,
            expected: N,
            actual: bytes.len(),
        })
}

/// What a sender must keep to make its knock idempotent and to complete the first
/// ratchet step when the recipient replies.
///
/// **Every field is required, and two are easy to miss.** `ss0` alone re-derives
/// the channel, so a retry re-lands on the same conversation instead of forking a
/// second one. But without the opening ephemeral DECAPSULATION key the sender
/// cannot decapsulate the recipient's reply, so it would lose the first ratchet
/// step — and with it the forward secrecy that the reply is supposed to establish.
/// And [`ratchet::Ratchet::initiator`] needs the ENCAPSULATION key too, to check
/// the two halves are a pair before a silent mismatch costs the conversation; it
/// is carried here because [`build`] generates the keypair internally, so nowhere
/// else has it (#255).
///
/// **No `Drop` impl, deliberately.** `ss0` is [`Zeroizing`] instead. A container
/// `Drop` forbids moving fields *out*, so a caller could not hand `eph_dk` to a
/// ratchet without copying the bytes back out — manufacturing a second live copy
/// of exactly the secret the newtype exists to keep down to one (#255). With the
/// zeroizing wrapper the field destroys itself, ordinary partial moves work, and
/// [`Self::into_provisional`] moves both halves straight through.
///
/// **What that trade buys, stated precisely.** The old container `Drop` wiped
/// `ss0`'s slot on *every* path, because forbidding partial moves left no path
/// where the slot was not still the owner. [`Zeroizing`] wipes only whichever
/// slot still owns the value at drop, so after [`Self::into_provisional`] the
/// source slot is a moved-from `[u8; N]` — `Copy`, no destructor — whose bytes
/// stay in that frame until it is reused. The trade is still right, and what it
/// buys is **aliasing, not residue**: one live copy with a moved-from shadow
/// beats two live copies each wiped at its own end, because a second live copy is
/// a second thing to lose.
///
/// **Fields are private, and [`Self::into_provisional`] is the sole exit.** With
/// the container `Drop` gone, a public `ss0` means `let ss0 = *state.ss0;` — a
/// deref to a bare `Copy` array with no zeroize on it — which is precisely the
/// second live copy the whole `Drop`-to-`Zeroizing` change was made to avoid.
/// [`build`] is the only constructor, so nothing outside this module ever needed
/// the fields.
pub struct FirstContactState {
    ss0: Zeroizing<[u8; SS0_LEN]>,
    eph_ek: Box<[u8; ml_kem::EK_LEN]>,
    eph_dk: ratchet::EphemeralDecapKey,
    roots: ChannelRoots,
}

impl FirstContactState {
    /// The channel's address root and conversation identifier, computed at
    /// [`build`] time.
    ///
    /// By value: [`ChannelRoots`] is two public-in-effect derivations the caller
    /// needs to address and sign with, and `chan_id` must stay in memory rather
    /// than be written down (§ v4 minor invariant).
    pub fn roots(&self) -> &ChannelRoots {
        &self.roots
    }

    /// The opening ephemeral's public half — what the recipient encapsulates to.
    ///
    /// No accessor for the *secret* half, and none for `ss0`: the only way either
    /// leaves this type is [`Self::into_provisional`], which moves them.
    pub fn eph_ek(&self) -> &[u8; ml_kem::EK_LEN] {
        &self.eph_ek
    }

    /// Hand the state to the record that persists it across a restart (#243,
    /// #255).
    ///
    /// Consuming, so neither half of the ephemeral is ever duplicated. `roots` is
    /// dropped here rather than carried on: the record recomputes `ar` and
    /// `chan_id` from `ss0`, and `chan_id` must never be serialized at all.
    pub fn into_provisional(
        self,
    ) -> Result<crate::dm::provisional::ProvisionalRecord, crate::dm::provisional::ProvisionalError>
    {
        let Self {
            ss0,
            eph_ek,
            eph_dk,
            roots: _,
        } = self;
        crate::dm::provisional::ProvisionalRecord::new(ss0, eph_ek, eph_dk)
    }
}

impl std::fmt::Debug for FirstContactState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FirstContactState(<redacted>)")
    }
}

/// Build a padded, sealed first-contact entry, plus the state the sender must keep.
///
/// `signing_lt` is the sender's long-term identity key and `signing_pc` the
/// per-contact pseudonym minted for this correspondent. `kem_ek_b` is the
/// recipient's published encapsulation key — the caller is responsible for having
/// verified the key record it came from, because everything here is encapsulated
/// to it.
pub fn build(
    signing_lt: &SignKeypair,
    signing_pc: &SignKeypair,
    recipient_pk_lt: &[u8; ml_dsa::PK_LEN],
    kem_ek_b: &[u8; ml_kem::EK_LEN],
    fc_epoch: u64,
    sent_unix_ms: i64,
    body: &str,
) -> Result<(Vec<u8>, FirstContactState), FirstContactError> {
    if body.len() > DM_BODY_CAP {
        return Err(FirstContactError::TooLarge {
            got: body.len(),
            max: DM_BODY_CAP,
        });
    }

    // Encapsulate to the recipient's STATIC key. This is the step with no forward
    // secrecy — see the module docs.
    let mut m = [0u8; ml_kem::SEED_LEN];
    getrandom::fill(&mut m).map_err(|_| FirstContactError::EntropySource)?;
    let encapsulated = ml_kem::encapsulate(kem_ek_b, &m);
    m.zeroize();
    let (ss0, ct0) = encapsulated.map_err(FirstContactError::Module)?;

    // The opening ratchet ephemeral is generated HERE rather than taken as an
    // argument, so a caller cannot keep the public half and drop the secret one.
    // Losing `eph_dk` costs the first ratchet step — and with it the forward
    // secrecy the recipient's reply is supposed to establish — which is a silent
    // failure no test on the wire would catch.
    let mut d = [0u8; ml_kem::SEED_LEN];
    let mut z = [0u8; ml_kem::SEED_LEN];
    getrandom::fill(&mut d).map_err(|_| FirstContactError::EntropySource)?;
    getrandom::fill(&mut z).map_err(|_| FirstContactError::EntropySource)?;
    let generated = ml_kem::keygen(&d, &z);
    d.zeroize();
    z.zeroize();
    let (eph_ek_arr, eph_dk_arr) = generated.map_err(FirstContactError::Module)?;
    let eph_ek = &eph_ek_arr;

    let roots = derive_channel_roots(&ss0)?;
    let rcpt_hash = recipient_hash(recipient_pk_lt)?;

    let bind_lt = signing_lt
        .sign(&bind_lt_input(
            signing_lt.public_key(),
            signing_pc.public_key(),
        ))
        .map_err(FirstContactError::Signing)?;

    let seq = 0u64;
    let msg_sig = signing_pc
        .sign(&msg_sig_input(
            FRAME_KIND_FIRST_CONTACT,
            &roots.chan_id,
            DIR_A2B,
            seq,
            eph_ek,
            &rcpt_hash,
            signing_pc.public_key(),
            signing_lt.public_key(),
            sent_unix_ms,
            body,
        ))
        .map_err(FirstContactError::Signing)?;

    let body_msg = wire::FirstContactBody {
        intended_recipient_hash: rcpt_hash.to_vec(),
        pk_lt: signing_lt.public_key().to_vec(),
        pk_pc: signing_pc.public_key().to_vec(),
        bind_lt: bind_lt.to_vec(),
        key_selector: wire::KeySelector::Static as i32,
        seq,
        sent_unix_ms,
        body: body.to_owned(),
        eph_ek: eph_ek.to_vec(),
        msg_sig: msg_sig.to_vec(),
        token: Vec::new(),
    };

    let mut encoded = body_msg.encode_to_vec();
    let mut padded = pad_plaintext(&encoded)?;
    encoded.zeroize();
    let addr = keyrec::derive_owner_seed(recipient_pk_lt).map_err(owner_seed_err)?;
    let sealed = seal_envelope(
        &seal_key(&ss0)?,
        &seal_aad(addr.as_bytes(), fc_epoch),
        &padded,
    );
    padded.zeroize();
    let sealed = sealed?;

    let entry = wire::FirstContactEntry {
        ct0: ct0.to_vec(),
        sealed,
        pow: Vec::new(),
    }
    .encode_to_vec();

    if entry.len() > MAX_ENTRY_LEN {
        return Err(FirstContactError::TooLarge {
            got: entry.len(),
            max: MAX_ENTRY_LEN,
        });
    }
    Ok((
        entry,
        FirstContactState {
            ss0: Zeroizing::new(ss0),
            eph_ek: Box::new(eph_ek_arr),
            eph_dk: ratchet::EphemeralDecapKey::new(Box::new(eph_dk_arr)),
            roots,
        },
    ))
}

/// A first-contact entry whose seal opened and whose every signature verified.
/// Only constructible via [`open`], so holding one IS the proof.
#[derive(Clone)]
pub struct VerifiedFirstContact {
    /// The sender's long-term identity key — what to display, accept, or block.
    pub pk_lt: Box<[u8; ml_dsa::PK_LEN]>,
    /// The pseudonym that will sign this conversation.
    pub pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
    /// The sender's opening ratchet ephemeral, to encapsulate to in the reply.
    pub eph_ek: Box<[u8; ml_kem::EK_LEN]>,
    pub seq: u64,
    pub sent_unix_ms: i64,
    pub body: String,
    /// The encapsulated secret, to persist as provisional handshake state.
    pub ss0: [u8; SS0_LEN],
    pub roots: ChannelRoots,
}

impl Drop for VerifiedFirstContact {
    /// `ss0` is a bare array, so it has no `Drop` of its own and would otherwise
    /// outlive this struct in whatever stack or heap slot held it — and it is the
    /// secret the seal key, `AR`, `chan_id` and the whole ratchet root on. The
    /// boxed public halves need no wiping. (#259)
    fn drop(&mut self) {
        self.ss0.zeroize();
    }
}

impl std::fmt::Debug for VerifiedFirstContact {
    /// Hand-written, never derived: `ss0` is the root of the seal key, `AR`,
    /// `chan_id` and the ratchet, so one `debug!(?verified)` would put the whole
    /// conversation in a log. The public halves are safe to show and are what a
    /// reader actually wants.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedFirstContact")
            .field("pk_lt", &"<ML-DSA-87 pubkey>")
            .field("pk_pc", &"<ML-DSA-87 pubkey>")
            .field("eph_ek", &"<ML-KEM-1024 ek>")
            .field("seq", &self.seq)
            .field("sent_unix_ms", &self.sent_unix_ms)
            .field("body", &self.body)
            .field("ss0", &"<redacted>")
            .field("roots", &self.roots)
            .finish()
    }
}

/// Open and fully verify an entry from a doorbell slot.
///
/// `current_fc_epoch` is the recipient's own clock-derived epoch; the current and
/// previous epoch are both accepted, which is the window that lets an entry
/// composed while the recipient was offline still be collected.
///
/// Everything fails closed, and the failures are deliberately hard to tell apart
/// from outside: the doorbell is world-writable, so garbage is an ordinary input.
pub fn open(
    entry_bytes: &[u8],
    recipient_dk: &[u8; ml_kem::DK_LEN],
    recipient_pk_lt: &[u8; ml_dsa::PK_LEN],
    current_fc_epoch: u64,
) -> Result<VerifiedFirstContact, FirstContactError> {
    let entry =
        wire::FirstContactEntry::decode(entry_bytes).map_err(|_| FirstContactError::Malformed)?;
    let ct0: [u8; CT0_LEN] = exact("ct0", &entry.ct0)?;

    // ML-KEM decapsulation uses implicit rejection: a bogus ciphertext yields a
    // pseudorandom secret rather than an error, in constant time. So a forged
    // entry is not detected here — it is detected when the AEAD open fails under
    // the resulting wrong key, which is exactly the uniform failure we want.
    let ss0 = ml_kem::decapsulate(recipient_dk, &ct0).map_err(FirstContactError::Module)?;

    let addr = keyrec::derive_owner_seed(recipient_pk_lt).map_err(owner_seed_err)?;
    let key = seal_key(&ss0)?;

    // Current epoch first, then the previous one. Trying both is what tolerates a
    // sender who composed just before a boundary; anything older simply will not
    // open, so staleness needs no persisted seen-set.
    let mut candidates = vec![current_fc_epoch];
    if let Some(previous) = current_fc_epoch.checked_sub(1) {
        candidates.push(previous);
    }
    let padded = candidates
        .into_iter()
        .find_map(|epoch| {
            open_envelope(&key, &seal_aad(addr.as_bytes(), epoch), &entry.sealed).ok()
        })
        .ok_or(FirstContactError::Aead)?;

    let mut padded = padded;
    let decoded = wire::FirstContactBody::decode(unpad_plaintext(&padded)?)
        .map_err(|_| FirstContactError::Malformed);
    padded.zeroize();
    let body = decoded?;

    let rcpt_hash: [u8; RECIPIENT_HASH_LEN] =
        exact("intended_recipient_hash", &body.intended_recipient_hash)?;
    let pk_lt: [u8; ml_dsa::PK_LEN] = exact("pk_lt", &body.pk_lt)?;
    let pk_pc: [u8; ml_dsa::PK_LEN] = exact("pk_pc", &body.pk_pc)?;
    let bind_lt: [u8; ml_dsa::SIG_LEN] = exact("bind_lt", &body.bind_lt)?;
    let msg_sig: [u8; ml_dsa::SIG_LEN] = exact("msg_sig", &body.msg_sig)?;
    let eph_ek: [u8; ml_kem::EK_LEN] = exact("eph_ek", &body.eph_ek)?;

    if rcpt_hash != recipient_hash(recipient_pk_lt)? {
        return Err(FirstContactError::WrongRecipient);
    }
    // First contact is always the opening frame. Accepting any other value would
    // hand a stranger the receiver's page cursor: the design pages messages at
    // `seq / K`, so a `seq` near `u64::MAX` starts collection at an absurd page.
    if body.seq != 0 {
        return Err(FirstContactError::Malformed);
    }
    // Reject a selector we do not understand rather than treating it as STATIC.
    // The field exists so a future prekey-capable client is DISTINGUISHABLE from
    // this one; silently coercing it would throw that away, and proto3's zero
    // default means an omitted field must be rejected too.
    if body.key_selector != wire::KeySelector::Static as i32 {
        return Err(FirstContactError::Malformed);
    }
    if body.body.len() > DM_BODY_CAP {
        return Err(FirstContactError::TooLarge {
            got: body.body.len(),
            max: DM_BODY_CAP,
        });
    }

    // The pseudonym is only meaningful if the long-term key vouches for it...
    verify_signature(&pk_lt, &bind_lt_input(&pk_lt, &pk_pc), &bind_lt)
        .map_err(|_| FirstContactError::Signature)?;

    // ...and the frame is only authentic if the pseudonym signed it. This second
    // check is also the sole proof that the sender HOLDS the pseudonym key: without
    // it, anyone could staple someone else's `bind_lt` to their own message.
    let roots = derive_channel_roots(&ss0)?;
    verify_signature(
        &pk_pc,
        &msg_sig_input(
            FRAME_KIND_FIRST_CONTACT,
            &roots.chan_id,
            DIR_A2B,
            body.seq,
            &eph_ek,
            &rcpt_hash,
            &pk_pc,
            &pk_lt,
            body.sent_unix_ms,
            &body.body,
        ),
        &msg_sig,
    )
    .map_err(|_| FirstContactError::Signature)?;

    Ok(VerifiedFirstContact {
        pk_lt: Box::new(pk_lt),
        pk_pc: Box::new(pk_pc),
        eph_ek: Box::new(eph_ek),
        seq: body.seq,
        sent_unix_ms: body.sent_unix_ms,
        body: body.body,
        ss0,
        roots,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::{Identity, IdentityKeys, derive_identity_keys};
    use crate::identity::mnemonic::Mnemonic;

    const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon art";
    const PHRASE_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                            zoo zoo zoo zoo zoo zoo zoo vote";
    const EPOCH: u64 = 2_900_000;
    const SENT: i64 = 1_700_000_000_000;

    fn keys(phrase: &str) -> IdentityKeys {
        let _ = oxicrypt_module::initialize();
        derive_identity_keys(&Mnemonic::from_phrase(phrase).unwrap(), Identity::Primary).unwrap()
    }

    fn alice() -> IdentityKeys {
        keys(PHRASE_A)
    }

    fn bob() -> IdentityKeys {
        keys(PHRASE_B)
    }

    /// A fresh identity, used where the test needs a third party or a pseudonym.
    /// Real pseudonyms are random per correspondent — never mnemonic-derived —
    /// which is what makes them unlinkable across conversations.
    fn pseudonym() -> IdentityKeys {
        let _ = oxicrypt_module::initialize();
        derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap()
    }

    struct Knock {
        entry: Vec<u8>,
        a: IdentityKeys,
        b: IdentityKeys,
        pc: IdentityKeys,
        state: FirstContactState,
    }

    fn knock(body: &str, epoch: u64) -> Knock {
        let a = alice();
        let b = bob();
        let pc = pseudonym();
        let (entry, state) = build(
            &a.signing,
            &pc.signing,
            b.signing.public_key(),
            b.kem.encapsulation_key(),
            epoch,
            SENT,
            body,
        )
        .unwrap();
        Knock {
            entry,
            a,
            b,
            pc,
            state,
        }
    }

    fn open_at(k: &Knock, epoch: u64) -> Result<VerifiedFirstContact, FirstContactError> {
        open(
            &k.entry,
            k.b.kem.decapsulation_key(),
            k.b.signing.public_key(),
            epoch,
        )
    }

    /// Assemble an entry from hand-built parts, so a test can present a body the
    /// honest `build` would never produce. This is how the checks that only a
    /// malicious sender can trigger get exercised at all.
    fn hand_built(
        recipient: &IdentityKeys,
        body: wire::FirstContactBody,
        epoch: u64,
    ) -> (Vec<u8>, [u8; SS0_LEN]) {
        let mut m = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut m).unwrap();
        let (ss0, ct0) = ml_kem::encapsulate(recipient.kem.encapsulation_key(), &m).unwrap();
        let addr = keyrec::derive_owner_seed(recipient.signing.public_key()).unwrap();
        let sealed = seal_envelope(
            &seal_key(&ss0).unwrap(),
            &seal_aad(addr.as_bytes(), epoch),
            &pad_plaintext(&body.encode_to_vec()).unwrap(),
        )
        .unwrap();
        (
            wire::FirstContactEntry {
                ct0: ct0.to_vec(),
                sealed,
                pow: Vec::new(),
            }
            .encode_to_vec(),
            ss0,
        )
    }

    /// A body that would verify, as a starting point for tests that corrupt one
    /// field. `signer_pc` signs `msg_sig`; `claimed_lt` is what the body claims.
    #[allow(clippy::too_many_arguments)]
    fn signed_body(
        claimed_lt: &[u8; ml_dsa::PK_LEN],
        binder: &SignKeypair,
        signer_pc: &SignKeypair,
        claimed_pc: &[u8; ml_dsa::PK_LEN],
        recipient: &IdentityKeys,
        ss0: &[u8; SS0_LEN],
        eph_ek: &[u8; ml_kem::EK_LEN],
        seq: u64,
        body: &str,
    ) -> wire::FirstContactBody {
        let rcpt = recipient_hash(recipient.signing.public_key()).unwrap();
        let roots = derive_channel_roots(ss0).unwrap();
        wire::FirstContactBody {
            intended_recipient_hash: rcpt.to_vec(),
            pk_lt: claimed_lt.to_vec(),
            pk_pc: claimed_pc.to_vec(),
            bind_lt: binder
                .sign(&bind_lt_input(binder.public_key(), claimed_pc))
                .unwrap()
                .to_vec(),
            key_selector: wire::KeySelector::Static as i32,
            seq,
            sent_unix_ms: SENT,
            body: body.to_owned(),
            eph_ek: eph_ek.to_vec(),
            msg_sig: signer_pc
                .sign(&msg_sig_input(
                    FRAME_KIND_FIRST_CONTACT,
                    &roots.chan_id,
                    DIR_A2B,
                    seq,
                    eph_ek,
                    &rcpt,
                    claimed_pc,
                    claimed_lt,
                    SENT,
                    body,
                ))
                .unwrap()
                .to_vec(),
            token: Vec::new(),
        }
    }

    // ── The happy path ──────────────────────────────────────────────────────

    /// The whole point, end to end: a stranger holding only Bob's public identity
    /// produces something Bob opens, and Bob recovers exactly what was sent —
    /// including the ephemeral his reply must encapsulate to.
    #[test]
    fn a_knock_round_trips_and_every_field_survives() {
        let k = knock("hello — this is caraka", EPOCH);
        let v = open_at(&k, EPOCH).unwrap();
        assert_eq!(&v.pk_lt[..], &k.a.signing.public_key()[..]);
        assert_eq!(&v.pk_pc[..], &k.pc.signing.public_key()[..]);
        assert_eq!(v.body, "hello — this is caraka");
        assert_eq!(v.sent_unix_ms, SENT);

        // The ephemeral is the forward-secrecy pivot: Bob encapsulates his reply
        // to it. If `build` had serialized the wrong 1568-byte KEM key — Bob's own
        // static key is the same type and was an adjacent argument — every other
        // assertion here would still pass, `msg_sig` would still verify, and the
        // ratchet would silently never fork.
        let (expected_ek, _) = ml_kem::keygen(&[0u8; 32], &[0u8; 32]).unwrap();
        assert_eq!(v.eph_ek.len(), expected_ek.len());
        assert_ne!(
            &v.eph_ek[..],
            &k.b.kem.encapsulation_key()[..],
            "the ephemeral must not be the recipient's own static key"
        );
        assert_ne!(
            &v.eph_ek[..],
            &k.a.kem.encapsulation_key()[..],
            "the ephemeral must not be the sender's static key either"
        );
    }

    /// `build` must hand back the DECAPSULATION half of the ephemeral. Without it
    /// the sender cannot open the recipient's reply, so the first ratchet step —
    /// and the forward secrecy it establishes — is lost. Returning only the public
    /// half would let a caller lose it without noticing.
    #[test]
    fn build_returns_the_ephemeral_secret_matching_the_published_key() {
        let k = knock("hi", EPOCH);
        let v = open_at(&k, EPOCH).unwrap();
        let mut m = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut m).unwrap();
        let (ss, ct) = ml_kem::encapsulate(&v.eph_ek, &m).unwrap();
        assert_eq!(
            ml_kem::decapsulate(k.state.eph_dk.as_bytes(), &ct).unwrap(),
            ss,
            "the persisted eph_dk must decapsulate what a reply encapsulates to eph_ek"
        );
    }

    /// **#255.** The state carries the ephemeral's PUBLIC half too. `build`
    /// generates the keypair internally, so nowhere else holds it, and
    /// `Ratchet::initiator` needs it to check the two halves are a pair before a
    /// silent mismatch costs the conversation. Without this field a caller had to
    /// slice it back out of the decapsulation key at the FIPS 203 offset.
    #[test]
    fn build_returns_both_halves_of_the_opening_ephemeral() {
        let k = knock("hi", EPOCH);
        let v = open_at(&k, EPOCH).unwrap();
        assert_eq!(
            k.state.eph_ek(),
            v.eph_ek.as_ref(),
            "the state's eph_ek is not the one the entry published"
        );
        assert!(
            k.state.eph_dk.matches(k.state.eph_ek()),
            "the state's two halves are not a keypair"
        );
    }

    /// **#255.** The state hands both halves to the record that persists them,
    /// consuming itself — so there is no moment at which a second copy of the
    /// decapsulation key exists. A `Drop` impl on `FirstContactState` would make
    /// this not compile, which is what the issue was about; the test therefore
    /// pins the ergonomic property as much as the values.
    #[test]
    fn the_state_moves_into_a_provisional_record() {
        let k = knock("hi", EPOCH);
        // Deliberately NOT `let ss0 = *k.state.ss0;`. That deref yields a bare
        // `[u8; N]` -- `Copy`, no destructor -- which is the second live copy of
        // the channel's opening secret that #255 exists to prevent, and it is why
        // the fields are private. `ar` is a derived, non-secret root, so copying
        // it is fine.
        let ar = k.state.roots().ar;

        let record = k.state.into_provisional().expect("a matched pair");

        // Same conversation on the far side of the move: `ar` is recomputed from
        // `ss0` rather than carried, so this also pins that recomputation.
        assert_eq!(record.address_root().unwrap(), ar);

        // And the ratchet it opens is the one `ss0` roots.
        let ratchet = record.into_ratchet().expect("opens a ratchet");
        assert_eq!(ratchet.role(), ratchet::Role::Initiator);
        assert_eq!(ratchet.generation(), 0);
    }

    /// `into_provisional`'s `Err` arm, which nothing exercised. It forwards
    /// `ProvisionalRecord::new`'s pairing check, and a state whose halves do not
    /// pair must be refused HERE rather than becoming a record that rejects every
    /// reply forever.
    ///
    /// `build` cannot produce such a state -- it generates the keypair itself --
    /// so the state is assembled by hand, which the private fields permit only
    /// inside this module. That is the point: the failure is unreachable through
    /// the public surface, and this pins that it is still refused if it is ever
    /// reached.
    #[test]
    fn a_state_whose_ephemeral_halves_disagree_does_not_become_a_record() {
        let k = knock("hi", EPOCH);
        let (other_ek, _) = ml_kem::keygen(&[0x5Eu8; 32], &[0x7Du8; 32]).unwrap();

        // Positive control: the state as built DOES convert, so the refusal below
        // is the mismatch and not something else about the hand-built state.
        let good = knock("hi", EPOCH);
        assert!(good.state.into_provisional().is_ok());

        let spliced = FirstContactState {
            ss0: k.state.ss0.clone(),
            eph_ek: Box::new(other_ek),
            eph_dk: k.state.eph_dk,
            roots: k.state.roots,
        };
        assert_eq!(
            spliced.into_provisional().unwrap_err(),
            crate::dm::provisional::ProvisionalError::MismatchedEphemeral
        );
    }

    /// Both parties must reach the same conversation independently — the sender at
    /// compose time, the recipient after decapsulating. If these diverged they
    /// would address different channels and never meet.
    #[test]
    fn both_ends_derive_the_same_channel_roots() {
        let k = knock("hi", EPOCH);
        let v = open_at(&k, EPOCH).unwrap();
        assert_eq!(v.ss0, *k.state.ss0);
        assert_eq!(v.roots.ar, k.state.roots.ar);
        assert_eq!(v.roots.chan_id, k.state.roots.chan_id);
        assert_ne!(
            k.state.roots.ar, k.state.roots.chan_id,
            "the address root and the channel id must be independent derivations"
        );
    }

    // ── Secrets must not leak through Debug ─────────────────────────────────

    /// `ss0` roots the seal key, `AR`, `chan_id` and the ratchet. One
    /// `debug!(?verified)` would put the entire conversation in a log, so the
    /// `Debug` impl is hand-written and this is the test that keeps it that way.
    #[test]
    fn a_verified_knock_never_debug_prints_its_secret() {
        let k = knock("hi", EPOCH);
        let v = open_at(&k, EPOCH).unwrap();
        let rendered = format!("{v:?}");
        assert!(
            !rendered.contains(&hex::encode(v.ss0)),
            "ss0 must never appear in Debug output"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(!format!("{:?}", k.state).contains(&hex::encode(v.ss0)));
        assert!(!format!("{:?}", v.roots).contains(&hex::encode(v.roots.ar)));
    }

    // ── Authenticity ────────────────────────────────────────────────────────

    /// `msg_sig` is the SOLE proof that the sender holds the pseudonym key.
    /// Without it, anyone could staple a genuine `bind_lt` they observed onto
    /// their own message and impersonate the identity it vouches for.
    #[test]
    fn a_stapled_binding_without_the_pseudonym_key_is_rejected() {
        let a = alice();
        let b = bob();
        let pc = pseudonym();
        let impostor = pseudonym();
        let eph = pseudonym();
        let mut m = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut m).unwrap();
        let (ss0, _) = ml_kem::encapsulate(b.kem.encapsulation_key(), &m).unwrap();
        // Alice's real binding, but msg_sig signed by an impostor claiming her
        // pseudonym. The binding verifies; authorship must not.
        let body = signed_body(
            a.signing.public_key(),
            &a.signing,
            &impostor.signing,
            pc.signing.public_key(),
            &b,
            &ss0,
            eph.kem.encapsulation_key(),
            0,
            "trust me",
        );
        let (entry, _) = hand_built(&b, body, EPOCH);
        assert!(matches!(
            open(
                &entry,
                b.kem.decapsulation_key(),
                b.signing.public_key(),
                EPOCH
            ),
            Err(FirstContactError::Signature)
        ));
    }

    /// `bind_lt` is what makes `pk_lt` mean anything. An entry claiming one
    /// identity while carrying another's binding must be rejected — this check is
    /// all that stands between a copied binding and full impersonation of the
    /// identity a recipient displays, accepts, and blocks on.
    ///
    /// `msg_sig` here is signed correctly over the FORGED `pk_lt` by a pseudonym
    /// key the sender really holds, so only the binding check can catch it.
    #[test]
    fn a_binding_that_does_not_cover_the_claimed_identity_is_rejected() {
        let victim = pseudonym();
        let a = alice();
        let mallory = bob();
        let pc = pseudonym();
        let eph = pseudonym();
        let mut m = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut m).unwrap();
        let (ss0, _) = ml_kem::encapsulate(victim.kem.encapsulation_key(), &m).unwrap();
        // Body claims Mallory's identity; the binding is Alice's and covers only
        // Alice. msg_sig is honest about everything the body says.
        let mut body = signed_body(
            mallory.signing.public_key(),
            &a.signing,
            &pc.signing,
            pc.signing.public_key(),
            &victim,
            &ss0,
            eph.kem.encapsulation_key(),
            0,
            "hi",
        );
        body.pk_lt = mallory.signing.public_key().to_vec();
        let (entry, _) = hand_built(&victim, body, EPOCH);
        assert!(matches!(
            open(
                &entry,
                victim.kem.decapsulation_key(),
                victim.signing.public_key(),
                EPOCH
            ),
            Err(FirstContactError::Signature)
        ));
    }

    // ── Addressing ──────────────────────────────────────────────────────────

    /// A knock addressed to Bob must not open at anyone else — not even far
    /// enough to reveal who sent it.
    #[test]
    fn a_knock_does_not_open_at_a_different_identity() {
        let k = knock("hi", EPOCH);
        let mallory = pseudonym();
        assert!(matches!(
            open(
                &k.entry,
                mallory.kem.decapsulation_key(),
                mallory.signing.public_key(),
                EPOCH
            ),
            Err(FirstContactError::Aead)
        ));
    }

    /// Decapsulating successfully is not enough. The AAD independently binds the
    /// recipient's own key-record address, so holding the decapsulation key that
    /// produced `ss0` still does not open an entry addressed to someone else.
    /// This isolates the AAD binding from the KEM binding — the previous test
    /// exercises only the latter.
    #[test]
    fn the_aad_binds_the_recipient_independently_of_the_encapsulation() {
        let k = knock("hi", EPOCH);
        let other = pseudonym();
        assert!(matches!(
            open(
                &k.entry,
                k.b.kem.decapsulation_key(),
                other.signing.public_key(),
                EPOCH
            ),
            Err(FirstContactError::Aead)
        ));
    }

    /// The hashed intended recipient is the misdirection check. Only a hand-built
    /// entry can reach it — an honest sender derives the AAD and the hash from the
    /// same key — so without this test the check is unreachable and could be
    /// deleted with the suite still green.
    #[test]
    fn a_body_addressed_elsewhere_is_rejected_after_decapsulation() {
        let b = bob();
        let elsewhere = pseudonym();
        let a = alice();
        let pc = pseudonym();
        let eph = pseudonym();
        let mut m = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut m).unwrap();
        let (ss0, _) = ml_kem::encapsulate(b.kem.encapsulation_key(), &m).unwrap();
        // Sealed to Bob, but naming someone else inside.
        let mut body = signed_body(
            a.signing.public_key(),
            &a.signing,
            &pc.signing,
            pc.signing.public_key(),
            &elsewhere,
            &ss0,
            eph.kem.encapsulation_key(),
            0,
            "hi",
        );
        body.intended_recipient_hash = recipient_hash(elsewhere.signing.public_key())
            .unwrap()
            .to_vec();
        let (entry, _) = hand_built(&b, body, EPOCH);
        assert!(matches!(
            open(
                &entry,
                b.kem.decapsulation_key(),
                b.signing.public_key(),
                EPOCH
            ),
            Err(FirstContactError::WrongRecipient)
        ));
    }

    // ── Replay ──────────────────────────────────────────────────────────────

    /// The epoch window is current-or-previous. One back is still collectable (the
    /// sender may have composed while the recipient was offline); two back is a
    /// stale replay.
    #[test]
    fn the_epoch_window_accepts_current_and_previous_only() {
        for (composed, accepted) in [(EPOCH, true), (EPOCH - 1, true), (EPOCH - 2, false)] {
            let k = knock("hi", composed);
            assert_eq!(
                open_at(&k, EPOCH).is_ok(),
                accepted,
                "entry composed at epoch {composed} against current {EPOCH}"
            );
        }
    }

    /// A recipient whose clock has never passed epoch 0 must not underflow looking
    /// for a previous epoch. The negative half is the load-bearing one: a plain
    /// `- 1` panics in debug but WRAPS in release, which would silently make an
    /// entry sealed at `u64::MAX` acceptable at epoch 0.
    #[test]
    fn epoch_zero_neither_underflows_nor_admits_a_wrapped_epoch() {
        let k = knock("hi", 0);
        assert!(open_at(&k, 0).is_ok(), "epoch 0 must open against itself");
        let far_future = knock("hi", u64::MAX);
        assert!(
            matches!(open_at(&far_future, 0), Err(FirstContactError::Aead)),
            "an entry from the maximum epoch must not open at epoch 0"
        );
    }

    // ── Hostile input ───────────────────────────────────────────────────────

    /// The doorbell is world-writable, so arbitrary bytes in a slot are an
    /// ordinary input. Every shape of garbage must fail closed and cheaply.
    #[test]
    fn garbage_in_a_slot_fails_closed() {
        let b = bob();
        for bytes in [
            Vec::new(),
            vec![0u8; 16],
            vec![0xffu8; 4096],
            b"not a protobuf at all".to_vec(),
        ] {
            assert!(
                open(
                    &bytes,
                    b.kem.decapsulation_key(),
                    b.signing.public_key(),
                    EPOCH
                )
                .is_err(),
                "garbage must never open"
            );
        }
    }

    /// Tampering anywhere in the sealed region must be caught by the AEAD tag.
    #[test]
    fn a_tampered_seal_is_rejected() {
        let k = knock("hi", EPOCH);
        let mut decoded = wire::FirstContactEntry::decode(&k.entry[..]).unwrap();
        let mid = decoded.sealed.len() / 2;
        decoded.sealed[mid] ^= 0x01;
        assert!(
            open(
                &decoded.encode_to_vec(),
                k.b.kem.decapsulation_key(),
                k.b.signing.public_key(),
                EPOCH
            )
            .is_err()
        );
    }

    /// Substituting the ciphertext changes the decapsulated secret. ML-KEM's
    /// implicit rejection means this surfaces as an AEAD failure rather than a
    /// decapsulation error — indistinguishable from garbage, which is the point.
    #[test]
    fn a_substituted_ciphertext_is_rejected() {
        let k = knock("hi", EPOCH);
        let mut decoded = wire::FirstContactEntry::decode(&k.entry[..]).unwrap();
        decoded.ct0[0] ^= 0x01;
        assert!(matches!(
            open(
                &decoded.encode_to_vec(),
                k.b.kem.decapsulation_key(),
                k.b.signing.public_key(),
                EPOCH
            ),
            Err(FirstContactError::Aead)
        ));
    }

    /// First contact is always the opening frame. A large `seq` would start the
    /// recipient's collection cursor at an absurd page, since the conversation
    /// pages at `seq / K` — so it is rejected rather than carried through.
    #[test]
    fn a_nonzero_sequence_number_is_rejected() {
        let b = bob();
        let a = alice();
        let pc = pseudonym();
        let eph = pseudonym();
        let mut m = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut m).unwrap();
        let (ss0, _) = ml_kem::encapsulate(b.kem.encapsulation_key(), &m).unwrap();
        let body = signed_body(
            a.signing.public_key(),
            &a.signing,
            &pc.signing,
            pc.signing.public_key(),
            &b,
            &ss0,
            eph.kem.encapsulation_key(),
            u64::MAX,
            "hi",
        );
        let (entry, _) = hand_built(&b, body, EPOCH);
        assert!(matches!(
            open(
                &entry,
                b.kem.decapsulation_key(),
                b.signing.public_key(),
                EPOCH
            ),
            Err(FirstContactError::Malformed)
        ));
    }

    /// The key selector exists so a future prekey-capable client is
    /// DISTINGUISHABLE from this one. Coercing an unknown or absent value to
    /// `STATIC` would throw that away, and proto3's zero default means an omitted
    /// field arrives as `UNSPECIFIED` — so it must be rejected too.
    #[test]
    fn an_unrecognised_key_selector_is_rejected() {
        let b = bob();
        let a = alice();
        let pc = pseudonym();
        let eph = pseudonym();
        let mut m = [0u8; ml_kem::SEED_LEN];
        getrandom::fill(&mut m).unwrap();
        let (ss0, _) = ml_kem::encapsulate(b.kem.encapsulation_key(), &m).unwrap();
        for selector in [wire::KeySelector::Unspecified as i32, 99] {
            let mut body = signed_body(
                a.signing.public_key(),
                &a.signing,
                &pc.signing,
                pc.signing.public_key(),
                &b,
                &ss0,
                eph.kem.encapsulation_key(),
                0,
                "hi",
            );
            body.key_selector = selector;
            let (entry, _) = hand_built(&b, body, EPOCH);
            assert!(
                matches!(
                    open(
                        &entry,
                        b.kem.decapsulation_key(),
                        b.signing.public_key(),
                        EPOCH
                    ),
                    Err(FirstContactError::Malformed)
                ),
                "selector {selector} must be rejected"
            );
        }
    }

    // ── Padding and size ────────────────────────────────────────────────────

    /// Padding must collapse message length to a coarse class: two very different
    /// bodies in the same bucket produce byte-identical entry lengths, and the
    /// ladder must actually have two rungs.
    #[test]
    fn padding_hides_body_length_within_a_bucket() {
        let short = knock("hi", EPOCH).entry.len();
        let longer = knock(&"x".repeat(2000), EPOCH).entry.len();
        assert_eq!(
            short, longer,
            "two bodies in one bucket must not be distinguishable by entry length"
        );
        let top = knock(&"x".repeat(DM_BODY_CAP), EPOCH).entry.len();
        assert!(
            top > short,
            "the ladder must have more than one rung, or it is a single constant"
        );
    }

    /// The ladder's arithmetic is on the FRAMED length, and the boundary is where
    /// it breaks: comparing the unframed length instead makes an exactly-filling
    /// body index past the end of its own buffer — a panic on the send path.
    #[test]
    fn the_padding_ladder_is_exact_at_every_boundary_and_round_trips() {
        for &bucket in PAD_BUCKETS {
            let exact = vec![0xabu8; bucket - LEN_PREFIX];
            let padded = pad_plaintext(&exact).unwrap();
            assert_eq!(padded.len(), bucket);
            assert_eq!(unpad_plaintext(&padded).unwrap(), &exact[..]);
        }
        assert_eq!(
            pad_plaintext(&vec![0u8; PAD_BUCKETS[0] - LEN_PREFIX + 1])
                .unwrap()
                .len(),
            PAD_BUCKETS[1],
            "one byte over a rung must promote to the next"
        );
        assert!(matches!(
            pad_plaintext(&vec![0u8; PAD_BUCKETS[1] - LEN_PREFIX + 1]),
            Err(FirstContactError::TooLarge { .. })
        ));
        // A hostile length prefix must fail closed, not over-read.
        assert!(unpad_plaintext(&[0xff, 0xff, 0xff, 0xff, 0x00]).is_err());
        assert!(unpad_plaintext(&[0u8; 3]).is_err());
    }

    /// The frozen build contract requires the top bucket to leave room for a
    /// token-bearing entry inside the `dflt(32)` subkey. The arithmetic is easy to
    /// get wrong by a few hundred bytes and the failure mode is a write the
    /// network refuses, so the constraint is asserted on the reserve — not just on
    /// today's outcome.
    #[test]
    fn a_maximal_entry_fits_the_doorbell_subkey() {
        let k = knock(&"x".repeat(DM_BODY_CAP), EPOCH);
        let mut decoded = wire::FirstContactEntry::decode(&k.entry[..]).unwrap();
        decoded.pow = vec![0u8; POW_RESERVE];
        let with_pow = decoded.encode_to_vec().len();
        // The token now rides INSIDE the seal, so its cost is already inside the
        // padded bucket rather than added on top. Reserve it explicitly anyway, so
        // the admission slice cannot silently spend headroom that is not there.
        let maximal = with_pow + ml_dsa::SIG_LEN;
        assert!(
            maximal <= MAX_ENTRY_LEN,
            "a maximal entry is {maximal} bytes, over the {MAX_ENTRY_LEN}-byte subkey cap"
        );
    }

    /// A body past the cap is refused locally at compose time, not discovered when
    /// the network rejects the write.
    #[test]
    fn an_oversized_body_is_refused_at_compose_time() {
        let a = alice();
        let b = bob();
        let pc = pseudonym();
        assert!(matches!(
            build(
                &a.signing,
                &pc.signing,
                b.signing.public_key(),
                b.kem.encapsulation_key(),
                EPOCH,
                SENT,
                &"x".repeat(DM_BODY_CAP + 1),
            ),
            Err(FirstContactError::TooLarge { .. })
        ));
    }

    // ── Interop contract ────────────────────────────────────────────────────

    /// Known-answer vectors for every deterministic derivation and preimage.
    ///
    /// Structural tests cannot see a uniformly-wrong preimage: swapping
    /// big-endian for little, dropping a length prefix, or reordering two fields
    /// keeps every round-trip green while making this implementation incompatible
    /// with any other. `msg_sig_input` and `seal_aad` are the two that matter most
    /// — the design elevates the `/v6` preimage to an interop contract — and both
    /// are self-consistent between `build` and `open`, so nothing else here would
    /// notice.
    ///
    /// The `seq` and timestamp below have distinct bytes in every position, so an
    /// endianness flip cannot survive. Captured from this implementation once
    /// reviewed; they guard drift, not first correctness.
    #[test]
    fn deterministic_derivations_match_their_known_answer_vectors() {
        let a = alice();
        let b = bob();

        let bind = sha384(&bind_lt_input(
            a.signing.public_key(),
            b.signing.public_key(),
        ))
        .unwrap();
        assert_eq!(
            hex::encode(bind),
            concat!(
                "6fd3fbefba0532b7c1db358d689af770894cecb35abbdd7a99458be3",
                "33bb94161b0fe2ae65d4c9ab2a133bbf366d9d4d"
            )
        );

        let roots = derive_channel_roots(&[7u8; SS0_LEN]).unwrap();
        assert_eq!(
            hex::encode(roots.ar),
            "ac73f35ba0c469f8e3cee6708294ab9ac48bfbacea82b7393ec174287beb53ac"
        );
        assert_eq!(
            hex::encode(roots.chan_id),
            "c1724ec000d212dedaa8769ce618a9da5be6c3f30c3618b1f97381e8ebc20232"
        );
        assert_eq!(
            hex::encode(recipient_hash(b.signing.public_key()).unwrap()),
            concat!(
                "f37f0ccace79333569611a476c76425ee7c9dba823ca46b57cb08a8b",
                "ad7ee0f16f09b779f5c286a80ae117968f35f2ab"
            )
        );

        let (eph_ek, _) = ml_kem::keygen(&[5u8; 32], &[6u8; 32]).unwrap();
        let preimage = sha384(&msg_sig_input(
            FRAME_KIND_FIRST_CONTACT,
            &[1u8; ROOT_LEN],
            DIR_A2B,
            0x0102_0304_0506_0708,
            &eph_ek,
            &[2u8; RECIPIENT_HASH_LEN],
            a.signing.public_key(),
            b.signing.public_key(),
            0x0a0b_0c0d_0e0f_1011,
            "ab",
        ))
        .unwrap();
        assert_eq!(
            hex::encode(preimage),
            concat!(
                "8ca78b74a9f72f4db167378a3063bf753d755387151aaa695619441b",
                "e288cbf647f2187cce9f69e10bf89398df4581fe"
            )
        );

        let addr = keyrec::derive_owner_seed(b.signing.public_key()).unwrap();
        let aad = sha384(&seal_aad(addr.as_bytes(), EPOCH)).unwrap();
        assert_eq!(
            hex::encode(aad),
            concat!(
                "221b591c8dcfb1a69ce05ca3c937b0caf1d7ce8179b25cb6e30b3a4a",
                "8e0c135d8710c62ad70e25c9d0eb7c06cbe0f9e5"
            )
        );
    }

    /// The preimages must be unambiguous: no two distinct field tuples may produce
    /// the same signed bytes. Length prefixes are what guarantee it, and this
    /// notices if one is dropped.
    #[test]
    fn signing_preimages_are_unambiguous_across_fields() {
        let a = alice();
        let b = bob();
        assert_ne!(
            bind_lt_input(a.signing.public_key(), b.signing.public_key()),
            bind_lt_input(b.signing.public_key(), a.signing.public_key()),
            "the binding must not be symmetric in its two keys"
        );

        let (eph_ek, _) = ml_kem::keygen(&[5u8; 32], &[6u8; 32]).unwrap();
        let rcpt = recipient_hash(b.signing.public_key()).unwrap();
        let sig = |kind: &[u8], chan: [u8; ROOT_LEN], dir: &[u8], seq, body| {
            msg_sig_input(
                kind,
                &chan,
                dir,
                seq,
                &eph_ek,
                &rcpt,
                b.signing.public_key(),
                a.signing.public_key(),
                5,
                body,
            )
        };
        let base = sig(FRAME_KIND_FIRST_CONTACT, [1u8; ROOT_LEN], DIR_A2B, 0, "ab");
        assert_ne!(
            base,
            sig(FRAME_KIND_FIRST_CONTACT, [1u8; ROOT_LEN], DIR_A2B, 1, "ab"),
            "seq must be bound"
        );
        assert_ne!(
            base,
            sig(FRAME_KIND_FIRST_CONTACT, [1u8; ROOT_LEN], DIR_A2B, 0, "abc"),
            "the body must be bound"
        );
        assert_ne!(
            base,
            sig(FRAME_KIND_FIRST_CONTACT, [2u8; ROOT_LEN], DIR_A2B, 0, "ab"),
            "chan_id must be bound"
        );
        assert_ne!(
            base,
            sig(
                FRAME_KIND_FIRST_CONTACT,
                [1u8; ROOT_LEN],
                ratchet::Direction::BToA.label(),
                0,
                "ab",
            ),
            "the direction must be bound"
        );
        assert_ne!(
            base,
            sig(b"ch", [1u8; ROOT_LEN], DIR_A2B, 0, "ab"),
            "the frame kind must be bound, or a first-contact signature is a \
             byte-valid channel-frame signature"
        );
    }
}
