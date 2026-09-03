//! What a client keeps about a correspondent between conversations (ISC-C44).
//!
//! [`crate::dm::provisional`] is the sender's half of § v4 4.1 and says where
//! the other half lives: the recipient's `PK_pc_A` — the peer pseudonym it must
//! verify frames against — "is not here and is not recomputable from `ss0`; its
//! home is the ISC-C44 contact cache, which holds 'long-term + pseudonym
//! pubkeys' per contact". This module is that home.
//!
//! ## What the record stores
//!
//! Five fields and no sixth:
//!
//! | Field | Shape | Why it cannot be recomputed |
//! |---|---|---|
//! | `pk_lt` | the contact's long-term identity key | a public key the peer chose; nothing derives it |
//! | `pk_pc` | the contact's per-contact pseudonym key | likewise, and it is what authorship is checked against |
//! | `AR` | the correspondence's address root | derived from an `ss0` this record must not keep |
//! | `first_seen_ms` | `i64` milliseconds | an observation, not a derivation |
//! | `last_seen_ms` | `i64` milliseconds | likewise |
//!
//! **`ss0` is NOT among them, and that is the design of record rather than a
//! preference.** § D-PFS (`docs/design/direct-messaging.md:319`) seeds both the
//! address chain and the deletable seal-key chain from the initial `ss0` and
//! then says only `AR` is retained; line 706 names this record's earlier `ss0`
//! retention as the error outright — *"the design is not open on that point, and
//! retaining `ss0` is not a live option — it regenerates `RK0` and with it every
//! message key the ratchet believes it deleted"* — and line 710's retained set
//! ends *"Deleted: `ss0`, `chan_id`, and all ratchet state."* A record holding
//! `ss0` for the life of a correspondence is a permanent copy of the one value
//! that reconstructs every deleted message key, which is the whole of what
//! content forward secrecy here rests on.
//!
//! **So the record stores the derived root and never its input.** `AR` is what
//! both of this type's readers actually want —
//! [`ContactRecord::address_root`] returns it and
//! [`ContactRecord::addresses_same_channel`] compares against it — so the
//! substitution costs nothing at the call sites and removes the retention. It
//! also removes an internal-consistency question rather than creating one: with
//! `ss0` gone there is no second stored fact for the root to disagree with, and
//! [`derive_channel_roots`] runs once at the caller, before the record exists.
//!
//! **`ss0` is still what a caller holds when it builds one.** The caller derives
//! the root, hands it over, and lets its own `ss0` destroy itself; the record
//! never sees it. That is the same discipline
//! [`crate::dm::provisional::ProvisionalRecord`] applies at the other end of the
//! handshake, where `ss0` genuinely must be kept until establishment and is then
//! erased.
//!
//! `chan_id` is deliberately not exposed beside it: § v4's minor invariant says
//! it must never be serialized anywhere, and handing it out alongside a record's
//! other outputs invites a caller to persist it with them. A caller that
//! genuinely needs it reaches [`derive_channel_roots`] directly and keeps it in
//! memory.
//!
//! ## The record is encoded here and sealed by the store
//!
//! [`ContactRecord::encode`] produces a fixed-length plaintext and nothing more;
//! [`crate::storage::dm_store`] is what seals it. **That is the whole difference
//! from [`crate::dm::provisional`], and it follows from where each record can
//! travel.** `ProvisionalRecord::seal` returns sealed bytes because a
//! provisional record has a life outside the store. A contact record has none —
//! ISC-A-C25 states that the contact cache never leaves the at-rest blob and
//! that no wire message carries any portion of it — so a record that only ever
//! exists inside the store is already sealed by the store, under
//! `derive_store_key` over the profile's at-rest material with the
//! correspondence label *and* the record kind bound as AAD. A second seal here
//! would derive a second key from the same at-rest root and bind a second
//! spelling of the same per-correspondence fact, at the cost of freezing three
//! more protocol labels. ISC-C44 asks for "encrypted at rest under the
//! passphrase that protects mute/hide", and the store's seal is that.
//!
//! **What deferring costs, stated exactly.** A record encoded today is the
//! plaintext a sealed record would carry, so the layer can be added later — but
//! adding it changes the encoded length, hence this kind's bucket, hence every
//! file already on disk. That is free *only because no contact record has ever
//! been written*, which is a much weaker claim than "no migration needed" and
//! stops being true the day one ships. The same applies to any other
//! length-changing edit; see [`CONTACT_RECORD_VERSION`].
//!
//! ## At rest
//!
//! `version ‖ pk_lt ‖ pk_pc ‖ AR ‖ first_seen ‖ last_seen` —
//! [`CONTACT_RECORD_LEN`] bytes for every record. Every field is fixed-width, so
//! there are no interior length prefixes able to disagree with what they
//! describe, and once the store has sealed and padded it a directory of these
//! leaks neither how much is known about a contact nor how long they have been
//! known.
//!
//! **A truncation is still diagnosed here.** [`ContactRecord::decode`] checks the
//! length before it parses, so a short or padded payload reports
//! [`ContactCacheError::WrongLength`] naming both numbers rather than being read
//! as a field that happens to land wrong. The store's AEAD speaks to bytes that
//! were tampered with; this speaks to bytes that are the wrong shape.

use oxicrypt_ml_dsa as ml_dsa;
use zeroize::{Zeroize, Zeroizing};

use crate::dm::firstcontact::ROOT_LEN;

/// Format version of a [`ContactRecord`]'s encoding.
///
/// Read *after* the length check, so a **same-length** shape change reports
/// [`ContactCacheError::UnsupportedVersion`] naming the version it found instead
/// of mis-parsing an old record as a new one. That is the whole of what this
/// byte buys, and the limit is worth stating: [`CONTACT_RECORD_LEN`] is the
/// store's `capacity()` for this kind with zero headroom, so a v2 of any other
/// length changes `on_disk_len()` and the store refuses every existing file as
/// `WrongFileLen` before [`ContactRecord::decode`] is ever reached. A
/// length-changing version is a format break, not a version negotiation.
///
/// ⚠️ **It stayed at `1` across the `ss0` → `AR` change, which is exactly the
/// same-length reinterpretation this byte exists to catch.** The bytes at
/// `1 + 2·PK_LEN ..+ ROOT_LEN` mean something different than they did, at the
/// same length, so a v1 record written by an older build would be read as a
/// current one with the wrong value in the field that decides addressing. Not
/// bumping is licensed by the module docs' condition above and nothing weaker:
/// **no contact record has ever been written** — the type does not exist in the
/// newest signed tag. That is the escape hatch being invoked deliberately, not
/// an oversight, and it expires the day one ships.
pub const CONTACT_RECORD_VERSION: u8 = 1;

/// Bytes in each of the two timestamps: an `i64` of milliseconds, big-endian.
const TIMESTAMP_LEN: usize = 8;

/// Encoded length: the version byte, both public keys, `AR`, and the two
/// timestamps. Fixed — every field is fixed-width.
///
/// One number for every record, which is what lets the store give this kind a
/// fixed-size bucket:
/// [`RecordKind::ContactCache`](crate::storage::dm_store::RecordKind::ContactCache)
/// takes it verbatim as its capacity.
///
/// **The number was unchanged by the move from `ss0` to `AR`**, because the
/// two lengths happened to be equal — 32 each — so the store's bucket for this
/// kind did not move and no file already on disk was invalidated. That was a
/// coincidence of two independent constants and is recorded here as history,
/// not relied on: only [`ROOT_LEN`] participates in this length now, and if it
/// moves, the bucket moves with it and — per
/// [`CONTACT_RECORD_VERSION`]'s docs — that is a format break rather than a
/// version negotiation.
pub const CONTACT_RECORD_LEN: usize = 1 + 2 * ml_dsa::PK_LEN + ROOT_LEN + 2 * TIMESTAMP_LEN;

/// Why a contact record could not be built or read back.
#[derive(Debug, PartialEq, Eq)]
pub enum ContactCacheError {
    /// The payload is not [`CONTACT_RECORD_LEN`] bytes. Checked before the parse
    /// so a truncation is diagnosable, rather than surfacing as a field that
    /// happens to land in the wrong place.
    WrongLength { expected: usize, actual: usize },
    /// The payload names a format version this build does not read.
    UnsupportedVersion { found: u8, expected: u8 },
    /// The record claims it was last seen before it was first seen.
    ///
    /// Refused at **construction** as well as at [`ContactRecord::decode`], so
    /// an inconsistent record is unconstructible rather than something a
    /// validator has to catch — [`crate::dm::provisional`]'s principle. The
    /// decode-side check is still needed, because bytes that did not come from
    /// [`ContactRecord::new`] have made no such promise.
    TimestampsOutOfOrder {
        first_seen_ms: i64,
        last_seen_ms: i64,
    },
    /// `AR` is all zeroes, which no key derivation produces.
    ///
    /// **Refused because the stored root decides more than addressing.**
    /// [`ContactRecord::addresses_same_channel`] reads it to tell a
    /// correspondent's lost at-rest state from an introduction re-seeded (#261),
    /// so a placeholder record holds a root no correspondent can ever present:
    /// every knock from that identity reads as state loss and irreversibly ends
    /// its queue.
    ///
    /// **This refuses the placeholder, not every wrong root**, and the
    /// distinction is honest: a record cannot check that its `AR` is the one the
    /// correspondent's `ss0` derives, because nothing at rest witnesses that.
    /// All zeroes is the pattern a caller reaches for when it means *not filled
    /// in yet*, and this type has no such state — the same argument as
    /// [`Self::TimestampsOutOfOrder`], which refuses a self-contradicting record
    /// at construction rather than leaving it for a validator.
    PlaceholderAddressRoot,
}

impl std::fmt::Display for ContactCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => write!(
                f,
                "a contact record is {expected} bytes, this one is {actual}"
            ),
            Self::UnsupportedVersion { found, expected } => write!(
                f,
                "the contact record is version {found}, this build reads {expected}"
            ),
            Self::TimestampsOutOfOrder {
                first_seen_ms,
                last_seen_ms,
            } => write!(
                f,
                "the contact was last seen at {last_seen_ms}, before it was first \
                 seen at {first_seen_ms}"
            ),
            Self::PlaceholderAddressRoot => f.write_str(
                "the contact record's address root is all zeroes, which is a placeholder \
                 rather than a key derivation's output",
            ),
        }
    }
}

impl std::error::Error for ContactCacheError {}

/// What is known about one correspondent, as it is held in memory and written to
/// rest.
///
/// One type serves both, so there is no second shape to translate between and no
/// moment where a second copy of the root exists.
///
/// **`Box` for the public keys, [`Zeroizing`] for the root** —
/// [`crate::dm::provisional::ProvisionalRecord`]'s split, and it is a split
/// rather than one uniform choice. The public keys are large and not secret, so
/// they are boxed to keep them off the stack; `AR` is small and is key-bearing
/// material, so it destroys itself wherever the value ends up owned. It is not
/// `ss0` and buys no content: § D-PFS states plainly that address-linkability is
/// not forward-secret, so what a disclosed `AR` costs is the channel's address
/// graph, past and future — metadata, and enough to be worth erasing.
///
/// **No `Drop` of its own**, deliberately: a container `Drop` forbids moving
/// fields *out*, which is what forces a caller to copy a secret back out and
/// manufacture a second live copy of it. Every field here destroys itself or has
/// nothing to destroy.
///
/// Not [`Clone`], for the same reason: a second copy of a correspondence's
/// address root has no use that [`Self::encode`] taking `&self` does not serve.
///
/// **The fields are private and the timestamps are ordered by construction.**
/// [`Self::new`] and [`Self::decode`] are the only two doors, both refuse
/// `last_seen_ms < first_seen_ms`, and [`Self::observed_at`] cannot move a
/// sighting behind the first one — so a record that contradicts itself about
/// when it was known does not exist to be validated.
pub struct ContactRecord {
    pk_lt: Box<[u8; ml_dsa::PK_LEN]>,
    pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
    ar: Zeroizing<[u8; ROOT_LEN]>,
    first_seen_ms: i64,
    last_seen_ms: i64,
}

impl std::fmt::Debug for ContactRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContactRecord(<redacted>)")
    }
}

impl ContactRecord {
    /// What is known about a correspondent as of `first_seen_ms`.
    ///
    /// Refuses `last_seen_ms < first_seen_ms`: the two are one fact about a span
    /// of time, and a span that ends before it starts is not a record to be
    /// checked later but a record that must not be built. Refuses an all-zero
    /// `ar` for the same reason — see
    /// [`ContactCacheError::PlaceholderAddressRoot`].
    ///
    /// **Takes `AR`, never `ss0`.** The caller derives the root with
    /// [`derive_channel_roots`] and keeps `ss0` to itself; this type must not
    /// retain it (§ D-PFS, and the module docs above). A constructor taking
    /// `ss0` and deriving internally would read as tidier and would put the one
    /// value that reconstructs every deleted message key into the frame of every
    /// caller that only wanted to note a contact.
    ///
    /// `ar` arrives already wrapped so it can be *moved* in. Taking a bare
    /// `[u8; ROOT_LEN]` would copy it at the call site and leave that copy live
    /// in the caller's frame, which is the hazard the wrapper exists to close.
    pub fn new(
        pk_lt: Box<[u8; ml_dsa::PK_LEN]>,
        pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
        ar: Zeroizing<[u8; ROOT_LEN]>,
        first_seen_ms: i64,
        last_seen_ms: i64,
    ) -> Result<Self, ContactCacheError> {
        if last_seen_ms < first_seen_ms {
            return Err(ContactCacheError::TimestampsOutOfOrder {
                first_seen_ms,
                last_seen_ms,
            });
        }
        // Not a constant-time comparison: the pattern being refused is the one
        // value that is not key material at all.
        if ar.iter().all(|b| *b == 0) {
            return Err(ContactCacheError::PlaceholderAddressRoot);
        }
        Ok(Self {
            pk_lt,
            pk_pc,
            ar,
            first_seen_ms,
            last_seen_ms,
        })
    }

    /// The contact's long-term identity key.
    pub fn pk_lt(&self) -> &[u8; ml_dsa::PK_LEN] {
        &self.pk_lt
    }

    /// The contact's per-contact pseudonym key — what a frame's authorship
    /// signature is verified against.
    pub fn pk_pc(&self) -> &[u8; ml_dsa::PK_LEN] {
        &self.pk_pc
    }

    /// When this correspondence was first observed, in milliseconds.
    pub fn first_seen_ms(&self) -> i64 {
        self.first_seen_ms
    }

    /// When this correspondence was last observed, in milliseconds.
    pub fn last_seen_ms(&self) -> i64 {
        self.last_seen_ms
    }

    /// Note an observation at `at_ms`, returning whether it was recorded.
    ///
    /// Only [`Self::last_seen_ms`] moves; the first sighting is a fact about the
    /// past and does not change.
    ///
    /// **Monotonic: anything earlier than the last recorded sighting is
    /// refused.** Guarding only against times before [`Self::first_seen_ms`]
    /// would leave the *interesting* rewind legal — a sighting between the first
    /// and the last would move `last_seen_ms` backwards and report success, so a
    /// caller that dutifully checked the refusal would be told the sighting was
    /// recorded while the record had quietly come to understate when the contact
    /// was last seen. Anything keying eviction or staleness on `last_seen_ms`
    /// then discards a live contact. Refusing everything below `last_seen_ms`
    /// also subsumes the `first_seen_ms` guard, because the two are ordered by
    /// construction.
    ///
    /// **What the bool means: the record now reflects a sighting at `at_ms`.**
    /// Not "the stamp moved" — re-recording the same instant is accepted and
    /// changes nothing, which is idempotent rather than a failure. That is
    /// deliberately weaker than
    /// [`crate::dm::provisional::ReceiveCursor::advance_to`], whose bool does
    /// mean *moved* because a no-op advance there is a cursor that failed to
    /// make progress. It is `#[must_use]` for that type's reason all the same:
    /// an ignored refusal is an observation the caller believes it recorded and
    /// did not.
    #[must_use = "an ignored refusal is a sighting that was silently not recorded"]
    pub fn observed_at(&mut self, at_ms: i64) -> bool {
        if at_ms < self.last_seen_ms {
            return false;
        }
        self.last_seen_ms = at_ms;
        true
    }

    /// The channel's address root `AR`.
    ///
    /// **Read straight back from the record**, because it is the one thing this
    /// record stores about the channel — see the module docs. It was derived
    /// once, by the caller that built the record, from an `ss0` neither of them
    /// keeps.
    ///
    /// **Infallible, where the `ss0`-deriving version was not.** There is no
    /// derivation left to fail, so callers no longer carry a
    /// [`FirstContactError`](crate::dm::firstcontact::FirstContactError) arm for
    /// a case that could not arise.
    ///
    /// **`chan_id` is not available here at all**, which is stronger than the
    /// deliberate omission it replaces. It must never be serialized anywhere
    /// (§ v4 minor invariant), and a record without `ss0` cannot derive it: a
    /// caller that genuinely needs it reaches [`derive_channel_roots`] with the
    /// secret it holds, and keeps the result in memory only.
    pub fn address_root(&self) -> [u8; ROOT_LEN] {
        *self.ar
    }

    /// Whether `ar` addresses the channel this record already holds (#261).
    ///
    /// **The fact that separates a correspondent's lost state from their
    /// restart, and it is the only one at rest that can.** `AR` descends from
    /// `ss0`, `ss0` is encapsulated afresh for every first-contact entry, and
    /// this record is written from the entry that opened the correspondence. So
    /// an entry arriving under the recorded root is the *same* introduction —
    /// the sender re-seeding it on the schedule, which the design requires them
    /// to do until they see evidence of establishment, and which therefore keeps
    /// arriving for up to seven days after a first contact that worked
    /// perfectly. An entry under a different root is a *new* `ss0`, which a
    /// correspondent who still held their at-rest state would never mint:
    /// re-establishment after a restart is an ordinary frame on the channel
    /// plane, addressed under the `AR` they still have.
    ///
    /// A restart therefore cannot reach the false branch, and a re-seed cannot
    /// either — which is the whole reason this compares roots rather than merely
    /// noticing that a known identity knocked.
    ///
    /// **Not a constant-time comparison, and it does not need to be.** `ar` is
    /// derived from an `ss0` its sender chose and already knows, so the only
    /// party who can drive this comparison learns nothing from its timing that
    /// the return value does not state outright. `ss0` itself is never compared.
    ///
    /// # The invariant this assumes, which nothing enforces
    ///
    /// **One at-rest store per `pk_lt`.** A second device belonging to the same
    /// correspondent would knock with a fresh `ss0` while the first device's
    /// channel is perfectly alive: `pk_lt` is mnemonic-derived and identical
    /// across a user's devices, while the doorbell slot secret is deliberately
    /// *not* multi-device-consistent (`docs/design/direct-messaging.md`, the
    /// 2026-07-28 note on the identity-scoped slot label). A caller acting on
    /// this predicate would then mark pending frames the first device can still
    /// collect as undelivered — irreversibly, since that transition is terminal.
    ///
    /// **Not a defect today: M11 records that the recovery-phrase model recovers
    /// identity but not DM reachability**, so a second device has no live
    /// channel to contradict. It becomes one the day multi-device lands, and the
    /// fix is a design question rather than a predicate change — this comparison
    /// has no way to tell a second device from a restored one, because at rest
    /// there is nothing that distinguishes them. **Multi-device support must
    /// revisit this before it ships.**
    pub fn addresses_same_channel(&self, ar: &[u8; ROOT_LEN]) -> bool {
        self.address_root() == *ar
    }

    /// The at-rest form, for [`crate::storage::dm_store`] to seal.
    ///
    /// Returned in a [`Zeroizing`] buffer because it carries `AR` in the clear:
    /// the caller hands it straight to the store's seal, and the copy that
    /// outlives that call is the ciphertext.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(CONTACT_RECORD_LEN));
        out.push(CONTACT_RECORD_VERSION);
        out.extend_from_slice(self.pk_lt.as_slice());
        out.extend_from_slice(self.pk_pc.as_slice());
        out.extend_from_slice(self.ar.as_slice());
        out.extend_from_slice(&self.first_seen_ms.to_be_bytes());
        out.extend_from_slice(&self.last_seen_ms.to_be_bytes());
        debug_assert_eq!(out.len(), CONTACT_RECORD_LEN);
        out
    }

    /// Read the at-rest form back.
    ///
    /// Three checks, and deliberately no more:
    ///
    /// 1. **The length**, before the parse, so a truncated or padded payload is
    ///    named as such instead of surfacing as a field that landed wrong.
    /// 2. **The version byte**, so a future shape change fails by name.
    /// 3. **The timestamp order**, because these bytes did not come from
    ///    [`Self::new`] and have made none of its promises.
    ///
    /// Authenticity is **not** among them and is not missing: the store opens
    /// the AEAD before this ever sees a byte, under a key derived from the
    /// profile's at-rest material with the correspondence label and the record
    /// kind bound as AAD. A payload from another correspondence, another kind or
    /// another profile never reaches here.
    ///
    /// There is **no `AR` cross-check**, and its absence is the design rather
    /// than a gap: `AR` is the only channel fact stored, so there is no second
    /// value for it to disagree with. Designing an inconsistency class out is
    /// strictly better than detecting it.
    ///
    /// **Takes a [`Zeroizing`] buffer, and that is the signature doing work
    /// rather than ceremony.** [`Self::new`] takes `AR` already wrapped so a
    /// caller cannot leave a bare copy live in its frame; a `decode` over a bare
    /// `&[u8]` would reopen exactly that hole at the other end, because this
    /// kind's store payload carries key-bearing material. Every other
    /// [`RecordKind`](crate::storage::dm_store::RecordKind) hands
    /// the store pre-sealed or non-secret bytes, so this is the first at-rest
    /// cleartext key-material buffer in the tree, and
    /// [`crate::storage::dm_store::Locked::read`] returns a plain `Vec<u8>` that
    /// nothing would otherwise own. `crate::dm::resume` solves this by wrapping
    /// at each call site — a convention that holds only while every caller
    /// remembers it. Requiring the wrapper here makes forgetting it a compile
    /// error instead.
    pub fn decode(bytes: &Zeroizing<Vec<u8>>) -> Result<Self, ContactCacheError> {
        if bytes.len() != CONTACT_RECORD_LEN {
            return Err(ContactCacheError::WrongLength {
                expected: CONTACT_RECORD_LEN,
                actual: bytes.len(),
            });
        }

        let found = bytes[0];
        if found != CONTACT_RECORD_VERSION {
            return Err(ContactCacheError::UnsupportedVersion {
                found,
                expected: CONTACT_RECORD_VERSION,
            });
        }

        let mut at = 1;
        let pk_lt = boxed_from_slice::<{ ml_dsa::PK_LEN }>(&bytes[at..at + ml_dsa::PK_LEN]);
        at += ml_dsa::PK_LEN;
        let pk_pc = boxed_from_slice::<{ ml_dsa::PK_LEN }>(&bytes[at..at + ml_dsa::PK_LEN]);
        at += ml_dsa::PK_LEN;
        let mut ar = [0u8; ROOT_LEN];
        ar.copy_from_slice(&bytes[at..at + ROOT_LEN]);
        at += ROOT_LEN;
        let first_seen_ms = i64_from_slice(&bytes[at..at + TIMESTAMP_LEN]);
        at += TIMESTAMP_LEN;
        let last_seen_ms = i64_from_slice(&bytes[at..at + TIMESTAMP_LEN]);
        debug_assert_eq!(at + TIMESTAMP_LEN, CONTACT_RECORD_LEN);

        // The wrapper takes a copy of the bare array, which is `Copy` with no
        // `Drop` — so the wrapper's copy is the only one anything protects and
        // this one would otherwise stay live in the frame (#135). Cleared on
        // both paths, including the timestamp refusal below.
        let record = Self::new(
            pk_lt,
            pk_pc,
            Zeroizing::new(ar),
            first_seen_ms,
            last_seen_ms,
        );
        ar.zeroize();
        record
    }
}

/// Copy `n` bytes straight into a heap allocation, with no stack-sized
/// temporary.
///
/// `Box::new(*array)` materialises the array as a value in the caller's frame on
/// the way to the allocation and leaves it there. A zeroed `Vec` is allocated on
/// the heap and written in place. [`crate::dm::provisional`]'s helper, verbatim,
/// because the hazard is the same one.
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

/// Read a big-endian `i64` out of an exactly-[`TIMESTAMP_LEN`] slice.
fn i64_from_slice(bytes: &[u8]) -> i64 {
    let mut buf = [0u8; TIMESTAMP_LEN];
    buf.copy_from_slice(bytes);
    i64::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::firstcontact::{SS0_LEN, derive_channel_roots};

    const FIRST_SEEN: i64 = 1_700_000_000_000;
    const LAST_SEEN: i64 = 1_700_000_123_456;

    /// Byte-distinct so an encoding that transposed or mis-sliced its fields
    /// would not pass by coincidence — and `pk_lt` and `pk_pc` differ from each
    /// other, so an `encode` that wrote one key twice is caught.
    fn pk(tag: u8) -> Box<[u8; ml_dsa::PK_LEN]> {
        let mut out = vec![0u8; ml_dsa::PK_LEN].into_boxed_slice();
        for (i, b) in out.iter_mut().enumerate() {
            *b = tag.wrapping_add((i as u8).wrapping_mul(3));
        }
        out.try_into().unwrap()
    }

    fn ss0() -> [u8; SS0_LEN] {
        let mut out = [0u8; SS0_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = 0x10u8.wrapping_add(i as u8 * 7);
        }
        out
    }

    /// The fixture's address root, derived the way a caller derives it.
    ///
    /// **It initialises the crypto module**, because [`derive_channel_roots`]
    /// runs a real derivation and the module is process-global. Without this the
    /// module's tests pass only when some *other* test happened to initialise it
    /// first — green under the whole suite, failing when run alone, which is the
    /// worst way for a test to be wrong.
    ///
    /// Derived rather than a literal so the tests below can also assert what is
    /// **not** in the record: the `ss0` it came from is a real input to a real
    /// derivation, so a record that had kept it would be found.
    fn ar() -> [u8; ROOT_LEN] {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        derive_channel_roots(&ss0()).expect("derives").ar
    }

    /// A second correspondence's root: a different `ss0`, which is the only way
    /// a different root arises.
    fn other_ar() -> [u8; ROOT_LEN] {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let mut other = ss0();
        other[0] ^= 0xAA;
        derive_channel_roots(&other).expect("derives").ar
    }

    /// The shared fixture.
    fn record() -> ContactRecord {
        ContactRecord::new(
            pk(0x01),
            pk(0x80),
            Zeroizing::new(ar()),
            FIRST_SEEN,
            LAST_SEEN,
        )
        .expect("ordered timestamps")
    }

    // ---- the record round-trips ---------------------------------------------

    /// The oracle for the record: every stored field comes back, and comes back
    /// through the encoded form rather than around it.
    #[test]
    fn a_contact_record_round_trips() {
        let encoded = record().encode();
        assert_eq!(encoded.len(), CONTACT_RECORD_LEN, "the size is fixed");

        let reopened = ContactRecord::decode(&encoded).expect("decodes");

        // Control on the fixture: the two keys are distinct, so an `encode` that
        // wrote one of them twice cannot pass the two assertions below.
        assert_ne!(
            pk(0x01),
            pk(0x80),
            "the fixture's two keys are the same key"
        );
        assert_eq!(reopened.pk_lt(), pk(0x01).as_ref());
        assert_eq!(reopened.pk_pc(), pk(0x80).as_ref());

        // Likewise: distinct stamps, so a decode that read one field twice fails.
        assert_ne!(
            FIRST_SEEN, LAST_SEEN,
            "the two timestamps are the same value"
        );
        assert_eq!(reopened.first_seen_ms(), FIRST_SEEN);
        assert_eq!(reopened.last_seen_ms(), LAST_SEEN);

        // The address root came back byte-identical, which is the whole of what
        // this record now stores about the channel.
        assert_eq!(record().address_root(), reopened.address_root());
        assert_eq!(reopened.address_root(), ar());
    }

    /// **The oracle for "stored, not derived".** The accessor returns exactly
    /// the root the caller handed over, so a record that had gone back to
    /// deriving one — or that read the wrong field — would disagree here.
    #[test]
    fn the_address_root_is_the_root_the_caller_stored() {
        assert_ne!(ar(), [0u8; ROOT_LEN], "a real AR is not all-zero");
        assert_eq!(record().address_root(), ar());

        // And it tracks what it was given rather than being a constant.
        let other = ContactRecord::new(
            pk(0x01),
            pk(0x80),
            Zeroizing::new(other_ar()),
            FIRST_SEEN,
            LAST_SEEN,
        )
        .unwrap();
        assert_ne!(other.address_root(), ar());
        assert_eq!(other.address_root(), other_ar());
    }

    /// **The at-rest layout of `AR`, plus two regression guards that cannot
    /// currently fail. Which is which is stated, because it decides what may be
    /// deleted later.**
    ///
    /// **Live, and the only assertion pinning where `AR` sits in the encoding:**
    /// the root appears in the record's bytes at its declared offset. A mutation
    /// that writes the field reversed and reads it back reversed survives both
    /// the round-trip test and the accessor test and is killed only here.
    ///
    /// **Regression guards, not oracles:** the `ss0` and `chan_id` scans cannot
    /// fail while [`ContactRecord`] has no field either could come from — no
    /// production mutation makes them fire. They exist to fail loudly if the
    /// struct ever regains an `ss0` field, which is what design line 706 forbids
    /// ("retaining `ss0` is not a live option — it regenerates `RK0` and with it
    /// every message key the ratchet believes it deleted") and line 710's
    /// retained set names among what is deleted. Do not read them as evidence
    /// that anything was checked today.
    ///
    /// **The production guard for the same property is elsewhere**, in
    /// `dm::persist`'s `accepting_a_knock_establishes_a_findable_correspondence`:
    /// storing `ss0` in place of the derived root compiles, because both are 32
    /// bytes, and that test is what kills it.
    #[test]
    fn the_address_root_is_at_its_at_rest_offset_and_neither_ss0_nor_chan_id_is() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let encoded = record().encode();
        let roots = derive_channel_roots(&ss0()).unwrap();

        assert_eq!(encoded.len(), CONTACT_RECORD_LEN);

        // The layout claim, at the offset the module docs declare:
        // `version ‖ pk_lt ‖ pk_pc ‖ AR ‖ first_seen ‖ last_seen`.
        let at = 1 + 2 * ml_dsa::PK_LEN;
        assert_eq!(
            &encoded[at..at + ROOT_LEN],
            roots.ar.as_slice(),
            "the address root is not at its at-rest offset"
        );

        assert!(
            !encoded.windows(SS0_LEN).any(|w| w == ss0()),
            "ss0 is in the record, against design lines 706 and 710"
        );
        assert!(
            !encoded
                .windows(roots.chan_id.len())
                .any(|w| w == roots.chan_id),
            "the channel id is in the record"
        );
    }

    /// Every record is one length whatever it holds, so the store can give this
    /// kind a fixed bucket and a directory of them leaks nothing.
    #[test]
    fn every_record_encodes_to_one_length() {
        let sparse = ContactRecord::new(
            Box::new([0u8; ml_dsa::PK_LEN]),
            Box::new([0u8; ml_dsa::PK_LEN]),
            Zeroizing::new([0x01u8; ROOT_LEN]),
            0,
            0,
        )
        .unwrap();
        assert_eq!(record().encode().len(), sparse.encode().len());
        assert_eq!(record().encode().len(), CONTACT_RECORD_LEN);
    }

    /// The record does not render its key material, the way every other
    /// key-bearing type here does not.
    #[test]
    fn a_record_does_not_render_its_secrets() {
        let rendered = format!("{:?}", record());
        assert!(!rendered.contains(&hex::encode(ar())));
        assert_eq!(rendered, "ContactRecord(<redacted>)");
    }

    // ---- the timestamps are one ordered fact --------------------------------

    /// **The oracle for the invariant.** An inconsistent record is
    /// unconstructible, not merely detectable — so the refusal is at the
    /// constructor, and `decode` re-checks because raw bytes made no promise.
    #[test]
    fn a_record_last_seen_before_it_was_first_seen_cannot_be_built() {
        // Positive control: the equal case is legal, which pins the check as
        // `<` and not `<=` — a contact seen exactly once has one instant.
        assert!(
            ContactRecord::new(
                pk(0x01),
                pk(0x80),
                Zeroizing::new(ar()),
                FIRST_SEEN,
                FIRST_SEEN,
            )
            .is_ok(),
            "a contact seen exactly once was refused"
        );

        assert_eq!(
            ContactRecord::new(
                pk(0x01),
                pk(0x80),
                Zeroizing::new(ar()),
                FIRST_SEEN,
                FIRST_SEEN - 1,
            )
            .unwrap_err(),
            ContactCacheError::TimestampsOutOfOrder {
                first_seen_ms: FIRST_SEEN,
                last_seen_ms: FIRST_SEEN - 1,
            }
        );
    }

    /// And on the way back in, from bytes the constructor never saw — which is
    /// the only way such a record can reach this build at all.
    #[test]
    fn a_decoded_record_with_inverted_timestamps_is_refused() {
        let mut bytes = record().encode();
        let last_at = CONTACT_RECORD_LEN - TIMESTAMP_LEN;
        bytes[last_at..].copy_from_slice(&(FIRST_SEEN - 1).to_be_bytes());

        assert_eq!(
            ContactRecord::decode(&bytes).unwrap_err(),
            ContactCacheError::TimestampsOutOfOrder {
                first_seen_ms: FIRST_SEEN,
                last_seen_ms: FIRST_SEEN - 1,
            },
            "hand-built bytes bypassed the constructor's invariant"
        );

        // Positive control: the same bytes with the stamp restored do decode, so
        // the refusal is the ordering and not the hand-editing.
        bytes[last_at..].copy_from_slice(&LAST_SEEN.to_be_bytes());
        assert!(ContactRecord::decode(&bytes).is_ok());
    }

    /// **The oracle for the monotonic clause.** The last sighting advances, the
    /// first never moves, and a refusal leaves both alone — a mutator can
    /// otherwise build exactly the state `new` and `decode` both refuse to
    /// produce.
    ///
    /// The middle case is the one that matters and the one a `first_seen`-only
    /// guard lets through: a sighting *between* the two stamps is not before the
    /// first sighting, so it passes that guard, rewinds `last_seen_ms` and
    /// returns `true`. Deleting `at_ms < self.last_seen_ms` from
    /// [`ContactRecord::observed_at`] fails this test at
    /// `an earlier sighting rewound last_seen`.
    #[test]
    fn observing_a_contact_moves_the_last_seen_stamp_forwards_only() {
        let mut r = record();
        assert_eq!(r.first_seen_ms(), FIRST_SEEN);

        // Positive control: a later sighting IS taken, so the refusals below are
        // the guard and not a mutator that stopped working.
        assert!(
            r.observed_at(LAST_SEEN + 1_000),
            "a later sighting was refused"
        );
        assert_eq!(r.last_seen_ms(), LAST_SEEN + 1_000);

        // The rewind a `first_seen`-only guard admits: after the fixture's own
        // `LAST_SEEN`, and so comfortably past `FIRST_SEEN`.
        // Settled at compile time, where it is actually decided: both sides are
        // `const`, so a runtime assertion here would be a probe that cannot fire
        // (`clippy::assertions_on_constants` says so).
        const { assert!(FIRST_SEEN < LAST_SEEN, "the fixture straddles no guard") };
        assert!(
            !r.observed_at(LAST_SEEN),
            "an earlier sighting rewound last_seen"
        );
        assert_eq!(
            r.last_seen_ms(),
            LAST_SEEN + 1_000,
            "a refused sighting must not move the stamp"
        );

        // And the case the old guard did catch, which must stay caught.
        assert!(
            !r.observed_at(FIRST_SEEN - 1),
            "a sighting before the first one was accepted"
        );
        assert_eq!(r.last_seen_ms(), LAST_SEEN + 1_000);

        // Re-recording the same instant is idempotent, not a failure: the bool
        // means the record reflects a sighting at `at_ms`, not that it moved.
        assert!(r.observed_at(LAST_SEEN + 1_000));
        assert_eq!(r.last_seen_ms(), LAST_SEEN + 1_000);

        // `first_seen` never moves, whatever happened above.
        assert_eq!(r.first_seen_ms(), FIRST_SEEN);
    }

    // ---- what a payload is refused for --------------------------------------

    /// A truncated payload is refused **by length**, not read as a field that
    /// landed wrong — the length is public, so reporting it precisely leaks
    /// nothing and saves a reader hunting for tampering that never happened.
    #[test]
    fn a_truncated_record_is_refused_by_length() {
        let encoded = record().encode();
        for len in [0, 1, CONTACT_RECORD_LEN - 1] {
            let short = Zeroizing::new(encoded[..len].to_vec());
            assert_eq!(
                ContactRecord::decode(&short).unwrap_err(),
                ContactCacheError::WrongLength {
                    expected: CONTACT_RECORD_LEN,
                    actual: len,
                },
                "a {len}-byte record was not refused by length"
            );
        }
    }

    /// And an over-long one, which a `<` pre-check would let fall through to a
    /// parse that silently ignored the tail.
    #[test]
    fn an_over_long_record_is_refused_by_length() {
        for extra in [1, TIMESTAMP_LEN, CONTACT_RECORD_LEN] {
            let mut padded = record().encode();
            padded.resize(CONTACT_RECORD_LEN + extra, 0);
            assert_eq!(
                ContactRecord::decode(&padded).unwrap_err(),
                ContactCacheError::WrongLength {
                    expected: CONTACT_RECORD_LEN,
                    actual: CONTACT_RECORD_LEN + extra,
                },
                "a record {extra} bytes too long was not refused by length"
            );
        }
    }

    /// A version this build does not read fails **by name**, so a future shape
    /// change cannot be mis-parsed as this one.
    #[test]
    fn a_record_with_a_wrong_version_byte_is_refused() {
        let mut bytes = record().encode();
        bytes[0] = CONTACT_RECORD_VERSION + 1;

        assert_eq!(
            ContactRecord::decode(&bytes).unwrap_err(),
            ContactCacheError::UnsupportedVersion {
                found: CONTACT_RECORD_VERSION + 1,
                expected: CONTACT_RECORD_VERSION,
            }
        );

        // Positive control: restored, the same bytes decode.
        bytes[0] = CONTACT_RECORD_VERSION;
        assert!(ContactRecord::decode(&bytes).is_ok());
    }

    /// **The predicate that separates a correspondent's lost state from their
    /// restart, checked in both directions.**
    ///
    /// The mirror control is what makes it a predicate rather than a constant: a
    /// body of `Ok(false)` fires on every re-seed and marks live messages
    /// undelivered, and a body of `Ok(true)` never fires at all — one of the two
    /// assertions below kills each.
    #[test]
    fn a_record_recognises_its_own_channel_and_no_other() {
        let r = record();
        let mine = r.address_root();
        assert!(
            r.addresses_same_channel(&mine),
            "a record did not recognise its own address root"
        );

        // A different `ss0`, which is the only way a different root arises, and
        // is what a correspondent who lost their at-rest state mints.
        let other = other_ar();
        assert_ne!(mine, other, "the fixture built two equal roots");
        assert!(
            !r.addresses_same_channel(&other),
            "a record claimed a channel it does not hold"
        );

        // The identity keys are equal across the two records the fixtures build,
        // so this reads the root and nothing else — a predicate comparing
        // `pk_lt` would pass both assertions above only by never firing on the
        // case #261 exists for.
    }

    /// **A placeholder `AR` is refused at both doors**, because a record
    /// carrying one holds a root no correspondent can present — so every knock
    /// from that identity would read as lost at-rest state and irreversibly end
    /// its queue (#261).
    ///
    /// The control is the neighbouring non-zero root: a refusal that fired on
    /// any low-entropy value, or on nothing at all, fails one of the two halves.
    #[test]
    fn a_placeholder_address_root_is_refused_at_both_doors() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let build = |root: [u8; ROOT_LEN]| {
            ContactRecord::new(pk(0x01), pk(0x80), Zeroizing::new(root), 0, 0)
        };

        // Control: one bit away from the refused pattern, and accepted.
        let mut nearly = [0u8; ROOT_LEN];
        nearly[ROOT_LEN - 1] = 1;
        let good = build(nearly).expect("a real root was refused");

        assert_eq!(
            build([0u8; ROOT_LEN]).expect_err("a placeholder root was accepted"),
            ContactCacheError::PlaceholderAddressRoot
        );

        // The at-rest door, over bytes that never went through `new` — which is
        // the one that matters, since a placeholder on disk is what a future
        // writer would leave behind.
        let mut bytes = good.encode().to_vec();
        let at = 1 + 2 * ml_dsa::PK_LEN;
        bytes[at..at + ROOT_LEN].fill(0);
        assert_eq!(
            ContactRecord::decode(&Zeroizing::new(bytes)).expect_err("decode accepted one"),
            ContactCacheError::PlaceholderAddressRoot
        );

        // And it says so, rather than only having a name.
        let said = ContactCacheError::PlaceholderAddressRoot.to_string();
        assert!(said.contains("placeholder"), "unhelpful rendering: {said}");
    }
}
