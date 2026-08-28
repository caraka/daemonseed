//! What a client keeps about a correspondent between conversations (ISC-C44).
//!
//! [`crate::dm::provisional`] is the sender's half of § v4 4.1 and says where
//! the other half lives: the recipient's `PK_pc_A` — the peer pseudonym it must
//! verify frames against — "is not here and is not recomputable from `ss0`; its
//! home is the ISC-C44 contact cache, which holds 'long-term + pseudonym
//! pubkeys' per contact". This module is that home.
//!
//! ## What the record stores, and what it recomputes
//!
//! Five fields and no sixth:
//!
//! | Field | Shape | Why it cannot be recomputed |
//! |---|---|---|
//! | `pk_lt` | the contact's long-term identity key | a public key the peer chose; nothing derives it |
//! | `pk_pc` | the contact's per-contact pseudonym key | likewise, and it is what authorship is checked against |
//! | `ss0` | the correspondence's shared secret | the encapsulated secret itself |
//! | `first_seen_ms` | `i64` milliseconds | an observation, not a derivation |
//! | `last_seen_ms` | `i64` milliseconds | likewise |
//!
//! **The `AR` / channel material is derived, never stored.**
//! [`derive_channel_roots`] is a pure function of `ss0`, so a stored copy of
//! `AR` would be a second copy of a fact this record can already produce — and
//! two stored copies of one fact can disagree, which turns a derivation into a
//! validation problem somebody has to remember to solve. Secret material
//! additionally should not be written twice: every extra at-rest copy of
//! key-bearing bytes is another thing an erase has to find. So [`ContactRecord`]
//! exposes [`ContactRecord::address_root`] as an accessor over the one stored
//! secret, and an internally-inconsistent record is unconstructible rather than
//! detectable. This is [`crate::dm::provisional`]'s argument verbatim, and it is
//! the same argument because it is the same fact.
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
//! `version ‖ pk_lt ‖ pk_pc ‖ ss0 ‖ first_seen ‖ last_seen` —
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

use crate::dm::firstcontact::{FirstContactError, ROOT_LEN, SS0_LEN, derive_channel_roots};

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
pub const CONTACT_RECORD_VERSION: u8 = 1;

/// Bytes in each of the two timestamps: an `i64` of milliseconds, big-endian.
const TIMESTAMP_LEN: usize = 8;

/// Encoded length: the version byte, both public keys, `ss0`, and the two
/// timestamps. Fixed — every field is fixed-width.
///
/// One number for every record, which is what lets the store give this kind a
/// fixed-size bucket:
/// [`RecordKind::ContactCache`](crate::storage::dm_store::RecordKind::ContactCache)
/// takes it verbatim as its capacity.
pub const CONTACT_RECORD_LEN: usize = 1 + 2 * ml_dsa::PK_LEN + SS0_LEN + 2 * TIMESTAMP_LEN;

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
        }
    }
}

impl std::error::Error for ContactCacheError {}

/// What is known about one correspondent, as it is held in memory and written to
/// rest.
///
/// One type serves both, so there is no second shape to translate between and no
/// moment where a second copy of `ss0` exists.
///
/// **`Box` for the public keys, [`Zeroizing`] for the secret** —
/// [`crate::dm::provisional::ProvisionalRecord`]'s split, and it is a split
/// rather than one uniform choice. The public keys are large and not secret, so
/// they are boxed to keep them off the stack; `ss0` is small and secret, so it
/// destroys itself wherever the value ends up owned.
///
/// **No `Drop` of its own**, deliberately: a container `Drop` forbids moving
/// fields *out*, which is what forces a caller to copy a secret back out and
/// manufacture a second live copy of it. Every field here destroys itself or has
/// nothing to destroy.
///
/// Not [`Clone`], for the same reason: a second copy of a correspondence's
/// shared secret has no use that [`Self::encode`] taking `&self` does not serve.
///
/// **The fields are private and the timestamps are ordered by construction.**
/// [`Self::new`] and [`Self::decode`] are the only two doors, both refuse
/// `last_seen_ms < first_seen_ms`, and [`Self::observed_at`] cannot move a
/// sighting behind the first one — so a record that contradicts itself about
/// when it was known does not exist to be validated.
pub struct ContactRecord {
    pk_lt: Box<[u8; ml_dsa::PK_LEN]>,
    pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
    ss0: Zeroizing<[u8; SS0_LEN]>,
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
    /// checked later but a record that must not be built.
    ///
    /// `ss0` arrives already wrapped so it can be *moved* in. Taking a bare
    /// `[u8; SS0_LEN]` would copy it at the call site and leave that copy live
    /// in the caller's frame, which is the hazard the wrapper exists to close.
    pub fn new(
        pk_lt: Box<[u8; ml_dsa::PK_LEN]>,
        pk_pc: Box<[u8; ml_dsa::PK_LEN]>,
        ss0: Zeroizing<[u8; SS0_LEN]>,
        first_seen_ms: i64,
        last_seen_ms: i64,
    ) -> Result<Self, ContactCacheError> {
        if last_seen_ms < first_seen_ms {
            return Err(ContactCacheError::TimestampsOutOfOrder {
                first_seen_ms,
                last_seen_ms,
            });
        }
        Ok(Self {
            pk_lt,
            pk_pc,
            ss0,
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

    /// The channel's address root `AR`, recomputed.
    ///
    /// **Not read back from the record** — see the module docs. The record holds
    /// `ss0` and [`derive_channel_roots`] is pure, so this is the one place the
    /// value exists and there is nothing for a second copy to disagree with.
    ///
    /// **`chan_id` is deliberately not returned with it.** It must never be
    /// serialized anywhere (§ v4 minor invariant), so handing it out beside a
    /// record's other outputs invites a caller to persist it alongside them; a
    /// caller that genuinely needs it reaches [`derive_channel_roots`] directly
    /// and keeps it in memory only.
    pub fn address_root(&self) -> Result<[u8; ROOT_LEN], FirstContactError> {
        Ok(derive_channel_roots(&self.ss0)?.ar)
    }

    /// The at-rest form, for [`crate::storage::dm_store`] to seal.
    ///
    /// Returned in a [`Zeroizing`] buffer because it carries `ss0` in the clear:
    /// the caller hands it straight to the store's seal, and the copy that
    /// outlives that call is the ciphertext.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(CONTACT_RECORD_LEN));
        out.push(CONTACT_RECORD_VERSION);
        out.extend_from_slice(self.pk_lt.as_slice());
        out.extend_from_slice(self.pk_pc.as_slice());
        out.extend_from_slice(self.ss0.as_slice());
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
    /// than a gap: `AR` is recomputed from `ss0` on every call, so a record that
    /// disagrees with it cannot be constructed. Designing an inconsistency class
    /// out is strictly better than detecting it.
    ///
    /// **Takes a [`Zeroizing`] buffer, and that is the signature doing work
    /// rather than ceremony.** [`Self::new`] takes `ss0` already wrapped so a
    /// caller cannot leave a bare copy live in its frame; a `decode` over a bare
    /// `&[u8]` would reopen exactly that hole at the other end, because this
    /// kind's store payload *is* the secret. Every other
    /// [`RecordKind`](crate::storage::dm_store::RecordKind) hands
    /// the store pre-sealed or non-secret bytes, so this is the first at-rest
    /// cleartext `ss0` buffer in the tree, and
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
        let mut ss0 = [0u8; SS0_LEN];
        ss0.copy_from_slice(&bytes[at..at + SS0_LEN]);
        at += SS0_LEN;
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
            Zeroizing::new(ss0),
            first_seen_ms,
            last_seen_ms,
        );
        ss0.zeroize();
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

    /// The shared fixture.
    ///
    /// **It initialises the crypto module**, because [`ContactRecord::address_root`]
    /// runs a real derivation and the module is process-global. Without this the
    /// module's tests pass only when some *other* test happened to initialise it
    /// first — green under the whole suite, failing when run alone, which is the
    /// worst way for a test to be wrong.
    fn record() -> ContactRecord {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        ContactRecord::new(
            pk(0x01),
            pk(0x80),
            Zeroizing::new(ss0()),
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

        // `ss0` came back: the address root it recomputes matches the one the
        // original computes.
        assert_eq!(
            record().address_root().unwrap(),
            reopened.address_root().unwrap()
        );
    }

    /// **The oracle for "derived, not stored".** The accessor is the same
    /// function an independent caller would run over the same `ss0`, so a record
    /// that had quietly stored an `AR` — or derived one from the wrong field —
    /// would disagree here.
    #[test]
    fn the_address_root_is_derived_from_ss0() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let independent = derive_channel_roots(&ss0()).expect("derives");
        assert_ne!(independent.ar, [0u8; ROOT_LEN], "a real AR is not all-zero");
        assert_eq!(record().address_root().unwrap(), independent.ar);

        // And it tracks `ss0` rather than being a constant: a different secret
        // gives a different root.
        let other = ContactRecord::new(
            pk(0x01),
            pk(0x80),
            Zeroizing::new([0x99u8; SS0_LEN]),
            FIRST_SEEN,
            LAST_SEEN,
        )
        .unwrap();
        assert_ne!(other.address_root().unwrap(), independent.ar);
    }

    /// Neither the address root nor the channel id is written down. `chan_id`
    /// must never be serialized anywhere (§ v4 minor invariant), and `AR` beside
    /// a record's secrets would be a second copy of a fact the record derives.
    #[test]
    fn the_record_carries_no_address_root_and_no_channel_id() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let encoded = record().encode();
        let roots = derive_channel_roots(&ss0()).unwrap();

        assert_eq!(encoded.len(), CONTACT_RECORD_LEN);
        // Positive control: this really is the record's encoding, so a miss
        // below is an absence rather than a scan that never matched anything.
        assert!(
            encoded.windows(SS0_LEN).any(|w| w == ss0()),
            "the scan does not see the bytes it claims to search"
        );

        assert!(
            !encoded.windows(roots.ar.len()).any(|w| w == roots.ar),
            "the address root is in the record"
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
            Zeroizing::new([0u8; SS0_LEN]),
            0,
            0,
        )
        .unwrap();
        assert_eq!(record().encode().len(), sparse.encode().len());
        assert_eq!(record().encode().len(), CONTACT_RECORD_LEN);
    }

    /// The record does not render its secrets, the way every other key-bearing
    /// type here does not.
    #[test]
    fn a_record_does_not_render_its_secrets() {
        let rendered = format!("{:?}", record());
        assert!(!rendered.contains(&hex::encode(ss0())));
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
                Zeroizing::new(ss0()),
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
                Zeroizing::new(ss0()),
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
}
