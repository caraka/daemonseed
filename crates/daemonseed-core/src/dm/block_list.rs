//! The block list — the direct-messaging revocation primitive (ISC-C46).
//!
//! Design of record: `docs/design/direct-messaging.md`. A set of long-term
//! identity public keys, and the one predicate that both suppression planes ask.
//!
//! ## One rule, asked at two planes
//!
//! ISC-C46 names two suppressions: a blocked sender's doorbell entry is dropped
//! at sweep, and the client stops sweeping a blocked correspondent's channel.
//! They are **the same predicate over the same key**, and this module does not
//! pretend otherwise — [`BlockList::is_blocked`] is the rule, and
//! [`BlockList::suppresses_knock`] and [`BlockList::suppresses_channel`] are
//! named wrappers so a call site says which plane it is standing on. Naming them
//! is worth a line each because the two planes fail differently when one is
//! forgotten: a missed knock suppression lets a blocked stranger reach the
//! contact-request surface, while a missed channel suppression keeps a
//! conversation that was already established alive.
//!
//! ## Where the doorbell suppression can actually run
//!
//! **Not at the fetch.** A doorbell sweep returns slots of unverified, still
//! sealed bytes — a per-message KEM ciphertext, the sealed body, and a proof of
//! work — none of which names a sender, and the sweeping layer holds no
//! decapsulation key. Only [`open`](crate::dm::firstcontact::open) decides an
//! entry is genuine and reveals who wrote it, so the drop happens **after** the
//! open, at the slot the entry came from — which is why a doorbell sweep hands
//! its slot back beside the bytes.
//!
//! **The slot index is a real pre-open correlate, and refusing to use it is a
//! choice worth recording.** A slot is derived per sender-and-recipient pair and
//! is stable across restarts, so a recipient who has already opened one knock
//! from someone could suppress that slot without opening the next. It would leak
//! nothing outward — the sweep fetches every slot regardless, so no timing or
//! traffic changes — but with only thirty-two slots it would also silently
//! suppress roughly one unrelated stranger in thirty-two. Sender-blindness is
//! the reason a *general* pre-open filter is impossible; this collision rate is
//! the reason the one available shortcut is refused.
//!
//! ISC-C46's own wording — *"dropped at sweep on the sealed sender hash"* — is
//! stale lineage. The sender-hash field it names was refuted as attacker-chosen
//! and does not exist in the current entry. The substance survives, in the form
//! above; the criterion's text has not caught up.
//!
//! [`BlockList::suppresses_knock`] therefore takes an opened
//! [`VerifiedFirstContact`], not a slot. A predicate that took raw slot bytes
//! could not be written honestly.
//!
//! ## Where it lives at rest
//!
//! **It persists, and a block survives a restart.** [`BlockList::encode`] and
//! [`BlockList::decode`] are its at-rest form and
//! [`crate::storage::dm_store::RecordKind::BlockList`] is its slot: **one
//! fixed-size sealed file at the store root, created at every open**, holding
//! up to [`BLOCK_LIST_MAX_ENTRIES`] identities.
//!
//! Three properties of that placement are the whole of why it is not simply a
//! serialized set. The record is **profile-level**, because a block names an
//! identity there is no established correspondence with — which is exactly the
//! case a per-correspondence record cannot hold. It is **one size whatever it
//! holds**, because the design forbids a store shape that reveals how many
//! entries it has and a variable-length list of 2592-byte keys would report the
//! size of a user's block list to anyone who can read the file. And it is
//! **created whether or not anyone has blocked anybody**, so its presence says
//! nothing about whether the feature is in use.
//!
//! ## What this module is not, yet
//!
//! **Nothing consults it.** No doorbell consumer and no channel-sweep path asks
//! either predicate; the wiring belongs to a later slice. So the obligations
//! below are written for a caller that does not exist yet, and are here to be
//! read when it does.
//!
//! ## What this module cannot enforce
//!
//! **"Byte-identical to never came online" is the caller's obligation, and it
//! holds fully only at the doorbell.** ISC-C46 requires a blocked sender to be
//! unable to distinguish a block from silence. At the doorbell that is
//! achievable and it is the caller's to achieve: drop the entry where an
//! un-blocked one would have been filed, emit nothing, write nothing, and take
//! the same time doing it. A refusal that logs, replies, or returns early enough
//! to be timed reintroduces exactly the oracle the criterion forbids.
//!
//! **At the channel plane a residual survives any amount of caller care.**
//! Ceasing to sweep *is* the channel suppression, and the design records it as a
//! known minor: a block is third-party-detectable, because writes continue while
//! the re-sweep GETs stop. It is not visible to the blocked *sender*, who does
//! not observe another party's reads — which is why the criterion's own wording
//! survives — but it is not nothing, and a reader should not take the doorbell
//! paragraph above as the whole story.
//!
//! **Reversal is the caller's too, and the criterion says what it costs:**
//! unblocking is reversible with the contact cache preserved. This module holds
//! only the set, so removing a key restores delivery and nothing here ever had a
//! contact record to lose.
//!
//! Mute is a different thing and is not here: it suppresses chat rendering and
//! leaves delivery alone.

use std::collections::BTreeSet;

use oxicrypt_ml_dsa as ml_dsa;

use crate::dm::firstcontact::VerifiedFirstContact;

/// The set of identity keys a client refuses.
///
/// Keyed on the **long-term** identity public key. That is what ISC-C46 names,
/// and it is the key the in-seal binding exists to expose: blocking a pseudonym
/// would be undone by the next conversation, and `pk_lt` is authenticated by
/// `bind_lt` before a [`VerifiedFirstContact`] exists at all, so it is proven
/// rather than claimed.
///
/// **The limit of that, stated rather than implied:** a long-term key cannot be
/// rotated in place, so a block cannot be shed by rotation — but one mnemonic
/// can derive more than one identity, and nothing here pins direct messaging to
/// the primary one. A block reaches the identity it names and no other.
///
/// **Neither `Copy` nor `Clone`, and only one of those was a choice.** `Copy`
/// cannot be derived on a type holding a `BTreeSet` at all, so claiming it as a
/// decision would dress a compiler rule as a design one. `Clone` was available
/// and is refused: a cloned revocation list is a second list that a later block
/// never reaches, and the divergence is silent. Nothing needs one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BlockList {
    /// Boxed rather than inline: an ML-DSA-87 public key is 2592 bytes, and a
    /// set node holding one inline would move that on every rebalance.
    blocked: BTreeSet<Box<[u8; ml_dsa::PK_LEN]>>,
}

impl BlockList {
    /// An empty list, blocking nobody.
    pub fn new() -> Self {
        Self {
            blocked: BTreeSet::new(),
        }
    }

    /// Block an identity. Returns whether the list changed.
    ///
    /// Blocking an already-blocked identity is not an error — a revocation that
    /// refused to be repeated would make the caller track state this type
    /// already holds.
    pub fn block(&mut self, pk_lt: &[u8; ml_dsa::PK_LEN]) -> bool {
        self.blocked.insert(Box::new(*pk_lt))
    }

    /// Unblock an identity. Returns whether the list changed.
    ///
    /// Nothing else happens: the contact cache is not this type's to touch, so
    /// the reversal ISC-C46 requires is exactly the removal, and delivery
    /// resumes with whatever was already stored.
    pub fn unblock(&mut self, pk_lt: &[u8; ml_dsa::PK_LEN]) -> bool {
        self.blocked.remove(pk_lt as &[u8; ml_dsa::PK_LEN])
    }

    /// Whether this identity is blocked. **The rule; both planes below ask it.**
    pub fn is_blocked(&self, pk_lt: &[u8; ml_dsa::PK_LEN]) -> bool {
        self.blocked.contains(pk_lt as &[u8; ml_dsa::PK_LEN])
    }

    /// How many identities are blocked.
    pub fn len(&self) -> usize {
        self.blocked.len()
    }

    /// Whether the list blocks nobody.
    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }

    /// **Doorbell plane.** Whether an opened knock must be dropped.
    ///
    /// Takes the opened entry rather than a slot for the reason the module
    /// header gives: before the open there is no sender to test. The caller
    /// drops the entry at the slot it arrived in and does nothing else — see
    /// *What this module cannot enforce*.
    pub fn suppresses_knock(&self, entry: &VerifiedFirstContact) -> bool {
        self.is_blocked(entry.pk_lt())
    }

    /// **Channel plane.** Whether an established correspondent's channel must
    /// stop being swept.
    ///
    /// The correspondent's long-term key is the one the contact cache holds, so
    /// this is answerable without opening anything.
    pub fn suppresses_channel(&self, correspondent_pk_lt: &[u8; ml_dsa::PK_LEN]) -> bool {
        self.is_blocked(correspondent_pk_lt)
    }

    /// The at-rest form: every blocked key, concatenated, in ascending byte
    /// order.
    ///
    /// **Nothing describes the entries — no header, no count, no occupancy
    /// map — and that is what keeps the count off the disk.** The store pads
    /// every payload out to [`RecordKind::capacity`](crate::storage::dm_store::RecordKind::capacity)
    /// with CSPRNG filler and carries the true length in a prefix *inside* the
    /// seal, so a file holding no entries and one holding 512 are the same
    /// number of bytes and differ only in ciphertext. An occupancy bitmap over
    /// 512 fixed slots would hide the count equally well and would additionally
    /// have to be kept consistent with the slots it describes; a bare
    /// concatenation has no second representation to disagree with the first.
    /// The store's fixed bucket is what does the hiding either way, which is the
    /// reason to prefer the encoding with less to get wrong.
    ///
    /// **Ascending order is canonical, not incidental.** Two lists with the same
    /// members encode to the same bytes whatever order they were blocked in, so
    /// a re-encode after an unrelated change produces byte-identical plaintext
    /// and [`Self::decode`] can reject a duplicate as a violated ordering rather
    /// than by searching the set it is still building.
    ///
    /// **Refused above the ceiling rather than truncated.** A truncated
    /// revocation list is one that opens, parses to fewer entries than it had,
    /// and silently unblocks somebody — the store's own argument for
    /// [`DmStoreError::PayloadTooLong`](crate::storage::dm_store::DmStoreError::PayloadTooLong),
    /// one layer up. The store's bucket is exactly
    /// [`BLOCK_LIST_MAX_ENTRIES`] keys, so its refusal is the same refusal; this
    /// one names the ceiling in the units the user chose entries in.
    pub fn encode(&self) -> Result<Vec<u8>, BlockListError> {
        let count = self.blocked.len();
        if count > BLOCK_LIST_MAX_ENTRIES {
            return Err(BlockListError::Full { count });
        }
        let mut out = Vec::with_capacity(count * ml_dsa::PK_LEN);
        for key in &self.blocked {
            out.extend_from_slice(key.as_slice());
        }
        Ok(out)
    }

    /// Read back what [`Self::encode`] wrote.
    ///
    /// An empty payload is the empty list, which is what a store that has just
    /// created the record holds — the record exists from the first open whether
    /// or not anyone has ever blocked anybody, so "no entries" must be an
    /// ordinary value and not an absence.
    ///
    /// Every departure from the canonical form is refused rather than repaired.
    /// A length that is not a whole number of keys means the payload is not this
    /// record; an out-of-order or repeated key means bytes that no [`encode`]
    /// here produced. Both are reachable only by something holding the profile
    /// key — the store authenticates before this sees anything — so the refusal
    /// is a statement that the encoding has exactly one spelling, not a defence.
    ///
    /// [`encode`]: Self::encode
    pub fn decode(bytes: &[u8]) -> Result<Self, BlockListError> {
        if !bytes.len().is_multiple_of(ml_dsa::PK_LEN) {
            return Err(BlockListError::NotWholeKeys { len: bytes.len() });
        }
        let count = bytes.len() / ml_dsa::PK_LEN;
        if count > BLOCK_LIST_MAX_ENTRIES {
            return Err(BlockListError::Full { count });
        }

        let mut blocked = BTreeSet::new();
        let mut previous: Option<&[u8]> = None;
        for chunk in bytes.chunks_exact(ml_dsa::PK_LEN) {
            if previous.is_some_and(|prev| chunk <= prev) {
                return Err(BlockListError::NotAscending);
            }
            previous = Some(chunk);
            let mut key = Box::new([0u8; ml_dsa::PK_LEN]);
            key.copy_from_slice(chunk);
            blocked.insert(key);
        }
        Ok(Self { blocked })
    }
}

/// The most identities one profile's block list may hold.
///
/// **512 is ratified and is user-visible** (issue #390). Every entry is an
/// ML-DSA-87 public key, and the store pays for the ceiling in full on every
/// profile whether it blocks nobody or all 512 — which is the price of the
/// file's size not reporting how many people a user has blocked. Raising it
/// later changes the size of a record that already exists, so it needs a
/// migration pass rather than an edit here: ordinary traffic no longer
/// re-encodes an unchanged record (#347), so nothing would migrate as a side
/// effect.
pub const BLOCK_LIST_MAX_ENTRIES: usize = 512;

/// The payload size of a full block list, and therefore the store bucket's.
pub const BLOCK_LIST_CAPACITY: usize = BLOCK_LIST_MAX_ENTRIES * ml_dsa::PK_LEN;

/// What can be wrong with a block list's at-rest bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockListError {
    /// More than [`BLOCK_LIST_MAX_ENTRIES`] identities.
    ///
    /// Raised at the encode, so the write never happens and the stored list is
    /// left exactly as it was. Blocking is what reaches this; unblocking cannot.
    Full { count: usize },
    /// The payload is not a whole number of ML-DSA-87 public keys.
    NotWholeKeys { len: usize },
    /// The keys are not in strictly ascending order — out of order, or repeated.
    NotAscending,
}

impl core::fmt::Display for BlockListError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full { count } => write!(
                f,
                "a block list holds at most {BLOCK_LIST_MAX_ENTRIES} identities, not {count}"
            ),
            Self::NotWholeKeys { len } => write!(
                f,
                "{len} bytes is not a whole number of {}-byte identity keys",
                ml_dsa::PK_LEN
            ),
            Self::NotAscending => {
                f.write_str("the stored identity keys are not in strictly ascending order")
            }
        }
    }
}

impl core::error::Error for BlockListError {}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dm::firstcontact::{self, FirstContactRequest};
    use crate::dm::pow::PowDifficulty;
    use crate::identity::keys::{Identity, IdentityKeys, derive_identity_keys};
    use crate::identity::mnemonic::Mnemonic;

    fn key(seed: u8) -> [u8; ml_dsa::PK_LEN] {
        let mut k = [0u8; ml_dsa::PK_LEN];
        k[0] = seed;
        // A second differing byte well inside the key, so a comparison that only
        // looked at a prefix would still have to be wrong on purpose to pass.
        k[ml_dsa::PK_LEN - 1] = seed.wrapping_mul(7);
        k
    }

    /// The rule, both ways round. A predicate tested only on the blocked case
    /// passes just as happily when it returns `true` for everyone.
    #[test]
    fn a_blocked_identity_is_blocked_and_an_unblocked_one_is_not() {
        let mut list = BlockList::new();
        let blocked = key(1);
        let stranger = key(2);

        assert!(
            !list.is_blocked(&blocked),
            "nobody is blocked to begin with"
        );
        assert!(
            list.block(&blocked),
            "blocking a new identity changes the list"
        );

        assert!(list.is_blocked(&blocked));
        assert!(
            !list.is_blocked(&stranger),
            "blocking one identity must not block another"
        );
        assert_eq!(list.len(), 1);
    }

    /// Two keys differing only in their last byte are different identities.
    ///
    /// This is the probe against a comparison that stops early — the fixture's
    /// keys differ in the first byte *and* the last, so a prefix-only compare
    /// would pass the test above and fail this one.
    #[test]
    fn identities_differing_only_in_their_last_byte_are_distinct() {
        let mut list = BlockList::new();
        let mut a = [0u8; ml_dsa::PK_LEN];
        let mut b = [0u8; ml_dsa::PK_LEN];
        a[ml_dsa::PK_LEN - 1] = 1;
        b[ml_dsa::PK_LEN - 1] = 2;

        assert!(list.block(&a));
        assert!(list.is_blocked(&a));
        assert!(
            !list.is_blocked(&b),
            "a key differing only in its final byte is a different identity"
        );
    }

    /// Blocking twice is idempotent and reports it; the set does not grow.
    #[test]
    fn blocking_twice_changes_the_list_only_once() {
        let mut list = BlockList::new();
        let k = key(3);

        assert!(list.block(&k), "the first block changes the list");
        assert!(!list.block(&k), "the second does not");
        assert_eq!(list.len(), 1, "and the set did not grow");
        assert!(list.is_blocked(&k), "still blocked either way");
    }

    /// Unblocking reverses the block exactly, and reports whether it did
    /// anything. ISC-C46's reversibility, at this layer.
    #[test]
    fn unblocking_reverses_a_block_and_reports_whether_it_did_anything() {
        let mut list = BlockList::new();
        let k = key(4);
        let never_blocked = key(5);

        list.block(&k);
        assert!(
            list.unblock(&k),
            "unblocking a blocked identity changes the list"
        );
        assert!(!list.is_blocked(&k), "and it is no longer blocked");
        assert!(list.is_empty());

        assert!(
            !list.unblock(&never_blocked),
            "unblocking someone who was never blocked changes nothing"
        );
    }

    /// **The channel plane asks the same rule as the doorbell plane.**
    ///
    /// Pinned because the two are separate methods: a change that made one of
    /// them consult a different set, or answer a different key, would leave a
    /// blocked correspondent suppressed at one plane and reachable at the other,
    /// and nothing else in the suite would notice.
    #[test]
    fn both_planes_answer_the_same_rule_for_the_same_identity() {
        let mut list = BlockList::new();
        let blocked = key(6);
        let allowed = key(7);
        list.block(&blocked);

        assert!(list.suppresses_channel(&blocked));
        assert_eq!(
            list.suppresses_channel(&blocked),
            list.is_blocked(&blocked),
            "the channel plane must be the rule, not a second copy of it"
        );

        assert!(!list.suppresses_channel(&allowed));
        assert_eq!(
            list.suppresses_channel(&allowed),
            list.is_blocked(&allowed),
            "and it must agree on the un-blocked case too"
        );
    }

    /// An empty list suppresses nothing at either plane, and reports a length of
    /// zero.
    ///
    /// The degenerate case a "does it suppress?" predicate passes vacuously if
    /// it is only ever asked about someone who is blocked. The `len` assertion
    /// is here rather than anywhere else because every other test's list holds
    /// exactly one key: without a zero case, `len` returning a constant `1`
    /// passes the whole suite.
    #[test]
    fn an_empty_list_suppresses_nobody_and_has_length_zero() {
        let list = BlockList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0, "an empty list has no members");
        assert!(!list.is_blocked(&key(8)));
        assert!(!list.suppresses_channel(&key(8)));
    }

    /// **A list holds more than one identity, and each is independent.**
    ///
    /// Every other test blocks exactly one key, and that is enough to hide two
    /// whole classes of defect: a `block` that accepts only the first identity
    /// it is ever given, and an `unblock` that clears the set instead of
    /// removing one member. Both pass a suite whose lists never hold two things.
    /// This is the test that holds three.
    #[test]
    fn many_identities_are_blocked_independently_and_removed_one_at_a_time() {
        let mut list = BlockList::new();
        let a = key(10);
        let b = key(11);
        let c = key(12);

        assert!(list.block(&a));
        assert!(list.block(&b));
        assert!(list.block(&c));
        assert_eq!(list.len(), 3, "three distinct identities are three members");
        for (name, k) in [("a", &a), ("b", &b), ("c", &c)] {
            assert!(
                list.is_blocked(k),
                "{name} was blocked and must stay blocked"
            );
        }

        // Removing one leaves the others exactly where they were.
        assert!(list.unblock(&b));
        assert_eq!(list.len(), 2, "one removal removes one member, not the set");
        assert!(!list.is_blocked(&b), "b is gone");
        assert!(list.is_blocked(&a), "a survives b's removal");
        assert!(list.is_blocked(&c), "c survives b's removal");
    }

    /// Two identities differing only in the MIDDLE of the key are distinct.
    ///
    /// The sibling test differs at the last byte and the fixture differs at the
    /// first, so between them a comparator that skipped an interior range would
    /// still pass. This aims at that range directly.
    #[test]
    fn identities_differing_only_in_the_middle_are_distinct() {
        let mut list = BlockList::new();
        let mut a = [0u8; ml_dsa::PK_LEN];
        let mut b = [0u8; ml_dsa::PK_LEN];
        a[ml_dsa::PK_LEN / 2] = 1;
        b[ml_dsa::PK_LEN / 2] = 2;

        assert!(list.block(&a));
        assert!(list.is_blocked(&a));
        assert!(
            !list.is_blocked(&b),
            "keys differing only in an interior byte are different identities"
        );
    }

    /// `Default` is an empty list, exactly as [`BlockList::new`] is.
    ///
    /// This is also the only consumer of the type's `PartialEq`: without it,
    /// both `Default` and the equality derive could be deleted and the suite
    /// would not notice. `Default` itself is not optional — clippy's
    /// `new_without_default` requires it beside a `new`.
    #[test]
    fn default_is_an_empty_list_like_new() {
        assert_eq!(BlockList::default(), BlockList::new());

        let mut d = BlockList::default();
        assert!(!d.is_blocked(&key(13)), "a defaulted list blocks nobody");
        assert!(d.block(&key(13)), "and is usable as a fresh list");
    }

    // ── The doorbell plane ──────────────────────────────────────────────────

    const FC_EPOCH: u64 = 2_900_000;
    const SENT_UNIX_MS: i64 = 1_700_000_000_000;

    /// A fresh random identity. A real pseudonym is random per correspondent, so
    /// the sender's long-term identity and its pseudonym are made the same way.
    fn fresh_identity() -> IdentityKeys {
        // In the fixture rather than in one test body: an uninitialised
        // process-global crypto module makes these tests fail when this module
        // is run on its own and pass when something earlier in the suite
        // happened to initialise it first.
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap()
    }

    /// A genuine opened knock, built and opened by the real path.
    ///
    /// There is no other way to hold a [`VerifiedFirstContact`] — which is
    /// exactly why the doorbell plane had no test while the channel plane did.
    fn opened_knock() -> VerifiedFirstContact {
        let sender = fresh_identity();
        let sender_pseudonym = fresh_identity();
        let recipient = fresh_identity();

        let (entry, _state) = firstcontact::build(FirstContactRequest {
            signing_lt: &sender.signing,
            signing_pc: &sender_pseudonym.signing,
            recipient_pk_lt: recipient.signing.public_key(),
            kem_ek_b: recipient.kem.encapsulation_key(),
            fc_epoch: FC_EPOCH,
            sent_unix_ms: SENT_UNIX_MS,
            body: "knock",
            token: None,
            difficulty: PowDifficulty::reduced_for_test(4),
        })
        .expect("the test knock builds");

        firstcontact::open(
            &entry,
            recipient.kem.decapsulation_key(),
            recipient.signing.public_key(),
            FC_EPOCH,
        )
        .expect("the test knock opens")
    }

    /// Blocking the sender's long-term identity suppresses its knock.
    #[test]
    fn blocking_the_long_term_key_suppresses_the_knock() {
        let entry = opened_knock();
        let mut list = BlockList::new();

        assert!(
            !list.suppresses_knock(&entry),
            "the control: an un-blocked sender's knock is not suppressed"
        );
        assert!(list.block(entry.pk_lt()), "blocking the sender is a change");
        assert!(
            list.suppresses_knock(&entry),
            "and then the doorbell plane suppresses it"
        );
    }

    /// **Blocking the pseudonym does not suppress the knock.**
    ///
    /// The whole reason [`BlockList::suppresses_knock`] exists rather than the
    /// call site asking [`BlockList::is_blocked`] itself: it must read the
    /// entry's long-term key, because a block on a pseudonym is undone the next
    /// time the correspondent rotates one.
    ///
    /// **What this test uniquely catches is over-blocking, not the swap.** A
    /// version reading `pk_pc` instead of `pk_lt` fails the test above as well,
    /// so that mutation is not this test's to catch. The one it alone kills is a
    /// version asking whether *either* key is blocked — which looks harmless,
    /// passes every other test here, and quietly makes a pseudonym block
    /// permanent.
    #[test]
    fn blocking_the_pseudonym_does_not_suppress_the_knock() {
        let entry = opened_knock();
        // Without this the test is vacuous: if the two keys were the same value
        // there would be nothing for the method to get wrong.
        assert_ne!(
            &entry.pk_lt()[..],
            &entry.pk_pc()[..],
            "the fixture's long-term and pseudonym keys must actually differ"
        );

        let mut list = BlockList::new();
        assert!(
            list.block(entry.pk_pc()),
            "block the pseudonym, and only it"
        );
        assert!(
            !list.is_blocked(entry.pk_lt()),
            "the long-term key is deliberately not blocked"
        );

        assert!(
            !list.suppresses_knock(&entry),
            "a pseudonym block must not suppress the knock — \
             suppression is keyed on the long-term identity"
        );
    }

    /// An empty list does not suppress a genuine knock.
    ///
    /// The degenerate case: a `suppresses_knock` that answered `true`
    /// unconditionally would satisfy the first test on its own.
    #[test]
    fn an_empty_list_does_not_suppress_a_genuine_knock() {
        let entry = opened_knock();
        let list = BlockList::new();

        assert!(list.is_empty());
        assert!(!list.suppresses_knock(&entry));
    }

    // ---- the at-rest form --------------------------------------------------

    /// A key whose bytes depend on `seed` throughout, so a round trip that
    /// truncated, shifted or reordered could not pass.
    fn spread_key(seed: u16) -> [u8; ml_dsa::PK_LEN] {
        let mut k = [0u8; ml_dsa::PK_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u16).wrapping_mul(31).wrapping_add(seed) as u8;
        }
        // Both halves of the seed land in their own byte, so keys are distinct
        // across the whole `u16` range rather than colliding every 256 seeds —
        // which at a 512-entry ceiling would silently halve the fixture.
        k[0] = (seed >> 8) as u8;
        k[1] = seed as u8;
        k
    }

    /// Encode, decode, and get the same membership back.
    #[test]
    fn the_at_rest_form_round_trips() {
        let mut list = BlockList::new();
        for seed in [7u16, 1, 400, 40_000] {
            assert!(list.block(&spread_key(seed)));
        }

        let bytes = list.encode().unwrap();
        assert_eq!(
            bytes.len(),
            4 * ml_dsa::PK_LEN,
            "one key per entry, no header"
        );

        let back = BlockList::decode(&bytes).unwrap();
        assert_eq!(back, list, "the decoded list is the encoded one");
        for seed in [7u16, 1, 400, 40_000] {
            assert!(back.is_blocked(&spread_key(seed)));
        }
        // Control: a key that was never blocked is not blocked after a round
        // trip either, so `decode` is not simply answering true.
        assert!(!back.is_blocked(&spread_key(9)));
    }

    /// The empty list encodes to nothing and decodes back from nothing.
    ///
    /// This is the value the store writes when it creates the record, so "no
    /// entries" has to be an ordinary round trip rather than a special case.
    #[test]
    fn the_empty_list_round_trips_through_an_empty_payload() {
        let empty = BlockList::new();
        assert!(empty.encode().unwrap().is_empty());
        assert_eq!(BlockList::decode(&[]).unwrap(), empty);
    }

    /// The encoding is canonical: the same members produce the same bytes
    /// whatever order they were blocked in.
    #[test]
    fn the_encoding_does_not_depend_on_the_order_blocks_were_added() {
        let mut forwards = BlockList::new();
        let mut backwards = BlockList::new();
        for seed in 0u16..16 {
            forwards.block(&spread_key(seed));
        }
        for seed in (0u16..16).rev() {
            backwards.block(&spread_key(seed));
        }
        assert_eq!(forwards.encode().unwrap(), backwards.encode().unwrap());
    }

    /// The ceiling is refused at the encode, and the 512th entry is not.
    ///
    /// Both halves: a refusal at 512 would be an off-by-one that silently cost a
    /// user an entry, and no refusal at all is the truncation the ceiling exists
    /// to make impossible.
    #[test]
    fn the_ceiling_is_enforced_at_the_encode() {
        let mut list = BlockList::new();
        for seed in 0..BLOCK_LIST_MAX_ENTRIES {
            assert!(
                list.block(&spread_key(seed as u16)),
                "fixture produced a duplicate key at {seed}"
            );
        }
        assert_eq!(list.len(), BLOCK_LIST_MAX_ENTRIES);
        assert_eq!(
            list.encode().unwrap().len(),
            BLOCK_LIST_CAPACITY,
            "a full list encodes to exactly the store bucket"
        );

        assert!(list.block(&spread_key(BLOCK_LIST_MAX_ENTRIES as u16)));
        assert_eq!(
            list.encode(),
            Err(BlockListError::Full {
                count: BLOCK_LIST_MAX_ENTRIES + 1
            }),
            "one identity past the ceiling is refused, not truncated"
        );
    }

    /// Every departure from the canonical form is refused.
    #[test]
    fn a_non_canonical_payload_is_refused() {
        let a = spread_key(1);
        let b = spread_key(2);
        let (lower, higher) = if a <= b { (a, b) } else { (b, a) };

        let mut ascending = Vec::new();
        ascending.extend_from_slice(&lower);
        ascending.extend_from_slice(&higher);
        // Control: the canonical spelling of these very bytes is accepted, so the
        // refusals below are about the ordering and not about the fixture.
        assert_eq!(BlockList::decode(&ascending).unwrap().len(), 2);

        let mut descending = Vec::new();
        descending.extend_from_slice(&higher);
        descending.extend_from_slice(&lower);
        assert_eq!(
            BlockList::decode(&descending),
            Err(BlockListError::NotAscending)
        );

        let mut repeated = Vec::new();
        repeated.extend_from_slice(&lower);
        repeated.extend_from_slice(&lower);
        assert_eq!(
            BlockList::decode(&repeated),
            Err(BlockListError::NotAscending),
            "a repeat is a violated ordering"
        );

        assert_eq!(
            BlockList::decode(&ascending[..ascending.len() - 1]),
            Err(BlockListError::NotWholeKeys {
                len: 2 * ml_dsa::PK_LEN - 1
            })
        );

        let over = vec![0u8; (BLOCK_LIST_MAX_ENTRIES + 1) * ml_dsa::PK_LEN];
        assert_eq!(
            BlockList::decode(&over),
            Err(BlockListError::Full {
                count: BLOCK_LIST_MAX_ENTRIES + 1
            })
        );
    }
}
