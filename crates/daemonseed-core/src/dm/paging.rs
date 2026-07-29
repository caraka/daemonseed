//! Where a conversation's messages live: per-page scattered channel records
//! (ISC-C42 / ISC-A-C24).
//!
//! Every message of a conversation sits in one slot of one page, and each page is
//! its own Veilid record at an address derived from the conversation's secret
//! address root. This module is the whole of that mapping — the arithmetic from a
//! sequence number to a page and a slot, and the derivation from a page to the
//! record that holds it.
//!
//! ## Why pages, and not one record or one record per message
//!
//! Both simpler shapes were tried and both broke.
//!
//! A **single shared record** concentrates the conversation: one storage node
//! co-hosting it sees every message, in order, with timing — the shape of the
//! whole relationship, even though it can read none of the content. It also caps
//! the conversation at the record's slot count and forces a ring, so message
//! `n + slots` overwrites message `n` and a party that fell behind loses the
//! difference permanently.
//!
//! **One record per message** fixes both and replaces them with a write budget
//! that does not fit: every message costs a record open, and the open lane is the
//! scarcest thing the network has.
//!
//! Pages sit between. [`PAGE_SLOTS`] messages share a record, so opens amortise
//! sixteen-to-one; a `(direction, sequence)` maps to exactly one page and slot and
//! is written once, so nothing wraps and nothing is overwritten; the backlog is
//! unbounded because a conversation simply adds pages; and each page hashes to a
//! different place in the network, so no single co-host sees the conversation's
//! shape. A reader can also watch the current page and be told when a new slot
//! appears, which a scatter of single-message records cannot offer.
//!
//! ## The address is secret, and that is what makes the page safe
//!
//! Every other DM record is addressed from a public key, so anybody can compute
//! it — the key record and the doorbell are world-derivable by design, and
//! therefore world-**writable**, and both carry that as an accepted cost.
//!
//! A page is different. Its owner seed derives from `AR`, which comes from the
//! secret encapsulated at first contact, so only the two parties can compute the
//! address at all — and under Veilid a derivable owner seed *is* write access. A
//! third party cannot find the record, let alone write to it, which is why the
//! ongoing channel needs no admission control and no proof of work: the defences
//! the doorbell carries against strangers have nothing to defend against here.
//!
//! **That is authority against outsiders, and nothing more.** `AR` is symmetric:
//! *both* parties can derive the owner seed for *both* directions, so the address
//! separates the two streams, not the two authors. Finding a frame in the `a2b`
//! pages does **not** establish that A wrote it. Authorship within the pair comes
//! from `msg_sig` alone — mandatory, verified on every frame, under the
//! per-contact pseudonym, carrying the binding to the long-term identity. The
//! frozen build contract makes that the sole proof-of-possession path and warns
//! that any frame type omitting it loses proof-of-possession silently. A frame
//! layer that read "no admission control" as "the address vouches for the author"
//! would be that frame type.
//!
//! ## Two pointers, not one
//!
//! A collector holds two positions and they are **not** the same number, however
//! much they look alike.
//!
//! The **probe frontier** is how far ahead pages have been reached. It advances
//! on a page holding *any* populated slot, never on a page being full — the
//! initiator's very first page has a permanently empty first slot, because its
//! sequence zero is the first-contact entry and that travels by doorbell.
//!
//! The **contiguous cursor** is how far the unbroken prefix of collected messages
//! runs, and it is what the delivery acknowledgement reports. A single message
//! that is never recoverable holds it in place forever, by design — that is the
//! point of an honest acknowledgement.
//!
//! Anchoring the frontier to the cursor collapses them, and one permanently lost
//! message then stalls the entire rest of the conversation. So
//! [`position_of`] answers "where does sequence *n* live" and is the right tool
//! for the cursor; it is the wrong tool for the frontier, which is not a function
//! of any sequence number.
//!
//! ## The collector must check where a message was found
//!
//! A frame declares its own sequence number, and the slot it was found in also
//! implies one. **They must agree**, and a collector has to verify it rather than
//! trusting the frame: taking the sequence number from the frame alone unbinds it
//! from the position it occupies, and the write-once, never-overwritten property
//! this whole scheme rests on stops being checked by anything. Only the two
//! parties can write to a page, so a mismatch is peer non-conformance rather than
//! a third-party attack — but it is exactly what the injective mapping exists to
//! make impossible, and leaving it unverified would hand the acknowledgement layer
//! positions nothing has confirmed. [`PagePosition::new`] is the checked way to
//! turn a swept slot into a sequence number for that comparison.
//!
//! The cost is stated plainly in the frozen design and worth repeating: `AR` is
//! retained for the life of the conversation, so **addressing is not
//! forward-secret even though content is**. A future compromise of the identity
//! key recovers `ss0`, and from it this entire address graph, past and future. It
//! recovers no message — those keys are ratcheted and deleted — but it does
//! reveal that the conversation happened and how it was shaped. That asymmetry is
//! deliberate: it is what lets a party who has been offline for a month still
//! find its way back.

use oxicrypt_kdf::HkdfSha384;

use crate::dm::domain;
use crate::dm::ratchet::Direction;
use crate::secret_seed::{derive_boxed_seed, redacted_secret_newtype};

/// Byte length of the Veilid owner seed this module derives.
pub const DM_PAGE_OWNER_SEED_LEN: usize = 32;

/// Messages per page — the `o_cnt` of the page record's `dflt(o_cnt)` schema.
///
/// **Sixteen because the frozen design pins K=16**, not because sixteen is where
/// the slot cap runs out. It is worth being exact about that: the cap is
/// `min(32768, 1 MiB / o_cnt)`, so anything up to `dflt(32)` keeps the full
/// 32 KiB slot — the sibling doorbell derives precisely that and uses 32. Sixteen
/// buys a wider margin under a slot than a message needs, at sixteen-to-one open
/// amortisation rather than thirty-two.
///
/// **A writer MUST build its `RecordShape` from this constant**, never from a
/// hand-typed literal. `o_cnt` is part of the deterministic record address, so a
/// shape that disagrees with it addresses a record the other party never sweeps —
/// silently, with no error on any surface (ISC-C100).
pub const PAGE_SLOTS: u16 = 16;

/// The address root's length. Aliased rather than restated, because the only
/// value any caller passes is `ChannelRoots.ar`.
pub const ADDRESS_ROOT_LEN: usize = crate::dm::firstcontact::ROOT_LEN;

redacted_secret_newtype! {
    /// The Veilid record-owner seed for one page of one direction of one
    /// conversation.
    ///
    /// Unlike its siblings in [`crate::dm::keyrec`] and [`crate::dm::doorbell`],
    /// this one is **genuinely secret**: it is derived from `AR`, so holding it
    /// means being one of the two parties. Under Veilid a derivable owner seed is
    /// write access, which is exactly the point — see the module docs.
    boxed pub struct DmPageOwnerSeed([u8; DM_PAGE_OWNER_SEED_LEN]);
}

/// Anything that can go wrong deriving a page address.
#[derive(Debug, PartialEq, Eq)]
pub enum DmPageError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf(oxicrypt_kdf::KdfError),
}

impl std::fmt::Display for DmPageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "page address derivation failed: {e}"),
        }
    }
}

impl std::error::Error for DmPageError {}

/// The highest page a sequence number can live on: `u64::MAX / PAGE_SLOTS`.
///
/// Above it `page * PAGE_SLOTS + slot` leaves the sequence space, so the page
/// holds no position at all — whatever slot is named. [`PagePosition::new`]
/// refuses such a page, and it refuses it for the **page**, not for the slot; a
/// caller that reports which of the two was at fault compares against this
/// rather than restating the arithmetic, so there is one home for the bound.
pub const MAX_PAGE: u64 = u64::MAX / PAGE_SLOTS as u64;

/// Where a sequence number lives: which page, and which slot of it.
///
/// **Fields are private, and that is load-bearing.** A position is only valid
/// when its slot is inside the record and its page cannot overflow a sequence
/// number — and the place invalid ones come from is a *sweep*: subkey indices
/// arrive bounded by the record shape the caller opened with, not by
/// [`PAGE_SLOTS`]. A page opened with the wrong shape yields slot indices past
/// the end, and an unchecked `page * PAGE_SLOTS + slot` turns those into sequence
/// numbers belonging to the *next* page — silently, feeding wrong positions to
/// the ratchet and to the delivery acknowledgement. With one validating
/// constructor that becomes `None` at the point of the mistake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PagePosition {
    page: u64,
    slot: u16,
}

impl PagePosition {
    /// A position, if `slot` is inside the record and `page` is at most
    /// [`MAX_PAGE`].
    ///
    /// This is the entry point for the **slot-to-sequence** direction — turning
    /// "I found bytes in subkey 9 of page 3" into a sequence number. Use it
    /// rather than arithmetic, so a slot that could not have come from
    /// [`position_of`] is rejected instead of aliasing another page's position.
    pub fn new(page: u64, slot: u16) -> Option<Self> {
        if slot >= PAGE_SLOTS || page > MAX_PAGE {
            return None;
        }
        Some(Self { page, slot })
    }

    /// Which page.
    pub fn page(self) -> u64 {
        self.page
    }

    /// Which slot of it — a subkey index of the page's record.
    pub fn slot(self) -> u16 {
        self.slot
    }

    /// The sequence number this position holds — the exact inverse of
    /// [`position_of`], and total, because no invalid position can be built.
    pub fn seq(self) -> u64 {
        self.page * PAGE_SLOTS as u64 + self.slot as u64
    }
}

/// Which page and slot a sequence number occupies.
///
/// Total and injective: every sequence number has exactly one home and no two
/// share one, which is what lets a message be written once and never moved,
/// overwritten, or wrapped around.
///
/// This answers **"where does sequence *n* live"**. It does not answer "which
/// page am I up to" — see the module docs on why those are two different
/// pointers.
pub fn position_of(seq: u64) -> PagePosition {
    PagePosition {
        page: seq / PAGE_SLOTS as u64,
        slot: (seq % PAGE_SLOTS as u64) as u16,
    }
}

/// Derive the Veilid owner seed for one page:
/// `HKDF-SHA-384(salt = DM_PAGE_SALT, ikm = AR, info = DM_PAGE_ADDR ‖ lp(dir) ‖ lp(BE64(page)))`.
///
/// Deterministic and pure — no clock, no randomness, no network — so both parties
/// reach the same record from the same conversation, and a party returning after
/// a month recomputes an address it never stored.
///
/// Take the direction from [`crate::dm::ratchet::Ratchet::send_direction`] or
/// [`recv_direction`](crate::dm::ratchet::Ratchet::recv_direction) rather than
/// mapping a role onto one by hand. Passing the sending direction where the
/// receiving one was meant derives a perfectly valid seed — for your own pages —
/// and then sweeps your own writes forever, which nothing here can catch.
///
/// The direction is bound so the two halves of a conversation never collide: A's
/// page 3 and B's page 3 are unrelated records, which is what stops one party's
/// writes landing in the other's slots. The page number is bound so consecutive
/// pages are unrelated too — a co-host of page 3 learns nothing about where page
/// 4 lives, which is the scatter the whole scheme rests on.
pub fn derive_owner_seed(
    address_root: &[u8; ADDRESS_ROOT_LEN],
    direction: Direction,
    page: u64,
) -> Result<DmPageOwnerSeed, DmPageError> {
    let hkdf =
        HkdfSha384::extract(Some(domain::DM_PAGE_SALT), address_root).map_err(DmPageError::Kdf)?;

    let dir = direction.label();
    let mut info = Vec::with_capacity(domain::DM_PAGE_ADDR.len() + dir.len() + 24);
    info.extend_from_slice(domain::DM_PAGE_ADDR);
    crate::dm::push_lp(&mut info, dir);
    crate::dm::push_lp(&mut info, &page.to_be_bytes());

    let seed =
        derive_boxed_seed::<DM_PAGE_OWNER_SEED_LEN>(&hkdf, &info).map_err(DmPageError::Kdf)?;
    Ok(DmPageOwnerSeed(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte-distinct address root: a run of equal bytes would pass under a
    /// derivation that mis-sliced its input, and this does not.
    fn ar(tag: u8) -> [u8; ADDRESS_ROOT_LEN] {
        let mut out = [0u8; ADDRESS_ROOT_LEN];
        for (i, b) in out.iter_mut().enumerate() {
            *b = tag ^ (i as u8).wrapping_mul(11).wrapping_add(0x3d);
        }
        out
    }

    fn seed(tag: u8, dir: Direction, page: u64) -> String {
        let _ = oxicrypt_module::initialize();
        hex::encode(derive_owner_seed(&ar(tag), dir, page).unwrap().as_bytes())
    }

    // ---- known-answer vectors ------------------------------------------------
    //
    // The address is the wire. A uniform change to the label, the salt, the
    // length-prefix width, or the byte order of the page number would keep every
    // structural test in this file green while addressing records no other
    // implementation writes to — a conversation that silently never connects.
    //
    // Honest scope, as in `doorbell`: these were captured from this
    // implementation, so they guard against DRIFT. They cannot tell us the
    // derivation was right to begin with — only the design doc and review do
    // that.

    #[test]
    fn page_addresses_are_pinned() {
        assert_eq!(
            seed(0x41, Direction::AToB, 0),
            "f7188b50d26697b05a47ff6e8fa8f166a7a4af31397ccc5c46d0b393e5fca75b"
        );
        assert_eq!(
            seed(0x41, Direction::AToB, 1),
            "c39002df0dfb6a6c65f8d9d0d7023743f0ac593c82516e4403b07fc1d3ec06fa"
        );
        assert_eq!(
            seed(0x41, Direction::BToA, 0),
            "66b769ad77905d91ce4bc28618d0aa04231407af11930cf22119f24fef6eb47a"
        );
    }

    /// A page number that differs only in its low byte must not be confusable
    /// with one that differs only in its high byte — which is what a wrong
    /// endianness or a truncated encoding would do.
    #[test]
    fn distant_page_numbers_are_pinned() {
        assert_eq!(
            seed(0x41, Direction::AToB, 0x0102_0304_0506_0708),
            "2ba8da7b4e16602730444f93d721a4480fcb266e65afa81d5007966f0edd6696"
        );
    }

    #[test]
    fn page_slots_is_pinned() {
        assert_eq!(PAGE_SLOTS, 16);
    }

    // ---- the mapping ---------------------------------------------------------

    /// Total and injective: every sequence number has one home, no two share one.
    /// Checked across a page boundary rather than within one page, because an
    /// off-by-one in the division only shows at the seam.
    #[test]
    fn every_sequence_number_has_exactly_one_home() {
        let mut seen = std::collections::BTreeSet::new();
        for seq in 0..(PAGE_SLOTS as u64 * 4) {
            let at = position_of(seq);
            assert!(seen.insert(at), "two sequence numbers share {at:?}");
            assert_eq!(at.seq(), seq, "the mapping does not round-trip");
        }
        assert_eq!(seen.len(), PAGE_SLOTS as usize * 4);
    }

    #[test]
    fn pages_fill_before_they_advance() {
        assert_eq!(PagePosition::new(0, 0), Some(position_of(0)));
        assert_eq!(
            PagePosition::new(0, PAGE_SLOTS - 1),
            Some(position_of(PAGE_SLOTS as u64 - 1))
        );
        assert_eq!(
            PagePosition::new(1, 0),
            Some(position_of(PAGE_SLOTS as u64))
        );
    }

    /// The initiator's first channel message is sequence one, not zero — sequence
    /// zero is the first-contact entry, which travels by doorbell. So its very
    /// first page has an empty first slot, permanently. Pinned here because a
    /// collector that judged a page by being full, rather than by holding any
    /// populated slot, would stall on it forever.
    #[test]
    fn the_initiators_first_page_has_a_permanently_empty_first_slot() {
        use crate::dm::ratchet::FIRST_INITIATOR_CHANNEL_SEQ;
        let at = position_of(FIRST_INITIATOR_CHANNEL_SEQ);
        assert_eq!((at.page(), at.slot()), (0, 1));
    }

    /// The slot-to-sequence direction rejects anything `position_of` could not
    /// have produced. Without this, a page swept with the wrong record shape
    /// yields slot indices past the end, and the arithmetic quietly maps them
    /// into the next page's sequence numbers.
    #[test]
    fn a_position_outside_the_record_cannot_be_built() {
        assert!(PagePosition::new(3, 0).is_some());
        assert!(PagePosition::new(3, PAGE_SLOTS - 1).is_some());
        assert_eq!(PagePosition::new(3, PAGE_SLOTS), None, "slot past the end");
        assert_eq!(PagePosition::new(3, 31), None, "a doorbell-shaped slot");
        assert_eq!(PagePosition::new(u64::MAX, 0), None, "page would overflow");
        assert!(PagePosition::new(MAX_PAGE, 0).is_some());
        assert_eq!(PagePosition::new(MAX_PAGE + 1, 0), None, "one past the top");
    }

    /// The page bound has one home, and a caller reporting which of page or slot
    /// was at fault reads it from there — see [`crate::dm::collect::CollectError`].
    ///
    /// There is deliberately no assertion that `MAX_PAGE == u64::MAX /
    /// PAGE_SLOTS`: that compares the constant to its own definition and cannot
    /// fail. What is pinned instead is the constant's relationship to the
    /// mapping — the top of the sequence space lands on it — which a wrong value
    /// breaks.
    #[test]
    fn the_highest_page_is_where_the_sequence_space_ends() {
        assert_eq!(position_of(u64::MAX).page(), MAX_PAGE, "the top position");
        assert_ne!(
            MAX_PAGE,
            u64::MAX,
            "a legal slot on page u64::MAX holds no sequence number"
        );
    }

    /// The two directions are exact inverses across the whole space, including
    /// the very top of it, so no caller has to reason about overflow.
    #[test]
    fn the_mapping_inverts_exactly_at_both_ends() {
        for seq in [0u64, 1, 15, 16, 17, 4095, u64::MAX - 1, u64::MAX] {
            let at = position_of(seq);
            assert_eq!(at.seq(), seq, "round trip failed at {seq}");
            assert_eq!(
                PagePosition::new(at.page(), at.slot()),
                Some(at),
                "position_of produced something new() rejects, at {seq}"
            );
        }
    }

    /// A slot index is only ever a valid subkey of the record's schema.
    #[test]
    fn a_slot_is_always_within_the_record() {
        for seq in [0u64, 1, 15, 16, 4095, u64::MAX] {
            assert!(position_of(seq).slot() < PAGE_SLOTS, "seq {seq} escaped");
        }
    }

    // ---- separation ----------------------------------------------------------

    /// The two halves of a conversation must not collide, or one party's writes
    /// would land in the other's slots on the very same record.
    #[test]
    fn the_two_directions_address_different_records() {
        assert_ne!(
            seed(0x41, Direction::AToB, 7),
            seed(0x41, Direction::BToA, 7)
        );
    }

    /// Consecutive pages must be unrelated, or a co-host of one page could follow
    /// the conversation forward — which is the scatter the design rests on.
    #[test]
    fn consecutive_pages_are_unrelated() {
        let a = seed(0x41, Direction::AToB, 41);
        let b = seed(0x41, Direction::AToB, 42);
        assert_ne!(a, b);
    }

    /// Two conversations must never share a page address, however close their
    /// roots. This is what stops a shared co-host correlating them.
    #[test]
    fn distinct_conversations_address_distinct_pages() {
        assert_ne!(
            seed(0x41, Direction::AToB, 0),
            seed(0x42, Direction::AToB, 0)
        );
    }

    /// A sweep of the first several pages of both directions must be entirely
    /// distinct — no accidental structure, no repetition.
    #[test]
    fn a_conversations_page_addresses_are_all_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for dir in [Direction::AToB, Direction::BToA] {
            for page in 0..16 {
                assert!(
                    seen.insert(seed(0x41, dir, page)),
                    "page {page} of {dir:?} repeated an address"
                );
            }
        }
        assert_eq!(seen.len(), 32);
    }

    /// The seed is a conversation secret, not a public address like the key
    /// record's or the doorbell's — so it must not render itself.
    #[test]
    fn the_page_seed_does_not_render_its_bytes() {
        let _ = oxicrypt_module::initialize();
        let s = derive_owner_seed(&ar(0x41), Direction::AToB, 0).unwrap();
        assert_eq!(format!("{s:?}"), "DmPageOwnerSeed(<redacted>)");
    }
}
