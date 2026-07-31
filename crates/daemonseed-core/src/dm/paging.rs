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
//! ## An address is a checked value, not three loose primitives
//!
//! [`DmPageAddress`] binds the owner seed, the page number, and the stream into one
//! value, and it is what a transport takes. The seed alone is not enough: it
//! carries neither the page it belongs to — so a slot from a different page can be
//! named alongside it — nor the direction it was derived for, and both parties can
//! derive both streams, so the wrong one is a *valid* address for the wrong record.
//! The stream rides in the type parameter ([`Sending`] / [`Receiving`]) so a sweep
//! handed a sending address does not compile, and the direction itself is taken
//! from the ratchet's own accessors rather than from an argument.
//!
//! **The guarantee is relative to the ratchet passed in, and stops there.** The
//! address root and the ratchet are two unbound arguments; nothing checks that the
//! ratchet belongs to the conversation the root came from, so a caller holding two
//! channels whose local roles differ can resolve one conversation's root against
//! the other's ratchet and get a valid, wrongly-directed address — silently. See
//! [`DmPageAddress`] for the shape of that mistake and where the structural fix is
//! tracked.
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

use std::marker::PhantomData;

use oxicrypt_kdf::HkdfSha384;

use crate::dm::domain;
use crate::dm::ratchet::{Direction, Ratchet};
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
    /// The page is above [`MAX_PAGE`], so it holds no position whatever slot is
    /// named — `page * PAGE_SLOTS + slot` leaves the sequence space.
    ///
    /// Named as the sibling of [`crate::dm::collect::CollectError::PageBeyondSequenceSpace`]
    /// because it is the same fault seen from the addressing end rather than the
    /// collecting end. [`DmPageAddress`] refuses such a page, which is what lets a
    /// sweep of an address assume every in-record slot places.
    PageBeyondSequenceSpace {
        /// The page that was asked for.
        page: u64,
    },
}

impl std::fmt::Display for DmPageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "page address derivation failed: {e}"),
            Self::PageBeyondSequenceSpace { page } => write!(
                f,
                "page {page} is above the highest page a sequence number can live on ({MAX_PAGE})"
            ),
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
/// # A page-0 fixture cannot tell a slot from a sequence
///
/// **Never test anything that converts between a slot and a sequence number
/// using a position on page 0.** On page 0 [`Self::seq`] reduces to
/// `0 * PAGE_SLOTS + slot`, so a position's slot and its sequence number are the
/// *same integer* — and a fixture built there cannot distinguish an
/// implementation that returns one from an implementation that returns the
/// other. Neither can it distinguish a derivation that carries its page argument
/// from one that hardcoded zero.
///
/// This is not hypothetical: two such mutants survived the entire workspace
/// suite, one of them aliasing every page of a conversation onto page 0's sixteen
/// slots so that message sixteen would overwrite message zero with both ends
/// agreeing (#272, found closing #254).
///
/// Use **page 3, slot 9 — sequence 57**, or any position whose three numbers
/// differ, so substituting any one of them for another is caught. Where page 0 is
/// genuinely the subject — a first-message path, the initiator's permanently
/// empty first slot, a cold probe — keep the page-0 fixture *and* add a non-zero
/// sibling rather than moving it.
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
/// **This is the raw primitive; [`DmPageAddress`] is what a transport takes.** A
/// seed on its own carries neither the page it belongs to nor the stream it was
/// derived for, so the two mistakes below are available to anyone holding one.
/// Reach for this directly only to pin the derivation itself.
///
/// Take the direction from [`crate::dm::ratchet::Ratchet::send_direction`] or
/// [`recv_direction`](crate::dm::ratchet::Ratchet::recv_direction) rather than
/// mapping a role onto one by hand. Passing the sending direction where the
/// receiving one was meant derives a perfectly valid seed — for your own pages —
/// and then sweeps your own writes forever, which nothing in *this* function's
/// signature can catch. [`DmPageAddress`] is what catches it: the stream lives in
/// its type parameter, so naming the wrong direction *for a given ratchet* does not
/// compile. That is the reason to prefer it over this primitive — and the limit of
/// what it buys, since pairing a root with the wrong conversation's ratchet reaches
/// the same place (see that type's docs, and #270).
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

/// Which of a conversation's two streams a page belongs to, **as a type**.
///
/// Both implementors are uninhabited, so the only thing either can ever do is
/// parameterise [`DmPageAddress`]. That is the point: the stream is carried in the
/// type, so a publish handed a receiving address — or a sweep handed a sending one —
/// does not compile. Before it was a type it was a comment, and
/// [`derive_owner_seed`]'s own docs record what the comment bought: the wrong
/// direction derives a perfectly valid seed for *your own* pages, and a sweep then
/// reads your own writes back forever while the correspondent's stream sits
/// untouched. Nothing at runtime can see that.
///
/// **What the marker fixes is the mapping, not the pairing.** It resolves "which
/// stream" against *the ratchet it is given*, so no call site writes a
/// role-to-direction mapping by hand. It cannot see whether that ratchet is the
/// right one for the address root beside it — see [`DmPageAddress`].
///
/// **Sealed.** The two mappings are the ratchet's own accessors and nothing else;
/// a third implementation could only be a role-to-direction mapping written by
/// hand, which is exactly what [`crate::dm::ratchet::Role`] exists to prevent.
pub trait PageDirection: sealed::Sealed {
    /// The absolute [`Direction`] this marker names for `ratchet`.
    fn of(ratchet: &Ratchet) -> Direction;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Sending {}
    impl Sealed for super::Receiving {}
}

/// The stream this end **sends** on — [`Ratchet::send_direction`].
///
/// Uninhabited: a marker, never a value.
pub enum Sending {}

/// The stream this end **receives** on — [`Ratchet::recv_direction`].
///
/// Uninhabited: a marker, never a value.
pub enum Receiving {}

impl PageDirection for Sending {
    fn of(ratchet: &Ratchet) -> Direction {
        ratchet.send_direction()
    }
}

impl PageDirection for Receiving {
    fn of(ratchet: &Ratchet) -> Direction {
        ratchet.recv_direction()
    }
}

/// One page of one stream of one conversation: its owner seed, its page number,
/// and the direction it was derived for, bound together and checked.
///
/// **Why the three travel as one value.** They are three facts about a single
/// record, and every way of pulling them apart fails silently:
///
/// - A seed beside a loose slot lets a caller derive the seed for page A and name
///   a slot belonging to page B. The write succeeds, the frame lands where nobody
///   looks, and the sequence number it declares is one no reader will ever
///   associate with that slot. [`PagePosition`] was given private fields and a
///   validating constructor to stop exactly this arithmetic escaping; a transport
///   taking a seed and a bare `u32` re-opens the hole one layer up.
/// - A seed with no direction attached is the [`derive_owner_seed`] hazard above:
///   both streams are derivable by both parties, so the wrong one is a valid
///   address for the wrong record.
///
/// **The direction is never passed in** — it comes from the ratchet's own
/// [`send_direction`](Ratchet::send_direction) /
/// [`recv_direction`](Ratchet::recv_direction) via the [`PageDirection`] marker,
/// so the role-to-direction mapping happens once, inside [`crate::dm::ratchet`],
/// and a call site has no direction argument to get wrong.
///
/// **The guarantee is stated relative to the ratchet argument, and it is worth
/// being exact about that rather than claiming the mistake is impossible.**
/// `address_root` and `ratchet` arrive as two unbound arguments, and nothing here
/// checks that the ratchet belongs to the conversation the root came from. An
/// application holding two channels whose local roles differ can resolve one
/// conversation's root against the other's ratchet: the marker then reads the
/// *other* ratchet's directions, so a [`DmPageAddress<Receiving>`](DmPageAddress)
/// can name the first conversation's *sending* page. That address is valid, its
/// sweep returns `Ok` with `found > 0`, and this end reads its own writes back
/// forever — the failure the marker eliminates *within* a ratchet, reached by
/// mispairing the two arguments instead. A root fingerprint carried in
/// [`Ratchet`], which would let this constructor refuse the pair, is tracked as
/// **#270** and deliberately not built here. Until then: take the root and the
/// ratchet from the same conversation record, never from two lookups.
///
/// **Moved, not borrowed, and that is a constraint rather than a taste (#244).**
/// The owner seed is the conversation's write *capability*: under Veilid a
/// derivable owner seed is write access, which is why it is a boxed, redacted,
/// zeroize-on-drop [`DmPageOwnerSeed`] and deliberately neither `Clone` nor
/// constructible from bytes outside this module. A transport must *move* it into
/// the command that crosses its channel, so the address moves too — a `&`
/// parameter could only be honoured by copying the secret into a fresh
/// non-zeroizing buffer, which is the copy the type exists to remove. So the
/// address is single-use: **derive one per call**, and read the seed through
/// [`owner_seed`](Self::owner_seed) — a borrow, for the one thing that needs it, a
/// keypair derivation — rather than taking it out. Derivation is pure (no clock,
/// no randomness, no network), which is what makes re-deriving the right answer
/// rather than a workaround.
pub struct DmPageAddress<D: PageDirection> {
    owner_seed: DmPageOwnerSeed,
    page: u64,
    direction: Direction,
    stream: PhantomData<D>,
}

impl DmPageAddress<Sending> {
    /// The address of one page of the stream this ratchet **sends** on — where our
    /// own outbound frames are published.
    ///
    /// Fails with [`DmPageError::PageBeyondSequenceSpace`] for a page above
    /// [`MAX_PAGE`], which no position can live on.
    pub fn sending(
        address_root: &[u8; ADDRESS_ROOT_LEN],
        ratchet: &Ratchet,
        page: u64,
    ) -> Result<Self, DmPageError> {
        Self::derive(address_root, ratchet, page)
    }
}

impl DmPageAddress<Receiving> {
    /// The address of one page of the stream this ratchet **receives** on — where
    /// the correspondent's frames are swept from.
    ///
    /// Fails with [`DmPageError::PageBeyondSequenceSpace`] for a page above
    /// [`MAX_PAGE`], which no position can live on.
    pub fn receiving(
        address_root: &[u8; ADDRESS_ROOT_LEN],
        ratchet: &Ratchet,
        page: u64,
    ) -> Result<Self, DmPageError> {
        Self::derive(address_root, ratchet, page)
    }
}

impl<D: PageDirection> DmPageAddress<D> {
    /// The shared body of both constructors — one derivation, so the two named
    /// entry points differ in nothing but which of the ratchet's directions they
    /// ask for.
    fn derive(
        address_root: &[u8; ADDRESS_ROOT_LEN],
        ratchet: &Ratchet,
        page: u64,
    ) -> Result<Self, DmPageError> {
        // Refused BEFORE the derivation, so an address never names a page that
        // holds no position: it is what lets a sweep of this address treat a
        // `PagePosition::new` failure as the record shape's fault alone
        // (ISC-C100) rather than as an ambiguity between shape and page.
        if page > MAX_PAGE {
            return Err(DmPageError::PageBeyondSequenceSpace { page });
        }
        let direction = D::of(ratchet);
        Ok(Self {
            owner_seed: derive_owner_seed(address_root, direction, page)?,
            page,
            direction,
            stream: PhantomData,
        })
    }

    /// Which page this address names. At most [`MAX_PAGE`], by construction.
    pub fn page(&self) -> u64 {
        self.page
    }

    /// The absolute direction this address was derived for.
    ///
    /// Exposed because a frame needs its direction at three places per message —
    /// the authorship signature, the page address, and the receive-side signature
    /// reconstruction — and this address already resolved it from the ratchet. A
    /// caller reading it here does not map a role onto a direction a second time.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Borrow the record-owner seed, to derive the Veilid owner keypair from.
    ///
    /// A borrow because that derivation only reads it, and because the seed has no
    /// second home to go to: see the type's docs on why the address is moved
    /// rather than borrowed. Callers must not copy these bytes into a
    /// non-zeroizing buffer.
    pub fn owner_seed(&self) -> &DmPageOwnerSeed {
        &self.owner_seed
    }
}

/// Hand-written rather than derived: `#[derive(Debug)]` on a generic would demand
/// `D: Debug`, which an uninhabited marker cannot satisfy. The seed renders through
/// its own redacted `Debug`, so this leaks nothing (ISC-A-C1).
impl<D: PageDirection> std::fmt::Debug for DmPageAddress<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmPageAddress")
            .field("direction", &self.direction)
            .field("page", &self.page)
            .field("owner_seed", &self.owner_seed)
            .finish()
    }
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

    // ---- the checked address -------------------------------------------------

    /// A recipient's ratchet, which is the cheap one to build: it takes only the
    /// PUBLIC half of the opening ephemeral, so no keygen is needed and the bytes
    /// are never inspected. Its role fixes both directions —
    /// `send_direction() == BToA`, `recv_direction() == AToB` — so one ratchet
    /// exercises both markers.
    fn recipient_ratchet() -> Ratchet {
        let _ = oxicrypt_module::initialize();
        Ratchet::recipient(&[0x5c; 32], Box::new([0x11; oxicrypt_ml_kem::EK_LEN]))
            .expect("open a recipient ratchet")
    }

    /// **The refactor did not move a single address.** Every assertion carries the
    /// hex from `page_addresses_are_pinned` above — the same known-answer vectors,
    /// reached through [`DmPageAddress`] instead of the raw derivation.
    ///
    /// This is the assertion that matters most in this file. A checked address type
    /// that quietly changed what it derives would move every conversation to
    /// records no other client writes to, and every structural test here would stay
    /// green: the seeds would still be distinct per page, distinct per direction,
    /// distinct per root, and redacted in `Debug`. Only a pinned byte string
    /// notices.
    ///
    /// It doubles as the direction wiring's oracle. This is a RECIPIENT ratchet, so
    /// `sending` must resolve to `BToA` and `receiving` to `AToB`; a `Sending`
    /// marker wired to `recv_direction` swaps the two vectors and fails both halves
    /// at once.
    ///
    /// **And it pins the PAGE ARGUMENT, which is why page 1 is here.** On page 0
    /// alone a `derive` that dropped its page and passed a hardcoded zero to
    /// [`derive_owner_seed`] is byte-identical to the correct one, so every vector
    /// matches and nothing in this file notices — while in production every page of
    /// a conversation would alias page 0's sixteen slots, message sixteen
    /// overwriting message zero with both ends agreeing and no error anywhere. The
    /// page-1 vector is independently derived, so it is the value a lost page
    /// argument cannot produce.
    #[test]
    fn the_address_type_derives_the_pinned_seed_for_its_stream() {
        let r = recipient_ratchet();

        let sending = DmPageAddress::sending(&ar(0x41), &r, 0).expect("sending address");
        let receiving = DmPageAddress::receiving(&ar(0x41), &r, 0).expect("receiving address");

        assert_eq!(
            hex::encode(sending.owner_seed().as_bytes()),
            "66b769ad77905d91ce4bc28618d0aa04231407af11930cf22119f24fef6eb47a",
            "a recipient SENDS on b2a — this is `page_addresses_are_pinned`'s BToA \
             vector, and a different value means the address graph moved"
        );
        assert_eq!(
            hex::encode(receiving.owner_seed().as_bytes()),
            "f7188b50d26697b05a47ff6e8fa8f166a7a4af31397ccc5c46d0b393e5fca75b",
            "a recipient RECEIVES on a2b — this is `page_addresses_are_pinned`'s \
             AToB vector"
        );

        // Page ONE, through the same type: `page_addresses_are_pinned`'s AToB page-1
        // vector, which is what the address must reach when it is asked for page 1
        // rather than what page 0 happens to derive.
        let page_one = DmPageAddress::receiving(&ar(0x41), &r, 1).expect("page-1 address");
        assert_eq!(
            hex::encode(page_one.owner_seed().as_bytes()),
            "c39002df0dfb6a6c65f8d9d0d7023743f0ac593c82516e4403b07fc1d3ec06fa",
            "the address must carry its PAGE into the derivation — this is \
             `page_addresses_are_pinned`'s AToB page-1 vector, and a page argument \
             dropped on the way to `derive_owner_seed` yields page 0's instead"
        );
        assert_ne!(
            page_one.owner_seed().as_bytes(),
            receiving.owner_seed().as_bytes(),
            "page 1 and page 0 of one stream must be different records"
        );

        assert_eq!(sending.direction(), Direction::BToA);
        assert_eq!(receiving.direction(), Direction::AToB);
        assert_eq!(sending.page(), 0);
        assert_eq!(receiving.page(), 0);
        assert_eq!(page_one.page(), 1);
    }

    /// The two streams of one conversation must address different records at the
    /// same page number, or one party's writes land in the other's slots.
    ///
    /// Distinct from `the_two_directions_address_different_records` above, which
    /// pins the same property of the raw derivation: what is checked here is that
    /// the two MARKERS reach the two directions, which a pair of constructors both
    /// calling `send_direction` would break while leaving that test green.
    #[test]
    fn sending_and_receiving_address_different_records() {
        let r = recipient_ratchet();
        for page in [0u64, 1, 4_096] {
            let s = DmPageAddress::sending(&ar(0x41), &r, page).unwrap();
            let v = DmPageAddress::receiving(&ar(0x41), &r, page).unwrap();
            assert_ne!(
                s.owner_seed().as_bytes(),
                v.owner_seed().as_bytes(),
                "page {page} of the two streams shares a record"
            );
            assert_ne!(s.direction(), v.direction());
            // The page each address REPORTS is the page it was asked for. Without
            // this the loop compares two addresses at one page and never observes
            // the page at all, so an address that stored some other page number —
            // and derived under it — passes every assertion above.
            assert_eq!(s.page(), page, "the sending address forgot its page");
            assert_eq!(v.page(), page, "the receiving address forgot its page");
        }
    }

    /// **A swept slot plus the page it was swept from rebuilds the sender's
    /// sequence number.** This is the runnable twin of the reconstruction the
    /// two-node tests make on the far side of a real sweep: a collector holds a
    /// subkey index and the page it addressed, and nothing else, so this arithmetic
    /// is the only thing that can tell it which message it is looking at.
    ///
    /// Every page here is NON-ZERO and every slot differs from its own sequence
    /// number, which is the degeneracy that let an earlier mutation survive: on page
    /// 0 a position is numerically indistinguishable from its slot, so a
    /// reconstruction that dropped the page entirely still produced the right answer.
    #[test]
    fn a_swept_slot_and_its_page_rebuild_the_senders_sequence() {
        for (page, slot, seq) in [
            (3u64, 9u16, 57u64),
            (1, 0, 16),
            (1, PAGE_SLOTS - 1, 31),
            (256, 5, 4_101),
        ] {
            // What the sender derived, from a sequence number alone.
            let sent = position_of(seq);
            assert_eq!((sent.page(), sent.slot()), (page, slot));
            // What the collector rebuilds, from the swept slot and the swept page.
            let rebuilt = PagePosition::new(page, slot).expect("a slot inside the record");
            assert_eq!(
                rebuilt.seq(),
                seq,
                "page {page} slot {slot} must rebuild sequence {seq} — a \
                 reconstruction that dropped the page yields {slot} instead"
            );
            assert_eq!(
                rebuilt, sent,
                "the two directions must agree on the position"
            );
            assert_ne!(
                rebuilt.seq(),
                u64::from(slot),
                "the vector is blind if the sequence number equals the slot"
            );
        }
    }

    /// A page above [`MAX_PAGE`] holds no position at all, so an address for it is
    /// refused rather than derived — which is what lets a sweep of an address blame
    /// the record shape, and only the record shape, for a slot that will not place.
    ///
    /// Checked on both constructors: they share a body, and a page bound that lived
    /// in only one of them would leave the other deriving unusable addresses.
    #[test]
    fn an_address_above_the_top_page_is_refused() {
        let r = recipient_ratchet();
        for page in [MAX_PAGE + 1, u64::MAX] {
            assert_eq!(
                DmPageAddress::sending(&ar(0x41), &r, page).unwrap_err(),
                DmPageError::PageBeyondSequenceSpace { page },
            );
            assert_eq!(
                DmPageAddress::receiving(&ar(0x41), &r, page).unwrap_err(),
                DmPageError::PageBeyondSequenceSpace { page },
            );
        }
        assert!(DmPageAddress::sending(&ar(0x41), &r, MAX_PAGE).is_ok());
        assert!(DmPageAddress::receiving(&ar(0x41), &r, MAX_PAGE).is_ok());
    }

    /// The address wraps the conversation's write capability, so it must not render
    /// it — the same obligation `the_page_seed_does_not_render_its_bytes` puts on
    /// the seed, re-checked on the wrapper because a derived `Debug` on a struct
    /// holding it would be the obvious way to lose the property.
    ///
    /// The exact-string assertion is the primary check; the two below survive a
    /// change to the struct's field names or ordering, which the exact string does
    /// not. Both are matched against MULTI-BYTE renderings on purpose: a
    /// single-byte decimal is one to three digits, and the rendering's own page
    /// number is digits, so `contains(byte.to_string())` fires on a seed whose first
    /// byte happens to read like part of the page — 1 in 256 for a one-digit page.
    /// A flaky security test is worse than none, so the needles here are long enough
    /// that no page number can supply them.
    #[test]
    fn an_address_does_not_render_its_seed() {
        let r = recipient_ratchet();
        let addr = DmPageAddress::receiving(&ar(0x41), &r, 7).unwrap();
        let rendered = format!("{addr:?}");
        assert_eq!(
            rendered,
            "DmPageAddress { direction: AToB, page: 7, owner_seed: DmPageOwnerSeed(<redacted>) }"
        );

        let seed = addr.owner_seed().as_bytes();
        // A derived `Debug` on the array or on a tuple newtype renders the bytes in
        // decimal, comma-separated. Three bytes of that is 5–11 characters of digits
        // and separators, which nothing else in this rendering can produce.
        let as_decimals = format!("{}, {}, {}", seed[0], seed[1], seed[2]);
        assert!(
            !rendered.contains(&as_decimals),
            "seed bytes leaked in decimal: {rendered}"
        );
        // And a hex rendering: sixteen hex characters, likewise unreachable by
        // accident.
        let as_hex = hex::encode(&seed[..8]);
        assert!(
            !rendered.contains(&as_hex),
            "seed bytes leaked in hex: {rendered}"
        );
    }
}
