//! Error surface for the Veilid transport layer.

use daemonseed_core::dm::paging::PagePosition;

/// Errors from bringing up or operating the daemonseed Veilid node.
#[derive(Debug, thiserror::Error)]
pub enum VeilidNetError {
    #[error("veilid startup failed: {0}")]
    Startup(String),

    #[error("node did not become public-internet-ready in time")]
    NotReady,

    #[error("routing error: {0}")]
    Routing(String),

    #[error("send failed: {0}")]
    Send(String),

    /// The peer ANSWERED, but does not serve the requested share/chunk — it was
    /// withdrawn (unpublished via `stop_serve`) or never offered. Distinct from a
    /// transport error (`Send` / offline / slow / dead route): this is an
    /// authoritative negative from a reachable owner, so the client can report
    /// "withdrawn" immediately instead of leaving the user to guess through
    /// timeouts (the Demonsaw failed-vs-slow-vs-withdrawn ambiguity).
    #[error("the peer no longer serves this share (withdrawn or never offered)")]
    NotServed,

    /// The sharer served content that failed verification: a SHA-384
    /// content-address mismatch (ISC-S28 / ISC-A-S20), a chunk-address mismatch,
    /// or a malformed / oversized response frame. Distinct from a transport error
    /// (`Send`) because the route is fine — the *content* is hostile — so the
    /// download engine treats it as FATAL for the share (never persisted, never
    /// resumed past), not as a resumable blip (#205: both were `Send(String)`).
    #[error("share content failed verification: {0}")]
    Integrity(String),

    #[error("invalid node identity: {0}")]
    Identity(String),

    /// The actor task is gone or dropped a reply before answering a command.
    #[error("actor channel error: {0}")]
    Actor(String),

    /// A DM channel-page publish named a position belonging to a different page
    /// than the address it was published under (#254).
    ///
    /// A caller fault at the API boundary, caught before the write is enqueued, so
    /// nothing reaches the network. Without the check the write succeeds: the frame
    /// lands in a slot of the addressed page that belongs to some other sequence
    /// number, and the reader that eventually sweeps it rejects it as misplaced —
    /// while the message it was meant to be sits nowhere at all.
    ///
    /// **The page is the fault, and the slot is not** — the slot was valid for the
    /// page it came from. Sibling of
    /// `daemonseed_core::dm::collect::CollectError::SlotOutsideRecord` in reporting
    /// the culprit rather than the symptom.
    ///
    /// **The whole position is carried, not just its page, because a log line has to
    /// identify the MESSAGE.** Two page numbers alone say a mismatch happened and
    /// leave the reader unable to name which message went missing or what sequence
    /// number the caller meant — and the sequence number is the only handle the
    /// sender, the acknowledgement and the correspondent all share. Carrying the
    /// `PagePosition` gives page, slot and sequence with nothing derivable
    /// duplicated, which is the same reason the transport takes a position rather
    /// than a loose page and slot.
    #[error(
        "dm page position (page {}, slot {}, sequence {}) is not on its address's page {address_page}",
        .position.page(), .position.slot(), .position.seq()
    )]
    DmPageWrongPage {
        /// The page the address names.
        address_page: u64,
        /// The position that was offered — its page is the one that disagrees.
        position: PagePosition,
    },

    /// A DM channel page's record was opened under a shape whose `o_cnt` is not
    /// `daemonseed_core::dm::paging::PAGE_SLOTS`, so it is not a page and is not
    /// swept (#254).
    ///
    /// **Checked in BOTH directions, and the low side is the one that hides.** A
    /// shape *above* `PAGE_SLOTS` yields slot indices the page cannot hold and
    /// surfaces as [`Self::DmPageSlotOutsideRecord`]. A shape *below* it yields no
    /// unplaceable slot at all: the sweep is bounded by the record's own `o_cnt`, so
    /// every position it produces places cleanly, and the caller gets `Ok` with a
    /// **silently truncated page** — the messages in the missing slots simply do not
    /// exist as far as the collector can tell. That is exactly the "lost message
    /// under an `Ok`" the sibling variant's docs say cannot happen, reached from the
    /// other side, so the shape is compared before any slot is read.
    #[error(
        "dm page {page}'s record has {o_cnt} slot(s), not the {} a page holds",
        daemonseed_core::dm::paging::PAGE_SLOTS
    )]
    DmPageShapeMismatch {
        /// The page whose record was opened.
        page: u64,
        /// The `o_cnt` the opened record actually carries.
        o_cnt: u16,
    },

    /// A DM channel-page sweep returned a slot the addressed page cannot hold
    /// (#254).
    ///
    /// A slot outside the page means the record was opened under a shape whose
    /// `o_cnt` exceeds `daemonseed_core::dm::paging::PAGE_SLOTS`, so the position
    /// belongs to some other page — the ISC-C100 failure mode. The page number
    /// itself cannot be at fault: `DmPageAddress` refuses a page above `MAX_PAGE` at
    /// construction.
    ///
    /// **This is now the second line, not the first.** The sweep compares the
    /// record's `o_cnt` against `PAGE_SLOTS` before reading any slot and fails as
    /// [`Self::DmPageShapeMismatch`], which is what makes the too-small direction
    /// loud as well — so a shape disagreement is caught before it can produce an
    /// unplaceable slot, and reaching this variant means the placement itself went
    /// wrong. It is kept because the alternative to reporting is skipping the slot,
    /// and a skipped slot is a lost message under an `Ok`.
    #[error("dm page sweep returned slot {slot}, which page {page}'s record cannot hold")]
    DmPageSlotOutsideRecord {
        /// The page that was swept.
        page: u64,
        /// The subkey index that came back.
        slot: u32,
    },

    /// A Phase 2+ surface (circles / shares / presence / announcements) that
    /// this crate does not implement yet.
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, VeilidNetError>;

/// Coarse class of a fetch-path failure. The download engine switches on this to
/// decide resume vs abort vs surface, WITHOUT switching on error *message
/// strings* — the #205 blocker was that a transient timeout and a content
/// integrity failure were indistinguishable, both `Send(String)`. The class is
/// derived at the site where the knowledge exists (the SHA-384 verify, the
/// malformed-frame guards, the retry loop), never re-inferred downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchErrorClass {
    /// Transport / route failure — a fragment timed out after its retry budget,
    /// the route died or would not import, or a reply went absent mid-stream.
    /// RESUMABLE: verified units are retained and the share stays Unresolved
    /// (#180 park semantics).
    Transient,
    /// The sharer served content that failed verification — SHA-384
    /// content-address mismatch, chunk-address mismatch, or a malformed /
    /// oversized frame. FATAL for the share: never persisted, never resumed past.
    Integrity,
    /// The reachable owner answered that it does not serve this share/chunk
    /// (withdrawn or never offered) — an authoritative negative, not an error of
    /// the route.
    NotServed,
    /// A local fault on the fetcher (path sanitize, disk create/write, index
    /// write). The route is unaffected and verified units are retained. This
    /// class is contributed by the download engine's own filesystem failures, so
    /// [`VeilidNetError::fetch_class`] never returns it.
    Local,
}

impl VeilidNetError {
    /// Classify this transport error for the download engine's resume/abort
    /// decision (DL-ISC-10). Never returns [`FetchErrorClass::Local`] — that
    /// class originates in the engine's own disk/path failures, not the wire.
    pub fn fetch_class(&self) -> FetchErrorClass {
        match self {
            VeilidNetError::Integrity(_) => FetchErrorClass::Integrity,
            VeilidNetError::NotServed => FetchErrorClass::NotServed,
            // Every transport / route / actor / config failure is treated as a
            // resumable transient at the fetch boundary. A local identity or
            // not-yet-implemented fault must NEVER poison-abort a share, so it
            // classifies transient (surfaced, route untouched), not integrity.
            //
            // The three DM-page faults are unreachable here — no share fetch touches
            // a channel page — and classify transient for the same reason a local
            // identity fault does: a local caller/shape fault is never grounds to
            // declare a share's CONTENT hostile.
            VeilidNetError::Send(_)
            | VeilidNetError::Routing(_)
            | VeilidNetError::Actor(_)
            | VeilidNetError::NotReady
            | VeilidNetError::Startup(_)
            | VeilidNetError::Identity(_)
            | VeilidNetError::DmPageWrongPage { .. }
            | VeilidNetError::DmPageSlotOutsideRecord { .. }
            | VeilidNetError::DmPageShapeMismatch { .. }
            | VeilidNetError::Unimplemented(_) => FetchErrorClass::Transient,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A position on `page`, for the error fixtures below. Slot 9 on page 3 makes
    /// page, slot and sequence three different numbers, so a message that rendered
    /// the wrong one of the three is visible.
    fn at(page: u64) -> PagePosition {
        PagePosition::new(page, 9).expect("slot 9 is inside a page's record")
    }

    /// **A wrong-page log line names the message, not just the mismatch.** Two page
    /// numbers alone leave a reader unable to say which message was lost or what
    /// sequence number the caller meant; the sequence number is the handle the
    /// sender, the acknowledgement and the correspondent share.
    #[test]
    fn the_wrong_page_error_renders_the_position_it_refused() {
        let rendered = VeilidNetError::DmPageWrongPage {
            address_page: 3,
            position: at(4),
        }
        .to_string();
        // Page, slot and sequence are three distinct values here (4, 9, 73), so each
        // is pinned on its own and a swapped pair cannot pass.
        assert!(rendered.contains("page 4"), "{rendered}");
        assert!(rendered.contains("slot 9"), "{rendered}");
        assert!(
            rendered.contains("sequence 73"),
            "the sequence number the caller meant must be in the line: {rendered}"
        );
        assert!(
            rendered.contains("page 3"),
            "the addressed page is the reference and must be named too: {rendered}"
        );
    }

    /// **A page record whose shape is not the page shape is refused in BOTH
    /// directions**, and the rendering says what it found against what a page holds —
    /// the too-small case being the one that would otherwise truncate a page under an
    /// `Ok`.
    #[test]
    fn the_shape_mismatch_error_renders_what_it_found_and_what_it_wanted() {
        let slots = daemonseed_core::dm::paging::PAGE_SLOTS;
        for o_cnt in [slots - 1, slots + 1, 1, 1024] {
            let rendered = VeilidNetError::DmPageShapeMismatch { page: 3, o_cnt }.to_string();
            assert!(
                rendered.contains(&format!("{o_cnt} slot")),
                "the shape it found must be in the line: {rendered}"
            );
            assert!(
                rendered.contains(&slots.to_string()),
                "the shape a page holds must be in the line: {rendered}"
            );
        }
    }

    /// DL-ISC-10: the fetch boundary types transient-transport, integrity, and
    /// not-served failures apart; the SHA-384 mismatch (an `Integrity`) is the
    /// headline case that #205 could not distinguish from a timeout.
    #[test]
    fn fetch_class_maps_each_variant_to_its_class() {
        assert_eq!(
            VeilidNetError::Integrity("sha-384 mismatch".into()).fetch_class(),
            FetchErrorClass::Integrity,
        );
        assert_eq!(
            VeilidNetError::NotServed.fetch_class(),
            FetchErrorClass::NotServed,
        );
        for e in [
            VeilidNetError::Send("Timeout".into()),
            VeilidNetError::Routing("no route".into()),
            VeilidNetError::Actor("actor gone".into()),
            VeilidNetError::NotReady,
            VeilidNetError::Startup("boot".into()),
            VeilidNetError::Identity("bad identity".into()),
            VeilidNetError::DmPageWrongPage {
                address_page: 3,
                position: at(4),
            },
            VeilidNetError::DmPageSlotOutsideRecord { page: 3, slot: 31 },
            VeilidNetError::DmPageShapeMismatch { page: 3, o_cnt: 1 },
            VeilidNetError::Unimplemented("phase-2"),
        ] {
            assert_eq!(e.fetch_class(), FetchErrorClass::Transient, "{e:?}");
        }
    }

    /// DL-ISC-10: `Local` is engine-contributed; no transport error yields it.
    #[test]
    fn fetch_class_never_returns_local_from_a_transport_error() {
        let all = [
            VeilidNetError::Integrity("x".into()),
            VeilidNetError::NotServed,
            VeilidNetError::Send("x".into()),
            VeilidNetError::Routing("x".into()),
            VeilidNetError::Actor("x".into()),
            VeilidNetError::NotReady,
            VeilidNetError::Startup("x".into()),
            VeilidNetError::Identity("x".into()),
            VeilidNetError::DmPageWrongPage {
                address_page: 1,
                position: at(2),
            },
            VeilidNetError::DmPageSlotOutsideRecord { page: 1, slot: 16 },
            VeilidNetError::DmPageShapeMismatch { page: 1, o_cnt: 32 },
            VeilidNetError::Unimplemented("x"),
        ];
        assert!(all
            .iter()
            .all(|e| e.fetch_class() != FetchErrorClass::Local));
    }
}
