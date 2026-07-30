//! Integration test (#234, ISC-C42): node A publishes sealed channel frames into
//! slots of a DM channel page, and node B — deriving the same page address from the
//! conversation's address root alone — sweeps them back paired with the checked
//! position each was written to.
//!
//! This is the live oracle for the transport half of the channel. The unit tests
//! prove the arithmetic and the funnel classification; only two independent nodes
//! can prove that a frame put into slot *n* of a record derived at one end comes
//! back out of slot *n* of the record derived at the other. Four properties are
//! unreachable without it, and every one of them fails SILENTLY:
//!
//! 1. **The slot is honoured.** A publish that ignored its argument and wrote
//!    subkey 0 would round-trip a single message perfectly. So the frames go to
//!    NON-ZERO slots, and the sweep must hand back the positions they were written
//!    to.
//! 2. **Two writes to one page both survive.** The page is the funnel's coalescing
//!    scope, so a coalescible write kind would collapse two concurrent publishes
//!    last-writer-wins — dropping one message off the wire while its `publish_dm_page`
//!    still returns `Ok(())`. The two publishes below are issued CONCURRENTLY for
//!    exactly this reason; serialised, the funnel never holds two pending writes to
//!    one record and the property goes untested.
//! 3. **An unwritten page is empty, not an error.** Collection probes the frontier
//!    page ahead of the one being filled, so a sweep of a page nobody has written is
//!    the ordinary steady state and must be `Ok` with no slots.
//! 4. **Publish and sweep address the same record.** The record shape is part of the
//!    address; driving the round trip from opposite ends is the only oracle that
//!    fails when the two halves disagree about it.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network. This
//! VM cannot: something in the QEMU bridge eats the Veilid connection, so attach
//! returns `NotReady` after the full 180 s timeout (measured 2026-07-28). Run it on
//! a real-network host:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_dm_page -- --ignored --nocapture
//!
//! It drives the productized `VeilidNetHandle` surface the app drives, and reuses
//! the REAL daemonseed page arithmetic (`dm::paging::{DmPageAddress, position_of,
//! PagePosition}`) — no addressing is reimplemented here. The addresses come from
//! real ratchets, so the direction each end uses is the ratchet's own and never a
//! role mapped onto one by hand (#254).

use std::collections::{BTreeMap, BTreeSet};

use daemonseed_core::dm::paging::{self, DmPageAddress, PagePosition};
use daemonseed_core::dm::ratchet::{EphemeralDecapKey, Ratchet, Role};
use daemonseed_core::identity::keys::{derive_identity_keys, Identity};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig};

/// A node config with a fresh daemonseed-derived node identity, a distinct listen
/// port, and its own storage dir — so two can coexist in one process. The node
/// identity is per-node and unrelated to the *conversation* whose page is under
/// test: the page address derives from the address root, never from a node key.
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_page{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

/// A fresh address root for this run.
///
/// Random per run, and that is load-bearing rather than hygiene: the page address
/// is deterministic in the root and the record PERSISTS on the public DHT, so a
/// fixed root would sweep a previous run's frames back and pass on stale bytes.
/// Entropy comes from a throwaway mnemonic-derived node seed — the crate already
/// depends on that, and it saves pulling an RNG into the dev-deps.
fn fresh_address_root() -> [u8; paging::ADDRESS_ROOT_LEN] {
    let throwaway =
        derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let entropy = throwaway.veilid_node_seed.as_bytes();
    let mut root = [0u8; paging::ADDRESS_ROOT_LEN];
    for (dst, src) in root.iter_mut().zip(entropy.iter().cycle()) {
        *dst = *src;
    }
    root
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored"]
async fn frames_published_to_page_slots_sweep_back_in_the_slots_they_were_written_to() {
    oxicrypt_module::initialize().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-dm-page-it");
    let _ = std::fs::remove_dir_all(&base);

    let address_root = fresh_address_root();

    // The two parties' ratchets over one first-contact secret: A knocked, B was
    // knocked at. They exist here only to supply the *direction* each end addresses
    // with — `DmPageAddress` takes it from `send_direction` / `recv_direction`, which
    // is what makes A's sending stream and B's receiving stream provably the same
    // one rather than two hand-written constants that happen to match.
    let ss0 = [0x3b; 32];
    let opening_eph =
        derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let ratchet_a = Ratchet::initiator(
        &ss0,
        Box::new(*opening_eph.kem.encapsulation_key()),
        EphemeralDecapKey::new(Box::new(*opening_eph.kem.decapsulation_key())),
    )
    .expect("A opens the ratchet as initiator");
    let ratchet_b = Ratchet::recipient(&ss0, Box::new(*opening_eph.kem.encapsulation_key()))
        .expect("B opens the ratchet as recipient");
    assert_eq!(ratchet_a.role(), Role::Initiator);
    assert_eq!(ratchet_b.role(), Role::Recipient);
    assert_eq!(
        ratchet_a.send_direction(),
        ratchet_b.recv_direction(),
        "A's sending stream and B's receiving stream must be the same one, or \
         nothing below is a round trip"
    );

    let (node_a, _rx_a) = VeilidNet::start(node_config(":5174", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, _rx_b) = VeilidNet::start(node_config(":5175", &base.join("B")))
        .await
        .expect("start B");

    node_a
        .attach_and_wait(180)
        .await
        .expect("A public-internet-ready");
    node_b
        .attach_and_wait(180)
        .await
        .expect("B public-internet-ready");

    // ── both ends derive the same page ───────────────────────────────────────
    // A addresses its SENDING stream, B its RECEIVING one, and those are the same
    // stream. Nothing about the address is transmitted — the derivation is the whole
    // discovery mechanism, so two addresses computed independently must be
    // byte-identical or nothing that follows means anything.
    //
    // Each use derives its own address rather than reusing one: the owner seed
    // inside is the conversation's write capability, so it is deliberately not
    // `Clone` and the transport takes the address by value (#244/#254). The
    // derivation is pure, which is what makes re-deriving the right answer rather
    // than a workaround.
    // A NON-ZERO page, and that is load-bearing rather than arbitrary. On page 0 a
    // position is numerically indistinguishable from its own slot and the addressed
    // page is indistinguishable from a hardcoded zero, so `assert_eq!(at.page(),
    // PAGE)` is dead, the sequence numbers below equal their slots, and a transport
    // that placed every swept slot on page 0 regardless would round-trip this test
    // perfectly. Page 3 makes the page, the slot and the sequence three different
    // numbers at every assertion.
    const PAGE: u64 = 3;
    let addr_a = || {
        DmPageAddress::sending(&address_root, &ratchet_a, PAGE)
            .expect("A derives its sending page address")
    };
    let addr_b = || {
        DmPageAddress::receiving(&address_root, &ratchet_b, PAGE)
            .expect("B derives its receiving page address")
    };
    assert_eq!(
        addr_a().owner_seed().as_bytes(),
        addr_b().owner_seed().as_bytes(),
        "both ends must derive the same page record from the address root alone"
    );

    // ── two messages, two slots, NEITHER of them slot 0 ──────────────────────
    // Slots come from sequence numbers via the real arithmetic, as the sender will.
    // Both are on the same page, which is what makes them a coalescing pair; both
    // are non-zero, so a transport that ignored the slot and always wrote subkey 0
    // cannot round-trip them.
    // Sequences 57 and 51 — slots 9 and 3 of page 3. Derived from the page rather
    // than typed, so the pair moves with `PAGE` and cannot silently drift onto
    // another page.
    const SLOTS: u64 = paging::PAGE_SLOTS as u64;
    const FIRST_SEQ: u64 = PAGE * SLOTS + 9;
    const SECOND_SEQ: u64 = PAGE * SLOTS + 3;
    let first = paging::position_of(FIRST_SEQ);
    let second = paging::position_of(SECOND_SEQ);
    assert_eq!(
        first.page(),
        PAGE,
        "sequence {FIRST_SEQ} must live on the page under test"
    );
    assert_eq!(
        second.page(),
        PAGE,
        "sequence {SECOND_SEQ} must live on the page under test"
    );
    assert_ne!(first.slot(), 0, "the test is blind if the slot is 0");
    assert_ne!(second.slot(), 0, "the test is blind if the slot is 0");
    assert_ne!(first.slot(), second.slot());
    // The three numbers must be three numbers, or the assertions downstream cannot
    // tell a page from a slot from a sequence.
    assert_ne!(first.seq(), u64::from(first.slot()));
    assert_ne!(second.seq(), u64::from(second.slot()));

    let frame_first = format!("channel frame at sequence {FIRST_SEQ}").into_bytes();
    let frame_second = format!("channel frame at sequence {SECOND_SEQ}").into_bytes();

    // Issued CONCURRENTLY, deliberately. Both commands reach the write funnel
    // before either dispatches, which is the only arrangement in which a coalescing
    // classification could actually collapse them. Awaiting the two publishes in
    // sequence would leave the funnel holding one pending write to this record at a
    // time, and the anti-coalescing property — the one whose failure mode is a
    // message silently missing from the wire under an `Ok(())` — would go untested.
    let (published_first, published_second) = tokio::join!(
        node_a.publish_dm_page(addr_a(), first, frame_first.clone()),
        node_a.publish_dm_page(addr_a(), second, frame_second.clone()),
    );
    published_first.expect("A publishes the first frame");
    published_second.expect("A publishes the second frame");

    // ── B sweeps the page from the other end ─────────────────────────────────
    // DHT writes are eventually consistent; poll rather than assume convergence.
    // Wait for BOTH slots — settling for one would accept exactly the coalescing
    // bug this test exists to catch.
    let mut swept = Vec::new();
    for attempt in 0..30 {
        match node_b.sweep_dm_page(addr_b()).await {
            Ok((slots, outcome)) => {
                eprintln!(
                    "attempt {attempt}: {} slot(s) back, outcome {outcome:?}",
                    slots.len()
                );
                if slots.len() == 2 {
                    swept = slots;
                    break;
                }
            }
            Err(e) => eprintln!("attempt {attempt}: sweep error {e}, retrying"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    assert_eq!(
        swept.len(),
        2,
        "both frames must survive to the wire — one slot back means two writes to \
         one page collapsed, which is a message lost under a successful publish"
    );

    // The positions must be the ones written to, not positional indices and not
    // slot zero. They come back as checked `PagePosition`s built against the
    // ADDRESSED page, so a sweep that placed its slots on some other page — or on
    // page zero regardless — fails here rather than handing a collector positions
    // nothing confirmed.
    let positions: BTreeSet<PagePosition> = swept.iter().map(|(at, _)| *at).collect();
    assert_eq!(
        positions,
        BTreeSet::from([first, second]),
        "the sweep must return the positions the frames were written to"
    );
    for at in &positions {
        assert_eq!(
            at.page(),
            PAGE,
            "a swept position must be on the page swept"
        );
    }

    // ...and each position must carry ITS OWN frame. Two frames in the right two
    // slots but swapped would pass a position-set check and then hand the collector
    // a frame whose declared sequence number disagrees with where it was found.
    let by_position: BTreeMap<PagePosition, Vec<u8>> = swept.into_iter().collect();
    assert_eq!(
        by_position.get(&first),
        Some(&frame_first),
        "the frame for sequence {FIRST_SEQ} must come back from its own position"
    );
    assert_eq!(
        by_position.get(&second),
        Some(&frame_second),
        "the frame for sequence {SECOND_SEQ} must come back from its own position"
    );

    // ── slot + swept page → the sender's sequence number ─────────────────────
    // The collector's own arithmetic, and the thing this loop is here to exercise:
    // it holds a SUBKEY INDEX and the page it addressed, and from those two facts
    // alone must recover which message it is looking at.
    //
    // It is rebuilt through `PagePosition::new(PAGE, slot)` rather than read off the
    // returned key. `PagePosition` derives `Eq` and `Ord` over `(page, slot)` and
    // `seq()` is a pure function of those, so `by_position.get_key_value(&at).0` is
    // field-identical to the probe by construction — asserting on its `seq()` compares
    // the probe to itself and cannot fail, which is what this assertion had degenerated
    // into. Reconstructing from the swept slot puts the arithmetic back under test.
    for (probe, expected_seq) in [(first, FIRST_SEQ), (second, SECOND_SEQ)] {
        let swept_at = *by_position
            .get_key_value(&probe)
            .expect("the position came back")
            .0;
        let rebuilt = PagePosition::new(PAGE, swept_at.slot())
            .expect("a swept slot must be inside the page's record");
        assert_eq!(
            rebuilt.seq(),
            expected_seq,
            "slot {} on page {PAGE} must rebuild sequence {expected_seq} — a \
             reconstruction that lost the page yields {} instead",
            swept_at.slot(),
            swept_at.slot()
        );
        assert_eq!(
            rebuilt, swept_at,
            "the rebuilt position must be the one the sweep handed back"
        );
    }

    // ── an unwritten page is empty, not an error ─────────────────────────────
    // Collection probes the frontier page ahead of the one being filled, so this is
    // the ordinary steady state, not a failure. A page far past anything either end
    // has touched, in the opposite direction for good measure.
    // Addressed off A's ratchet, whose RECEIVING stream is the other one — a sweep
    // only ever takes a receiving address, so the opposite stream is reached by
    // asking the other party's ratchet rather than by naming a direction.
    const UNWRITTEN_PAGE: u64 = 4_096;
    let unwritten = DmPageAddress::receiving(&address_root, &ratchet_a, UNWRITTEN_PAGE)
        .expect("derive an unwritten page's address");
    assert_ne!(
        unwritten.direction(),
        addr_b().direction(),
        "the unwritten page must be on the OTHER stream"
    );
    let (empty, outcome) = node_b
        .sweep_dm_page(unwritten)
        .await
        .expect("sweeping a page nobody has written must be Ok, not Err");
    eprintln!("unwritten page sweep: outcome {outcome:?}");
    assert!(
        empty.is_empty(),
        "a page nobody has written must come back with no slots"
    );
    assert_eq!(
        outcome.found, 0,
        "no slot of an unwritten page is populated"
    );
    assert_eq!(
        outcome.attempted,
        u32::from(paging::PAGE_SLOTS),
        "a sweep must attempt every slot of the record, bounded by the page shape"
    );

    eprintln!(
        "ISC-C42 live oracle: two frames -> two non-zero slots of one page -> swept \
         back from the far end with their slots OK"
    );
}
