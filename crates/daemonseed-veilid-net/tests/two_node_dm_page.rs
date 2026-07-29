//! Integration test (#234, ISC-C42): node A publishes sealed channel frames into
//! slots of a DM channel page, and node B — deriving the same page address from the
//! conversation's address root alone — sweeps them back paired with the slot each
//! was written to.
//!
//! This is the live oracle for the transport half of the channel. The unit tests
//! prove the arithmetic and the funnel classification; only two independent nodes
//! can prove that a frame put into slot *n* of a record derived at one end comes
//! back out of slot *n* of the record derived at the other. Four properties are
//! unreachable without it, and every one of them fails SILENTLY:
//!
//! 1. **The slot is honoured.** A publish that ignored its argument and wrote
//!    subkey 0 would round-trip a single message perfectly. So the frames go to
//!    NON-ZERO slots, and the sweep must hand back the slots they were written to.
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
//! the REAL daemonseed page arithmetic (`dm::paging::{derive_owner_seed,
//! position_of, PagePosition}`) — no addressing is reimplemented here.

use std::collections::{BTreeMap, BTreeSet};

use daemonseed_core::dm::paging::{self, PagePosition};
use daemonseed_core::dm::ratchet::Direction;
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
    // A is the initiator speaking, so its stream is the A→B direction; B derives
    // the same direction because it is *receiving* that stream. Nothing about the
    // address is transmitted — the derivation is the whole discovery mechanism, so
    // two seeds computed independently must be byte-identical or nothing that
    // follows means anything.
    const PAGE: u64 = 0;
    let owner_seed_a = *paging::derive_owner_seed(&address_root, Direction::AToB, PAGE)
        .expect("A derives the page owner seed")
        .as_bytes();
    let owner_seed_b = *paging::derive_owner_seed(&address_root, Direction::AToB, PAGE)
        .expect("B derives the page owner seed")
        .as_bytes();
    assert_eq!(
        owner_seed_a, owner_seed_b,
        "both ends must derive the same page record from the address root alone"
    );

    // ── two messages, two slots, NEITHER of them slot 0 ──────────────────────
    // Slots come from sequence numbers via the real arithmetic, as the sender will.
    // Both are on the same page, which is what makes them a coalescing pair; both
    // are non-zero, so a transport that ignored the slot and always wrote subkey 0
    // cannot round-trip them.
    let first = paging::position_of(9);
    let second = paging::position_of(3);
    assert_eq!(first.page(), PAGE, "seq 9 must live on the page under test");
    assert_eq!(
        second.page(),
        PAGE,
        "seq 3 must live on the page under test"
    );
    assert_ne!(first.slot(), 0, "the test is blind if the slot is 0");
    assert_ne!(second.slot(), 0, "the test is blind if the slot is 0");
    assert_ne!(first.slot(), second.slot());

    let frame_first = b"channel frame at sequence nine".to_vec();
    let frame_second = b"channel frame at sequence three".to_vec();

    // Issued CONCURRENTLY, deliberately. Both commands reach the write funnel
    // before either dispatches, which is the only arrangement in which a coalescing
    // classification could actually collapse them. Awaiting the two publishes in
    // sequence would leave the funnel holding one pending write to this record at a
    // time, and the anti-coalescing property — the one whose failure mode is a
    // message silently missing from the wire under an `Ok(())` — would go untested.
    let (published_first, published_second) = tokio::join!(
        node_a.publish_dm_page(owner_seed_a, u32::from(first.slot()), frame_first.clone()),
        node_a.publish_dm_page(owner_seed_a, u32::from(second.slot()), frame_second.clone()),
    );
    published_first.expect("A publishes the first frame");
    published_second.expect("A publishes the second frame");

    // ── B sweeps the page from the other end ─────────────────────────────────
    // DHT writes are eventually consistent; poll rather than assume convergence.
    // Wait for BOTH slots — settling for one would accept exactly the coalescing
    // bug this test exists to catch.
    let mut swept = Vec::new();
    for attempt in 0..30 {
        match node_b.sweep_dm_page(owner_seed_b).await {
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

    // The slots must be the ones written to, not positional indices and not zero.
    let slots: BTreeSet<u32> = swept.iter().map(|(slot, _)| *slot).collect();
    assert_eq!(
        slots,
        BTreeSet::from([u32::from(first.slot()), u32::from(second.slot())]),
        "the sweep must return the subkeys the frames were written to"
    );

    // ...and each slot must carry ITS OWN frame. Two frames in the right two slots
    // but swapped would pass a slot-set check and then hand the collector a frame
    // whose declared sequence number disagrees with where it was found.
    let by_slot: BTreeMap<u32, Vec<u8>> = swept.into_iter().collect();
    assert_eq!(
        by_slot.get(&u32::from(first.slot())),
        Some(&frame_first),
        "the frame for sequence 9 must come back from sequence 9's slot"
    );
    assert_eq!(
        by_slot.get(&u32::from(second.slot())),
        Some(&frame_second),
        "the frame for sequence 3 must come back from sequence 3's slot"
    );

    // The swept slot is the input to the checked slot→sequence direction, so it must
    // survive `PagePosition::new` and land back on the sequence number that produced
    // it. This is the check a collector will make; failing it here means a collector
    // could not be written against this transport at all.
    for (slot, expected_seq) in [(first.slot(), first.seq()), (second.slot(), second.seq())] {
        let at = PagePosition::new(PAGE, slot).expect("a swept slot is a valid page position");
        assert_eq!(
            at.seq(),
            expected_seq,
            "slot {slot} of page {PAGE} must resolve back to the sequence it was derived from"
        );
    }

    // ── an unwritten page is empty, not an error ─────────────────────────────
    // Collection probes the frontier page ahead of the one being filled, so this is
    // the ordinary steady state, not a failure. A page far past anything either end
    // has touched, in the opposite direction for good measure.
    const UNWRITTEN_PAGE: u64 = 4_096;
    let unwritten = *paging::derive_owner_seed(&address_root, Direction::BToA, UNWRITTEN_PAGE)
        .expect("derive an unwritten page's owner seed")
        .as_bytes();
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
