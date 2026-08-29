//! Integration test (#235, ISC-C39): node A publishes the acknowledgement record
//! for the direction it collects on, and node B — deriving the same record from
//! the conversation's address root alone — fetches it, verifies it, and merges it
//! under its own ceiling.
//!
//! This is the live oracle for the transport half of the acknowledgement. The unit
//! tests prove the seal, the signature and the merge algebra; only two independent
//! nodes can prove that the record one end writes is the record the other end
//! reads. Three properties are unreachable without it, and each fails silently:
//!
//! 1. **Both ends address the same record from `AR` alone.** Nothing about the
//!    address is transmitted — the derivation *is* the rendezvous — and the writer
//!    takes its direction from `recv_direction` while the reader takes its from
//!    `send_direction`. Those are the same direction by construction, and a
//!    transport or a derivation that disagreed would write a perfectly valid
//!    acknowledgement at a record the correspondent never reads, with no error on
//!    any surface.
//! 2. **The runs survive the wire, not just the prefix.** A conversation that
//!    collected out of order settles a contiguous prefix plus runs beyond it, and a
//!    path that carried only the prefix would round-trip a strictly-in-order
//!    conversation perfectly. So the state published below has GAPS, and the merged
//!    result is asserted position by position — the settled ones and the unsettled
//!    ones both.
//! 3. **An unwritten record is empty, not an error.** A correspondent that has
//!    settled nothing yet is the ordinary opening state of every conversation, so
//!    the fetch must come back `Ok(None)`. Conflating that with a transport failure
//!    is the direction a fail-safe delivery state must never blur.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network.
//! Where attach is blocked, `attach_and_wait` returns `NotReady` after the full
//! 180 s timeout. Run it on a host that can attach:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_dm_ack -- --ignored --nocapture
//!
//! It drives the productized `VeilidNetHandle` surface the app drives, and reuses
//! the REAL daemonseed acknowledgement crypto (`dm::ack::AckState` and
//! `dm::ack_record::{DmAckAddress, build_encoded, decode_and_verify}`) — nothing is
//! reimplemented here. The directions come from real ratchets, so each end
//! addresses with its own ratchet's reading rather than a role mapped onto one by
//! hand.
//!
//! The two tests at the foot need no network and run on every ordinary `cargo test`
//! (the pattern `two_node_doorbell.rs` uses): they pin the parts of the live test's
//! claim that are pure crypto — the address agreement and the fixture's own shape —
//! so a broken assertion set is caught here rather than resting on an `#[ignore]`d
//! body.

use daemonseed_core::dm::ack::{AckState, PeerAckOutcome};
use daemonseed_core::dm::ack_record::{self, DmAckAddress};
use daemonseed_core::dm::firstcontact::{derive_channel_roots, ChannelRoots};
use daemonseed_core::dm::ratchet::{EphemeralDecapKey, Ratchet, Role};
use daemonseed_core::identity::keys::{derive_identity_keys, Identity, IdentityKeys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig};

/// A node config with a fresh daemonseed-derived node identity, a distinct listen
/// port, and its own storage dir — so two can coexist in one process. The node
/// identity is per-node and unrelated to the *conversation* whose acknowledgement
/// is under test: the record's address derives from the address root, never from a
/// node key.
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_ack{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

/// A fresh conversation secret for this run.
///
/// Random per run, and that is load-bearing rather than hygiene: the record's
/// address is deterministic in `AR` and the record PERSISTS on the public DHT, so a
/// fixed secret would fetch a previous run's acknowledgement back and pass on stale
/// bytes. Entropy comes from a throwaway mnemonic-derived node seed — the crate
/// already depends on that, and it saves pulling an RNG into the dev-deps.
fn fresh_ss0() -> [u8; 32] {
    let throwaway =
        derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let entropy = throwaway.veilid_node_seed.with_bytes(|b| *b);
    let mut ss0 = [0u8; 32];
    for (dst, src) in ss0.iter_mut().zip(entropy.iter().cycle()) {
        *dst = *src;
    }
    ss0
}

/// One conversation: the roots both ends derive from, and the two parties'
/// ratchets over the same first-contact secret — A knocked, B was knocked at.
///
/// The ratchets exist here only to supply the *direction* each end addresses with.
/// `DmAckAddress` takes it from `recv_direction` at the writer and `send_direction`
/// at the reader, which is what makes the record A writes and the record B reads
/// provably the same one rather than two hand-written constants that happen to
/// match.
fn conversation() -> (ChannelRoots, Ratchet, Ratchet) {
    let ss0 = fresh_ss0();
    let roots = derive_channel_roots(&ss0).expect("derive this run's channel roots");

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
    (roots, ratchet_a, ratchet_b)
}

/// A fresh per-contact pseudonym keypair. It signs every message of a conversation
/// and, here, the acknowledgement — never the long-term identity key.
fn pseudonym() -> IdentityKeys {
    derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).expect("pseudonym keys")
}

/// The positions the publishing end has collected.
///
/// **Deliberately not contiguous.** `0..=2` folds into the prefix and `5` and `9`
/// each become a run beyond it, so the encoded statement exercises the run set
/// rather than a bare high-water number — the half a prefix-only path would carry
/// perfectly while dropping every gap.
const COLLECTED: [u64; 5] = [0, 1, 2, 5, 9];

/// The highest sequence number the *sending* end has actually sent, and therefore
/// the ceiling a merge of the peer's claim is bounded by. It clips nothing here:
/// every collected position is one this end sent.
const HIGHEST_SENT: u64 = 9;

/// A ceiling BELOW the top of the claim, for the clip case.
const LOW_CEILING: u64 = 4;

fn fixture_state() -> AckState {
    let mut state = AckState::new();
    for seq in COLLECTED {
        state.collect(seq).expect("within the run cap");
    }
    assert_eq!(
        state.high_water(),
        Some(2),
        "fixture precondition: 0..=2 is the contiguous prefix"
    );
    assert_eq!(
        state.runs(),
        2,
        "fixture precondition: 5 and 9 are runs beyond the prefix, or this test \
         cannot tell a run set from a bare prefix"
    );
    state
}

/// What a merge of the fixture under a ceiling that clips nothing must look like.
///
/// The unsettled positions are asserted alongside the settled ones: a merge that
/// widened a run — or that read an absent position as settled — is the
/// false-delivered failure the whole fail-safe posture exists to prevent, and a
/// settled-only check cannot see it.
fn assert_merged_as_collected(merged: &AckState) {
    assert_eq!(
        merged.high_water(),
        Some(2),
        "the prefix must survive intact"
    );
    for seq in COLLECTED {
        assert!(merged.is_settled(seq), "position {seq} was collected");
    }
    for seq in [3u64, 4, 6, 7, 8, 10] {
        assert!(
            !merged.is_settled(seq),
            "position {seq} was never collected and must not read as settled"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "attaches to the public Veilid network; opt-in, run with --ignored"]
async fn an_acknowledgement_published_by_one_node_merges_at_the_other() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-dm-ack-it");
    let _ = std::fs::remove_dir_all(&base);

    let (roots, ratchet_a, ratchet_b) = conversation();
    // A acknowledges what it RECEIVES; B reads that acknowledgement about what it
    // SENDS. Those are one direction, taken from each end's own ratchet.
    let acknowledged = ratchet_a.recv_direction();
    assert_eq!(
        acknowledged,
        ratchet_b.send_direction(),
        "A's receiving stream and B's sending stream must be the same one, or \
         nothing below is a round trip"
    );

    // A's per-contact pseudonym key. B holds only its PUBLIC half, as it would from
    // first contact.
    let pc_a = pseudonym();
    let peer_pk = *pc_a.signing.public_key();

    let (node_a, _rx_a) = VeilidNet::start(node_config(":5180", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, _rx_b) = VeilidNet::start(node_config(":5181", &base.join("B")))
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

    // ── both ends derive the same record ─────────────────────────────────────
    // Each use derives its own address rather than reusing one: the owner seed
    // inside is the conversation's write capability, so it is deliberately not
    // `Clone` and the transport takes the address by value (#244). The derivation is
    // pure, which is what makes re-deriving the right answer rather than a
    // workaround.
    let addr = |direction| {
        DmAckAddress::for_direction(&roots.ar, direction).expect("derive an ack-record address")
    };
    {
        let from_a = addr(ratchet_a.recv_direction());
        let from_b = addr(ratchet_b.send_direction());
        assert_eq!(
            from_a.owner_seed().as_bytes(),
            from_b.owner_seed().as_bytes(),
            "both ends must derive the same acknowledgement record from the address \
             root alone"
        );
        assert_eq!(from_a.direction(), acknowledged);
    }

    // ── A publishes what it has collected ────────────────────────────────────
    let state = fixture_state();
    let record = ack_record::build_encoded(
        &state,
        &roots.chan_id,
        acknowledged,
        &roots.ar,
        &pc_a.signing,
    )
    .expect("A builds its acknowledgement");
    node_a
        .publish_dm_ack(addr(acknowledged), record)
        .await
        .expect("A publishes its acknowledgement");

    // ── B fetches it from the other end ──────────────────────────────────────
    // DHT writes are eventually consistent; poll rather than assume convergence.
    let mut fetched = None;
    for attempt in 0..30 {
        match node_b.fetch_dm_ack(addr(ratchet_b.send_direction())).await {
            Ok(Some(bytes)) => {
                fetched = Some(bytes);
                break;
            }
            Ok(None) => eprintln!("attempt {attempt}: slot still empty, retrying"),
            Err(e) => eprintln!("attempt {attempt}: fetch error {e}, retrying"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    let fetched = fetched.expect("B fetched A's acknowledgement within the convergence window");

    // ── B verifies and merges ────────────────────────────────────────────────
    // Decode → verify → merge, in that order and with no shortcut: a `PeerAck`
    // answers no question about settlement until it has been bounded by what this
    // end has actually sent.
    let peer =
        ack_record::decode_and_verify(&fetched, &roots.chan_id, acknowledged, &roots.ar, &peer_pk)
            .expect("the fetched record verifies against A's pseudonym key");

    let mut ours = AckState::new();
    assert_eq!(
        ours.merge_peer_ack(peer, Some(HIGHEST_SENT))
            .expect("the peer's statement merges"),
        PeerAckOutcome::WithinCeiling,
        "every collected position is one this end sent, so nothing may be clipped"
    );
    assert_merged_as_collected(&ours);

    // ── and the ceiling still bounds bytes that came off the wire ────────────
    // Re-decoded from the same fetched bytes: the clip is a property of the merge,
    // and a record that only ever meets a generous ceiling exercises the union
    // algebra while saying nothing about the bound.
    let peer_again =
        ack_record::decode_and_verify(&fetched, &roots.chan_id, acknowledged, &roots.ar, &peer_pk)
            .expect("the same record verifies twice");
    let mut clipped = AckState::new();
    assert_eq!(
        clipped
            .merge_peer_ack(peer_again, Some(LOW_CEILING))
            .expect("a clipped statement still merges"),
        PeerAckOutcome::ClippedToCeiling {
            claimed: HIGHEST_SENT,
            ceiling: Some(LOW_CEILING),
        }
    );
    assert!(
        !clipped.is_settled(5) && !clipped.is_settled(9),
        "nothing above the ceiling may survive the merge"
    );

    // ── and an impostor cannot pass ──────────────────────────────────────────
    // The record is owner-write-gated, so only the two parties can write here — but
    // the signature is what says WHICH of them did, and a reader checks it against
    // the pseudonym key it holds for its correspondent.
    assert!(
        ack_record::decode_and_verify(
            &fetched,
            &roots.chan_id,
            acknowledged,
            &roots.ar,
            pseudonym().signing.public_key(),
        )
        .is_err(),
        "an acknowledgement must never verify against a key that did not sign it"
    );

    // ── a record nobody has written is empty, not an error ───────────────────
    // The other direction: B has published no acknowledgement of its own yet, which
    // is the opening state of every conversation.
    let unwritten = ratchet_b.recv_direction();
    assert_ne!(
        unwritten, acknowledged,
        "the unwritten record must be the OTHER direction's"
    );
    assert_eq!(
        node_a
            .fetch_dm_ack(addr(unwritten))
            .await
            .expect("an unwritten acknowledgement must be Ok, not Err"),
        None,
        "a correspondent that has settled nothing yet has no record to read"
    );

    eprintln!(
        "ISC-C39 live oracle: collect with gaps -> publish -> fetch from the far end \
         -> verify -> merge under a ceiling OK"
    );
}

/// **Both ends derive the same record, and the two directions do not collide —
/// runnable here, no network.**
///
/// The live test's whole rendezvous claim rests on this, and it is pure crypto: A
/// addresses off `recv_direction` and B off `send_direction`, with nothing
/// transmitted between them. Verified on every ordinary `cargo test` run rather
/// than resting on the `#[ignore]`d body, because a derivation that put the two
/// ends on different records would make the live test fail as a *convergence
/// timeout* — indistinguishable, on a host that cannot attach, from the network
/// being unavailable.
#[test]
fn both_ends_derive_the_same_acknowledgement_record() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let (roots, ratchet_a, ratchet_b) = conversation();
    let writer = DmAckAddress::for_direction(&roots.ar, ratchet_a.recv_direction())
        .expect("A derives the record it writes");
    let reader = DmAckAddress::for_direction(&roots.ar, ratchet_b.send_direction())
        .expect("B derives the record it reads");
    assert_eq!(
        writer.owner_seed().as_bytes(),
        reader.owner_seed().as_bytes()
    );
    assert_eq!(writer.direction(), reader.direction());

    // And the other half of the conversation must be a DIFFERENT record, or the
    // live test's unwritten-record probe would be reading the one just published.
    let other = DmAckAddress::for_direction(&roots.ar, ratchet_b.recv_direction())
        .expect("the other direction's record");
    assert_ne!(other.direction(), writer.direction());
    assert_ne!(
        other.owner_seed().as_bytes(),
        writer.owner_seed().as_bytes()
    );
}

/// **The fixture round-trips and clips as the live test claims — runnable here, no
/// network.**
///
/// Everything the live test asserts except the DHT hop: the state's gaps, the seal
/// and signature over them, and the two merges. It is not a duplicate of
/// `ack_record`'s own unit tests — those pin the module against fixtures of their
/// own, while this pins THIS test's fixture and THIS test's ceilings, which are
/// what the `#[ignore]`d body is written against. A fixture whose positions did not
/// settle the way the assertions say would otherwise be discovered only on a host
/// that can attach.
#[test]
fn the_fixture_round_trips_and_clips_without_a_network() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let (roots, ratchet_a, _ratchet_b) = conversation();
    let acknowledged = ratchet_a.recv_direction();
    let pc = pseudonym();

    let record = ack_record::build_encoded(
        &fixture_state(),
        &roots.chan_id,
        acknowledged,
        &roots.ar,
        &pc.signing,
    )
    .expect("the fixture builds a record");

    let peer = ack_record::decode_and_verify(
        &record,
        &roots.chan_id,
        acknowledged,
        &roots.ar,
        pc.signing.public_key(),
    )
    .expect("the fixture verifies");
    let mut ours = AckState::new();
    assert_eq!(
        ours.merge_peer_ack(peer, Some(HIGHEST_SENT))
            .expect("merge under a ceiling that clips nothing"),
        PeerAckOutcome::WithinCeiling
    );
    assert_merged_as_collected(&ours);

    let peer_again = ack_record::decode_and_verify(
        &record,
        &roots.chan_id,
        acknowledged,
        &roots.ar,
        pc.signing.public_key(),
    )
    .expect("the fixture verifies twice");
    let mut clipped = AckState::new();
    assert_eq!(
        clipped
            .merge_peer_ack(peer_again, Some(LOW_CEILING))
            .expect("merge under a ceiling that clips"),
        PeerAckOutcome::ClippedToCeiling {
            claimed: HIGHEST_SENT,
            ceiling: Some(LOW_CEILING),
        }
    );
    assert_eq!(clipped.high_water(), Some(2));
    assert!(!clipped.is_settled(5));
    assert!(!clipped.is_settled(9));
}
