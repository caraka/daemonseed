//! Integration test (#234, ISC-C42): node A seals real channel messages under real
//! ratchet keys, publishes them into their page slots, and node B — driving its own
//! independently-constructed ratchet — sweeps the page, parses the frames, and
//! opens them back to the plaintext A sent.
//!
//! ## How this differs from `two_node_dm_page`
//!
//! The sibling oracle proves the *transport*: it moves opaque byte strings and
//! asks only that slot *n* in comes back out of slot *n*. Its payloads are ASCII
//! literals — nothing in it would notice if the ratchet, the seal, the AAD, the
//! authorship signature, or the address derivation were wrong, because none of
//! them are involved.
//!
//! This one carries actual **sealed, signed, ratcheted** messages, so it closes
//! over the whole seam at once: `ratchet -> frame::seal -> paging -> the wire ->
//! paging -> frame::parse -> ratchet::receive -> ParsedFrame::open`. Six
//! independently-correct components can still fail to compose, and the ways they
//! fail here are all silent:
//!
//! 1. **The page address and the frame's AAD must be rooted in the same
//!    conversation.** `chan_id` is never serialized — the receiver recomputes it —
//!    and the page's owner seed derives from `AR`. Both come from `ss0`, via
//!    [`derive_channel_roots`]. A build that took the page address from one root
//!    and the AAD from another would publish and sweep perfectly and then fail
//!    every open with the error the module reserves for tampering.
//! 2. **The two ends must agree on the direction.** A addresses its *sending*
//!    stream and B its *receiving* one, both taken from their own ratchets by
//!    `DmPageAddress`. The wrong one derives a perfectly valid seed for the wrong
//!    stream and then sweeps forever in silence — the failure
//!    `paging::derive_owner_seed`'s docs warn about, and the reason the stream now
//!    rides in the address's type.
//! 3. **The slot a frame was found in must reach `open`.** `found_at` is the
//!    collector's own knowledge, and it can only be reconstructed on the far side
//!    of a real sweep — locally the caller already has the `PagePosition` it wrote
//!    with, so a unit test cannot tell "the position survived the round trip" from
//!    "the caller passed its own value back to itself".
//! 4. **A frame that does not authenticate must move no ratchet state — and the
//!    load-bearing part of that is the skipped-key cache.** The messages are
//!    therefore delivered OUT OF ORDER, which is what puts a key in the cache in
//!    the first place; the tampered frame is then aimed at exactly that cached
//!    position. An implementation that took the key before checking the open would
//!    destroy the honest message's only remaining key for the cost of one corrupt
//!    write, and every counter in `DeliveryLosses` would still read correct if the
//!    frames had arrived in order. See the tamper section below for why the
//!    in-order version of this assertion is blind.
//!
//! The unit tests in `dm::frame` prove each half in isolation and cannot reach any
//! of the four: they hand `open` a position they computed themselves, from a frame
//! that never left the process.
//!
//! ## Scope, stated honestly
//!
//! Two messages on one page, at their natural positions. Slot fidelity as a
//! property in its own right — several scattered slots, and two concurrent writes
//! surviving the funnel's coalescing scope — is `two_node_dm_page`'s job and is not
//! re-proved here; what this test needs from the slots is only that they are not
//! zero, so an always-slot-0 publish cannot pass. The design supplies that for
//! free, because the initiator's first channel sequence is **one** (sequence zero
//! was the knock, which travels by doorbell). Page *discovery* — the probe frontier
//! that finds which pages exist — arrives with collection (#236); B is told which
//! page to sweep here.
//!
//! **The run therefore sits on page 0, and that bounds property 3.** The positions
//! reaching `open` are rebuilt from the swept slot against the page B addressed,
//! which is the reconstruction a collector performs — but on page 0 a sequence
//! number equals its slot, so a reconstruction that dropped the page entirely would
//! produce the same values here. Reaching a non-zero page means advancing A's send
//! chain past `PAGE_SLOTS` and carrying B's skipped-key cache across the gap, which
//! changes what property 4 exercises; `two_node_dm_page` runs the same
//! reconstruction on page 3, and `paging`'s own
//! `a_swept_slot_and_its_page_rebuild_the_senders_sequence` pins the arithmetic on
//! four non-degenerate pages where it can actually run.
//!
//! The whole run also sits in **generation zero**. Only the initiator speaks, so it
//! never has a peer ephemeral to step against, and every frame therefore carries no
//! `eph_ct`. Nothing here reaches `receive`'s advancing branch, its
//! `MissingCiphertext` / `UnknownEphemeral` gates, or `parse`'s length gate on the
//! ciphertext field — a reply-direction oracle over a real generation step is
//! separate work. Read the `generation()` half of the tamper check below as a cheap
//! invariant, not as coverage of the root ratchet: it is constant for this reason.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network. This
//! VM cannot: something in the QEMU bridge eats the Veilid connection, so attach
//! returns `NotReady` after the full 180 s timeout (measured 2026-07-28). Run it on
//! a real-network host:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test two_node_dm_channel -- --ignored --nocapture
//!
//! It drives the productized `VeilidNetHandle` surface the app drives, and reuses
//! the REAL daemonseed crypto and addressing (`dm::firstcontact::{
//! derive_channel_roots, recipient_hash}`, `dm::ratchet::Ratchet`,
//! `dm::frame::{seal, parse, ParsedFrame::open}`, `dm::paging::{DmPageAddress,
//! position_of, PagePosition}`) — nothing is reimplemented here.

use std::collections::BTreeMap;

use daemonseed_core::dm::firstcontact::{derive_channel_roots, recipient_hash};
use daemonseed_core::dm::frame::{self, AuthorKeys, DmFrameError, ParsedFrame};
use daemonseed_core::dm::paging::{self, DmPageAddress, PagePosition};
use daemonseed_core::dm::ratchet::{DeliveryLosses, EphemeralDecapKey, Ratchet, Role};
use daemonseed_core::identity::keys::{derive_identity_keys, Identity, IdentityKeys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig};

/// Sender-asserted, signed, display-only — a fixed value so the round trip can
/// assert it came back unchanged.
const SENT: i64 = 1_700_000_000_000;

/// The two plaintexts under test. Distinct from each other and from anything a
/// padding, zero fill, or the sibling test's payloads could produce, so a frame
/// opened from the wrong position could not pass for the right one.
const BODY_FIRST: &str = "the channel is open, and this sentence went through the ratchet";
const BODY_SECOND: &str = "and this one arrived first, out of order, as they really do";

/// A node config with a fresh daemonseed-derived node identity, a distinct listen
/// port, and its own storage dir — so two can coexist in one process. The node
/// identity is per-node and unrelated to the *conversation* under test: nothing
/// about a page address or a message key derives from a node key.
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_dm_channel{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

/// A throwaway user identity — an ML-DSA-87 signing keypair and an ML-KEM-1024
/// keypair, derived exactly as a real one is.
fn identity() -> IdentityKeys {
    derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).expect("identity")
}

/// A fresh first-contact secret for this run.
///
/// Random per run, and that is load-bearing rather than hygiene: `AR` derives from
/// it, the page address derives from `AR`, and the record PERSISTS on the public
/// DHT — so a fixed secret would sweep a previous run's frames back and open stale
/// bytes under a chain that had already moved. Entropy comes from a throwaway
/// mnemonic-derived node seed, which is already 32 bytes of the right shape and
/// saves pulling an RNG into the dev-deps.
fn fresh_ss0() -> [u8; 32] {
    identity().veilid_node_seed.with_bytes(|b| *b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored"]
async fn sealed_channel_messages_round_trip_through_a_page_and_open_out_of_order() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-dm-channel-it");
    let _ = std::fs::remove_dir_all(&base);

    // ── the conversation ─────────────────────────────────────────────────────
    // Alice knocked, Bob was knocked at. `alice_pc` is the per-contact pseudonym
    // that signs this conversation — a random key in production, a second derived
    // identity here. It is deliberately NOT Alice's long-term key: the whole point
    // of the pseudonym is that a channel frame carries no long-term identity, and
    // a test that signed with the long-term key would pass under an implementation
    // that had collapsed the two.
    let alice = identity();
    let alice_pc = identity();
    let bob = identity();

    // In production `ss0` is the secret Alice encapsulated to Bob's published KEM
    // key at first contact, and the opening ratchet ephemeral rode the same entry.
    // Both are stood in for here — this oracle is about the ongoing channel, and
    // the first-contact handshake has its own coverage — but everything derived
    // FROM them runs through the real API.
    let ss0 = fresh_ss0();
    let opening_eph = identity();

    // Both ends derive the conversation's roots from `ss0` alone. Derived twice,
    // once per end, and asserted equal: nothing about the address or `chan_id`
    // travels on the wire, so this derivation IS the discovery mechanism, and two
    // independent computations must be byte-identical or nothing below means
    // anything.
    let roots_a = derive_channel_roots(&ss0).expect("A derives the channel roots");
    let roots_b = derive_channel_roots(&ss0).expect("B derives the channel roots");
    assert_eq!(
        roots_a.ar, roots_b.ar,
        "both ends must derive the same address root from ss0 alone"
    );
    assert_eq!(
        roots_a.chan_id, roots_b.chan_id,
        "both ends must derive the same channel id from ss0 alone"
    );

    // Two ratchets over one secret, exactly as the two parties hold them: Alice as
    // the party that knocked, Bob as the party that was knocked at. Bob is given
    // only the PUBLIC half of the opening ephemeral, which is all a real recipient
    // ever receives.
    let mut ratchet_a = Ratchet::initiator(
        &ss0,
        Box::new(*opening_eph.kem.encapsulation_key()),
        EphemeralDecapKey::new(Box::new(*opening_eph.kem.decapsulation_key())),
    )
    .expect("A opens the ratchet as initiator");
    let mut ratchet_b = Ratchet::recipient(&ss0, Box::new(*opening_eph.kem.encapsulation_key()))
        .expect("B opens the ratchet as recipient");
    assert_eq!(
        ratchet_a.role(),
        Role::Initiator,
        "A must be the initiator — the roles fix the send/recv directions, and swapping \
         them derives a valid seed for the wrong stream"
    );
    assert_eq!(
        ratchet_b.role(),
        Role::Recipient,
        "B must be the recipient, for the same reason"
    );

    // The direction each end uses, taken from its own ratchet rather than mapped
    // by hand — the mapping is exactly what `Role` exists to stop a call site
    // getting wrong, and getting it wrong here derives a valid seed for the wrong
    // stream and then sweeps in silence forever.
    let dir_a = ratchet_a.send_direction();
    let dir_b = ratchet_b.recv_direction();
    assert_eq!(
        dir_a, dir_b,
        "A's sending direction and B's receiving direction are the same stream"
    );

    // ── the nodes ────────────────────────────────────────────────────────────
    let (node_a, _rx_a) = VeilidNet::start(node_config(":5176", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, _rx_b) = VeilidNet::start(node_config(":5177", &base.join("B")))
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

    // ── A seals two messages and publishes each at its position ──────────────
    // Sealed in order, as a sender does. They are DELIVERED out of order below,
    // which is the point — but the sender never reorders its own chain.
    let rcpt_hash = recipient_hash(bob.signing.public_key()).expect("recipient hash");
    let mut sent = Vec::new();
    for body in [BODY_FIRST, BODY_SECOND] {
        let outbound = ratchet_a.send_next().expect("A mints an outbound key");
        let seq = outbound.header.seq;
        let at = paging::position_of(seq);

        // The initiator's first channel sequence is ONE, not zero — sequence zero
        // was the first-contact entry, which travelled by doorbell — so even the
        // very first frame lands in a non-zero slot. That is what keeps this test
        // from being blind: a `publish_dm_page` that ignored the slot in its address and
        // always wrote subkey 0 would round-trip a slot-0 message perfectly, and
        // fails here.
        assert_ne!(
            at.slot(),
            0,
            "the test cannot see an always-slot-0 publish if the slot is 0"
        );

        let frame_bytes = frame::seal(
            outbound,
            &roots_a.chan_id,
            &alice_pc.signing,
            alice.signing.public_key(),
            &rcpt_hash,
            SENT,
            body,
        )
        .expect("A seals the channel frame");

        // The address IS the placed slot, so page and slot come from ONE sequence
        // number by construction (#269). There is nothing left for the transport
        // to re-check: a page from one sequence number and a slot from another is
        // no longer a pair that can be built.
        let address = DmPageAddress::sending(&roots_a.ar, &ratchet_a, at)
            .expect("A derives its sending page address");
        node_a
            .publish_dm_page(address, frame_bytes)
            .await
            .expect("A publishes the sealed frame into its slot");

        sent.push((seq, at, body));
    }
    let (first_seq, first_at, _) = sent[0];
    let (second_seq, second_at, _) = sent[1];
    assert_eq!(
        first_at.page(),
        second_at.page(),
        "both messages must share a page, or B would need two sweeps and the \
         out-of-order delivery below would not exercise one chain"
    );
    assert_ne!(
        first_at.slot(),
        second_at.slot(),
        "the two frames must occupy different slots, or the second write would \
         overwrite the first and the sweep could not tell them apart"
    );
    let page = first_at.page();

    // ── B sweeps the page it derived for itself ──────────────────────────────
    // B computes the address from the address root and its own receiving
    // direction. Nothing about it came from A over the wire.
    //
    // Re-derived per use rather than held: the owner seed inside is the
    // conversation's write capability, so the address is deliberately not `Clone`
    // and the transport takes it by value (#244/#254). Derivation is pure, so this
    // is the intended usage. B can only pass a RECEIVING address to a sweep, which
    // is the direction it wants — the type refuses the other one.
    let addr_b = || {
        DmPageAddress::receiving(&roots_b.ar, &ratchet_b, page)
            .expect("B derives its receiving page address")
    };
    assert_eq!(
        DmPageAddress::sending(
            &roots_a.ar,
            &ratchet_a,
            // Any slot on the page: the owner seed descends from the root, the
            // direction and the page, never the slot.
            PagePosition::new(page, 0).expect("slot 0 is inside a page's record"),
        )
        .expect("A derives its sending page address")
        .with_owner_seed(|b| *b),
        addr_b().with_owner_seed(|b| *b),
        "both ends must derive the same page record from the address root alone"
    );

    // DHT writes are eventually consistent; poll rather than assume convergence.
    // Wait for BOTH slots: settling for one would leave the out-of-order delivery
    // below untested, which is the whole of this file's fourth property.
    let mut swept = Vec::new();
    for attempt in 0..30 {
        match node_b.sweep_dm_page(addr_b()).await {
            Ok(sweep) => {
                eprintln!(
                    "attempt {attempt}: {} slot(s) back, outcome {:?}",
                    sweep.slots.len(),
                    sweep.outcome
                );
                assert_eq!(
                    sweep.conversation,
                    *addr_b().conversation(),
                    "the sweep must name the conversation it addressed (#270)"
                );
                let slots = sweep.slots;
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
        "both frames must survive to the wire and come back within the \
         convergence window"
    );

    // **Positions REBUILT from the sweep, not taken from what A wrote.** This file's
    // third property is that `found_at` can only be reconstructed on the far side of a
    // real sweep, and a lookup cannot establish it: `PagePosition` derives `Eq`/`Ord`
    // over `(page, slot)`, so the key `get_key_value` hands back is field-identical to
    // the probe by construction, and feeding that to `open` passes A's own knowledge
    // through under the appearance of sweep-side reconstruction.
    //
    // So each swept slot is put back through `PagePosition::new` against the page B
    // ADDRESSED — the two facts a collector genuinely holds — and it is the rebuilt
    // position that reaches `open` below. A reconstruction that lost the page (or took
    // the wrong one) no longer matches what A wrote, so the lookups here fail rather
    // than silently agreeing.
    let by_position: BTreeMap<PagePosition, Vec<u8>> = swept
        .into_iter()
        .map(|(swept_at, bytes)| {
            let rebuilt = PagePosition::new(page, swept_at.slot())
                .expect("a swept slot must be inside the addressed page's record");
            (rebuilt, bytes)
        })
        .collect();
    let (first_found_at, first_bytes) = by_position
        .get_key_value(&first_at)
        .map(|(at, bytes)| (*at, bytes.clone()))
        .expect("the first frame must come back from the position it was written to");
    let (second_found_at, second_bytes) = by_position
        .get_key_value(&second_at)
        .map(|(at, bytes)| (*at, bytes.clone()))
        .expect("the second frame must come back from the position it was written to");

    let first = frame::parse(&first_bytes).expect("the first swept bytes are a decodable frame");
    let second = frame::parse(&second_bytes).expect("the second swept bytes are a decodable frame");

    // A frame declares a sequence number; the slot it was found in implies one.
    // Only the collector holds both facts, so only the collector can compare them.
    // `open` re-checks this and would reject a mismatch as `Misplaced` — the
    // assertions here are the collector's own check, which must not be skipped just
    // because the frame layer also makes it.
    for (parsed, found_at, expected) in [
        (&first, first_found_at, first_seq),
        (&second, second_found_at, second_seq),
    ] {
        assert_eq!(
            parsed.header().seq,
            found_at.seq(),
            "a frame's declared sequence number must agree with the slot it was \
             found in"
        );
        assert_eq!(parsed.header().seq, expected, "and with the one A sent");
    }

    let author = AuthorKeys {
        pc: alice_pc.signing.public_key(),
        lt: alice.signing.public_key(),
    };

    // The receive seam, wired exactly as a collector wires it: the ratchet decides
    // which key, this module decides whether the frame is genuine, and the ratchet
    // commits nothing unless it is. The outer `Result` is the ratchet's (it refused
    // the position) and the inner one this module's (the frame did not
    // authenticate) — different failures, deliberately not flattened.
    let receive = |ratchet: &mut Ratchet, parsed: &ParsedFrame, found_at: PagePosition| {
        ratchet.receive(parsed.header(), parsed.eph_ct(), parsed.eph_ek(), |mk| {
            parsed.open(mk, &roots_b.chan_id, dir_b, found_at, &rcpt_hash, author)
        })
    };

    // ── the SECOND message opens first, out of order ─────────────────────────
    // Out-of-order arrival is the ordinary steady state, not an edge case, and it
    // is what puts the first message's key into the skipped-key cache — where the
    // tamper test below can actually see whether a failed open moved it.
    let opened_second = receive(&mut ratchet_b, &second, second_found_at)
        .expect("the ratchet accepts the later position")
        .expect("the second frame opens");
    assert_eq!(
        opened_second.body, BODY_SECOND,
        "the plaintext B recovered must be the one A sent"
    );
    assert_eq!(
        opened_second.seq, second_seq,
        "the opened frame must report the position it occupies"
    );
    assert_eq!(
        opened_second.sent_unix_ms, SENT,
        "the signed timestamp must survive the round trip"
    );

    // Stepping over the first message retained its key rather than destroying it.
    // Without this the conversation would lose every message that arrived late,
    // and the loss would look exactly like tampering.
    assert_eq!(
        ratchet_b.losses(),
        DeliveryLosses {
            pending: 1,
            evicted: 0,
            abandoned: 0,
        },
        "opening a later message must retain the skipped one's key, not drop it"
    );

    // ── a tampered frame fails closed, and moves nothing ─────────────────────
    // Aimed at the CACHED position, and run BEFORE the honest open of the same
    // frame. Both are deliberate:
    //
    // - Before, because a message key is used once. Afterwards the position is
    //   spent and a second attempt fails as `AlreadyConsumed`, which proves
    //   nothing about authentication.
    // - At the cached position, because that is the only place the "no state
    //   moved" claim is OBSERVABLE. Delivered in order, a failed open cannot move
    //   `generation` (no root step), `pending` (nothing skipped), `evicted` or
    //   `abandoned` — so every counter would read correct under an implementation
    //   that committed unconditionally, and the assertion would be blind. Against
    //   a cached key, an implementation that took the key before checking the open
    //   drops `pending` to 0 here, and the honest frame below then has no key left
    //   at all: one corrupt write destroys a message permanently.
    //
    // `sealed` is field 6, the last field prost encodes, so the final byte of the
    // frame is the final byte of the GCM tag: inside the sealed body, outside every
    // length prefix. The frame therefore still PARSES, and only the AEAD can reject
    // it — which is what makes this a test of authentication rather than of
    // decoding.
    let mut tampered_bytes = first_bytes.clone();
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 0xff;
    let tampered = frame::parse(&tampered_bytes)
        .expect("a frame with an edited body still parses; only the AEAD may reject it");

    let before = (ratchet_b.generation(), ratchet_b.losses());
    let refused = receive(&mut ratchet_b, &tampered, first_found_at)
        .expect("the ratchet accepts the position — the header was not touched");
    assert!(
        matches!(refused, Err(DmFrameError::Aead)),
        "a tampered body must fail INSIDE the open closure, not outside it: an \
         outer error would mean the ratchet rejected the position instead, and the \
         authentication path would go untested"
    );
    assert_eq!(
        (ratchet_b.generation(), ratchet_b.losses()),
        before,
        "a frame that did not authenticate must leave the ratchet — including the \
         skipped-key cache — exactly where it was"
    );

    // ── and the honest frame still opens afterwards ──────────────────────────
    // The strongest half of the previous assertion, and the one that fails loudly:
    // if the refused frame had consumed the cached key, this open would now fail as
    // `AlreadyConsumed` and a corrupted write would have destroyed its honest twin.
    let opened_first = receive(&mut ratchet_b, &first, first_found_at)
        .expect("the ratchet accepts the position")
        .expect("the honest frame opens after the tampered one was refused");
    assert_eq!(
        opened_first.body, BODY_FIRST,
        "the plaintext B recovered must be the one A sent"
    );
    assert_eq!(
        opened_first.seq, first_seq,
        "the opened frame must report the position it occupies"
    );
    assert_eq!(
        opened_first.sent_unix_ms, SENT,
        "the signed timestamp must survive the round trip"
    );

    // The cache is empty again: a key is used once, and a successful open is what
    // consumes it. A `peek` that never became a `take` would leave a usable message
    // key alive for the rest of the conversation.
    assert_eq!(
        ratchet_b.losses(),
        DeliveryLosses {
            pending: 0,
            evicted: 0,
            abandoned: 0,
        },
        "a successful open must consume the cached key, and nothing must have been \
         evicted or abandoned along the way"
    );

    eprintln!(
        "ISC-C42 live oracle: ratchet -> seal -> page slots {} and {} -> the wire \
         -> sweep -> parse -> out-of-order receive -> open OK",
        first_at.slot(),
        second_at.slot()
    );
}
