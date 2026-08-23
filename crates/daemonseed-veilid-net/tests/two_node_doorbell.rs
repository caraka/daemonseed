//! Integration test (#233, ISC-C41): node A knocks on node B's doorbell, and B —
//! holding nothing but its own keys — sweeps its own doorbell, finds the entry, and
//! opens it into a verified first contact.
//!
//! This is the live oracle for cold first contact, the one exchange in daemonseed
//! where a party writes a record it does not own. A is given exactly what a real
//! sender would already have: B's ML-DSA-87 public identity key (which rides every
//! provenance-signed artifact) and B's published ML-KEM encapsulation key. It is
//! given no shared secret, no roster, no route, and no prior contact with B.
//!
//! It exists because the unit tests cannot reach the property that matters. They
//! prove the derivations, the guards and the funnel classification; what they
//! cannot show is that the address A derives for a record it has never seen is the
//! record B sweeps, over a real DHT, with the write signed by an owner keypair A
//! computed from B's public key alone. If the world-derivable owner argument were
//! wrong anywhere — the shape, the seed, the signing key — the write would still
//! return `Ok` and B's sweep would simply come back empty.
//!
//! Three assertions carry it, in order of what they would catch:
//!
//! 1. **The knock arrives and opens.** Address, shape, slot, seal and signature all
//!    agree end to end.
//! 2. **A retry lands in the same slot and overwrites.** The slot is derived from
//!    A's mnemonic-rooted secret, so a second knock must not orphan the first in a
//!    second slot — the `#118` ephemeral-key bug class, which on a doorbell would
//!    consume a slot per retry out of only 32.
//! 3. **A third identity cannot open the entry.** What makes a world-WRITABLE,
//!    world-READABLE record safe is that the entry is sealed to B's encapsulation
//!    key; anyone can read the bytes and nobody else can open them.
//!
//! `#[ignore]` — it needs a host that can attach to the PUBLIC Veilid network.
//! Where attach is blocked, `attach_and_wait` returns `NotReady` after the full
//! 180 s timeout. Run it on a host that can attach:
//!
//!     cargo test -p daemonseed-veilid-net --test two_node_doorbell -- --ignored --nocapture
//!
//! Or build it into a standalone binary and run that on such a host:
//!
//!     packaging/oracles/build-oracle.sh two_node_doorbell
//!
//! Expect minutes rather than seconds: the knock mints a real proof of work at
//! production difficulty, and each publish waits on DHT propagation.
//!
//! It drives the productized `VeilidNetHandle` surface the app drives, and reuses
//! the REAL daemonseed crypto (`dm::doorbell::{derive_owner_seed, slot_for}` and
//! `dm::firstcontact::{build, open}`) — no crypto is reimplemented here.

use daemonseed_core::dm::firstcontact::FirstContactRequest;
use daemonseed_core::dm::pow::PowDifficulty;
use daemonseed_core::dm::{doorbell, firstcontact};
use daemonseed_core::identity::keys::{derive_identity_keys, Identity, IdentityKeys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_veilid_net::actor::DoorbellDispatch;
use daemonseed_veilid_net::{VeilidNet, VeilidNetConfig};

/// The first-contact epoch both ends agree on for this run. `open` accepts the
/// current epoch and the one before it; zero has no predecessor, so this pins the
/// test to exactly one epoch and removes the tolerance window as a variable.
const FC_EPOCH: u64 = 0;

/// A node config with a fresh daemonseed-derived node identity, a distinct listen
/// port, and its own storage dir — so two can coexist in one process. The node
/// identity is per-node and unrelated to the *user* identities under test.
fn node_config(port: &str, dir: &std::path::Path) -> VeilidNetConfig {
    let id = derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
    let mut cfg = VeilidNetConfig::new(id.veilid_node_seed, dir.to_string_lossy().into_owned());
    cfg.namespace = format!("two_node_doorbell{}", port.replace(':', "_"));
    cfg.listen_address = Some(port.to_owned());
    cfg
}

/// A fresh user identity. Fresh per run rather than fixed, because a doorbell's
/// address is deterministic in the identity and PERSISTS on the public DHT, so a
/// fixed recipient would inherit every previous run's knocks.
fn identity() -> IdentityKeys {
    derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).expect("identity")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored"]
async fn a_knock_reaches_the_recipients_doorbell_and_opens_for_them_alone() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    let base = std::env::temp_dir().join("daemonseed-veilid-net-doorbell-it");
    let _ = std::fs::remove_dir_all(&base);

    // **B is drawn until A's slot at B is non-zero, and that is not fussiness.** The
    // slot is `HKDF(A's secret, B's pubkey) % 32`, so with fresh per-run identities
    // one run in thirty-two draws slot 0 — and on that run a transport that hard-wired
    // subkey 0 would pass. A test that is right for the wrong reason 1 run in 32 is
    // worse than no test, so the draw is constrained and then ASSERTED, which is what
    // makes the wire-fidelity claim below deterministic rather than probabilistic.
    let alice = identity();
    // The per-contact pseudonym A mints for this correspondent. A separate keypair
    // from A's long-term identity by design: the entry binds the two together
    // inside the seal, and the pseudonym is what signs the conversation afterwards.
    let alice_pseudonym = identity();
    let bob = (0..64)
        .map(|_| identity())
        .find(|b| {
            doorbell::slot_for(&alice.dm_doorbell_slot_secret, b.signing.public_key())
                .expect("slot derivation")
                != 0
        })
        .expect("64 draws without a non-zero slot is a broken derivation, not bad luck");

    // Everything node A is allowed to know about B. In production both arrive from
    // B's key record, itself found from the public identity key alone (#232).
    let bob_pk = *bob.signing.public_key();
    let bob_ek = *bob.kem.encapsulation_key();

    let (node_a, _rx_a) = VeilidNet::start(node_config(":5178", &base.join("A")))
        .await
        .expect("start A");
    let (node_b, _rx_b) = VeilidNet::start(node_config(":5179", &base.join("B")))
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

    // ── B's doorbell is empty, and sweeping it does not bring it into being ──
    // Asserted BEFORE anything is written, which is the only moment the absent-record
    // path is observable. `attempted: 0` is the signature of `IfAbsent::ReportAbsent`:
    // a sweep that opened with `Create` would find (or manufacture) a record and
    // report `attempted: 32, found: 0`, which is a different fact — "a doorbell with
    // nothing in it" rather than "no doorbell". Both give an empty slot list, so the
    // outcome is the only thing that tells them apart, and until now nothing asserted
    // it.
    let owner_seed_pre = *doorbell::derive_owner_seed(&bob_pk)
        .expect("B derives its own doorbell owner seed")
        .as_bytes();
    let pre = node_b
        .sweep_doorbell(owner_seed_pre)
        .await
        .expect("sweeping an unknocked doorbell is not an error");
    assert!(
        pre.slots.is_empty(),
        "nobody has knocked yet: {:?}",
        pre.slots.len()
    );
    assert_eq!(
        pre.outcome.attempted, 0,
        "a sweep must NOT create the record it is reading — attempted 0 is what \
         distinguishes `no doorbell` from `a doorbell nobody has written to`, and a \
         read path that creates destroys that difference permanently (#253's argument, \
         on this record)"
    );
    assert_eq!(pre.outcome.found, 0);

    // ── A knocks ─────────────────────────────────────────────────────────────
    const BODY: &str = "knock knock — this is the first thing alice ever said to bob";
    let sent_unix_ms = 1_700_000_000_000i64;
    // Production difficulty, not a reduced one. This test runs on a real host against
    // the public network, so the entry it puts on the wire should be the entry a real
    // sender puts there — a reduced proof would pass here and be refused by any verifier
    // that later reads the slot. The couple of seconds it costs to mint is dwarfed by
    // the DHT propagation this test already waits on.
    let (entry, _state) = firstcontact::build(FirstContactRequest {
        signing_lt: &alice.signing,
        signing_pc: &alice_pseudonym.signing,
        recipient_pk_lt: &bob_pk,
        kem_ek_b: &bob_ek,
        fc_epoch: FC_EPOCH,
        sent_unix_ms,
        body: BODY,
        token: None,
        difficulty: PowDifficulty::PRODUCTION,
    })
    .expect("A builds a first-contact entry");
    assert!(
        entry.len() <= firstcontact::MAX_ENTRY_LEN,
        "a built entry must fit one doorbell subkey: {} > {}",
        entry.len(),
        firstcontact::MAX_ENTRY_LEN
    );

    // A derives B's doorbell address from B's PUBLIC key — the record A is about to
    // write to and create, and does not own.
    let owner_seed_a = *doorbell::derive_owner_seed(&bob_pk)
        .expect("A derives B's doorbell owner seed")
        .as_bytes();
    // And its own slot within it, from a secret only A holds. Nothing B or an
    // observer knows can compute this value; that is what sender-blindness means.
    let slot = doorbell::slot_for(&alice.dm_doorbell_slot_secret, &bob_pk).expect("A derives slot");
    assert_ne!(
        slot, 0,
        "the recipient was drawn for a non-zero slot precisely so that a transport \
         writing a hard-wired subkey 0 fails on EVERY run rather than on 31 of 32"
    );

    node_a
        .publish_doorbell_entry(
            owner_seed_a,
            slot,
            entry.clone(),
            DoorbellDispatch::FirstSend,
        )
        .await
        .expect("A knocks on B's doorbell");

    // ── B sweeps its own doorbell ────────────────────────────────────────────
    // The load-bearing step: B derives the SAME address with no input from A at all.
    // If the derivation were not world-derivable and deterministic, these two seeds
    // would differ and B's sweep would find nothing while A's write reported success.
    let owner_seed_b = *doorbell::derive_owner_seed(&bob_pk)
        .expect("B derives its own doorbell owner seed")
        .as_bytes();
    assert_eq!(
        owner_seed_a, owner_seed_b,
        "sender and recipient must derive the same doorbell from the public key alone"
    );

    // DHT writes are eventually consistent; poll rather than assume convergence.
    let found = poll_for_slot(&node_b, owner_seed_b, slot)
        .await
        .expect("B found A's knock within the convergence window");

    // ── B opens it ───────────────────────────────────────────────────────────
    let verified = firstcontact::open(&found, bob.kem.decapsulation_key(), &bob_pk, FC_EPOCH)
        .expect("the entry opens for B");
    assert_eq!(
        verified.pk_lt(),
        alice.signing.public_key(),
        "the sender B recovers must be the identity that built the entry"
    );
    assert_eq!(
        verified.pk_pc(),
        alice_pseudonym.signing.public_key(),
        "and the pseudonym that will sign the conversation must be the one A minted"
    );
    assert_eq!(
        verified.body(),
        BODY,
        "the message must survive the round trip"
    );
    assert_eq!(verified.sent_unix_ms(), sent_unix_ms);

    // ── an idempotent retry overwrites A's own slot ──────────────────────────
    // The slot is mnemonic-rooted, so a retry must re-land where the first knock
    // went. If it scattered, a sender with a flaky link would consume slots out of
    // only 32 and orphan every earlier attempt (#118's bug class, on a record with
    // no room for it).
    let (retry_entry, _retry_state) = firstcontact::build(FirstContactRequest {
        signing_lt: &alice.signing,
        signing_pc: &alice_pseudonym.signing,
        recipient_pk_lt: &bob_pk,
        kem_ek_b: &bob_ek,
        fc_epoch: FC_EPOCH,
        sent_unix_ms: sent_unix_ms + 1,
        body: BODY,
        token: None,
        difficulty: PowDifficulty::PRODUCTION,
    })
    .expect("A rebuilds its entry for the retry");
    assert_ne!(
        retry_entry, entry,
        "a rebuilt entry differs byte-wise (fresh encapsulation), so a slot that did \
         NOT overwrite would be visible as the old bytes rather than the new"
    );
    let retry_slot =
        doorbell::slot_for(&alice.dm_doorbell_slot_secret, &bob_pk).expect("A re-derives its slot");
    assert_eq!(retry_slot, slot, "a retry must re-derive the same slot");

    node_a
        .publish_doorbell_entry(
            owner_seed_a,
            retry_slot,
            retry_entry.clone(),
            // The retry is a scheduler-driven re-dispatch, so it takes the class
            // `direct-messaging.md:128` gives it — a different lane from the send it
            // repeats, which is exactly what this leg is exercising over a real DHT.
            DoorbellDispatch::Reseed,
        )
        .await
        .expect("A retries its knock");

    let mut overwritten = None;
    for attempt in 0..30 {
        if let Some(bytes) = poll_once(&node_b, owner_seed_b, slot).await {
            if bytes == retry_entry {
                overwritten = Some(bytes);
                break;
            }
            eprintln!("attempt {attempt}: slot still holds the first entry, retrying");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    let overwritten = overwritten.expect("the retry overwrote A's own slot in place");
    let reopened = firstcontact::open(&overwritten, bob.kem.decapsulation_key(), &bob_pk, FC_EPOCH)
        .expect("the retried entry opens for B");
    assert_eq!(
        reopened.sent_unix_ms(),
        sent_unix_ms + 1,
        "the slot must hold the RETRY, not the original"
    );

    // ── a never-knocked doorbell is still absent after all of that ───────────
    // The control that makes the pre-knock assertion mean something. By this point A
    // has created and twice written B's doorbell, so a sweep that creates would look
    // identical to one that does not when pointed at B. Pointed at an identity nobody
    // has ever knocked on, and swept by the same node that has been sweeping all
    // along, `attempted: 0` can only come from `open_only`.
    let never_knocked = identity();
    let unknocked_seed = *doorbell::derive_owner_seed(never_knocked.signing.public_key())
        .expect("derive a never-knocked doorbell")
        .as_bytes();
    assert_ne!(
        unknocked_seed, owner_seed_b,
        "the control must name a DIFFERENT record, or it is re-sweeping B's"
    );
    // Retried, because by this point the run is minutes deep into a live DHT and a
    // routing layer is entitled to answer "TryAgain: offline" for a while. Every
    // other network step here already polls; this one did not, and it failed a
    // whole run on a transient state after every assertion above had passed.
    //
    // **A transient error is NOT read as absence.** Doing that would make this
    // control vacuous — "the record is not there" and "I could not find out" are
    // the same bytes to a caller and opposite facts to this assertion. So the loop
    // waits for a definitive answer and fails with the last error if none arrives.
    let mut unknocked = None;
    let mut last_err = None;
    for attempt in 0..30 {
        match node_b.sweep_doorbell(unknocked_seed).await {
            Ok(outcome) => {
                unknocked = Some(outcome);
                break;
            }
            Err(e) => {
                eprintln!("attempt {attempt}: never-knocked sweep not yet definitive: {e}");
                last_err = Some(e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
    let unknocked = unknocked.unwrap_or_else(|| {
        panic!(
            "sweeping a never-knocked doorbell never returned a definitive answer; \
             last error: {last_err:?}"
        )
    });
    assert!(unknocked.slots.is_empty());
    assert_eq!(
        unknocked.outcome.attempted, 0,
        "sweeping must never create: a doorbell nobody has knocked on must stay \
         absent, however many other doorbells this node has swept"
    );

    // ── and nobody else can open it ──────────────────────────────────────────
    // The doorbell is world-readable as well as world-writable; a co-hosting storage
    // node holds these exact bytes. This is the property that makes that acceptable.
    let mallory = identity();
    assert!(
        firstcontact::open(
            &overwritten,
            mallory.kem.decapsulation_key(),
            mallory.signing.public_key(),
            FC_EPOCH
        )
        .is_err(),
        "a first-contact entry must never open for an identity it was not sealed to"
    );

    eprintln!(
        "ISC-C41 live oracle: knock -> world-derivable doorbell (slot {slot}) -> sweep \
         -> open -> idempotent retry OK"
    );
}

/// One sweep of `owner_seed`'s doorbell, returning the bytes in `slot` if it is
/// populated. Reports the outcome, because an empty slot list and a sweep whose
/// GETs all failed are different facts.
async fn poll_once(
    node: &daemonseed_veilid_net::VeilidNetHandle,
    owner_seed: [u8; 32],
    slot: u16,
) -> Option<Vec<u8>> {
    match node.sweep_doorbell(owner_seed).await {
        Ok(sweep) => {
            eprintln!(
                "sweep: attempted={} found={} failed={}",
                sweep.outcome.attempted, sweep.outcome.found, sweep.outcome.failed
            );
            sweep
                .slots
                .into_iter()
                .find(|(at, _)| *at == slot)
                .map(|(_, bytes)| bytes)
        }
        Err(e) => {
            eprintln!("sweep error {e}, retrying");
            None
        }
    }
}

/// Poll `slot` until it is populated or the convergence window expires.
async fn poll_for_slot(
    node: &daemonseed_veilid_net::VeilidNetHandle,
    owner_seed: [u8; 32],
    slot: u16,
) -> Option<Vec<u8>> {
    for attempt in 0..30 {
        if let Some(bytes) = poll_once(node, owner_seed, slot).await {
            return Some(bytes);
        }
        eprintln!("attempt {attempt}: slot {slot} still empty, retrying");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    None
}

/// **The recipient draw always yields a non-zero slot — runnable here, no network.**
///
/// The live test's wire-fidelity claim ("a transport writing a hard-wired subkey 0
/// fails") is only deterministic because `bob` is drawn until A's slot at B is
/// non-zero. That constraint is pure crypto and needs no DHT, so it is verified on
/// every ordinary `cargo test` run rather than resting on the `#[ignore]`d body
/// nobody executes on this host. Without it the draw loop could be deleted and the
/// live test would silently go back to passing-for-the-wrong-reason 1 run in 32.
#[test]
fn the_recipient_draw_always_yields_a_non_zero_slot() {
    daemonseed_core::kats::initialize_module_unsigned_test_binary().expect("oxicrypt init");

    // Enough repetitions that a draw loop which did not constrain anything would fail
    // with probability 1 - (31/32)^24 ~= 0.53 per run of this test, and a loop that
    // constrained nothing at all fails outright.
    for _ in 0..24 {
        let alice = identity();
        let bob = (0..64)
            .map(|_| identity())
            .find(|b| {
                doorbell::slot_for(&alice.dm_doorbell_slot_secret, b.signing.public_key())
                    .expect("slot derivation")
                    != 0
            })
            .expect("64 draws without a non-zero slot is a broken derivation");
        let slot =
            doorbell::slot_for(&alice.dm_doorbell_slot_secret, bob.signing.public_key()).unwrap();
        assert_ne!(slot, 0, "the constrained draw must never return slot 0");
        assert!(
            slot < doorbell::DOORBELL_SLOTS,
            "and it must still be inside the record"
        );
    }
}
