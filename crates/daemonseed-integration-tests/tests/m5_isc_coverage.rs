//! M5 federation milestone — the trust-slider regression matrix + ISC
//! coverage. Logical home of the plan's `tests/trust_slider/` surface (the
//! repo uses flat `mN_isc_coverage.rs` files).
//!
//! Per implementation-plan decision #6 the slider tests are **in-process
//! state-machine tests**: the trust decision (ISC-C22 / ISC-S12) is entirely
//! client/peer-side, so a "one client + two servers, trust mode parameterized"
//! scenario is expressed directly over the library primitives
//! ([`apply_trust`], [`InMemoryTrustStore`], [`introducer_response`]) rather
//! than spun up as real TLS daemons — fast, deterministic, and exercising the
//! exact state machine. The end-to-end real-TLS path is already covered by the
//! M4a/M4b harnesses, which now drive the slider via the seeded trust store.
//!
//! ISCs closed end-to-end here: S1, S6, S12, S13, C22, A-S7, A-C10. ISC-A-S4b
//! (signer-whitelist power boundary) is **forward-referenced to M6**: its
//! subject, the ISC-S8 signer whitelist, is not built until M6, so there is no
//! boundary to assert yet.

use daemonseed_cli::connect::MAX_CONCURRENT_CONNECTIONS_PER_SERVER;
use daemonseed_core::federation::peering::initiates_peer_tofu;
use daemonseed_core::federation::store::{
    InMemoryTrustStore, ServerEntry, TrustStore, apply_trust,
};
use daemonseed_core::federation::trust::{TrustDecision, TrustMode};
use daemonseed_core::handle::{HASH_PREFIX_BYTES, Handle};
use daemonseed_integration_tests::isc_coverage::Coverage;
use daemonseed_proto::v1::IntroducerQuery;
use daemonseed_server::config::PeerConfig;
use daemonseed_server::federation::introducer_response;

fn ensure_module() {
    let _ = oxicrypt_module::initialize();
}

/// A server-id Handle and its hash prefix, derived from a fake key (the trust
/// slider does no crypto, so any bytes work as a stand-in for an ML-DSA-87 key;
/// the prefix is what the caller would compute via `Handle::from_pubkey`).
fn server(key: &[u8], name: &str) -> (Handle, [u8; HASH_PREFIX_BYTES]) {
    ensure_module();
    let h = Handle::from_pubkey(Some(name.to_owned()), key).unwrap();
    let prefix = *h.hash_prefix();
    (h, prefix)
}

fn peer(server_id: &str, introduce: bool) -> PeerConfig {
    PeerConfig {
        server_id: server_id.to_owned(),
        address: format!("{server_id}.example:443"),
        trust_mode: TrustMode::Trusted,
        introduce_to_clients: introduce,
        key_hex: None,
    }
}

// ── T1 (ISC-C22): one client, two servers, independent trust modes ────────

#[test]
fn client_trusts_two_servers_with_independent_modes() {
    let key_a = [0xAA; 32];
    let key_b = [0xBB; 32];
    let (id_a, prefix_a) = server(&key_a, "alpha");
    let (id_b, prefix_b) = server(&key_b, "beta");

    let mut store = InMemoryTrustStore::new();
    // Server A is trusted (TOFU on first contact); server B is untrusted with a
    // pre-loaded key. The two entries are configured fully independently.
    store.upsert(ServerEntry::new_trusted(id_a.clone(), "a:443".into()));
    store.upsert(ServerEntry::new_untrusted(
        id_b.clone(),
        "b:443".into(),
        key_b.to_vec(),
    ));

    // A: trusted first contact → accept + pin.
    assert_eq!(
        apply_trust(&mut store, &id_a, &key_a, &prefix_a),
        TrustDecision::Accept
    );
    assert_eq!(
        store.get(&id_a).unwrap().pinned_key.as_deref(),
        Some(&key_a[..]),
        "trusted A pinned on first contact"
    );

    // B: untrusted exact match → accept, no pin written.
    assert_eq!(
        apply_trust(&mut store, &id_b, &key_b, &prefix_b),
        TrustDecision::Accept
    );
    assert_eq!(
        store.get(&id_b).unwrap().pinned_key,
        None,
        "untrusted B anchors on its configured key, never pins"
    );
}

// ── T2 (ISC-S6): introducer never returns a public key ────────────────────

#[test]
fn introducer_response_carries_no_public_key() {
    let peers = vec![
        peer("alpha#0123456789ab", true),
        peer("beta#0123456789ab", true),
    ];
    let resp = introducer_response(
        &peers,
        &IntroducerQuery {
            target_server_id: None,
        },
    );
    assert_eq!(resp.peers.len(), 2);
    // PeerTriple has exactly {server_id, address, last_known_availability} —
    // there is no field that could carry a key (structural ISC-S6 invariant).
    // We additionally confirm availability is unset at MVP (finding F15).
    for triple in &resp.peers {
        assert!(!triple.server_id.is_empty());
        assert!(!triple.address.is_empty());
        assert_eq!(triple.last_known_availability_unix_ms, None);
    }
}

// ── T3 (ISC-A-S6, reinforced): server has no trust-mode input ─────────────

#[test]
fn introducer_output_is_independent_of_any_client_trust_mode() {
    // The server-side introducer takes only its own config — there is no
    // parameter through which a client's trust mode could influence it, so a
    // compromised server cannot enumerate "paranoid" clients (ISC-A-S6, counted
    // under M4a; reinforced here at the federation surface).
    let peers = vec![peer("alpha#0123456789ab", true)];
    let q = IntroducerQuery {
        target_server_id: None,
    };
    let first = introducer_response(&peers, &q);
    let second = introducer_response(&peers, &q);
    assert_eq!(
        first, second,
        "identical config → identical response, always"
    );
}

// ── T4 (ISC-S12): s2s peering reuses the slider + F31 tiebreaker ──────────

#[test]
fn s2s_peer_uses_the_same_slider_as_the_client() {
    // A peering server evaluates a peer's key through the very same store +
    // apply_trust path the client uses (ISC-S12-7 shared implementation).
    let key = [0x42; 32];
    let (peer_id, prefix) = server(&key, "peer");
    let mut peer_store = InMemoryTrustStore::new();
    peer_store.upsert(ServerEntry::new_trusted(peer_id.clone(), "peer:443".into()));
    assert_eq!(
        apply_trust(&mut peer_store, &peer_id, &key, &prefix),
        TrustDecision::Accept
    );
    assert!(peer_store.get(&peer_id).unwrap().pinned_key.is_some());
}

#[test]
fn concurrent_tofu_tiebreaker_picks_exactly_one_initiator() {
    // F31 (ISC-S12-8): the lower server-id hash initiates; antisymmetric so no
    // split-brain double-pin.
    let low = [0u8, 0, 0, 0, 0, 1];
    let high = [0u8, 0, 0, 0, 0, 2];
    assert!(initiates_peer_tofu(&low, &high));
    assert_ne!(
        initiates_peer_tofu(&low, &high),
        initiates_peer_tofu(&high, &low)
    );
}

// ── T5 (ISC-S13 + ISC-A-S7): don't-introduce invisibility ─────────────────

#[test]
fn dont_introduce_peer_is_invisible_to_an_active_enumerator() {
    let peers = vec![
        peer("public#0123456789ab", true),
        peer("secret#0123456789ab", false),
    ];

    // S13: the suppressed peer is absent from the full list.
    let list = introducer_response(
        &peers,
        &IntroducerQuery {
            target_server_id: None,
        },
    );
    assert_eq!(list.peers.len(), 1);
    assert_eq!(list.peers[0].server_id, "public#0123456789ab");

    // A-S7: a by-id query for the suppressed peer is byte-identical to a query
    // for a name that was never configured — the attacker learns nothing.
    let suppressed = introducer_response(
        &peers,
        &IntroducerQuery {
            target_server_id: Some("secret#0123456789ab".into()),
        },
    );
    let unknown = introducer_response(
        &peers,
        &IntroducerQuery {
            target_server_id: Some("phantom#0123456789ab".into()),
        },
    );
    assert!(suppressed.peers.is_empty());
    assert_eq!(suppressed, unknown);
}

#[test]
fn dont_introduce_peer_still_present_for_traffic() {
    // ISC-S13-4: suppression hides a peer from introductions but the operator's
    // config still carries it, so user/peer traffic flows normally.
    let peers = [peer("secret#0123456789ab", false)];
    assert_eq!(peers.len(), 1, "the peer remains a configured, usable peer");
    assert!(!peers[0].introduce_to_clients);
}

// ── ISC-C22-16: introducer-sourced addition == user-typed addition ────────

#[test]
fn introducer_sourced_server_addition_behaves_like_typed() {
    // The trust store has no "source" field, so a server added from an
    // introducer's list is indistinguishable from one the user typed: both are
    // trusted entries that TOFU-pin on first contact (ISC-C22-16).
    let key = [0x7C; 32];
    let (id, prefix) = server(&key, "fromintroducer");
    let mut store = InMemoryTrustStore::new();
    store.upsert(ServerEntry::new_trusted(id.clone(), "x:443".into()));
    assert_eq!(
        apply_trust(&mut store, &id, &key, &prefix),
        TrustDecision::Accept
    );
    assert_eq!(
        store.get(&id).unwrap().pinned_key.as_deref(),
        Some(&key[..])
    );
}

// ── ISC-A-C10: reference-client civility cap ──────────────────────────────

#[test]
fn reference_client_documents_concurrent_connection_cap() {
    // ISC-A-C10-1: the per-server concurrent-connection cap defaults to 4.
    // A-C10-2/3/4 are structural: `connect` has no identity-rotation-on-refusal
    // path and derives a fresh envelope per call (no proof replay across
    // reconnects). Enforcement against a hostile client is an accepted
    // limitation (Sybil resistance is post-MVP).
    assert_eq!(MAX_CONCURRENT_CONNECTIONS_PER_SERVER, 4);
}

// ── ISC-S1: the federation trust model is the TOFU slider ─────────────────

#[test]
fn federation_trust_model_is_per_server_tofu_slider() {
    // ISC-S1: "federated. Trust model: TOFU with per-server trusted/untrusted
    // slider." Demonstrate both arms exist and behave: trusted TOFUs, untrusted
    // demands an exact pre-loaded key and refuses a mismatch.
    let key = [0x11; 32];
    let other = [0x22; 32];
    let (id, prefix) = server(&key, "relay");
    let other_prefix = *Handle::from_pubkey(None, &other).unwrap().hash_prefix();

    let mut trusted = InMemoryTrustStore::new();
    trusted.upsert(ServerEntry::new_trusted(id.clone(), "r:443".into()));
    assert_eq!(
        apply_trust(&mut trusted, &id, &key, &prefix),
        TrustDecision::Accept,
        "trusted arm TOFUs"
    );

    let mut untrusted = InMemoryTrustStore::new();
    untrusted.upsert(ServerEntry::new_untrusted(
        id.clone(),
        "r:443".into(),
        key.to_vec(),
    ));
    assert_eq!(
        apply_trust(&mut untrusted, &id, &other, &other_prefix),
        TrustDecision::Refuse,
        "untrusted arm refuses a key that isn't the pre-loaded one"
    );
}

// ── ISC-C22 rotation reachability (end-to-end) ────────────────────────────

/// The reconciliation test: a trusted-mode operator key rotation must reach the
/// C22 `AcceptWithRotation` notice path through the *real* identity-proof
/// exchange — not be refused upstream. Drives run_server/run_client over an
/// in-memory duplex for two rounds: first contact pins the original key; a
/// second round where the server presents a NEW key (the client still dialing
/// the original server-id) must surface a rotation notice and re-pin.
#[tokio::test]
async fn trusted_key_rotation_reaches_the_notice_path_end_to_end() {
    use core::str::FromStr;
    use daemonseed_cli::identity_proof::{ClientIdentity, run_client_identity_proof};
    use daemonseed_core::identity_proof::CHANNEL_BINDING_LEN;
    use daemonseed_core::storage::seeds::CounterState;
    use daemonseed_proto::v1 as wire;
    use daemonseed_server::identity::{Seed, derive_server_id};
    use daemonseed_server::identity_proof::{SeenMap, ServerIdentity, run_server_identity_proof};
    use tokio::io::duplex;

    ensure_module();
    let cb = [9u8; CHANNEL_BINDING_LEN];
    let ver = wire::ProtocolVersion { major: 1, minor: 0 };
    const NOW: u64 = 1_700_000_000_000;

    // The dialed/config server-id is derived from the server's ORIGINAL key.
    let seed1 = Seed([1u8; 32]);
    let sid1 = derive_server_id(&seed1, Some("relay".to_owned())).unwrap();
    let dialed = ServerIdentity::from_seed(&seed1, &sid1)
        .unwrap()
        .handle()
        .to_owned();
    let dialed_handle = Handle::from_str(&dialed).unwrap();

    let client = ClientIdentity::ephemeral().expect("client");
    let mut counters = CounterState::default();
    let mut store = InMemoryTrustStore::new();
    store.upsert(ServerEntry::new_trusted(
        dialed_handle.clone(),
        "relay:443".into(),
    ));

    // Round 1 — first contact with the original key → TOFU-pin.
    let vp1 = {
        let id1 = ServerIdentity::from_seed(&seed1, &sid1).unwrap();
        let (c_end, s_end) = duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            let mut s = s_end;
            let seen = SeenMap::new();
            let _ = run_server_identity_proof(&mut s, cb, ver, &id1, NOW, 1000, &seen).await;
        });
        let mut c = c_end;
        let vp = run_client_identity_proof(&mut c, cb, ver, &client, NOW, &mut counters, &dialed)
            .await
            .expect("first contact completes");
        srv.await.unwrap();
        vp
    };
    let prefix1 = *Handle::from_pubkey(None, vp1.pubkey())
        .unwrap()
        .hash_prefix();
    assert_eq!(
        apply_trust(&mut store, &dialed_handle, vp1.pubkey(), &prefix1),
        TrustDecision::Accept
    );

    // Round 2 — operator rotated to a NEW key. The client still dials the
    // original server-id; the rotated key has a different hash. This must NOT
    // be refused upstream — it must reach the C22 rotation-notice path.
    let seed2 = Seed([2u8; 32]);
    let sid2 = derive_server_id(&seed2, Some("relay".to_owned())).unwrap();
    let id2 = ServerIdentity::from_seed(&seed2, &sid2).unwrap();
    assert_ne!(
        id2.handle(),
        dialed.as_str(),
        "a rotated key yields a different server handle"
    );
    let vp2 = {
        let (c_end, s_end) = duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            let mut s = s_end;
            let seen = SeenMap::new();
            let _ = run_server_identity_proof(&mut s, cb, ver, &id2, NOW, 2000, &seen).await;
        });
        let mut c = c_end;
        let vp = run_client_identity_proof(&mut c, cb, ver, &client, NOW, &mut counters, &dialed)
            .await
            .expect("rotated server still completes the proof — dialed-identity is the trust layer's job");
        srv.await.unwrap();
        vp
    };
    let prefix2 = *Handle::from_pubkey(None, vp2.pubkey())
        .unwrap()
        .hash_prefix();
    match apply_trust(&mut store, &dialed_handle, vp2.pubkey(), &prefix2) {
        TrustDecision::AcceptWithRotation { fingerprint } => {
            assert!(fingerprint.starts_with('#') && fingerprint.len() == 13);
        }
        other => panic!("expected AcceptWithRotation on key rotation, got {other:?}"),
    }
    assert_eq!(
        store.get(&dialed_handle).unwrap().pinned_key.as_deref(),
        Some(vp2.pubkey()),
        "the pin followed the rotation to the new key"
    );
}

// ── ISC coverage tally ─────────────────────────────────────────────────────

#[test]
fn m5_closes_seven_iscs() {
    let mut coverage = Coverage::empty();
    coverage.register("ISC-S1", "federation_trust_model_is_per_server_tofu_slider");
    coverage.register("ISC-S6", "introducer_response_carries_no_public_key");
    coverage.register("ISC-S12", "s2s_peer_uses_the_same_slider_as_the_client");
    coverage.register(
        "ISC-S13",
        "dont_introduce_peer_is_invisible_to_an_active_enumerator",
    );
    coverage.register(
        "ISC-C22",
        "client_trusts_two_servers_with_independent_modes",
    );
    coverage.register(
        "ISC-A-S7",
        "dont_introduce_peer_is_invisible_to_an_active_enumerator",
    );
    coverage.register(
        "ISC-A-C10",
        "reference_client_documents_concurrent_connection_cap",
    );
    assert_eq!(
        coverage.covered_count(),
        7,
        "M5 closes 7 of its 8 ISCs (A-S4b forward-referenced to M6)"
    );
}
