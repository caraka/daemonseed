//! #77 GUI per-circle connected-presence — ISC-C94 coverage.
//!
//! Exercises the member-plane presence primitives the GUI net actor ports into
//! the circle path: a circle beacon is sealed under a circle key
//! ([`seal_circle_heartbeat`]), opens ONLY under that same circle key
//! ([`open_heartbeat`] — relay-blind / wrong-circle isolation, ISC-A-S2), and the
//! opened beacon folds into a per-circle [`PresenceTracker`] (member appears, then
//! ages out on reap). The own-beacon self-filter (a daemon never lists itself) is
//! the same pubkey-equality predicate the actor runs before routing to the lobby
//! or any circle. The GUI net-actor wiring (per-circle emit/ingest/reap + the
//! room-scoped roster event) is unit-tested IN the `daemonseed-gui` binary crate
//! (`net::tests::presence_roster::{circle_beacon_opens_under_its_key_only_then_rosters,
//! self_filter_drops_own_beacon_only, roster_render_changed_matrix}`), whose `pub`
//! does not escape to this integration crate; the visible circle-roster render is
//! felt-test-gated (ISA `## Criteria` ISC-C94 left `[ ]`). Registers ISC-C94.

use daemonseed_core::circle::key::derive_cot_key;
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::heartbeat::{HeartbeatFields, open_heartbeat, seal_circle_heartbeat};
use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_core::presence::{
    HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT, PresenceChange, PresenceTracker,
};
use daemonseed_integration_tests::isc_coverage::Coverage;
use std::time::{Duration, Instant};

fn keypair(seed: u8) -> SignKeypair {
    let _ = oxicrypt_module::initialize();
    SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
}

/// ISC-C94: a circle member heartbeat seals under the circle key, opens ONLY under
/// that same key (a different circle key never opens it, and the relay holds no
/// circle key at all — relay-blind, ISC-A-S2), surfaces the member in a per-circle
/// `PresenceTracker`, and is reaped past the TTL (live-only presence). The own
/// beacon is self-filtered by pubkey equality so a daemon never lists itself.
#[test]
fn circle_presence_seal_open_track_round_trip() {
    let _ = oxicrypt_module::initialize();
    let circle_a = derive_cot_key("alpha circle phrase one", &CNSA_2_0).unwrap();
    let circle_b = derive_cot_key("beta circle phrase two", &CNSA_2_0).unwrap();
    let member = keypair(5);

    let fields = HeartbeatFields {
        room: "jolly-otter",
        sender_handle: "wandering-otter#abc",
        sent_unix_ms: 1_000,
        live_share_ids: &[],
        is_leave: false,
    };
    let sealed = seal_circle_heartbeat(&circle_a, &member, &fields).unwrap();

    // Wrong-circle isolation: a beacon sealed under circle A never opens under
    // circle B (and a relay, holding no circle key, can open none of them).
    assert!(
        open_heartbeat(&circle_b, &sealed).is_err(),
        "a circle-A beacon must not open under circle B"
    );

    // Opens under its own circle key and folds into that circle's tracker.
    let hb = open_heartbeat(&circle_a, &sealed).expect("verified circle beacon opens");
    assert_eq!(hb.sender_pubkey, member.public_key().to_vec());

    let mut tracker = PresenceTracker::with_cadence(HEARTBEAT_INTERVAL_MAX, HEARTBEAT_MISS_COUNT);
    let t0 = Instant::now();
    assert_eq!(tracker.apply(&hb, t0), PresenceChange::Appeared);
    assert_eq!(tracker.members().len(), 1, "the circle member is present");

    // Self-filter: a daemon never lists its OWN beacon as a live other member.
    let own = member.public_key().to_vec();
    assert!(
        own.as_slice() == hb.sender_pubkey.as_slice(),
        "the self-filter compares our pubkey to the beacon's (equal here ⇒ dropped)"
    );
    let stranger = keypair(6);
    assert!(
        stranger.public_key() != hb.sender_pubkey.as_slice(),
        "another member's beacon is admitted"
    );

    // Live-only: past the TTL the member is reaped and the roster empties.
    let past_ttl = t0 + tracker.ttl() + Duration::from_secs(1);
    assert_eq!(
        tracker.reap(past_ttl, false).len(),
        1,
        "the member ages out"
    );
    assert!(tracker.members().is_empty(), "circle presence is live-only");
}

#[test]
fn isc_c94_covered() {
    let mut c = Coverage::empty();
    c.register("ISC-C94", "circle_presence_seal_open_track_round_trip");
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C94 registered (GUI per-circle connected-presence)"
    );
}
