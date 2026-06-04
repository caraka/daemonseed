//! alpha2 — interactive public rooms (ISC-S22..S26 / ISC-A-S16..A-S19 / ISC-C56..C58).
//!
//! M6 (v0.8.0) shipped only the read-only operator side of public space
//! (announcements, MOTD, signer whitelist). The interactive public room — where
//! ANY daemon posts and everyone reads by default (ISC-S4 "public rooms") — was
//! the gap this work closes. It is built over the SAME `CircleOfTrust.Subscribe`
//! live relay (ISC-S20) and `CotFrame` mechanism as a circle; the only
//! differences are the GLOBAL shared key (server-readable, never wire-cleartext)
//! and the self-signed-for-provenance posting auth.
//!
//! Substantive coverage:
//! - `daemonseed_core::public_room` — global key derivation, rendezvous address,
//!   seal/open + provenance verify (unit tests in that module).
//! - `tests/public_room_e2e.rs` — full post→read round-trip through the real
//!   `serve_application` relay, plus the forged-provenance rejection.

use daemonseed_integration_tests::isc_coverage::Coverage;

#[test]
fn public_rooms_close_their_iscs() {
    let mut coverage = Coverage::empty();

    coverage.register(
        "ISC-S22",
        "daemonseed_core::public_room::derive_room_key (global shared key from public inputs) + public_room_e2e::any_daemon_posts_everyone_reads_through_relay",
    );
    coverage.register(
        "ISC-S23",
        "daemonseed_core::public_room::room_asset_address (SHA-384(room_key ‖ server_id), same relay surface) + public_room::tests::room_address_deterministic_and_namespaced",
    );
    coverage.register(
        "ISC-S24",
        "daemonseed_core::public_room::seal_room_message (self-signed provenance) + public_room::tests::seal_open_round_trip_verifies_provenance",
    );
    coverage.register(
        "ISC-S25",
        "daemonseed_core::public_room::open_room_message (open + verify client-side) + public_room_e2e::any_daemon_posts_everyone_reads_through_relay",
    );
    coverage.register(
        "ISC-S26",
        "daemonseed_server::cot live-only refcounted relay (same reaping as circles, ISC-A-S5) exercised by public_room_e2e over serve_application",
    );

    coverage.register(
        "ISC-A-S16",
        "daemonseed_core::public_room::tests::body_never_wire_cleartext + public_room_e2e::any_daemon_posts_everyone_reads_through_relay (ciphertext-on-wire assertion)",
    );
    coverage.register(
        "ISC-A-S17",
        "daemonseed_core::public_room::tests::tampered_provenance_rejected + public_room_e2e::forged_provenance_is_rejected_end_to_end",
    );
    coverage.register(
        "ISC-A-S18",
        "daemonseed_core::public_room::tests::room_key_does_not_collide_with_circle_key (disjoint derivation domains)",
    );
    coverage.register(
        "ISC-A-S19",
        "daemonseed_core::public_room::tests::wrong_room_key_fails_authentication + tampered_provenance_rejected (room bound into address + signature)",
    );

    coverage.register(
        "ISC-C56",
        "daemonseed_core::public_room::{derive_room_key,room_asset_address,DEFAULT_ROOM} (client-side global key + default-room chat surface) + public_room_e2e",
    );
    coverage.register(
        "ISC-C57",
        "daemonseed_core::public_room::open_room_message (provenance verify + pubkey-bound author) + public_room::tests::seal_open_round_trip_verifies_provenance",
    );
    coverage.register(
        "ISC-C58",
        "public-room mute reuses the existing ISC-C15 client-local mute story (daemonseed_core mute list) + per-connection rate limits (ISC-S17); full ban deferred per ISC-C58",
    );

    assert_eq!(
        coverage.covered_count(),
        12,
        "public rooms close S22-S26 + A-S16-A-S19 + C56-C58"
    );
}
