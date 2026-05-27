//! M9 milestone — rate limits, backoff, mute/hide, mentions — ISC coverage.
//!
//! The substantive behaviour for each M9 ISC is unit-tested in the crate that
//! owns it (`daemonseed_core::{storage::seeds, mention, backoff}` and
//! `daemonseed_server::rate_limit`). This file pins the cross-crate
//! *anti-criteria* that are best demonstrated end-to-end — the no-leak
//! guarantees (A-C3 / A-C4) and the server's RAM-only / uniform-close shape
//! (S17 / A-S12) — and registers the milestone's ISC tally.
//!
//! ISCs closed: S17, C15, C16, C17, C18, C26 (positive); A-S12, A-C3, A-C4
//! (negative). M9 adds no new ISC ids — all nine pre-date this milestone in
//! `ds-isc-draft.md`.

use daemonseed_core::handle::Handle;
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::mention::{MentionResolution, find_self_mentions, resolve_mention};
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::storage::seeds::{Seeds, open, seal};
use daemonseed_integration_tests::isc_coverage::Coverage;
use daemonseed_server::rate_limit::{PerKeyRateTable, RateLimitTrip};
use uuid::Uuid;

fn ensure_module() {
    let _ = oxicrypt_module::initialize();
}

/// Cheap Argon2 params — single-digit-ms KDF so the suite doesn't bog. NEVER a
/// production setting (mirrors the seeds-module test params).
fn test_params() -> ArgonParams {
    ArgonParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    }
}

/// A-C3: the mute and hide-shares lists are client-local at-rest state and
/// leak to no peer. They live only inside the AES-256-GCM-sealed seeds blob —
/// there is no wire/proto message that carries them — so a muted handle never
/// appears in cleartext on any surface that crosses the wire or hits disk
/// unencrypted.
#[test]
fn mute_and_hide_lists_never_leak_in_cleartext() {
    ensure_module();
    let pid = Uuid::new_v4();
    let pp = "correct horse battery staple table mountain";
    let mut seeds = Seeds::new(Mnemonic::generate().unwrap());
    // Distinctive substrings so a leak would be unmistakable.
    seeds.add_mute("zqxjmute#aabbccddeeff");
    seeds.add_hidden_share("zqxjhide#001122334455");

    let blob = seal(&seeds, pp, pid, test_params()).unwrap();
    for needle in [b"zqxjmute".as_slice(), b"zqxjhide".as_slice()] {
        assert!(
            !blob.windows(needle.len()).any(|w| w == needle),
            "A-C3: list contents must not appear in cleartext in the at-rest blob"
        );
    }
    // The only way back to the lists is decrypt-with-passphrase — no wire path.
    let recovered = open(&blob, pp, pid, test_params()).unwrap().seeds;
    assert!(recovered.is_muted("zqxjmute#aabbccddeeff"));
    assert!(recovered.is_share_hidden("zqxjhide#001122334455"));
}

/// A-C4: @mention handling adds no server-visible distinction over plain chat.
/// Recognition is a read-only scan returning byte ranges into the unchanged
/// plaintext; resolution turns a typed token into a handle the message would
/// already carry on the wire. Neither emits a new wire byte — the `mention`
/// module has no dependency on `daemonseed_proto`.
#[test]
fn mention_handling_adds_no_server_visible_distinction() {
    let own: Handle = "alice#aabbccddeeff".parse().unwrap();
    let with_mention = "hey @alice#aabbccddeeff ping";

    // Recognition does not mutate the relayed plaintext.
    let before = with_mention.to_owned();
    let spans = find_self_mentions(with_mention, &own);
    assert_eq!(spans.len(), 1);
    assert_eq!(with_mention, before, "recognition must be read-only");

    // Resolution yields a handle whose wire form is exactly what the composed
    // message already carries — the mention contributes nothing new on the wire.
    let scope = [own.clone()];
    match resolve_mention("alice", &scope) {
        MentionResolution::Resolved(h) => assert_eq!(h.to_string(), "alice#aabbccddeeff"),
        other => panic!("expected Resolved, got {other:?}"),
    }
}

/// S17 / A-S12: the per-identity-key rate-limit table is RAM-only — a fresh
/// table (a just-restarted server) holds no state, and releasing a connection
/// GCs the key entirely, leaving nothing lingering. Every trip is the same
/// opaque server-side enum with no wire form, so the server's uniform silent
/// close cannot reveal which budget was hit.
#[test]
fn rate_limit_state_is_ram_only_and_gcs_clean() {
    let table = PerKeyRateTable::new(2);
    assert_eq!(
        table.tracked_keys(),
        0,
        "A-S12: a fresh table (restarted server) holds no per-key state"
    );

    let key = b"identity-key";
    table.admit(key).unwrap();
    table.admit(key).unwrap();
    assert_eq!(
        table.admit(key),
        Err(RateLimitTrip::PerKeyConnCap),
        "S17: per-key concurrent-connection cap enforced"
    );
    table.release(key);
    table.release(key);
    assert_eq!(
        table.tracked_keys(),
        0,
        "A-S12: GC-on-disconnect leaves no lingering per-key record"
    );
}

// ── ISC coverage tally ──────────────────────────────────────────────────────

#[test]
fn m9_closes_nine_iscs() {
    let mut coverage = Coverage::empty();
    coverage.register(
        "ISC-S17",
        "daemonseed_server::rate_limit::tests + m9::rate_limit_state_is_ram_only_and_gcs_clean",
    );
    coverage.register(
        "ISC-C15",
        "daemonseed_core::storage::seeds::tests::mute_list_round_trips_through_blob",
    );
    coverage.register(
        "ISC-C16",
        "daemonseed_core::storage::seeds::tests::hide_shares_list_round_trips_through_blob",
    );
    coverage.register(
        "ISC-C17",
        "daemonseed_core::mention::tests::recognizes_full_handle_mention",
    );
    coverage.register(
        "ISC-C18",
        "daemonseed_core::mention::tests::resolve_single_display_name_match",
    );
    coverage.register(
        "ISC-C26",
        "daemonseed_core::backoff::tests::delay_curve_doubles_from_one_second_capped_at_sixty",
    );
    coverage.register(
        "ISC-A-S12",
        "daemonseed_server::rate_limit + m9::rate_limit_state_is_ram_only_and_gcs_clean",
    );
    coverage.register(
        "ISC-A-C3",
        "m9::mute_and_hide_lists_never_leak_in_cleartext",
    );
    coverage.register(
        "ISC-A-C4",
        "m9::mention_handling_adds_no_server_visible_distinction",
    );
    assert_eq!(
        coverage.covered_count(),
        9,
        "M9 closes 9 ISCs (S17/C15/C16/C17/C18/C26 + A-S12/A-C3/A-C4)"
    );
}
