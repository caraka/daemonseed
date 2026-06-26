//! #66 rename identity from the Ctrl-K palette — ISC-C95 coverage.
//!
//! Exercises the persistence substrate the palette rename depends on: a display
//! name set on an unlocked identity ([`Seeds::set_display_name`]) re-seals under the
//! cached at-rest key ([`SealingKey::seal`]) and survives an unlock from disk — the
//! same write-through `GuiState::rename_identity` → `Profile::rename` runs, and the
//! same path that recovers a profile created nameless before #65 (a `None` → `Some`
//! display name). The cryptographic identity is unchanged; only the presented name
//! is. The GUI palette wiring (the `on_open_rename` / `on_submit_rename` callbacks,
//! `is_valid_display_name` gating, and the live handle update — the rail identity
//! line plus the net actor's `SetMyHandle`) is unit-tested IN the `daemonseed-gui`
//! binary crate (`state::tests::rename_identity_*` and
//! `net::tests::set_my_handle_updates_presented_handle`), whose `pub` does not escape
//! to this integration crate; the visible palette flow is felt-test-gated (ISA
//! `## Criteria` ISC-C95 left `[ ]`). Registers ISC-C95.

use daemonseed_core::bootstrap::BootstrapAnchor;
use daemonseed_core::first_start::FirstStart;
use daemonseed_core::profile::config::ArgonParams;
use daemonseed_core::profile::persist::{
    load_for_unlock, session_materials_from_unlock, write_first_start, write_seeds_blob,
};
use daemonseed_core::storage::seeds;
use daemonseed_integration_tests::isc_coverage::Coverage;

const PASS: &str = "correct horse battery staple table mountain";

fn fast() -> ArgonParams {
    ArgonParams {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    }
}

fn anchor() -> BootstrapAnchor {
    BootstrapAnchor {
        server_id: "relay#aabbccddeeff".to_string(),
        address: "127.0.0.1:443".to_string(),
    }
}

fn temp_root(tag: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ds-rename-isc-{tag}-{}-{nonce}",
        std::process::id()
    ))
}

/// The display name read back after an unlock from disk under the passphrase.
fn name_after_unlock(root: &std::path::Path) -> Option<String> {
    let (config, blob) = load_for_unlock(root).unwrap();
    let opened = seeds::open(&blob, PASS, config.profile_id, config.argon2).unwrap();
    let materials = session_materials_from_unlock(
        opened.seeds,
        opened.key,
        opened.index_key,
        config,
        blob.clone(),
        vec![],
    )
    .unwrap();
    materials.display_name
}

/// Enroll a profile named `initial`, then re-seal it with `renamed` (the rename
/// write-through), and return the name read back from a fresh unlock.
fn rename_round_trip(initial: Option<&str>, renamed: &str) -> Option<String> {
    let _ = oxicrypt_module::initialize();
    let root = temp_root(if initial.is_some() {
        "named"
    } else {
        "nameless"
    });

    let sealed = FirstStart::new().initialize(PASS, fast()).unwrap();
    let phrase = sealed.display_phrase();
    let verified = sealed.verify_round_trip(&phrase).unwrap();
    let materials = verified
        .finalize(initial.map(str::to_owned), anchor())
        .unwrap()
        .into_session_materials();
    assert_eq!(
        materials.display_name.as_deref(),
        initial,
        "fixture: the enrolled name matches"
    );
    write_first_start(&root, &materials, None, false).unwrap();

    // The rename write-through (Profile::rename's core path): unlock the blob to get
    // the at-rest SealingKey, set the new display name on the unlocked seeds, re-seal
    // under that cached key, and write the blob back.
    let (config, blob) = load_for_unlock(&root).unwrap();
    let mut opened = seeds::open(&blob, PASS, config.profile_id, config.argon2).unwrap();
    assert!(
        opened.seeds.set_display_name(Some(renamed.to_owned())),
        "the seeds layer accepts the new name"
    );
    let bytes = opened.key.seal(&opened.seeds).unwrap();
    write_seeds_blob(&root, &bytes).unwrap();

    let out = name_after_unlock(&root);
    let _ = std::fs::remove_dir_all(&root);
    out
}

/// ISC-C95: renaming a NAMED identity re-seals and the new name persists across an
/// unlock from disk.
#[test]
fn rename_named_identity_persists_across_unlock() {
    assert_eq!(
        rename_round_trip(Some("alice"), "bob").as_deref(),
        Some("bob")
    );
}

/// ISC-C95 (#65 recovery): a profile created NAMELESS (the pre-#65 state) can be
/// given a name via the same rename write-through, and that name persists.
#[test]
fn rename_recovers_a_nameless_profile() {
    assert_eq!(rename_round_trip(None, "carol").as_deref(), Some("carol"));
}

#[test]
fn isc_c95_covered() {
    let mut c = Coverage::empty();
    c.register("ISC-C95", "rename_named_identity_persists_across_unlock");
    c.register("ISC-C95", "rename_recovers_a_nameless_profile");
    assert_eq!(
        c.covered_count(),
        1,
        "ISC-C95 registered (palette rename-identity + live update)"
    );
}
