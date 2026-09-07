//! Derive the two public keys a project-release seed bakes into clients.
//!
//! Reads the seed as 64 hex characters from standard input — never from an
//! argument, so it does not land in a shell history or a process listing — and
//! prints what a rotation commits: the SHA-384 of the ML-DSA-87 signing public key
//! (the value `current_trust_anchors_kat` pins) and the announce record's Ed25519
//! owner public key as a Rust array literal (the value of
//! `PROJECT_ANNOUNCE_OWNER_PUBKEY`). With `--pubkey-out <path>` it also writes the
//! raw signing public key to that path, which is the file `include_bytes!` bakes
//! as `project_release_pubkey.bin`.
//!
//! The seed itself is never printed. Every derivation runs through the same
//! functions the runtime uses to check a loaded seed, so this tool cannot disagree
//! with the code that will later refuse a seed that does not match its output.
//!
//!     cargo run -p daemonseed-veilid-net --example project_release_pubkeys -- \
//!         --pubkey-out crates/daemonseed-core/src/project_release_pubkey.bin < seed-file

use std::io::Read;

use daemonseed_core::public_space::{content_address, ProjectReleaseSeed};
use daemonseed_veilid_net::identity::rendezvous_owner_public_bytes;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut pubkey_out: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pubkey-out" => match args.next() {
                Some(path) => pubkey_out = Some(path),
                None => {
                    eprintln!("--pubkey-out needs a path");
                    std::process::exit(2);
                }
            },
            other => {
                eprintln!("unknown argument {other:?}; the seed is read from standard input");
                std::process::exit(2);
            }
        }
    }

    let mut text = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut text) {
        eprintln!("could not read the seed from standard input: {e}");
        std::process::exit(2);
    }
    let seed = match ProjectReleaseSeed::parse_hex(&text) {
        Ok(seed) => seed,
        Err(e) => {
            eprintln!("the seed is malformed: {e}");
            std::process::exit(2);
        }
    };
    // The bytes were read into a plain `String`; the seed has its own zeroizing
    // copy now, so the text is wiped before anything else runs.
    zeroize::Zeroize::zeroize(&mut text);

    if let Err(e) = daemonseed_core::kats::initialize_module_unsigned_test_binary() {
        eprintln!("crypto module init failed: {e}");
        std::process::exit(1);
    }

    let signer = match seed.signing_keypair() {
        Ok(signer) => signer,
        Err(e) => {
            eprintln!("signing key derivation failed: {e}");
            std::process::exit(1);
        }
    };
    let owner = match seed.announce_owner_seed() {
        Ok(owner) => owner,
        Err(e) => {
            eprintln!("announce owner seed derivation failed: {e}");
            std::process::exit(1);
        }
    };
    let owner_public = rendezvous_owner_public_bytes(owner.as_bytes());

    // `content_address` is SHA-384 over its input — the same digest the KAT pins.
    let digest = match content_address(signer.public_key()) {
        Ok(digest) => digest,
        Err(e) => {
            eprintln!("SHA-384 over the signing public key failed: {e:?}");
            std::process::exit(1);
        }
    };
    println!(
        "project-release signing pubkey, SHA-384: {}",
        hex(digest.as_bytes())
    );
    println!("announce owner pubkey, hex: {}", hex(&owner_public));
    println!("announce owner pubkey, Rust array:");
    for row in owner_public.chunks(16) {
        let cells: Vec<String> = row.iter().map(|b| format!("0x{b:02x}")).collect();
        println!("    {},", cells.join(", "));
    }

    if let Some(path) = pubkey_out {
        if let Err(e) = std::fs::write(&path, signer.public_key()) {
            eprintln!("could not write the signing public key to {path}: {e}");
            std::process::exit(1);
        }
        println!(
            "wrote the {}-byte signing public key to {path}",
            signer.public_key().len()
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
