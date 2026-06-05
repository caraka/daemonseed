//! Operator helper: print a relay's server-id (`<name>#<12hex>`) from its seed
//! file, so an operator can hand testers the bootstrap handle without standing
//! up a client. Read-only — it refuses to run if the seed file is absent (so it
//! can never accidentally generate/overwrite a seed).
//!
//! Usage: `print_server_id <path-to-seed.bin> [display_name]`

use std::path::Path;
use std::process::exit;

use daemonseed_server::kats::CNSA_2_0_KATS;
use oxicrypt_module::{AlgorithmProfile, initialize_with_profile};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: print_server_id <seed.bin> [display_name]");
        exit(2);
    };
    let display_name = args.next();

    if !Path::new(&path).exists() {
        eprintln!("seed file not found (refusing to generate): {path}");
        exit(2);
    }

    // The oxicrypt FIPS module gate must be Operational before any ML-DSA
    // keygen (same init the server/cli run at startup), else keygen returns
    // NotOperational.
    initialize_with_profile(CNSA_2_0_KATS, AlgorithmProfile::Cnsa2).unwrap_or_else(|e| {
        eprintln!("oxicrypt module init failed: {e:?}");
        exit(1);
    });

    let seed = daemonseed_server::identity::load_or_generate(Path::new(&path))
        .unwrap_or_else(|e| {
            eprintln!("failed to load seed: {e}");
            exit(1);
        });
    let id = daemonseed_server::identity::derive_server_id(&seed, display_name)
        .unwrap_or_else(|e| {
            eprintln!("failed to derive server-id: {e}");
            exit(1);
        });
    println!("{id}");
}
