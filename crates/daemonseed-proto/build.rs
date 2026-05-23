//! Build script — regenerates Rust from `proto/**/*.proto` into `OUT_DIR`.
//!
//! Why OUT_DIR: every `cargo build` regenerates fresh from the .proto files,
//! so the compiled binary is always in lock-step with the wire schema and the
//! source tree never gets mutated by a build.
//!
//! The committed snapshot under `src/generated/` is for human / AI inspection
//! and is maintained separately by `cargo xtask gen-proto`. `cargo xtask
//! check-proto` verifies that the snapshot still matches what tonic-build
//! emits — i.e. that the committed copy hasn't drifted from the .proto files.
//!
//! Keep this build script aligned with `xtask/src/main.rs::compile_protos` so
//! `build.rs` output and xtask snapshot output stay byte-identical.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("proto");

    let protos = collect_protos(&proto_root)?;
    if protos.is_empty() {
        // No .proto files yet — nothing to do. (Allows the crate to compile
        // before the first message is defined.)
        return Ok(());
    }

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    println!("cargo:rerun-if-changed={}", proto_root.display());

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &[proto_root])?;

    Ok(())
}

fn collect_protos(root: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "proto") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}
