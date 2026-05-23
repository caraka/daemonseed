# `src/generated/` — committed snapshot of the wire schema codegen

This directory holds a **read-only snapshot** of the Rust code that
`tonic-build` emits for the `.proto` files under `crates/daemonseed-proto/proto/`.

**It is not what gets compiled.** Every `cargo build` regenerates fresh
output into `OUT_DIR` via `build.rs`; `src/lib.rs` `include!`s from there.

This snapshot exists so:

- Cross-language client implementers can see exactly what Rust types the
  schema produces without running cargo.
- Code review can spot wire-surface changes in the same PR as the .proto
  change (otherwise they'd be invisible until someone built locally).
- CI can refuse PRs where the snapshot has drifted from the .proto files,
  catching `.proto` edits where the author forgot to refresh the snapshot.

## How to refresh

```
cargo xtask gen-proto
```

…writes fresh output into this directory. Commit the result alongside the
`.proto` change.

## How CI verifies

```
cargo xtask check-proto
```

…regenerates into a temp directory and diffs against this snapshot. Exits
non-zero on any difference, with a list of changed files and an instruction
to run `cargo xtask gen-proto`.
