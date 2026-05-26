//! Pi civility benchmark harness for the share indexer (ISC-24 / ISC-A-C7).
//!
//! `#[ignore]`d by design: a normal `cargo test` (and the DoD gate) compiles it
//! but does not run it, so it never slows CI. Run it on the target hardware on
//! demand:
//!
//! ```text
//! DSEED_BENCH_FILES=200000 cargo test -p daemonseed-integration-tests \
//!     --release --ignored indexer_civility_bench -- --nocapture
//! ```
//!
//! `DSEED_BENCH_FILES` scales the synthetic share (default 5000 for a quick
//! local sanity run; the real stress run uses a large value on an SD-card-backed
//! host). What this measures — the distilled ISC-A-C7 pass criteria that *can*
//! be checked in-process:
//!
//! 1. cold-scan time + throughput over a large synthetic share,
//! 2. persistence reuse — a reopen recovers the index with no rescan (ISC-C21),
//! 3. single-file incremental-update throughput (ISC-C21 / no share-wide rewalk).
//!
//! The civility properties that need *external* observation on real hardware —
//! foreground apps staying interactive, the 1-minute load average not pinned
//! above the CPU count — are for the operator to watch during the run; the
//! harness prints `/proc/loadavg` samples on Linux to assist. On Caraka's
//! available rig (a **Pi 5**, not a Pi 4) a pass is *suggestive, not a
//! Pi-4-floor proof* — the Pi 5 is more capable than the documented spec floor;
//! degrade it to SD-card storage for the I/O-bound stress (see the corrected
//! prerequisite decision).

use std::time::Instant;

use daemonseed_core::indexer::{FsEvent, Indexer};
use daemonseed_core::storage::share_index::ShareIndex;

const BENCH_INDEX_KEY: [u8; 32] = [0x24; 32];

fn bench_file_count() -> usize {
    std::env::var("DSEED_BENCH_FILES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000)
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "n/a (non-Linux)".to_owned())
}

#[test]
#[ignore = "civility benchmark — run on target hardware with --ignored"]
fn indexer_civility_bench() {
    let _ = oxicrypt_module::initialize();
    let n = bench_file_count();

    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path().join("share");
    std::fs::create_dir_all(&root).unwrap();

    // Synthetic share: N small files fanned across 256 subdirectories (so the
    // walk hits a realistic directory tree, not one giant flat folder).
    let gen_start = Instant::now();
    for i in 0..n {
        let sub = root.join(format!("d{:03}", i % 256));
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(format!("f{i}.bin")), b"x").unwrap();
    }
    eprintln!("generated {n} files in {:?}", gen_start.elapsed());
    eprintln!("loadavg before scan: {}", loadavg());

    let index = ShareIndex::open(dir.path().join("index.redb"), BENCH_INDEX_KEY).unwrap();
    let indexer = Indexer::new(index, &root);

    // (1) Cold scan.
    let scan_start = Instant::now();
    let indexed = indexer.cold_scan().unwrap();
    let scan = scan_start.elapsed();
    eprintln!(
        "cold-scan: indexed {indexed} files in {scan:?} ({:.0} files/s)",
        indexed as f64 / scan.as_secs_f64()
    );
    eprintln!("loadavg after scan:  {}", loadavg());
    assert_eq!(indexed, n, "cold scan must index every file");

    // (2) Persistence reuse: a fresh open recovers the index without rescanning.
    drop(indexer);
    let reopen_start = Instant::now();
    let index2 = ShareIndex::open(dir.path().join("index.redb"), BENCH_INDEX_KEY).unwrap();
    let reused = index2.len().unwrap();
    eprintln!(
        "reopen: recovered {reused} entries in {:?} (no rescan)",
        reopen_start.elapsed()
    );
    assert_eq!(reused, n, "reopen must recover the persisted index");

    // (3) Incremental single-file updates.
    let indexer = Indexer::new(index2, &root);
    let updates = (n / 10).max(1);
    let upd_start = Instant::now();
    for i in 0..updates {
        let sub = root.join(format!("d{:03}", i % 256));
        let path = sub.join(format!("f{i}.bin"));
        std::fs::write(&path, b"updated-content").unwrap();
        indexer.apply_event(&FsEvent::Upserted(path)).unwrap();
    }
    let upd = upd_start.elapsed();
    eprintln!(
        "incremental: {updates} single-file updates in {upd:?} ({:.0} updates/s)",
        updates as f64 / upd.as_secs_f64()
    );

    eprintln!(
        "\nISC-A-C7 note: foreground responsiveness + 1-min loadavg-not-pinned \
         need external observation on the target host during this run. On a Pi 5 \
         a pass is suggestive, not a Pi-4-floor proof."
    );
}
