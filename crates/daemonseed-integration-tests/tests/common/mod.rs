//! Shared test-only harness modules. Lives under `tests/common/` so the
//! shipping `daemonseed-integration-tests` library never compiles any of it
//! — ISC-A1 (no test-only surface in ship binaries) survives at the
//! dependency-graph layer.

pub mod gate;
