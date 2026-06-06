//! ISC coverage — re-exported from the `daemonseed-isc` leaf crate.
//!
//! The registry (`IscClass`, `ISCS`, `TOTAL`, `COVERED`, `Coverage`, …) was
//! extracted into the zero-dependency `daemonseed-isc` leaf crate (M15 E) so
//! `xtask` can read `TOTAL` / `COVERED` live without dragging in this crate's
//! heavy dependency graph (core + proto). This module re-exports it verbatim, so
//! every `m*_isc_coverage` test keeps using `isc_coverage::{ISCS, Coverage, …}`
//! exactly as before.
pub use daemonseed_isc::*;
