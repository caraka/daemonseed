//! Circle-of-trust types (ISC-C8 / ISC-A-C8 / ISC-C24).
//!
//! M3 lands the type-only slot for per-circle `min_suite_id`. Circle
//! creation itself (founder enrollment, member join, content posting)
//! arrives in M6 — at that point [`Metadata`] gains construction sites
//! beyond the test surface. Until then the type exists so the wire
//! schema (`daemonseed.v1::CircleMin`) and the at-rest blob can carry
//! the field without speculating about the runtime shape.

pub mod metadata;
