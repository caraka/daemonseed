//! Circle-of-trust types (ISC-C8 / ISC-A-C8 / ISC-C24).
//!
//! **Scope: client-only.** Circles in daemonseed are anonymous to the
//! server per ISC-A-S2 — the federation surface never sees which circles
//! exist, who is a member, or any per-circle parameters in cleartext.
//! [`metadata::Metadata`] is a client-local view of a circle a daemon is
//! a member of; it is held inside the at-rest blob (ISC-C3) and exchanged
//! among members exclusively inside CoT-asset ciphertext that the server
//! relays opaquely. The companion `daemonseed.v1::CircleMin` proto
//! message is the inner-payload serialization shape for those encrypted
//! exchanges, never a server-visible field.
//!
//! M3 lands the type-only slot for per-circle `min_suite_id`. Circle
//! creation itself (founder enrollment, member join, content posting)
//! arrives in M6 — at that point [`metadata::Metadata`] gains construction
//! sites beyond the test surface. Until then the type exists so the wire
//! schema (`daemonseed.v1::CircleMin`) and the at-rest blob can carry
//! the field without speculating about the runtime shape.

pub mod metadata;
