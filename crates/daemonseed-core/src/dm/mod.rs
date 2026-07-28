//! Direct messaging — one-to-one conversation between two identities
//! (ISC-C38–C46 / ISC-A-C20–A-C25).
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN, DRAFT v6). In one
//! sentence: **a DM is a circle with one other person, where their published
//! identity key replaces the shared phrase.** The sender encapsulates to the
//! recipient's published static ML-KEM-1024 key, seals under the encapsulated
//! secret, and publishes; the recipient decapsulates whenever they next come
//! online. No handshake round-trip, no session, no new transport.
//!
//! Three record kinds carry it, and the shape of each is part of its address:
//!
//! | Record | Schema | Role |
//! |---|---|---|
//! | key record ([`keyrec`]) | `dflt(1)` | the identity's published static KEM key — all of DM discovery |
//! | doorbell | `dflt(32)` | sender-blind first-contact entries, the only unauthenticated write surface |
//! | channel page | `dflt(16)` | the established conversation, owner-write-gated so no third party can forge or erase it |
//!
//! Only the doorbell is world-writable, and it carries no conversation content.
//!
//! Built in dependency order as GitHub issues #232–#236; modules land as their
//! slices do.

pub mod domain;
pub mod doorbell;
pub mod firstcontact;
pub mod keyrec;
