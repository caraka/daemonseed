//! daemonseed-core — protocol library.
//!
//! Identity primitives, profile substrate, and crypto plumbing for the
//! daemonseed client and server. M1 lands the foundational pieces — handle
//! format, BIP-39 mnemonic, HKDF-derived ML-DSA-87 / ML-KEM-1024 keypairs,
//! at-rest blob storage. M4a adds the wire-protocol negotiation policy
//! ([`version`]) and the type-state [`connection::Connection`] machine
//! that gates pre-auth traffic at compile time per ISC-C23. M6 adds
//! [`public_space`] — the signed-artifact model (content-address,
//! signer whitelist, ML-DSA-87 verification) the server and clients share
//! for the post-Authenticated public-space service. M8 adds the circle path:
//! [`circle::key`] (shared-entropy key derivation), [`cot`] (rendezvous
//! addressing), [`storage::cas`] (the content-addressed chunk store),
//! [`storage::share_index`] (the encrypted redb share index), and [`indexer`]
//! (the share-folder indexer engine driving that index). M9 adds client-side
//! abuse-resilience and chat affordances: [`backoff`] (reconnect curve +
//! close-cause categorization, ISC-C26), [`mention`] (@-mention recognition +
//! resolution, ISC-C17/C18), and the mute / hide-shares lists on
//! [`storage::seeds::Seeds`] (ISC-C15/C16). M10-completion adds the two
//! platform-feature *scaffolds*: [`biometric`] (the `BiometricStore` trait for
//! secure-enclave session-passphrase unlock, ISC-C7) and [`autostart`] (the
//! pure OS-autostart descriptor generator + `AutostartManager` trait,
//! ISC-C20) — abstraction + opt-in flags + warnings only; the platform halves
//! are reserved to the future GUI/mobile client. Alpha2 adds [`share_serve`] —
//! the reusable sharer-side of the share-fetch protocol ([`ShareContent`]:
//! directory indexing + content-addressed chunk store + the pure manifest/chunk
//! `answer` step), factored out of the integration test so `cli publish --path`
//! and the tests drive byte-identical serve logic (ISC-S27 / ISC-S28 / ISC-S29).
//! The unified share model adds [`share_announce`] — seal/open for the in-band
//! share-announcement payload that replaces relay-hosted share discovery, the
//! share-tier analogue of [`public_room`] — its request-half [`share_rollcall`]
//! (the sealed late-join roll-call that prompts live sharers to re-announce),
//! [`share_catalog`] (the client-side discovery catalog that folds announcements
//! and ages them out, replacing the relay's share registry) — and [`share_seal`],
//! which seals the
//! [`share_envelope::ShareFrame`] content itself so share traffic is
//! indistinguishable from chat on the wire. Both seal under tier-typed keys
//! ([`circle::key::CircleKey`] / [`public_room::PublicRoomKey`], the key-class
//! guard). Design-of-record: `docs/design/unified-share-model.md`.
//!
//! [`ShareContent`]: share_serve::ShareContent

#![forbid(unsafe_code)]

pub mod autostart;
pub mod backoff;
pub mod biometric;
pub mod bootstrap;
pub mod circle;
pub mod connection;
pub mod cot;
pub mod crypto;
pub mod federation;
pub mod first_start;
pub mod format;
pub mod handle;
pub mod heartbeat;
pub mod identity;
pub mod identity_proof;
pub mod indexer;
pub mod kdf;
pub mod mention;
pub mod passphrase;
pub mod presence;
pub mod profile;
pub mod public_room;
pub mod public_space;
pub mod release;
pub mod share_announce;
pub mod share_catalog;
pub mod share_envelope;
pub mod share_rollcall;
pub mod share_seal;
pub mod share_serve;
pub mod storage;
pub mod transcript;
pub mod trust_events;
pub mod version;
