//! daemonseed-cli library — the Veilid clients' shared authoring surface.
//!
//! Once the relay transport was retired at the v0.33.0 Veilid cutover the
//! crate stopped being a runnable binary (its only subcommand was the relay
//! `connect`) and became a library the gui/tui import. Two capabilities
//! remain, both transport-independent:
//!
//! - [`route_signer`] — the least-authority `RouteAdvertSigner` adapter the
//!   share-publish path hands `daemonseed-veilid-net`, so a Veilid route
//!   advertisement is signed with the node's identity key without exposing
//!   the key material to the transport crate.
//! - [`public_space`] — the announcements/MOTD **authoring and render**
//!   helpers: sign a MOTD / post ([`public_space::sign_motd`],
//!   [`public_space::sign_post`]), render a signed MOTD as inert plaintext
//!   ([`public_space::render_motd`]), re-verify served artifacts client-side
//!   ([`public_space::verify_served_motd`] / [`public_space::verify_served_post`]),
//!   gate the composer on the signer whitelist
//!   ([`public_space::composer_visible`]), and filter/select share listings
//!   ([`public_space::filter_shares_excluding_hidden`],
//!   [`public_space::filter_shares_by_rating`], [`public_space::select_rating`]).
//!   All pure data plumbing, independent of any transport.

#![forbid(unsafe_code)]

pub mod public_space;
/// Veilid-transport route-advert signing capability.
pub mod route_signer;
