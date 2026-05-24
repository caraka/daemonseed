//! Type-state marker types for [`super::Connection`].
//!
//! The marker types carry no fields — they exist only at the type
//! level. [`Connection<S, T>`](super::Connection) is parametric over
//! `S: ConnState`, and the transitions between states are consuming
//! methods on the corresponding `impl` blocks. See `super`'s
//! module-level docs for the state diagram.

use core::fmt::Debug;

/// Sealed marker trait for state types. Sealed so the daemonseed
/// codebase is the only crate able to introduce new states — third-
/// party clients can compose against `Negotiating` / `Versioned` /
/// `Authenticated` but cannot invent a fourth state and pretend it
/// fits anywhere in the existing machine.
pub trait ConnState: Debug + private::Sealed {}

mod private {
    pub trait Sealed {}
}

/// Pre-`APP_HELLO` state. The TLS handshake is complete; no
/// application-layer negotiation has happened yet. No I/O is exposed
/// at this state — by design.
#[derive(Debug)]
pub enum Negotiating {}

impl ConnState for Negotiating {}
impl private::Sealed for Negotiating {}

/// Post-`APP_HELLO_ACK` state. The wire-protocol version is pinned
/// for the connection's lifetime. M4b's identity-proof envelope flows
/// on this state's transport handle (via [`super::Connection::transport_mut`]);
/// M4a does not invoke that path.
#[derive(Debug)]
pub enum Versioned {}

impl ConnState for Versioned {}
impl private::Sealed for Versioned {}

/// Post-identity-proof state. M4b adds the consuming transition
/// `Versioned → Authenticated` plus the `AsyncRead` / `AsyncWrite`
/// surface that exposes application I/O. M4a defines the type so the
/// machine is shape-complete from day one.
#[derive(Debug)]
pub enum Authenticated {}

impl ConnState for Authenticated {}
impl private::Sealed for Authenticated {}
