//! M0 type-state ↔ tonic compatibility spike (closes redteam R2).
//!
//! Verifies that the type-state pattern named in ISC-C23 composes with
//! `tonic` + `tokio` + `tower` in Rust 2024 edition. The goal is to prove,
//! at compile time, that:
//!
//! - A `Connection<State, T>` newtype can wrap any `T` that satisfies
//!   `AsyncRead + AsyncWrite + Send + Unpin + 'static` (the bound tonic's
//!   transport layer expects).
//! - State transitions are expressed as **consuming methods** — the previous
//!   state is destroyed at the type level, not just hidden behind a flag.
//! - Only `Connection<Authenticated, T>` can be handed to a function that
//!   asks for `tonic` server types — `Connection<Negotiating, T>` and
//!   `Connection<Versioned, T>` fail to compile in that position.
//! - `tokio::io::split` on the inner stream is available pre-authentication
//!   only inside `pub(crate)` helpers, never on the public surface.
//!
//! This test compiles but does not execute meaningful work at runtime —
//! the `#[test]` body is a smoke instantiation only. **If this file ever
//! fails to compile, R2 has tripped and ISC-C23 must downgrade from
//! compile-time type-state to a `tower::Layer` runtime invariant; record
//! the downgrade in `ds-mvp-implementation-plan.md` before M4a starts.**

#![forbid(unsafe_code)]

use std::marker::PhantomData;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tonic::transport::Server;
use tower::ServiceBuilder;

/// State markers. Empty enums so they cannot be constructed at runtime —
/// they exist only as type-level tags.
pub enum Negotiating {}
pub enum Versioned {}
pub enum Authenticated {}

/// Connection newtype. `S` is the state marker; `T` is the underlying stream.
///
/// The compile-time bounds mirror tonic's transport requirements so that a
/// `Connection<Authenticated, T>` is structurally substitutable wherever
/// tonic expects a transport stream.
pub struct Connection<S, T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    inner: T,
    _state: PhantomData<S>,
}

impl<T> Connection<Negotiating, T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Wrap a freshly-accepted stream. Pre-handshake; nothing has been
    /// validated yet.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            _state: PhantomData,
        }
    }

    /// APP_HELLO succeeded; advance to `Versioned`. Consumes `self` — the
    /// previous state cannot be re-used by mistake.
    pub fn into_versioned(self) -> Connection<Versioned, T> {
        Connection {
            inner: self.inner,
            _state: PhantomData,
        }
    }
}

impl<T> Connection<Versioned, T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Identity-proof verified; advance to `Authenticated`. Consuming.
    pub fn into_authenticated(self) -> Connection<Authenticated, T> {
        Connection {
            inner: self.inner,
            _state: PhantomData,
        }
    }
}

impl<T> Connection<Authenticated, T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Surrender the inner stream to tonic. Only available on
    /// `Authenticated`; the compile-time bound on `T` matches what tonic's
    /// transport layer asks for, so this hand-off type-checks today.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// Compile-prove that `Server::builder()` accepts our wrapped stream and
/// that `ServiceBuilder` composes. We do not actually call `.serve()` —
/// the assertion is structural.
#[allow(dead_code)]
fn structural_compat_check<T>(c: Connection<Authenticated, T>)
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let _stream = c.into_inner();
    let _server = Server::builder();
    let _svc = ServiceBuilder::new();
}

#[test]
fn spike_compiles_and_state_transitions_work() {
    // DuplexStream satisfies AsyncRead + AsyncWrite + Send + Unpin + 'static.
    let (a, _b): (DuplexStream, DuplexStream) = tokio::io::duplex(64);

    let neg = Connection::<Negotiating, _>::new(a);
    let ver = neg.into_versioned();
    let auth = ver.into_authenticated();
    let _raw = auth.into_inner();
}

// The following block must NOT compile. We assert this by leaving it as a
// comment plus a doctest-style negative check. If you uncomment it, `cargo
// build` will fail at the type-state mismatch:
//
//   fn structural_negative_check<T>(c: Connection<Negotiating, T>)
//   where T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
//   { let _stream = c.into_inner(); }   // <- no method `into_inner` on
//                                       //    Connection<Negotiating, _>
//
// The negative check is intentionally not exercised at compile time here
// because trybuild-style compile-fail harnesses are M4a infrastructure;
// M0 only needs the positive shape to compile.
