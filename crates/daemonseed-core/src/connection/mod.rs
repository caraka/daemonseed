//! Type-state wrapper around a TLS-terminated transport.
//!
//! **Invariant 3** in the daemonseed implementation plan: the
//! `Connection<S, T>` machine lives here so server, cli, and tui share
//! exactly one definition of "what state am I in." ISC-C23 mandates
//! compile-time prevention of pre-`APP_HELLO` application traffic via
//! Rust type-state; the M0 spike at
//! `daemonseed-integration-tests/tests/spike_type_state.rs` confirmed
//! this composes cleanly with `tonic 0.12` + `tokio 1.43` + `tower 0.5`
//! under Rust 2024 / 1.95, so we ship the compile-time form (no
//! `tower::Layer` runtime downgrade).
//!
//! ## States
//!
//! ```text
//! Negotiating ──send_hello──▶ Versioned ──(M4b: run_identity_proof)──▶ Authenticated
//! ```
//!
//! Transitions consume `self` so the previous-state value is dropped
//! at the type level — code that holds a `Connection<Negotiating, T>`
//! cannot also hold a `Connection<Versioned, T>` over the same
//! transport. Combined with the deliberate absence of any
//! `AsyncRead`/`AsyncWrite` impl on `Connection<Negotiating, T>` and
//! `Connection<Versioned, T>` (only [`Authenticated`] exposes I/O —
//! and that exposure lands in M4b), pre-auth application traffic is a
//! compile error, not a runtime check.
//!
//! M4a ships `Negotiating → Versioned`. M4b adds
//! `Versioned → Authenticated` and the I/O exposure on `Authenticated`.
//! M4a-side test coverage of the type-state shape lives in this
//! module's unit tests plus the M4a integration-tests crate.

use core::marker::PhantomData;

use tokio::io::{AsyncRead, AsyncWrite};

pub mod state;

pub use state::{Authenticated, ConnState, Negotiating, Versioned};

// ── Transport trait ──────────────────────────────────────────────

/// Abstract bidirectional byte-stream the [`Connection`] type-state
/// wraps. Concrete TLS implementations live in `daemonseed-server`
/// (server-side `tokio_rustls::server::TlsStream`) and
/// `daemonseed-cli` (client-side equivalent). The trait is a marker —
/// it carries no methods of its own; the supertrait bounds are what
/// callers actually use.
///
/// Implementations are free (any type satisfying the bounds gets the
/// blanket impl), so concrete TLS streams need no daemonseed-side
/// glue.
pub trait Transport: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Transport for T {}

// ── Connection<S, T> ─────────────────────────────────────────────

/// Type-state wrapper around a TLS-terminated transport. The state
/// parameter `S` advances through [`Negotiating`] → [`Versioned`] →
/// [`Authenticated`] via consuming transitions, dropping the prior
/// state's value at the type level on each step. See module-level
/// docs for the transition diagram.
///
/// `T` is the underlying transport. For daemonseed-server,
/// `T = tokio_rustls::server::TlsStream<tokio::net::TcpStream>`.
/// For daemonseed-cli, the client-side equivalent.
#[derive(Debug)]
pub struct Connection<S: ConnState, T: Transport> {
    transport: T,
    _state: PhantomData<fn() -> S>,
}

// ── Initial state constructor ────────────────────────────────────

impl<T: Transport> Connection<Negotiating, T> {
    /// Wrap a freshly-TLS-handshaked transport in a `Negotiating`
    /// Connection. The transport's TLS handshake MUST already be
    /// complete; this constructor does not drive it.
    ///
    /// At the type level, the returned value exposes no `AsyncRead`
    /// or `AsyncWrite` — application traffic cannot flow until
    /// `send_hello` advances to `Versioned`.
    pub fn from_handshaked_transport(transport: T) -> Self {
        Self {
            transport,
            _state: PhantomData,
        }
    }

    /// Advance from `Negotiating` to `Versioned`. The caller is
    /// expected to have driven the `APP_HELLO` / `APP_HELLO_ACK`
    /// frame exchange against `transport` using the
    /// `daemonseed-server::hello` framing helpers (which land later
    /// in M4a). This method consumes `self` so the `Negotiating`
    /// value is dropped at the type level on success.
    ///
    /// The hello frame exchange happens **outside** this method
    /// because the frame encoding lives in `daemonseed-proto` and the
    /// framing helpers live in `daemonseed-server` — pulling either
    /// into `daemonseed-core` would invert the dependency direction.
    /// `core` owns the type-state shape; concrete I/O orchestration
    /// is the consumer's responsibility, which the consuming
    /// signature enforces.
    pub fn advance_to_versioned(self) -> Connection<Versioned, T> {
        Connection {
            transport: self.transport,
            _state: PhantomData,
        }
    }
}

// ── Versioned state ──────────────────────────────────────────────

impl<T: Transport> Connection<Versioned, T> {
    /// Borrow the underlying transport for the identity-proof
    /// envelope I/O that M4b will drive. M4a does not ship this
    /// path — kept here to give the M4b implementer the obvious
    /// hook point.
    ///
    /// Note this returns `&mut T`, not an `AsyncRead`/`AsyncWrite`
    /// impl on `Self`. That distinction is deliberate: code that
    /// holds a `Connection<Versioned, T>` and wants to read/write
    /// bytes must explicitly call `transport_mut` and use the
    /// transport's I/O traits directly. There is no automatic
    /// `Versioned → I/O` coercion via the `Connection` wrapper.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// **M4b** — placeholder for the consuming transition that runs
    /// the identity-proof envelope (ISC-S19) and advances to
    /// `Authenticated` on success. M4a ships the type signature so
    /// the consuming-method contract is fixed; M4b fills in the
    /// body.
    #[doc(hidden)]
    pub fn _into_authenticated_m4b_placeholder(self) -> Connection<Authenticated, T> {
        // Body deliberately empty in M4a. M4b replaces with channel-
        // bound identity-proof envelope I/O + verification, and
        // removes the leading underscore + `#[doc(hidden)]`.
        Connection {
            transport: self.transport,
            _state: PhantomData,
        }
    }
}

// ── Authenticated state ──────────────────────────────────────────
//
// M4a deliberately exposes no I/O methods on `Authenticated`. M4b
// adds the `AsyncRead` / `AsyncWrite` impl (or equivalent) so
// application traffic can flow ONLY on a value of this state. The
// type exists in M4a so the state-machine type is complete; the
// transition into it from `Versioned` is the placeholder above.

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use tokio::io::DuplexStream;

    use super::*;

    /// `DuplexStream` is a tokio in-memory bidirectional pair, both
    /// halves satisfy `AsyncRead + AsyncWrite + Send + Unpin + 'static`
    /// — sufficient for verifying `Transport` blanket-impl coverage
    /// without spinning up real TLS.
    fn pair() -> (DuplexStream, DuplexStream) {
        tokio::io::duplex(64)
    }

    /// Constructing a `Connection<Negotiating, _>` and consuming it
    /// into `Versioned` is the M4a happy-path type-state assertion.
    /// If the consuming signature regresses (e.g., someone changes
    /// the transition to `&mut self`), this test stops compiling.
    #[test]
    fn negotiating_advances_to_versioned_via_consuming_transition() {
        let (a, _b) = pair();
        let neg: Connection<Negotiating, _> = Connection::from_handshaked_transport(a);
        let _ver: Connection<Versioned, _> = neg.advance_to_versioned();
        // If we reach this line, the consuming transition compiled +
        // ran. The compile-time-only property we care about is that
        // `neg` is unusable after `advance_to_versioned()` — the
        // borrow checker rejects any later use of the moved value.
    }

    /// The Transport blanket impl covers anything that satisfies the
    /// supertrait bounds — including tokio's in-memory `DuplexStream`.
    /// This is the seam that lets concrete TLS streams plug in
    /// without any per-implementation `impl Transport for ...` glue.
    #[test]
    fn duplex_stream_satisfies_transport() {
        fn assert_transport<T: Transport>(_t: &T) {}
        let (a, _b) = pair();
        assert_transport(&a);
    }

    /// `Connection<Versioned, _>` exposes a mutable transport handle
    /// so M4b's identity-proof envelope I/O has somewhere to go. The
    /// notable absence is any `AsyncRead`/`AsyncWrite` impl on the
    /// `Connection` wrapper itself — by design (see module docs).
    #[test]
    fn versioned_exposes_mutable_transport_for_m4b() {
        let (a, _b) = pair();
        let mut ver: Connection<Versioned, _> =
            Connection::from_handshaked_transport(a).advance_to_versioned();
        let _t: &mut _ = ver.transport_mut();
    }
}
