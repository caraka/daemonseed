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
//! Negotiating ──advance_to_versioned──▶ Versioned ──into_authenticated(VerifiedPeer)──▶ Authenticated
//! ```
//!
//! Transitions consume `self` so the previous-state value is dropped
//! at the type level — code that holds a `Connection<Negotiating, T>`
//! cannot also hold a `Connection<Versioned, T>` over the same
//! transport. Combined with the deliberate absence of any
//! `AsyncRead`/`AsyncWrite` impl on `Connection<Negotiating, T>` and
//! `Connection<Versioned, T>` (only [`Authenticated`] impls I/O),
//! pre-auth application traffic is a compile error, not a runtime
//! check.
//!
//! The `Versioned → Authenticated` step consumes a
//! [`crate::identity_proof::VerifiedPeer`] — a token only a successful
//! `verify_envelope` can mint — so the gate cannot be skipped: there
//! is no way to construct the argument without a passed identity-proof
//! verification.
//!
//! M4a shipped `Negotiating → Versioned`. M4b adds
//! `Versioned → Authenticated` and the `AsyncRead`/`AsyncWrite`
//! exposure on `Authenticated`.

use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::identity_proof::VerifiedPeer;

pub mod state;

pub use state::{Authenticated, ConnState, Negotiating, Versioned};

// ── Transport trait ──────────────────────────────────────────────

/// Abstract bidirectional byte-stream the [`Connection`] type-state
/// wraps. The trait is a marker — it carries no methods of its own;
/// the supertrait bounds are what callers actually use.
///
/// Implementations are free (any type satisfying the bounds gets the
/// blanket impl), so a concrete stream needs no daemonseed-side glue.
///
/// The type-state machine has no production implementor since the
/// v0.33.0 Veilid cutover retired the TLS-terminated relay transport;
/// it is exercised by the type-state spike test.
pub trait Transport: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Transport for T {}

// ── Connection<S, T> ─────────────────────────────────────────────

/// Type-state wrapper around an authenticated-transport handshake. The
/// state parameter `S` advances through [`Negotiating`] → [`Versioned`]
/// → [`Authenticated`] via consuming transitions, dropping the prior
/// state's value at the type level on each step. See module-level
/// docs for the transition diagram.
///
/// `T` is the underlying transport — any type meeting the [`Transport`]
/// bounds.
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
    /// or `AsyncWrite` — application traffic cannot flow until the
    /// connection reaches `Authenticated` (via `advance_to_versioned`
    /// then `into_authenticated`).
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

    /// Advance from `Versioned` to `Authenticated` (ISC-S19 step 5).
    ///
    /// Consumes a [`VerifiedPeer`] — a token that only
    /// [`crate::identity_proof::verify_envelope`] can mint on a
    /// successful identity-proof verification. Because there is no
    /// other way to obtain one, the type system makes reaching
    /// `Authenticated` without a passed verification impossible
    /// (ISC-C23 compile-time enforcement). The caller derives the
    /// channel binding, exchanges + verifies envelopes against
    /// `transport_mut`, then calls this once it holds the resulting
    /// `VerifiedPeer`.
    ///
    /// The token is consumed rather than stored: peer identity that
    /// the application layer needs (handle, pubkey, counter) is
    /// retained by the caller from its own `VerifiedPeer`. Keeping it
    /// out of the wrapper leaves the `Connection` struct shape uniform
    /// across all states.
    pub fn into_authenticated(self, _verified: VerifiedPeer) -> Connection<Authenticated, T> {
        Connection {
            transport: self.transport,
            _state: PhantomData,
        }
    }
}

// ── Authenticated state ──────────────────────────────────────────
//
// Only `Authenticated` exposes application I/O: it impls `AsyncRead`
// and `AsyncWrite` by delegating to the inner transport, so a value of
// this state IS an application byte stream (ISC-S19 step 5 / ISC-C23).
// `Negotiating` and `Versioned` deliberately do NOT impl these traits
// — pre-auth application traffic is therefore a compile error, not a
// runtime check (ISC-C23). The transport is `Unpin` (a `Transport`
// supertrait bound), so the projections below are infallible.

impl<T: Transport> Connection<Authenticated, T> {
    /// Consume the connection, returning the raw authenticated
    /// transport — e.g. to hand to `tonic::transport::Server` for the
    /// post-auth application stream.
    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T: Transport> AsyncRead for Connection<Authenticated, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().transport).poll_read(cx, buf)
    }
}

impl<T: Transport> AsyncWrite for Connection<Authenticated, T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().transport).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().transport).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().transport).poll_shutdown(cx)
    }
}

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

    /// Build a `VerifiedPeer` through the real verification path so the
    /// type-state transition test exercises the genuine token, not a
    /// test-only constructor.
    fn a_verified_peer() -> crate::identity_proof::VerifiedPeer {
        use crate::handle::{DisplayMode, Handle};
        use crate::identity::keys::{Identity, derive_identity_keys};
        use crate::identity::mnemonic::Mnemonic;
        use crate::identity_proof::{build_envelope, verify_envelope};
        use daemonseed_proto::v1 as wire;

        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let keys = derive_identity_keys(&Mnemonic::from_phrase(phrase).unwrap(), Identity::Primary)
            .unwrap();
        let cb = [9u8; 32];
        let ver = wire::ProtocolVersion { major: 1, minor: 0 };
        let handle = Handle::from_pubkey(Some("alice".to_string()), keys.signing.public_key())
            .unwrap()
            .format(DisplayMode::Verify);
        let env = build_envelope(
            &keys.signing,
            &cb,
            &handle,
            wire::Role::Client,
            1,
            ver,
            0,
            1,
        )
        .unwrap();
        verify_envelope(&env, &cb, ver, 0, None).unwrap()
    }

    /// ISC-29 / ISC-30: the consuming transition into `Authenticated`
    /// requires a `VerifiedPeer` token — which only `verify_envelope`
    /// can mint — so the type system forbids reaching `Authenticated`
    /// without a successful verification.
    #[test]
    fn versioned_into_authenticated_consumes_verified_peer() {
        let (a, _b) = pair();
        let ver: Connection<Versioned, _> =
            Connection::from_handshaked_transport(a).advance_to_versioned();
        let _auth: Connection<Authenticated, _> = ver.into_authenticated(a_verified_peer());
    }

    /// ISC-31: `Connection<Authenticated, _>` IS an application byte
    /// stream — it impls `AsyncRead + AsyncWrite`. The companion
    /// negative (Versioned does NOT impl them, ISC-32) is enforced by
    /// the deliberate absence of those impls; per the M4a D4 decision we
    /// verify it by inspection rather than a `trybuild` compile-fail.
    #[test]
    fn authenticated_is_an_async_stream() {
        fn assert_async_io<T: AsyncRead + AsyncWrite>(_t: &T) {}
        let (a, _b) = pair();
        let auth: Connection<Authenticated, _> = Connection::from_handshaked_transport(a)
            .advance_to_versioned()
            .into_authenticated(a_verified_peer());
        assert_async_io(&auth);
    }
}
