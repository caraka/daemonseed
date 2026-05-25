//! Server-side identity-proof orchestration (ISC-S19, ISC-A-S14, ISC-A-S12,
//! ISC-A-S1).
//!
//! After the `APP_HELLO` exchange advances a connection to `Versioned`
//! (M4a), the server runs the post-HELLO identity-proof exchange that gates
//! the `Versioned → Authenticated` transition. This module owns the
//! server's half of that exchange:
//!
//! 1. **Channel binding** — [`RustlsServerExporter`] adapts the live rustls
//!    `ServerConnection` to core's [`ChannelBindingSource`], so the 32-byte
//!    binding is derived from *this* TLS session's exporter (RFC 8446 §7.5)
//!    and never a constant (ISC-37 / ISC-A-S14 / ISC-A1). The label and
//!    context byte-layout live in `daemonseed-core`; this crate only
//!    supplies the exporter call.
//! 2. **Envelope exchange** — [`run_server_identity_proof`] builds + sends
//!    the server's signed envelope and reads the client's, both as
//!    length-prefixed frames over the same raw TLS stream (reusing
//!    [`crate::hello::write_frame`] / [`crate::hello::read_frame`]).
//! 3. **Verification** — the client envelope runs through core's
//!    [`verify_envelope`]; success mints a [`VerifiedPeer`] (the token that
//!    unlocks `Connection::into_authenticated`); any failure closes the
//!    connection uniformly (ISC-40 / ISC-A-S12 — no per-check reason frame,
//!    the peer sees only a closed socket).
//!
//! ## No persistence of connecting clients (ISC-A-S1 / ISC-42 / ISC-A5)
//!
//! The server keeps a process-lifetime, **RAM-only** [`SeenMap`] of the
//! highest identity-proof counter seen per client signing key — the
//! replay-defense companion to the TLS channel binding (ISC-34). It writes
//! no client identity record, IP, or handle to any disk or log surface. The
//! map holds a single `u64` per key (a counter, not an envelope — ISC-41)
//! and resets on restart.
//!
//! ## Server outbound counter (decision D7)
//!
//! The server has no persistent per-key counter store (its identity is a
//! raw seed, not a recoverable seeds blob), so [`now_unix_ms`] is its
//! monotonic counter source: monotonic across restarts for free given the
//! NTP requirement the ±5min skew gate already imposes, so a restarted
//! server is never rejected as a replay by returning clients. The
//! orchestration itself is counter-agnostic — the caller passes the value.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use daemonseed_core::handle::DisplayMode;
use daemonseed_core::identity::keys::{KeyDerivationError, SignKeypair};
use daemonseed_core::identity_proof::{
    ChannelBindingError, ChannelBindingSource, VerifiedPeer, VerifyRejection, build_envelope,
    verify_envelope,
};
use daemonseed_proto::v1 as wire;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::hello::{HelloError, read_frame, write_frame};
use crate::identity::{Seed, ServerId};

/// MVP cryptographic suite id carried by the server's identity-proof
/// envelope: `1` = CNSA 2.0 (ML-DSA-87 + ML-KEM-1024 + AES-256-GCM +
/// SHA-384). Mirrors the proto/registry default; widened to a real suite
/// negotiation post-MVP (ISC-S15 / S16).
pub const MVP_SUITE_ID: u32 = 1;

/// Current OS wall-clock time in milliseconds since the Unix epoch.
///
/// Sourced once per envelope for both the freshness timestamp
/// (`signed_at_unix_ms`, ISC-18) and — per decision D7 — the server's
/// monotonic outbound counter. Clamped at the epoch on the (unreachable on
/// a sane host) pre-1970 clock.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Channel-binding source over rustls ───────────────────────────

/// Adapts a borrowed rustls [`rustls::ServerConnection`] to core's
/// [`ChannelBindingSource`] so the identity-proof channel binding is
/// derived from the live TLS exporter (ISC-37 / ISC-A-S14).
///
/// There is deliberately **no** constructor that fabricates a constant:
/// the only way to build one is from a real connection, which is the
/// structural form of ISC-A1 ("server substitutes a constant for the TLS
/// exporter output — forbidden").
pub struct RustlsServerExporter<'a>(&'a rustls::ServerConnection);

impl<'a> RustlsServerExporter<'a> {
    /// Wrap a live server-side rustls connection. Obtain the reference via
    /// `tokio_rustls::server::TlsStream::get_ref().1`.
    pub fn new(conn: &'a rustls::ServerConnection) -> Self {
        Self(conn)
    }
}

impl ChannelBindingSource for RustlsServerExporter<'_> {
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), ChannelBindingError> {
        self.0
            .export_keying_material(out, label, Some(context))
            .map(|_filled| ())
            .map_err(|e| ChannelBindingError::Export(e.to_string()))
    }
}

// ── Server long-term identity ─────────────────────────────────────

/// The server's long-term signing identity for the identity-proof
/// envelope: its ML-DSA-87 keypair plus the canonical `<name>#<12hex>`
/// handle (ISC-S11) clients verify the key against.
pub struct ServerIdentity {
    signing: SignKeypair,
    handle: String,
    suite_id: u32,
}

impl ServerIdentity {
    /// Build from the server's persisted raw seed and derived server-id.
    /// The signing keypair is re-derived from the seed via
    /// [`SignKeypair::from_ml_dsa_seed`]; the handle is the server-id in
    /// canonical verify form. Suite defaults to [`MVP_SUITE_ID`].
    pub fn from_seed(seed: &Seed, server_id: &ServerId) -> Result<Self, IdentityProofError> {
        let signing =
            SignKeypair::from_ml_dsa_seed(seed.as_bytes()).map_err(IdentityProofError::Key)?;
        let handle = server_id.format(DisplayMode::Verify).to_string();
        Ok(Self {
            signing,
            handle,
            suite_id: MVP_SUITE_ID,
        })
    }

    /// The server's canonical verify-form handle (`<name>#<12hex>`).
    pub fn handle(&self) -> &str {
        &self.handle
    }
}

// ── RAM-only replay-counter map (ISC-34 / ISC-A-S1) ───────────────

/// Process-lifetime, RAM-only map of the highest identity-proof counter
/// accepted from each client signing key. Cheaply cloneable (shares one
/// `Arc<Mutex<…>>`) so every per-connection task observes the same
/// highest-seen state within a single server uptime.
///
/// Holds only a `u64` per key — never an envelope (ISC-41) — and is never
/// serialized to disk or a log (ISC-A-S1 / ISC-42 / ISC-A5). Resets on
/// restart, at which point the channel binding remains the cross-session
/// replay defense and the wall-clock counter (D7) keeps returning clients
/// from being rejected.
#[derive(Clone, Default)]
pub struct SeenMap {
    inner: Arc<Mutex<HashMap<Vec<u8>, u64>>>,
}

impl SeenMap {
    /// A fresh, empty map.
    pub fn new() -> Self {
        Self::default()
    }

    fn highest_seen(&self, pubkey: &[u8]) -> Option<u64> {
        self.inner
            .lock()
            .expect("SeenMap mutex poisoned")
            .get(pubkey)
            .copied()
    }

    fn record(&self, pubkey: &[u8], counter: u64) {
        let mut map = self.inner.lock().expect("SeenMap mutex poisoned");
        let slot = map.entry(pubkey.to_vec()).or_insert(0);
        if counter > *slot {
            *slot = counter;
        }
    }
}

// ── Orchestration ─────────────────────────────────────────────────

/// Run the server's side of the identity-proof exchange over an
/// already-`Versioned` stream (ISC-S19, ISC-38/39/40).
///
/// Builds and sends the server's signed envelope, reads the client's, and
/// verifies it against the locally-recomputed `channel_binding` +
/// `negotiated_version`. On success returns the [`VerifiedPeer`] token that
/// gates `Connection::into_authenticated`; on **any** failure returns an
/// [`IdentityProofError`] whose only observable effect is the caller closing
/// the connection — there is no per-check reason on the wire (ISC-40 /
/// ISC-A-S12). The verify path does not branch on `role` (ISC-A-S8); the
/// server-role bookkeeping lives entirely in the envelope it *builds*.
///
/// `now_unix_ms` supplies both the server envelope's freshness timestamp
/// (ISC-18) and the client-envelope skew check; `send_counter` is the
/// server's monotonic counter (decision D7 — wall-clock ms). `seen` is the
/// RAM-only replay map (ISC-34).
pub async fn run_server_identity_proof<S>(
    stream: &mut S,
    channel_binding: [u8; daemonseed_core::identity_proof::CHANNEL_BINDING_LEN],
    negotiated_version: wire::ProtocolVersion,
    identity: &ServerIdentity,
    now_unix_ms: u64,
    send_counter: u64,
    seen: &SeenMap,
) -> Result<VerifiedPeer, IdentityProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 2/3 — build + send the server's envelope first. Sending before
    // verifying the client is safe: the server's identity is a public relay
    // identity, and a uniform close after the send leaks nothing about which
    // client check (if any) failed.
    let envelope = build_envelope(
        &identity.signing,
        &channel_binding,
        &identity.handle,
        wire::Role::Server,
        identity.suite_id,
        negotiated_version,
        now_unix_ms,
        send_counter,
    )
    .map_err(IdentityProofError::Sign)?;
    write_frame(stream, &envelope)
        .await
        .map_err(IdentityProofError::Frame)?;

    // Step 3/4 — read the client's envelope and verify it. channel_binding +
    // negotiated_version are this side's locally-derived values, never read
    // from the wire, which is what makes a cross-session replay fail closed.
    let client_envelope: wire::IdentityProof = read_frame(stream)
        .await
        .map_err(IdentityProofError::Frame)?;

    let highest_seen = seen.highest_seen(&client_envelope.claimed_pubkey);
    let verified = verify_envelope(
        &client_envelope,
        &channel_binding,
        negotiated_version,
        now_unix_ms,
        highest_seen,
    )
    .map_err(IdentityProofError::Verify)?;

    // Step 5 — record the accepted counter as the new highest-seen for this
    // signing key (RAM-only; ISC-34). Only reached on a passed verification.
    seen.record(verified.pubkey(), verified.counter());

    Ok(verified)
}

// ── Errors ────────────────────────────────────────────────────────

/// Failure modes of the server identity-proof exchange.
///
/// The variants exist for the server's own diagnostics; they are **not** a
/// wire surface. The caller's response to every variant is identical — close
/// the connection — so the connecting peer cannot distinguish a bad signature
/// from a stale timestamp from a counter replay (ISC-40 / ISC-A-S12 /
/// ISC-A-C18 uniform close-shape).
#[derive(Debug)]
pub enum IdentityProofError {
    /// Deriving the server's signing keypair from its seed failed (module
    /// not operational).
    Key(KeyDerivationError),
    /// Signing the server's envelope failed (module not operational).
    Sign(daemonseed_core::identity::keys::SignatureError),
    /// Frame read/write or decode failed on the transport.
    Frame(HelloError),
    /// The channel binding could not be derived from the TLS exporter.
    ChannelBinding(ChannelBindingError),
    /// The client's envelope failed verification (uniform — sub-cause is
    /// deliberately opaque).
    Verify(VerifyRejection),
}

impl fmt::Display for IdentityProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(e) => write!(f, "server signing-key derivation failed: {e}"),
            Self::Sign(e) => write!(f, "server envelope signing failed: {e}"),
            Self::Frame(e) => write!(f, "identity-proof frame I/O failed: {e}"),
            Self::ChannelBinding(e) => write!(f, "channel-binding derivation failed: {e}"),
            Self::Verify(e) => write!(f, "client identity-proof rejected: {e}"),
        }
    }
}

impl Error for IdentityProofError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Key(e) => Some(e),
            Self::Sign(e) => Some(e),
            Self::Frame(e) => Some(e),
            Self::ChannelBinding(e) => Some(e),
            Self::Verify(e) => Some(e),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use daemonseed_core::handle::Handle;
    use daemonseed_core::identity::keys::{Identity, IdentityKeys, derive_identity_keys};
    use daemonseed_core::identity::mnemonic::Mnemonic;
    use daemonseed_core::identity_proof::CHANNEL_BINDING_LEN;
    use tokio::io::duplex;

    const ALL_ZEROS_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const NOW: u64 = 1_700_000_000_000;

    fn ensure_module() {
        oxitls_rustls_provider::testing::ensure_module_operational();
    }

    fn ver() -> wire::ProtocolVersion {
        wire::ProtocolVersion { major: 1, minor: 0 }
    }

    /// A server identity derived from a fixed seed, with a real verify-form
    /// server-id handle.
    fn test_server_identity() -> ServerIdentity {
        ensure_module();
        let seed = Seed([5u8; 32]);
        let server_id = crate::identity::derive_server_id(&seed, Some("relay-bear".to_owned()))
            .expect("module operational");
        ServerIdentity::from_seed(&seed, &server_id).expect("server identity builds")
    }

    fn client_keys() -> IdentityKeys {
        ensure_module();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        derive_identity_keys(&m, Identity::Primary).unwrap()
    }

    /// The client's canonical verify-form handle for `keys`.
    fn client_handle(keys: &IdentityKeys) -> String {
        Handle::from_pubkey(Some("alice".to_owned()), keys.signing.public_key())
            .unwrap()
            .format(DisplayMode::Verify)
            .to_string()
    }

    /// Build a client envelope as a well-behaved peer would, for the shared
    /// `cb` / `version`.
    fn good_client_envelope(
        keys: &IdentityKeys,
        cb: &[u8; CHANNEL_BINDING_LEN],
        counter: u64,
        ts: u64,
    ) -> wire::IdentityProof {
        build_envelope(
            &keys.signing,
            cb,
            &client_handle(keys),
            wire::Role::Client,
            MVP_SUITE_ID,
            ver(),
            ts,
            counter,
        )
        .unwrap()
    }

    /// ISC-38 / ISC-39 happy path: the server sends a verifiable envelope
    /// and accepts the client's, returning a `VerifiedPeer` bound to the
    /// client's key + handle.
    #[tokio::test]
    async fn server_completes_identity_proof_with_valid_client() {
        let identity = test_server_identity();
        let keys = client_keys();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let seen = SeenMap::new();

        let (mut client_end, mut server_end) = duplex(64 * 1024);
        let client_pubkey = keys.signing.public_key().to_vec();
        let client_h = client_handle(&keys);

        let client = tokio::spawn(async move {
            // The client reads the server's envelope (ISC-38 round-trip:
            // it must verify under the same channel binding) then sends its
            // own.
            let server_env: wire::IdentityProof = read_frame(&mut client_end).await.unwrap();
            verify_envelope(&server_env, &cb, ver(), NOW, None)
                .expect("server envelope must verify client-side (ISC-38)");
            let env = good_client_envelope(&keys, &cb, 1, NOW);
            write_frame(&mut client_end, &env).await.unwrap();
        });

        let verified = run_server_identity_proof(
            &mut server_end,
            cb,
            ver(),
            &identity,
            NOW,
            now_unix_ms(),
            &seen,
        )
        .await
        .expect("valid client must be accepted");

        client.await.unwrap();
        assert_eq!(verified.pubkey(), client_pubkey.as_slice());
        assert_eq!(verified.handle(), client_h);
        // Counter recorded as highest-seen (ISC-34).
        assert_eq!(seen.highest_seen(&client_pubkey), Some(1));
    }

    /// ISC-40 / ISC-A-S12: a tampered-signature client envelope is rejected,
    /// and the failure is the same opaque close as a stale-timestamp
    /// rejection — the orchestration returns `Err` for both, having written
    /// only its own envelope (no reason frame distinguishes the cause).
    #[tokio::test]
    async fn server_rejects_uniformly_across_failure_causes() {
        async fn run_with(
            mutate: impl FnOnce(&mut wire::IdentityProof) + Send + 'static,
        ) -> Result<VerifiedPeer, IdentityProofError> {
            let identity = test_server_identity();
            let keys = client_keys();
            let cb = [9u8; CHANNEL_BINDING_LEN];
            let seen = SeenMap::new();
            let (mut client_end, mut server_end) = duplex(64 * 1024);

            let client = tokio::spawn(async move {
                let _server_env: wire::IdentityProof = read_frame(&mut client_end).await.unwrap();
                let mut env = good_client_envelope(&keys, &cb, 1, NOW);
                mutate(&mut env);
                write_frame(&mut client_end, &env).await.unwrap();
            });

            let out = run_server_identity_proof(
                &mut server_end,
                cb,
                ver(),
                &identity,
                NOW,
                now_unix_ms(),
                &seen,
            )
            .await;
            client.await.unwrap();
            out
        }

        // Cause 1: tampered signature.
        let bad_sig = run_with(|env| env.signature[0] ^= 0xff).await;
        // Cause 2: timestamp far outside the ±5min skew window.
        let bad_skew = run_with(|env| env.signed_at_unix_ms = NOW - 60 * 60 * 1000).await;

        assert!(matches!(bad_sig, Err(IdentityProofError::Verify(_))));
        assert!(matches!(bad_skew, Err(IdentityProofError::Verify(_))));
    }

    /// ISC-34 replay defense: a second connection from the same key reusing
    /// the same counter is rejected against the shared RAM seen-map.
    #[tokio::test]
    async fn server_rejects_counter_replay_against_seen_map() {
        let identity = test_server_identity();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let seen = SeenMap::new();

        // First connection: counter 5 accepted.
        {
            let keys = client_keys();
            let (mut client_end, mut server_end) = duplex(64 * 1024);
            let client = tokio::spawn(async move {
                let _e: wire::IdentityProof = read_frame(&mut client_end).await.unwrap();
                let env = good_client_envelope(&keys, &cb, 5, NOW);
                write_frame(&mut client_end, &env).await.unwrap();
            });
            run_server_identity_proof(
                &mut server_end,
                cb,
                ver(),
                &identity,
                NOW,
                now_unix_ms(),
                &seen,
            )
            .await
            .expect("first envelope accepted");
            client.await.unwrap();
        }

        // Second connection from the same key reusing counter 5 → replay.
        let keys = client_keys();
        let (mut client_end, mut server_end) = duplex(64 * 1024);
        let client = tokio::spawn(async move {
            let _e: wire::IdentityProof = read_frame(&mut client_end).await.unwrap();
            let env = good_client_envelope(&keys, &cb, 5, NOW);
            write_frame(&mut client_end, &env).await.unwrap();
        });
        let out = run_server_identity_proof(
            &mut server_end,
            cb,
            ver(),
            &identity,
            NOW,
            now_unix_ms(),
            &seen,
        )
        .await;
        client.await.unwrap();
        assert!(matches!(out, Err(IdentityProofError::Verify(_))));
    }

    /// `now_unix_ms` returns a plausibly-current epoch-ms value (well past
    /// 2020), confirming the D7 counter source is wall-clock-derived.
    #[test]
    fn now_unix_ms_is_current() {
        assert!(now_unix_ms() > 1_577_836_800_000); // 2020-01-01
    }

    /// The server's own envelope is built role=Server with its verify-form
    /// handle and the MVP suite (ISC-17/20 server sourcing).
    #[tokio::test]
    async fn server_envelope_carries_server_role_and_handle() {
        let identity = test_server_identity();
        let server_handle = identity.handle().to_owned();
        let cb = [3u8; CHANNEL_BINDING_LEN];
        let seen = SeenMap::new();
        let (mut client_end, mut server_end) = duplex(64 * 1024);

        let captured = tokio::spawn(async move {
            let server_env: wire::IdentityProof = read_frame(&mut client_end).await.unwrap();
            // Don't bother replying with a valid envelope — close after
            // capturing. The server's read will then fail, but we only care
            // about the envelope it sent.
            drop(client_end);
            server_env
        });

        let _ =
            run_server_identity_proof(&mut server_end, cb, ver(), &identity, NOW, 7, &seen).await;
        let server_env = captured.await.unwrap();
        assert_eq!(server_env.role, wire::Role::Server as i32);
        assert_eq!(server_env.claimed_handle, server_handle);
        assert_eq!(
            server_env.suite_id,
            Some(wire::SuiteId {
                value: MVP_SUITE_ID
            })
        );
        assert_eq!(server_env.counter, 7);
        assert_eq!(server_env.signed_at_unix_ms, NOW);
    }
}
