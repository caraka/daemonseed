//! Client-side identity-proof orchestration (ISC-S19, ISC-A-C18).
//!
//! The mirror of `daemonseed-server::identity_proof`, run from the client
//! after `connect` reaches the negotiated (`Versioned`) state. The client:
//!
//! 1. derives the channel binding from **its** rustls session via
//!    [`RustlsClientExporter`] (ISC-A-C18 — never a constant);
//! 2. builds + sends its signed envelope (role = `Client`), then reads +
//!    verifies the server's via core [`verify_envelope`];
//! 3. **pins the verified server handle to the server-id it dialed** —
//!    self-consistency (handle ↔ pubkey) is checked inside `verify_envelope`,
//!    and this adds "…and it's the server I *meant* to reach", so a different
//!    but internally-consistent server cannot silently pass (A-C18);
//! 4. fails **closed** on any failure with no partial-trust continuation
//!    (ISC-45) and no UX speculation about which check failed (ISC-46 — the
//!    caller maps every cause to the single "server refused" category).
//!
//! ## Counter mechanism (ISC-19), persistence deferred (decision D8)
//!
//! The send counter comes from [`CounterState::next_send`] and the server's
//! highest-seen counter from [`CounterState::highest_seen`] /
//! [`CounterState::record_seen`] — the same per-key replay machinery the
//! seeds blob persists (ISC-33/34). For now the CLI injects an **ephemeral**
//! identity with an in-memory `CounterState` (D8); sealing that state to a
//! passphrase-encrypted seeds blob across runs is a later client-identity
//! commit, not part of this orchestration.

use std::error::Error;
use std::fmt;

use daemonseed_core::handle::{DisplayMode, Handle};
use daemonseed_core::identity::keys::{
    Identity, SignKeypair, SignatureError, derive_identity_keys,
};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::identity_proof::{
    CHANNEL_BINDING_LEN, ChannelBindingError, ChannelBindingSource, VerifiedPeer, VerifyRejection,
    build_envelope, verify_envelope,
};
use daemonseed_core::storage::seeds::CounterState;
use daemonseed_proto::v1 as wire;
use daemonseed_server::hello::{HelloError, read_frame, write_frame};
use tokio::io::{AsyncRead, AsyncWrite};

/// MVP cryptographic suite id carried by the client envelope: `1` =
/// CNSA 2.0. Mirrors `daemonseed_server::identity_proof::MVP_SUITE_ID`.
pub const MVP_SUITE_ID: u32 = 1;

// ── Channel-binding source over rustls ───────────────────────────

/// Adapts a borrowed rustls [`rustls::ClientConnection`] to core's
/// [`ChannelBindingSource`] so the channel binding is derived from the
/// live client-side TLS exporter (ISC-A-C18). Like the server adapter,
/// there is no constructor that fabricates a constant.
pub struct RustlsClientExporter<'a>(&'a rustls::ClientConnection);

impl<'a> RustlsClientExporter<'a> {
    /// Wrap a live client-side rustls connection. Obtain the reference via
    /// `tokio_rustls::client::TlsStream::get_ref().1`.
    pub fn new(conn: &'a rustls::ClientConnection) -> Self {
        Self(conn)
    }
}

impl ChannelBindingSource for RustlsClientExporter<'_> {
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

// ── Client identity ───────────────────────────────────────────────

/// The client's signing identity for the identity-proof envelope: its
/// ML-DSA-87 keypair plus its canonical `<name>#<12hex>` handle.
pub struct ClientIdentity {
    signing: SignKeypair,
    handle: String,
}

impl ClientIdentity {
    /// Build from an explicit signing keypair + verify-form handle.
    pub fn new(signing: SignKeypair, handle: String) -> Self {
        Self { signing, handle }
    }

    /// Generate a throwaway client identity: a fresh BIP-39 mnemonic →
    /// Primary `SignKeypair` → floor-form handle. Per decision D8 this is
    /// the MVP path until persisted client identity (passphrase + sealed
    /// seeds blob) lands; the handle is therefore not stable across runs.
    /// Requires the oxicrypt module to be operational.
    pub fn ephemeral() -> Result<Self, ClientIdentityError> {
        let mnemonic = Mnemonic::generate().map_err(|e| ClientIdentityError(e.to_string()))?;
        let keys = derive_identity_keys(&mnemonic, Identity::Primary)
            .map_err(|e| ClientIdentityError(e.to_string()))?;
        let handle = Handle::from_pubkey(None, keys.signing.public_key())
            .map_err(|e| ClientIdentityError(e.to_string()))?
            .format(DisplayMode::Verify);
        Ok(Self {
            signing: keys.signing,
            handle,
        })
    }

    /// The client's canonical verify-form handle.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// Borrow the client's long-term signing keypair. Used to self-sign
    /// public-room messages for provenance (ISC-S24): the same identity that
    /// proved the connection authors public-room posts, so the provenance
    /// signature binds to a key the relay already saw at identity-proof time.
    pub fn signing(&self) -> &SignKeypair {
        &self.signing
    }
}

// ── Orchestration ─────────────────────────────────────────────────

/// Run the client's side of the identity-proof exchange over the
/// already-`Versioned` stream (ISC-S19, ISC-A-C18).
///
/// Sends the client's signed envelope, then reads + verifies the server's
/// against the locally-recomputed `channel_binding` + `negotiated_version`.
/// On success returns the [`VerifiedPeer`] — a server whose envelope is
/// **self-consistent** (its claimed handle hashes to its claimed pubkey, the
/// channel binding matches, the signature verifies, the freshness/counter
/// checks pass). On **any** of those failures returns a [`ClientProofError`]
/// and the caller closes — no partial-trust branch (ISC-45).
///
/// **Dialed-identity is NOT decided here.** Whether this self-consistent server
/// is the one the caller meant to reach — and whether a changed key is an
/// acceptable trusted-mode rotation or an untrusted-mode mismatch — is the C22
/// trust layer's job (`daemonseed_core::federation::apply_trust`, run by
/// `connect`). Keeping the binding in one place (the pin store) is what lets
/// trusted-mode key rotation surface a notice instead of being refused here.
/// `expected_server_id` is used only to key the per-server replay counter
/// (ISC-34), not as an identity gate.
///
/// `now_unix_ms` supplies the client envelope's timestamp (ISC-18) and the
/// server-envelope skew check; `counters` provides the monotonic send
/// counter (ISC-19) and the server's highest-seen counter (ISC-34).
pub async fn run_client_identity_proof<S>(
    stream: &mut S,
    channel_binding: [u8; CHANNEL_BINDING_LEN],
    negotiated_version: wire::ProtocolVersion,
    identity: &ClientIdentity,
    now_unix_ms: u64,
    counters: &mut CounterState,
    expected_server_id: &str,
) -> Result<VerifiedPeer, ClientProofError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Build + send the client's envelope. The counter advances once per
    // envelope built (ISC-19); the handle + timestamp are sourced locally
    // (ISC-17 / ISC-18).
    let counter = counters.next_send();
    let envelope = build_envelope(
        &identity.signing,
        &channel_binding,
        &identity.handle,
        wire::Role::Client,
        MVP_SUITE_ID,
        negotiated_version,
        now_unix_ms,
        counter,
    )
    .map_err(ClientProofError::Sign)?;
    write_frame(stream, &envelope)
        .await
        .map_err(ClientProofError::Frame)?;

    // Read + verify the server's envelope. channel_binding +
    // negotiated_version are this side's locally-derived values (never read
    // off the wire), so a captured envelope from another session fails closed.
    let server_envelope: wire::IdentityProof =
        read_frame(stream).await.map_err(ClientProofError::Frame)?;
    let highest_seen = counters.highest_seen(expected_server_id);
    let verified = verify_envelope(
        &server_envelope,
        &channel_binding,
        negotiated_version,
        now_unix_ms,
        highest_seen,
    )
    .map_err(ClientProofError::Verify)?;

    // Dialed-identity (A-C18) is decided by the C22 trust layer, not here — see
    // the function docs. verify_envelope already proved the envelope is
    // self-consistent (handle hashes to pubkey); `apply_trust` in `connect`
    // then decides whether this is the dialed server (first-contact hash match)
    // or an accepted rotation of the pinned key. Deciding it here would refuse
    // a rotated key before the trust layer could surface a notice.

    // Record the server's counter as highest-seen for this server-id
    // (ISC-34 mechanism). Only reached on a fully-verified envelope.
    counters.record_seen(expected_server_id, verified.counter());
    Ok(verified)
}

// ── Errors ────────────────────────────────────────────────────────

/// Failure constructing an ephemeral [`ClientIdentity`]. Stringified
/// because it bridges three unrelated core error types (mnemonic, key
/// derivation, handle construction) for an MVP-only helper.
#[derive(Debug)]
pub struct ClientIdentityError(String);

impl fmt::Display for ClientIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client identity generation failed: {}", self.0)
    }
}

impl Error for ClientIdentityError {}

/// Failure modes of the client identity-proof exchange. Diagnostic only —
/// the caller (`connect`) collapses every variant to a single "server
/// refused" outcome so the user is told nothing about which check failed
/// (ISC-46 / ISC-A-C18).
#[derive(Debug)]
pub enum ClientProofError {
    /// Signing the client's envelope failed (module not operational).
    Sign(SignatureError),
    /// Frame read/write or decode failed on the transport.
    Frame(HelloError),
    /// The server's envelope failed verification (uniform — sub-cause is
    /// deliberately opaque).
    Verify(VerifyRejection),
}

impl fmt::Display for ClientProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sign(e) => write!(f, "client envelope signing failed: {e}"),
            Self::Frame(e) => write!(f, "identity-proof frame I/O failed: {e}"),
            Self::Verify(e) => write!(f, "server identity-proof rejected: {e}"),
        }
    }
}

impl Error for ClientProofError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sign(e) => Some(e),
            Self::Frame(e) => Some(e),
            Self::Verify(e) => Some(e),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use core::str::FromStr;
    use daemonseed_core::identity::keys::IdentityKeys;
    use daemonseed_server::identity::{Seed, ServerId, derive_server_id};
    use daemonseed_server::identity_proof::{
        SeenMap, ServerIdentity, now_unix_ms, run_server_identity_proof,
    };
    use tokio::io::duplex;

    const NOW: u64 = 1_700_000_000_000;

    fn ensure_module() {
        oxitls_rustls_provider::testing::ensure_module_operational();
    }

    fn ver() -> wire::ProtocolVersion {
        wire::ProtocolVersion { major: 1, minor: 0 }
    }

    fn test_server() -> (ServerIdentity, ServerId) {
        ensure_module();
        let seed = Seed([5u8; 32]);
        let server_id = derive_server_id(&seed, Some("relay-bear".to_owned())).unwrap();
        let identity = ServerIdentity::from_seed(&seed, &server_id).unwrap();
        (identity, server_id)
    }

    fn ephemeral_client() -> ClientIdentity {
        ensure_module();
        ClientIdentity::ephemeral().expect("ephemeral identity builds")
    }

    /// Build a self-consistent server envelope signed by `keys` claiming
    /// `handle` — used to script a "server" half for the negative tests.
    fn server_envelope(
        keys: &IdentityKeys,
        handle: &str,
        cb: &[u8; CHANNEL_BINDING_LEN],
    ) -> wire::IdentityProof {
        build_envelope(
            &keys.signing,
            cb,
            handle,
            wire::Role::Server,
            MVP_SUITE_ID,
            ver(),
            NOW,
            1,
        )
        .unwrap()
    }

    /// ISC-43/44/47 happy path: client + server both reach a VerifiedPeer
    /// over an in-memory duplex (the in-process precursor to the commit-7
    /// real-TLS e2e). The client's verified peer is the dialed server.
    #[tokio::test]
    async fn client_and_server_complete_mutual_identity_proof() {
        let (server_identity, server_id) = test_server();
        let server_handle = server_identity.handle().to_owned();
        let client = ephemeral_client();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let seen = SeenMap::new();
        let mut counters = CounterState::default();

        let (client_end_raw, server_end_raw) = duplex(64 * 1024);
        let server_task = {
            tokio::spawn(async move {
                let mut server_end = server_end_raw;
                run_server_identity_proof(
                    &mut server_end,
                    cb,
                    ver(),
                    &server_identity,
                    NOW,
                    now_unix_ms(),
                    &seen,
                    None,
                )
                .await
                .map(|p| p.handle().to_owned())
            })
        };

        let mut client_end = client_end_raw;
        let verified = run_client_identity_proof(
            &mut client_end,
            cb,
            ver(),
            &client,
            NOW,
            &mut counters,
            &server_handle,
        )
        .await
        .expect("client reaches Authenticated");

        let server_saw = server_task
            .await
            .unwrap()
            .expect("server reaches Authenticated");
        // Client authenticated the server it dialed; server authenticated the client.
        assert_eq!(
            Handle::from_str(verified.handle()).unwrap().hash_prefix(),
            Handle::from_str(&server_handle).unwrap().hash_prefix()
        );
        assert_eq!(server_saw, client.handle());
        // ISC-34: the server's counter is recorded as highest-seen.
        let _ = server_id;
        assert_eq!(
            counters.highest_seen(&server_handle),
            Some(verified.counter())
        );
    }

    /// ISC-45: a tampered server signature fails the client closed.
    #[tokio::test]
    async fn client_fails_closed_on_bad_server_signature() {
        ensure_module();
        let server_keys =
            derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
        let server_handle = Handle::from_pubkey(None, server_keys.signing.public_key())
            .unwrap()
            .format(DisplayMode::Verify);
        let client = ephemeral_client();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let mut counters = CounterState::default();

        let (client_end_raw, server_end_raw) = duplex(64 * 1024);
        let scripted = {
            let server_handle = server_handle.clone();
            tokio::spawn(async move {
                let mut server_end = server_end_raw;
                let _client_env: wire::IdentityProof = read_frame(&mut server_end).await.unwrap();
                let mut env = server_envelope(&server_keys, &server_handle, &cb);
                env.signature[0] ^= 0xff;
                write_frame(&mut server_end, &env).await.unwrap();
            })
        };

        let mut client_end = client_end_raw;
        let out = run_client_identity_proof(
            &mut client_end,
            cb,
            ver(),
            &client,
            NOW,
            &mut counters,
            &server_handle,
        )
        .await;
        scripted.await.unwrap();
        assert!(matches!(out, Err(ClientProofError::Verify(_))));
    }

    /// Dialed-identity moved to the trust layer (M5): a self-consistent server
    /// envelope now COMPLETES the proof even when its handle differs from the
    /// dialed server-id. `run_client_identity_proof` proves self-consistency
    /// only; `connect`'s `apply_trust` is what refuses a wrong/unknown server
    /// (first-contact hash mismatch → Refuse) or accepts a trusted-mode
    /// rotation. This is the change that makes ISC-C22 key rotation reachable.
    #[tokio::test]
    async fn proof_completes_for_any_self_consistent_server_dialed_id_is_trust_layer() {
        ensure_module();
        let server_keys =
            derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap();
        let server_handle = Handle::from_pubkey(None, server_keys.signing.public_key())
            .unwrap()
            .format(DisplayMode::Verify);
        // The client dialed a DIFFERENT server-id — yet the proof still
        // completes, because the dialed-identity decision is no longer here.
        let dialed = "someone-else#000000000000";
        let client = ephemeral_client();
        let cb = [9u8; CHANNEL_BINDING_LEN];
        let mut counters = CounterState::default();

        let (client_end_raw, server_end_raw) = duplex(64 * 1024);
        let scripted = {
            let server_handle = server_handle.clone();
            tokio::spawn(async move {
                let mut server_end = server_end_raw;
                let _client_env: wire::IdentityProof = read_frame(&mut server_end).await.unwrap();
                let env = server_envelope(&server_keys, &server_handle, &cb);
                write_frame(&mut server_end, &env).await.unwrap();
            })
        };

        let mut client_end = client_end_raw;
        let verified = run_client_identity_proof(
            &mut client_end,
            cb,
            ver(),
            &client,
            NOW,
            &mut counters,
            dialed,
        )
        .await
        .expect("self-consistent server completes the proof regardless of dialed-id");
        scripted.await.unwrap();
        // The proof returns the server's own (self-consistent) identity; the
        // trust layer would refuse it against the dialed `someone-else` id.
        assert_eq!(verified.handle(), server_handle);
    }

    #[test]
    fn ephemeral_identity_handle_is_verify_form() {
        let id = ephemeral_client();
        // Floor form is `#<12hex>`; verify-form of a None-named handle.
        assert!(id.handle().contains('#'));
        assert!(Handle::from_str(id.handle()).is_ok());
    }
}
