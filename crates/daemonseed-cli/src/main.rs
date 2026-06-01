//! daemonseed-cli — scriptable client.
//!
//! Subcommands:
//! - `connect <server-id> [--address host:port]` — open a TLS-1.3
//!   connection to a daemonseed-server, exchange APP_HELLO, print the
//!   negotiated wire version, exit 0 on success.
//! - `publish <server-id> <name> [--rating R] [--handle H]` — publish a
//!   public-space share (M12, gate step 5); prints the server-assigned id.
//! - `unpublish <server-id> <share-id>` — unpublish a share (owner-scoped).
//! - `list-shares <server-id>` — list the server's live public shares.
//!
//! The library surface that backs this binary lives in `lib.rs` so the
//! integration tests drive the same `connect`/`session` entry points
//! in-process. The application subcommands reach `Authenticated` via
//! `connect::connect_session` and run RPCs over an `AppSession`.

#![forbid(unsafe_code)]

use core::str::FromStr;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use daemonseed_cli::connect::{ConnectError, connect, connect_session, resolve_address};
use daemonseed_cli::identity_proof::{ClientIdentity, ClientIdentityError};
use daemonseed_cli::session::{AppSession, SessionError};
use daemonseed_core::federation::store::{InMemoryTrustStore, ServerEntry, TrustStore};
use daemonseed_core::handle::Handle;
use daemonseed_core::storage::seeds::CounterState;
use daemonseed_proto::v1::{
    ListPublicSharesRequest, PublicShareListing, PublishShareRequest, UnpublishShareRequest,
};
use daemonseed_server::kats::CNSA_2_0_KATS;
use daemonseed_server::tls::install_provider;
use oxicrypt_module::{AlgorithmProfile, initialize_with_profile};

#[derive(Parser, Debug)]
#[command(
    name = "daemonseed-cli",
    about = "daemonseed scriptable client",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Open a TLS-1.3 connection to `<server-id>`, exchange APP_HELLO,
    /// print the negotiated `MAJOR.MINOR` wire version on success.
    Connect {
        /// Target server-id in the canonical `<name>#<12hex>` form.
        server_id: String,
        /// Override the bootstrap-anchor address resolution. Format:
        /// `<host>:<port>`. Required when the bundled anchor is
        /// empty or doesn't match `<server-id>`.
        #[arg(long, value_name = "HOST:PORT")]
        address: Option<String>,
    },
    /// Publish a public-space share to `<server-id>` (M12, gate step 5). The
    /// server assigns and prints an opaque share id. The share is RAM-only and
    /// vanishes when this process disconnects — so for a real share, keep a
    /// long-lived client; this one-shot CLI is for scripting and testing.
    Publish {
        /// Target server-id (`<name>#<12hex>`).
        server_id: String,
        /// Display name of the shared folder.
        name: String,
        /// Address override (`<host>:<port>`).
        #[arg(long, value_name = "HOST:PORT")]
        address: Option<String>,
        /// Self-asserted content rating from the server's taxonomy (advisory).
        #[arg(long, default_value = "")]
        rating: String,
        /// Self-asserted sharer handle (`<name>#<hash>`); advisory, not bound to
        /// the connection identity.
        #[arg(long, default_value = "")]
        handle: String,
    },
    /// Unpublish a share previously published on this server (M12). Owner-scoped:
    /// only the publishing connection can unpublish, so this succeeds only within
    /// the same long-lived client that published the share.
    Unpublish {
        /// Target server-id (`<name>#<12hex>`).
        server_id: String,
        /// The server-assigned share id returned by `publish`.
        share_id: String,
        /// Address override (`<host>:<port>`).
        #[arg(long, value_name = "HOST:PORT")]
        address: Option<String>,
    },
    /// List the public-space shares currently published on `<server-id>` (M12),
    /// one per line: `share_id<TAB>name<TAB>[rating]<TAB>sharer_handle`.
    ListShares {
        /// Target server-id (`<name>#<12hex>`).
        server_id: String,
        /// Address override (`<host>:<port>`).
        #[arg(long, value_name = "HOST:PORT")]
        address: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("daemonseed-cli: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    // Module-gate init — symmetric with the server. The CLI shares the
    // same process-wide CryptoProvider as the server would; doing the
    // KATS init here means a future operator running both binaries on
    // the same host doesn't get two competing inits (each call
    // short-circuits if the module is already Operational).
    initialize_with_profile(CNSA_2_0_KATS, AlgorithmProfile::Cnsa2)
        .map_err(CliError::ModuleInit)?;
    install_provider().map_err(CliError::ProviderInstall)?;

    let rt = tokio::runtime::Runtime::new().map_err(CliError::Runtime)?;
    match cli.cmd {
        Cmd::Connect { server_id, address } => {
            let dial =
                resolve_address(&server_id, address.as_deref()).map_err(CliError::Connect)?;
            // D8: ephemeral client identity + in-memory counter for the MVP
            // CLI. The module gate is already Operational (initialized above),
            // which `ephemeral()` requires for keygen.
            let identity = ClientIdentity::ephemeral().map_err(CliError::Identity)?;
            let mut counters = CounterState::default();
            // M5/C22: the CLI's trust store is ephemeral — no on-disk
            // persistence yet (deferred with the client-identity work, mirroring
            // D8). Seed a trusted entry for the dialed server so this connection
            // performs trusted-mode first-contact TOFU and pins the key for the
            // life of the process. Rotation-across-runs needs the persisted store
            // (later commit); untrusted mode is exercised via the library + the
            // federation test matrix, not the M5 CLI surface.
            let server_handle = Handle::from_str(&server_id)
                .map_err(|_| CliError::Connect(ConnectError::BadServerId))?;
            let mut trust = InMemoryTrustStore::new();
            trust.upsert(ServerEntry::new_trusted(server_handle, dial.clone()));
            let outcome = rt
                .block_on(connect(
                    &server_id,
                    &dial,
                    &identity,
                    &mut counters,
                    &mut trust,
                ))
                .map_err(CliError::Connect)?;
            // ISC-47: an authenticated-success line, printed only after the
            // connection reached `Authenticated` (connect returns Ok only then).
            println!(
                "authenticated {server} at {dialled}; wire version {version}",
                server = outcome.server_handle,
                dialled = outcome.dialled,
                version = outcome.version,
            );
            // ISC-C22: surface a non-blocking key-rotation notice if the
            // trusted-mode server presented a new (undismissed) key.
            if let Some(fingerprint) = outcome.rotation_notice {
                println!("notice: server key rotated; new fingerprint {fingerprint}");
            }
            Ok(())
        }
        Cmd::Publish {
            server_id,
            name,
            address,
            rating,
            handle,
        } => {
            let session = dial_session(&rt, &server_id, address.as_deref())?;
            let mut ps = session.public_space();
            // listing.share_id is ignored — the server assigns it (F25).
            let resp = rt
                .block_on(ps.publish_share(PublishShareRequest {
                    listing: Some(PublicShareListing {
                        share_id: String::new(),
                        name,
                        rating,
                        sharer_handle: handle,
                    }),
                }))
                .map_err(|s| CliError::Rpc(Box::new(s)))?;
            println!("published share {}", resp.into_inner().share_id);
            Ok(())
        }
        Cmd::Unpublish {
            server_id,
            share_id,
            address,
        } => {
            let session = dial_session(&rt, &server_id, address.as_deref())?;
            let mut ps = session.public_space();
            rt.block_on(ps.unpublish_share(UnpublishShareRequest {
                share_id: share_id.clone(),
            }))
            .map_err(|s| CliError::Rpc(Box::new(s)))?;
            // Owner-scoped + silent no-op: success here means the request was
            // served, not necessarily that a share was removed (ISC-A-S1).
            println!("unpublish requested for share {share_id}");
            Ok(())
        }
        Cmd::ListShares { server_id, address } => {
            let session = dial_session(&rt, &server_id, address.as_deref())?;
            let mut ps = session.public_space();
            let shares = rt
                .block_on(ps.list_public_shares(ListPublicSharesRequest {}))
                .map_err(|s| CliError::Rpc(Box::new(s)))?
                .into_inner()
                .shares;
            if shares.is_empty() {
                println!("no public shares");
            }
            for s in shares {
                println!(
                    "{id}\t{name}\t[{rating}]\t{handle}",
                    id = s.share_id,
                    name = s.name,
                    rating = s.rating,
                    handle = s.sharer_handle,
                );
            }
            Ok(())
        }
    }
}

/// Open an authenticated application session to `server_id`: resolve the
/// address, mint an ephemeral client identity (D8 — no persisted identity on
/// the MVP CLI), seed a trusted-mode store entry for first-contact TOFU
/// (ISC-C22), reach `Authenticated` via [`connect_session`], and build the
/// gRPC [`AppSession`] over the live stream. The identity, counters, and trust
/// store are ephemeral to this process (mirrors the `connect` subcommand).
fn dial_session(
    rt: &tokio::runtime::Runtime,
    server_id: &str,
    address: Option<&str>,
) -> Result<AppSession, CliError> {
    let dial = resolve_address(server_id, address).map_err(CliError::Connect)?;
    let identity = ClientIdentity::ephemeral().map_err(CliError::Identity)?;
    let mut counters = CounterState::default();
    let server_handle =
        Handle::from_str(server_id).map_err(|_| CliError::Connect(ConnectError::BadServerId))?;
    let mut trust = InMemoryTrustStore::new();
    trust.upsert(ServerEntry::new_trusted(server_handle, dial.clone()));
    let (_outcome, stream) = rt
        .block_on(connect_session(
            server_id,
            &dial,
            &identity,
            &mut counters,
            &mut trust,
        ))
        .map_err(CliError::Connect)?;
    rt.block_on(AppSession::open(stream))
        .map_err(CliError::Session)
}

/// CLI-level failure modes. Each maps to one preflight step or to the
/// underlying `ConnectError`.
#[derive(Debug)]
enum CliError {
    ModuleInit(oxicrypt_module::Error),
    ProviderInstall(daemonseed_server::tls::TlsError),
    Runtime(std::io::Error),
    Identity(ClientIdentityError),
    Connect(ConnectError),
    Session(SessionError),
    // Boxed: `tonic::Status` is large, and a bare large Err-variant bloats
    // every `Result<_, CliError>` (clippy::result_large_err).
    Rpc(Box<tonic::Status>),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleInit(e) => write!(f, "oxicrypt module init failed: {e}"),
            Self::ProviderInstall(e) => write!(f, "{e}"),
            Self::Runtime(e) => write!(f, "tokio runtime build failed: {e}"),
            Self::Identity(e) => write!(f, "{e}"),
            Self::Connect(e) => write!(f, "{e}"),
            Self::Session(e) => write!(f, "{e}"),
            Self::Rpc(e) => write!(f, "rpc failed: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cmd {
        Cli::try_parse_from(args).expect("args parse").cmd
    }

    #[test]
    fn publish_parses_required_and_optional_args() {
        match parse(&[
            "daemonseed-cli",
            "publish",
            "relay#0123456789ab",
            "design-docs",
            "--rating",
            "PG",
            "--handle",
            "me#aabbccddeeff",
            "--address",
            "host:443",
        ]) {
            Cmd::Publish {
                server_id,
                name,
                address,
                rating,
                handle,
            } => {
                assert_eq!(server_id, "relay#0123456789ab");
                assert_eq!(name, "design-docs");
                assert_eq!(rating, "PG");
                assert_eq!(handle, "me#aabbccddeeff");
                assert_eq!(address.as_deref(), Some("host:443"));
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    #[test]
    fn publish_rating_and_handle_default_to_empty() {
        match parse(&["daemonseed-cli", "publish", "relay#0123456789ab", "docs"]) {
            Cmd::Publish { rating, handle, .. } => {
                assert_eq!(rating, "");
                assert_eq!(handle, "");
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    #[test]
    fn unpublish_parses_share_id() {
        match parse(&[
            "daemonseed-cli",
            "unpublish",
            "relay#0123456789ab",
            "00000000000000ab",
        ]) {
            Cmd::Unpublish {
                server_id,
                share_id,
                ..
            } => {
                assert_eq!(server_id, "relay#0123456789ab");
                assert_eq!(share_id, "00000000000000ab");
            }
            other => panic!("expected Unpublish, got {other:?}"),
        }
    }

    #[test]
    fn list_shares_parses() {
        match parse(&["daemonseed-cli", "list-shares", "relay#0123456789ab"]) {
            Cmd::ListShares { server_id, address } => {
                assert_eq!(server_id, "relay#0123456789ab");
                assert!(address.is_none());
            }
            other => panic!("expected ListShares, got {other:?}"),
        }
    }
}
