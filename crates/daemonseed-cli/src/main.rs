//! daemonseed-cli — M4a scriptable client.
//!
//! Subcommands:
//! - `connect <server-id> [--address host:port]` — open a TLS-1.3
//!   connection to a daemonseed-server, exchange APP_HELLO, print the
//!   negotiated wire version, exit 0 on success.
//!
//! The library surface that backs this binary lives in `lib.rs` so the
//! commit-6 integration test drives the same `connect::connect` entry
//! point in-process.

#![forbid(unsafe_code)]

use core::str::FromStr;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use daemonseed_cli::connect::{ConnectError, connect, resolve_address};
use daemonseed_cli::identity_proof::{ClientIdentity, ClientIdentityError};
use daemonseed_core::federation::store::{InMemoryTrustStore, ServerEntry, TrustStore};
use daemonseed_core::handle::Handle;
use daemonseed_core::storage::seeds::CounterState;
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
    }
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
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleInit(e) => write!(f, "oxicrypt module init failed: {e}"),
            Self::ProviderInstall(e) => write!(f, "{e}"),
            Self::Runtime(e) => write!(f, "tokio runtime build failed: {e}"),
            Self::Identity(e) => write!(f, "{e}"),
            Self::Connect(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CliError {}
