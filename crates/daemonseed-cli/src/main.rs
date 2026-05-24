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

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use daemonseed_cli::connect::{ConnectError, connect, resolve_address};
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
            let outcome = rt
                .block_on(connect(&server_id, &dial))
                .map_err(CliError::Connect)?;
            println!(
                "connected to {server_id} at {dialled}; wire version {version}",
                server_id = server_id,
                dialled = outcome.dialled,
                version = outcome.version,
            );
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
    Connect(ConnectError),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleInit(e) => write!(f, "oxicrypt module init failed: {e}"),
            Self::ProviderInstall(e) => write!(f, "{e}"),
            Self::Runtime(e) => write!(f, "tokio runtime build failed: {e}"),
            Self::Connect(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CliError {}
