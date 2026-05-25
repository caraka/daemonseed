//! daemonseed-server binary.
//!
//! Boot sequence:
//!
//! 1. Parse `--config <path>` flag (clap)
//! 2. Initialize the `oxicrypt-module` gate with CNSA 2.0 KATS — every
//!    subsequent oxicrypt call returns `Error::NotOperational` if this
//!    step fails, so we treat any error here as fatal
//! 3. Resolve the config file (explicit → XDG → CWD per ISC-C35)
//! 4. Install the oxitls rustls `CryptoProvider` as the process-wide
//!    default — fatal if anything else already won the install race
//!    (ISC-A6)
//! 5. Load (or first-boot generate) the server's long-term ML-DSA-87
//!    seed (ISC-S11)
//! 6. Derive the server-id from the seed + display name (ISC-S11 / C4)
//! 7. Build the rustls `ServerConfig` (TLS 1.3, ALPN `h2`, 0-RTT off,
//!    ML-DSA-87 cert; ISC-S2a/S2b/S5/A-S9)
//! 8. Bind the TCP listener + accept loop + per-connection HELLO
//!    handler, until SIGTERM / Ctrl-C (ISC-9)
//!
//! The library surface that backs this binary lives in `lib.rs` so the
//! integration-test crate can drive the same modules in-process.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use daemonseed_server::{
    config::{ConfigError, ServerConfig as DseedConfig, resolve_config_path},
    identity::{IdentityError, derive_server_id, load_or_generate},
    identity_proof::{IdentityProofError, ServerIdentity},
    kats::CNSA_2_0_KATS,
    runtime::{noop_observer, parse_listen_addr, run, shutdown_signal},
    tls::{DEFAULT_CERT_VALIDITY, TlsError, build_server_config, install_provider},
};
use oxicrypt_module::{AlgorithmProfile, initialize_with_profile};

#[derive(Parser, Debug)]
#[command(name = "daemonseed-server", about = "daemonseed relay daemon", version)]
struct Cli {
    /// Explicit path to `daemonseed.toml`. If omitted, the resolver
    /// searches `$XDG_CONFIG_HOME/daemonseed/daemonseed.toml` then
    /// `./daemonseed.toml`. The full search list is included in the
    /// error message when nothing is found.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run_server(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("daemonseed-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_server(cli: Cli) -> Result<(), BootError> {
    // Step 2 — module gate. The CNSA 2.0 KATS slice is union-assembled
    // in `kats.rs`; failure here latches the module into the error
    // state and any subsequent oxicrypt call would return
    // `Error::NotOperational`, so this is fatal.
    initialize_with_profile(CNSA_2_0_KATS, AlgorithmProfile::Cnsa2)
        .map_err(BootError::ModuleInit)?;

    // Step 3 — resolve config.
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let cwd = std::env::current_dir().map_err(BootError::Cwd)?;
    let config_path =
        resolve_config_path(cli.config.as_deref(), xdg.as_deref(), home.as_deref(), &cwd)
            .map_err(BootError::Config)?;
    let config = DseedConfig::from_path(&config_path).map_err(BootError::Config)?;

    // Step 4 — provider install.
    install_provider().map_err(BootError::Tls)?;

    // Step 5 — server identity (seed → ML-DSA-87 keypair).
    let seed = load_or_generate(&config.key_path).map_err(BootError::Identity)?;
    let server_id =
        derive_server_id(&seed, config.display_name.clone()).map_err(BootError::Identity)?;

    // Step 6/7 — ServerConfig assembly.
    let tls_config =
        build_server_config(&seed, &server_id, DEFAULT_CERT_VALIDITY).map_err(BootError::Tls)?;

    // Long-term signing identity for the post-HELLO identity-proof envelope
    // (ISC-S19). Re-derived from the same seed; shared read-only across all
    // per-connection tasks.
    let identity =
        Arc::new(ServerIdentity::from_seed(&seed, &server_id).map_err(BootError::IdentityProof)?);

    let addr = parse_listen_addr(&config.listen_addr).map_err(BootError::ListenAddr)?;

    // Step 8 — runtime. The multi-thread builder is used so the accept
    // loop and per-connection handlers can run on separate worker
    // threads on a multi-core host.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(BootError::Runtime)?;
    runtime
        .block_on(run(
            addr,
            tls_config,
            identity,
            shutdown_signal(),
            noop_observer(),
        ))
        .map_err(BootError::Accept)
}

/// Boot-time failure modes. Each variant maps to one of the eight
/// numbered steps in the module docs; the operator sees the underlying
/// error wrapped with that context on stderr.
#[derive(Debug)]
enum BootError {
    ModuleInit(oxicrypt_module::Error),
    Cwd(std::io::Error),
    Config(ConfigError),
    Tls(TlsError),
    Identity(IdentityError),
    IdentityProof(IdentityProofError),
    ListenAddr(std::io::Error),
    Runtime(std::io::Error),
    Accept(std::io::Error),
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleInit(e) => write!(f, "oxicrypt module init failed: {e}"),
            Self::Cwd(e) => write!(f, "current-directory read failed: {e}"),
            Self::Config(e) => write!(f, "{e}"),
            Self::Tls(e) => write!(f, "{e}"),
            Self::Identity(e) => write!(f, "{e}"),
            Self::IdentityProof(e) => write!(f, "server identity setup failed: {e}"),
            Self::ListenAddr(e) => write!(f, "listen_addr parse failed: {e}"),
            Self::Runtime(e) => write!(f, "tokio runtime build failed: {e}"),
            Self::Accept(e) => write!(f, "accept loop failed: {e}"),
        }
    }
}

impl std::error::Error for BootError {}
