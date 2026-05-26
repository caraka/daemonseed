//! daemonseed-server TOML configuration.
//!
//! Per ISC-S3 the server is stateless (no in-process mutation between
//! requests); all operator state arrives via a TOML config file. Per
//! ISC-C35 / ISC-S3 the config-file location resolution order is:
//!
//! 1. Explicit `--config <path>` flag (highest precedence)
//! 2. `XDG_CONFIG_HOME/daemonseed/daemonseed.toml` (or
//!    `$HOME/.config/daemonseed/daemonseed.toml` if XDG isn't set)
//! 3. `./daemonseed.toml` in the current working directory
//!
//! Resolution failure exits non-zero with a named error so operators see
//! "I looked in [path1, path2, path3] and found nothing" rather than a
//! silent default.

use core::fmt;
use std::error::Error;
use std::path::{Path, PathBuf};

use daemonseed_core::federation::trust::TrustMode;
use serde::{Deserialize, Serialize};

// ── Config struct ────────────────────────────────────────────────

/// Parsed `daemonseed.toml` contents.
///
/// Field set is intentionally minimal for M4a — adds happen as later
/// milestones grow the operator surface (signer whitelist in M6,
/// suite-deprecation policy in M7, rate limits in M9, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// TCP listen address. Default is `0.0.0.0:443` per ISC-S5.
    /// String form to keep the TOML human-typable; parsed to `SocketAddr`
    /// at bind time.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Path to the operator-managed long-term ML-DSA-87 seed file. Per
    /// ISC-S11 the keypair lives under the operator's TOML-referenced
    /// key path. M4a stores the raw 32-byte seed; the keypair is
    /// re-derived on each boot via `oxicrypt_ml_dsa::keygen`.
    pub key_path: PathBuf,

    /// Optional human-friendly server display name. Pairs with the
    /// derived hash prefix to form the server-id per ISC-S11 / ISC-C4.
    /// Empty / unset surfaces the floor `#<12hex>` form (ISC-C4b).
    #[serde(default)]
    pub display_name: Option<String>,

    /// Federation peers (ISC-S12). Each `[[peer]]` table entry carries the
    /// peer's server-id, address, trust mode (the same slider as the client's
    /// ISC-C22), and the `introduce-to-clients` flag (ISC-S13). Empty by
    /// default — a server federates with no peers until the operator adds them.
    ///
    /// The TOML key is the conventional singular `[[peer]]`; the Rust field is
    /// the idiomatic plural, bridged by `rename`.
    #[serde(rename = "peer", default)]
    pub peers: Vec<PeerConfig>,

    // ── Public space (M6) ────────────────────────────────────────────
    //
    // All optional / defaulted so a pre-M6 minimal config still parses. A
    // relay with no `posts_dir` / `motd_path` simply serves an empty
    // public space.
    /// Directory holding signer-written announcement posts (ISC-S7 / ISC-16).
    /// The server loads every file here into RAM on startup and is the only
    /// runtime-writable path besides `motd_path` (ISC-A-S8).
    #[serde(default)]
    pub posts_dir: Option<PathBuf>,

    /// Path to the single-slot signed MOTD file `motd.signed` (ISC-S9 /
    /// ISC-22). Absent / missing → no MOTD area.
    #[serde(default)]
    pub motd_path: Option<PathBuf>,

    /// Path to the plaintext signer-whitelist file (ISC-S8). One entry per
    /// line: a hex full ML-DSA-87 key or a `<name>#<hash>` handle. The file is
    /// operator-owned and never written by the server (ISC-A-S8 / ISC-13).
    #[serde(default)]
    pub signer_whitelist_path: Option<PathBuf>,

    /// Operator-defined content-rating labels published to clients (ISC-S10 /
    /// ISC-27). The server publishes but never enforces these (ISC-A-S5b).
    #[serde(default)]
    pub rating_taxonomy: Vec<String>,

    /// Operator-defined announcement topic set (ISC-S7 / ISC-19). Signers may
    /// post into these topics but cannot create or modify the set.
    #[serde(default)]
    pub topics: Vec<String>,

    /// Source-code location advertised in the APP_HELLO `server_source` field
    /// (ISC-9 / finding F32) — the AGPL "corresponding source" pointer.
    #[serde(default)]
    pub server_source: Option<String>,

    /// Crypto-agility operator policy (M7): suite-deprecation cutoffs (ISC-S16).
    /// Absent / default → no deprecation policy published.
    #[serde(default)]
    pub crypto: CryptoConfig,
}

/// Operator crypto-agility configuration (ISC-S16 / ISC-A-S11, M7).
///
/// The operator declares per-suite deprecation cutoffs plus a monotonic
/// `deprecation_policy_version`. The server builds a signed policy from this
/// table at startup and publishes it through the public-space service. Changing
/// any cutoff **requires** bumping `deprecation_policy_version` — the server
/// re-signs and clients replay-protect on the version (ISC-A-S11 / ISC-C25).
///
/// TOML shape:
/// ```toml
/// [crypto]
/// deprecation_policy_version = 3
/// [[crypto.deprecation]]
/// suite_id = 1
/// cutoff_unix_ms = 1893456000000
/// recommended_suite_id = 2
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Monotonic policy version. `0` (the default) means "no policy
    /// configured" and nothing is published. The operator increments this on
    /// every cutoff change (ISC-A-S11 / ISC-16).
    #[serde(default)]
    pub deprecation_policy_version: u64,

    /// Per-suite deprecation cutoffs. The TOML key is the singular
    /// `[[crypto.deprecation]]`; the Rust field is the idiomatic plural.
    #[serde(rename = "deprecation", default)]
    pub deprecations: Vec<DeprecationConfigEntry>,
}

/// One operator-declared deprecation cutoff (`[[crypto.deprecation]]`).
///
/// `cutoff_unix_ms` is wall-clock milliseconds UTC — the codebase's uniform
/// time representation (matching every other signed timestamp). ISC-S16 frames
/// this as ISO-8601; the unix-ms form is the M7 ergonomics choice to avoid a
/// date-parser dependency and stay consistent with the wire payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeprecationConfigEntry {
    /// The suite being retired (u16 SuiteId range).
    pub suite_id: u32,
    /// UTC cutoff in wall-clock milliseconds.
    pub cutoff_unix_ms: i64,
    /// Operator-recommended successor suite (u16 SuiteId range).
    pub recommended_suite_id: u32,
}

/// One federation peer in the server's TOML (`[[peer]]`).
///
/// The trust model is identical to the client's per-server slider (ISC-S12
/// reuses ISC-C22): a `trusted` peer is hash-verified then TOFU-pinned on first
/// contact; an `untrusted` peer must carry a pre-loaded `key_hex` matched
/// byte-for-byte. `introduce_to_clients = false` (ISC-S13) keeps the peer out
/// of every introducer response while still federating its traffic normally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    /// The peer's server-id, `<name>#<12hex>` (ISC-S11 / ISC-C4).
    pub server_id: String,

    /// Reachable address: hostname or raw IP literal, optional `:port`
    /// (default 443 per ISC-S5).
    pub address: String,

    /// Trust slider position for this peer. Defaults to `trusted` (ISC-C22
    /// default), matching the client-side default for newly-added servers.
    #[serde(default)]
    pub trust_mode: TrustMode,

    /// Whether this peer appears in introducer responses (ISC-S13). Default
    /// `true`; `false` suppresses introductions (client AND server-to-server)
    /// without stopping traffic.
    #[serde(default = "default_true")]
    pub introduce_to_clients: bool,

    /// Hex-encoded pre-loaded full public key, required for `untrusted` peers
    /// (ISC-C22 untrusted / ISC-S12-5). Ignored for `trusted` peers, which
    /// TOFU-pin on first contact.
    #[serde(default)]
    pub key_hex: Option<String>,
}

fn default_listen_addr() -> String {
    "0.0.0.0:443".to_owned()
}

fn default_true() -> bool {
    true
}

impl ServerConfig {
    /// Parse the TOML contents of a config file. Used by both the file-
    /// reader path ([`Self::from_path`]) and tests that fabricate
    /// config strings in-memory.
    pub fn from_toml(toml_src: &str) -> Result<Self, ConfigError> {
        toml::from_str(toml_src).map_err(ConfigError::Parse)
    }

    /// Read + parse a TOML config file at `path`.
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&contents)
    }
}

// ── Resolution ───────────────────────────────────────────────────

/// Resolve a config-file location per the precedence order in the
/// module docs. Returns the first path that exists; returns
/// [`ConfigError::NotFound`] carrying the search list if all three
/// fall through.
pub fn resolve_config_path(
    explicit: Option<&Path>,
    xdg_config_home: Option<&Path>,
    home: Option<&Path>,
    cwd: &Path,
) -> Result<PathBuf, ConfigError> {
    let mut searched = Vec::new();

    if let Some(p) = explicit {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        searched.push(p.to_path_buf());
    }

    // XDG path — prefer XDG_CONFIG_HOME, fall back to $HOME/.config.
    let xdg_base = xdg_config_home.map(Path::to_path_buf).or_else(|| {
        home.map(|h| {
            let mut p = h.to_path_buf();
            p.push(".config");
            p
        })
    });
    if let Some(mut p) = xdg_base {
        p.push("daemonseed");
        p.push("daemonseed.toml");
        if p.exists() {
            return Ok(p);
        }
        searched.push(p);
    }

    let mut cwd_path = cwd.to_path_buf();
    cwd_path.push("daemonseed.toml");
    if cwd_path.exists() {
        return Ok(cwd_path);
    }
    searched.push(cwd_path);

    Err(ConfigError::NotFound { searched })
}

// ── Errors ───────────────────────────────────────────────────────

/// Errors raised by [`ServerConfig`] loading + resolution.
#[derive(Debug)]
pub enum ConfigError {
    /// No config file was found at any path in the resolution order.
    NotFound { searched: Vec<PathBuf> },
    /// Reading the config file from disk failed.
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Parsing the TOML failed.
    Parse(toml::de::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { searched } => {
                write!(f, "no daemonseed.toml found in search order: {searched:?}")
            }
            Self::Read { path, source } => {
                write!(f, "failed to read config file {}: {source}", path.display())
            }
            Self::Parse(e) => write!(f, "TOML parse error: {e}"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse(e) => Some(e),
            Self::NotFound { .. } => None,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn minimal_config_parses_with_defaults() {
        let cfg = ServerConfig::from_toml(r#"key_path = "/var/lib/daemonseed/seed""#).unwrap();
        assert_eq!(
            cfg.listen_addr, "0.0.0.0:443",
            "default listen_addr per ISC-S5"
        );
        assert_eq!(cfg.key_path, PathBuf::from("/var/lib/daemonseed/seed"));
        assert_eq!(cfg.display_name, None, "display_name optional per ISC-C4b");
    }

    #[test]
    fn full_config_parses() {
        let cfg = ServerConfig::from_toml(
            r#"
            listen_addr = "127.0.0.1:8443"
            key_path = "/srv/daemonseed/seed.bin"
            display_name = "happy-bear"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:8443");
        assert_eq!(cfg.display_name.as_deref(), Some("happy-bear"));
    }

    #[test]
    fn peers_default_to_empty() {
        let cfg = ServerConfig::from_toml(r#"key_path = "/k""#).unwrap();
        assert!(cfg.peers.is_empty(), "no [[peer]] tables → no peers");
    }

    #[test]
    fn public_space_fields_default_when_absent() {
        // A minimal pre-M6 config must still parse — every public-space field
        // is optional / defaulted so existing relays don't need rewriting.
        let cfg = ServerConfig::from_toml(r#"key_path = "/k""#).unwrap();
        assert_eq!(cfg.posts_dir, None);
        assert_eq!(cfg.motd_path, None);
        assert_eq!(cfg.signer_whitelist_path, None);
        assert!(cfg.rating_taxonomy.is_empty());
        assert!(cfg.topics.is_empty());
        assert_eq!(cfg.server_source, None);
    }

    #[test]
    fn public_space_fields_parse_when_present() {
        let cfg = ServerConfig::from_toml(
            r#"
            key_path = "/k"
            posts_dir = "/srv/ds/posts"
            motd_path = "/srv/ds/motd.signed"
            signer_whitelist_path = "/srv/ds/signers.txt"
            rating_taxonomy = ["PG13", "R", "X"]
            topics = ["announcements", "downtime"]
            server_source = "https://relay.example/source"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.posts_dir, Some(PathBuf::from("/srv/ds/posts")));
        assert_eq!(cfg.motd_path, Some(PathBuf::from("/srv/ds/motd.signed")));
        assert_eq!(
            cfg.signer_whitelist_path,
            Some(PathBuf::from("/srv/ds/signers.txt"))
        );
        assert_eq!(cfg.rating_taxonomy, vec!["PG13", "R", "X"]);
        assert_eq!(cfg.topics, vec!["announcements", "downtime"]);
        assert_eq!(
            cfg.server_source.as_deref(),
            Some("https://relay.example/source")
        );
    }

    #[test]
    fn peer_parses_all_fields() {
        let cfg = ServerConfig::from_toml(
            r#"
            key_path = "/k"
            [[peer]]
            server_id = "relay-bear#0123456789ab"
            address = "relay.example:8443"
            trust_mode = "untrusted"
            introduce_to_clients = false
            key_hex = "aabb"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.peers.len(), 1);
        let p = &cfg.peers[0];
        assert_eq!(p.server_id, "relay-bear#0123456789ab");
        assert_eq!(p.address, "relay.example:8443");
        assert_eq!(p.trust_mode, TrustMode::Untrusted);
        assert!(!p.introduce_to_clients);
        assert_eq!(p.key_hex.as_deref(), Some("aabb"));
    }

    #[test]
    fn peer_trust_mode_defaults_trusted_and_introduce_defaults_true() {
        let cfg = ServerConfig::from_toml(
            r#"
            key_path = "/k"
            [[peer]]
            server_id = "x#0123456789ab"
            address = "x.example"
            "#,
        )
        .unwrap();
        let p = &cfg.peers[0];
        assert_eq!(p.trust_mode, TrustMode::Trusted, "ISC-C22 default");
        assert!(p.introduce_to_clients, "ISC-S13 default true");
        assert_eq!(p.key_hex, None);
    }

    #[test]
    fn multiple_peers_parse_in_order() {
        let cfg = ServerConfig::from_toml(
            r#"
            key_path = "/k"
            [[peer]]
            server_id = "a#0123456789ab"
            address = "a.example"
            [[peer]]
            server_id = "b#0123456789ab"
            address = "b.example"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.peers[0].server_id, "a#0123456789ab");
        assert_eq!(cfg.peers[1].server_id, "b#0123456789ab");
    }

    #[test]
    fn missing_required_field_errors_named() {
        // key_path has no default; omitting it must fail with Parse.
        let err = ServerConfig::from_toml("listen_addr = \"0.0.0.0:443\"")
            .expect_err("key_path is required");
        match err {
            ConfigError::Parse(_) => {}
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn from_path_reads_disk() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("daemonseed.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"key_path = "/some/seed""#).unwrap();
        let cfg = ServerConfig::from_path(&path).unwrap();
        assert_eq!(cfg.key_path, PathBuf::from("/some/seed"));
    }

    #[test]
    fn from_path_missing_file_errors_with_path_context() {
        let err = ServerConfig::from_path(Path::new("/nonexistent/daemonseed.toml"))
            .expect_err("file doesn't exist");
        match err {
            ConfigError::Read { path, .. } => {
                assert_eq!(path, PathBuf::from("/nonexistent/daemonseed.toml"));
            }
            other => panic!("expected Read with path context, got {other:?}"),
        }
    }

    #[test]
    fn resolve_picks_explicit_when_present() {
        let dir = TempDir::new().unwrap();
        let explicit = dir.path().join("custom.toml");
        std::fs::write(&explicit, r#"key_path = "/k""#).unwrap();
        let resolved = resolve_config_path(Some(&explicit), None, None, dir.path()).unwrap();
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn resolve_falls_through_to_cwd_when_no_xdg() {
        let dir = TempDir::new().unwrap();
        let cwd_cfg = dir.path().join("daemonseed.toml");
        std::fs::write(&cwd_cfg, r#"key_path = "/k""#).unwrap();
        let resolved = resolve_config_path(None, None, None, dir.path()).unwrap();
        assert_eq!(resolved, cwd_cfg);
    }

    #[test]
    fn resolve_picks_xdg_when_present_and_no_explicit() {
        let dir = TempDir::new().unwrap();
        let xdg_base = dir.path().join("xdg");
        let xdg_daemonseed = xdg_base.join("daemonseed");
        std::fs::create_dir_all(&xdg_daemonseed).unwrap();
        let xdg_cfg = xdg_daemonseed.join("daemonseed.toml");
        std::fs::write(&xdg_cfg, r#"key_path = "/k""#).unwrap();
        let resolved = resolve_config_path(None, Some(&xdg_base), None, dir.path()).unwrap();
        assert_eq!(resolved, xdg_cfg);
    }

    #[test]
    fn resolve_not_found_carries_search_list() {
        let dir = TempDir::new().unwrap();
        let err = resolve_config_path(None, None, None, dir.path()).expect_err("nothing exists");
        match err {
            ConfigError::NotFound { searched } => {
                assert!(searched.iter().any(|p| p.ends_with("daemonseed.toml")));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
