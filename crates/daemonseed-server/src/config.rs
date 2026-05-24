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
}

fn default_listen_addr() -> String {
    "0.0.0.0:443".to_owned()
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
