//! Profile-root resolution (ISC-C35).
//!
//! Resolution order:
//! 1. **`--config <path>` CLI flag** (highest priority). Either a file path
//!    (its parent dir becomes the profile root) or a directory (the binary
//!    looks for `daemonseed.toml` inside).
//! 2. **`daemonseed.toml` in the current working directory**. The CWD
//!    becomes the profile root. This is the tester-grade multi-instance
//!    path — `cd alice/ && daemonseed-tui` runs alice; `cd bob/ &&
//!    daemonseed-tui` runs bob, no flags needed.
//! 3. **XDG conventions** (fallback). On Linux:
//!    `$XDG_CONFIG_HOME/daemonseed/daemonseed.toml` (defaulting to
//!    `~/.config/daemonseed/daemonseed.toml`). Platform equivalents apply
//!    on macOS / Windows.
//!
//! If none of the above turns up a config, [`ResolvedProfileRoot::FirstStart`]
//! is returned so the caller can run the enrollment flow.
//!
//! ## Portable mode (`--portable`, ISC-C52)
//!
//! `--portable` forces the **current working directory** to be the profile root
//! and **skips the XDG fallback entirely** — so a *fresh* first-start writes its
//! config, blob, and `.dseed` into the CWD instead of the system location. This
//! is the once-only "make a new self-contained instance here" verb: after the
//! first run the directory holds a `daemonseed.toml`, so plain CWD discovery
//! (path 2) picks it up with no flag thereafter. `--config` still wins over
//! `--portable` if both are given (it is the more specific instruction).

use std::env;
use std::path::{Path, PathBuf};

/// Canonical config filename. Uniform across all three discovery paths per
/// the F19 finding fix.
pub const CONFIG_FILENAME: &str = "daemonseed.toml";

/// Inputs to [`resolve`]. Future flags land here without touching the
/// resolution body.
#[derive(Debug, Default, Clone)]
pub struct ResolveArgs {
    /// Value passed via the `--config <path>` CLI flag, if any.
    pub config_flag: Option<PathBuf>,
    /// `--portable`: force the CWD as the profile root and skip XDG (ISC-C52),
    /// so a fresh first-start writes into the CWD. Ignored when `config_flag`
    /// is set (`--config` is the more specific instruction).
    pub portable: bool,
}

/// Outcome of resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedProfileRoot {
    /// An existing profile root (contains `daemonseed.toml`). The path is
    /// the *directory*, not the file.
    Existing { root: PathBuf, config_path: PathBuf },
    /// No existing config found; M2 first-start should run. The path is
    /// where a new config would be written (XDG location by default).
    FirstStart { default_root: PathBuf },
}

/// Errors from resolution.
#[derive(Debug)]
pub enum ResolveError {
    /// `--config` was supplied but the path doesn't exist.
    ConfigFlagNotFound { path: PathBuf },
    /// `--config` pointed at a directory but no `daemonseed.toml` inside.
    ConfigFlagDirWithoutConfig { path: PathBuf },
    /// XDG default location is unresolvable (`$HOME` unset and no fallback).
    NoXdgRoot,
    /// `--portable` was requested but the current working directory could not
    /// be determined (ISC-C52) — there is no "here" to be portable to.
    PortableWithoutCwd,
}

impl core::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResolveError::ConfigFlagNotFound { path } => {
                write!(f, "--config path not found: {}", path.display())
            }
            ResolveError::ConfigFlagDirWithoutConfig { path } => write!(
                f,
                "--config points at directory `{}` but no `{CONFIG_FILENAME}` inside",
                path.display()
            ),
            ResolveError::NoXdgRoot => write!(
                f,
                "could not resolve XDG profile location ($HOME unset and no fallback)"
            ),
            ResolveError::PortableWithoutCwd => write!(
                f,
                "--portable requested but the current working directory is unavailable"
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Resolve the profile root per ISC-C35.
///
/// `args` carries the explicit CLI input. `cwd_override` and `env_lookup` are
/// dependency-injection points for tests; production callers pass `None` /
/// `std::env::var_os` semantics via [`resolve`].
pub fn resolve(args: ResolveArgs) -> Result<ResolvedProfileRoot, ResolveError> {
    resolve_with_env(args, env::current_dir().ok(), |k| {
        env::var_os(k).map(|v| v.to_string_lossy().into_owned())
    })
}

/// Test-friendly variant: caller supplies CWD + an env-var resolver.
pub fn resolve_with_env<F>(
    args: ResolveArgs,
    cwd: Option<PathBuf>,
    env_lookup: F,
) -> Result<ResolvedProfileRoot, ResolveError>
where
    F: Fn(&str) -> Option<String>,
{
    // (1) --config flag (most specific; wins over --portable).
    if let Some(p) = args.config_flag {
        return resolve_config_flag(&p);
    }

    // (1b) --portable: force the CWD as the profile root and SKIP the XDG
    // fallback (ISC-C52). An existing config in the CWD is honoured; otherwise a
    // fresh first-start is targeted at the CWD, not the system location.
    if args.portable {
        let root = cwd.ok_or(ResolveError::PortableWithoutCwd)?;
        let config_path = root.join(CONFIG_FILENAME);
        return Ok(if config_path.is_file() {
            ResolvedProfileRoot::Existing { root, config_path }
        } else {
            ResolvedProfileRoot::FirstStart { default_root: root }
        });
    }

    // (2) CWD daemonseed.toml.
    if let Some(c) = cwd
        && c.join(CONFIG_FILENAME).is_file()
    {
        return Ok(ResolvedProfileRoot::Existing {
            root: c.clone(),
            config_path: c.join(CONFIG_FILENAME),
        });
    }

    // (3) XDG fallback.
    let xdg_root = xdg_default_root(&env_lookup).ok_or(ResolveError::NoXdgRoot)?;
    let xdg_config = xdg_root.join(CONFIG_FILENAME);
    if xdg_config.is_file() {
        Ok(ResolvedProfileRoot::Existing {
            root: xdg_root,
            config_path: xdg_config,
        })
    } else {
        Ok(ResolvedProfileRoot::FirstStart {
            default_root: xdg_root,
        })
    }
}

fn resolve_config_flag(p: &Path) -> Result<ResolvedProfileRoot, ResolveError> {
    if p.is_file() {
        let root = p
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(ResolvedProfileRoot::Existing {
            root,
            config_path: p.to_path_buf(),
        });
    }
    if p.is_dir() {
        let candidate = p.join(CONFIG_FILENAME);
        if candidate.is_file() {
            return Ok(ResolvedProfileRoot::Existing {
                root: p.to_path_buf(),
                config_path: candidate,
            });
        }
        return Err(ResolveError::ConfigFlagDirWithoutConfig {
            path: p.to_path_buf(),
        });
    }
    Err(ResolveError::ConfigFlagNotFound {
        path: p.to_path_buf(),
    })
}

/// Resolve the platform-appropriate default XDG-style profile root.
///
/// - Linux / *BSD: `$XDG_CONFIG_HOME/daemonseed` or `$HOME/.config/daemonseed`.
/// - macOS: `$HOME/Library/Application Support/daemonseed`.
/// - Windows: `%APPDATA%\daemonseed`.
///
/// Falls back to `None` only when none of the above env vars resolve.
fn xdg_default_root<F: Fn(&str) -> Option<String>>(env_lookup: &F) -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        env_lookup("HOME").map(|h| {
            PathBuf::from(h)
                .join("Library")
                .join("Application Support")
                .join("daemonseed")
        })
    } else if cfg!(target_os = "windows") {
        env_lookup("APPDATA").map(|a| PathBuf::from(a).join("daemonseed"))
    } else {
        env_lookup("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env_lookup("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|p| p.join("daemonseed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// Build a tempdir whose deletion fires on drop.
    struct Tmp {
        path: PathBuf,
    }
    impl Tmp {
        fn new() -> Self {
            let path = env::temp_dir().join(format!("daemonseed-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_config(dir: &Path) -> PathBuf {
        let p = dir.join(CONFIG_FILENAME);
        let mut f = fs::File::create(&p).unwrap();
        writeln!(f, "profile_id = \"123e4567-e89b-12d3-a456-426614174000\"").unwrap();
        p
    }

    // ── --config flag ──────────────────────────────────────────────────────

    #[test]
    fn config_flag_file_path_resolves() {
        let tmp = Tmp::new();
        let cfg = write_config(&tmp.path);
        let resolved = resolve_with_env(
            ResolveArgs {
                config_flag: Some(cfg.clone()),
                ..ResolveArgs::default()
            },
            None,
            |_| None,
        )
        .unwrap();
        match resolved {
            ResolvedProfileRoot::Existing { root, config_path } => {
                assert_eq!(root, tmp.path);
                assert_eq!(config_path, cfg);
            }
            other => panic!("expected Existing, got {other:?}"),
        }
    }

    #[test]
    fn config_flag_directory_resolves() {
        let tmp = Tmp::new();
        let cfg = write_config(&tmp.path);
        let resolved = resolve_with_env(
            ResolveArgs {
                config_flag: Some(tmp.path.clone()),
                ..ResolveArgs::default()
            },
            None,
            |_| None,
        )
        .unwrap();
        match resolved {
            ResolvedProfileRoot::Existing { root, config_path } => {
                assert_eq!(root, tmp.path);
                assert_eq!(config_path, cfg);
            }
            other => panic!("expected Existing, got {other:?}"),
        }
    }

    #[test]
    fn config_flag_nonexistent_path_errors() {
        let bogus = PathBuf::from("/this/path/should/not/exist/daemonseed-bogus");
        match resolve_with_env(
            ResolveArgs {
                config_flag: Some(bogus.clone()),
                ..ResolveArgs::default()
            },
            None,
            |_| None,
        ) {
            Err(ResolveError::ConfigFlagNotFound { path }) => assert_eq!(path, bogus),
            other => panic!("expected ConfigFlagNotFound, got {other:?}"),
        }
    }

    #[test]
    fn config_flag_dir_without_config_errors() {
        let tmp = Tmp::new();
        // dir exists but no daemonseed.toml inside
        match resolve_with_env(
            ResolveArgs {
                config_flag: Some(tmp.path.clone()),
                ..ResolveArgs::default()
            },
            None,
            |_| None,
        ) {
            Err(ResolveError::ConfigFlagDirWithoutConfig { path }) => {
                assert_eq!(path, tmp.path);
            }
            other => panic!("expected ConfigFlagDirWithoutConfig, got {other:?}"),
        }
    }

    // ── CWD discovery ─────────────────────────────────────────────────────

    #[test]
    fn cwd_discovery_resolves_to_cwd_root() {
        let tmp = Tmp::new();
        write_config(&tmp.path);
        let resolved =
            resolve_with_env(ResolveArgs::default(), Some(tmp.path.clone()), |_| None).unwrap();
        match resolved {
            ResolvedProfileRoot::Existing { root, .. } => assert_eq!(root, tmp.path),
            other => panic!("expected Existing, got {other:?}"),
        }
    }

    #[test]
    fn cwd_without_config_falls_through_to_xdg() {
        let tmp = Tmp::new();
        let xdg = Tmp::new();
        let resolved = resolve_with_env(
            ResolveArgs::default(),
            Some(tmp.path.clone()),
            |k| match k {
                "XDG_CONFIG_HOME" => Some(xdg.path.to_string_lossy().into_owned()),
                _ => None,
            },
        )
        .unwrap();
        match resolved {
            // XDG dir doesn't have a config either, so FirstStart.
            ResolvedProfileRoot::FirstStart { default_root } => {
                assert_eq!(default_root, xdg.path.join("daemonseed"));
            }
            other => panic!("expected FirstStart, got {other:?}"),
        }
    }

    // ── --portable (ISC-C52) ──────────────────────────────────────────────

    #[test]
    fn portable_fresh_targets_cwd_not_xdg() {
        // A fresh --portable run (no config in the CWD) first-starts INTO the
        // CWD, never the XDG location — even though XDG is resolvable here.
        let cwd = Tmp::new();
        let xdg = Tmp::new();
        let resolved = resolve_with_env(
            ResolveArgs {
                portable: true,
                ..ResolveArgs::default()
            },
            Some(cwd.path.clone()),
            |k| match k {
                "XDG_CONFIG_HOME" => Some(xdg.path.to_string_lossy().into_owned()),
                "HOME" => Some(xdg.path.to_string_lossy().into_owned()),
                _ => None,
            },
        )
        .unwrap();
        match resolved {
            ResolvedProfileRoot::FirstStart { default_root } => assert_eq!(default_root, cwd.path),
            other => panic!("expected FirstStart in CWD, got {other:?}"),
        }
    }

    #[test]
    fn portable_existing_cwd_config_resolves_existing() {
        let cwd = Tmp::new();
        let cfg = write_config(&cwd.path);
        let resolved = resolve_with_env(
            ResolveArgs {
                portable: true,
                ..ResolveArgs::default()
            },
            Some(cwd.path.clone()),
            |_| None,
        )
        .unwrap();
        match resolved {
            ResolvedProfileRoot::Existing { root, config_path } => {
                assert_eq!(root, cwd.path);
                assert_eq!(config_path, cfg);
            }
            other => panic!("expected Existing in CWD, got {other:?}"),
        }
    }

    #[test]
    fn portable_skips_xdg_even_when_xdg_has_a_config() {
        // XDG has a real config, but --portable must ignore it and first-start
        // in the (config-less) CWD.
        let cwd = Tmp::new();
        let xdg_home = Tmp::new();
        let daemonseed_dir = xdg_home.path.join("daemonseed");
        fs::create_dir_all(&daemonseed_dir).unwrap();
        write_config(&daemonseed_dir);
        let resolved = resolve_with_env(
            ResolveArgs {
                portable: true,
                ..ResolveArgs::default()
            },
            Some(cwd.path.clone()),
            |k| match k {
                "XDG_CONFIG_HOME" => Some(xdg_home.path.to_string_lossy().into_owned()),
                _ => None,
            },
        )
        .unwrap();
        match resolved {
            ResolvedProfileRoot::FirstStart { default_root } => assert_eq!(default_root, cwd.path),
            other => panic!("--portable must skip XDG, got {other:?}"),
        }
    }

    #[test]
    fn portable_without_cwd_errors() {
        match resolve_with_env(
            ResolveArgs {
                portable: true,
                ..ResolveArgs::default()
            },
            None,
            |_| None,
        ) {
            Err(ResolveError::PortableWithoutCwd) => {}
            other => panic!("expected PortableWithoutCwd, got {other:?}"),
        }
    }

    #[test]
    fn config_flag_wins_over_portable() {
        // Both --config and --portable given: --config is the more specific
        // instruction and takes precedence.
        let tmp = Tmp::new();
        let cfg = write_config(&tmp.path);
        let resolved = resolve_with_env(
            ResolveArgs {
                config_flag: Some(cfg.clone()),
                portable: true,
            },
            Some(PathBuf::from("/some/other/cwd")),
            |_| None,
        )
        .unwrap();
        match resolved {
            ResolvedProfileRoot::Existing { root, .. } => assert_eq!(root, tmp.path),
            other => panic!("expected --config to win, got {other:?}"),
        }
    }

    // ── XDG fallback ──────────────────────────────────────────────────────

    #[test]
    fn xdg_finds_existing_config() {
        let xdg_home = Tmp::new();
        let daemonseed_dir = xdg_home.path.join("daemonseed");
        fs::create_dir_all(&daemonseed_dir).unwrap();
        let cfg = write_config(&daemonseed_dir);

        let resolved = resolve_with_env(
            ResolveArgs::default(),
            None, // no CWD discovery
            |k| match k {
                "XDG_CONFIG_HOME" => Some(xdg_home.path.to_string_lossy().into_owned()),
                _ => None,
            },
        )
        .unwrap();
        match resolved {
            ResolvedProfileRoot::Existing { root, config_path } => {
                assert_eq!(root, daemonseed_dir);
                assert_eq!(config_path, cfg);
            }
            other => panic!("expected Existing, got {other:?}"),
        }
    }

    #[test]
    fn xdg_falls_back_to_home_dot_config() {
        let home = Tmp::new();
        let resolved = resolve_with_env(ResolveArgs::default(), None, |k| match k {
            "HOME" => Some(home.path.to_string_lossy().into_owned()),
            _ => None,
        })
        .unwrap();
        match resolved {
            ResolvedProfileRoot::FirstStart { default_root } => {
                // On non-macos/non-windows the fallback is $HOME/.config/daemonseed
                if !cfg!(target_os = "macos") && !cfg!(target_os = "windows") {
                    assert_eq!(default_root, home.path.join(".config").join("daemonseed"));
                }
            }
            other => panic!("expected FirstStart, got {other:?}"),
        }
    }

    #[test]
    fn no_env_at_all_errors() {
        let result = resolve_with_env(ResolveArgs::default(), None, |_| None);
        assert!(matches!(result, Err(ResolveError::NoXdgRoot)));
    }
}
