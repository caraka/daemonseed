//! OS-native autostart — **scaffold only** (ISC-C20, M10-completion).
//!
//! Two pieces ship here, both buildable and testable with zero OS dependency:
//!
//! 1. [`unit_descriptor`] — a **pure** function that, given an [`AutostartSpec`]
//!    and a target OS mechanism, returns the *text* of an autostart unit
//!    (systemd user unit / launchd plist / Windows Startup command). It does
//!    NOT write files, register units, enable, or run anything.
//! 2. [`AutostartManager`] — the trait a future client implements to actually
//!    install/enable/disable the descriptor. No implementation ships here.
//!
//! Autostart is opt-in and off by default (`ProfileConfig::autostart`). When
//! enabled it launches the profile **headless** unless the user explicitly
//! chose a GUI surface. Enabling it pins the daemon's primary identity to
//! "online whenever the machine is on" — a presence side-channel the user
//! accepts (see [`PRESENCE_SIDE_CHANNEL_WARNING`]).
//!
//! ## What is NOT here (reserved)
//!
//! Actual OS installation, GUI-autostart wiring, mobile background-execution
//! policy, and the persistent headless client the unit would launch all belong
//! to the GUI and mobile clients and are not implemented, so ISC-C20 in
//! `ISA.md` stays open. The descriptor *text* is generated here so the install
//! step is later additive.

/// Which OS autostart mechanism a descriptor targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutostartTarget {
    /// systemd user unit (`~/.config/systemd/user/<name>.service`), Linux.
    SystemdUser,
    /// launchd LaunchAgent plist (`~/Library/LaunchAgents/<label>.plist`), macOS.
    Launchd,
    /// Windows Startup-folder command / `Run` key entry.
    WindowsStartup,
}

/// Whether autostart launches the profile headless (default) or with a GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutostartMode {
    /// No GUI surface — the daemon runs in the background (ISC-C20 default).
    #[default]
    Headless,
    /// Explicit opt-in GUI surface.
    Gui,
}

/// The inputs the pure descriptor generator needs to render a unit for one
/// profile. All fields are plain strings so the generator stays free of any
/// filesystem or process type.
#[derive(Debug, Clone)]
pub struct AutostartSpec {
    /// Human-facing profile name, used to namespace the unit (multi-instance).
    pub profile_name: String,
    /// Absolute path to the daemonseed executable to launch.
    pub exec_path: String,
    /// The profile's config directory, passed via `--config` (ISC-C35) so the
    /// unit pins this specific enrollment.
    pub config_dir: String,
    /// Headless (default) or explicit GUI.
    pub mode: AutostartMode,
}

impl AutostartSpec {
    /// The command-line arguments the unit launches with: always `--config
    /// <dir>`, plus `--gui` only when the GUI surface was explicitly chosen.
    fn args(&self) -> Vec<String> {
        let mut args = vec!["--config".to_string(), self.config_dir.clone()];
        if self.mode == AutostartMode::Gui {
            args.push("--gui".to_string());
        }
        args
    }

    /// Reverse-DNS-ish label used by launchd / as the systemd unit stem.
    fn label(&self) -> String {
        format!("dev.daemonseed.{}", self.profile_name)
    }
}

/// Render the autostart unit **text** for `target`. Pure: no I/O, no process
/// spawning, deterministic for a given spec.
pub fn unit_descriptor(spec: &AutostartSpec, target: AutostartTarget) -> String {
    match target {
        AutostartTarget::SystemdUser => systemd_user_unit(spec),
        AutostartTarget::Launchd => launchd_plist(spec),
        AutostartTarget::WindowsStartup => windows_startup_command(spec),
    }
}

fn systemd_user_unit(spec: &AutostartSpec) -> String {
    let exec_args = spec.args().join(" ");
    format!(
        "[Unit]\n\
         Description=daemonseed ({profile})\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec} {args}\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        profile = spec.profile_name,
        exec = spec.exec_path,
        args = exec_args,
    )
}

fn launchd_plist(spec: &AutostartSpec) -> String {
    let mut program_args = String::new();
    program_args.push_str(&format!("    <string>{}</string>\n", spec.exec_path));
    for arg in spec.args() {
        program_args.push_str(&format!("    <string>{arg}</string>\n"));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20 <key>Label</key>\n\
         \x20 <string>{label}</string>\n\
         \x20 <key>ProgramArguments</key>\n\
         \x20 <array>\n\
         {program_args}\
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key>\n\
         \x20 <true/>\n\
         </dict>\n\
         </plist>\n",
        label = spec.label(),
        program_args = program_args,
    )
}

fn windows_startup_command(spec: &AutostartSpec) -> String {
    // A Startup-folder .cmd line; the real installer would also offer the
    // HKCU\...\Run registry form. Quoted so paths with spaces survive.
    format!(
        "@echo off\r\nstart \"\" \"{exec}\" {args}\r\n",
        exec = spec.exec_path,
        args = spec.args().join(" "),
    )
}

/// Failure modes an autostart backend can surface when it actually installs.
#[derive(Debug)]
pub enum AutostartError {
    /// The target mechanism is unavailable on this platform.
    Unsupported,
    /// The platform backend returned an error.
    Backend(String),
}

impl core::fmt::Display for AutostartError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AutostartError::Unsupported => {
                write!(f, "autostart mechanism unsupported on this platform")
            }
            AutostartError::Backend(e) => write!(f, "autostart backend error: {e}"),
        }
    }
}

impl std::error::Error for AutostartError {}

/// Installs / removes an autostart unit on the host. Implemented by the
/// platform-holding client, NOT by this crate — generating the descriptor
/// ([`unit_descriptor`]) is in scope; touching the OS is reserved.
pub trait AutostartManager {
    /// Install and enable autostart for `spec` via `target`.
    fn enable(&self, spec: &AutostartSpec, target: AutostartTarget) -> Result<(), AutostartError>;
    /// Disable and remove the autostart unit.
    fn disable(&self, target: AutostartTarget) -> Result<(), AutostartError>;
    /// Whether autostart is currently enabled for `target`.
    fn is_enabled(&self, target: AutostartTarget) -> Result<bool, AutostartError>;
}

/// Mandatory warning surfaced before a user opts into autostart (ISC-C20).
/// Enabling autostart pins the daemon's primary identity to "online whenever
/// the machine is on" — an observable presence side-channel. Multi-instance
/// support (Reservation) will later let a user autostart an *unlinked* instance
/// to decouple presence from their primary identity.
pub const PRESENCE_SIDE_CHANNEL_WARNING: &str = "\
Autostart launches daemonseed every time this machine starts. That makes your \
presence observable: your primary identity will appear online whenever the \
machine is on, a pattern a network observer or relay can correlate. Autostart \
runs headless by default; enabling a GUI surface is a separate explicit choice. \
Until multi-instance support lands, prefer autostarting only an identity whose \
online presence you are comfortable revealing.";

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(mode: AutostartMode) -> AutostartSpec {
        AutostartSpec {
            profile_name: "alice".into(),
            exec_path: "/usr/bin/daemonseed".into(),
            config_dir: "/home/alice/.config/daemonseed".into(),
            mode,
        }
    }

    #[test]
    fn systemd_descriptor_is_a_well_formed_user_unit() {
        let unit = unit_descriptor(&spec(AutostartMode::Headless), AutostartTarget::SystemdUser);
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("ExecStart=/usr/bin/daemonseed"));
        // systemd *user* units install into the per-user default target.
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn launchd_descriptor_is_a_well_formed_plist() {
        let plist = unit_descriptor(&spec(AutostartMode::Headless), AutostartTarget::Launchd);
        assert!(plist.contains("<?xml"));
        assert!(plist.contains("<!DOCTYPE plist"));
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("/usr/bin/daemonseed"));
    }

    #[test]
    fn windows_startup_descriptor_invokes_the_binary_with_the_profile_config() {
        let cmd = unit_descriptor(
            &spec(AutostartMode::Headless),
            AutostartTarget::WindowsStartup,
        );
        assert!(cmd.to_lowercase().contains("daemonseed"));
        assert!(cmd.contains("--config"));
        assert!(cmd.contains("/home/alice/.config/daemonseed"));
    }

    #[test]
    fn headless_is_the_default_and_carries_no_gui_flag() {
        for target in [
            AutostartTarget::SystemdUser,
            AutostartTarget::Launchd,
            AutostartTarget::WindowsStartup,
        ] {
            let d = unit_descriptor(&spec(AutostartMode::Headless), target);
            assert!(
                !d.contains("--gui"),
                "headless descriptor must not request a GUI surface"
            );
        }
    }

    #[test]
    fn gui_mode_is_opt_in_and_explicit() {
        let d = unit_descriptor(&spec(AutostartMode::Gui), AutostartTarget::SystemdUser);
        assert!(
            d.contains("--gui"),
            "GUI autostart must be explicit per ISC-C20"
        );
    }

    #[test]
    fn every_descriptor_threads_the_profile_config_dir() {
        // Multi-instance (ISC-C35): autostart must pin the specific profile.
        for target in [
            AutostartTarget::SystemdUser,
            AutostartTarget::Launchd,
            AutostartTarget::WindowsStartup,
        ] {
            let d = unit_descriptor(&spec(AutostartMode::Headless), target);
            assert!(d.contains("/home/alice/.config/daemonseed"));
        }
    }

    #[test]
    fn generator_is_pure_and_deterministic() {
        // Same spec → byte-identical output, no side effects: the generator
        // only formats text, it never touches the filesystem or a process.
        let a = unit_descriptor(&spec(AutostartMode::Headless), AutostartTarget::SystemdUser);
        let b = unit_descriptor(&spec(AutostartMode::Headless), AutostartTarget::SystemdUser);
        assert_eq!(a, b);
    }

    #[test]
    fn presence_side_channel_warning_names_the_tradeoff() {
        assert!(!PRESENCE_SIDE_CHANNEL_WARNING.is_empty());
        let w = PRESENCE_SIDE_CHANNEL_WARNING.to_ascii_lowercase();
        assert!(w.contains("presence") || w.contains("online"));
    }

    #[test]
    fn manager_trait_is_object_safe() {
        fn _assert(_: &dyn AutostartManager) {}
    }
}
