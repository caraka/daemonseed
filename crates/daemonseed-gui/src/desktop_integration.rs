//! First-run desktop integration — universal / freedesktop-XDG.
//!
//! AppImages are deliberately *not installed*, so no app-menu/dock icon appears until
//! something registers a `.desktop` entry + icon into the user's XDG data dir. Rather
//! than require an external integrator (Gear Lever / AppImageLauncher / appimaged), the
//! app offers to self-register on first run. Everything here is standards-based so it
//! works across desktop environments (GNOME, KDE Plasma, XFCE, Cinnamon, …):
//!
//!   - `.desktop` → `$XDG_DATA_HOME/applications/`        (Desktop Entry Spec)
//!   - icons      → `$XDG_DATA_HOME/icons/hicolor/{256x256,scalable}/apps/` (Icon Theme Spec)
//!   - `StartupWMClass` ties the running window (WM_CLASS == [`APP_ID`]) to the entry, so
//!     the live window inherits the icon on the dock/taskbar — the part GNOME needs.
//!   - cache refresh (`update-desktop-database`, `gtk-update-icon-cache`) is best-effort:
//!     absent tools are ignored, and most DEs read the files directly anyway.
//!
//! It only ever prompts when launched FROM an AppImage (`$APPIMAGE` is set), never
//! installs silently, and honours a persisted "don't ask again" marker — keeping the
//! portable, install-free promise intact. `install()` / `remove()` also back the
//! `--install` / `--remove` CLI flags for scripted / headless use.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The single shared identifier: the window `WM_CLASS`, the `.desktop` basename, AND
/// the `Icon=` name must all be this value, or the DE can't map the window to the icon.
const APP_ID: &str = "daemonseed-gui";
const DISPLAY_NAME: &str = "Daemonseed";
const DECLINE_MARKER: &str = "desktop-integration-declined";

/// Absolute path of the running AppImage, or `None` when not launched from one
/// (e.g. `cargo run`, or an extracted binary) — in which case there is nothing to
/// register and we never prompt.
fn appimage_path() -> Option<PathBuf> {
    std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// The mounted AppDir (set by the AppImage runtime) — the source of the bundled icons.
fn appdir() -> Option<PathBuf> {
    std::env::var_os("APPDIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

fn desktop_file_path() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("applications").join(format!("{APP_ID}.desktop")))
}

fn decline_marker_path() -> Option<PathBuf> {
    dirs::config_dir().map(|c| c.join(APP_ID).join(DECLINE_MARKER))
}

/// True only when ALL hold: launched from an AppImage, not already integrated, and the
/// user has not chosen "don't ask again". Only consulted by the windowed (`desktop`)
/// startup path; the offscreen/base build never calls it.
#[cfg_attr(not(feature = "desktop"), allow(dead_code))]
pub fn should_prompt() -> bool {
    appimage_path().is_some() && !is_installed() && !declined()
}

/// Whether the `.desktop` entry already exists in the XDG data dir.
pub fn is_installed() -> bool {
    desktop_file_path().map(|p| p.exists()).unwrap_or(false)
}

fn declined() -> bool {
    decline_marker_path().map(|p| p.exists()).unwrap_or(false)
}

/// Build the `.desktop` body for a given `Exec` target. Pure → unit-testable; the
/// invariant that `Icon` and `StartupWMClass` both equal [`APP_ID`] is what makes the
/// running window inherit the icon, so it is asserted in tests.
fn desktop_entry(exec: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={DISPLAY_NAME}\n\
         GenericName=Encrypted communication & file sharing\n\
         Comment=Federated, end-to-end-encrypted communication and file sharing\n\
         Exec={exec} %U\n\
         Icon={APP_ID}\n\
         StartupWMClass={APP_ID}\n\
         Categories=Network;FileTransfer;\n\
         Terminal=false\n"
    )
}

/// Register the app: write the `.desktop` + icons into the XDG data dir and refresh
/// caches. Returns a human-readable message on success.
pub fn install() -> Result<String, String> {
    let exec = appimage_path()
        .ok_or("not running from an AppImage (no $APPIMAGE)")?
        .to_string_lossy()
        .into_owned();
    let data = dirs::data_dir().ok_or("could not resolve the XDG data directory")?;

    // 1) the .desktop entry
    let apps = data.join("applications");
    fs::create_dir_all(&apps).map_err(|e| format!("create {}: {e}", apps.display()))?;
    let desktop = apps.join(format!("{APP_ID}.desktop"));
    fs::write(&desktop, desktop_entry(&exec)).map_err(|e| format!("write desktop entry: {e}"))?;
    set_exec_bit(&desktop); // conventional for launchers; some DEs warn without it

    // 2) icons, copied straight out of the mounted AppDir (best-effort per file; the
    //    256px PNG is the load-bearing one, the SVG is a bonus for scalable themes).
    if let Some(dir) = appdir() {
        copy_icon(
            &dir.join("usr/share/icons/hicolor/256x256/apps")
                .join(format!("{APP_ID}.png")),
            &data.join("icons/hicolor/256x256/apps"),
            &format!("{APP_ID}.png"),
        );
        copy_icon(
            &dir.join("usr/share/icons/hicolor/scalable/apps")
                .join(format!("{APP_ID}.svg")),
            &data.join("icons/hicolor/scalable/apps"),
            &format!("{APP_ID}.svg"),
        );
    }

    // 3) refresh caches — best-effort: missing tools / non-GTK DEs are fine.
    refresh_caches(&apps, &data.join("icons/hicolor"));

    Ok(format!("Added {DISPLAY_NAME} to your applications."))
}

/// The inverse of [`install`]: remove the entry + icons. Backs `--remove`.
pub fn remove() -> Result<String, String> {
    let data = dirs::data_dir().ok_or("could not resolve the XDG data directory")?;
    let apps = data.join("applications");
    let _ = fs::remove_file(apps.join(format!("{APP_ID}.desktop")));
    let _ = fs::remove_file(
        data.join("icons/hicolor/256x256/apps")
            .join(format!("{APP_ID}.png")),
    );
    let _ = fs::remove_file(
        data.join("icons/hicolor/scalable/apps")
            .join(format!("{APP_ID}.svg")),
    );
    refresh_caches(&apps, &data.join("icons/hicolor"));
    Ok(format!("Removed {DISPLAY_NAME} from your applications."))
}

/// Persist the user's "don't ask again" choice so [`should_prompt`] stays false.
pub fn mark_declined() {
    if let Some(p) = decline_marker_path() {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&p, b"");
    }
}

fn copy_icon(src: &Path, dst_dir: &Path, name: &str) {
    if src.exists() && fs::create_dir_all(dst_dir).is_ok() {
        let _ = fs::copy(src, dst_dir.join(name));
    }
}

fn refresh_caches(apps: &Path, hicolor: &Path) {
    // No shell: explicit argv, errors swallowed (these are convenience caches).
    let _ = Command::new("update-desktop-database").arg(apps).status();
    let _ = Command::new("gtk-update-icon-cache")
        .arg("-f")
        .arg("-t")
        .arg(hicolor)
        .status();
}

#[cfg(unix)]
fn set_exec_bit(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(p) {
        let mut perm = meta.permissions();
        perm.set_mode(0o755);
        let _ = fs::set_permissions(p, perm);
    }
}
#[cfg(not(unix))]
fn set_exec_bit(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entry_is_wellformed() {
        let e = desktop_entry("/opt/daemonseed/daemonseed-gui-x86_64.AppImage");
        assert!(e.starts_with("[Desktop Entry]\n"));
        assert!(e.contains("Type=Application\n"));
        assert!(e.contains("Name=Daemonseed\n"));
        assert!(e.contains("Exec=/opt/daemonseed/daemonseed-gui-x86_64.AppImage %U\n"));
        assert!(e.ends_with("Terminal=false\n"));
    }

    #[test]
    fn icon_and_wm_class_share_the_app_id() {
        // The whole fix hinges on these three being identical, or the DE cannot map the
        // running window (WM_CLASS) to the entry's Icon.
        let e = desktop_entry("/x");
        assert!(e.contains(&format!("Icon={APP_ID}\n")));
        assert!(e.contains(&format!("StartupWMClass={APP_ID}\n")));
        assert_eq!(APP_ID, "daemonseed-gui");
    }
}
