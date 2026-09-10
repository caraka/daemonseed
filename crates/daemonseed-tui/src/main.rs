//! daemonseed-tui binary — terminal lifecycle + event loop.
//!
//! This is the thin terminal driver around the testable state machine in
//! [`daemonseed_tui::app`]. It owns raw-mode / alternate-screen setup and
//! teardown and the blocking event loop; all interactive logic lives in the
//! library so it can be unit-tested and PTY-driven without a terminal.

#![forbid(unsafe_code)]

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use daemonseed_core::profile::resolve::resolve;
use daemonseed_core::profile::{
    ResolveArgs, ResolvedProfileRoot, load_for_unlock, session_materials_from_unlock,
    write_first_start, write_seeds_blob,
};
use daemonseed_core::storage::seeds;
use daemonseed_tui::app::App;
use daemonseed_tui::net::{NetCommand, NetHandle, RootKind};
use daemonseed_tui::ui;
use ratatui::crossterm::event::{self, Event};

/// Event-loop poll interval. Bounds redraw latency for time-driven UI (toasts,
/// indexer-progress ticks) without busy-spinning.
const TICK: Duration = Duration::from_millis(100);

/// How long the graceful close (#161) waits before announcing itself. A close with no
/// network work to do finishes inside this and exits without a word; anything slower is
/// a real DHT write the user is better off seeing than guessing at. Two render ticks —
/// long enough to cover a no-op close, short enough not to feel like a pause.
const QUIET_CLOSE_WINDOW: Duration = Duration::from_millis(200);

fn main() -> io::Result<()> {
    // Bring the oxicrypt module Operational before touching the terminal — a
    // failure here should print plainly, not corrupt a raw-mode screen.
    // First-start sealing needs the module Operational.
    if let Err(e) = daemonseed_core::kats::initialize_module() {
        eprintln!("daemonseed-tui: crypto module init failed: {e}");
        return Err(io::Error::other(e.to_string()));
    }

    // Resolve the profile root (ISC-C35) before raw mode so any config error
    // prints plainly. `--config <path>` points at an explicit profile;
    // `--portable` forces the CWD as the profile root (ISC-C52).
    let config_flag = parse_config_flag();
    let portable = parse_portable_flag();
    let (profile_root, existing) = match resolve(ResolveArgs {
        config_flag,
        portable,
    }) {
        Ok(ResolvedProfileRoot::Existing { root, .. }) => {
            // An existing config means an existing profile; if the blob is also
            // present this is a daily login (ISC-C3 / Item E), not enrollment.
            let has_blob = daemonseed_core::profile::blob_exists(&root);
            (root, has_blob)
        }
        Ok(ResolvedProfileRoot::FirstStart { default_root }) => (default_root, false),
        Err(e) => {
            eprintln!("daemonseed-tui: profile resolution failed: {e}");
            return Err(io::Error::other(e.to_string()));
        }
    };

    // The network actor (tokio runtime + connect driver) is built before raw
    // mode so a runtime-build failure prints plainly.
    let mut net = match NetHandle::new() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("daemonseed-tui: network runtime build failed: {e}");
            return Err(e);
        }
    };

    // Where fetched shares land as named files (downloads cleanup):
    // `--portable` keeps everything self-contained under the CWD profile root;
    // otherwise downloads go to the OS Downloads directory, namespaced under a
    // `daemonseed/` subfolder so the per-share folders + manifest stay tidy.
    let downloads_root = if portable {
        profile_root.join("downloads")
    } else {
        os_downloads_dir().join("daemonseed")
    };

    let mut terminal = ratatui::init();
    let result = run(
        &mut terminal,
        &mut net,
        profile_root,
        downloads_root,
        existing,
    );
    ratatui::restore();
    // Graceful close AFTER the terminal is restored (#161): the wait can run to the
    // full close budget, and a frozen alternate-screen frame for that long reads as a
    // hang. On a plain terminal a slow close can say so and be watched finish.
    graceful_close(&net);
    result
}

/// Publish the LEAVE tombstone + flush pending writes before the process exits (#161),
/// bounded by `GRACEFUL_CLOSE_BUDGET`. Without it a departed member lingers on peers'
/// rosters for the full `PRESENCE_TTL`, making a graceful quit indistinguishable from
/// a crash.
///
/// Bounded on BOTH sides: the actor stops its own work at the budget, and this
/// `recv_timeout` is the backstop for an actor that never acks at all (a wedged or
/// already-dead net thread). A session that never connected acks immediately, so
/// quitting from the unlock screen stays instant.
fn graceful_close(net: &NetHandle) {
    let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel(1);
    if net.send(NetCommand::GracefulClose { ack: ack_tx }).is_err() {
        return; // the net thread is already gone — nothing to flush
    }
    let budget = daemonseed_veilid_net::GRACEFUL_CLOSE_BUDGET;
    // A session with nothing to publish (never connected, no lobby) acks well inside
    // this, so quitting from the unlock screen stays silent and instant. Announce only
    // once it is clear there is real network work to wait on — otherwise the notice
    // would claim a departure that never happened.
    if ack_rx.recv_timeout(QUIET_CLOSE_WINDOW).is_ok() {
        return;
    }
    // Deliberately says what is being waited on, not what is being published: the actor
    // may be finishing an earlier command rather than the leave, so "leaving the lobby"
    // would not always be true.
    eprintln!("daemonseed-tui: closing network session…");
    let _ = ack_rx.recv_timeout(budget.saturating_sub(QUIET_CLOSE_WINDOW));
}

/// The OS default Downloads directory (ISC-C68 / A3). Resolved per-platform via
/// `dirs::download_dir()` (honors the XDG user-dirs config on Linux, the known
/// folder on Windows, `~/Downloads` on macOS), falling back to `$HOME/Downloads`
/// when the platform reports none, and the CWD as a last resort.
fn os_downloads_dir() -> PathBuf {
    if let Some(d) = dirs::download_dir() {
        return d;
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join("Downloads");
    }
    PathBuf::from("Downloads")
}

/// Expand a leading `~` / `~/` in a user-typed destination path to `$HOME`
/// (ISC-C68). The dest box is a plain text field, not a shell, so without this
/// a typed `~/Downloads` would create a literal directory named `~`. Only a
/// leading bare `~` or `~/` is expanded — a `~user` form or a mid-path `~` is
/// left verbatim. With no `$HOME`, the path is returned unchanged.
fn expand_tilde(dest: &str) -> PathBuf {
    let home = std::env::var_os("HOME").filter(|v| !v.is_empty());
    match home {
        Some(home) if dest == "~" => PathBuf::from(home),
        Some(home) if dest.starts_with("~/") => PathBuf::from(home).join(&dest[2..]),
        _ => PathBuf::from(dest),
    }
}

/// Minimal `--config <path>` parser (ISC-C35). A full arg parser arrives with
/// the wider CLI surface.
fn parse_config_flag() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--config" {
            return args.next().map(PathBuf::from);
        }
        if let Some(rest) = a.strip_prefix("--config=") {
            return Some(PathBuf::from(rest));
        }
    }
    None
}

/// `--portable` flag (ISC-C52): force the CWD as the profile root so a fresh
/// first-start writes its config/blob/`.dseed` into the current directory
/// instead of the system (XDG) location. Once-only — afterwards plain CWD
/// discovery picks the directory up with no flag.
fn parse_portable_flag() -> bool {
    std::env::args().skip(1).any(|a| a == "--portable")
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    net: &mut NetHandle,
    profile_root: PathBuf,
    downloads_root: PathBuf,
    existing_profile: bool,
) -> io::Result<()> {
    // An existing profile blob → daily-login Unlock (Item E). Otherwise the
    // Welcome → first-start enrollment path.
    let mut app = if existing_profile {
        App::for_existing_profile()
    } else {
        App::new()
    };
    while !app.should_quit() {
        // (#235 / #279) The frame reports which direct-message rows it painted,
        // and the surfacing answers for those and nothing else. After the draw
        // and not before: the driver's flag is durable precisely so a crash
        // between the two re-offers the state. A frame an overlay covered
        // reports nothing, which `ui::render` decides, because that is where the
        // overlays are drawn.
        let mut report = ui::RenderReport::default();
        terminal.draw(|frame| report = ui::render(&app, frame))?;
        app.dm_thread_drawn(&report.painted_dm_seqs);

        // Drain network events into UI state (non-blocking).
        for event in net.drain_events() {
            app.on_net_event(event);
        }

        if event::poll(TICK)?
            && let Event::Key(key) = event::read()?
        {
            app.on_key(key);
        }

        // Hand any queued commands to the network actor.
        if let Some(req) = app.take_pending_connect() {
            // (#92) Derive the stable identity signing key ONCE here and hand it to
            // the net actor so it can gate the public-space composer + sign
            // MOTD/announcements under the persistent identity (None on the
            // ephemeral / no-profile path). Wrapped for the Clone+Debug command enum.
            let stable_signing_key = app
                .stable_signing_key()
                .map(|k| daemonseed_tui::net::StableSigningKey(std::sync::Arc::new(k)));
            // (#156) Derive the share-root IKM once here too (same derivation) so
            // the veilid actor derives a receiver-verifiable share_id on publish.
            let stable_share_root_ikm = app.stable_share_root_ikm();
            // (#232) Derive the stable KEM encapsulation key so the actor can publish
            // the DM key record that makes this identity reachable for direct
            // messages. Public half only; wrapped for the Clone+Debug command enum.
            let stable_kem_encapsulation_key = app
                .stable_kem_encapsulation_key()
                .map(|k| daemonseed_tui::net::StableKemEncapsulationKey(std::sync::Arc::new(k)));
            // (#339) Derive the DM driver's own halves — the FULL KEM keypair,
            // the doorbell slot secret and the profile at-rest key — for the
            // driver the actor spawns beside itself. `None` before Unlock or on
            // the ephemeral path, where no driver is spawned.
            let dm_session_keys = app.dm_session_keys();
            let _ = net.send(NetCommand::Connect {
                server_id: req.server_id,
                address: req.address,
                trusted: req.trusted,
                stable_signing_key,
                stable_share_root_ikm,
                stable_kem_encapsulation_key,
                dm_session_keys,
                // (step 8b-2 / DL-ISC-20) Hand the profile root to the actor so a
                // verified resume anchors each fetch's manifest digest in the
                // client's own trusted state (not the co-resident downloads root).
                // The TUI always runs under an unlocked profile root, so this is
                // always available; the field stays `Option` for parity with the GUI.
                profile_root: Some(profile_root.clone()),
                // (presence fix) Hand our own `name#hash` to the actor at connect so
                // the lobby presence beacon carries the real name immediately — a
                // publish-only/lurking session never sends a chat (the old learn
                // point) and would otherwise broadcast "guest".
                self_handle: app.own_handle(),
            });
        }
        if let Some(phrase) = app.take_pending_join() {
            let _ = net.send(NetCommand::JoinCircle { phrase });
        }
        if let Some(chat) = app.take_pending_chat() {
            let _ = net.send(NetCommand::SendChat {
                circle_id: chat.circle_id,
                body: chat.body,
                sender_handle: chat.sender_handle,
            });
        }
        if let Some((body, sender_handle)) = app.take_pending_public_room() {
            let _ = net.send(NetCommand::SendPublicRoom {
                body,
                sender_handle,
            });
        }
        // M14: a Define-Share request → derive the index file path + key from
        // the active session (the App layer holds no key material) and activate
        // the indexer. The index lives under the profile root.
        if let Some(req) = app.take_pending_share_define()
            && let Some(session) = app.session()
        {
            let _ = net.send(NetCommand::DefineShare {
                root: req.root,
                label: req.label,
                index_path: profile_root.join("share-index.redb"),
                index_key: session.index_key.clone(),
            });
        }
        if app.take_pending_share_refresh() {
            let _ = net.send(NetCommand::RefreshShares);
        }
        if app.take_pending_public_space_refresh() {
            let _ = net.send(NetCommand::RefreshPublicSpace);
        }
        // (#92) signer composer uploads — the net actor signs with the held stable
        // key and uploads via UploadMotd / UploadPost, then refreshes.
        if let Some(text) = app.take_pending_set_motd() {
            let _ = net.send(NetCommand::SetMotd { text });
        }
        if let Some((topic, body)) = app.take_pending_upload_announcement() {
            let _ = net.send(NetCommand::UploadAnnouncement { topic, body });
        }
        // (#236) Answers to contact requests, forwarded verbatim to the DM
        // driver. Each is queued by one keypress in the direct-message pane.
        for cmd in app.take_pending_dm() {
            let _ = net.send(NetCommand::Dm(cmd));
        }
        if app.take_pending_deprecation_refresh() {
            let _ = net.send(NetCommand::RefreshDeprecation);
        }
        if app.take_pending_introducer_refresh() {
            let _ = net.send(NetCommand::RefreshIntroducer);
        }
        if let Some((share_id, sharer_handle, name)) = app.take_pending_share_fetch() {
            let _ = net.send(NetCommand::FetchShare {
                share_id,
                sharer_handle,
                name,
                fetched_root: downloads_root.clone(),
            });
        }
        // A1: the user accepted the manifest preview → download it. A3: an empty
        // `dest` means "use the default downloads dir"; a non-empty `dest` is the
        // user-chosen destination from the preview overlay (ISC-C68).
        if let Some((share_id, sharer_handle, name, selected, dest)) =
            app.take_pending_fetch_confirm()
        {
            let flat_dest = !dest.is_empty();
            let fetched_root = if dest.is_empty() {
                downloads_root.clone()
            } else {
                expand_tilde(&dest)
            };
            // (download-subsystem redesign, step 6 / DL-ISC-8) The TUI preview is a
            // flat manifest-row list (no folder tree), so the selection root is a
            // function of the confirmed selection: `None` = the whole share, one
            // checked row = a single file, several = a scattered folder selection
            // placed under their common parent-dir prefix. Only consulted net-side
            // for a user-chosen dest (`flat_dest`); the managed dir keeps the full
            // `<share>/<rel_path>` layout regardless.
            let root_kind = match &selected {
                None => RootKind::Share,
                Some(idxs) if idxs.len() == 1 => RootKind::File,
                Some(_) => RootKind::Dir,
            };
            let _ = net.send(NetCommand::ConfirmFetch {
                share_id,
                sharer_handle,
                name,
                fetched_root,
                selected,
                flat_dest,
                root_kind,
            });
        }
        // M15 C: browse — refresh the fetched-downloads list on demand.
        if app.take_pending_fetched_refresh() {
            let _ = net.send(NetCommand::ListFetched {
                fetched_root: downloads_root.clone(),
            });
        }
        // D, M15: a Publish request → publish the listing + serve the directory's
        // content for the life of the session. The actor checks for a live session
        // and emits PublishError if absent, so forward unconditionally.
        if let Some(req) = app.take_pending_publish() {
            let _ = net.send(NetCommand::PublishShare {
                root: req.root,
                name: req.name,
                sharer_handle: req.sharer_handle,
            });
        }
        // Publish-intent persistence: auto-republish each remembered-published
        // root restored on Unlock, once connected+authed (the drain is gated, so
        // these stay queued until then). Drain all ready this tick — each is a
        // distinct root, so no duplicate publish.
        while let Some(req) = app.take_pending_autopublish() {
            let _ = net.send(NetCommand::PublishShare {
                root: req.root,
                name: req.name,
                sharer_handle: req.sharer_handle,
            });
        }
        // M16 serve-from-disk: `[u]` mid-hash cancels the in-flight publish
        // hash for that defined root (a no-op on the actor if it already
        // finished — the race is benign).
        if let Some(root) = app.take_pending_cancel_publish() {
            let _ = net.send(NetCommand::CancelPublish { root });
        }
        if let Some(share_id) = app.take_pending_unpublish() {
            let _ = net.send(NetCommand::UnpublishShare { share_id });
        }

        // Item D / ISC-C49/C50: persist the at-rest blob + `.dseed` to the
        // profile root once first-start completes. The no-clobber guard
        // (ISC-A-C28) is satisfied structurally: an existing-profile launch
        // routes to Unlock, so first-start only runs against a root with no
        // blob. `allow_clobber = false` keeps the guard honest.
        if app.take_pending_persist()
            && let Some(materials) = app.session()
        {
            match write_first_start(&profile_root, materials, None, false) {
                Ok(_) => {}
                Err(e) => app.set_status(format!("could not save identity: {e}")),
            }
        }

        // M13 write-through: the running client re-sealed its at-rest payload
        // (display name / mute / hide / circles) under the cached SealingKey and
        // queued the refreshed blob bytes. Overwrite `seeds.blob` only — the
        // `.dseed` and config never change on a settings mutation. Distinct from
        // the first-start persist above (which writes config + blob + `.dseed`).
        if let Some(bytes) = app.take_pending_blob_update()
            && let Err(e) = write_seeds_blob(&profile_root, &bytes)
        {
            app.set_status(format!("could not save: {e}"));
        }

        // Item E / ISC-C3: service a queued Unlock attempt — load the on-disk
        // blob, decrypt with the typed passphrase, reconstruct SessionMaterials.
        if let Some(passphrase) = app.take_pending_unlock() {
            match load_for_unlock(&profile_root) {
                Ok((config, blob)) => {
                    match seeds::open(&blob, &passphrase, config.profile_id, config.argon2) {
                        Ok(opened) => match session_materials_from_unlock(
                            opened.seeds,
                            opened.key,
                            opened.index_key,
                            config,
                            blob,
                            Vec::new(),
                        ) {
                            Ok(session) => app.on_unlock_success(session),
                            Err(e) => app.on_unlock_failure(format!("unlock failed: {e}")),
                        },
                        Err(seeds::BlobError::AuthenticationFailed) => {
                            app.on_unlock_failure("wrong passphrase")
                        }
                        Err(e) => app.on_unlock_failure(format!("unlock failed: {e}")),
                    }
                }
                Err(e) => app.on_unlock_failure(format!("could not read profile: {e}")),
            }
        }
    }
    Ok(())
}
