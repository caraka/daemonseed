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
use daemonseed_server::kats::CNSA_2_0_KATS;
use daemonseed_server::tls::install_provider;
use daemonseed_tui::app::App;
use daemonseed_tui::net::{NetCommand, NetHandle};
use daemonseed_tui::ui;
use oxicrypt_module::{AlgorithmProfile, initialize_with_profile};
use ratatui::crossterm::event::{self, Event};

/// Event-loop poll interval. Bounds redraw latency for time-driven UI (toasts,
/// indexer-progress ticks) without busy-spinning.
const TICK: Duration = Duration::from_millis(100);

fn main() -> io::Result<()> {
    // Bring up the same process-wide CryptoProvider the cli/server use, before
    // touching the terminal — a failure here should print plainly, not corrupt
    // a raw-mode screen. First-start sealing needs the module Operational;
    // connect (later workstream) needs the rustls provider installed.
    if let Err(e) = initialize_with_profile(CNSA_2_0_KATS, AlgorithmProfile::Cnsa2) {
        eprintln!("daemonseed-tui: crypto module init failed: {e}");
        return Err(io::Error::other(e.to_string()));
    }
    if let Err(e) = install_provider() {
        eprintln!("daemonseed-tui: TLS provider install failed: {e}");
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
    let net = match NetHandle::new() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("daemonseed-tui: network runtime build failed: {e}");
            return Err(e);
        }
    };

    // Where fetched shares land as named files (M15 C, downloads cleanup):
    // `--portable` keeps everything self-contained under the CWD profile root;
    // otherwise downloads go to the OS Downloads directory, namespaced under a
    // `daemonseed/` subfolder so the per-share folders + manifest stay tidy.
    let downloads_root = if portable {
        profile_root.join("downloads")
    } else {
        os_downloads_dir().join("daemonseed")
    };

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, net, profile_root, downloads_root, existing);
    ratatui::restore();
    result
}

/// The OS default Downloads directory. Honors `XDG_DOWNLOAD_DIR` when set,
/// otherwise `$HOME/Downloads`, otherwise the CWD as a last resort. (A richer
/// per-platform resolver is ShareUX/M16 scope; this is the "call it done for
/// now" path for non-portable runs.)
fn os_downloads_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("XDG_DOWNLOAD_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(d);
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join("Downloads");
    }
    PathBuf::from("Downloads")
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
    mut net: NetHandle,
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
        terminal.draw(|frame| ui::render(&app, frame))?;

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
            let _ = net.send(NetCommand::Connect {
                server_id: req.server_id,
                address: req.address,
                trusted: req.trusted,
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
            });
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
