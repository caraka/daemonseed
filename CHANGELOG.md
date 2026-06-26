# Changelog

All notable changes to daemonseed are recorded here, one entry per release.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) on
the wire protocol (the `0.x` crate versions are tag-driven; `Cargo.toml` stays
`0.1.0`).

**This file plus the SSH-signed git tags are the canonical record of milestone
history** — what shipped, when, under which tag. Each entry corresponds to one
signed tag (`git tag --verify vX.Y.Z`). Nothing else in the repository
duplicates this record: `ISA.md` is the frozen design contract (principles,
boundaries, criteria — not history), live ISC coverage comes from
`cargo xtask isc-coverage`, and in-progress / next-milestone planning lives in
the project lead's vault manifest, never committed here.

Milestone identifiers (`Mn`) are the internal planning labels; the release tag
is the durable anchor.

## [Unreleased]

Changes that have landed on `main` since the last tag accumulate here; at the
next release this block is renamed to its version + date and a fresh
`[Unreleased]` is opened (see `AGENTS.md` doc-sync). Planning for *unstarted*
work lives in the project lead's vault manifest, not here.

### Added

- server: `UploadMotd` RPC — in-band signer-set MOTD, single-slot replace, plaintext-enforced (#89)
- cli/public_space: client signer authoring (`sign_post`/`sign_motd`/`sign_post_delete`) + signer self-determination (`local_key_is_whitelisted`) (#90)
- gui: announcement + MOTD display panes — relay MOTD (verbatim) + announcements list, client-re-verified (#91)
- gui/tui: signer-gated MOTD/announcement composer — shown only when the local identity key is on the relay's published whitelist; signs + uploads via UploadMotd/UploadPost (#92)
- gui: unread-gated landing — auto-open the Announcements pane on connect when the relay's MOTD/announcements changed since last seen (per-relay client-derived hash), else the Lobby (#93)
- gui: per-circle connected-presence — sealed member heartbeats emitted into and tracked per joined circle (relay-blind), feeding the active room's roster (#77)
- gui: rename your identity from the Ctrl-K palette — validate, re-seal, and update the live handle without a reload; also recovers a nameless profile (#66)
- gui: circle-details sheet shows the three name vectors — chosen name, the relay-scoped adj-noun label, and the universal `#<12hex>` fingerprint (#36)
- gui: right-click context menu (Cut / Copy / Paste / Select all) on text fields (#67)
- gui: a custom share name set at publish now persists and is used on auto-republish (was basename-only) (#41)
- gui: the circle-details sheet is reachable — a per-circle "Details" header control opens it and "Close" dismisses it (#35)

## [0.31.1] — 2026-06-25

### Fixed

- GUI chat auto-scrolls to the newest message: a new message in the active room pins the transcript to the bottom when the reader is already at the bottom (always on your own send), and holds position when scrolled up reading history. (#84)
- GUI chat messages wrap and bubbles size to their content: a long or multi-line message wraps within a bubble capped at ~72% of the row instead of clipping to a fixed height. (#86)
- GUI chat column stays within the window: a long pasted draft or message no longer balloons the centre column off-screen (which dropped the roster and overflowed the composer). The centre column takes available width and the single-line composer scrolls its text within a fixed box. (#86)

### Changed

- GUI chat bubble colors reversed — other people's messages use the readable green bubble, your own messages use the dark bubble. (#85)

## [0.31.0] — 2026-06-24

### Added

- `daemonseed_core::heartbeat` — AES-256-GCM-sealed, ML-DSA-87-self-signed `MemberHeartbeat`, tier-split by key class (`seal_public_heartbeat` / `seal_circle_heartbeat` / `open_heartbeat`), distinct AAD `daemonseed/presence/heartbeat/v1`. (#74)
- `daemonseed_core::presence::PresenceTracker` — per-room member liveness keyed by sender pubkey, reaped after a multi-miss TTL; `next_heartbeat_interval` draws a jittered ~10–15s emit interval. (#74)
- TUI net actor emits a member heartbeat per subscribed room on the jittered timer and folds inbound beacons into a per-room presence tracker; roster surfacing deferred to #75/#77. (#74)
- `MemberHeartbeat` carries a provenance-bound `live_share_ids` digest; `ShareCatalog::reconcile_sharer` / `prune_sharer` fold it so share liveness rides the heartbeat. (#76)
- GUI net actor emits and ingests the lobby member heartbeat (mirroring the TUI), and the GUI surfaces the live Lobby roster: a persistent right-hand people column showing currently-present members by display name, with the `#12hex` fingerprint on hover and no decorators. (#75)

### Changed

- Share discovery liveness rides the heartbeat: the periodic reconcile-timer roll-call is retired — a full `ShareAnnouncement` fires only on change (publish/unpublish) plus the startup and manual-refresh roll-calls, while ongoing liveness and drop-detection ride the heartbeat digest. `PresenceTracker::reap` now returns the reaped members. (#76)
- Raise the shared application-channel `KEEPALIVE_TIMEOUT` 10s → 30s (GUI/TUI/CLI via `AppSession::open`) so a slow keepalive ack on a congested WAN no longer trips a spurious dead-connection; a genuine half-open is still detected within ~45s. (#80)

### Fixed

- GUI message send no longer breaks after a stream blip: a graceful per-stream end-of-stream on a live connection now re-subscribes just that stream and leaves the session intact, instead of tearing down the lobby + every circle + all serve tasks (the v0.30.0 regression that blocked all sends while the relay still showed connected). Only a re-subscribe that fails on a genuinely dead connection — or a flapping stream — tears down and reconnects. (#80)
- GUI no longer re-hashes published shares from scratch on every publish and connect-time auto-republish: each share gets its own persisted redb index file (`share-index-<12hex(root)>.redb` under the profile `IndexKey`) and indexes via `cached_or_hash`, so an unchanged share — including a large one at startup, and every share for a multi-share user — is cache-hits-only instead of a CPU-bound re-hash. A per-share file holds only one root's files, so one share's cache pass never evicts another's. (#81)

### Security

- Presence replay-freshness: the heartbeat ingest drops a beacon whose advisory timestamp is outside a freshness window (`presence::beacon_is_fresh`), so an untrusted relay replaying a captured beacon can pin a departed member present for at most the window rather than indefinitely. Bounds replay; the window value and a clock-free nonce alternative are open design points. (#78)

## [0.30.0] — 2026-06-23

### Added

- GUI auto-reconnect: after a dropped connection the network actor re-issues the connect on a capped exponential backoff (2s–30s), restoring the persisted display handle, circles, and shares like a fresh launch. (#71)
- h2 keepalive on the application channel (`http2_keep_alive_interval` + `keep_alive_timeout` + `keep_alive_while_idle`), so a half-open socket surfaces as an error within a bounded window. (#72)
- Circle-detail data path: a deterministic-label accessor derived from the net-contract rendezvous (adj-noun label, fingerprint fallback pre-join), a second compare vector alongside the `#<12hex>` fingerprint and independent of the chosen name. Detail-pane affordance deferred. (#36)
- `cargo xtask release-gate`: runs the full DoD gate (fmt, clippy workspace + gui/desktop, `test --workspace`, check-proto, isc-coverage) and exits non-zero on any red step, so a release tag cannot be cut on a red tree. (#62)
- Rename identity (core): `GuiState::rename_identity` sets a new display name and re-seals the at-rest blob (write-through) so it persists across unlock, and names a profile created nameless before #65; the cryptographic identity is unchanged. Command-palette UI and live-wire-handle update deferred. (#66)

### Fixed

- GUI no longer shows "connected" over a dead session: a dropped or half-open connection now surfaces `NetEvent::Disconnected` and the actor clears its stale session/circle/share state so no half-open session is reused. (#72)
- GUI opening the Public Shares tab while a circle is the active room follows the room to the Lobby, so the highlighted room matches the public context shown. (#70)
- GUI single-instance guard: a second client resolving the same profile root refuses to start (advisory PID lockfile on the resolved root, stale-lock reclaim) instead of opening the single-writer storage layer concurrently; `--portable` instances on different roots are unaffected. (#60)

### Changed

- Sync `Cargo.lock` to `oxicrypt` 0.17.0 (workspace crypto path-deps).

## [0.29.2] — 2026-06-22

Tester-facing GUI fixes plus a first-start display-name persistence fix.

### Added

- Windows build recipe (`packaging/windows/build-windows.sh`): cross-compiles a self-contained `daemonseed-gui.exe` for `x86_64-pc-windows-gnu` via cargo-zigbuild (zig static-links the mingw runtime; depends only on stock Windows 10+ DLLs).
- In-app release-version readout: a version line in the rail footer plus an About overlay (version, license, source) reachable from the command palette. (#59)
- Client-side unread dot on rail rooms: an unfocused room (circle or Lobby) shows a dot when a chat message arrives, cleared when the room gains focus. Chat-only. (#64)

### Changed

- Renamed the "Shares" tab (and its in-pane heading) to "Public Shares", distinct from "Circle shares".

### Fixed

- Command palette has a close (×) control, so it dismisses without selecting an item. (#58)
- Switching rooms while on a shares tab selects the tab matching the destination — a circle's "Circle shares", the Lobby's "Public Shares" — so public shares no longer appear available inside a circle.
- First-start re-seals the at-rest blob with the chosen display name, so a named identity keeps its name across unlock; previously the name was lost at next launch (peers saw the hash-only handle) unless a later write-through happened to re-seal. (#65)
- Right-clicking the Join phrase field pastes from the clipboard and refocuses; previously a right-click only moved focus off the field, leaving Ctrl-V as the sole paste path. (#63)

## [0.29.1] — GUI window-size default + build-version readout

Fresh-identity windows open at the intended landscape size, the running build
version is visible on the auth screens, and the ISC distribution drift-guard is
corrected to the unified-share-model registry counts.

### Added

- Build version shown on the GUI unlock and first-start screens. (#59)

### Fixed

- Fresh-identity GUI windows open at the landscape default size instead of square. (#54)
- ISC distribution drift-guard counts corrected to 97 positive / 55 negative /
  152 total, matching the unified-share-model registry additions (S30, A-S22, C77).

## [0.29.0] — Unified share model: relay-blind in-band share discovery

Shares move to fully relay-blind in-band discovery: sealed `ShareAnnouncement` /
`ShareRollCall` over the subscribe stream replace the relay share registry,
public-share content is sealed under the public room key, and the relay holds no
share directory. Plus first-start passphrase confirmation and GUI felt-fixes.

### Added

- `ShareAnnouncement` wire message + `daemonseed-core::share_announce` seal/open
  (sealed under the public room key or a circle `cot_key`, ML-DSA self-signed;
  relay-agnostic). (#50)
- `daemonseed-core::share_seal` content sealing: `seal_public_share_frame` /
  `seal_circle_share_frame` (tier-guarded) + `open_share_frame` (generic over
  `AeadKey256`). (#49)
- `ShareRollCall` wire message + `daemonseed-core::share_rollcall` seal/open. (#52)
- `daemonseed-core::share_catalog` — client-side share discovery catalog
  (`ShareCatalog` apply / prune / remove). (#52)
- `daemonseed-core::share_announce::mint_share_id` — client-side 128-bit
  `share_id` minting. (#52)
- Desktop GUI window/taskbar icon on `AppWindow`. (#40)
- First-start backup confirmation as three single-word type-back fields (C34).
- Reproducible AppImage build recipe (`packaging/appimage/`, output to `dist/`).
- Optional wire-facing name persisted per published share
  (`PublishedShare { root, name }`). (#41)
- "Restored N shares from last session" label on the connect-time auto-republish
  path. (#34)
- First-run desktop-integration prompt + `--install` / `--remove` flags that
  register an XDG `.desktop` entry and hicolor icons.
- Desktop GUI window-size persistence across restarts (size only).
- First-start passphrase confirm re-entry — a second masked field that must match
  before sealing a new identity.

### Changed

- Key-class separation: `CotKey` → `CircleKey` and a distinct `PublicRoomKey`,
  both `AeadKey256`; non-substitutable (sealing a circle payload under a public
  key is a compile error). No wire change. (#49)
- Public-share content sealed under the public room key on the serve/fetch path
  (per-chunk SHA-384 integrity and the relay unchanged). (#52)
- TUI share publish / unpublish / refresh now run in-band — sealed
  `ShareAnnouncement` + `ShareRollCall` over the lobby, with a `ShareCatalog` and
  a reconcile timer — instead of the relay registry RPCs. (#52)
- GUI share publish / unpublish / refresh now run in-band — sealed
  `ShareAnnouncement` + `ShareRollCall` over the lobby, with a `ShareCatalog` and
  a reconcile timer — instead of the relay registry RPCs. (#53)
- Track oxicrypt 0.16.0 in the lockfile.
- Auto-republish on connect consumes the persisted per-share name
  (`PublishedShare.name`), falling back to the root basename. (#41)
- GUI trust copy: "sealed" → "encrypted".
- "Restored N shares…" shows as a tab-independent auto-dismissing banner on the
  Chat landing view. (#34)
- Desktop GUI window title is "Daemonseed".
- AppImage recipe emits a 256px PNG + top-level `.DirIcon`.
- The Shares-tab "Publish" button reads "Manage shares".
- The download-complete banner auto-dismisses after a 30s read. (#55)

### Fixed

- Circle rail/header no longer shows a stale "not yet connected" placeholder.
- Keyboard focus restored when the desktop window regains activation. (#39)
- The desktop GUI window size is remembered in the resolved profile root, so a
  `--portable` / `--config` instance keeps its own size instead of the shared XDG
  one.
- A long phrase/name in the circle-join and Publish-name fields is clipped to its
  box instead of overrunning to the window edge (the same `clip` fix the auth
  inputs already carry).
- A publisher's own shares now appear in their own Shares list, not only on other
  clients — own shares are merged into the snapshot since the relay never echoes
  an announcement back to its sender. (#53)
- The download folder picker defaults to the OS Downloads folder instead of `$HOME`.
- The chat composer regains focus when the circle-join dialog is closed (Esc or
  Close).
- The folder picker no longer hangs on a repeated publish — the pickers run on the
  app's long-lived runtime instead of a fresh per-pick one. (#33)

### Removed

- The relay share registry: the `PublishShare` / `UnpublishShare` /
  `ListPublicShares` PublicSpace RPCs, the `PublicShareListing` message, and the
  server-side `SharePublishRegistry`. (#51)
- The CLI's registry-backed `publish` / `unpublish` / `list-shares` subcommands. (#51)

## [0.28.0] — GUI auth-input felt-fixes + global font pass (round 2)

Post-`v0.27.0` round-2 polish of the first-start / unlock auth surface, felt-tested
on Ubuntu noble via an AppImage build.

- **Visible password mask + complete glyph coverage:** the software renderer now
  bundles DejaVu Sans as the default font, so the masked passphrase renders as `●`
  bullets (previously blank) and the share-tree disclosure carets render as real
  `▾`/`▶` chevrons (previously ASCII `v`/`>`). The font is vendored unmodified under
  the Bitstream Vera license.
- **First-start Enter-to-submit:** the 3-word backup type-back step submits on Enter;
  the recovery-phrase ("I've saved it") step also advances on Enter while the window
  holds focus.
- **Unlock clears on a wrong passphrase:** a failed unlock empties the field so the
  next attempt starts from a known-empty state.
- **Long-input containment:** a long or pasted entry in the single-line auth fields is
  clipped to its box instead of overrunning the window.

## [0.27.0] — GUI Shares-tab cleanup (round 1)

Post-`v0.26.0` cleanup of the GUI Shares tab and first-start flow, plus one core
refactor. Felt-tested on Ubuntu noble via an AppImage build.

- **Publish-persistence:** published shares survive restart and auto-republish on
  Unlock — the share's root is written through to the at-rest seeds blob (M16);
  explicit Unpublish forgets it, while a disconnect-reap restores it on reconnect.
- **First-start backup-verify is the C34 3-word type-back:** the C33 full-phrase
  round-trip is replaced by typing back 3 random words at cryptographically-chosen
  positions, with a non-consuming pre-check (a typo never destroys the sealed
  enrollment) and a fresh challenge per failed attempt. ISC-C47 amended to make C34
  the sole skip-backup confirmation.
- **Resizable window:** the GUI is no longer fixed at 1100×680 — it reflows to a
  720×480 floor so the shell and auth overlays no longer clip.
- **First-start focus:** auth fields focus on step entry and on error paths
  (confirm-mismatch, empty-name, save-failure), not just the initial screen.
- **Refactor:** the `human_bytes` display helper is consolidated into
  `daemonseed-core::format`; the TUI and GUI both delegate to it.

## [0.26.0] — GUI Shares tab: public-share browse, download & publish

The GUI gains the full public-share loop, matching the TUI's M16 surface.

- **Browse:** the Shares tab is an OS-style lazy-expand tree of the relay's public
  shares; each share previews its file manifest on first expand, with a manual
  Refresh and a ~3s comparative-real-time poll while the tab is open.
- **Download:** right-click any node (file / folder / whole share) → native folder
  picker → SHA-384-verified fetch to the chosen directory, with a rail-footer meter.
- **Publish:** a Publish overlay — choose a folder (optional name) → publish and serve
  it from disk for the session; a live-shares list with one-click Unpublish; your own
  shares are tagged "you" in the tree.
- **Fixes from the felt-test:** enter a tokio runtime on the main thread so Slint's
  winit xdg-settings watcher (zbus, forced onto tokio by rfd→ashpd) no longer panics
  at startup; the Publish overlay stays open and reports its outcome; a guard refuses
  to publish the home / system directories; auth fields re-focus after a failed unlock.

## [0.25.0] — GUI persistent identity: first-start + Unlock + silent circle rejoin

The GUI gains an identity that survives a relaunch — the blocker to a multi-session
tester felt-test.

- **First-start wizard:** passphrase (strength-gated) → 24-word recovery phrase →
  streamlined round-trip confirm → display name. Reuses the core `FirstStart` state
  machine and writes a sealed profile; no new crypto.
- **Daily-login Unlock:** opens the at-rest blob under the passphrase (wrong → "Wrong
  passphrase"), restores the stable display handle, and **silently re-joins** the
  circles recorded in the blob.
- **What persists:** the display name + circle *phrases* (the key is re-derived on
  rejoin, never stored). No message history is written — the no-client-history
  property holds. The connection proof stays ephemeral every connect (mirrors the
  TUI); persistence is a stable *display* identity, not a persisted connection key.
- **Crash fix carried in:** auth screens toggle with `visible:` (never `if`), so a
  screen change hides rather than destroys the focused field — avoiding a
  `partial_renderer` "RefCell already borrowed" teardown race.

## [0.24.0] — GUI affordances: persistent New/Join, command palette, edit-crash fix

Keyboard-first and discoverability polish on the GUI alpha, plus a crash fix.

- **Persistent New/Join entry:** the rail shows a "+ New circle / Join" entry
  whenever circles exist (the New/Join buttons previously vanished once you had a
  circle, leaving only the palette), so adding another circle is always one click.
- **Command palette + shortcuts:** Ctrl-K toggles the palette and Escape closes
  it; Ctrl+L (Lobby), Ctrl+N (New circle), Ctrl+J (Join) are bound directly.
  Overlays are mutually exclusive (no stacking); shortcut labels brightened. Global
  shortcuts are intentionally inert while a popup's text field has focus (text-entry
  mode); Escape / Enter / Close exit it.
- **Crash fix:** editing a circle phrase could crash the renderer ("RefCell already
  borrowed") because the status indicators toggled item-tree `if` conditionals
  mid-edit. They are now stable computed elements — editing changes only properties.

## [0.23.0] — GUI circle chat: circles talk on the relay

The circles created and joined in v0.22.0 now chat end-to-end-sealed over the
relay, completing the GUI alpha's core loop (public Lobby + circles).

- **Circle chat:** joining or creating a circle subscribes it to the relay;
  messages are sealed under the circle key and delivered to the other members.
  Each circle is independent (its own key and inbound reader); the public Lobby
  path is unchanged. Verified by an in-process round-trip and a live relay
  round-trip, then a two-client felt-test.
- **Phrase-sharing affordances:** the new-circle phrase is editable and
  copyable (Copy to the clipboard, with a confirmation); the join field accepts
  the pasted phrase and auto-focuses. (Out-of-band phrase sharing is the alpha's
  tester crutch; an in-app DM is the production path, a later milestone.)

## [0.22.0] — GUI circle plumbing: join, create, and materialize circles

The second desktop GUI milestone — the circle rail becomes live. Circles are
created and joined from the UI and materialize into the rail. They do not yet
chat over the network; the circle network path is the next milestone.

- **Join a circle:** a phrase-entry overlay with a co-equal QR slot (reserved),
  a quiet "looks strong" reassurance (no numeric meter), and a pre-commit
  confirmation card. The join is gated on the ≥128-bit circle-entropy floor — a
  weak phrase is blocked and kept so it can be strengthened in place.
- **New circle:** a one-tap generated diceware phrase (copy / show-QR reserved /
  re-roll), founderless — the creator is simply the first member. Generation is
  rejection-sampled so the phrase always clears the same floor the join gate
  applies.
- **Materialization:** a joined or created circle is added to the rail at
  runtime and carries its derived circle-of-trust key and a rendezvous slot,
  ready for the circle network path. The client seeds with the Lobby only and
  shows an empty-state until the first circle exists.
- **Composer:** sending in a materialized circle is locally echoed for now (the
  circle network path is the next milestone); the public Lobby keeps sending
  real sealed messages. Switching circles autofocuses the composer.

## [0.21.0] — GUI foundation: interactive Slint shell + real public-Lobby chat

The first desktop GUI milestone — the `gui-alpha` foundation work, taken from a
static shell to real networked chat.

- **`daemonseed-gui` crate (Slint, software-renderer):** the three-zone shell —
  circle rail, conversation pane, tab nav (Chat / Shares / a "coming soon"
  circle-shares placeholder), command palette — with a `desktop` feature for a
  real window and an offscreen `--screenshot` mode for headless verification.
- **Interactive shell:** click-to-switch rail over a per-circle RAM state layer
  that retains each circle's draft and scroll position across switches; a real
  text composer and a scrollable transcript.
- **Real public-Lobby chat:** a net actor (dedicated-thread tokio runtime, live
  application session, ephemeral identity, mirroring the TUI) connects to the
  relay, auto-joins the default public room, and sends/receives real AEAD-sealed
  messages; the UI thread never blocks. Verified by a two-client live felt-test
  on the relay.
- **`--x11` / `DAEMONSEED_X11=1` launch opt-in:** forces XWayland for testers on
  Wayland-in-a-VM (winit's Wayland pointer path drops clicks under VM software
  rendering); native Wayland stays the default.

Scope: the public Lobby only — circle chat (phrase entry), real shares fetch,
and persistent identity / first-start are subsequent milestones.

## [0.20.0] — M16, finished public share path

Completes the public share path as the reference implementation, plus the
post-smoke fixes from live two-daemon testing on the relay.

- **Fetch UX:** pre-fetch manifest preview, selective fetch, a collapsible
  folder tree, and a choosable download destination on the preview; multi-share
  publish from the Shares pane; the public-room sender is bound to its
  provenance pubkey (ISC-C57).
- **Serve-from-disk + 1 MiB sub-file chunking:** publish and serve a share of
  arbitrary size without loading it into memory — every wire frame stays
  relay-safe under the relay's 4 MB decode cap, transient serve RAM is one
  chunk per request, and a too-large manifest is refused at publish rather than
  stalling silently.
- **Chosen-destination download layout:** files land rebased to the selection
  root — a single selected file as its basename, a selected folder as
  `<dest>/<folder>/…` — and a leading `~` in the destination expands to `$HOME`.
- **No re-hash on relaunch:** the share index is reconciled (not cleared) when a
  remembered root re-indexes on unlock, so re-publishing an unchanged share
  reuses its cached chunk addresses instead of re-hashing every file.
- **Publish persistence:** a published share is remembered and auto-republishes
  on the next unlock once reconnected. The relay stays RAM-only and reaps on
  disconnect (ISC-S20), so each republish is a fresh, unlinkable share id.
- **Manifest-wait timeout:** fetching a share whose sharer is offline now errors
  cleanly instead of hanging until cancelled.

## [0.19.0] — M15, close the TUI gap

Brings the TUI to parity with the CLI for the full share loop, plus honest
coverage tooling.

- **Circle-entropy gate (ISC-C9):** a real ≥128-bit key-space estimator
  (`passphrase::strength::estimate_circle` — distinct BIP-39 words + a charset
  residue, with a zxcvbn low-end veto) driving a bits-driven join meter,
  replacing the M14 interim proxy.
- **Share publishing from the TUI:** publish / serve / unpublish a share via
  `[p]` / `[u]` on a defined share (define once, then publish — no separate
  Publish pane). Serving is session-scoped; the relay reaps on disconnect
  (ISC-S20).
- **Downloads:** a fetched share lands as named files in a per-share folder
  under a downloads root (`<profile>/downloads` in `--portable`, else the OS
  Downloads directory). Path-traversal-safe; nothing is written until the whole
  fetch verifies (ISC-C63/C64/C65, ISC-A-C31/A-C32).
- **Identity in chat + listings:** public-room posts and share listings carry
  the sender's display handle, so peers see the name rather than the `#hash`
  floor / "(operator)". The share-fetch overlay shows a progress gauge.
- **Coverage tooling:** the ISC registry `TOTAL` / `COVERED` are single-sourced
  in a new zero-dependency `daemonseed-isc` leaf crate read by both the
  integration tests and `xtask isc-coverage`; reconciled to the built ISA
  criteria (`TOTAL` 122 → 133, honest 100/133).

## [0.18.0] — M14, share-management surface + persistence

The TUI gains a **Define-Share** input box: type a local directory (`path` or
`path|label`) and the net actor opens the redb share index and cold-scans it on a
dedicated background thread — the command loop never blocks and the index stays
queryable during the scan (redb MVCC, ISC-A-C7). Defined roots **persist** in the
at-rest blob as a `share` directive (ISC-C21) and **re-index automatically** on the
next daily-login Unlock, mirroring circle rejoin. The share-index key is derived as
a **sibling of the at-rest key from a single Argon2id run** (domain-separated
HKDF-Expand, ISC-C3 / A-C6); the at-rest key output is byte-identical to before, so
existing blobs open unchanged. Also folds in the M13 deferrals: a circle-join
**entropy meter** with the ISC-C9 join gate, and a relay-independent **circle
fingerprint** (coded, not yet surfaced). Publishing remains operator/CLI-side; the
TUI is fetch + local-index only. No wire change.

## [0.17.0] — M13, persistence keystone

The at-rest seeds blob now persists display name, mute list, hidden-shares, and
circle membership (ISC-C51 / C15 / C16 / C59), restored on a daily-login Unlock;
circles silently rejoin without re-typing the phrase. A cached `SealingKey`
(`daemonseed_core::storage::seeds`) re-seals the blob on each mutation with no
second Argon2id (the Pi-4 floor); circle entropy + label are stored as hex
directive lines and stay non-mnemonic-derivable, so a mnemonic-only recovery
never reconstructs the social graph. This persists configuration, not history —
the no-client-history property is intact. No wire change.

## [0.16.0] — multi-circle carousel

Simultaneous membership in N circles (joining ADDS, never evicts), a split chat
view (lobby pane + active-circle carousel pane), arrow-key cycling of the active
circle, deterministic client-local labels, and per-circle surface isolation +
attribution (ISC-C59–C62 / A-C29 / A-C30). Purely client-side, no wire change.

## [0.15.1] — chat-surface precedence fix

Posts route to the joined circle rather than the auto-joined lobby, plus a
compose-box surface indicator. Client-only.

## [0.15.0] — alpha2 batch

Opaque server-assigned `share_id` (S21 / A-S15); share download
(S27–S29 / A-S20–A-S21); interactive public rooms — the auto-joined lobby
(S22–S26 / A-S16–A-S19 / C56–C58); client-identity lifecycle — first-start
persists the seeds blob + config + `.dseed`, daily-login Unlock, no-clobber of an
existing identity (C47–C51 / A-C26–A-C28); `--portable` mode forcing the CWD as
profile root (C52).

## [0.14.0] — M12, alpha1 MVP

The last two MVP-gate steps under one additive SemVer MINOR wire bump.
**Step 5** — user-publish file sharing: `PublishShare` / `UnpublishShare` /
`ListPublicShares` over the PublicSpace service; a RAM-only per-connection
registry (`SharePublishRegistry`), `publish` holds the connection open until
Ctrl-C, and `ShareReapGuard` reaps the share on real disconnect
(ISC-A-S1 / A-S5b / S4). **Step 6** — the federation introducer endpoint
(`FederationIntroducer` gRPC over the already-shipped
`IntroducerQuery`/`IntroducerResponse`) + the TUI Servers-pane refresh rendering
introducer-discovered candidates read-only, no keys, never auto-trusted
(ISC-S6 / S13 / C22 / A-C19). The full 4-daemon gate trips 10/10 → **MVP declared**.

## [0.13.0] — M11, MVP-gate client surfaces

The real interactive ratatui TUI driving the full transaction, M9 surface
wiring, public-space (MOTD + announcements) view, suite-deprecation policy
surfacing (fetch + ML-DSA verify + anti-rollback), and clean-device recovery
from a 24-word mnemonic / `.dseed` file — all over already-shipped, already-served
server APIs (no new wire protocol). Trips gate steps 3/7/8.

## [0.12.1] — M10-completion

Scaffolds the two platform-gated M10 ISCs as abstraction-only: C7
biometric/secure-enclave session-passphrase unlock and C20 OS-native autostart
(traits + opt-in `ProfileConfig` flags, default off; platform halves reserved to
M10-infra). Also brings every LAMA manifest (root + per-crate) to canonical
LAMA 0.1.

## [0.12.0] — M10-core, verifiable core

Release trust anchor + N-of-M ML-DSA-87 multi-sig verify
(`daemonseed_core::release`), the server boot-gate that refuses to boot on failed
verify (no boot-with-warning path), and the client update-lifecycle FSM
(verify-before-apply / never-auto-install / no-silent-downgrade /
wipe-and-log-on-failure). Plus the M9 per-key rate-limit RAII drop-guard and the
ISC-S20 coverage backfill. Closes S18 / A-S13 / C27 / A-C11.

## [0.11.0] — M9, abuse-resilience + chat affordances

Server: multi-granularity RAM-only rate limits (per-connection token bucket +
subscription/verify caps), per-identity-key connection table GC'd on disconnect,
uniform silent close (S17 / A-S12). Client: exponential+jitter reconnect backoff
with an 8-retry budget (C26); mute + hide-shares persisted in the seeds blob,
never leaked (C15 / C16 / A-C3); @-mention recognition + resolution as pure
functions with no new server-visible distinction (C17 / C18 / A-C4).

## [0.10.0] — M8, circle-of-trust relay + indexer

Circle-of-trust live relay (refcounted bidi Subscribe, reap-at-zero), flat
metadata-free circle key derivation, per-relay rendezvous addressing, a
content-addressed chunk store, and the encrypted incremental redb share indexer
with Pi-civility background scanning. Added ISC-S20.

## [0.9.0] — M7, suite deprecation + trust-event taxonomy

Suite deprecation policy (operator-signed, replay-protected cutoffs) + the
trust-event taxonomy (four affordance classes, closed `TrustEventKey` enum,
bounded encrypted audit log).

## [0.8.0] — M6, public space

The first post-Authenticated application service (PublicSpace gRPC). Verify-and-
serve signed announcement posts (S7) + MOTD (S9) against an operator signer
whitelist (S8) with a non-removable project-release entry; operator rating
taxonomy published, never enforced (S10 / A-S5b); public-share listing surface
(S4); client rating selection + filter plumbing (C19 / A-C5); AGPL-§13 source URL
advertised in the handshake ack; server filesystem isolation (A-S8). Closes 12
ISCs (55→67).

## [0.7.0] — M5, federation

Per-server trusted/untrusted trust slider with TOFU pinning + rotation notices
(C22), introducer responses that never carry public keys (S6), server-to-server
peering reusing the same slider (S12) with introduce-to-clients suppression (S13)
and active-attacker-resistant don't-introduce (A-S7), reference-client connection
cap (A-C10).

## [0.6.0] — M4b, identity-proof handshake

Post-HELLO identity-proof: mutual ML-DSA-87 envelopes bound to the TLS exporter
channel binding, ±5 min freshness + per-key replay counters, Versioned →
Authenticated type-state gate, uniform close on failure. Closes S19 / A-S14 /
A-C18 / A-S12 / A-S1.

## [0.5.0] — M4a, relay daemon

Server skeleton + TLS 1.3 on :443 with ALPN h2 + APP_HELLO + type-state
`Connection<Negotiating → Versioned>`; CLI connect initiator.

## [0.4.0] — M3, crypto-suite registry

Suite registry (CNSA 2.0 baseline), `suite_id` wire-tagging on at-rest artifacts,
read-old-write-new migration on touch, circle-metadata `min_suite_id` slot.

## [0.3.0] — M2, first-start + recovery

First-start type-state orchestrator, encrypted recovery file (`.dseed`),
bootstrap-anchor selection (canonical / manual-paste).

## [0.2.0] — M1, identity primitives

BIP-39 mnemonic, HKDF-derived ML-DSA-87 / ML-KEM-1024 keypairs, profile
substrate, at-rest seeds blob, handle format (adj-noun + 12-hex fingerprint).

## [0.1.0] — M0, scaffold

Pre-implementation findings, workspace scaffolding, proto-codegen pipeline.
