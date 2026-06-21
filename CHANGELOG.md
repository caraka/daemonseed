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

- In-band share discovery — announcement payload and seal/open: a
  `ShareAnnouncement` wire message and `daemonseed-core::share_announce`
  (`seal_public_announcement` / `seal_circle_announcement` / `open_announcement`),
  a share announcement sealed
  (AES-256-GCM) and ML-DSA self-signed for provenance, carried in a
  `CotFrame.payload` at a room/circle rendezvous address, mirroring
  `public_room`. Sealed under the public room key (public tier, server-readable)
  or a circle `cot_key` (members-only); relay-agnostic (carries `share_id`, not
  `server_id`). Design-of-record: `docs/design/unified-share-model.md`.
- Share content sealing (`daemonseed-core::share_seal`):
  `seal_public_share_frame` / `seal_circle_share_frame` (tier-guarded) and a
  tier-agnostic `open_share_frame` seal each `ShareFrame` (manifest/chunk) under
  the room/circle key with a distinct AAD, so share traffic is structurally
  indistinguishable from chat on the wire (the alpha shipped public-share content
  in the clear). No provenance signature — per-chunk SHA-384 integrity already
  lives inside the frame.
- In-band share discovery — roll-call request payload and seal/open: a
  `ShareRollCall` wire message and `daemonseed-core::share_rollcall`
  (`seal_public_rollcall` / `seal_circle_rollcall` / `open_rollcall`), the
  late-join request half that pairs with `ShareAnnouncement`. Because the relay
  is a blind forwarder that emits no subscribe events, late-join is pull-based: a
  joining/refreshing client posts a sealed, ML-DSA self-signed roll-call into the
  room and every connected sharer re-announces. A distinct sealed kind (not
  implicit-on-subscribe), tier-guarded by key type, with a distinct AAD
  (`SHARE_ROLLCALL_AAD`) so it can never be confused with an announcement, a
  content frame, or a chat message. Design-of-record:
  `docs/design/unified-share-model.md`.
- Desktop GUI window/taskbar icon: the `AppWindow` now carries an `icon`,
  rasterized from the AppImage's scalable placeholder so the windowed app and
  the AppImage share one mark (aesthetic refinement deferred).
- First-start backup confirmation as three single-word type-back fields (C34):
  one challenge word per box, Enter advancing to the next (the third confirms).
- Reproducible AppImage build recipe for the desktop GUI
  (`packaging/appimage/`, output to `dist/`).
- Per-share optional wire-facing name persisted with published shares
  (`PublishedShare { root, name }`; core slice — no naming UI yet).
- "Restored N shares from last session" label on the connect-time
  auto-republish path, distinguishing a restore from a fresh publish.
- First-run desktop integration: an opt-in prompt ("Add Daemonseed to your
  applications?") plus `--install` / `--remove` CLI flags self-register an XDG
  `.desktop` entry + hicolor icons (256px PNG + scalable SVG), so the app menu /
  dock resolve a real icon across desktop environments. AppImages are not
  "installed", so nothing did this before. Never silent; honours a "don't ask
  again" choice; `StartupWMClass=daemonseed-gui` matches the window's WM_CLASS so
  the live window inherits the icon (`src/desktop_integration.rs`).
- The desktop GUI remembers its window size across restarts: the last size is saved
  on close and restored on launch (size only — position is omitted to avoid landing
  off-screen on another monitor; an out-of-range saved value is ignored).

### Changed

- Key-class separation: the circle key type is renamed `CotKey` → `CircleKey`
  and the public room key gets its own distinct `PublicRoomKey` (was an aliased
  `CotKey`); both implement `AeadKey256` for tier-agnostic opens. The two are no
  longer substitutable — sealing a circle payload under a public key (or vice
  versa) is now a compile error. The share-announcement seal is tier-split
  accordingly (`seal_public_announcement` / `seal_circle_announcement`); opening
  stays tier-agnostic. Behavior-preserving (no wire change).
- Track oxicrypt 0.16.0 in the lockfile.
- Auto-republish on connect now consumes the persisted per-share name
  (`PublishedShare.name`), threaded through the restore path; it falls back to
  the root directory basename when unset. The name-a-share UI that would set a
  non-default name remains a follow-up.
- User-facing "sealed" → "encrypted" in all GUI trust copy (the E2EE pill and
  the end-to-end-encrypted lines).
- Session-restore notice ("Restored N shares…") now shows as a tab-independent,
  auto-dismissing banner on the landing (Chat) view, not only on the Shares tab.
- Desktop GUI window title is now "Daemonseed" (was the toolkit default).
- The AppImage recipe now emits a 256px raster PNG + a top-level `.DirIcon` (was
  scalable-SVG only) — what desktop integrators and the dock actually read.

### Fixed

- The circle rail/header no longer shows a stale "not yet connected" placeholder
  that contradicted the live connection state.
- Keyboard focus is restored when the desktop window regains activation, so
  typing / Enter survive an app-switch without clicking back into the field (#39).

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
