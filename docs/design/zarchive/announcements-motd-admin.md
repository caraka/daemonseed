> **⚠️ SUPERSEDED & ARCHIVED (2026-07-07).** This is the **relay-era** announcements/MOTD design
> (2026-06-25), written against a `daemonseed-server` that verifies posts and answers
> `UploadPost`/`UploadMotd`/`GetSignerWhitelist` — all deleted at the v0.33.0 cutover. Kept for
> rationale/history only. The single **active** design-of-record is
> [`docs/design/phase4-veilid-presence-announcements.md`](../phase4-veilid-presence-announcements.md),
> which re-grounds authoring on an operator-owned DHT rendezvous record (write-gate ≠ content-provenance;
> the whitelist becomes a client-verified documentary roster; multi-author quarantined post-MVP).
> Do not build from this doc.

# Design: announcements + MOTD admin authoring & GUI surface

**Status:** accepted (design-of-record) — re-scopes #88 from "fetch each release's
CHANGELOG" to "surface the existing announcements room + MOTD primitive, and build
the missing admin-authoring path + GUI." Decisions locked 2026-06-25. Component
deliverables are filed as issues (listed at foot); this doc persists as rationale.

## Problem

#88 asked for an in-app way for testers/users to learn a new build shipped and what
changed — today the only version signal is the login-footer build string (#59). The
original framing (bundle or *fetch* a CHANGELOG) raised a trust / relay-blind concern.

That concern is unfounded: daemonseed already has the right primitive. The
**announcements room + MOTD** (ISC-S4 public space, ISC-S7 announcement posts, ISC-S9
MOTD) are signed public-space assets delivered over the relay path the client already
uses, with provenance established by the operator/signer whitelist signature (ISC-S8) —
not an out-of-band HTTP changelog pull. "What's new in the app" is just a release
announcement the relay operator posts. One MOTD, one announcements channel; no new
update-awareness subsystem.

What is actually missing is the *authoring* and *GUI* halves:

- the TUI has display panes; the GUI has none;
- there is no client-side path for a whitelisted signer to compose/sign/upload an
  announcement or set the MOTD — "the admin backend to support the panes."

## What already exists (verified 2026-06-25)

- **Relay ingestion** — `daemonseed-server::public_space`: `load_whitelist`, post
  verification (`verify_stored_post`), `UploadPost` / `DeletePost`, `get_motd`, and the
  `GetSignerWhitelist` RPC that *publishes* the whitelist to clients.
- **Shared core** — `daemonseed-core::public_space`: `WhitelistEntry` (full-key |
  `name#hash`), `from_full_key_bytes` (the path "a client fetched via
  `GetSignerWhitelist`"), signature/authorization helpers (ISC-S8/S10/S11/S12).
- **Wire** — `SignedArtifact`, `PostPayload`, `MotdPayload`, `GetMotdRequest`,
  `GetSignerWhitelistRequest/Response`, `SignerWhitelistEntry`.
- **TUI** — announcement/MOTD display panes.

So whitelist infra (load + verify + **publish to clients**) and the announcement upload
path already exist. A client can fetch the published whitelist and self-determine signer
status — no new privilege machinery is needed.

## What's missing

1. **`UploadMotd` RPC** — MOTD is file-drop-only today (`load_motd(motd_path)` at
   startup; only `GetMotdRequest` to read). Posts upload in-band; MOTD cannot.
2. **Client authoring** — compose → sign with the local identity's signer key →
   `UploadPost` (and new `UploadMotd`); delete-own-post.
3. **Signer self-determination wiring** — fetch `GetSignerWhitelist`, compare the local
   pubkey, gate the authoring affordance. (Core helpers exist; not wired into clients.)
4. **GUI display panes** — port the TUI announcement/MOTD panes to the GUI.
5. **Unread-gated landing** — open to the announcements/MOTD pane only when there is
   unread news.

## Constraints (must hold)

- **ISC-S8** — only whitelisted signers (or the server-wide key) may author; every
  post/MOTD carries a signature the relay verifies against the published whitelist before
  storing or serving. The whitelist itself is operator-only, file-edited, out-of-band
  (ISC-A-S4) — `UploadMotd` does **not** change that; it carries *content*, never
  whitelist membership.
- **ISC-S9** — MOTD is a single-slot, plaintext-only string (no markdown/HTML/links —
  anti-injection). The GUI renders it verbatim. `UploadMotd` is latest-validated-wins,
  same as the file-drop slot.
- **ISC-A-S8** — operator config (TOML, whitelist file) stays operator-only-write; the
  server only writes signer-writable content in response to authenticated signer uploads.
  `UploadMotd` writes the MOTD slot the same way `UploadPost` writes the posts dir.
- **Precautionary default at the trust boundary** — `UploadMotd` reuses the *exact* trust
  model already in `UploadPost` (signed-by-whitelist-key, relay-verified). It adds
  in-client convenience without widening the boundary; file-drop remains a valid operator
  path.
- **Public-space tier** — announcements/MOTD are deliberately server-readable
  (ISC-S4 / ISC-A-S2); this is the public tier and carries no confidentiality guarantee.
  No private-circle opacity is touched.

## Decisions (locked 2026-06-25)

- **D1** — "what's new" = the operator posts a signed release announcement; no CHANGELOG
  fetch. #88 re-scoped; the changelog-fetch framing is dropped.
- **D2** — add an `UploadMotd` RPC (parity with `UploadPost`; single-slot replace per
  ISC-S9).
- **D3** — the authoring affordance is gated on the local pubkey appearing in the relay's
  *published* whitelist (`GetSignerWhitelist`); cryptographic, no separate admin login.
  Non-signers see read-only.
- **D4** — build GUI display panes for announcements + MOTD (port from TUI).
- **D5** — auto-land on the announcements/MOTD pane only when there is unread news (new
  MOTD or new announcement since last-seen; reuse the #64 unread machinery), else open the
  Lobby; always rail-reachable; scoped to the currently-connected relay.

## User story & unread mechanism (caraka, 2026-06-25)

The signer's-eye flow, end to end:

1. The signer is on the relay's whitelist. They have seen the current MOTD/announcements
   before, so the pane is **not** shown at startup.
2. **Unread detection:** the client stores a per-relay "last-seen content hash" in its
   local profile state (keyed by `server_id` — clients have no TOML; this is profile
   state). On connect it compares that stored hash to the hash of the relay's *current*
   MOTD + announcements. Equal ⇒ bypass, open the Lobby. Not-equal — or no stored hash, a
   first-time arrival ⇒ auto-open the announcements/MOTD pane. Viewing it updates the
   stored hash.
3. The pane is always reachable on demand via the **Ctrl-K** command palette, unread or not.
4. Because the local key is on the published whitelist (D3), the pane additionally shows a
   **composer** for the MOTD and for announcements. The signer edits and signs with their
   key; the client uploads via `UploadPost` / `UploadMotd`. The MOTD composer enforces the
   ISC-S9 plaintext rule (single line, no markdown/HTML/links).
5. A successful edit changes the current content, hence its hash, so every *subsequent*
   arrival whose stored hash differs is auto-shown the pane — returning users who saw the
   old version and brand-new users alike. A user who already saw this exact version matches
   and is bypassed. The single hash handles all three cases naturally.

**The hash is client-derived, not server-stored.** The relay stores signed artifacts, not
a digest; the client already fetches MOTD + announcements to render the pane, so it
computes the hash locally and compares to its stored marker — no new server state and no
new RPC for unread. (A server-advertised digest could later make the check cheaper, but it
would be an unsigned relay-controlled *hint* only; content is still verified by signature,
so correctness stays client-side.) A deletion also flips the hash (something changed) —
acceptable.

## Whitelist membership is out-of-band, by design (the uncovered item)

The story does not cover how a pubkey/handle gets *onto* the whitelist — because, per
ISC-S8 / ISC-A-S4, that path is deliberately **operator-only and out-of-band**, and must
stay that way:

- The whitelist is a plaintext file on the server host (`signer_whitelist_path`). Adding a
  line (full ML-DSA-87 pubkey, or a `name#hash` handle) grants signing rights; removing it
  revokes them; a reload/restart picks up the change. There is **no** in-band "add a
  signer" command — that is the precautionary boundary (a network attacker can never grant
  posting rights), and the GUI must **not** add one.
- **Onboarding flow:** a prospective signer sends their handle/pubkey to the operator
  *out-of-band* (their `name#hash` handle is already visible in-app and is the compact form
  ISC-S8 accepts); the operator edits the file and reloads. Since the operator runs their
  own relay, that is the operator editing `signers.txt` on the server host (directly or
  over SSH).
- The GUI's only legitimate whitelist role is **read-only display** — the relay already
  publishes the list via `GetSignerWhitelist`, so the pane can show "who can post here" for
  transparency. It never edits it.

This is the clean split ISC-S8 already draws: **signer powers (content — posts, MOTD,
delete-own) are in-band and GUI-driven; operator powers (whitelist, topics, taxonomy,
federation) stay out-of-band file-edit + reload.**

## Open questions

- **Single vs split hash** — one combined MOTD+announcements hash (MVP, per the story)
  vs separate MOTD/announcements hashes so the landing can show *which* changed.
- **Multi-relay** — MVP shows the currently-connected relay's announcements only;
  cross-relay aggregation is out of scope.
- **Server-wide-key MOTD** — ISC-S9 allows the server-wide key (not just whitelist
  signers) to set the MOTD; confirm whether the GUI operator path should expose that or
  leave server-wide-key MOTD to file-drop.

## Deliverables (issues)

- **[server]** `UploadMotd` RPC + handler (verify against whitelist, single-slot replace).
- **[core]** signer authoring: compose/sign/upload announcement (`UploadPost`), set MOTD
  (`UploadMotd`), delete own post; signer self-determination via `GetSignerWhitelist`.
- **[gui]** announcement + MOTD display panes (port from TUI).
- **[gui/tui]** signer-gated admin affordance (compose / set-MOTD shown iff local key ∈
  published whitelist).
- **[gui]** unread-gated landing on the announcements/MOTD pane.
