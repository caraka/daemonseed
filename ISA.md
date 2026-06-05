---
task: Daemonseed ideal-state contract and system of record
project: daemonseed
effort: comprehensive
phase: build
progress: 100/122
mode: interactive
started: 2026-04-19T00:00:00Z
updated: 2026-06-03T00:00:00Z
---

# Daemonseed — ISA (Ideal State Artifact)

> This file is the **system of record** for daemonseed: the articulated ideal state, the
> test harness (its ISCs are the tests), the build-verification surface, and the done-condition
> for the alpha1 MVP. It is also the contributor contract — read it to understand *where the
> boundaries are and why they hold* before changing anything. The companion working draft in the
> project lead's vault is scratch; **this file is authoritative.** Iteration on the project is
> iteration on this file.
>
> **Frozen contract vs. living state.** A contract must be stable for contributors; a system-of-record
> must absorb state. Those pull in opposite directions, so the boundary is explicit:
> **frozen-contract** sections — Principles, Constraints, Criteria (ISC IDs, never renumbered), and
> Out of Scope — change only deliberately and visibly, via PR. **Living-state** sections — Features
> (milestone status), Verification (coverage), and the `progress` frontmatter — are *derived* and
> may lag; the drift-proof source for those is `cargo xtask isc-coverage` and the project manifest,
> not hand-edits here. When in doubt, never let a state update mutate a contract surface.

## Problem

Demonsaw — the secure-communications and anonymous file-sharing application this project succeeds —
wound down around 2018–2019, leaving its community without a maintained, modern continuation. Its
distinctive design promised federation it never actually shipped at scale; its C++/Qt codebase is
unmaintained; and its cryptography predates the CNSA 2.0 post-quantum mandate. People who relied on
it for censorship-survivable, privacy-preserving sharing have no blessed successor. Daemonseed is
that successor: a **clean-room, pure-Rust** protocol and implementation, informed by the lineage but
inheriting **zero lines** of the original code — every prior design choice is interrogated, not ported.

## Vision

A contributor (LLM or human) opens this repository and, in one read, understands not just *what*
daemonseed does but *where its boundaries lie and why they hold* — the difference between "the server
doesn't log" as a slogan and "the server **cannot** persist user identifiers, and here is the
anti-criterion that fails if it ever does." A daemon (user) experiences a tool that is **private by
construction, not by promise**: identity recoverable from a 24-word mnemonic that never touches disk,
trust circles that form from shared entropy, a relay that sees ciphertext, presence-at-hash, and
refcount — never content, membership, or enumeration. The euphoric surprise is the realization that
every privacy guarantee is **falsifiable**: each is an ISC with a named probe or an anti-criterion
that would fail under violation. Trust here is earned by verification, not asserted by marketing.

## Out of Scope

The following are deliberately *not* part of the alpha1 MVP. They are recorded so the ideal state is
complete and so contributors don't mistake their absence for an oversight.

- **Direct messaging** (ISC-C38–C46 / ISC-A-C20–A-C25) — alpha2 scope, deferred from the alpha1 MVP gate.
  The design is drafted and carried in Criteria below, but **no MVP criterion depends on it.**
- **Folder encryption** (the vacated `ISC-C5` slot) — a post-MVP reservation; fully additive, no MVP
  shape commitments needed.
- **Multiple side-by-side daemon enrollments** — a reservation; MVP supports only tester-grade
  multi-instance via profile-root resolution (`ISC-C35`).
- **Per-device identity cross-device transfer** — fresh-enroll-only for MVP.
- **Pluggable / QUIC transport** — reserved; the MVP file-relay is chunk-oriented and transport-abstracted
  so QUIC drops in later without a refactor, but MVP ships TLS 1.3 only.
- **Hard Sybil resistance** — MVP accepts BIP-39 enrollment friction plus per-IP rate limits as the floor;
  proof-of-work, invitation-gating, and reputation are post-MVP options.
- **Application-level connection idle-timeout** — post-MVP, tracked. The M12 "you must be online to share"
  model (gate step 5) holds a per-connection server task open until the connection itself closes, so a
  handshake-complete but *silent* (zero-RPC) peer is bounded only by the OS/per-IP layer and process
  FD/memory limits — **not** by the per-RPC request-rate limiter or the per-key connection cap. The h2
  keepalive reaps a dead peer (~30s) but not a live-but-silent one. An app-level idle/keep-alive timeout
  (and the NAT/middlebox keep-alive noted in the `publish` hold-open path) is the deferred mitigation;
  acceptable for the closed alpha, must not be treated as already-solved.
- **Release-signing key governance** (N-of-M holder identities, rotation cadence) — deferred to a
  governance resolution; MVP reserves the multi-sig wire shape and trust-anchor *set* without naming holders.
- **A Demonsaw port** — zero lines of original code; the original C++/Qt source is a UX reference only.
- **Perfect traffic obfuscation** — the bar is GFW-survivability, not unobservability (see Principles).

## Principles

Substrate-independent truths the work must respect. These bind the *thinking*.

- **Information sharing, not hiding.** Encryption is present and load-bearing, but the framing is sharing
  under adversarial conditions — not a "dark" tool. (Lineage rhetoric, interrogated and kept.)
- **Public keys are compromised by definition.** Classify every key as secret-or-shared before designing
  around it; never rest a guarantee on a public key staying private.
- **Survive the GFW; do not chase unobservability.** Censorship-survivability is the bar (negative-allowlist
  detection, Wu et al., USENIX Security 2023). Real TLS 1.3 on :443 clears the fully-encrypted-traffic
  filter by construction; we do not pretend to be invisible.
- **The relay learns metadata, not content.** Separation of trust is structural: operators see
  presence-at-hash and refcount changes, never plaintext, membership, or circle enumeration.
- **Trust is per-entity and user-controlled.** TOFU with a per-server trusted/untrusted slider; no
  transitive trust — introducers carry addresses, never keys.
- **Identity is recoverable before it is exposed.** A daemon can always recover identity from its
  mnemonic; the mnemonic never persists to disk. Recovery precedes any exposure surface.
- **Falsifiable guarantees.** Every privacy/security claim is an ISC with a named probe, or an
  anti-criterion that would fail under violation. The slogans are not the contract; the ISCs are.
- **Clean-room.** Lineage informs; it never dictates. Every inherited choice is interrogated, not ported.

## Constraints

Immovable architectural mandates. These bind the *solution space*.

- **Backend: pure Rust, no C dependencies.** Networking, crypto, and runtime stay in the Rust ecosystem.
- **Crypto: CNSA 2.0** — ML-DSA-87 (signature), ML-KEM-1024 (KEM), AES-256-GCM (AEAD), SHA-384 (hash) —
  via the oxicrypt crate. The architecture absorbs CNSA 2.1 via additive MINOR bumps (per-artifact
  suite-id agility; BIP-39 + HKDF derivation root).
- **Transport: rustls + TLS 1.3 on :443**, ALPN `h2` (benign cover). Application-protocol identification
  happens after the handshake (APP_HELLO), never in the TLS fingerprint.
- **Wire: gRPC over h2 (prost / tonic)**, proto3, checked-in codegen verified by `cargo xtask check-proto`.
- **Storage: three-layer split** — passphrase-encrypted seeds file + redb indexed state + content-addressed
  chunk filesystem.
- **Versioning: SemVer 2.0**, MAJOR.MINOR negotiated on the wire; MINOR bumps MUST be additive-only.
- **Civility floor: Raspberry Pi 4 (4 GB).** Rate-limit and resource defaults are calibrated so a Pi-4 is
  a viable relay; operators scale the values up on larger hardware.
- **License: AGPL-3.0-or-later** on code crates; **Apache-2.0 OR MIT** dual on the `daemonseed-proto`
  schema crate.
- **ISC IDs are permanent** — never renumbered or reused; vacated IDs stay reserved; withdrawn ISCs get a
  `DEPRECATED` marker with a successor pointer.

## Goal

Daemonseed is a federated, end-to-end-encrypted, censorship-survivable communication and file-sharing
protocol — a clean-room pure-Rust successor to Demonsaw — in which **every privacy and security boundary
is expressed as a falsifiable Ideal State Criterion.** "Done" for the **alpha1 MVP** is: all MVP-scope
ISCs (the server + client criteria, excluding the alpha2 direct-messaging ISCs C38–C46 / A-C20–A-C25) pass their mechanized probes
via `cargo xtask isc-coverage`, plus the four-daemon end-to-end PTY gate passes, with the Definition-of-Done
gates green and the binaries built reproducibly under CNSA 2.0. This ISA is the system of record for that
contract: contributors read it to learn the boundaries, and the Algorithm iterates the project against it.

## Criteria

Each criterion is a verifiable boundary: positive ISCs describe a durable end-state the implementation must reach; anti-criteria (`ISC-A-*`) describe a forbidden state the implementation must never reach. IDs are permanent — an ID is never renumbered or reused, and vacated IDs are left reserved so cross-references stay stable.

**Identity model.** Every daemon has a single stable keypair root: per-domain ML-DSA-87 (signing) and ML-KEM-1024 (key encapsulation) keys derived from one BIP-39 mnemonic. All identity presentations a daemon makes — primary, per-device, handle-only, or fully anonymous — are surface choices layered on that one root; "anonymous" is a per-context presentation, not a separate identity tier. A user who needs hard-separated identities runs multiple daemon enrollments with separate mnemonics. The same handle format applies to every named entity, clients and servers alike. The wire/storage handle is `<name>#<first-12-hex-of-SHA384(pubkey)>`; the hash prefix is self-verifying (any party holding the underlying key can confirm the prefix matches) and defaults to 48 bits to make prefix-grinding attacks economically unattractive at federation scale. The display format in normal UX is just `<display-name>` — the prefix is hidden and surfaces only on demand (verification gesture, name collision, or mute/hide/verify actions). A daemon can be un-named by choice in the display but is never un-named in the wire format. SHA-384 is the hash function throughout (CNSA 2.0).

### Server — positive (ISC-S*)

- [ ] ISC-S1: The server is federated. Trust model is TOFU with a per-server trusted/untrusted slider (client-side per ISC-C22, server-to-server per ISC-S12). Server identity is a long-term ML-DSA-87 keypair (ISC-S11); the on-wire encoding (self-signed cert vs raw public key) is an implementation detail that does not change the trust model.
- [ ] ISC-S2a: Perfect forward secrecy via ephemeral ML-KEM exchanges per session.
- [ ] ISC-S2b: The server never exposes one client's IP or transport metadata to another client. Only the daemon's self-declared in-app handle (which may be the hash-prefix floor) is observable peer-to-peer.
- [ ] ISC-S3: The server is a stateless single binary, packaged as an OCI container and k8s-friendly (12-factor, health endpoints), and also runs as a standalone binary or under systemd.
  - rationale: "Stateless" means no in-process state mutation between requests; operator-managed config, the signer-pubkey whitelist (ISC-S8), and content-addressed signed-post directories (ISC-S7) are the only persisted artifacts, and they arrive only via operator action or signer upload — the server never autonomously writes runtime state to disk.
- [ ] ISC-S4: The server hosts two asset kinds through the same client UX (rooms, chat, file shares): public spaces (landing page, public rooms, MOTD, announcements) and circle-of-trust assets, created on demand when a daemon's subscription stream presents address `SHA-384(cot_key, server_id)`, for which the server is an opaque relay with no key, no plaintext, no membership list, and no enumeration. **A public space (public rooms, file shares, MOTD, announcements) is a circle-of-trust whose membership is open and includes the server itself.** Its key derives from public inputs (crypto family + room/share name), so any participant — and the relay — can derive it; the server is therefore a *member* of the public CoT and can read public content. This is the deliberately-public tier and carries no confidentiality guarantee. The defining contrast follows directly: **server compromise exposes public-space content (the server is a member), but exposes nothing in a private circle — there the server is not a member and never holds the key.** Operator-authored public content (MOTD, announcements) additionally carries a provenance signature from the server-wide key or a current whitelist signer (ISC-S7/S8); interactive public rooms (ISC-S22) are open-post, self-signed for provenance by each posting daemon's own identity (ISC-S24). Circle-of-trust content, by contrast, is sealed under a member-only key the relay never holds — that is the actual confidentiality guarantee. The distinction is CoT membership, an application-layer property independent of the transport; transport security (TLS 1.3 today, transport-agnostic by design) is a separate layer protecting all tiers equally and is never the source of the distinction. The CoT security boundary is invisible to UX and absolute cryptographically: private circles place the server outside it, public spaces place the server inside it by design.
- [ ] ISC-S5: The server terminates TLS 1.3 with every connecting client; circle-of-trust E2EE traffic is opaque relay. The handshake is shaped so the first TLS record looks like generic HTTPS on :443, supporting censorship survivability by construction.
- [ ] ISC-S6: The server may act as an introducer, returning `(server-id, address, last-known-availability)` triples on request, where `address` is a hostname or a raw IPv4/IPv6 literal (operators without DNS are first-class). Introducer responses never carry public keys.
  - rationale: This is a hard invariant preventing transitive-trust collapse — a client receiving an introduction must still obtain the introduced server's key through its own configured trust mode (ISC-C22); the introducer is discovery-only, never trust-establishment.
- [ ] ISC-S7: The server hosts an announcements channel as part of public space: operator-defined topics each holding zero or more posts. Posts are signed under a key in the signer whitelist (ISC-S8), content-addressed by `SHA-384(signed-payload)`, ordered by signed timestamp, and persisted as individual files separate from the server config (per ISC-A-S8). The server verifies signatures against the current whitelist and serves; it never originates posts. A signer may sign a delete of their own post; the operator may delete any post.
- [ ] ISC-S8: The server maintains a flat signer whitelist authorizing holders to author announcement posts (ISC-S7) and update the MOTD (ISC-S9). Each entry is a full ML-DSA-87 public key or a `<name>#<hash-prefix>` handle (the signer's full key arrives with each artifact and is verified against the handle before signature verification). The whitelist is operator-only out-of-band config (ISC-A-S4) and is published as public-space data so clients verify provenance against the same list the server uses. Signer powers are narrow: sign/author posts, sign deletes of their own posts, sign MOTD updates — and nothing else (topic set, rating taxonomy, whitelist, and federation are all operator-only). Revocation is immediate on reload.
  - rationale: Accepted limitation — a compromised server can publish a forged whitelist; neither trust mode protects against this, since trusting the server's content-relay function is what defines using it. Out-of-band whitelist-hash publication is possible future hardening.
- [ ] ISC-S9: The server hosts a MOTD — a short single-string message rendered on the landing page, plaintext only (no markdown, HTML, or links — anti-injection). The MOTD lives in a dedicated signer-writable file separate from operator config (per ISC-A-S8), containing a signed payload (text + signer pubkey + timestamp + signature). Single-slot: the latest validated update wins; empty/missing hides the area.
- [ ] ISC-S10: The server publishes a content-rating taxonomy as public-space data — an operator-defined set of rating labels. The taxonomy is purely declarative; the server does not enforce ratings on share contents (ISC-A-S5b). Clients consume it to render rating filters (ISC-C19).
- [ ] ISC-S11: The server has its own long-term ML-DSA-87 keypair, generated once at bootstrap and persisted, presented as the identity in its TLS 1.3 termination (ISC-S5). The server-id follows the same handle rules as clients (ISC-C4 family): wire form `<server-name>#<first-12-hex-of-SHA384(server-pubkey)>`, with the same display and enrollment defaults.
- [ ] ISC-S12: Server-to-server federation peering uses the same per-peer trusted/untrusted slider as ISC-C22. Trusted = first-contact hash verification against the peer's server-id, then TOFU-pin the full key and accept rotation; untrusted = peer key must be pre-loaded and match exactly. Introductions between federating servers obey the same no-keys-in-introducer-responses invariant (ISC-S6) — learning about server C through server B does not auto-trust C's key.
- [ ] ISC-S13: Each federation peer entry carries an `introduce-to-clients` boolean (default true). When false, the peer is excluded from all introducer responses (client and server-to-server) while continuing to federate normally — suitable for federating a low-profile server with a public one without leaking the low-profile server's existence.
- [ ] ISC-S14: The server negotiates an application-layer protocol version with each connecting peer via an APP_HELLO frame exchanged after the TLS 1.3 handshake, inside the encrypted channel; ALPN is a benign HTTP-family value so external observers see only generic HTTPS. Versions follow SemVer 2.0 but the wire negotiates MAJOR.MINOR only. The initiator offers versions in preference order; the responder selects the highest mutual version or rejects with the full supported list. The negotiated version is immutable for the connection's lifetime; MINOR bumps must be additive-only. The frame is uniform across client and server-to-server connections. TLS 1.3 0-RTT (early data) is disabled; APP_HELLO must be exchanged post-handshake.
- [ ] ISC-S15: The server's own cryptographic material is tagged with a `suite_id` (u16) per the suite registry; the default is CNSA 2.0. The server is suite-transparent on CoT relay — it must never inspect, alter, or strip the `suite_id` on relayed CoT payloads (extends ISC-A-S2). During identity-proof verification (ISC-S19) the verifier consults the local registry to match the signer's `suite_id` to a signature algorithm; an unsupported `suite_id` closes the connection with no fallback. Within-family suite migration is per-artifact retag (ISC-C24); cross-family migration is a circle-rekey event (ISC-A-C8).
- [ ] ISC-S16: The server operator may configure per-suite deprecation cutoffs (ISO-8601 UTC timestamps). Before the cutoff, the server accepts identity-proofs under that suite and publishes a signed deprecation-notice record (ISC-S4) so peers can warn the user. At or after the cutoff, it refuses identity-proof verification for that suite, closing with an explicit reason naming the suite, cutoff, and recommended successor. The policy is signed under the server-wide key with a monotonically increasing version (ISC-A-S11). Federation symmetry: a server initiating a peering connection honors the remote operator's published cutoffs.
- [ ] ISC-S17: The server enforces ephemeral, multi-granularity rate limits (OS/kernel per-source-IP layer documented but operator-owned; per-connection token-bucket and budget caps; per-identity-key aggregate caps) to defend against connection-, bandwidth-, subscription-, and compute-flooding. All abuse-tracking state is RAM-only and wiped on restart (ISC-A-S1, ISC-A-S12). Defaults are calibrated for a Raspberry Pi 4 (4 GB) civility floor (ISC-A-C7) and operator-tunable. Limit-trip response is a uniform, non-informative, constant-time protocol close so an attacker cannot deduce which budget was exhausted.
  - rationale: CoT-hash presence detection specifically uses constant-time lookups plus response padding so the relay cannot be turned into a circle-enumeration oracle (ISC-A-S2) — rate-limiting alone is insufficient; constant-time is the load-bearing defense.
- [ ] ISC-S18: The server ships as signed releases — multi-sig ML-DSA-87 (N-of-M threshold) plus Sigstore co-signature, from a reproducible build — and verifies its own signature chain against a bundled trust anchor at startup, refusing to boot on failure. Optionally, an operator may opt in to a read-only update-relay role, republishing recent signed release artifacts as public-space data (ISC-S4) to serve as a censorship-survivable fallback distribution channel; the relay does not authenticate the binaries — verification is the downloading client's responsibility (ISC-A-C11).
- [ ] ISC-S19: A post-HELLO identity-proof phase runs immediately after version negotiation (ISC-S14) on every connection, client-to-server and server-to-server, uniformly. Both peers derive a channel-binding value from the TLS 1.3 exporter (bound to the negotiated version), then exchange a signed envelope carrying `suite_id`, a bookkeeping `role`, the claimed handle, the claimed long-term pubkey, and freshness fields (timestamp + per-key monotonic counter). Verification checks: the handle's hash component matches `SHA-384(claimed_pubkey)[:12]`; the `suite_id` is locally supported; the signature verifies; freshness is within a ±5-minute skew window and the counter strictly exceeds the highest previously seen for that key; trust-mode and suite-deprecation rules apply. Freshness fields ride inside the signed input; the verification path is byte-identical for client and server envelopes — `role` is never an auth branch. On success the connection enters an Authenticated state that gates all application traffic; on any failure it closes with a uniform close-shape (ISC-A-S12).
  - rationale: Binding the signature to the TLS exporter value closes the offline-key-theft replay vector — a stolen long-term key cannot replay a captured envelope in a different TLS session.
- [ ] ISC-S20: The server provides the circle-of-trust live relay — the CoT side of the public-vs-CoT bifurcation (ISC-S4). A daemon subscribes to a circle's rendezvous address `SHA-384(cot_key ‖ server_id)` (derived client-side per ISC-C8; the relay never learns `cot_key`) over a single bidirectional stream, and the relay fans each inbound frame to every other current subscriber. The subscription stream's lifetime is the subscriber's presence; the asset and its routing entry are destroyed the instant refcount reaches zero (ISC-A-S5). Live-only: no store-and-forward, no offline delivery, no reconnect state — a frame sent while a daemon is absent is never delivered. File-share chunks are content-addressed by `SHA-384(chunk)`. Presence detection on a rendezvous address is constant-time (ISC-S17, ISC-A-S12).
- [ ] ISC-S21: A published share's server-assigned `share_id` is drawn from the OS CSPRNG — 128 bits of entropy, lowercase-hex encoded (32 chars) — not from a counter or any order-derived source. Because a share's circle-of-trust fetch-asset derives from its `share_id`, an unpredictable id makes the share's rendezvous address unpredictable, preserving the blind-relay privacy posture (ISC-A-S2). The id is unique in the live registry (collision-retried on draw) and any caller-supplied `share_id` is overwritten (ISC-C19).
- [ ] ISC-S27: A sharing daemon serves its published share's **content** — not only the discovery listing (ISC-S4 / ISC-C19) — by indexing the shared directory into a content-addressed store (one chunk per file, `SHA-384(file-bytes)`; multi-chunk-per-file is post-MVP, additive), deriving the share's circle-of-trust fetch-asset from `(share_id, server_id)` via the same derivation the consumer uses (ISC-S20 / ISC-C8 shape, with the public `share_id` replacing `cot_key`), and answering `ManifestRequest` / `ChunkRequest` frames over a single bidirectional subscribe stream while online. The relay forwards the opaque `ShareFrame` payloads verbatim, never decoding them (ISC-A-S2 holds for the share path as for chat).
- [ ] ISC-S28: Every chunk a fetcher accepts is verified against its content address before use: the fetcher re-derives `SHA-384(chunk-bytes)` and accepts the chunk only if it equals the `chunk_addr` the response advertised. The serve side sources each `ChunkResponse` straight from its content-addressed store, so a faithful serve+relay forward passes verification by construction; a fetcher recovers a multi-file share's bytes end-to-end, byte-for-byte.
- [ ] ISC-S29: One serve loop answers arbitrarily many concurrent fetchers: the relay fans every fetcher's request into the sharer's single subscribe stream and fans the sharer's responses back out, so a sharer need not track per-fetcher state. The flood surface is bounded by the relay's per-connection concurrent-subscription cap and rate limits (ISC-S17), not by sharer-side accounting.
- [ ] ISC-S22: The server hosts interactive public rooms — the public tier of ISC-S4 — over the SAME live relay (ISC-S20) and the SAME `CotFrame` mechanism as a circle. **Any daemon may post; everyone subscribed reads by default.** There is no signer whitelist or operator authorization gate (contrast ISC-S7/S8 announcements). Room content is encrypted under a *global shared key* derived from public inputs (`HKDF-SHA-384(salt = fixed protocol constant, ikm = crypto-family token, info = "daemonseed/public-room/<family>/<room>")`, derived client-side per ISC-C56) which the server and every public-space client hold, so the server is a key-holding party that can read it — but it is encrypted in transit, never wire-cleartext (ISC-A-S2 / ISC-A-S16). A default well-known room ("lobby") exists with no prior coordination.
- [ ] ISC-S23: A public room's rendezvous address is `SHA-384(room_key ‖ server_id)` — byte-identical in shape to a circle's address (ISC-S20), namespaced per relay for cross-server unlinkability. The room therefore rides the existing `CircleOfTrust.Subscribe` relay surface with no relay change: the relay routes blindly by the address its subscribers present and fans out exactly as for a circle.
- [ ] ISC-S24: Each public-room message is self-signed for provenance by the posting daemon's own ML-DSA-87 identity over a domain-separated input binding the room, sender pubkey, timestamp, and body. The signature establishes WHO posted, not that they were authorized to (posting is open, ISC-S22). The whole signed message is then sealed under the global room key (ISC-S22). Open-post does not mean open-forge: a recipient never surfaces a message whose signature does not verify (ISC-A-S17).
- [ ] ISC-S25: A public-room subscriber reads by opening each relayed frame under the global room key and verifying the embedded provenance signature client-side; only verified messages are surfaced. The reader is itself just another subscriber on the same fan-out relay — there is no posting/reading asymmetry at the relay (ISC-S22).
- [ ] ISC-S26: A public room is live-only with no persistent server state, exactly like a circle asset: the room's routing entry exists only while at least one subscriber references it and is reaped the instant refcount reaches zero (ISC-A-S5). A message posted while a daemon is absent is never delivered to it (no store-and-forward).

### Server — anti-criteria (ISC-A-S*)

- [ ] ISC-A-S1: The server binary persists no user identifiers, IP addresses, circle/room memberships, message content, or routing patterns. Carve-outs are operator-authorized, not user data: the signer-pubkey whitelist (ISC-S8) and the content-addressed signed-post directory (ISC-S7) are operator-managed publishing-authority config; the kernel firewall layer's per-source-IP state (ISC-S17) lives in OS structures outside the binary and is operator-owned. Optional ephemeral debug logs must be opt-in, auto-truncated, and exclude all of the above.
- [ ] ISC-A-S2: The public/private distinction is circle-of-trust *membership*. A private circle's key (`cot_key`) derives from a secret phrase the server never holds, so the server is not a member: it sees only sealed CotFrames, presence-at-hash, and refcount changes, and server compromise yields no circle content — no plaintext, no enumeration of circles, no membership list, no participant identity, no notion of "joining." A public space is a CoT whose membership is open and includes the server, so the server holds the key and can read public content; server compromise exposes public-space content, which is public by design (a bounded risk, never to be presented as private). Because both tiers ride the byte-identical sealed CotFrame over the identical Subscribe surface, frame shape and content never reveal whether a subscription is public or private — private use is not betrayed by traffic shape, and public traffic is cover. Caveat: public room/share addresses are publicly derivable, so a *known* public subscription stays identifiable by address-matching; circle addresses and all frame contents remain opaque; message length and timing are not yet padded (future work).
- [ ] ISC-A-S3: The server cannot author or modify announcement posts (ISC-S7) on behalf of a signer. Every post must verify against a current whitelist key; the server's role is verify-and-serve, never originate.
- [ ] ISC-A-S4: Signer-whitelist changes (ISC-S8) are out-of-band only — operator edits the file and reloads. No in-band command can add or remove signers, and a signer being on the list does not grant the ability to modify the list.
- [ ] ISC-A-S4b: The signer whitelist grants no filesystem, configuration, or server-binary access. A compromised signer key does not become a server compromise — the operator's separate host control is the gate for those operations.
- [ ] ISC-A-S5: The server holds no persistent CoT-asset state. CoT assets exist only while at least one subscription stream references them; refcount zero destroys the asset and its routing entry immediately. Public-space configuration may persist in operator config; public-space content lives with the running binary by default.
- [ ] ISC-A-S5b: The server does not enforce, filter, or moderate share content by rating (ISC-S10). Rating is self-classification by the sharing daemon; the server publishes the taxonomy and propagates the tag, never policing it.
  - rationale: Accepted limitation — a mis-tagged share reaches users who filtered against the misapplied tier; ratings are advisory, not verified. This is intrinsic to the no-server-moderation posture.
- [ ] ISC-A-S6: The server cannot detect or infer the trust mode (ISC-C22) of any connecting client. Protocol behavior is identical for trusted-mode and untrusted-mode clients, so a compromised or coerced server cannot enumerate its most-paranoid users.
- [ ] ISC-A-S7: The server does not confirm or deny the existence or peering status of any peer marked `introduce-to-clients = false` (ISC-S13), even when queried by exact server-id, and even from another server. A query about such a peer returns the same response as a query about an unknown peer.
- [ ] ISC-A-S8: The server enforces filesystem-level separation between operator-only config (read-only from the server's perspective) and signer-writable content (the announcement posts directory and the MOTD file). The server never writes to operator-only config at runtime and only writes to signer-writable paths in response to authenticated signer uploads. OS-level permissions reinforce the separation so a compromised signer key cannot reach operator config even given a server-side bug.
- [ ] ISC-A-S9: The server must not silently downgrade APP_HELLO (ISC-S14) negotiation: must not respond with a version outside the initiator's offered set, must not accept 0-RTT early data, must not retain per-pubkey offered-version sets in a fingerprintable way, and must not vary frame shape, ALPN, or 0-RTT posture by connection role.
- [ ] ISC-A-S10: The server must not refuse to relay, store, or surface CoT-asset content based on its `suite_id` (preserves ISC-A-S2 opacity), and must not correlate per-pubkey `suite_id` choices into a profile. It may refuse a federation peering connection (ISC-S12) whose identity-proof uses a deprecated-for-peering suite — identity-handshake policy, not content moderation. It must never reveal one daemon's `suite_id` choice to another (including via timing, errors, or differential rate limits).
- [ ] ISC-A-S11: The server's published deprecation policy (ISC-S16) is signed under the server-wide key with a monotonically increasing version. The server must not change an in-effect cutoff without re-signing and incrementing the version, must not serve a lower policy version than previously served (no rollback), and must not vary the policy by connecting peer — the same signed policy goes to every fetcher so cross-client comparison detects tampering.
- [ ] ISC-A-S12: The server must not persist any abuse-tracking state across restart (extends ISC-A-S1), must not correlate per-identity-key rate-limit observations into a long-term profile, and its response to any rate-limit trip must be uniform across limit types — same close-shape, timing, and lack of payload — so an attacker cannot tell which budget they exhausted. Abuse-trip events must not be logged to disk in a form retaining source identifiers, identity-key hashes, or CoT-asset hashes. Aggregate counters may be exposed via opt-in operator telemetry. CoT-hash presence detection must be timing-uniform regardless of whether the hash is active.
- [ ] ISC-A-S13: When serving artifacts in the update-relay role (ISC-S18) the server must not modify, repackage, or strip them, and must not validate, gate, or refuse them by signature chain — the relay is a dumb pipe and the trust anchor lives exclusively in the downloading client (ISC-A-C11). Operator policy may restrict which artifacts are hosted (content-selection, not signature-validation). The server must refuse to boot any release binary whose own signature fails to validate, must never auto-install upgrades to its own binary, and must not present a relayed artifact as if authoritatively endorsed.
  - rationale: Forbidding server-side validation eliminates the dual-authority failure mode where a coerced operator could be compelled to refuse legitimate binaries during a key rotation, and preserves the property that a relaying server cannot gatekeep the project's own release stream.
- [ ] ISC-A-S14: The server must not accept an identity-proof envelope (ISC-S19) whose signature is not bound to the current TLS session via the channel-binding value — cross-session replays must fail closed. It must not skip channel-binding derivation, substitute a constant for the exporter output, or omit the negotiated version from the exporter context; must not accept an envelope whose handle hash component does not match `SHA-384(claimed_pubkey)[:12]`; must not vary close timing or reason across identity-proof failures (extends ISC-A-S12); and must not cache identity-proof envelopes across connection close.
- [ ] ISC-A-S15: The server must not assign `share_id`s from a monotonic counter or any sequential / order-derived / guessable scheme — a peer must not be able to enumerate the published-share space by walking ids (`0000…`, `0001…`, …). The first id minted in a process is not a fixed constant, and successive ids are not adjacent integers.
- [ ] ISC-A-S20: A fetcher must not accept a chunk whose re-derived `SHA-384(chunk-bytes)` does not equal the address it requested (ISC-S28). A relay or a hostile sharer that tampers with a chunk's bytes in flight — leaving the advertised address unchanged — must fail the fetcher's verification, so falsified content can never be written; the share path's fail-closed posture mirrors the chat envelope's `open_message`.
- [ ] ISC-A-S21: An offline sharer's content is unfetchable. The serve side never fabricates a chunk it does not hold (an unknown `ChunkRequest` yields no response frame), and the relay is live-only (ISC-S20): when the sharer's serve process exits, its subscribe stream closes, the fetch-asset is reaped, and no party remains to answer `ManifestRequest` / `ChunkRequest`. A fetcher of an offline share's content gets no manifest and no chunks — the content is temporarily *unavailable*, never served stale by the relay.
- [ ] ISC-A-S16: Public-room content is never wire-cleartext. A posted message rides the relay as AES-256-GCM ciphertext (sealed under the global room key, ISC-S22); the plaintext body must never appear in any `CotFrame.payload` on the wire. Server-readability (the server holds the global key) is NOT plaintext-on-the-wire — the seal is mandatory even though the relay can open it.
- [ ] ISC-A-S17: A public-room message whose embedded provenance signature (ISC-S24) does not verify under its embedded sender pubkey must never be surfaced to the user. Open-post (ISC-S22) does not weaken to open-forge: a recipient drops a forged-provenance message rather than rendering it.
- [ ] ISC-A-S18: A public-room key must not collide with, or be derivable from, a circle key — the two derivation domains are disjoint (distinct HKDF salt and `info` template), so an identically-named public room and circle phrase yield independent keys. The public tier's server-readability must never bleed into the circle tier's secrecy.
- [ ] ISC-A-S19: A public-room message bound to one room must not verify or open as a message for a different room: the room name is bound both into the provenance signature input (ISC-S24) and into the rendezvous address (ISC-S23), so cross-room replay fails closed.

### Client — positive (ISC-C*)

- [ ] ISC-C1: At enrollment the client HKDF-derives two identity sets from the BIP-39 mnemonic: a primary identity (same on every enrolled device — default presentation in public and external contexts) and a per-device identity (stable for the life of that device — used to distinguish the user's own machines within a circle). Each produces ML-DSA-87 and ML-KEM-1024 keypairs via separate `info` suffixes. The mnemonic is never persisted; daily login uses a session passphrase only. The user controls which identity is presented in any context.
- [ ] ISC-C2: The identity seed is a 24-word BIP-39 mnemonic (256-bit entropy), HKDF-deriving the long-term ML-DSA-87 and ML-KEM-1024 keys via separate `info` strings.
- [ ] ISC-C3: The at-rest blob holds per-domain identity seeds, circle-of-trust seed material, mute/hide lists, and settings, encrypted under AES-256-GCM. The key derives via the two-stage passphrase KDF: Argon2id (salt = profile-id per ISC-C36, work factors per ISC-C14) producing a 32-byte intermediate, then HKDF-SHA-384 expanding it under an artifact-specific `info` string. The same two-stage construction applies to every passphrase-derived key (share index, audit log, recovery file), varying only the HKDF `info`. Seeds decrypt into RAM at login and are zeroed on exit; the mnemonic is never stored. Blob location is configurable.
- [ ] ISC-C4: Every daemon's wire/storage handle is `<display-name>#<first-12-hex-of-SHA384(primary-identity-pubkey)>`. The hash prefix is stable for the life of the primary identity and identical across all presentations. The 48-bit prefix length makes prefix-grinding economically unattractive at federation scale; it is operator-tunable but lowering it is discouraged.
- [ ] ISC-C4a: The default display of a handle is just `<display-name>`; the hash prefix is hidden in normal UIs and surfaces only on hover/long-press (verification), on a display-name collision in the current view (rendered inline to disambiguate), or during a mute/hide/verify action (always rendered to confirm the target). A fully-anonymous presentation (ISC-C13) shows the floor `#<hash-prefix>` because there is no display name — by design, signalling anonymity.
- [ ] ISC-C4b: At enrollment the client offers a random `{adjective}-{noun}` display name from a bundled curated wordlist (combined namespace ≥ 2M combinations so organic collisions are rare). The user may regenerate, override, or leave it empty (floor-handle presentation).
- [ ] ISC-C5: *(Reserved — vacated. When a future client-positive feature lands it takes the next available number rather than reclaiming this slot.)*
- [ ] ISC-C6: The client GUI is one Rust-native framework across all platforms — chosen for Rust-nativity, lightweight binary size (ISC-C11), and declarative markup, with mobile maturity adequate for the daemon's mobile use case (chat participation + remote access to the user's home/work daemon).
  - rationale: ISC-C6 commits to a future GUI client surface; the framework choice and its license posture remain an open question. The MVP gate ships against a terminal client, which is a separate surface and not a stand-in for this GUI commitment.
- [ ] ISC-C7: Optional. The session passphrase (not the mnemonic) may be stored in the platform secure enclave (iOS Keychain / Android Keystore / equivalent) for biometric login. Opt-in only, with an explicit warning that this shifts recovery risk to platform-account compromise.
- [ ] ISC-C8: Circle-of-trust keys derive from shared entropy provided by circle members (≥128 bits estimated). The shared entropy is the sole circle secret and sole distinguisher: `cot_key = HKDF-SHA-384(IKM = canonicalized-entropy, salt = fixed protocol constant, info = "daemonseed/circle/<family>", L = 32)`. There is no per-circle salt and no shared circle name — two circles differ iff their entropy differs. Derivation is anchored on the crypto family, so within-family server suite ratchets leave `cot_key` unchanged; only a cross-family change re-derives (the rekey event of ISC-A-C8). Circle-internal AEAD is AES-256-GCM. The server-side address derives separately as `SHA-384(cot_key, server_id)` (ISC-S4), namespacing the rendezvous per relay for cross-server unlinkability without tying the circle to a server. Circles carry no signed metadata record and no founder; names are client-local labels only.
- [ ] ISC-C9: Circle-of-trust entropy is text only — a passphrase or sentence. Binary inputs are rejected because re-encoding, format conversion, and metadata strip break determinism. Before derivation the input is canonicalized (Unicode NFKC, trim, collapse internal whitespace) and strength-estimated against the ≥128-bit threshold (ISC-C8). The canonicalized entropy is the only text input; the HKDF salt is a fixed protocol constant, so there is no second text input to coordinate.
- [ ] ISC-C10: The client is a fully developed Rust module; the GUI is an API consumer of the module, so others can build clients or run headless. The module API surface is stable enough to support concurrent instantiation.
- [ ] ISC-C11: Clients are lightweight and portable with minimal dependencies and no hard-coded local ports for IPC/control sockets, so multiple instances can coexist.
- [ ] ISC-C12: During enrollment and any passphrase change, a real-time zxcvbn-based strength meter shows estimated entropy with a red→yellow→green indicator; commit is blocked below green (target ≥60 bits). The default offer is a generated diceware-style passphrase guaranteed green; the user may override subject to the meter.
- [ ] ISC-C13: Identity presentation is per-context and user-controlled. In public spaces the user may present as handle-only (`#<prefix>` floor), primary identity, or fully anonymous (no display name, identity-claim chrome suppressed, handle still surfacing as `#<prefix>` for muteability). In circles the user may present as primary (default) or per-device identity. The client never auto-promotes a fully-anonymous presentation to a named one, and never reveals per-device identity in a public space.
- [ ] ISC-C14: Argon2id parameters for the session-passphrase KDF are profile-driven (OWASP-2024 defaults on desktop, calibrated lighter on mobile). The chosen params are persisted in the profile's config and mirrored in the recovery file's cleartext header (ISC-C32) so a clean-device recovery uses the exact params the blob was encrypted under, and are read at every session start. Raising defaults in a later release does not break existing profiles (the blob and its params travel together); migrating a profile to higher work factors is an explicit user-initiated re-key, never silent (ISC-A-C17).
- [ ] ISC-C15: The client maintains a local mute list keyed on the full wire handle (ISC-C4). Muted entries hide chat messages from that daemon in every shared room/circle; the list persists in the at-rest blob and survives reinstall. Mute is unilateral and silent — the muted party receives no signal. UI follows the ISC-C4a display rules so the user knows exactly which handle they muted.
- [ ] ISC-C16: The client maintains a local hide-shares list keyed on the same full-handle format with the same display rules. Hidden entries' file shares are suppressed from share-listing UI. Independent of the mute list.
- [ ] ISC-C17: @mention recognition is client-side only. The client scans decrypted incoming chat for its own full wire handle and renders a local highlight/notification. Recognition keys on the full handle (not the display name alone) so a same-display-name daemon does not falsely trigger. No new server-visible traffic is generated.
- [ ] ISC-C18: @mention typing uses shorthand by default (`@<display-name>`) with autocomplete against handles in the current scope; a single match resolves silently to the full wire handle, multiple matches show prefixes inline for the user to pick. Power users may type the full `@<display-name>#<prefix>` (or `@#<prefix>` for floor handles). On the wire and in recognition the mention always carries the full handle. Mention scope is bounded to streams the recipient is already subscribed to.
  - rationale: Known limitation — display-name collisions an attacker manufactures in a room the legitimate user is not in cannot be auto-disambiguated for the sender; verification rituals (hover-to-check-prefix, sticky known-contacts) are the defense for high-stakes mentions.
- [ ] ISC-C19: When sharing a folder, the sharing daemon assigns a content rating from the active server's published taxonomy (ISC-S10). For public shares the tag travels in the public listing (server-visible); for CoT shares it travels inside the encrypted asset (server-opaque per ISC-A-S2). Clients filter listings by local preference; ratings are self-classification, not enforcement (ISC-A-S5b, ISC-A-C5).
- [ ] ISC-C20: The client supports opt-in autostart via OS-native mechanisms (default off). When enabled it launches the configured profile's headless mode unless GUI autostart is explicitly chosen.
  - rationale: Security trade-off — autostart pins the daemon's primary identity to "online whenever the machine is on," a presence side-channel the user accepts by enabling it; multi-instance support eventually decouples this by allowing autostart of an unlinked instance only.
- [ ] ISC-C21: The share indexer maintains an incremental on-disk index persisted across launches: cold-start runs as a low-priority background task isolated from the network surface (chat, presence, control, and already-indexed fetches stay fully responsive — ISC-A-C7); incremental updates subscribe to native filesystem-event APIs so a single file change is a single-file update, never a share-wide re-walk, with a documented mtime-walk fallback when platform watch limits are exceeded; subsequent launches reuse the persisted (encrypted, ISC-A-C6) index and rescan only mtime/size-mismatched paths; the indexer respects a configurable per-host resource budget and yields aggressively under interactive load. The index storage path is configurable.
- [ ] ISC-C22: Each server entry in the client's configuration carries a per-server federation trust mode, comprising a server-id (ISC-S11) and an address (hostname or raw IP literal, optional `:port`, default 443). Trusted: on first connection the client verifies `SHA-384(presented-key)[:12]` matches the server-id's hash component, then pins the full key; subsequent connections check the pin, and a legitimate operator rotation surfaces a non-blocking, per-server-dismissible notification before the pin updates. Untrusted: the full key must be pre-configured out-of-band and match byte-for-byte; any mismatch (including legitimate rotation) refuses the connection until the user re-imports. Default for new servers is trusted. The server cannot influence or detect the mode (ISC-A-S6). Servers added from an introducer (ISC-S6) are treated identically to manual entry — never auto-trusted from the introduction.
- [ ] ISC-C23: The client verifies APP_HELLO_ACK (ISC-S14) against its own offer: the returned version must appear verbatim in the offered list or the client closes the connection without proceeding to identity-proof (ISC-S19). On a no-common-version rejection it surfaces an actionable upgrade message naming the server-supported versions and does not proceed. "No application traffic before APP_HELLO_ACK" is enforced via the type system where the language supports it (the reference Rust implementation uses a type-state pattern). Offered-version sets are never written to clear log surfaces.
- [ ] ISC-C24: Every cryptographic artifact the client authors carries a `suite_id` (u16) identifying its algorithm bundle: the at-rest blob header, the share-index header, each CoT-asset payload, and each identity-proof signature; handle hashes implicitly inherit the enrollment-time hash function, and changing the hash family is a MAJOR wire-protocol bump (ISC-S14), not a per-artifact bump. The client reads any `suite_id` still supported by the local registry and writes new artifacts under its configurable default-write suite (default: the highest non-deprecated supported suite). At-rest migration is read-old, write-new on touch. A circle's effective suite floor is intrinsic (its `cot_key` crypto family) combined with the server's signed deprecation policy (ISC-S16) and the local registry; there is no per-circle policy or founder.
- [ ] ISC-C25: On each successful connection the client fetches or cache-refreshes the server's signed suite-deprecation policy (ISC-S16), verifies the signature, and rejects any policy whose version is lower than its cached version (ISC-A-S11). Cached policies have a one-hour TTL. For any deprecated suite that intersects the client's default-write suite, identity material, or current circles, the client surfaces a persistent non-blocking warning on every start until the user migrates or dismisses it for that `(suite_id, server-id)`. A `SUITE_DEPRECATED_PAST_CUTOFF` identity-proof response surfaces a blocking error; the client never silently retries under a different suite. When servers disagree on cutoffs for the same suite, the earliest cutoff governs the warning.
- [ ] ISC-C26: The client backs off gracefully on connection refusal or unexplained close (a rate-limit trip is indistinguishable from any other-side disconnect by design): exponential backoff with ±25% jitter, starting at 1 s, doubling, capped at 60 s, for a maximum of 8 attempts per server-id per session before surfacing a "server unreachable or rate-limiting you" message and pausing automatic retries. The UX distinguishes network-level failure, application close before APP_HELLO_ACK, and application close after successful identity-proof, but must never speculate about which specific rate-limit was hit — the close is non-informative by design (ISC-A-S12).
- [ ] ISC-C27: The client ships as signed releases via multiple parallel channels (channel diversity is itself a censorship/coercion-resistance property): managed app stores, libre-software builds, direct signed packages, OS package managers, and an in-app updater. On every channel except OS-package paths the client validates the binary's multi-sig ML-DSA-87 signature against the bundled trust anchor (≥ N-of-M valid signatures), checks Sigstore co-signature as ecosystem confirmation, and verifies the manifest. The in-app updater falls back to a connected server's update-relay (ISC-S18) when the primary endpoint is unreachable, verifying against the bundled trust anchor regardless of source. The client never auto-installs and never silently downgrades; emergency security updates still require explicit user confirmation.
  - rationale: Silent auto-update is the coercion vector a compromised maintainer would use to ship a backdoor — the protocol forecloses it by construction, including for emergency updates.
- [ ] ISC-C28: The client renders all trust-state events according to a uniform affordance taxonomy of exactly four classes — blocking (prevents the affected functional path until explicit action), persistent-non-blocking (reappears every start until resolved or per-event-key dismissed), transient (auto-dismissing informational), and log-only (audit log only). Each event-key has exactly one class; state transitions are modelled as two distinct event-keys, never a transition annotation; sub-classes and combo annotations are forbidden. New trust-state events from future ISCs must be assigned one of the four classes. Event-keys are stable across implementations so per-event-key dismissal carries across upgrades. All non-transient events are recorded in a local trust-event audit log, encrypted at rest under the two-stage passphrase KDF (ISC-C3) with its own HKDF `info` (separate from the at-rest blob and share-index keys); the log is bounded, user-reviewable, and subject to the ISC-A-C1 no-sensitive-content rule. This ISC pins the semantics; visual treatment lives with the GUI framework (ISC-C6), and alternative clients (ISC-C10) follow the same semantic taxonomy.
- [ ] ISC-C29: The first-start sequence orders the experience so identity is verifiably recoverable before any network move: (1) passphrase entry (ISC-C12), (2) BIP-39 mnemonic generation (ISC-C2), (3) at-rest blob initialization (ISC-C3) with Argon2id params persisted (ISC-C14) before any later session reads them, (4) recovery-file backup + verification (ISC-C32/C33) OR skip-file with type-back verification (ISC-C34), (5) display-name assignment (ISC-C4b), (6) bootstrap-relay selection (ISC-C37), (7) first network connection. The ordering is enforced (ISC-A-C15).
  - rationale: Identity-recoverable-before-identity-exposed is the load-bearing invariant — if backup-verify happened after bootstrap, an interruption or coercion between connection and backup-confirm would leave the user network-exposed with no recovery path.
- [ ] ISC-C30: The session passphrase set at first-start is the single credential covering both daily at-rest-blob decryption (ISC-C3) and recovery-file decryption (ISC-C32). The Argon2id stage of the two-stage KDF is shared across both artifacts (same passphrase, same salt = profile-id, same params), and HKDF then expands the intermediate into two distinct keys via distinct `info` strings; the same AEAD applies to both. One credential to remember, two encrypted artifacts, amortizing the expensive memory-hard computation.
  - rationale: Daemonseed's no-long-term-client-history property (identity + federation state + ephemeral caches only — no message, post, or file-content archive) makes "forget passphrase = lose everything" acceptable: total wipe means starting over with a fresh identity, not losing accumulated data.
- [ ] ISC-C31: During first-start, after mnemonic generation, the client displays the 24-word phrase in a copy-friendly form — the full mnemonic visible at once, copyable as a single block, with no progressive reveal that would block copy-to-clipboard. This path is parallel to (not replaced by) the encrypted recovery file, so users who prefer paper, password-manager, or hardware backup can capture the phrase directly. Copy reminds the user that the phrase is the master key for the identity.
- [ ] ISC-C32: The client offers an encrypted recovery file as the default backup path at first-start. Format: a `.dseed` artifact named `identity.dseed`, stored at the profile root (ISC-C35) by default, user-overridable at install time. Contents: the BIP-39 mnemonic only — no derived keys, no settings. Crypto: same AEAD/KDF/passphrase as the at-rest blob (ISC-C30). Layout: a small cleartext header carrying the profile-id (ISC-C36) and the Argon2id params (ISC-C14) precedes the AEAD-protected mnemonic, so recovery on a clean device can derive the correct salt, params, and HKDF `info` without a pre-existing config. The header is unauthenticated by design — tampering with any header value just produces a wrong key and the AEAD fails closed. User-facing copy states where the file is written and recommends an off-device copy.
- [ ] ISC-C33: On the recovery-file path, backup verification is a round-trip decrypt-and-confirm that completes before first-start finishes: the client reopens the just-written `.dseed`, decrypts with the session passphrase, and confirms the contained mnemonic matches the generated phrase. This proves end-to-end on the user's actual system that the passphrase is correct, the file is written readably, the path is reachable, and crypto round-trips. A failed verification surfaces a remedy and blocks completion until it succeeds or the user switches to the skip-backup path (ISC-C34).
- [ ] ISC-C34: Users who decline the recovery file must demonstrate phrase capture by typing back N=3 random words from the displayed mnemonic at cryptographically-chosen positions (not user-chosen, not position-fixed across sessions). This is the only acceptable substitute for the round-trip decrypt of ISC-C33. A user who declines both the recovery file and the type-back cannot complete first-start (ISC-A-C13).
- [ ] ISC-C35: Client binaries resolve their profile root — the directory containing config, at-rest blob (ISC-C3), recovery file (ISC-C32), index DB, and cached state — by priority: `--config <path>` flag (highest); else a config file in the current working directory (CWD becomes the profile root — the tester-grade multi-instance path: `cd alice/ && run`, `cd bob/ && run`); else XDG conventions (with macOS/Windows/mobile equivalents); none of the above triggers first-start (ISC-C29). The config filename is uniform across all discovery paths. The server binary follows operator-specified paths via `--config` only — CWD discovery is a client-side affordance, not a server pattern.
  - rationale: This enables tester-grade multi-instance isolation on a single host, a concrete subset of the full multi-instance support reserved post-MVP.
- [ ] ISC-C36: Every profile has a stable profile-id — a UUID v4 from cryptographic randomness, generated at first-start immediately before at-rest blob initialization, stored in plain text in the profile's config. It is the substituted value wherever the spec writes `<profile-id>` in an HKDF `info` string, and also serves as the Argon2id salt for the two-stage KDF (the two uses are cryptographically independent). The profile-id is non-secret by design — knowing it weakens no key; its purpose is HKDF domain separation between same-machine profiles that may share a passphrase (a foreseeable tester error per ISC-C35). The `.dseed` recovery file carries it in its cleartext header so clean-device recovery can derive the correct `info` without a pre-existing config. A missing or malformed profile-id causes the client to refuse to start and direct the user to recover or re-enroll.
- [ ] ISC-C37: At first-start the client offers exactly two bootstrap-relay paths: default project-canonical relay (server-id + address shipped in a bundled bootstrap-anchor file, added in trusted mode), and manual paste (a server-id + address obtained out-of-band, also added in trusted mode with first-contact hash verification). No third path — no mDNS/DHT/introducer auto-discovery and no "connect without a relay" mode. The chosen relay persists in the profile config.
  - rationale: Manual paste is the relief valve for users in censored regions — the project canonical relay is the single largest target for network-level censorship, so a community-relay bootstrap path distributed out-of-band must always exist. Shipping a default bootstrap-anchor obliges the project to operate the canonical relay as a governance-level commitment.
- [ ] ISC-C56: The client derives the global public-room key client-side from public inputs (crypto-family token + room name; ISC-S22) and the room's rendezvous address as `SHA-384(room_key ‖ server_id)` (ISC-S23). The default chat surface is the well-known default public room ("lobby") — no circle is required to chat; circles are the private opt-in. The room key is global by construction (no secret IKM), so any client computes it without coordination.
- [ ] ISC-C57: When reading a public room the client verifies each message's provenance signature (ISC-S24) and binds the *displayed* author to the handle hash-prefix `SHA-384(sender_pubkey)[:12]` (ISC-C4), trusting the embedded pubkey over the self-asserted `sender_handle`. A handle whose hash component disagrees with the pubkey is shown at its verified `#<prefix>` floor, never under the spoofed display name. When posting, the client self-signs with the user's own identity (ISC-S24).
- [ ] ISC-C58: Public-room abuse is mitigated by the same client-local mute story as circles (ISC-C15): a muted full handle's public-room messages are suppressed locally, unilaterally and silently, on top of the per-connection relay rate limits (ISC-S17). A full ban system is out of scope for the MVP (deferred); mute + rate-limiting is the alpha surface.

- [ ] ISC-C47: The default backup-verification confirmation at first-start (ISC-C29 step 4) is the 3-word random type-back challenge (ISC-C34): pressing the primary confirm action issues `issue_type_back_challenge(OsRng)` and requires the user to type back N=3 cryptographically-chosen words. The full 24-word re-type round-trip (ISC-C33) remains available as an explicit secondary opt-in. Either path is a real demonstration of phrase capture (never a click-through, ISC-A-C13); the change is which one is the default, not weakening the gate.
- [ ] ISC-C48: When no circle is joined, the chat pane states the circle requirement explicitly ("join a circle to chat") rather than presenting a ready-to-send empty state, and the compose box is rendered disabled until a circle is joined. This makes the circle-required precondition visible before the user types, closing the gap between the warning and the actual send behaviour (ISC-A-C26).
- [ ] ISC-C49: First-start persists the at-rest seeds blob (ISC-C3) to the resolved profile root (ISC-C35) on completion. The orchestrator (ISC-C29) produces the blob bytes filesystem-free; the client writes them to `<profile-root>/seeds.blob` so a daily-login Unlock (ISC-C3) can decrypt them on the next launch. The profile config (`daemonseed.toml`, carrying profile-id + Argon2 params + the chosen bootstrap relay per ISC-C37) is written in the same step.
- [ ] ISC-C50: First-start saves the `.dseed` recovery file (ISC-C32) as the default backup at completion: the client writes `identity.dseed` to the profile root (ISC-C35) by default, honouring a user-chosen destination override. The round-trip the recovery-file path verifies (ISC-C33) and this default-save are complementary — verify proves the file is readable; this save is what makes daily recovery possible.
- [ ] ISC-C51: When a profile blob already exists at the resolved profile root (ISC-C35) at startup, the client routes to a passphrase Unlock screen (ISC-C3) — never the enrollment wizard. A correct passphrase decrypts the blob (`storage::seeds::open`), reconstructs the session (re-deriving the identity handle from the recovered mnemonic so the hash prefix is byte-identical to enrollment, ISC-C4), and reaches the main view without the user re-typing the mnemonic. The bootstrap relay persisted at first-start (ISC-C37) is reconnected automatically.
- [ ] ISC-C52: A `--portable` CLI flag forces the current working directory to be the profile root and skips the XDG fallback (extends ISC-C35): a fresh first-start writes its config, at-rest blob, and `.dseed` into the CWD rather than the system location, and an existing `daemonseed.toml` in the CWD is honoured. It is a once-only affordance — after the first run, plain CWD discovery (ISC-C35 path 2) resolves the directory with no flag. `--config` takes precedence when both are supplied. This is the intuitive "make a self-contained portable instance here" verb for a new identity.
- [ ] ISC-C59: The client supports simultaneous membership in multiple circles within a session. Each joined circle is held independently with its own `cot_key` (ISC-C8), rendezvous address `SHA-384(cot_key ‖ server_id)` (ISC-S20), and live `CircleOfTrust.Subscribe` stream. Joining a new circle from entropy (ISC-C8/C9) **adds** to the membership set; it never evicts a currently-joined circle. The membership set is **persisted in the at-rest blob** (ISC-C3, M13 remember-all): each joined circle's entropy and client-local label (ISC-C62) are stored encrypted and silently rejoined on the next Unlock (ISC-C51) without re-typing the phrase. Circle entropy remains non-mnemonic-derivable (ISC-A-C2), so a clean-device mnemonic-only recovery does **not** restore circles — they must be re-entered there. A per-circle "ephemeral" opt-out (do-not-remember) is the deferred B-path; remember-all is the default per the M13 decision.
- [ ] ISC-C60: The client maintains a single active chat surface spanning the lobby (ISC-C56) and the joined-circle set (ISC-C59). The compose box posts to the active surface; a circle, when selected active, takes precedence over the auto-joined lobby (the established `active_chat_surface` resolver, extended to N circles). The user cycles the active circle with ←/→ within the circle pane; the active surface and its label are named in the compose indicator so the post destination is never ambiguous.
- [ ] ISC-C61: The main chat view is split — a lobby pane (always present, top) and an active-circle pane (bottom carousel slot). Every stored chat line carries a `surface` tag identifying its origin (lobby, or a specific joined circle); the lobby pane renders only lobby-tagged lines and the circle pane renders only the active circle's lines. When the membership set is empty the circle pane shows the join prompt (ISC-C48 scope narrows to the circle pane — the lobby pane is always live and postable per ISC-C56).
- [ ] ISC-C62: Each joined circle carries a client-local label (ISC-C8: "names are client-local labels only") assigned at join — a locally-generated default (adj-noun or `#<hash-of-entropy>` floor), user-overridable — shown in the carousel and the compose indicator. The label is never transmitted, never derived from other members, and exists only on this client.

### Client — anti-criteria (ISC-A-C*)

- [ ] ISC-A-C29: A chat line received on one surface must never render in another surface's pane (ISC-C61). The split view's per-pane filter is keyed strictly on the line's `surface` tag; a circle's plaintext must not appear in the lobby pane, nor in any other circle's pane. Cross-surface bleed in the transcript is forbidden.
- [ ] ISC-A-C30: Joining or cycling circles (ISC-C59/C60) must not mix `cot_key`s or sender attribution across circles. A composed post is sealed under exactly the active circle's `cot_key` (ISC-C8 / `seal_message`), and an inbound `CotFrame` is attributed to the single circle whose `cot_key` opened it — never guessed, never broadcast to all panes. Posting to the wrong circle, or attributing a message to a circle other than the one that decrypted it, is forbidden.


- [ ] ISC-A-C1: The client persists no plaintext identifiers, no session-activity logs, no message content, and no recently-contacted lists — only the encrypted at-rest blob (ISC-C3) and a minimal configuration file. Optional ephemeral debug logs must be opt-in, auto-truncated, and exclude identifiers and message content.
- [ ] ISC-A-C2: The BIP-39 mnemonic is the only mechanism for cross-device setup and post-loss/post-passphrase-loss recovery — no server-side recovery, no email reset, no backup service. It exists on the device only transiently and is zeroed from RAM immediately after seed derivation. Circle entropy, though persisted in the at-rest blob (ISC-C59, M13), is **not** derived from the mnemonic; a mnemonic-only recovery on a clean device therefore does not restore circle memberships — this preserves the invariant that the mnemonic alone never reconstructs the social graph.
  - rationale: Real limitation — the mnemonic regenerates the identity seeds but not the circle-of-trust seeds (user-chosen entropy not derivable from the mnemonic), so recovery via mnemonic alone regains identity but loses circle access unless the circle passphrase is retained separately. This is intentional (circles are shared secrets, not personal-recovery surface) and must be told to the user at enrollment.
- [ ] ISC-A-C3: Mute lists (ISC-C15) and hide-shares lists (ISC-C16) never leak to the server — no enumeration, no presence-by-prefix, no per-prefix analytics. The server cannot tell whether one daemon has muted another.
- [ ] ISC-A-C4: The @mention feature (ISC-C17) introduces no new server-visible distinction beyond what regular chat already exposes — no mention-index, no server-side notification dispatch, no membership inference.
  - rationale: Honest scope — existing chat side-channels (length, timing, burstiness) are unchanged and may still statistically distinguish mention-bearing messages; closing those channels is separate scope.
- [ ] ISC-A-C5: The client never auto-shares content from a rating tier the user filtered out and never auto-fetches the ciphertext of a filtered share until the user explicitly opts in. Filtering is render-time and fetch-time, not just visual.
- [ ] ISC-A-C6: The share index (ISC-C21) is never persisted in plaintext — it is encrypted under the two-stage passphrase KDF with its own HKDF `info`, separate from the at-rest blob key. Index ciphertext yields no filenames, sizes, paths, or content hashes to an offline attacker.
- [ ] ISC-A-C7: The daemon — and the share indexer (ISC-C21) specifically — must never make the host unusable for other work. Locked-out failure modes: gating any user-facing function on indexing completion; failing the "civility" floor on Raspberry Pi 4 (4 GB, USB-3 storage)-class hardware even under a worst-case cold-index of a multi-terabyte share; share-wide rescans on single-file changes (even under platform-event-limit pressure); silent unbounded work (any worse-than-O(changed-paths) work must be user-visible and cancellable); and fate-sharing between the indexer and the network surface (separate task budgets so the indexer cannot starve the network task).
- [ ] ISC-A-C8: The client must not display, write, or auto-accept content encrypted under a `suite_id` below the circle's effective floor (the `cot_key` crypto family per ISC-C8 combined with the server's signed deprecation policy per ISC-S16 and the local registry; no per-circle `min_suite_id`, no founder). Sub-minimum content surfaces a deprecated-suite warning at render time requiring explicit user action, with the exception recorded locally. The client must not write new artifacts under a `read-only-deprecated` suite. Cross-family migration is treated as a new-circle event (a "create a new circle to migrate" UX), not in-place rekeying.
  - rationale: In-place cross-family migration would require simultaneous re-derivation by every active member, which needs a synchronization primitive the protocol does not yet have.
- [ ] ISC-A-C9: The client must not silently bypass, dismiss, or work around a server's announced suite-deprecation cutoff (ISC-S16, ISC-C25). The persistent warning surfaces on every start while a notice is active, dismissible only per `(suite_id, server-id)`. The client must not auto-rotate identity material to escape a cutoff (migration is always explicit), must not treat a missing/unparseable/signature-invalid policy as permission to use any suite (it falls back to the local registry with no auto-downgrade), and must not skip a policy fetch when the cached policy is past its TTL. Offline acceptance of stale cached policies is forbidden.
- [ ] ISC-A-C10: The client must not silently rotate identity keys to circumvent a server rate limit (ISC-S17) — switching identity is always explicit. The client must not exceed a small documented per-server concurrent-connection cap (default 4) so legitimate clients do not present as an attack pattern to a low-powered operator, and must not cache or pre-emptively replay identity-proofs, CoT-subscriptions, or signed-post submissions across connection-close in a way that intensifies reconnection load — the ISC-C26 backoff applies before any retry, and the retry uses a freshly-derived identity-proof signature.
  - rationale: Accepted limitation — these are reference-client commitments, not enforceable against a hostile non-conformant client; Sybil resistance proper is deferred.
- [ ] ISC-A-C11: The client must not install any release binary whose multi-sig ML-DSA-87 signature fails the bundled trust anchor's N-of-M threshold (sub-quorum, unknown keys, or expired anchor keys are all hard refusals). It must not auto-install any update — including emergency security updates — without explicit user confirmation, must not silently downgrade to an older signed version (downgrades surface as explicit user decisions), must not cache/persist/replay update payloads after a verification failure (failed artifacts are wiped immediately, the failure logged within ISC-A-C1 limits), and must not trust a server-relayed update (ISC-S18) any more than any other channel — the trust anchor is the project release-signing key, never the relaying server.
  - rationale: Silent auto-update is the coercion vector a compromised maintainer would use to ship a backdoor before users notice.
- [ ] ISC-A-C12: The client must not silently suppress any trust-state event in ISC-C28 — every non-transient event is logged and surfaces at its assigned class (except log-only). It must not permit global dismissal of a persistent-non-blocking class (dismissal is always per `(event-key, scope)`), must not degrade a blocking event to a lower class via preference/config/"expert mode", and must not ship a "disable security warnings" or "skip blocking prompts" toggle. It must not retain ISC-A-C1-forbidden data in the audit log, must not export the log out-of-band (no telemetry, remote reporting, or crash-dump inclusion), and must not skip the audit-log entry for any non-transient event even when the user dismisses the affordance.
- [ ] ISC-A-C13: First-start must not complete on a passive "I have saved my phrase" checkbox — backup verification must be demonstrably performed via the round-trip decrypt (ISC-C33) or the type-back (ISC-C34). A click-through that does not demonstrate phrase capture is forbidden, including any hidden "let me skip this" toggle.
  - rationale: Checkbox-only paths produce users who lose their seed phrase and blame the software; the no-long-term-history property softens recovery loss but does not justify the foot-gun.
- [ ] ISC-A-C14: The first-start sequence is purely local — no network connection except the explicit first connection at ISC-C29 step 7. The client must not upload the mnemonic, the recovery file, the at-rest blob, the session passphrase, or any derived key material to any remote endpoint as part of install or first-start. No cloud backup, no telemetry, no analytics.
  - rationale: Cloud backup of seed phrases is privacy-hostile in this threat model; introducing a server-side attack surface for the most sensitive artifact contradicts the architecture. The user's own deliberate off-device copying of the recovery file is explicitly different — that is the user moving an artifact they already own.
- [ ] ISC-A-C15: First-start must not initiate any network connection — including the first bootstrap-relay connection — until backup verification has succeeded (ISC-C33 or ISC-C34). The bootstrap decision and any network resolution it requires are deferred to ISC-C29 step 7, after backup-verify.
  - rationale: If the bootstrap connection happened before backup-verify, an interruption or coercion at that moment would leave the user network-exposed under an unrecoverable identity — backup-first ordering preserves the "identity recoverable before identity exposed" invariant.
- [ ] ISC-A-C16: The client must not derive the profile-id (ISC-C36) from any user-visible or filesystem-derived input (display name, path, hostname, username, mnemonic, passphrase) — it must come from cryptographic randomness alone. It must not proceed with per-profile key derivation when the profile-id is empty/missing/unparseable, must not silently regenerate or rotate the profile-id during a profile's life (rotation is profile re-initialization, not continuation, and a detected change should surface a warning), and must not include the profile-id in any out-of-band log, telemetry, or crash-dump.
- [ ] ISC-A-C17: The client must not use a constant or environment-derived value as the Argon2id salt — the salt is the profile-id (ISC-C36) and only the profile-id, itself from cryptographic randomness (ISC-A-C16). It must not silently change a profile's persisted Argon2 params mid-life (param change is profile re-initialization; migration is an explicit user-initiated re-key re-encrypting both blob and recovery file), must not omit the Argon2 params from the `.dseed` cleartext header (their absence must fail recovery closed rather than fall back to current defaults and risk silent data loss), and must not share Argon2 params across profiles via a shared file.
- [ ] ISC-A-C18: The client must not accept a server identity-proof envelope (ISC-S19) whose signature is not bound to the current TLS session via the channel-binding value — captured envelopes from earlier sessions must fail closed. It must not skip the handle-pubkey hash verification (anchors ISC-C4's self-verifying-handle property), must not proceed past a verification failure with partial trust ("almost valid, tentatively continue" is forbidden — failed identity-proof closes unconditionally), and must not speculate to the user about which specific check failed (the close-shape is uniform by design per ISC-A-S12).
- [ ] ISC-A-C19: The client must not attempt zero-config bootstrap-relay discovery at first-start (ISC-C37) — no mDNS, DHT, broadcast probe, or introducer-without-a-relay handshake; the two paths in ISC-C37 are exhaustive. It must not proceed past first-start with zero configured servers, and must not silently substitute a default relay different from the bundled bootstrap-anchor — binding the default to the binary is the integrity guarantee, so any divergence implies tampering and the client must refuse rather than fall back to a runtime-overridable value.
- [ ] ISC-A-C26: With no circle joined, the client must not append the composed message to the local transcript and must not transmit anything when the send action is invoked — Enter is a strict no-op (ISC-C48). A false local echo that makes an unsent message look sent is forbidden: the message never left the machine, so it must not appear in the user's own transcript. The composed draft may be preserved, but it must not masquerade as a posted message.
- [ ] ISC-A-C27: "Back"/Esc on the main view must never strand the user at the enrollment wizard (ISC-C29) — it routes to a logged-in menu or confirm-disconnect, never to the cold first-start flow that would prompt re-enrollment or seed re-entry. Disconnect drops to the daily-login Unlock screen (ISC-C51), not the enrollment wizard.
- [ ] ISC-A-C28: First-start (ISC-C29) must not silently overwrite an existing profile blob (ISC-C3) at the resolved profile root (ISC-C35). An existing-profile launch routes to Unlock (ISC-C51) rather than enrollment; a re-run of first-start against a root that already holds a blob requires an explicit user confirm before any overwrite, and absent that confirm fails closed rather than destroying the existing identity.

### Direct messaging (ISC-C38–C46 / ISC-A-C20–A-C25) — alpha2 scope, deferred from MVP

The direct-messaging family is deferred from the MVP gate to alpha2. The MVP terminal client ships without DM; users who want 1-to-1 private conversation in the interim use a 2-member circle-of-trust with a shared phrase (ISC-C8). The family is captured here so the alpha2 implementation has a frozen target. These ISCs take **permanent main-line IDs from conception** (C38–C46 / A-C20–A-C25) — deferral is signalled by this subheading and the Out of Scope section, never by a separate ID namespace, so the IDs are stable from now forward and are never renumbered when the feature ships. This follows the precedent of the first-start family (ISC-C29–C37), which was folded into the main client line the same way. The family extends the unified CoT mechanism (one subscribe RPC, one frame, one envelope codec) to one more asset kind: a 2-member private channel keyed by a per-session ML-KEM-1024 shared secret rather than a shared phrase.

- [ ] ISC-C38: A direct message is a circle-of-trust circle of exactly two members where the asset-routing key derives from a per-session ML-KEM-1024 encapsulation rather than a shared phrase (cf. ISC-C8). The wire mechanism is byte-identical to a chat circle (same subscribe RPC, frame, and AES-256-GCM-sealed envelope), so relay opacity (ISC-A-S2) and refcounted reaping (ISC-A-S5) hold structurally.
- [ ] ISC-C39: DM session keys are ephemeral and live-only. A fresh ML-KEM encapsulation produces a new shared secret per session; the derived `dm_key` never persists past disconnect of either party, and the asset is reaped at refcount zero. There is no message queue at any layer and no offline delivery — the daemon's complete-teardown-on-shutdown property extends to DMs without exception.
- [ ] ISC-C40: `dm_key = HKDF-SHA384(ikm = ss, salt = NULL, info = "daemonseed/dm/v1/" || server_id, L = 32)` where `ss` is the 32-byte ML-KEM-1024 shared secret; `dm_asset_address = SHA-384(dm_key || server_id)` — the same derivation shape as a chat circle (ISC-C8), with `dm_key` in the role of `cot_key`. Both parties derive byte-identical values from the same `ss` and meet at the same opaque relay rendezvous.
- [ ] ISC-C41: The HELLO envelope is the first-contact handshake. Each daemon subscribes to a per-handle inbox channel `inbox_addr = SHA-384("daemonseed/dm/inbox/v1" || handle_bytes || server_id)`; anyone who knows the recipient's handle can publish to it. A HELLO carries the initiator's handle, full ML-DSA-87 and ML-KEM-1024 pubkeys, a nonce, a signed timestamp, and an ML-DSA signature over all of it. HELLO is plaintext on the wire (no recipient key material exists yet). The recipient verifies the handle binds to the pubkey (ISC-C4) before surfacing it as a contact request.
- [ ] ISC-C42: The ACCEPT envelope closes the handshake. If the recipient accepts, they encapsulate against the initiator's ML-KEM pubkey to produce `(ct, ss)`, derive `dm_key` (ISC-C40), subscribe to the resulting address, and publish ACCEPT (carrying their handle, pubkeys, the ciphertext `ct`, and an ML-DSA signature). The initiator decapsulates `ct`, derives the same `dm_key`, subscribes to the same address, and the session is live. If the recipient ignores or rejects the HELLO, no ACCEPT is sent and the initiator times out — no queued state at any layer.
- [ ] ISC-C43: The RESUME path avoids the inbox after first contact. Once two parties have completed at least one HELLO/ACCEPT and cached each other's ML-KEM pubkeys (ISC-C44), either may publish a RESUME envelope to `resume_addr = SHA-384("daemonseed/dm/resume/v1" || sort(initiator_kem_pk_hash, responder_kem_pk_hash) || server_id)` — derivable only by parties holding both pubkeys, so eavesdroppers cannot subscribe. RESUME carries only a fresh encapsulation ciphertext; the responder decapsulates and the session proceeds as ISC-C42's tail. RESUME envelopes never persist.
- [ ] ISC-C44: The contact cache lives in the at-rest blob — a `contacts` map keyed by full wire handle holding each contact's ML-DSA-87 and ML-KEM-1024 pubkeys and first/last-session timestamps, encoded as additive directive lines parallel to mute/hide (ISC-C3). It enables the RESUME path across restarts and a contact list in the UI. Contacts hold only public information, but the binding of those public values to the local user's handle is sensitive social-graph metadata and is therefore encrypted at rest under the same passphrase that protects mute/hide.
- [ ] ISC-C45: First-time contact UX is explicit-accept. A HELLO from an unknown handle surfaces as a contact request the user must explicitly accept; accepting sends ACCEPT, opens the session, and inserts a cache entry for future RESUME. Ignoring or rejecting leaves no trace. A HELLO from a known handle whose ML-KEM pubkey matches the cache is auto-accepted (the cached pubkey is the trust anchor); a known handle presenting a different pubkey surfaces as a trust event ("known handle, new key — possible rotation or impersonation") routed through the ISC-C28 taxonomy.
- [ ] ISC-C46: The block list is the DM revocation primitive — a `blocked_handles` set parallel to mute/hide (ISC-C15/C16). Blocking a handle yields three behaviors: HELLO suppression (dropped silently at the inbox before surfacing — same unilateral, silent posture as mute), RESUME suppression (the daemon stops subscribing to the blocked party's resume address, so their RESUME finds no subscriber and the blocked party cannot distinguish "blocked" from "offline"), and active-session termination (any open DM ends and its `dm_key` is zeroed). The cache entry is preserved — block is reversible; fully severing (requiring re-HELLO) is a distinct, more destructive cache removal. Mute (ISC-C15) stays scoped to chat-circle render suppression and does not affect DM channels.
- [ ] ISC-A-C20: The relay never sees DM content. The frame payload riding on `dm_asset_address` is sealed under `dm_key`; ISC-A-S2 holds the same way it does for chat circles.
- [ ] ISC-A-C21: No DM message queue, no offline delivery, no later replay. A HELLO published while the recipient is offline is dropped at the live-only relay; the initiator sees a timeout, not "queued." Returning online delivers no past message because none exists.
- [ ] ISC-A-C22: HELLO/ACCEPT/RESUME identity forgery requires the sender's ML-DSA-87 private key. Each envelope's signature binds the claimed handle to the actual signing key via the handle's hash prefix (ISC-C4), so an attacker registering a similar-looking handle cannot impersonate someone else.
- [ ] ISC-A-C23: HELLO and ACCEPT envelopes carry visible metadata — honest scope. They are plaintext at first contact because no shared key material exists yet, so the relay (and any observer subscribed to a per-handle inbox) sees the timestamps and claimed sender handles of incoming HELLOs ("alice tried to contact bob at time T") but not content. After ratcheting to `dm_key`, all subsequent activity is sealed. Future mitigations (mixnet, dummy traffic, padded broadcast) are post-alpha2; alpha2 accepts the first-contact metadata leak as a documented limit.
- [ ] ISC-A-C24: The `resume_addr` derivation requires both parties' full ML-KEM pubkeys, neither of which is on the wire except inside signed envelopes addressed to specific parties. An observer without those pubkeys cannot derive the address or subscribe. After first contact, all DM activity is invisible to the relay beyond the traffic-analysis side channels common to all CoT subscriptions.
- [ ] ISC-A-C25: The contact cache (ISC-C44) never leaves the at-rest blob. No wire message carries any portion of a user's contact list, and the relay cannot enumerate a user's contacts. Pubkey exchanges happen only via direct, signed HELLO/ACCEPT envelopes between the two parties involved.

## Test Strategy

| surface | check | tool / probe |
|---------|-------|--------------|
| Per-ISC coverage | each MVP spec ISC has ≥1 registered integration test | `cargo xtask isc-coverage` (registry: `crates/daemonseed-integration-tests/src/isc_coverage.rs` — its `TOTAL` is the canonical ISC count; never hand-copied elsewhere) |
| Format | no unformatted code | `cargo fmt --all --check` |
| Lint | zero warnings | `cargo clippy --workspace --all-targets -- -D warnings` |
| Tests | all green | `cargo test --workspace` |
| Wire codegen | committed snapshot matches | `cargo xtask check-proto` |
| MVP gate | 4-daemon end-to-end scenario passes | `cargo xtask mvp-gate` (portable-pty harness, 8-step transaction) |
| Anti-criteria | forbidden states fail closed | negative fixtures: replay, clock-skew, counter-rollback, handle-mismatch, uniform-close |
| Censorship survivability | first TLS record is generic-HTTPS-shaped on :443 | wire-shape fixtures (negative-allowlist model) |
| Resource floor | viable on Raspberry Pi 4 (4 GB) | Pi-4 bench |

The mechanized probe of record is `cargo xtask isc-coverage`, and the integration-test registry
(`isc_coverage::TOTAL` / `ISCS`) is the single source of truth for the ISC count and for what "covered"
means. No other file carries a hand-written ISC count. **Known coverage debt** (tracked follow-up): the
`covered` figure xtask reports is still a static lower-bound floor (`xtask::COVERED_ISCS`); a live tally
that walks the per-milestone `Coverage::register` calls is the deferred replacement. The denominator
(`TOTAL`) is no longer duplicated — xtask imports it from the registry crate.

## Features

Work decomposes into **milestones**: one milestone is one PR (multiple commits),
one SSH-signed release tag from M4a onward, and — for MVP-affecting work — a pass
of the 4-daemon end-to-end gate (`cargo xtask mvp-gate`; the Definition-of-Done
lives in `## Test Strategy`). The atomic unit of a feature is an ISC (`## Criteria`);
a milestone bundles the ISCs whose end-states it delivers.

This section is intentionally **not** a milestone roadmap or status table. That
history rots the moment it is hand-maintained in two places, so it lives only
where it cannot drift:

- **Shipped history** (which milestone delivered what, at which tag) →
  the SSH-signed **git tags** and **`CHANGELOG.md`** at the repository root.
- **Live ISC coverage** (how many ISCs are exercised) →
  `cargo xtask isc-coverage` (registry: `crates/daemonseed-integration-tests/src/isc_coverage.rs`).
- **In-progress / next-milestone** (planning) →
  the project lead's vault manifest (not committed to this repo).

The ISA is the frozen contract — Problem, Vision, Principles, Constraints,
Criteria, Out of Scope — that every milestone must honor. *What* shipped and
*when* is history; this file is about what must always hold.

## Decisions

- 2026-06-05: **M13 persistence keystone — remember-all (A) over per-circle opt-in (B) (caraka).** The
  at-rest blob now persists display name (ISC-C4b), mute (ISC-C15), hide (ISC-C16), and **circle
  membership** (ISC-C59: entropy + label) via a session write-through, so a daily-login Unlock stops
  forgetting them. The trust-boundary fork was whether to persist *every* joined circle's entropy by
  default (A — friction-free returning daemons, larger seized-blob surface) or only user-pinned circles
  (B — precautionary, but default still "forgets"). caraka chose **A for alpha** ("see if the daemons
  share my paranoia; we can add B if users request it"), explicitly accepting the larger at-rest surface;
  B (a per-circle "ephemeral" opt-out) stays a fast-follow. This revises **ISC-C59** (membership is now
  persisted, not session-scoped) and clarifies **ISC-A-C2** (entropy persists in the blob but stays
  non-mnemonic-derivable, so mnemonic-only recovery never reconstructs the social graph). **Backward
  compat waived during alpha (caraka)** — no blob-format migration; new `name`/`circle` directive lines
  are additive and existing testers re-enroll if needed. **Design pins:** circle entropy + label stored
  as hex-encoded directive lines (space/newline-safe); a cached `SealingKey` re-seals on each mutation
  with no second Argon2id (Pi-4 floor would stall ~1-2s otherwise); `CircleJoined` echoes the entropy
  in-process so rejoin pairing needs no fragile dispatch-ordering; persisted label (ISC-C62) wins over the
  actor-supplied label on rejoin. **Scope split:** Batch 1 (this PR) = write-through + name/mute/hide +
  circle persist/rejoin; Batch 2 = circle-rename UI (ISC-C62 override) + own-share-definition persistence
  (ISC-C21). **Delegation:** primary did the core crypto + net-actor design; bounded TUI wiring delegated
  to in-place general-purpose agents (never Engineer — worktree-isolation bug; no new worktrees), each
  diff reviewed + gates re-run by the primary.

- 2026-06-03: **M12 finish authorized as a full unattended run, incl. release (caraka).** Data-SIM
  connectivity restored, so the network-gated release path is reachable. caraka authorized the complete
  run end-to-end: build the remaining surface, trip the full 8-step gate, advance coverage + doc-sync, then
  **ff-merge `feat/m12`→`main`, SSH-signed `v0.14.0` tag, push, PR #18, declare MVP** — all unattended.
  Hard abort condition: release only if the gate is green and the AGENTS.md DoD passes. **Step-6 scope
  decision (caraka, 2026-06-03): surface introducer-discovered candidates in the TUI Servers pane and
  PTY-drive it like the other panes** — chosen over "session-level test is enough" / a `cli introducer`
  subcommand. This adds a small MVP client-UI surface beyond the M11→M12 handoff's minimal lean: the
  Servers pane gains a refresh action (`NetCommand::RefreshIntroducer` → `session.refresh_introducer` →
  `NetEvent::IntroducerSnapshot`) and renders each candidate as `server-id  address` (no key bytes,
  ISC-S6/A-C19), with promotion staying the explicit user action. **Delegation approach:** primary
  orchestrates; bulk editing + cargo loops delegated to non-isolating general-purpose agents working
  directly in the existing `feat-m12` worktree (never Engineer — worktree-isolation bug; never spawning new
  worktrees), serial because the feature is tightly coupled. Mode/tier: classifier E3; honored, with the
  scope expansion logged here (the run is E4-sized but mechanically follows the existing 3-pane pattern).
- 2026-06-01: **H2 `PublishShare` — RAM-only, connection-reaped, owner-scoped, blind-relay (gate step 5).**
  M12 has no dedicated `ISC-38`; the user-publish wire surface was designed against the existing ISCs.
  Forced choices: **RAM-only** (ISC-A-S1 — a published share is user data, not an operator carve-out, so it
  is never persisted; it lives in process memory and is **reaped on disconnect**, mirroring the CoT live
  relay's model); **server-assigned opaque `share_id`** (the M6 `PublicShareListing` doc already specifies
  "opaque server-scoped identifier"); **self-asserted `sharer_handle`** relayed verbatim and **not bound to
  the connection's authenticated identity** (M6 doc + ISC-A-S5b — the relay is a blind forwarder, never
  polices); the RPCs extend the existing **`PublicSpace`** service (additive). Decision (caraka,
  2026-06-01): **`PublishShare` + `UnpublishShare`** (not publish-only) so a daemon can stop sharing one
  folder without dropping the connection. `UnpublishShare` is **owner-scoped** — an unknown or other-owned
  `share_id` is a silent no-op, so the relay never reveals another connection's share ownership (ISC-A-S1).
  Implementation: `daemonseed-server::share::SharePublishRegistry` (RAM-only, per-connection owner token) +
  `ShareReapGuard` (reaps on connection close, every exit path incl. panic); `ListPublicShares` now serves
  the live registry. Additive SemVer **MINOR** (wire version stays 1.0). Server half shipped on `feat/m12`
  (proto + registry + handlers + reaping + over-the-wire publish/list/unpublish test); TUI/cli publish UX +
  the full mvp-gate step-5 wiring are the next increment.
- 2026-06-01: **Introducer refresh is precautionary — discovered peers are candidates the user promotes,
  never auto-trusted (ISC-C22 / ISC-A-C19).** The spec settled the *trust semantics* of an
  introducer-discovered server ("treated identically to manual entry — never auto-trusted from the
  introduction", ISC-C22) but left the *refresh behaviour* open: when the client calls a relay's
  introducer, does it auto-add every discovered peer to the active trust set, or surface them as
  candidates? **Decision (caraka, 2026-06-01): candidates.** `daemonseed-core::federation::discovered`
  holds a RAM-only `DiscoveredPeers` cache, structurally distinct from the `TrustStore`; `merge()`
  records candidates and reads `known` only to skip already-configured servers — it **never writes the
  trust set**. `promote_trusted` / `promote_untrusted` are the explicit user actions that move a
  candidate into the active set (the key is then established by first-contact hash verification or an
  out-of-band key, identical to a manual paste). Rationale: auto-adding would let a relay you connect to
  populate your active server list with addresses it controls and silently get its own key TOFU-pinned —
  exactly the transitive-trust hole ISC-S6's no-keys invariant and ISC-A-C19's anti-auto-discovery bias
  exist to close. The precautionary option keeps discovery and trust strictly separated at every point in
  the client lifecycle, not just at first-start. Client half shipped on `feat/m12` (AppSession
  `introducer()` + `refresh_introducer()`, over-the-wire test). Completes the **H1 client refresh
  surface** (gate step 6); the wire endpoint (H1 server half) shipped earlier this day.
- 2026-06-01: **M12 kicked off on `feat/m12`** (worktree at `.worktrees/feat-m12`, based on `main`
  449206a). Scope = two halves under **one** additive SemVer MINOR bump → **v0.14.0**, the moment both
  land the full 4-daemon MVP gate trips and the **MVP is declared**: **H1 (gate step 6)** federation
  introducer endpoint — additive gRPC RPC over the already-shipped `IntroducerQuery`/`IntroducerResponse`
  messages + `introducer_response()` builder (verified present on base) + its client refresh surface;
  **H2 (gate step 5)** `PublishShare` — new RPC + server handler + TUI publish surface (verified absent on
  base, as expected). Sequencing **H1-first** (smaller/additive warm-up validating the gate harness +
  version-bump plumbing), then H2; coupling is low (federation discovery vs user-content publish) and the
  gate trips only on both, so ordering is risk/momentum only. **Coding approach: primary-drives-directly**
  on the `feat/m12` worktree — the halves are sequential so worktree isolation buys nothing; the
  Engineer-isolation bug stays **deferred** (do not delegate in-worktree edits to `Engineer`; a single
  non-isolating general-purpose agent per half, strictly serial, is the only sanctioned delegation). The
  orphan Engineer-isolation worktree (branch `worktree-agent-a5f26bed24e95a65d`, tip `ad9b520`, zero
  unmerged commits) was purged as part of this kickoff. Single MINOR bump + changelog land **after** both
  halves, never per-half. (refined: advisor-reviewed at the kickoff commitment boundary.)
- 2026-06-01: **Clean-device recovery shipped (gate step 8 — ISC-C29 recover branch / C30 / C32 / C36 /
  A-C2).** Recovery is the mirror of cold first-start: `FirstStart::<Welcome>::recover(mnemonic, passphrase,
  argon)` accepts a phrase the user already holds instead of generating one, and lands directly in
  `BackupVerified` — backup is verified-by-possession, so the C33/C34 backup-verify steps are skipped —
  rejoining the shared `finalize` / `into_session_materials` tail. The TUI exposes **both** input paths
  (caraka's call 2026-06-01): typed 24 words, or an `identity.dseed` file decrypted with the passphrase;
  both converge on one phrase, so the core flow is source-agnostic. The recovered device mints a **fresh
  local `profile_id`** (C36) and re-seals its own at-rest blob + `.dseed` under it, yet the identity is
  **byte-identical** to the source device: the ML-DSA-87 / ML-KEM-1024 keys and handle derive from the
  mnemonic alone via fixed HKDF `info` strings, independent of `profile_id`. This is the load-bearing fact
  — recovery is identity-from-mnemonic, and the profile is just local scaffolding around it. Circle-of-trust
  seeds are **not** recovered (A-C2: user-chosen entropy not in the mnemonic), surfaced in the recover UI
  copy. Failure paths fail closed and stay on-step (bad BIP-39 checksum, wrong `.dseed` passphrase, weak new
  passphrase); a fresh `Welcome` per recover attempt means a wrong passphrase costs only a retry, never the
  session. The cold-enrollment path is byte-identical to before — gate steps 1/2/4 unaffected. The gate test
  `fresh_daemon_recovers_identity_from_mnemonic` models real device loss: daemon A enrolls → chats → is
  dropped → a fresh daemon B recovers from A's captured mnemonic → B's own `#<12hex>` floor handle must equal
  A's (identity observed via the floor-handle self-echo, comparable across devices because both pick the
  floor handle). **With step 8 done, the narrowed M11 (gate steps 7 + 8) is complete → v0.13.0.**
- 2026-05-30: **Introducer endpoint deferred M11→M12; M11 scope = gate steps 7 + 8 only.** While resuming
  M11, investigation found the federation introducer was never wired to the socket in M5. The
  `IntroducerQuery` / `IntroducerResponse` messages, the `introducer_response()` builder, and operator
  peer-config all shipped — but there is **no endpoint**: no gRPC RPC and no post-auth frame handler. The
  entire post-Authenticated surface is tonic gRPC (`PublicSpace` + `CircleOfTrust`); `IntroducerQuery` is
  referenced only inside `federation.rs` (builder + its unit tests), never read off a socket. So gate
  step 6 (introducer refresh) was never "client-only over already-shipped server APIs" as the 2026-05-29
  Path-2 scope assumed — completing it necessarily adds protocol surface. **Resolution:** the introducer
  endpoint (an additive gRPC RPC reusing the shipped messages) + its client refresh surface + gate step 6
  move to **M12**, riding the single additive MINOR bump already planned there for `PublishShare` — one
  reviewable wire change instead of two, and M11 stays literally wire-clean. M11 now delivers only the
  genuinely no-wire surfaces: **step 7** (deprecation-policy fetch + trust-event surfacing over the
  shipped-and-served `GetDeprecationPolicy` RPC) and **step 8** (clean-device recovery, first-start
  TUI-only branch). The full 8-step gate still trips only at M12/v0.14.0, so the move costs nothing —
  v0.13.0 never claimed a full gate pass. Approved by caraka 2026-05-30.
- 2026-05-30: **Effort-tier note:** this resume ran under ALGORITHM E3 via conversation-context override —
  the UserPromptSubmit classifier tagged the short approval messages MINIMAL/MINIMAL, but in thread
  context they greenlit a multi-file milestone build. Delegation-floor (E3 soft ≥2) relaxed: work is
  driven directly by the primary because the investigation context is already loaded, the patterns to
  mirror (public-space client surface; first-start orchestrator) are in-repo, and the degraded tool-output
  channel makes subagent-output coordination unreliable this session.
- 2026-05-30: **Step-7 deprecation surface — version-gated trust-event emission (ISC-C25 / C28).** The
  warning *panel* (`DeprecationWarningRow` rows) is the always-on persistent non-blocking surface: an
  idempotent snapshot-replace, never an append, so a re-fetch can't duplicate or resurrect rows. Separately,
  *trust events* (the C28 taxonomy) are emitted from the net actor only on a meaningful transition — a
  `policy_version` bump (gated on `PolicyCache::cached_version` read *before* the cache insert) **or** a
  blocking cutoff-hit — so a passively re-fetched, already-dismissed warning never resurrects while a real
  escalation always breaks through. A relay that *withdraws* a previously-served policy (serves `None` after
  we held a version) is treated as a rollback (`ServerDeprecationPolicyRollback`), not a benign empty state,
  closing the strip-the-policy downgrade hole. A missing/short pinned key and any signature failure fail
  closed to `ServerDeprecationPolicyUnreadable` — an unverifiable policy is never accepted (ISC-A-C9). The
  decision logic lives in a pure `decide_deprecation(prev_version, artifact, server_pubkey, in_use, now)`
  so every branch (rollback, withdrawal, missing-key, version-gating, escalation) is unit-tested without a
  live session; the surface reuses core's `assess_deprecation` bridge rather than re-deriving the
  pending-vs-cutoff mapping. The single-relay alpha collapses the C25 `(suite_id, server-id)` dismissal
  scope to per-server, which is **safe only because** `assess_deprecation` filters the policy against the
  one-element in-use set `&[CNSA_2_0.id]` — at most one warning can ever surface, so a dismissal cannot
  swallow a sibling-suite deprecation. Adding a second in-use suite **requires** restoring the per-suite
  dismissal key before that collapse is removed. **Known limitations (coupled to the deferred client
  profile-persistence path, not independent):** the `PolicyCache` is in-memory only, so the anti-rollback
  and withdrawal-as-rollback guarantees hold **within a session only** — a restart wipes the cached version,
  after which a server that silently withdraws a previously-committed deprecation reads as a fresh clean
  state rather than a rollback. The one-hour TTL is likewise not cross-restart enforced (the actor refetches
  on every user action, stricter within-session). Multi-server earliest-cutoff governance is also post-MVP.
  The unverifiable/unreadable path is deliberately **visible and non-destructive**:
  `ServerDeprecationPolicyUnreadable` is PersistentNonBlocking (a status badge, never a silent no-op) and
  flows through the same `DeprecationError` path that keeps the last good cached warning, so an attacker
  forcing the unreadable branch cannot erase a previously-surfaced pending deprecation.
- 2026-05-29: **refined:** This `ISA.md` *is* the promotion of the vault ISC draft into the repository as
  the authoritative system-of-record and contributor contract — unifying the previously-planned
  `docs/spec/isc.md` promotion with the Algorithm v6.3 project-ISA requirement into a single artifact. The
  vault draft becomes scratch for in-progress spec edits, promoted via PR when stable.
- 2026-05-29: **Three ISC numbering systems reconciled.** (a) The **94 MVP spec ISCs** (`ISC-S*` / `ISC-C*`
  and their `A-` anti-criteria), code-tracked in `isc_coverage.rs` (`TOTAL = 94`). (b) The **68 M11
  test-harness criteria** — the MVP-gate scenario's own step IDs, **not** spec ISC IDs. (c) `COVERED_ISCS =
  72` — a static M7 coverage floor against the 94. The direct-messaging ISCs (C38–C46 / A-C20–A-C25,
  15 criteria) are additional and alpha2-deferred, bringing the ISA's full criteria count to 109
  (94 MVP-tracked + 15 DM).
- 2026-05-29: ISC numbering is permanent — never renumber or reuse; vacated IDs (e.g. `ISC-C5`) stay
  reserved; withdrawn ISCs get a `DEPRECATED` marker plus a successor pointer. Commit/PR bodies cite ISC IDs
  only when a boundary is strengthened, deployed, or altered — never as decoration.
- 2026-05-29: Direct messaging (ISC-C38–C46 / A-C20–A-C25) deferred from alpha1 MVP to alpha2; kept in
  Criteria, marked out of scope for the MVP gate.
- 2026-05-29: **DM family folded into the main client line from conception.** The direct-messaging ISCs
  were drafted under a `ISC-C-DM*` / `A-C-DM*` namespace; they are renumbered once, here, into the
  main client line (C38–C46 / A-C20–A-C25) **before** this ISA's first commit makes any ID citable.
  Rationale: it follows the project's own first-start precedent (ISC-C29–C37 folded the same way), and
  deferral is better signalled by Out of Scope + a subheading than by an ID namespace. This is the last
  pre-citation renumber; the never-renumber rule binds from the promotion PR forward.
- 2026-05-29: **Reconciliation debt logged** — `xtask::TOTAL_ISCS = 93` is stale (should be 94) and
  `COVERED_ISCS = 72` is a static floor; both to be replaced by a live `isc-coverage` count.
- 2026-05-29: **MVP-gate scope sliced by depth (Path 2).** Scope itself was settled earlier ("if we cannot
  chat and share files, both publicly and in circles, we haven't hit MVP; DMs wait"). The remaining gate
  work splits at the protocol/surface fault line: **M11** delivers the four no-new-protocol client surfaces
  (gate steps 3/6/7/8) → v0.13.0; **M12** delivers the single wire-protocol change, user-publish shares
  (step 5, `PublishShare`, ISC-38), isolated in its own PR with its own MINOR bump → v0.14.0 = full gate
  passes = MVP. Rationale: keeps the wire change reviewable and SemVer-clean, lands the finished surface
  work sooner, and leaves an explicit milestone (M12) as headroom for anything that surfaces late.
- 2026-05-29: **Clean-device recovery (gate step 8) is MVP-gating** — confirmed not deferrable; it is the
  first-start recover branch (ISC-C30–C34 family) and upholds the "identity recoverable before exposed"
  Principle. It lands in M11 (TUI-only) and the full gate at v0.14.0 includes it.

## Changelog

- **conjectured:** project state is "86 ISCs, pre-implementation" (per the vault current-phase snapshot,
  last updated 2026-05-22).
  **refuted by:** reconciliation on 2026-05-29 — git tags show M0–M10 shipped (through v0.12.1) with M11 in
  flight; `isc_coverage.rs` reports `TOTAL = 94`; coverage floor is 72/94.
  **learned:** the vault current-phase snapshot drifted roughly six milestones behind reality because
  milestone-completion memos were written but the living snapshot was never updated.
  **criterion now:** project state is tracked by `cargo xtask isc-coverage` against this ISA — a mechanized,
  drift-proof system of record — not by a hand-maintained prose snapshot.

## Verification

- Milestone / release history is tracked canonically by the SSH-signed git tags + `CHANGELOG.md`; this ISA
  records no milestone status (the dated entries below are historical evidence, not a live status board).
  Probe: `git -C ~/repos/daemonseed tag --verify <tag>` + `CHANGELOG.md`.
- ISC coverage is reported live by `cargo xtask isc-coverage` (registry `isc_coverage::TOTAL`); no coverage
  count is hand-written here. Probe: `cargo xtask isc-coverage`.
- DoD gates green as of M10 close (fmt / clippy `-D warnings` / test / check-proto); 636+ workspace tests.
- M11 step 7 (suite-deprecation client surface, ISC-C25 / A-S11 / C28) verified 2026-05-30: 96 `daemonseed-tui`
  unit tests pass (11 pure `decide_deprecation` cases covering rollback / withdrawal / missing-key / short-key /
  version-gating / cutoff escalation / unaffected-suite, plus app-fold + Tab-ring + render tests), and the
  end-to-end gate test `daemon_fetches_verifies_and_surfaces_deprecation_policy` passes inside `cargo xtask
  mvp-gate` (relay boots a signed `[crypto]` policy, daemon fetches over `GetDeprecationPolicy`, verifies
  against the TOFU-pinned server-wide key, and renders `suite-deprecation-pending`). Probe: `cargo xtask
  mvp-gate` (PASS) + `cargo test -p daemonseed-tui`.
- M11 step 8 (clean-device recovery, ISC-C29 recover branch / C30 / C32 / C36 / A-C2) verified 2026-06-01:
  6 `daemonseed-core` unit tests (recovered handle == source, fresh `profile_id`, blob + `.dseed` re-seal
  round-trip, invalid-mnemonic + weak-passphrase fail-closed) and 7 `daemonseed-tui` tests (recover-choose
  routing, typed + `.dseed` happy paths each asserting the recovered handle's hash-prefix equals the source
  device's, invalid-mnemonic + wrong-`.dseed`-passphrase stay-on-step, and the Welcome `[r]` → recover-branch
  wiring) pass, and the end-to-end gate test `fresh_daemon_recovers_identity_from_mnemonic` passes inside
  `cargo xtask mvp-gate`. Probe: `cargo xtask mvp-gate` (PASS) + `cargo test -p daemonseed-core -p daemonseed-tui`.
- M12 steps 5 & 6 verified 2026-06-03: the PTY/subprocess gate now runs **10 tests and passes 10/10**.
  Step 5 (user-publish file sharing) — `cli_published_share_is_cross_client_visible_then_reaped`: a held
  `daemonseed-cli publish docs` connection is seen by a *separate* ephemeral client via `ListPublicShares`
  (online → cross-client visible), then SIGINT'd; the second client polls until the share is gone
  (offline → reaped), exercising the RAM-only `ShareReapGuard` cross-client reap (ISC-A-S1), the blind-relay
  publish posture (ISC-A-S5b), and the public-space file-share surface (ISC-S4). Step 6 (introducer refresh)
  — `daemon_servers_pane_surfaces_introducer_candidate`: a relay seeded with one `introduce_to_clients` peer
  is queried via `RefreshIntroducer`; the daemon's Servers pane renders the candidate's server-id + address
  under "Discovered (introducer)" with the `candidate` label, carrying no key material (ISC-S6) and never
  auto-trusting it (ISC-C22 / ISC-A-C19). Both steps re-exercise already-covered ISCs end-to-end — no
  genuinely-new ISC closes at M12 (see `m12_isc_coverage` trace map), so the coverage floor stays 72/94.
  Probe: `cargo xtask mvp-gate` → 10/10 pass.
- MVP gate: all 8 scenario steps now pass on real binaries via the PTY harness (`cargo xtask mvp-gate`,
  10/10 subprocess tests) → **MVP reached at v0.14.0**. Probe: `cargo xtask mvp-gate`.
- ISA sanitization fidelity (no leaked internal paths or personal names; all ISC IDs preserved) — verified
  this session via advisor + Cato cross-vendor audit; see session record.
