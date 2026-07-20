# Download subsystem — per-route concurrency budget, placement model, verified resume

**Status: RATIFIED 2026-07-20 (all nine items — see Ratification record).** Design-of-record for the public-share download path redesign. Supersedes #205; folds #207 and #208; resolves the residual dimensions of #113 and #128 D-1/D-2. RFC-lite: problem → invariants → approach (three parts) → composition → ISC changes → implementation plan → oracles → issue dispositions → open questions. Hardened by a 3-lens adversarial panel (correctness / hostile-adversary / specification-rigor; 3 BLOCKERs and 15 MAJORs folded) + an advisor pass.

## Problem

Three interacting defects in the consumer download path (`daemonseed-{gui,tui}::veilid_net::run_confirm_download`, `daemonseed-veilid-net::share`):

1. **Concurrency.** The quantity that kills a serving private route is the total concurrent in-flight `app_call`s to that one route (#204: sustained 8×2 fanout died; 1–2 held; single files passed because their fanout is brief). But the code caps that quantity only indirectly, as the *product* of two per-level AIMD windows (chunk × fragment, GUI) or a static per-level window (TUI). A product of proxies must be conservative on both factors, so downloads are near-sequential; files are sequential (#113 residual); cross-share parallelism is structurally possible since #197 but unexploited; the TUI uses none of the adaptive machinery.
2. **Placement.** Downloads do not land in the destination correctly. Reproduced from `daemonseed_core::storage::fetched::rebase_to_selection_root` (pure function, verbatim inputs): a scattered selection (two album folders from different parents) recreates the full share-internal ancestry under the user's dest instead of landing the selected folders as top-level entries; a folder containing exactly one file collapses to the bare basename, losing the folder. Root cause is at ingestion: `ConfirmFetch` carries only manifest file indices + `flat_dest`, so the user's actual selection (which tree nodes were toggled, ISC-C72) is discarded and placement guesses intent from path shapes — no downstream heuristic can recover discarded intent. Separately, the GUI managed-dir path diverges from the TUI/ISC-C63 contract: no `resolve_share_folder` collision suffix, no `downloads.idx` (`gui/veilid_net.rs` writes `<root>/<safe_folder_name(name)>/<rel>` directly).
3. **All-or-nothing wipe.** ISC-A-C31 as implemented deletes every file the failed download wrote (`written`/`cleanup_written` tails), so a transient transport blip on file 9/10 wipes files 1–8; the TUI additionally truncates a previously-downloaded copy at `File::create` before any byte verifies. A resume cannot be built on the current error surface because transient-transport and integrity failures are indistinguishable — both `VeilidNetError::Send(String)` (#205 blocker). The GUI also buffers each whole file in RAM before writing (`Vec::with_capacity(entry.size)` — a hostile manifest panics it, #207 trigger).

These interact: a resume that re-drives the old fanout re-kills the route; placement fixes without stable selection-aware paths break resume's ability to find retained bytes; parallelism without serialized bookkeeping loses `downloads.idx` entries (#208). One design, three parts.

## Invariants (unchanged, load-bearing)

- **ISC-S28 / ISC-A-S20** — per-chunk SHA-384 content-address verification, fail-closed. Untouched.
- **ISC-A-C32** — path-traversal guard on every manifest rel-path and share-folder name. Untouched in wording; this design *extends* the guarded surface (selection-root paths, the staging namespace — DL-ISC-18) because it introduces new joined components the current wording never covered.
- **ISC-A-C33 / ISC-C66** — no chunk is requested or written except against a manifest the user has previewed and confirmed. A resume is bound to the *stored confirmed* manifest (DL-ISC-20); a changed manifest re-gates on preview.
- **ISC-A-C31 intent** — unverified/poisoned/truncated content is never persisted *as a download* nor surfaced. The wipe softens to verified-unit retention; the intent hardens (see Part 3 and the reword).
- **#180 route-death semantics** — route-death parks the one-shot retry, never prunes; the share stays listed Unresolved (CRSH-ISC-5/6); resume is user-initiated, per the #180 route-freshness reframe.
- **#197 off-loop seam** — no download is awaited on the net-actor loop (CRSH-ISC-8/29); the fold owns all `&mut ShareState` mutation.
- **Chat coexistence (#128)** — the download leaves the fetcher headroom for interactive traffic. Precisely: fragment `app_call`s and chat DHT writes are distinct *daemonseed* primitives (fetch traffic never draws on the WB write gate), but they share the one veilid node's RPC scheduler, socket path, and global `rpc.timeout_ms` — coexistence therefore rests on the global cap `G` plus the latency-yield valve (Part 1), and its felt-test must run at the NEW maximum concurrency, not inherit #197's 2×2-era result.
- **Controllers are clock-free / signal-agnostic** — deterministically unit-testable with injected observations (`AimdWindow` discipline).
- **GUI + TUI parity** — this design wires both frontends through one shared engine.
- **No wire/proto change** — everything below is in-process or crate-API only (verified: `ConfirmFetch` is a `NetCommand` on the main↔actor mpsc in both frontends, nothing in `daemonseed-proto`; see SemVer note in the implementation plan).

## Part 1 — one per-route concurrency budget

### The invariant

**All fragment `app_call`s in flight to one serving route are bounded by a single per-route budget `W(route)`; files, chunks, and fragments parallelize freely underneath it.** The budget caps the exact physical quantity #204 identified, not a per-level proxy. Cross-route downloads (different sharers, or different shares on distinct routes) hold independent budgets. A fetcher-global cap `G` additionally bounds total in-flight fragment calls across all routes (the fetcher's own capacity — #128 named both nodes'). **`W_ceil < G` is a design invariant** (DL-ISC-19): one route at ceiling must never occupy the whole global pool, else a single slow-but-healthy (or hostile) sharer starves every other concurrent download; at `G = W_ceil` cross-route parallelism buys only FIFO interleaving, so real cross-route aggregate speedup also requires the gap.

Peak in-flight to a route is `min(W(route), G − other routes' usage)`; today's shipped behavior (2×2..8 product) becomes the floor case, and a healthy route climbs toward `W_ceil` with genuinely parallel files under it — a claim the oracle set tests positively (DL-ISC-15/16), not just as an upper bound.

### Mechanism

A `RouteBudget` registry lives in `daemonseed-veilid-net`, owned alongside the actor state and reachable from every fetch path (the chokepoint every fragment call already passes: `share::fetch_chunk` / the manifest fetch).

Two keys, deliberately different lifetimes:

- **Live accounting is keyed by imported `RouteId`** — the precise failing resource. An accounting entry exists while fetches reference the route and is dropped when the route dies/releases (bounded by concurrent downloads; no session-long growth).
- **The learned ceiling is keyed by sharer pubkey** (the catalog's verified owner — available at every fetch since #156 binds `share_id` to it). This is forced by veilid semantics: `RouteId` is a deterministic function of the route's keys, so a post-death rotation yields a *new* `RouteId`, and a ceiling keyed there would be discarded on exactly the kill→resume path it exists to protect. The pubkey-keyed ceiling map is session-lifetime, bounded by the number of discovered sharers. **Deliberate consequence:** two shares from one sharer on distinct routes share the one pubkey ceiling — a kill on route A caps healthy route B of the same sharer. That coupling is intended (both routes terminate on the same node, whose capacity is the real limit); live `W` accounting stays route-independent.

Budget admission is **counter-gated, not permit-revoking**: `W(route)` is a *target*; a fragment call is admitted while `in_flight(route) < W(route)` and `in_flight(global) < G`, in that fixed acquisition order (release in any order; no admission is held while waiting on the other stage in reverse, so no deadlock). A collapse of `W` gates *new* admissions while in-flight calls drain — nothing tries to revoke a granted slot (a tokio `Semaphore` cannot remove granted permits; the accounting is a counter + notify, FIFO-fair on waiters). During a fragment's **retry backoff sleeps** (`FRAGMENT_RETRIES` × 250 ms, each attempt up to veilid's ~5 s rpc timeout) both slots are **released and re-acquired for the next attempt** — a dying route's doomed retries must not pin `G` and starve healthy routes for the ~15–20 s death-detection window.

### The controller — error-primary, not latency-primary

The AIMD-on-latency premise is refuted in this repo's own record: WB-5 §I5′.2 (`docs/design/veilid-write-budget.md`) — the wrong controller against an exogenous latency regime, with measured ~100× day-scale latency variance independent of offered load — and #123 (measured ~7.5 s one-way private-route transit vs the 2 s `FRAGMENT_LATENCY_THRESHOLD`): transit latency is dominated by the veilid regime, not by our load on the route. Worse, #204's evidence is consistent with veilid's flood protection being a **cliff**: latency stays unremarkable until the route dies, so a latency-fed additive-increase probes straight into route-death — the shipped slow-start can still climb back to the lethal fanout on any run where latency never breaches.

The controller for `W(route)`:

- **Slow-start** at `W_floor` (2), as #204 shipped — a cold route is never hit with a fanout it hasn't demonstrated surviving.
- **Additive increase is window-clocked, not ack-clocked**: +1 after a full window's worth of healthy completions (the healthy-completion counter resets on any decrease), not +1 per completion (per-completion increase is super-linear in time at high W — the current `observe`-per-chunk shape). Under sustained health the window reaches `W_ceil` within a bounded number of windows (DL-ISC-15 — the liveness half; without it a stuck-at-floor controller passes every safety probe).
- **Error is the primary decrease signal**: a fragment timeout or route-death collapses `W(route)` to `W_floor` AND records the **learned ceiling** `max(W_floor, W_kill/2)` in the pubkey-keyed map, so a subsequent attempt against the same *sharer* — including a resume on a rotated route — cannot climb back to the width that killed it (the R3 kill–resume–kill breaker; keyed by pubkey precisely so rotation does not erase it).
- **Latency is the secondary, coexistence signal**, with WB-5-style discrimination rather than single-sample reaction: an observation at/over `FRAGMENT_LATENCY_THRESHOLD` is a breach; **≥3 breaches within the last 5 completions** steps the window down one halving (floored), and the healthy-climb counter resets; a single slow sample does nothing. The asymmetry is the *opposite* of WB-5's write-path conclusion, deliberately: there a false decrease reintroduced an O(records × RTT) pathology (expensive) while a false hold was cheap; here a false decrease costs download speed (cheap) while a false hold risks route-death (expensive). Same discrimination framework, inverted bias — **bias to decrease**. Initial values (3-of-5, the 2 s threshold) are named constants, felt-test-tunable.
- Clock-free: the controller consumes injected completion observations `(latency, error-class)`; no internal clock reads.

### Scheduling under the budget

`run_confirm_download` becomes a scheduler over work units: up to `F` files in flight **per download** (a small static bound, e.g. 4 — memory/progress bookkeeping only, not route protection; with `N` concurrent downloads the fetcher accepts `N×F` open staging files, while total *network* in-flight stays bounded by `G`), each file's chunks fetched under the budget and **written at their manifest-derived byte offsets** (Part 3 — no ordering requirement, no reorder buffer), each chunk's fragments pipelined — all admission flowing through the one route budget. Chunk reassembly RAM is bounded by in-flight chunks ≤ `W(route)` × `CHUNK_SIZE`. FIFO-fair admission makes starvation structurally impossible within a route; across routes, budgets are independent and `G`'s waiter queue is FIFO too. The per-level windows (`FRAGMENT_FETCH_CONCURRENCY`, `CHUNK_FETCH_CONCURRENCY`, `CHUNK_SLOW_START`, both fetch-path `AimdWindow` instances) retire once both frontends are on the engine (implementation plan step 7).

### Interactions

- **Route-death → #180 park**: unchanged fold semantics (`TransientFailed` marks Unresolved + parks). The pubkey-keyed ceiling records the kill before the accounting entry retires with the dead route.
- **#204 slow-start**: subsumed — slow-start is the controller's opening state.
- **#123 deadline**: not required by this design. The budget governs concurrency, not per-call patience; transient timeouts are handled by the taxonomy + resume (Part 3). The `app_message` re-protocol stays deferred (see dispositions).

## Part 2 — placement as a stated total function

### The layout specification

Placement is a total function over (selection, destination). Selection roots are **normalized first**: any selected node nested inside another selected node is subsumed (removed); each selected file then maps to its unique deepest enclosing remaining root — so overlapping selections (a dir plus a file inside it, nested dirs) are well-defined.

| Selection | Managed downloads dir | User-chosen dest (`flat_dest`) |
|---|---|---|
| Single file | `<root>/<share-folder>/<full rel_path>` | `<dest>/<basename>` |
| One folder (≥1 file — including exactly 1) | `<root>/<share-folder>/<full rel_path>` | `<dest>/<folder-basename>/<subpath below it>` |
| Multiple roots (scattered files/folders) | `<root>/<share-folder>/<full rel_path>` | each normalized root lands per the two rows above; basename collisions *between roots* suffix the later root (`name-2`, mirroring `resolve_share_folder`) |
| Whole share | `<root>/<share-folder>/<full rel_path>` | `<dest>/<top-level entries of the share>` (the share root is the selection root) |

`<share-folder>` = `resolve_share_folder` (reuse on re-fetch, collision-suffix by `share_id`) — in BOTH frontends. The managed dir keeps `downloads.idx`; a user-chosen dest gets no idx (ISC-C68 unchanged in that clause; its chosen-dest layout clause changes behavior for the scattered case — a ratification item, Open question 2, not a mere text refresh). **A chosen dest never overwrites a pre-existing path it cannot prove is this download's own artifact** (its own `.dspart` continuation, or an existing file whose bytes fully match the confirmed manifest); anything else collision-suffixes instead of clobbering (DL-ISC-21) — a hostile basename must not become an overwrite primitive against the user's directory.

### The fix is at ingestion: carry selection roots

`ConfirmFetch` gains the user's **selection roots** — the tree nodes actually toggled (ISC-C72 already has them: a toggled `Dir` node, or individual files), as manifest-relative dir paths + file indices. Placement then maps each selected file to its governing root deterministically; `rebase_to_selection_root`'s shape-guessing retires. This is an in-process `NetCommand` field (main ↔ actor mpsc), **not a wire change**. The reproduced defects fall out: a scattered selection lands each selected folder as a top-level entry; a one-file folder keeps its folder.

**Traversal guard extension (DL-ISC-18):** selection-root names come from the manifest's untrusted `rel_path`s, so the resolver's *entire computed destination-relative path* — root basename + subpath, as one unit — passes `sanitize_rel_path` before any join; and the staging component (below) is a reserved name `sanitize_rel_path` refuses, so no manifest can express a path into the quarantine namespace. ISC-A-C32's current wording covers manifest rel-paths and the share-folder name; these two new joined surfaces get their own anti-criterion rather than a silent widening claim.

### Concurrency-safe bookkeeping (#208)

All `downloads.idx` mutation goes behind an **OS advisory file lock** (a `.idx.lock` sibling; flock / `LockFileEx`) — not an in-process mutex, because the GUI and TUI are separate binaries that can share one non-portable downloads root. The read-modify-write (fresh `list_shares` read under the lock → mutate → `render_downloads_idx` write) is atomic under the lock and re-reads at write time, never from a download-start snapshot. This holds for concurrent downloads in one process, and across processes. (The alternative — folding idx mutation on-loop — couples bookkeeping latency to the actor loop the #197 restructure just freed, and cannot serialize across processes; rejected.)

### GUI/TUI unification

The download engine (Part 3's staging writer + this placement resolver + the idx lock) is shared: placement + staging + idx in `daemonseed-core::storage::fetched` (pure fs, no veilid dep), the fetch scheduler in `daemonseed-veilid-net`. Frontends keep only their event mapping and fold. The GUI adopts `resolve_share_folder` + `downloads.idx` (its managed-dir divergence closes; its Downloads browse follows the same manifest the TUI's does). **Migration note:** pre-change GUI managed downloads live under bare `safe_folder_name(name)` folders with no idx entry; the first post-change run adopts a folder iff it exactly equals `safe_folder_name(name)` for a currently-known share and no idx entry claims it — anything else is left untouched on disk (never deleted) — stated precisely so the implementing session doesn't guess. This is the #200 dedup, scoped to the download path.

## Part 3 — verified resume, fail-closed

### Error taxonomy first (#205's blocker)

`daemonseed-veilid-net` gains a typed fetch-failure surface at the fetch boundary:

| Class | Members (today all `Send(String)`) | Posture |
|---|---|---|
| `Transient` | fragment timeout after retries, dead/unimportable route, `RouteChange` mid-fetch | RESUMABLE — verified units retained; marks Unresolved + parks (#180) |
| `Integrity` | SHA-384 content-address mismatch (`share.rs` chunk-verify), chunk-address mismatch, malformed/oversized fragment | FATAL for the share — never persisted, never resumed past; no mark, no park |
| `NotServed` | authoritative negative (already modeled) | not resumable; not an error of the route |
| `Local` | path sanitize, disk create/write, idx write | surfaced; route unaffected; **verified units are retained** (they verified — a disk-full blip must not wipe them), and a user-initiated re-download reuses them |

Crate-API change only (veilid-net public error enum; MINOR for the crate, no proto/wire impact). The classification site is where the knowledge exists (the verify site, the call_fragment retry loop) — downstream code switches on class, never on message strings.

### Stage-then-promote: the persistence model

- Every in-progress file writes into a **reserved staging area** under the destination root — `<dest-root>/.dspart/<share_id>/<final-rel-path>` — a namespace no manifest can express (`sanitize_rel_path` refuses the reserved `.dspart` component, DL-ISC-18), so a hostile `rel_path` can neither collide with a partial nor plant a file the sweep would delete. Chunk bytes are written **only after** that chunk's SHA-384 verification, **at the chunk's manifest-derived byte offset** (files are pre-sized sparse; chunks complete in any order under the budget — partial state is a *set of verified chunks*, not a prefix). Verify-then-write replaces the GUI's whole-file RAM buffering (also closing #207's hostile-`size` alloc panic; staging must never reintroduce an `entry.size`-sized allocation).
- A file **promotes** — a rename to its final path — only when every chunk has verified and the size matches the confirmed manifest. Promotion is platform-specified, since `std::fs::rename` does not replace an existing destination on Windows (the felt-test platform): Unix `rename` (atomic replace); Windows `ReplaceFileW`-equivalent, or remove-then-rename with the documented sub-millisecond non-atomic window. "Atomic promote" is never claimed unqualified.
- `downloads.idx` records only promoted files of fully-completed shares (unchanged surface semantics: the browse pane never shows an in-progress or partial download).
- On **transient** failure: verified state stays — promoted files in place, staged verified chunks in place. Nothing is wiped.
- On **integrity** failure: **every staged partial belonging to this fetch is destroyed** (not just the failing file's — the poison boundary is the whole fetch's unpromoted state); already-promoted files remain — they are self-authenticated by their own content-address verification, which a poisoned sibling cannot retroactively falsify (retaining them is itself a ratification item, Open question 3). The share is flagged poisoned, keyed by `share_id` in session state **independent of the discovery lifecycle** — catalog-TTL eviction, withdraw/re-advert, or route rotation does not clear it (a re-*mint* under a new `share_id` does defeat the flag, which is why the flag is a UX guard, not the enforcement: per-chunk verification, ISC-A-S20, is the always-on backstop that re-catches poison on every attempt). No automatic path re-fetches a poisoned share; an explicit user re-download warns (Open question 3).
- On **local** failure: verified state stays (it is verified); the error surfaces.
- Resumable staging is **never auto-deleted**: incomplete downloads are surfaced in the Downloads view with resume/delete affordances, and staging persists until the user resumes, re-downloads, or deletes (ratified — Ratification record item 4). A startup/idle sweep reclaims only unresumable debris — staging that carries no stored confirmed manifest (e.g. a crash before the manifest persisted) — and is gated on a **live-fetch registry** (a sweep never deletes state belonging to a registered in-flight or resuming fetch; a resume registers its staging set before the sweep can run — closing the TOCTOU), never on name patterns alone. The staging area is part of the R-PANIC erasure surface.

### Resume is re-derivation, never trust — against the *stored confirmed* manifest

`ConfirmFetch` persists the **confirmed manifest** (the per-file `rel_path` + size + chunk-address list the user previewed) into the fetch's staging area, and records the manifest's **digest in the profile's local state store** (redb — the client's own trusted state, not the co-resident-writable downloads root). Before any use, the staging copy is verified against that digest: the manifest is the one content-*defining* artifact (chunk bytes re-hash against it, so it is the root of the fetch's trust chain), and without the profile-anchored digest a co-resident tamper of the staging copy plus a colluding sharer serving the matching manifest would bypass the confirm gate. "No sidecar is trusted for content" holds precisely because the manifest's integrity chains to the profile store, and every byte then chains to the manifest. A resume (user re-initiates the download — consistent with the #180 route-freshness reframe; no autonomous re-drive loop, which also avoids re-driving the exact load pattern that killed the route, restarting at slow-start under the sharer's learned ceiling from Part 1) proceeds:

1. Re-fetch the manifest from the (possibly rotated) route. **If it differs from the stored confirmed manifest, the resume stops and re-gates on preview/confirm** (ISC-A-C33/C66 — the sharer must not be able to swap the content set past the user's confirmation; retained bytes are never reinterpreted under a different manifest's chunk boundaries or paths). The stored copy is what binds; DL-ISC-20.
2. For each selected file, re-derive verified state **from bytes on disk, not from bookkeeping**: an existing promoted file or staged partial is re-hashed chunk-by-chunk against the stored manifest's chunk addresses (boundaries are known: `CHUNK_SIZE` + `entry.size`; the file never self-describes its boundaries). A chunk's bytes verify or that chunk is discarded and re-fetched — per-chunk set semantics, no prefix assumption. Unwritten sparse regions simply fail the hash and re-fetch.
3. Fetch only the missing/unverified chunks. Re-verified chunks count toward `FetchProgress` (the bar resumes ahead rather than jumping).

No sidecar journal is trusted for *content*; local hashing is cheap relative to network fetch. A resume can therefore never be tricked past an integrity check by tampered on-disk state — the same fail-closed property, extended to at-rest partials. A flat-dest resume finds its staging only under the same chosen dest (no idx exists there); resuming into a different dest starts fresh and the old staging ages out via the sweep — stated, accepted.

### Outcome + fold semantics (#197 seam, extended)

`ConfirmOutcome` gains the class distinction: `Complete` (unchanged), `TransientFailed` (folds exactly as today's `RouteFailed`: mark Unresolved + park the one-shot retry + `FetchError` — but no wipe), `IntegrityFailed` (new: `FetchError` with a distinct message + the durable poison flag; **no** Unresolved mark, **no** parked retry — the route is fine, the content is hostile; the message names no chunk index on any non-local surface), `LocalFailed` (unchanged emission; verified state retained per the taxonomy). The spawn seam retains the `JoinHandle` (#207, both seams — browse and download): a `JoinError` folds to `LocalFailed` with a terminal event; staging-by-construction means a panic strands only quarantined state, reclaimed by the sweep.

### The ISC-A-C31 reword (ratification item 1 — verbatim proposal)

> **ISC-A-C31 (reworded):** A share fetch must never persist or surface unverified or falsified content. Chunk bytes reach disk only after SHA-384 content-address verification (ISC-S28), and only inside the fetch's reserved staging area, which no manifest path can name (ISC-A-C32 extension); a file appears under its real name only by promotion after every one of its chunks has verified against the user-confirmed manifest; the downloads browse manifest records only promoted files of fully-completed fetches. An integrity failure (ISC-A-S20) destroys all of the fetch's staged partials, aborts the share's fetch, flags the share against automatic re-fetch, and is never resumed past. A transient-transport failure retains verified units (promoted files and staged verified chunks) for resume; a resume is bound to the stored user-confirmed manifest, re-verifies every retained byte against its content address before reuse, and re-fetches only what is missing. The staging area is part of the panic-erasure surface. A persistence failure after verification surfaces as a fetch error rather than a silent partial success.

The all-or-nothing wipe clause is gone; every security property it protected is retained or strengthened (unverified bytes now never touch a final filename even mid-download, which the current write-then-delete does not guarantee under crash). What is *new* is an at-rest surface: verified partials survive an interruption until resumed or swept — the old wording guaranteed an interrupted download left no trace. That softening is deliberate and is Open question 4.

## Composition — why one design

- Resume requires the taxonomy (else it retries past poison), the stored-manifest binding (else the confirm gate is bypassable on resume), and the budget (else a resumed folder re-drives the kill fanout; the pubkey-keyed learned ceiling + slow-start restart is the R3 "kill–resume–kill" breaker — keyed by sharer precisely because rotation renews the `RouteId`).
- The budget's parallel files/chunks require the offset-writing staged writer (set-not-prefix partials with atomic-enough promotion) and the cross-process idx lock (#208) — retrofitting parallelism onto the current write-then-wipe tail would re-engineer it.
- Placement's selection roots give resume its stable path contract (re-derivation must find bytes where the spec says they land) and give staging its final-name targets; the staging namespace in turn is what makes placement's no-clobber rule enforceable mid-download.
- Piecemeal ordering that avoids re-engineering does exist *inside this design* (taxonomy → budget → placement/staging → resume), which is exactly the implementation plan.

## Proposed ISC set (registered at build commits, not here)

New family `DL-ISC-*` (per the CRSH-ISC precedent), coordinated against `daemonseed-isc` registry TOTAL + distribution ledger by the implementing session. IDs permanent from ratification:

- **DL-ISC-1**: Peak concurrent in-flight fragment `app_call`s to one route never exceeds the route's budget under any composition of parallel files, chunks, fragments, and shares (probe: concurrency-counting fake fetcher over the scheduler). *Correctness/perf property of the honest fetcher — not an adversarial defense.*
- **DL-ISC-2**: A fragment timeout / route-death collapses that route's budget to floor and records a learned ceiling of half the killing width **keyed by sharer pubkey**; a later attempt against the same sharer — including on a rotated route with a fresh `RouteId` — cannot open wider than the learned ceiling (probe: unit — kill at W, rotate key, re-attempt, assert cap).
- **DL-ISC-3**: Additive increase is window-clocked — at most +1 per full window of healthy completions, and the healthy counter resets on any decrease (probe: unit, N completions at width W yield ≤ N/W increments; interleaved decrease resets).
- **DL-ISC-4**: Downloads to distinct routes hold independent budgets and progress concurrently (probe: two-route counting fake).
- **DL-ISC-5**: Total in-flight fragment calls across all routes never exceed the global cap `G` (probe: counting fake, two routes, sum bound).
- **DL-ISC-6**: Anti — no fetch path (manifest or chunk) issues a fragment `app_call` without budget admission, and no admission is held across a retry backoff sleep (probe: counting fake covering both paths + a stalled-route fake asserting `G` frees during backoff).
- **DL-ISC-7**: Each (selection × destination) case of the placement table lands exactly per the table, including normalized overlapping roots (a selected file inside a selected dir is subsumed) (probe: table-driven unit over the placement resolver, overlap cases pinned).
- **DL-ISC-8**: `ConfirmFetch` carries the selection roots and placement is a function of them — a scattered selection lands each selected root as a top-level entry; a one-file folder keeps its folder (probe: unit on the reproduced cases A–F).
- **DL-ISC-9**: Anti — two concurrent managed-dir downloads, in one process or two, never lose a `downloads.idx` entry (probe: interleaved unit through the file lock; two-process spawn test).
- **DL-ISC-10**: The fetch boundary types transient-transport, integrity, not-served, and local failures apart; the SHA-384 mismatch is `Integrity` (probe: unit mapping table over failure injections).
- **DL-ISC-11**: Chunk bytes reach disk only post-verification, only inside the reserved staging namespace, at their manifest-derived offsets; promotion occurs only after full-file verification, via the platform-specified replace primitive (probe: unit + fs inspection mid-download; Windows CI/felt-test covers the replace path).
- **DL-ISC-12**: A resume re-fetches only missing/unverified chunks; every retained byte re-verifies against its content address before reuse; re-verified chunks count toward progress (probe: kill-mid-download unit counting re-fetched chunks; tamper-a-partial unit showing per-chunk discard+refetch).
- **DL-ISC-13**: Anti — an integrity failure destroys every staged partial of the fetch, keeps promoted files, sets the durable poison flag, never parks a retry, never marks Unresolved, and is never resumed past (probe: unit over the fold + worker tail).
- **DL-ISC-14**: A panicking download worker still yields a terminal outcome and leaves only staged (quarantined) state (probe: unit spawning a panicking worker through the spawn seam).
- **DL-ISC-15**: Liveness — under sustained healthy completions on one route the window reaches `W_ceil` within a bounded number of windows (probe: counting fake, K-window bound asserted).
- **DL-ISC-16**: Liveness — N files on one healthy route achieve peak in-flight > `W_floor` (files genuinely parallelize under the budget) (probe: counting fake with per-file markers).
- **DL-ISC-17**: The latency valve steps the window down on a sustained breach (≥3 of the last 5 completions at/over threshold) and NOT on a single slow sample (probe: injected-latency unit driving both patterns).
- **DL-ISC-18**: Anti — the full computed destination-relative path (selection-root basename + subpath) passes the traversal guard as one unit, and the reserved staging component is refused in any manifest `rel_path`; no hostile manifest or selection can write outside the dest or into the staging namespace (probe: hostile-path unit suite).
- **DL-ISC-19**: Anti — `W_ceil < G`, and no single route ever holds more than `W_ceil` global slots (probe: compile-time/unit constant assertion + counting fake with one saturated route asserting a second route still admits).
- **DL-ISC-20**: Anti — no chunk is ever fetched against a manifest that differs from the stored user-confirmed manifest, and the stored staging copy is used only after verifying against the profile-anchored digest; a differing resume-time manifest, or a staging copy failing its digest, halts the resume pending a fresh preview/confirm (probe: unit — swapped-manifest resume and tampered-staging-manifest resume each assert zero chunk requests).
- **DL-ISC-21**: Anti — at a user-chosen dest, promotion never overwrites a pre-existing path that is not provably this download's own artifact; the incoming root collision-suffixes instead (probe: unit with a pre-existing unrelated file).
- **DL-ISC-22**: Anti — the staging sweep deletes only state absent from the live-fetch registry (probe: unit — sweep during a registered resume deletes nothing of its set).
- **ISC-A-C31**: reworded as above (same ID — a reword, never a renumber).
- **ISC-C68**: chosen-dest layout clause changes behavior for the scattered case (gated on Open question 2) — a semantic edit under the same ID, flagged as such, not a text refresh.
- ISC-S28 / ISC-A-S20 / ISC-A-C32 / ISC-C63..C67 / C72: unchanged.
- CRSH-ISC-29 regression-holds: the new engine still never awaits a download on the actor loop.

## Implementation plan (ordered, per-crate; every step names its oracle; every commit lands gate-green)

1. **veilid-net: error taxonomy.** Introduce the typed fetch-failure classes at the fetch boundary (`share.rs` verify + retry sites, route import). Oracle: DL-ISC-10 mapping unit.
2. **veilid-net: `RouteBudget` registry + controller.** Counter-gated admission keyed by `RouteId`, pubkey-keyed ceiling map, global `G` pool, window-clocked climb, error-primary collapse, 3-of-5 latency valve, backoff-releases-slots. Clock-free; injected observations. Oracles: DL-ISC-1..6, 15..17, 19 counting-fake suite.
3. **veilid-net: budget-backed fetch seam, added alongside the existing API.** `fetch_manifest`/`fetch_chunk` gain budget-admitted variants; the legacy window-parameter path stays so both frontends keep compiling (the DoD gate holds at every commit). Oracle: DL-ISC-6 on the new seam.
4. **core: placement resolver + staging writer + idx lock.** Selection-root normalization + total function; reserved staging namespace + offset writes + platform-specified promote; OS file lock on the idx; live-fetch registry + sweep. Oracles: DL-ISC-7/9/11/18/21/22 + the reproduced placement cases as pinned tests.
5. **gui: engine adoption.** `run_confirm_download` becomes the shared scheduler on the new seam: staged offset writes (RAM buffering retired), selection roots from the C72 tree, stored-manifest persistence, extended `ConfirmOutcome` + fold, `JoinHandle` retained at both spawn seams, managed-dir migration note honored, and the **incomplete-downloads affordance** (Downloads view rows with resume/delete for surviving staging — ratification item 4). Oracles: DL-ISC-8/13/14/20; `crsh_isc_29_*` stay green.
6. **tui: parity.** Same engine replaces the sequential static-window loop; same outcome/fold surface. Oracles: the step-5 suite on the TUI + `crsh_isc_29_*`.
7. **veilid-net: retire the legacy windows.** With both frontends migrated, remove the window-parameter path and the fetch-path `AimdWindow` wiring (`aimd.rs` itself stays — WB-5 I5 names it a candidate pacer). Oracle: grep-clean + workspace gate.
8. **resume.** Stored-manifest check + re-derivation pass (per-chunk re-hash, discard+refetch, progress semantics) wired into the confirm path. Oracle: DL-ISC-12/20.
9. **Attended felt-tests** (live, two-client): the #204 folder repro completes on Windows (including the replace-on-promote path); kill-mid-download → user re-initiates → verified files kept, only missing chunks re-fetched; scattered-selection lands per the table; chat stays live through a download running at the NEW maximum concurrency (`W_ceil` reached, cross-share active) — not the #197-era 2×2 load.

Each step is its own reviewed commit (doc-sync per AGENTS.md; registry TOTAL moves at the ISC-registering commits). SemVer: no proto/wire change anywhere in this plan; veilid-net's public error/fetch API changes are crate-internal to the workspace (not in a LAMA manifest).

## Oracle / test strategy

- **Unit (deterministic, clock-free):** the counting fake fetcher (peak-in-flight ≤ budget; both paths; two-route independence; global bound; **liveness**: ceiling reached, files parallel; backoff frees `G`; one saturated route never blocks another), controller state-machine (climb clocking + reset, error collapse, pubkey-keyed ceiling across rotation, 3-of-5 valve vs single-sample), placement table incl. overlap normalization + no-clobber, idx interleavings incl. two-process, taxonomy mapping, staging/offset/promotion fs properties incl. hostile-path suite, resume re-fetch-only-missing + tamper-discard + swapped-manifest halt, integrity-abort full-staging destruction, panic-seam terminal outcome, sweep-vs-registry.
- **Regression:** `crsh_isc_29_*` (off-loop), `crsh_isc_5/6/25` (Unresolved/park semantics via the new outcome variants), placement pinned cases A–F from the repro.
- **Attended felt-tests:** step 9 above — the live oracles for the three headline symptoms (route survives a folder, resume keeps verified work, placement lands right), plus the chat-cadence coexistence check at the new maximum concurrency.

## Issue dispositions

- **#205** — superseded by this design (Part 3 + Part 1); close on ratification pointing here.
- **#207** — folded: `JoinHandle` retained at both spawn seams (browse + download), `JoinError` → terminal `LocalFailed`; staging-by-construction + registry-gated sweep neutralize the orphaned-partial hazard. The browse seam's fix rides step 5.
- **#208** — folded: the cross-process idx file lock (step 4).
- **#123** — deferred, unblocked-around: the budget does not need per-call patience control, and a transient timeout is now a typed, resumable outcome rather than a wipe. Re-evaluate the `app_message` re-protocol only if step-9 felt-tests still show fragment timeouts dominating on healthy routes.
- **#113** — closes at steps 3–7 (chunk + file + cross-share parallelism under the budget, both frontends).
- **#128** — D-1/D-2 subsumed by the controller (latency demoted to the secondary 3-of-5 valve, slow-start retained); D-3 (transfer-active affordance) remains open as its own UI issue.
- **#200** — partially realized (download-path dedup); the remaining self-heal orchestration dedup stays open.

## Ratification record (2026-07-20)

1. **ISC-A-C31 reword** — RATIFIED as written (the verbatim text in Part 3). The implementing session edits `ISA.md` under the same ID at its build commit.
2. **Scattered-selection semantics** — RATIFIED: per-root top-level (the table as written; the ISC-C68 same-ID behavior change approved). Pinned clarification: a single toggled folder is ONE root and arrives whole — selecting an `Artist` folder lands `<dest>/Artist/<Albums>/…` intact; only individually-toggled roots land as separate top-level entries.
3. **Poisoned-share policy** — RATIFIED both halves: already-promoted verified files are kept (self-authenticating); an explicit user re-download of a flagged share is allowed with a warning naming the prior integrity failure. The durable-by-`share_id` flag blocks automatic re-fetch; per-chunk verification (ISC-A-S20) remains the enforcement.
4. **At-rest posture of retained partials** — RATIFIED: visible + kept-until-the-user-acts. Incomplete downloads are surfaced in the Downloads view with resume/delete affordances; no time-based deletion; the sweep reclaims only unresumable debris; staging rides the R-PANIC erasure surface. The old "a failed download leaves no trace" guarantee is knowingly retired.
5. **Resume re-verify depth** — RATIFIED: re-hash everything, promoted files included (state is always derived from bytes). The cheaper trust-promoted knob stays available if felt-tests show hashing pain on large folders.
6. **GUI `downloads.idx` adoption** — RATIFIED: adopt (ISC-C63 parity, collision-suffix, cross-process lock), with the pinned never-delete migration.
7. **Initial constants** — RATIFIED as listed with `G=12`: `W_floor=2`, `W_ceil=8`, `G=12` (satisfies `W_ceil < G`; the 4-slot gap guarantees a second route *admits* while one is saturated — full aggregate speedup would need `G ≥ 2×W_ceil`), `F=4` per download, valve 3-of-5 at the 2 s threshold. Felt-test-tunable in one place; step-9 evidence may retune.
8. **Sharer-side admission control** — RATIFIED as a follow-up: filed as #209 (serve-lane inbound cap, no wire change — the commons governor a per-fetcher budget cannot provide; DL-ISC-1 is fetcher-honesty, not sharer protection). Out of this design's build scope.
9. **Receiver-granted credits** (sharer grants fetch credits in the manifest reply — true flow control) — RATIFIED posture: recorded as a future direction only, explicitly NOT adopted; **wire-visible (fragment-protocol framing change, SemVer-flagged)** if ever revisited.

## Risks

- **Veilid's flood threshold is a cliff whose height is unknown and version-dependent** (0.5.7 evidence only). Mitigated: slow-start + pubkey-keyed learned ceiling + error-primary collapse mean the design never *depends* on advance knowledge of the threshold; step-9 felt-tests bound it empirically per release.
- **Re-hash-on-resume cost** on very large folders (GB-scale) — bounded by local hash throughput; Open question 5 keeps the cheaper knob available.
- **Engine extraction scope** (steps 4–6 touch both frontends' largest functions) — the ordered plan keeps each step oracle-gated and compile-green; the felt-test baseline (send a message in Lobby + a circle every round) guards the actor seams.
- **FIFO-fair two-stage admission is the highest-risk implementation surface** — the starvation-impossibility and liveness claims (DL-ISC-4/5/16) rest on FIFO fairness over the counter+notify accounting, and a subtly unfair implementation can pass a naive test; the counting-fake suite must drive oversubscribed contention patterns, not just bounds.
- **Sparse-file staging portability** — offset writes into pre-sized files are portable, but sparse-allocation behavior differs by filesystem (a non-sparse FS pre-allocates `entry.size` on disk at staging start); acceptable, noted for the implementing session.
