//! # daemonseed-veilid-net — the Veilid transport layer (Phase 1)
//!
//! Replaces `daemonseed-server` (the relay) with the Veilid stack. This crate
//! owns one long-lived actor task (a `VeilidAPI` + `RoutingContext` + an update
//! pump), driven through a [`VeilidNetHandle`] command channel. The pump maps
//! raw `VeilidUpdate`s into typed [`VeilidNetEvent`]s the app/UI consumes.
//!
//! ## What is real here (Phase 1, proven in veilid-ds-spike)
//! - **Identity binding (D3):** the node key derives from the daemonseed
//!   mnemonic via [`daemonseed_core::identity::keys::VeilidNodeSeed`] — one
//!   phrase, one identity across content + transport.
//! - **1:1 sealed message over a private route:** allocate/import a private
//!   route, send daemonseed's opaque AES-256-GCM envelope via `app_message`.
//!   This layer carries CIPHERTEXT only — it never holds the content key or
//!   plaintext, which is what keeps the guarantee post-quantum regardless of
//!   Veilid's classical transport.
//!
//! ## Rendezvous engine (circles + lobby / public rooms)
//! One shared-owner DFLT DHT `rendezvous` record underlies every group surface.
//! What varies is how a party HOLDS that record's owner, which [`RendezvousOwner`]
//! states in the type: a circle member or a public-room participant holds the owner
//! SEED, derived from the shared circle entropy (a sibling of the content key,
//! Phase 2) or from the world-derivable room name+family (a sibling of the room key,
//! Phase 3/4), and so may create the record and write to it; a client of the
//! project-announce/MOTD record holds only the owner's PUBLIC key
//! ([`identity::PROJECT_ANNOUNCE_OWNER_PUBKEY`]), enough to address, read and watch
//! it and never enough to write it. Both reach the same address. Every participant
//! computes the SAME record key — the relay-free rendezvous address — writes
//! sealed items into per-participant append-rings, and a connecting participant
//! sweeps the record for a bounded backlog and watches it for new writes:
//! [`VeilidNetHandle::publish_circle`]/[`subscribe_circle`](VeilidNetHandle::subscribe_circle)
//! and [`publish_room`](VeilidNetHandle::publish_room)/[`subscribe_room`](VeilidNetHandle::subscribe_room).
//! Public-share **discovery** rides the lobby record (a `ShareAnnouncement`
//! sealed under the `PublicRoomKey` is just an item published there).
//!
//! ## Public-share content + discovery (Phase 3)
//! A share's bytes move owner-on-demand over `app_call` + a private route:
//! [`VeilidNetHandle::serve_share`] registers an indexed share, and a fetcher
//! pulls it with [`VeilidNetHandle::fetch_manifest`] +
//! [`VeilidNetHandle::fetch_chunk_budgeted`]. The 1 MiB content-addressed chunks are
//! transport-fragmented to ≤32 KiB and reassembled, then SHA-384-verified
//! against their address (ISC-S28). Content stays sealed under the
//! `PublicRoomKey` (ISC-A-S22).
//!
//! Discovery wires to that fetch through a SIGNED route advert
//! ([`discovery`], D-3.5): [`VeilidNetHandle::publish_share`] allocates a private
//! route, asks the sharer's [`RouteAdvertSigner`] capability to sign
//! `share_id ‖ route_blob`, and publishes a [`DiscoveryEnvelope`]
//! `{ sealed_announcement, route_blob, route_sig }` onto the lobby rendezvous —
//! re-publishing on `RouteChanged`. A fetcher opens the announcement (core), then
//! [`verify_route_advert`]s the route against the announcer's pubkey before
//! importing it, so a man-in-the-middle on the world-writable lobby record cannot
//! redirect the fetch (anti-swap). The GUI/TUI share-command wiring onto this
//! surface is the remaining Phase-3 step.
//!
//! ## Phase 4
//! Member presence is live: [`VeilidNetHandle::publish_presence`] writes a sealed
//! `MemberHeartbeat` to a per-member current-state slot on the presence sibling
//! rendezvous record (the app net actor holds the keys, seals/opens, and runs the
//! emit/ingest/reap loop; this crate only moves opaque bytes). Announcements/MOTD
//! transport is live too: [`VeilidNetHandle::publish_current_state`] writes a
//! public signed payload to a named slot on the operator-owned announce record —
//! the owner-signed write is the write-gate (only the project-announce owner-seed
//! holder can write; clients read via [`VeilidNetHandle::subscribe_room`]). The
//! signer-gated composer, the app publish wiring, and the rollback-freshness
//! version field are follow-ons.
//!
//! ## Write scheduler (WB-3 + WB-5.1)
//! Every `set_dht_value` funnels through one prioritized, rate-limited queue
//! ([`schedule`], design `docs/design/veilid-write-budget.md`): chat >
//! session-boundary > advert-refresh > keepalive > republish, per-record FIFO,
//! last-writer-wins current-state coalescing with non-coalescible dominant
//! tombstones, deadline override, shutdown flush/shed, and no read-triggered writes.
//! Concurrency is the WB-5.1 **four-pool partitioned [`dht_gate::DhtGate`]** (chat 2 /
//! I8-floor 1 / write `W_max`=2 / read 9) shared with the read lane, so daemonseed's
//! combined in-flight DHT ops stay provably under veilid's 16-permit gate and reads
//! never drain the write lanes. The non-chat window is the STATIC
//! `min(distinct pending non-chat records, W_max)` — the §I5′.2 acquire-wait controller
//! is retired (under dedicated pools it carries no signal); a dedicated capacity-1 floor
//! lane guarantees starved (`starved_since` past `FLOOR_AGE`) + deadline-due writes
//! forward progress. The actor's write commands and the advert-refresh path enqueue and
//! return, so a slow DHT set never parks the command loop (#154), and a panicked write —
//! including a synchronous dispatch-construction panic — is supervised so it can never
//! wedge the funnel nor leak a lane counter (#168). The scheduler dispatches through the
//! existing per-record write functions, so #131 clamp-at-insert and ring-seq-inside-
//! `record_lock` are untouched; a [`WriteSink`] seam makes it paused-time testable.
//!
//! ## Invariant
//! Content keys NEVER derive from Veilid (classical x25519) material. The seal/
//! open lives in `daemonseed-core`; this crate only moves opaque bytes.

/// Env-gated stderr trace for live attach/circle debugging on a real node.
///
/// Enabled when `DAEMONSEED_VEILID_TRACE` is set (any value); a zero-output
/// no-op otherwise. It exists because the attach and circle-rendezvous paths can
/// only be exercised on a real public-network host (a NAT'd VM blocks attach),
/// where no debugger attaches — so the next felt-test produces a decisive trace
/// instead of an inference. Not a logging framework: a deliberate, minimal probe
/// at the exact points the `veilid-migration` design's fault tree enumerates.
/// Reachable from dependent crates as `daemonseed_veilid_net::vtrace!`.
#[macro_export]
macro_rules! vtrace {
    ($($arg:tt)*) => {
        if ::std::env::var_os("DAEMONSEED_VEILID_TRACE").is_some() {
            ::std::eprintln!(
                "[veilid-net +{:>8.3}s] {}",
                $crate::trace_elapsed_secs(),
                ::std::format_args!($($arg)*)
            );
        }
    };
}

/// Seconds since this process's first trace line, prefixed onto every [`vtrace!`]
/// so a felt-test log carries relative timing. Event ORDER alone cannot show
/// where a deadline was spent (veilid answers an inbound `app_call` for only
/// `rpc.timeout_ms` = 5s; the 2026-07-02 chunk-fetch diagnosis needed to know
/// WHICH 5s elapsed, and the untimestamped trace could not say).
pub fn trace_elapsed_secs() -> f64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    EPOCH
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs_f64()
}

pub mod actor;
pub mod aimd;
pub mod config;
pub mod dht_gate;
pub mod discovery;
pub mod dm;
pub mod download;
pub mod error;
pub mod event;
pub mod identity;
mod rendezvous;
pub mod resweep;
pub mod route_budget;
pub mod schedule;
pub mod share;

pub use actor::{
    PresenceBoundary, VeilidNet, VeilidNetHandle, CLOSE_FLUSH_FLOOR, CLOSE_LEAVE_RESERVE,
    CLOSE_PREFLUSH_BUDGET, GRACEFUL_CLOSE_BUDGET, TEARDOWN_CAP,
};
pub use aimd::AimdWindow;
pub use config::VeilidNetConfig;
pub use dht_gate::{
    DhtGate, GatePermit, CHAT_PERMITS, DHT_BUDGET, DHT_GATE_MARGIN, DHT_GATE_PERMITS,
    FLOOR_PERMITS, READ_PERMITS, R_MIN, W_MAX,
};
pub use discovery::{
    route_provenance_input, verify_route_advert, DiscoveryEnvelope, RouteAdvertSigner,
};
pub use dm::{
    spawn_dm_key_record_publish, AcceptFailure, DmCommand, DmDht, DmDhtFuture, DmDriver,
    DmDriverConfig, DmDriverHandle, DmDriverParts, DmEvent, DmIdentity, PkLt, RefusalReason,
    RequestId, SpentTokenStore, WallClock,
};
pub use error::{FetchErrorClass, Result, VeilidNetError};
pub use event::VeilidNetEvent;
// The rendezvous-owner types travel in the handle's own signatures, so frontends
// name them without reaching into the module.
pub use identity::{OwnerPublic, OwnerSeed, RendezvousOwner};
pub use rendezvous::SweepOutcome;
pub use resweep::next_resweep_record;
pub use route_budget::{
    BudgetPermit, FragmentOutcome, RouteBudget, RouteLease, SharerKey, F_FILES, G_GLOBAL, W_CEIL,
    W_FLOOR,
};
pub use schedule::{
    DispatchOutcome, SchedulerConfig, WriteClass, WriteKind, WriteRequest, WriteScheduler,
    WriteSchedulerHandle, WriteSink,
};
// Re-export the veilid record-key type at the transport boundary so frontends can key a
// [`daemonseed_core::session_health::SessionHealthTracker`] on the record identity carried
// by [`VeilidNetEvent::SweepHealth`] without depending on `veilid-core` directly.
pub use veilid_core::{RecordKey, RouteId};
