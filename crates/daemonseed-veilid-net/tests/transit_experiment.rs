//! Transit experiment for #123: measure private-route `app_call` latency as a
//! function of the route knobs veilid-core 0.5.4 actually exposes, so the
//! share-transfer design session starts from data instead of one anomalous
//! figure (~7.5 s one-way, measured 2026-07-02 under chat-during-fetch load).
//!
//! `#[ignore]` — needs a host that can attach to the PUBLIC Veilid network.
//! Where the network path blocks a public attach, the wait returns `NotReady`
//! after the full timeout. This crate is `[workspace] exclude`d, so `-p` won't resolve
//! it from the repo root — run from the crate's own directory:
//!
//!     cd crates/daemonseed-veilid-net
//!     cargo test --test transit_experiment -- --ignored --nocapture
//!
//! What it measures, per cell (both nodes in ONE process → ONE clock, so the
//! round-trip splits cleanly):
//!   - `rtt` — caller send → reply received
//!   - `req_1way` — caller send → responder's update callback fires
//!   - `reply_op` — the responder's `app_call_reply` call duration (the
//!     unexplained ~4.6 s per-reply serialization question)
//!   - `reply_path` — rtt − req_1way − reply_op (the return transit)
//!
//! The cells (fixed matrix — pre-registered, do not tune mid-run). A/B/C/D
//! form the complete Stability × Sequencing 2×2; E and F are the extra axes:
//!   A  prod-baseline    Reliable + PreferOrdered (private route defaults,
//!                       1 hop), caller = DEFAULT routing context (Safe, 1-hop
//!                       safety) — exactly the shipping fetch path
//!   B  lowlat+ord       LowLatency + PreferOrdered on both route classes
//!   C  lowlat+unord     LowLatency + PreferUnordered on both
//!   D  rel+unord        Reliable + PreferUnordered on both (isolates sequencing)
//!   E  hop2             private route hop_count=2, caller default — the D5
//!                       anonymity dial-up cost, the other direction of interest
//!   F  burst-baseline   cell-A config, 8 CONCURRENT fragment-sized calls on
//!                       ONE shared route via veilid's RoutingContext directly
//!                       (no daemonseed actor FIFO) — reproduces prod's
//!                       one-serve-route-per-share fetch wave and exposes
//!                       reply-op serialization under load
//!
//! Validity envelope (advisor-reviewed — read before quoting numbers):
//!   - LIVE network: default public bootstrap, so relay hops are real remote
//!     nodes; results speak to production transit, at production noise.
//!   - One route allocation per cell and 3 calls per size: this is
//!     order-of-magnitude RECONNAISSANCE for the design session, NOT a policy
//!     ranking — route-instance luck dominates cross-cell deltas, so read the
//!     raw per-call lines, not just the medians.
//!   - Each cell's first call is a marked WARMUP (route handshake / cold
//!     path), excluded from medians; route-alloc attempt counts are reported
//!     per cell (alloc flakiness is itself a result, not just a gate).
//!   - Timestamp points (one monotonic clock, `std::time::Instant`):
//!     `req_1way` ends at the responder's veilid update-callback invocation
//!     (post transport delivery/reassembly); `reply_op` is the awaited
//!     `app_call_reply` (the canned response build is a trivial vec fill);
//!     `reply_path` is the derived remainder.
//!   - No direct node-to-node baseline is possible without veilid's
//!     `footgun-nodeid-target` feature (not shippable for daemonseed), so
//!     private-route overhead vs raw transit is NOT decomposable here.
//!
//! Interpretation guide (pre-registered):
//!   - cell A median rtt ≲ 2–3 s  → transit is NOT route-inherent; the 7.5 s
//!     figure was load/congestion — #123 may need only modest app-level retry.
//!   - cell B/C ≪ A               → stability/sequencing are the levers; the
//!     design session tunes route specs before inventing a transfer protocol.
//!   - all cells ≳ 5 s            → transit really exceeds the app_call ceiling;
//!     the app_message-based transfer (own deadlines) is confirmed necessary.
//!   - cell F reply_op ≫ B–E      → the ~4.6 s reply cost is contention in
//!     veilid's reply path, an input to the transfer design's concurrency.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use veilid_core::{
    api_startup, OperationId, PrivateSpec, RouteBlob, SafetySelection, SafetySpec, Sequencing,
    Stability, Target, VeilidAPI, VeilidConfig, VeilidUpdate,
};

const ATTACH_TIMEOUT_SECS: u64 = 240;
const RESP_SMALL: usize = 256;
const RESP_LARGE: usize = 24 * 1024; // fragment-scale; cap is 32768
const CALLS_PER_SIZE: usize = 3;
const BURST_WIDTH: usize = 8; // mirrors the fetch wave (FRAGMENT_FETCH_CONCURRENCY)
const ALLOC_RETRIES: usize = 3;

/// One answered serve on the responder, keyed by the caller's request tag.
#[derive(Clone, Copy)]
struct ServeRec {
    arrival: Instant,
    reply_op_ms: u128,
}

type Serves = Arc<Mutex<HashMap<u32, ServeRec>>>;

fn node_config(suffix: &str, port: &str, dir: &std::path::Path) -> VeilidConfig {
    // Mirrors the VeilidNet::start config block (actor.rs) minus identity
    // binding — node identity is irrelevant to transit timing.
    let storage = dir.to_string_lossy().into_owned();
    let mut vcfg = VeilidConfig::new(
        "daemonseed_transit_exp",
        "daemonseed",
        "net",
        Some(&storage),
        None,
    );
    vcfg.namespace = format!("transit_exp_{suffix}");
    vcfg.protected_store.always_use_insecure_storage = true;
    vcfg.protected_store.allow_insecure_fallback = true;
    vcfg.network.protocol.udp.listen_address = port.to_owned();
    vcfg.network.protocol.tcp.listen_address = port.to_owned();
    vcfg.network.protocol.ws.listen_address = port.to_owned();
    vcfg
}

/// Attach and poll until public-internet-ready (mirrors actor.rs
/// `attach_and_wait`, logging snapshot changes).
async fn attach_and_wait(api: &VeilidAPI, name: &str) {
    api.attach().await.expect("attach");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(ATTACH_TIMEOUT_SECS);
    let mut last = String::new();
    loop {
        let att = api.get_state().await.expect("get_state").attachment;
        let snap = format!(
            "state={:?} public={} peers(reliable={:?} live={:?})",
            att.state, att.public_internet_ready, att.reliable_peer_count, att.live_peer_count
        );
        if snap != last {
            eprintln!("[{name}] attach: {snap}");
            last = snap;
        }
        if att.public_internet_ready {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{name}: not public-internet-ready within {ATTACH_TIMEOUT_SECS}s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Allocate a route, reporting how many attempts it took — alloc flakiness per
/// policy is a first-class result (a policy that barely allocates is not a
/// candidate, however fast its lucky instances are).
async fn alloc_route(api: &VeilidAPI, spec: &PrivateSpec, cell: &str) -> Option<RouteBlob> {
    for attempt in 1..=ALLOC_RETRIES {
        match api.new_custom_private_route(spec.clone()).await {
            Ok(blob) => {
                eprintln!("[{cell}] route allocated on attempt {attempt}/{ALLOC_RETRIES}");
                return Some(blob);
            }
            Err(e) => {
                eprintln!("[{cell}] route alloc attempt {attempt}/{ALLOC_RETRIES} failed: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    None
}

/// Request wire shape: [tag: u32 LE][resp_size: u32 LE][zero padding to 256 B].
fn request_bytes(tag: u32, resp_size: usize) -> Vec<u8> {
    let mut req = vec![0u8; 256];
    req[0..4].copy_from_slice(&tag.to_le_bytes());
    req[4..8].copy_from_slice(&(resp_size as u32).to_le_bytes());
    req
}

struct CallOutcome {
    tag: u32,
    resp_size: usize,
    rtt_ms: Option<u128>, // None = failed/timed out
    err: Option<String>,
    t0: Instant,
}

async fn one_call(
    rc: &veilid_core::RoutingContext,
    route: &veilid_core::RouteId,
    tag: u32,
    resp_size: usize,
) -> CallOutcome {
    let t0 = Instant::now();
    match rc
        .app_call(
            Target::RouteId(route.clone()),
            request_bytes(tag, resp_size),
        )
        .await
    {
        Ok(resp) => {
            let rtt = t0.elapsed().as_millis();
            assert_eq!(resp.len(), resp_size, "short response for tag {tag}");
            CallOutcome {
                tag,
                resp_size,
                rtt_ms: Some(rtt),
                err: None,
                t0,
            }
        }
        Err(e) => CallOutcome {
            tag,
            resp_size,
            rtt_ms: None,
            err: Some(e.to_string()),
            t0,
        },
    }
}

fn report_call(cell: &str, out: &CallOutcome, serves: &Serves) {
    let serve = serves.lock().unwrap().get(&out.tag).copied();
    let (req_1way, reply_op) = match serve {
        Some(s) => (
            Some(s.arrival.duration_since(out.t0).as_millis()),
            Some(s.reply_op_ms),
        ),
        None => (None, None),
    };
    let fmt_opt = |v: Option<u128>| v.map_or("-".into(), |m| format!("{m}"));
    match out.rtt_ms {
        Some(rtt) => {
            let reply_path = match (req_1way, reply_op) {
                (Some(a), Some(b)) => Some(rtt.saturating_sub(a).saturating_sub(b)),
                _ => None,
            };
            eprintln!(
                "[{cell}] tag={} size={} rtt={}ms req_1way={}ms reply_op={}ms reply_path={}ms",
                out.tag,
                out.resp_size,
                rtt,
                fmt_opt(req_1way),
                fmt_opt(reply_op),
                fmt_opt(reply_path),
            );
        }
        None => eprintln!(
            "[{cell}] tag={} size={} FAILED after {}ms ({}) req_1way={}ms (arrived at all: {})",
            out.tag,
            out.resp_size,
            out.t0.elapsed().as_millis(),
            out.err.as_deref().unwrap_or("?"),
            fmt_opt(req_1way),
            req_1way.is_some(),
        ),
    }
}

fn median(mut v: Vec<u128>) -> Option<u128> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs public Veilid attach; run on a real-network host with --ignored --nocapture"]
async fn private_route_transit_matrix() {
    let base = std::env::temp_dir().join("daemonseed-transit-exp");
    let _ = std::fs::remove_dir_all(&base);

    // ── Responder node A: answers every inbound app_call with the requested
    // number of bytes, immediately, timing the app_call_reply op itself.
    let serves: Serves = Arc::new(Mutex::new(HashMap::new()));
    let (call_tx, mut call_rx) = mpsc::unbounded_channel::<(OperationId, Vec<u8>, Instant)>();
    let cb_a: Arc<dyn Fn(VeilidUpdate) + Send + Sync> = Arc::new(move |u| {
        if let VeilidUpdate::AppCall(call) = u {
            let _ = call_tx.send((call.id(), call.message().to_vec(), Instant::now()));
        }
    });
    let api_a = api_startup(cb_a, node_config("a", ":5250", &base.join("A")))
        .await
        .expect("start A");
    let serves_task = serves.clone();
    let api_a_task = api_a.clone();
    tokio::spawn(async move {
        while let Some((id, msg, arrival)) = call_rx.recv().await {
            let tag = u32::from_le_bytes(msg[0..4].try_into().unwrap());
            let size = u32::from_le_bytes(msg[4..8].try_into().unwrap()) as usize;
            let t = Instant::now();
            let res = api_a_task.app_call_reply(id, vec![0xAB; size]).await;
            let reply_op_ms = t.elapsed().as_millis();
            serves_task.lock().unwrap().insert(
                tag,
                ServeRec {
                    arrival,
                    reply_op_ms,
                },
            );
            if let Err(e) = res {
                eprintln!("[responder] reply for tag={tag} failed after {reply_op_ms}ms: {e}");
            }
        }
    });

    // ── Caller node B.
    let cb_b: Arc<dyn Fn(VeilidUpdate) + Send + Sync> = Arc::new(|_| {});
    let api_b = api_startup(cb_b, node_config("b", ":5251", &base.join("B")))
        .await
        .expect("start B");

    attach_and_wait(&api_a, "A").await;
    attach_and_wait(&api_b, "B").await;

    let spec = |stability: Stability, sequencing: Sequencing, hop_count: usize| PrivateSpec {
        crypto_kinds: vec![],
        hop_count,
        stability,
        sequencing,
    };
    let safety = |stability: Stability, sequencing: Sequencing| {
        SafetySelection::Safe(SafetySpec {
            preferred_route: None,
            hop_count: 0, // 0 → default (1)
            stability,
            sequencing,
        })
    };

    // (name, private route spec, caller safety override — None = prod default)
    let cells: Vec<(&str, PrivateSpec, Option<SafetySelection>)> = vec![
        (
            "A:prod-baseline",
            spec(Stability::Reliable, Sequencing::PreferOrdered, 0),
            None,
        ),
        (
            "B:lowlat+ord",
            spec(Stability::LowLatency, Sequencing::PreferOrdered, 0),
            Some(safety(Stability::LowLatency, Sequencing::PreferOrdered)),
        ),
        (
            "C:lowlat+unord",
            spec(Stability::LowLatency, Sequencing::PreferUnordered, 0),
            Some(safety(Stability::LowLatency, Sequencing::PreferUnordered)),
        ),
        (
            "D:rel+unord",
            spec(Stability::Reliable, Sequencing::PreferUnordered, 0),
            Some(safety(Stability::Reliable, Sequencing::PreferUnordered)),
        ),
        (
            "E:hop2",
            spec(Stability::Reliable, Sequencing::PreferOrdered, 2),
            None,
        ),
    ];

    let mut tag: u32 = 0;
    for (name, private_spec, safety_sel) in &cells {
        eprintln!("── cell {name}: allocating route ({private_spec}) …");
        let Some(blob) = alloc_route(&api_a, private_spec, name).await else {
            eprintln!("[{name}] SKIPPED — route unallocatable (that is itself a datum)");
            continue;
        };
        let route = api_b
            .import_remote_private_route(blob.blob.clone())
            .expect("import");
        let rc = {
            let rc = api_b.routing_context().expect("rc");
            match safety_sel {
                Some(sel) => rc.with_safety(sel.clone()).expect("with_safety"),
                None => rc,
            }
        };

        // Marked warm-up: the route's first call pays handshake/cold-path costs
        // that would contaminate the baseline — excluded from medians.
        tag += 1;
        let warm = one_call(&rc, &route, tag, RESP_SMALL).await;
        report_call(&format!("{name} WARMUP(excluded)"), &warm, &serves);

        let mut rtts_small = Vec::new();
        let mut rtts_large = Vec::new();
        let mut failures = 0usize;
        for &size in &[RESP_SMALL, RESP_LARGE] {
            for _ in 0..CALLS_PER_SIZE {
                tag += 1;
                let out = one_call(&rc, &route, tag, size).await;
                report_call(name, &out, &serves);
                match (out.rtt_ms, size) {
                    (Some(r), RESP_SMALL) => rtts_small.push(r),
                    (Some(r), _) => rtts_large.push(r),
                    (None, _) => failures += 1,
                }
            }
        }
        eprintln!(
            "== cell {name}: median rtt small={:?}ms large={:?}ms failures={failures}/6",
            median(rtts_small),
            median(rtts_large),
        );
        let _ = api_a.release_private_route(blob.route_id);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── Cell F: burst on the prod-baseline config — the fragment wave.
    eprintln!("── cell F:burst-baseline: allocating route …");
    let f_spec = spec(Stability::Reliable, Sequencing::PreferOrdered, 0);
    if let Some(blob) = alloc_route(&api_a, &f_spec, "F:burst-baseline").await {
        let route = api_b
            .import_remote_private_route(blob.blob.clone())
            .expect("import");
        let rc = api_b.routing_context().expect("rc");
        // Warm the route before the wave so F measures burst behavior, not cold start.
        tag += 1;
        let warm = one_call(&rc, &route, tag, RESP_SMALL).await;
        report_call("F:burst-baseline WARMUP(excluded)", &warm, &serves);
        let mut joins = Vec::new();
        for _ in 0..BURST_WIDTH {
            tag += 1;
            let rc = rc.clone();
            let route = route.clone();
            let t = tag;
            joins.push(tokio::spawn(async move {
                one_call(&rc, &route, t, RESP_LARGE).await
            }));
        }
        let mut rtts = Vec::new();
        let mut failures = 0usize;
        for j in joins {
            let out = j.await.expect("join");
            report_call("F:burst-baseline", &out, &serves);
            match out.rtt_ms {
                Some(r) => rtts.push(r),
                None => failures += 1,
            }
        }
        let reply_ops: Vec<u128> = serves
            .lock()
            .unwrap()
            .values()
            .map(|s| s.reply_op_ms)
            .collect();
        eprintln!(
            "== cell F:burst-baseline: median rtt={:?}ms failures={failures}/{BURST_WIDTH} — all-run reply_op median={:?}ms max={:?}ms",
            median(rtts),
            median(reply_ops.clone()),
            reply_ops.iter().max(),
        );
        let _ = api_a.release_private_route(blob.route_id);
    } else {
        eprintln!("[F:burst-baseline] SKIPPED — route unallocatable");
    }

    eprintln!("transit experiment complete — read cell summaries against the interpretation guide in this file's header");
    api_b.shutdown().await;
    api_a.shutdown().await;
}
