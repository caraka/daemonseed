//! Phase 3 — public-share CONTENT transfer over Veilid `app_call`.
//!
//! Discovery (`rendezvous` / `publish_room`) tells a fetcher a share EXISTS;
//! this module moves its bytes. A 1 MiB content-addressed chunk far exceeds
//! Veilid's 32 KiB `app_call` payload cap, so the transport fragments the
//! SEALED content frame into ≤[`FRAGMENT_SIZE`] pieces the fetcher pulls in a
//! bounded-concurrency pipeline ([`FRAGMENT_FETCH_CONCURRENCY`] `app_call`s in
//! flight, in request order) and reassembles. The 1 MiB SHA-384 content-addressing
//! is untouched (D-3.4, "the cleaner invariant"): the fetcher reassembles a
//! chunk, opens it under the `PublicRoomKey`, and re-derives SHA-384 to verify
//! it against the requested address (ISC-S28 / ISC-A-S20).
//!
//! Anti-dox (D-3.5): the sharer serves over a private route (its blob hides its
//! node/IP); the fetcher addresses `Target::RouteId` from its default safe
//! context. Content stays sealed under the `PublicRoomKey` — the route sees
//! ciphertext (ISC-A-S22), the same single-encryption-layer rule as circles.
//!
//! Fragment consistency: AES-256-GCM draws a fresh random nonce per seal, so
//! every fragment of one response MUST come from ONE seal. The serve side seals
//! each answer once and caches it ([`ServedShare`]), slicing fragments from the
//! cached blob; the fetcher reassembles all fragments before opening.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{self, StreamExt, TryStreamExt};

use daemonseed_core::public_room::PublicRoomKey;
use daemonseed_core::share_envelope::{ManifestEntry, ShareFrame};
use daemonseed_core::share_seal::{open_share_frame, seal_public_share_frame};
use daemonseed_core::share_serve::{ShareContent, MANIFEST_FRAME_BUDGET};
use daemonseed_core::storage::cas::{chunk_addr, ChunkAddr, CHUNK_ADDR_LEN};

use crate::error::{Result, VeilidNetError};
use crate::route_budget::{FragmentOutcome, RouteLease, W_CEIL};

/// Max sealed-content bytes per `app_call` fragment. The response frame is
/// `[status(1)][total(4)][fragment]`; 30 KiB leaves comfortable headroom under
/// the 32768-byte `app_call` cap.
pub const FRAGMENT_SIZE: usize = 30 * 1024;

/// Largest legitimate reassembled sealed response: a `MANIFEST_FRAME_BUDGET`
/// (3.5 MB) manifest dominates a 1 MiB content chunk, plus AEAD + framing
/// headroom. A reply claiming more than this — by fragment count or cumulative
/// bytes — is a malicious or buggy sharer; the fetcher rejects it BEFORE the
/// SHA-384 check (which only runs after full reassembly), bounding the fetch-side
/// `app_call` loop and its allocation against an attacker-controlled `total`.
const MAX_REASSEMBLED_LEN: usize = MANIFEST_FRAME_BUDGET + 64 * 1024;
const MAX_FRAGMENTS: u32 = MAX_REASSEMBLED_LEN.div_ceil(FRAGMENT_SIZE) as u32;

/// Per-fragment `app_call` retry budget. Veilid private routes are work-in-progress
/// on stability: a single round-trip among a chunk's ~34 fragments can transiently
/// time out, and without a retry one timeout fails the whole chunk (observed live —
/// `chunk fetch failed: send failed: Timeout`). Retry a fragment a few times with a
/// brief backoff before giving up.
const FRAGMENT_RETRIES: u32 = 3;
const FRAGMENT_RETRY_BACKOFF_MS: u64 = 250;

/// How many fragment `app_call`s (after fragment 0) are kept in flight at once.
/// Fragment 0 is fetched alone to learn `total`; fragments `1..total` are then
/// pipelined — up to this many concurrent round-trips within the one fetch task
/// (`StreamExt::buffered`, no spawn, so the in-process `call` closures need not
/// be `Send`/`'static`). Pipelining still collapses a chunk's serial round-trips
/// into fewer waves (the wall-clock win behind #109), just at a lower concurrency.
///
/// Set to 2 (#204): a multi-file folder download sustains this window across many
/// fragments, and a 2-client felt-test on veilid 0.5.7 showed a wider window kills
/// the serving private route mid-fetch — the whole folder fails with
/// `could not get remote private route`, while single files (one brief wave)
/// succeed. A bisect landed 2 as the widest window a folder downloads cleanly at
/// (8 and 4 both killed the route; 1 and 2 held). The route tolerates almost no
/// fetch-side concurrency on 0.5.7, so this stays conservative until the adaptive
/// window below is live-wired (the real fix — climb only while the route stays
/// healthy; #128 D-1 wiring, motivated by #204).
///
/// This is also the CEILING (and the safe-by-default starting value) of the
/// fetcher-side [`crate::AimdWindow`] adaptive window (#128 D-1): a healthy
/// download runs fully open at this cap, and the controller only narrows below it
/// on a latency breach.
pub const FRAGMENT_FETCH_CONCURRENCY: usize = 2;

/// Per-fragment `app_call` round-trip latency at or above which the fetcher-side
/// AIMD window treats the link as congested and backs off (#128 D-1). INITIAL,
/// felt-test-tunable value: a healthy private-route fragment `app_call` runs well
/// under this (the transit experiment's worst observed rtt was ~1.7 s), while
/// veilid's inbound `app_call` answer window (~5 s) is the hard ceiling — so a
/// fragment reaching this threshold signals real congestion and is the point to
/// yield concurrency (and thus bandwidth) back to interactive chat. Kept as a
/// named `const` so the fat-link felt-test can retune it in one place.
pub const FRAGMENT_LATENCY_THRESHOLD: Duration = Duration::from_secs(2);

/// A legitimate fragment is sliced to ≤[`FRAGMENT_SIZE`] on the serve side
/// ([`ServedShare::answer_fragment`]); a larger one is malformed or hostile.
/// Capping each fragment keeps the reassembly bound at
/// `MAX_FRAGMENTS × FRAGMENT_SIZE = `[`MAX_REASSEMBLED_LEN`] even though the
/// pipelined fetch can no longer abort mid-stream the way the serial loop did —
/// a strictly stronger bound than the prior cumulative-only check.
fn check_fragment_size(frag: &[u8]) -> Result<()> {
    if frag.len() > FRAGMENT_SIZE {
        return Err(VeilidNetError::Integrity(format!(
            "fragment is {} bytes, over the {FRAGMENT_SIZE}-byte cap (malicious?)",
            frag.len()
        )));
    }
    Ok(())
}

/// A `share_id` is 128 bits hex-encoded — 32 ASCII chars (`mint_share_id`).
const SHARE_ID_LEN: usize = 32;

const REQ_MANIFEST: u8 = 0x00;
const REQ_CHUNK: u8 = 0x01;
const RESP_OK: u8 = 0x00;
const RESP_NOT_FOUND: u8 = 0x01;

/// What a fetcher is pulling: the manifest, or one content chunk.
#[derive(Clone)]
pub enum FetchTarget {
    Manifest,
    Chunk(ChunkAddr),
}

impl FetchTarget {
    /// Serve-side cache key for the sealed-response cache.
    fn cache_key(&self) -> String {
        match self {
            FetchTarget::Manifest => "manifest".to_owned(),
            FetchTarget::Chunk(a) => hex(a.as_bytes()),
        }
    }

    fn share_frame(&self) -> ShareFrame {
        match self {
            FetchTarget::Manifest => ShareFrame::ManifestRequest,
            FetchTarget::Chunk(a) => ShareFrame::ChunkRequest { chunk_addr: *a },
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Request framing (fetcher → sharer) ───────────────────────────────────────

/// `[tag][share_id(32)]([chunk_addr(48)] iff chunk)[fragment(u32 BE)]`.
pub fn encode_request(share_id: &str, target: &FetchTarget, fragment: u32) -> Result<Vec<u8>> {
    if share_id.len() != SHARE_ID_LEN {
        return Err(VeilidNetError::Send(format!(
            "share_id must be {SHARE_ID_LEN} chars, got {}",
            share_id.len()
        )));
    }
    let mut buf = Vec::with_capacity(1 + SHARE_ID_LEN + CHUNK_ADDR_LEN + 4);
    buf.push(match target {
        FetchTarget::Manifest => REQ_MANIFEST,
        FetchTarget::Chunk(_) => REQ_CHUNK,
    });
    buf.extend_from_slice(share_id.as_bytes());
    if let FetchTarget::Chunk(a) = target {
        buf.extend_from_slice(a.as_bytes());
    }
    buf.extend_from_slice(&fragment.to_be_bytes());
    Ok(buf)
}

/// Decode an inbound request frame to `(share_id, target, fragment)`. Fails
/// closed on any malformed input (hostile/foreign noise → no answer).
pub fn decode_request(bytes: &[u8]) -> Result<(String, FetchTarget, u32)> {
    let bad = || VeilidNetError::Send("malformed share fetch request".to_owned());
    let tag = *bytes.first().ok_or_else(bad)?;
    let rest = &bytes[1..];
    let (share_id_bytes, rest) = rest.split_at_checked(SHARE_ID_LEN).ok_or_else(bad)?;
    let share_id = std::str::from_utf8(share_id_bytes)
        .map_err(|_| bad())?
        .to_owned();
    let (target, rest) = match tag {
        REQ_MANIFEST => (FetchTarget::Manifest, rest),
        REQ_CHUNK => {
            let (addr, rest) = rest.split_at_checked(CHUNK_ADDR_LEN).ok_or_else(bad)?;
            let mut a = [0u8; CHUNK_ADDR_LEN];
            a.copy_from_slice(addr);
            (FetchTarget::Chunk(ChunkAddr::from_bytes(a)), rest)
        }
        _ => return Err(bad()),
    };
    let frag: [u8; 4] = rest.try_into().map_err(|_| bad())?;
    Ok((share_id, target, u32::from_be_bytes(frag)))
}

// ── Response framing (sharer → fetcher) ──────────────────────────────────────

fn encode_response_ok(total: u32, fragment: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + fragment.len());
    buf.push(RESP_OK);
    buf.extend_from_slice(&total.to_be_bytes());
    buf.extend_from_slice(fragment);
    buf
}

fn encode_response_not_found() -> Vec<u8> {
    vec![RESP_NOT_FOUND]
}

/// Decode a reply to `Some((total_fragments, fragment_bytes))`, or `None` when
/// the sharer holds no such share/chunk (offline-equivalent — ISC-A-S21).
pub fn decode_response(bytes: &[u8]) -> Result<Option<(u32, Vec<u8>)>> {
    let bad = || VeilidNetError::Integrity("malformed share fetch response".to_owned());
    match *bytes.first().ok_or_else(bad)? {
        RESP_NOT_FOUND => Ok(None),
        RESP_OK => {
            let total: [u8; 4] = bytes
                .get(1..5)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?;
            Ok(Some((u32::from_be_bytes(total), bytes[5..].to_vec())))
        }
        _ => Err(bad()),
    }
}

// ── Serve side ───────────────────────────────────────────────────────────────

/// Max distinct per-target sealed responses cached per share. Each entry is at
/// most a `MANIFEST_FRAME_BUDGET`/1-MiB-chunk sealed blob, so a large share's many
/// chunks could otherwise grow the cache to the whole share. A fetcher (with #109
/// fragment pipelining) holds ONE target's fragments in flight at a time, so this
/// covers many concurrent fetchers before any mid-fetch eviction; an eviction
/// beyond capacity is fail-closed (a re-seal under a fresh nonce makes the
/// fetcher's mixed-seal reassembly fail its AEAD open — it errors, never accepts
/// bytes), not corruption.
const SEAL_CACHE_CAPACITY: usize = 16;

/// A share registered for serving: its indexed content + the public room key it
/// seals responses under, plus a bounded-LRU per-target sealed-response cache so
/// every fragment of one response comes from the SAME seal (AEAD nonce consistency).
pub struct ServedShare {
    content: Arc<ShareContent>,
    room_key: PublicRoomKey,
    cache: HashMap<String, Vec<u8>>,
    /// LRU recency, oldest at the front — bounds `cache` to [`SEAL_CACHE_CAPACITY`].
    lru: VecDeque<String>,
    /// When this share last answered a fetch request. The #124 advert watchdog reads
    /// it to skip re-allocating a route that is actively serving a download — rotating
    /// an in-use route would kill the recipient's single imported route mid-transfer.
    last_served: Instant,
}

impl ServedShare {
    pub fn new(content: Arc<ShareContent>, room_key: PublicRoomKey) -> Self {
        Self {
            content,
            room_key,
            cache: HashMap::new(),
            lru: VecDeque::new(),
            last_served: Instant::now(),
        }
    }

    /// When this share last answered a fetch request (the #124 watchdog's
    /// route-in-use signal). Stamped by [`serve`] on every matched request.
    pub fn last_served(&self) -> Instant {
        self.last_served
    }

    /// Mark `key` most-recently-used (move it to the back of the recency ring).
    fn touch(&mut self, key: &str) {
        if let Some(pos) = self.lru.iter().position(|k| k == key) {
            if let Some(k) = self.lru.remove(pos) {
                self.lru.push_back(k);
            }
        }
    }

    /// Insert a freshly-sealed blob as most-recently-used, evicting the
    /// least-recently-used entries first to hold the cache at capacity.
    fn insert_cached(&mut self, key: String, sealed: Vec<u8>) {
        while self.cache.len() >= SEAL_CACHE_CAPACITY {
            match self.lru.pop_front() {
                Some(old) => {
                    self.cache.remove(&old);
                }
                None => break,
            }
        }
        self.lru.push_back(key.clone());
        self.cache.insert(key, sealed);
    }

    /// Build the reply bytes for one fragment request: seal the answer once
    /// (cached), then slice fragment `fragment` out of the cached sealed blob.
    pub fn answer_fragment(&mut self, target: &FetchTarget, fragment: u32) -> Vec<u8> {
        let key = target.cache_key();
        if self.cache.contains_key(&key) {
            self.touch(&key);
        } else {
            let Some(resp) = self.content.answer(&target.share_frame()) else {
                return encode_response_not_found();
            };
            let Ok(sealed) = seal_public_share_frame(&self.room_key, &resp) else {
                return encode_response_not_found();
            };
            self.insert_cached(key.clone(), sealed);
        }
        let sealed = &self.cache[&key];
        let total = sealed.len().div_ceil(FRAGMENT_SIZE).max(1) as u32;
        let start = fragment as usize * FRAGMENT_SIZE;
        if start >= sealed.len() {
            return encode_response_not_found();
        }
        let end = (start + FRAGMENT_SIZE).min(sealed.len());
        encode_response_ok(total, &sealed[start..end])
    }
}

/// Answer a raw inbound request frame against a registry of served shares;
/// returns the reply bytes for `app_call_reply`. An unknown share/chunk or a
/// malformed request yields `NOT_FOUND` — the serve side never fabricates
/// content (ISC-A-S21).
pub fn serve(shares: &mut HashMap<String, ServedShare>, request: &[u8]) -> Vec<u8> {
    let Ok((share_id, target, fragment)) = decode_request(request) else {
        return encode_response_not_found();
    };
    match shares.get_mut(&share_id) {
        Some(s) => {
            // Stamp route-in-use so the #124 watchdog does not rotate this share's
            // route out from under an active download.
            s.last_served = Instant::now();
            s.answer_fragment(&target, fragment)
        }
        None => encode_response_not_found(),
    }
}

// ── Fetch side (reassembly + verification) ───────────────────────────────────

/// Open a reassembled sealed MANIFEST response frame. A malformed frame or the
/// wrong frame type is an [`VeilidNetError::Integrity`] (hostile / corrupt
/// sharer), fatal for the share.
fn open_manifest_frame(room_key: &PublicRoomKey, sealed: &[u8]) -> Result<Vec<ManifestEntry>> {
    match open_share_frame(room_key, sealed)
        .map_err(|e| VeilidNetError::Integrity(e.to_string()))?
    {
        ShareFrame::ManifestResponse { entries } => Ok(entries),
        _ => Err(VeilidNetError::Integrity(
            "expected a ManifestResponse".to_owned(),
        )),
    }
}

/// Open + VERIFY one reassembled sealed CHUNK response against `want`: re-derive
/// SHA-384 over the recovered bytes and reject any mismatch with the requested
/// address (ISC-S28 / ISC-A-S20). A faithful sharer passes by construction; a
/// tampered chunk, an address mismatch, or a wrong frame is an
/// [`VeilidNetError::Integrity`], fatal for the share.
fn open_and_verify_chunk(
    room_key: &PublicRoomKey,
    want: &ChunkAddr,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    let data = match open_share_frame(room_key, sealed)
        .map_err(|e| VeilidNetError::Integrity(e.to_string()))?
    {
        ShareFrame::ChunkResponse {
            chunk_addr: got,
            data,
        } => {
            if &got != want {
                return Err(VeilidNetError::Integrity(
                    "chunk address mismatch in response".to_owned(),
                ));
            }
            data
        }
        _ => {
            return Err(VeilidNetError::Integrity(
                "expected a ChunkResponse".to_owned(),
            ))
        }
    };
    let derived = chunk_addr(&data).map_err(|e| VeilidNetError::Integrity(e.to_string()))?;
    if &derived != want {
        return Err(VeilidNetError::Integrity(
            "chunk failed SHA-384 content-address verification (ISC-S28)".to_owned(),
        ));
    }
    Ok(data)
}

/// Reassemble + open the manifest for `share_id`, pulling fragments via `call`
/// (one `app_call` round-trip per fragment).
///
/// **Legacy window-parameter path** (retired at design step 7). New callers use
/// [`fetch_manifest_budgeted`], which admits every fragment through a shared
/// per-route [`crate::RouteBudget`] instead of a per-fetch window.
pub async fn fetch_manifest<F, Fut>(
    share_id: &str,
    room_key: &PublicRoomKey,
    call: F,
) -> Result<Vec<ManifestEntry>>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    // The manifest is one small fetch, fetched fully open at the ceiling; its
    // latency does not feed the adaptive window (that adapts across content chunks).
    let (sealed, _lat) = fetch_sealed(
        share_id,
        &FetchTarget::Manifest,
        FRAGMENT_FETCH_CONCURRENCY,
        &call,
    )
    .await?;
    open_manifest_frame(room_key, &sealed)
}

/// Reassemble + open + VERIFY one content chunk (ISC-S28 / ISC-A-S20).
///
/// **Legacy window-parameter path** (retired at design step 7). `window` caps
/// how many fragment `app_call`s run in flight for this chunk (the fetcher-side
/// AIMD window, #128 D-1). New callers use [`fetch_chunk_budgeted`]. Returns the
/// chunk bytes plus the MAX per-fragment round-trip latency observed.
pub async fn fetch_chunk<F, Fut>(
    share_id: &str,
    want: &ChunkAddr,
    room_key: &PublicRoomKey,
    window: usize,
    call: F,
) -> Result<(Vec<u8>, Duration)>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let (sealed, max_latency) =
        fetch_sealed(share_id, &FetchTarget::Chunk(*want), window, &call).await?;
    Ok((open_and_verify_chunk(room_key, want, &sealed)?, max_latency))
}

/// Pull every fragment of a target via `call` and concatenate into the full
/// sealed blob. `total_fragments` comes from the first reply.
/// One fragment `app_call`, retried on a transient transport error (e.g. Timeout)
/// up to [`FRAGMENT_RETRIES`] times. A retryable error is any `call` Err — a
/// not_found / withdraw is a SUCCESSFUL reply the caller decodes (`decode_response`
/// → `None`), never an Err here, so retry can never mask an authoritative negative.
async fn call_fragment<F, Fut>(call: &F, request: Vec<u8>) -> Result<Vec<u8>>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let mut last: Option<VeilidNetError> = None;
    for attempt in 0..=FRAGMENT_RETRIES {
        match call(request.clone()).await {
            Ok(reply) => return Ok(reply),
            Err(e) => {
                crate::vtrace!(
                    "fetch fragment app_call attempt {} failed: {e}",
                    attempt + 1
                );
                last = Some(e);
                if attempt < FRAGMENT_RETRIES {
                    tokio::time::sleep(std::time::Duration::from_millis(FRAGMENT_RETRY_BACKOFF_MS))
                        .await;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| VeilidNetError::Send("fragment fetch failed".to_owned())))
}

/// Pull every fragment of `target` and concatenate into the full sealed blob,
/// keeping up to `window` fragment `app_call`s in flight (the AIMD-controlled
/// concurrency, #128 D-1). Returns the blob plus the MAX per-fragment round-trip
/// latency observed across ALL fragments (fragment 0 included) — the congestion
/// signal the caller feeds back to its window controller.
async fn fetch_sealed<F, Fut>(
    share_id: &str,
    target: &FetchTarget,
    window: usize,
    call: &F,
) -> Result<(Vec<u8>, Duration)>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let frag0_started = Instant::now();
    let first = call_fragment(call, encode_request(share_id, target, 0)?).await?;
    let mut max_latency = frag0_started.elapsed();
    // A decoded not_found means the owner ANSWERED — the share is withdrawn or was
    // never offered, NOT offline (an offline owner errors `call` above, surfacing as
    // a transport error). This authoritative negative lets the client distinguish a
    // deliberate withdraw from a silent disconnect.
    let (total, frag0) = decode_response(&first)?.ok_or(VeilidNetError::NotServed)?;
    // The sharer is untrusted (any public announcer): a malicious `total` would
    // drive a ~4-billion-`app_call` loop, and oversize fragments would grow the
    // buffer without bound. Cap the fragment count up front and every fragment's
    // size as it lands — the SHA-384 chunk check only runs after the full blob is
    // in memory, so it is no defense here. `total ≤ MAX_FRAGMENTS` plus each
    // fragment `≤ FRAGMENT_SIZE` bounds reassembly at MAX_REASSEMBLED_LEN even
    // though the pipelined fetch can't abort mid-stream like the serial loop did.
    if total > MAX_FRAGMENTS {
        return Err(VeilidNetError::Integrity(format!(
            "sharer claims {total} fragments, over the {MAX_FRAGMENTS} cap (malicious?)"
        )));
    }
    check_fragment_size(&frag0)?;
    // Pipeline fragments 1..total (#109): `buffered` keeps up to `window`
    // round-trips in flight AND yields them in request order, so reassembly stays
    // a simple in-order concat. `window` is the AIMD-controlled cap (#128 D-1),
    // floored at 1 so a fetch never stalls to zero concurrency. Polling happens
    // within this one task (no spawn) → the `call` closure needs no Send/'static,
    // so the in-process test transports keep working. Each fragment is timed and
    // returned with its round-trip latency; a fragment that vanishes, oversteps its
    // size cap, or fails its retry budget fails the whole fetch (`try_collect`).
    let rest: Vec<(Vec<u8>, Duration)> = stream::iter(1..total)
        .map(|i| async move {
            let started = Instant::now();
            let reply = call_fragment(call, encode_request(share_id, target, i)?).await?;
            let latency = started.elapsed();
            let (_t, frag) = decode_response(&reply)?
                .ok_or_else(|| VeilidNetError::Send("fragment vanished mid-fetch".to_owned()))?;
            check_fragment_size(&frag)?;
            Ok::<(Vec<u8>, Duration), VeilidNetError>((frag, latency))
        })
        .buffered(window.max(1))
        .try_collect()
        .await?;

    let mut buf = frag0;
    for (frag, latency) in rest {
        max_latency = max_latency.max(latency);
        buf.extend_from_slice(&frag);
    }
    // Backstop the per-fragment cap: even within bounds the concat must not exceed
    // the largest legitimate reassembled response.
    if buf.len() > MAX_REASSEMBLED_LEN {
        return Err(VeilidNetError::Integrity(
            "reassembled share response exceeds the size cap (malicious?)".to_owned(),
        ));
    }
    Ok((buf, max_latency))
}

// ── Budget-backed fetch seam (download-subsystem redesign, step 3) ────────────
//
// The per-route [`crate::RouteBudget`] replaces the per-fetch `window`: every
// fragment `app_call` is admitted through a shared `RouteLease`, so files,
// chunks, and fragments parallelize freely underneath ONE per-route cap. The
// legacy window-parameter path above stays until design step 7 retires it, so
// both frontends keep compiling at every commit.

/// One fragment `app_call`, admitted through `lease`'s per-route budget and
/// retried on a transient transport error up to [`FRAGMENT_RETRIES`] times. The
/// permit is acquired for each attempt and DROPPED before any backoff sleep
/// (DL-ISC-6: no admission is held across the sleep, so a dying route's doomed
/// retries never pin the global pool). Returns the reply, or the last transport
/// error after the retry budget is exhausted.
async fn call_fragment_budgeted<R, F, Fut>(
    lease: &RouteLease<R>,
    call: &F,
    request: Vec<u8>,
) -> Result<Vec<u8>>
where
    R: Clone + Eq + std::hash::Hash,
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let mut last: Option<VeilidNetError> = None;
    for attempt in 0..=FRAGMENT_RETRIES {
        let permit = lease.acquire().await;
        let result = call(request.clone()).await;
        drop(permit); // release BEFORE any backoff sleep (DL-ISC-6)
        match result {
            Ok(reply) => return Ok(reply),
            Err(e) => {
                crate::vtrace!(
                    "fetch fragment app_call attempt {} failed: {e}",
                    attempt + 1
                );
                last = Some(e);
                if attempt < FRAGMENT_RETRIES {
                    tokio::time::sleep(std::time::Duration::from_millis(FRAGMENT_RETRY_BACKOFF_MS))
                        .await;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| VeilidNetError::Send("fragment fetch failed".to_owned())))
}

/// Pull every fragment of `target` under the per-route budget and concatenate
/// into the full sealed blob. Every fragment `app_call` is admitted through
/// `lease` (the single per-route limiter — no per-fetch window), and each
/// fragment's outcome feeds the window controller: a completion as
/// [`FragmentOutcome::Completed`] (its latency vs [`FRAGMENT_LATENCY_THRESHOLD`]
/// is the coexistence-valve signal), a terminal transport failure as
/// [`FragmentOutcome::Failed`] (window collapse). Content-integrity errors
/// (malformed / oversized / verify) abort the fetch but do NOT signal the
/// controller — the route is fine, the content is hostile. The stream yields in
/// request order for a simple in-order concat.
async fn fetch_sealed_budgeted<R, F, Fut>(
    share_id: &str,
    target: &FetchTarget,
    lease: &RouteLease<R>,
    call: &F,
) -> Result<(Vec<u8>, Duration)>
where
    R: Clone + Eq + std::hash::Hash,
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let frag0_started = Instant::now();
    let first =
        match call_fragment_budgeted(lease, call, encode_request(share_id, target, 0)?).await {
            Ok(r) => r,
            Err(e) => {
                lease.observe(FragmentOutcome::Failed);
                return Err(e);
            }
        };
    let frag0_latency = frag0_started.elapsed();
    lease.observe(FragmentOutcome::Completed {
        over_threshold: frag0_latency >= FRAGMENT_LATENCY_THRESHOLD,
    });
    let mut max_latency = frag0_latency;
    let (total, frag0) = decode_response(&first)?.ok_or(VeilidNetError::NotServed)?;
    if total > MAX_FRAGMENTS {
        return Err(VeilidNetError::Integrity(format!(
            "sharer claims {total} fragments, over the {MAX_FRAGMENTS} cap (malicious?)"
        )));
    }
    check_fragment_size(&frag0)?;
    // Poll up to W_CEIL fragment futures at once for in-order yield; the BUDGET
    // (not this bound) is the real concurrency limiter — each future blocks on
    // admission, so total in-flight app_calls to the route stay ≤ W(route), and
    // fragments across concurrent chunks/files on the same lease share that cap.
    let rest: Vec<(Vec<u8>, Duration)> = stream::iter(1..total)
        .map(|i| async move {
            let started = Instant::now();
            let reply =
                match call_fragment_budgeted(lease, call, encode_request(share_id, target, i)?)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        lease.observe(FragmentOutcome::Failed);
                        return Err(e);
                    }
                };
            let latency = started.elapsed();
            lease.observe(FragmentOutcome::Completed {
                over_threshold: latency >= FRAGMENT_LATENCY_THRESHOLD,
            });
            let (_t, frag) = decode_response(&reply)?
                .ok_or_else(|| VeilidNetError::Send("fragment vanished mid-fetch".to_owned()))?;
            check_fragment_size(&frag)?;
            Ok::<(Vec<u8>, Duration), VeilidNetError>((frag, latency))
        })
        .buffered(W_CEIL)
        .try_collect()
        .await?;
    let mut buf = frag0;
    for (frag, latency) in rest {
        max_latency = max_latency.max(latency);
        buf.extend_from_slice(&frag);
    }
    if buf.len() > MAX_REASSEMBLED_LEN {
        return Err(VeilidNetError::Integrity(
            "reassembled share response exceeds the size cap (malicious?)".to_owned(),
        ));
    }
    Ok((buf, max_latency))
}

/// Budget-admitted manifest fetch — the [`fetch_manifest`] replacement that
/// admits every fragment through the shared per-route [`crate::RouteBudget`].
pub async fn fetch_manifest_budgeted<R, F, Fut>(
    share_id: &str,
    room_key: &PublicRoomKey,
    lease: &RouteLease<R>,
    call: F,
) -> Result<Vec<ManifestEntry>>
where
    R: Clone + Eq + std::hash::Hash,
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let (sealed, _lat) =
        fetch_sealed_budgeted(share_id, &FetchTarget::Manifest, lease, &call).await?;
    open_manifest_frame(room_key, &sealed)
}

/// Budget-admitted chunk fetch — the [`fetch_chunk`] replacement (ISC-S28 /
/// ISC-A-S20). Returns the verified chunk bytes plus the MAX per-fragment
/// latency observed (kept for telemetry; the controller is fed live via
/// `lease.observe` inside the fetch).
pub async fn fetch_chunk_budgeted<R, F, Fut>(
    share_id: &str,
    want: &ChunkAddr,
    room_key: &PublicRoomKey,
    lease: &RouteLease<R>,
    call: F,
) -> Result<(Vec<u8>, Duration)>
where
    R: Clone + Eq + std::hash::Hash,
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let (sealed, max_latency) =
        fetch_sealed_budgeted(share_id, &FetchTarget::Chunk(*want), lease, &call).await?;
    Ok((open_and_verify_chunk(room_key, want, &sealed)?, max_latency))
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::crypto::suite::CNSA_2_0;
    use daemonseed_core::public_room::derive_room_key;

    fn room_key() -> PublicRoomKey {
        let _ = oxicrypt_module::initialize();
        derive_room_key("lobby", &CNSA_2_0).unwrap()
    }

    #[test]
    fn request_round_trips_manifest_and_chunk() {
        let id = "0123456789abcdef0123456789abcdef";
        let m = encode_request(id, &FetchTarget::Manifest, 0).unwrap();
        let (sid, t, frag) = decode_request(&m).unwrap();
        assert_eq!(sid, id);
        assert!(matches!(t, FetchTarget::Manifest));
        assert_eq!(frag, 0);

        let addr = ChunkAddr::from_bytes([7u8; CHUNK_ADDR_LEN]);
        let c = encode_request(id, &FetchTarget::Chunk(addr), 5).unwrap();
        let (sid, t, frag) = decode_request(&c).unwrap();
        assert_eq!(sid, id);
        match t {
            FetchTarget::Chunk(a) => assert_eq!(a.as_bytes(), &[7u8; CHUNK_ADDR_LEN]),
            _ => panic!("expected chunk"),
        }
        assert_eq!(frag, 5);
    }

    #[test]
    fn bad_share_id_length_rejected() {
        assert!(encode_request("too-short", &FetchTarget::Manifest, 0).is_err());
        assert!(decode_request(b"\x00short").is_err());
    }

    /// End-to-end in-process: serve a real indexed share through the fragment
    /// protocol and fetch the manifest + every chunk back, verifying SHA-384 —
    /// no Veilid, the `call` closure routes straight to `serve()`. A >FRAGMENT_SIZE
    /// chunk exercises real multi-fragment reassembly.
    #[tokio::test]
    async fn serve_then_fetch_round_trip_with_fragmentation() {
        let _ = oxicrypt_module::initialize();
        let dir = std::env::temp_dir().join(format!("ds-share-frag-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A file larger than FRAGMENT_SIZE so the sealed chunk spans >1 fragment.
        let payload = vec![0xABu8; FRAGMENT_SIZE * 2 + 123];
        std::fs::write(dir.join("blob.bin"), &payload).unwrap();

        let content = Arc::new(ShareContent::index_dir(&dir).unwrap());
        let rk = room_key();
        let mut shares: HashMap<String, ServedShare> = HashMap::new();
        let share_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        shares.insert(
            share_id.clone(),
            ServedShare::new(content.clone(), room_key()),
        );
        let shares = std::sync::Mutex::new(shares);

        // The transport: route a request straight into serve().
        let call = |req: Vec<u8>| {
            let reply = serve(&mut shares.lock().unwrap(), &req);
            async move { Ok(reply) }
        };

        let manifest = fetch_manifest(&share_id, &rk, &call).await.unwrap();
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].rel_path, "blob.bin");

        // Fetch + verify every chunk, reassemble the file, compare to the source.
        let mut recovered = Vec::new();
        for addr in &manifest[0].chunks {
            let (data, _lat) = fetch_chunk(&share_id, addr, &rk, FRAGMENT_FETCH_CONCURRENCY, &call)
                .await
                .unwrap();
            recovered.extend_from_slice(&data);
        }
        assert_eq!(recovered, payload, "fetched bytes match the served file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fetch_unknown_share_is_not_found() {
        let _ = oxicrypt_module::initialize();
        let shares: std::sync::Mutex<HashMap<String, ServedShare>> =
            std::sync::Mutex::new(HashMap::new());
        let call = |req: Vec<u8>| {
            let reply = serve(&mut shares.lock().unwrap(), &req);
            async move { Ok(reply) }
        };
        let rk = room_key();
        let err = fetch_manifest("ffffffffffffffffffffffffffffffff", &rk, &call)
            .await
            .unwrap_err();
        // The peer answered not_found → the authoritative NotServed (withdrawn /
        // never offered), distinct from a transport error (offline / slow).
        assert!(matches!(err, VeilidNetError::NotServed));
    }

    #[tokio::test]
    async fn call_fragment_retries_a_transient_error_then_succeeds() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let attempts = AtomicU32::new(0);
        // Times out on the first two attempts, then succeeds — a flaky private-route
        // round-trip that recovers within the retry budget (the live Timeout case).
        let call = |_req: Vec<u8>| {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(VeilidNetError::Send("Timeout".to_owned()))
                } else {
                    Ok(vec![9, 9, 9])
                }
            }
        };
        let reply = call_fragment(&call, vec![0]).await.unwrap();
        assert_eq!(reply, vec![9, 9, 9]);
        assert_eq!(attempts.load(Ordering::SeqCst), 3, "2 timeouts + 1 success");
    }

    #[tokio::test]
    async fn call_fragment_gives_up_after_the_retry_budget() {
        let call =
            |_req: Vec<u8>| async { Err::<Vec<u8>, _>(VeilidNetError::Send("Timeout".to_owned())) };
        assert!(matches!(
            call_fragment(&call, vec![0]).await.unwrap_err(),
            VeilidNetError::Send(_)
        ));
    }

    /// A malicious sharer claiming more fragments than any legitimate response
    /// is rejected before the reassembly loop (bounds the fetch-side DoS).
    #[tokio::test]
    async fn oversized_fragment_total_is_rejected() {
        let _ = oxicrypt_module::initialize();
        let rk = room_key();
        let call = |_req: Vec<u8>| {
            let reply = encode_response_ok(MAX_FRAGMENTS + 1, &[0u8; 16]);
            async move { Ok(reply) }
        };
        let err = fetch_manifest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &rk, &call)
            .await
            .unwrap_err();
        assert!(matches!(err, VeilidNetError::Integrity(_)));
    }

    /// #109 — fragments after fragment 0 are pulled CONCURRENTLY, and the
    /// out-of-order completion still reassembles in request order. A real
    /// multi-fragment chunk is served through an instrumented transport that
    /// records the peak number of fragment `app_call`s in flight at once and
    /// forces overlap with a small async delay. Pipelining is proven iff the
    /// peak exceeds 1 (a serial fetcher could never exceed 1); correctness is
    /// proven by the byte-for-byte recovery.
    #[tokio::test]
    async fn fragments_pipeline_concurrently_and_reassemble_in_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let _ = oxicrypt_module::initialize();
        let dir = std::env::temp_dir().join(format!("ds-share-pipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // One file well over FRAGMENT_SIZE but under the 1 MiB chunk size, so it
        // is a single content chunk whose SEALED form spans ~20 fragments —
        // comfortably more than FRAGMENT_FETCH_CONCURRENCY, so the window fills.
        let payload = vec![0xCDu8; FRAGMENT_SIZE * 20 + 7];
        std::fs::write(dir.join("blob.bin"), &payload).unwrap();

        let content = Arc::new(ShareContent::index_dir(&dir).unwrap());
        let rk = room_key();
        let mut shares: HashMap<String, ServedShare> = HashMap::new();
        let share_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
        shares.insert(
            share_id.clone(),
            ServedShare::new(content.clone(), room_key()),
        );
        let shares = std::sync::Mutex::new(shares);

        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let call = |req: Vec<u8>| {
            // serve() is synchronous; run it up front (the lock is released before
            // the future is awaited, so reassembly concurrency isn't serialized by
            // the test's own mutex).
            let reply = serve(&mut shares.lock().unwrap(), &req);
            let in_flight = in_flight.clone();
            let peak = peak.clone();
            async move {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(reply)
            }
        };

        let manifest = fetch_manifest(&share_id, &rk, &call).await.unwrap();
        assert_eq!(manifest[0].chunks.len(), 1, "600 KB < 1 MiB ⇒ one chunk");
        peak.store(0, Ordering::SeqCst); // measure the chunk fetch, not the manifest

        let (data, _lat) = fetch_chunk(
            &share_id,
            &manifest[0].chunks[0],
            &rk,
            FRAGMENT_FETCH_CONCURRENCY,
            &call,
        )
        .await
        .unwrap();
        assert_eq!(
            data, payload,
            "reassembled chunk is byte-for-byte the source"
        );
        let observed = peak.load(Ordering::SeqCst);
        assert!(
            observed > 1,
            "fragments must overlap (peak in-flight {observed}, serial would be 1)"
        );
        assert!(
            observed <= FRAGMENT_FETCH_CONCURRENCY,
            "concurrency stays bounded by the window (peak {observed})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A single oversized fragment (beyond [`FRAGMENT_SIZE`]) is rejected, holding
    /// the reassembly memory bound now that the pipelined fetch can't abort
    /// mid-stream on the running cumulative total.
    #[tokio::test]
    async fn oversized_fragment_is_rejected() {
        let _ = oxicrypt_module::initialize();
        let rk = room_key();
        // total=2: fragment 0 ok-sized, fragment 1 one byte over the cap.
        let call = |req: Vec<u8>| {
            let (_sid, _t, frag) = decode_request(&req).unwrap();
            let reply = if frag == 0 {
                encode_response_ok(2, &[0u8; 16])
            } else {
                encode_response_ok(2, &vec![0u8; FRAGMENT_SIZE + 1])
            };
            async move { Ok(reply) }
        };
        let err = fetch_manifest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &rk, &call)
            .await
            .unwrap_err();
        assert!(matches!(err, VeilidNetError::Integrity(_)));
    }

    /// The serve-side seal cache is LRU-bounded: more distinct targets than
    /// capacity evicts the least-recently-used, never growing past the cap, and a
    /// touched (recently-used) entry survives further inserts.
    #[test]
    fn seal_cache_is_lru_bounded() {
        let _ = oxicrypt_module::initialize();
        let dir = std::env::temp_dir().join(format!("ds-share-lru-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.bin"), [0u8; 8]).unwrap();
        let content = Arc::new(ShareContent::index_dir(&dir).unwrap());
        let mut s = ServedShare::new(content, room_key());

        for i in 0..(SEAL_CACHE_CAPACITY + 5) {
            s.insert_cached(format!("k{i}"), vec![0u8; 8]);
        }
        assert_eq!(s.cache.len(), SEAL_CACHE_CAPACITY, "cache held at capacity");
        assert_eq!(s.lru.len(), s.cache.len(), "recency ring tracks the cache");
        assert!(!s.cache.contains_key("k0"), "oldest evicted");
        let newest = format!("k{}", SEAL_CACHE_CAPACITY + 4);
        assert!(s.cache.contains_key(&newest), "newest retained");

        // Touch the current LRU entry → it becomes MRU and survives the next insert.
        let oldest_kept = s.lru.front().unwrap().clone();
        s.touch(&oldest_kept);
        s.insert_cached("knew".into(), vec![0u8; 8]);
        assert!(
            s.cache.contains_key(&oldest_kept),
            "a touched entry is not the next evicted"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DL-ISC-6 (seam): the budget-backed fetch admits every fragment `app_call`
    /// through the shared per-route budget — a multi-fragment chunk reassembles
    /// byte-for-byte, fragments overlap (peak > 1), peak in-flight never exceeds
    /// the route ceiling W_CEIL, and the controller climbed as fragments
    /// completed (observe feedback is wired).
    #[tokio::test]
    async fn budgeted_fetch_reassembles_and_admits_through_the_route_budget() {
        use crate::route_budget::{RouteBudget, SharerKey, W_CEIL, W_FLOOR};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let _ = oxicrypt_module::initialize();
        let dir = std::env::temp_dir().join(format!("ds-share-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // One file spanning ~20 fragments as a single content chunk.
        let payload = vec![0xABu8; FRAGMENT_SIZE * 20 + 7];
        std::fs::write(dir.join("blob.bin"), &payload).unwrap();
        let content = Arc::new(ShareContent::index_dir(&dir).unwrap());
        let rk = room_key();
        let mut shares: HashMap<String, ServedShare> = HashMap::new();
        let share_id = "cccccccccccccccccccccccccccccccc".to_owned();
        shares.insert(
            share_id.clone(),
            ServedShare::new(content.clone(), room_key()),
        );
        let shares = std::sync::Mutex::new(shares);

        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let call = |req: Vec<u8>| {
            let reply = serve(&mut shares.lock().unwrap(), &req);
            let (in_flight, peak) = (in_flight.clone(), peak.clone());
            async move {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(reply)
            }
        };

        let budget = Arc::new(RouteBudget::<u32>::new());
        let lease = budget.lease(7, SharerKey(vec![7]));

        let manifest = fetch_manifest_budgeted(&share_id, &rk, &lease, &call)
            .await
            .unwrap();
        assert_eq!(manifest[0].chunks.len(), 1, "600 KB < 1 MiB ⇒ one chunk");
        peak.store(0, Ordering::SeqCst); // measure the chunk fetch, not the manifest

        let (data, _lat) =
            fetch_chunk_budgeted(&share_id, &manifest[0].chunks[0], &rk, &lease, &call)
                .await
                .unwrap();
        assert_eq!(data, payload, "budgeted fetch reassembles byte-for-byte");
        let observed = peak.load(Ordering::SeqCst);
        assert!(
            observed > 1,
            "fragments admitted concurrently (peak {observed})"
        );
        assert!(
            observed <= W_CEIL,
            "never exceeds the route ceiling (peak {observed})"
        );
        assert!(
            budget.route_width(&7) > W_FLOOR,
            "the controller climbed as fragments completed (observe wired)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
