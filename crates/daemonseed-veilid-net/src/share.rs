//! Phase 3 — public-share CONTENT transfer over Veilid `app_call`.
//!
//! Discovery (`rendezvous` / `publish_room`) tells a fetcher a share EXISTS;
//! this module moves its bytes. A 1 MiB content-addressed chunk far exceeds
//! Veilid's 32 KiB `app_call` payload cap, so the transport fragments the
//! SEALED content frame into ≤[`FRAGMENT_SIZE`] pieces the fetcher pulls one
//! `app_call` at a time and reassembles. The 1 MiB SHA-384 content-addressing
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

use std::collections::HashMap;
use std::sync::Arc;

use daemonseed_core::public_room::PublicRoomKey;
use daemonseed_core::share_envelope::{ManifestEntry, ShareFrame};
use daemonseed_core::share_seal::{open_share_frame, seal_public_share_frame};
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::cas::{chunk_addr, ChunkAddr, CHUNK_ADDR_LEN};

use crate::error::{Result, VeilidNetError};

/// Max sealed-content bytes per `app_call` fragment. The response frame is
/// `[status(1)][total(4)][fragment]`; 30 KiB leaves comfortable headroom under
/// the 32768-byte `app_call` cap.
pub const FRAGMENT_SIZE: usize = 30 * 1024;

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
    let bad = || VeilidNetError::Send("malformed share fetch response".to_owned());
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

/// A share registered for serving: its indexed content + the public room key it
/// seals responses under, plus a per-target sealed-response cache so every
/// fragment of one response comes from the SAME seal (AEAD nonce consistency).
pub struct ServedShare {
    content: Arc<ShareContent>,
    room_key: PublicRoomKey,
    cache: HashMap<String, Vec<u8>>,
}

impl ServedShare {
    pub fn new(content: Arc<ShareContent>, room_key: PublicRoomKey) -> Self {
        Self {
            content,
            room_key,
            cache: HashMap::new(),
        }
    }

    /// Build the reply bytes for one fragment request: seal the answer once
    /// (cached), then slice fragment `fragment` out of the cached sealed blob.
    pub fn answer_fragment(&mut self, target: &FetchTarget, fragment: u32) -> Vec<u8> {
        let key = target.cache_key();
        if !self.cache.contains_key(&key) {
            let Some(resp) = self.content.answer(&target.share_frame()) else {
                return encode_response_not_found();
            };
            let Ok(sealed) = seal_public_share_frame(&self.room_key, &resp) else {
                return encode_response_not_found();
            };
            self.cache.insert(key.clone(), sealed);
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
        Some(s) => s.answer_fragment(&target, fragment),
        None => encode_response_not_found(),
    }
}

// ── Fetch side (reassembly + verification) ───────────────────────────────────

/// Reassemble + open the manifest for `share_id`, pulling fragments via `call`
/// (one `app_call` round-trip per fragment).
pub async fn fetch_manifest<F, Fut>(
    share_id: &str,
    room_key: &PublicRoomKey,
    call: F,
) -> Result<Vec<ManifestEntry>>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let sealed = fetch_sealed(share_id, &FetchTarget::Manifest, &call).await?;
    match open_share_frame(room_key, &sealed).map_err(|e| VeilidNetError::Send(e.to_string()))? {
        ShareFrame::ManifestResponse { entries } => Ok(entries),
        _ => Err(VeilidNetError::Send(
            "expected a ManifestResponse".to_owned(),
        )),
    }
}

/// Reassemble + open + VERIFY one content chunk: re-derive SHA-384 over the
/// recovered bytes and reject any mismatch with the requested address
/// (ISC-S28 / ISC-A-S20). A faithful sharer passes by construction; a tampered
/// chunk fails closed.
pub async fn fetch_chunk<F, Fut>(
    share_id: &str,
    want: &ChunkAddr,
    room_key: &PublicRoomKey,
    call: F,
) -> Result<Vec<u8>>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let sealed = fetch_sealed(share_id, &FetchTarget::Chunk(*want), &call).await?;
    let data = match open_share_frame(room_key, &sealed)
        .map_err(|e| VeilidNetError::Send(e.to_string()))?
    {
        ShareFrame::ChunkResponse {
            chunk_addr: got,
            data,
        } => {
            if &got != want {
                return Err(VeilidNetError::Send(
                    "chunk address mismatch in response".to_owned(),
                ));
            }
            data
        }
        _ => return Err(VeilidNetError::Send("expected a ChunkResponse".to_owned())),
    };
    let derived = chunk_addr(&data).map_err(|e| VeilidNetError::Send(e.to_string()))?;
    if &derived != want {
        return Err(VeilidNetError::Send(
            "chunk failed SHA-384 content-address verification (ISC-S28)".to_owned(),
        ));
    }
    Ok(data)
}

/// Pull every fragment of a target via `call` and concatenate into the full
/// sealed blob. `total_fragments` comes from the first reply.
async fn fetch_sealed<F, Fut>(share_id: &str, target: &FetchTarget, call: &F) -> Result<Vec<u8>>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let first = call(encode_request(share_id, target, 0)?).await?;
    let (total, frag0) = decode_response(&first)?
        .ok_or_else(|| VeilidNetError::Send("share/chunk not served (offline?)".to_owned()))?;
    let mut buf = frag0;
    for i in 1..total {
        let reply = call(encode_request(share_id, target, i)?).await?;
        let (_t, frag) = decode_response(&reply)?
            .ok_or_else(|| VeilidNetError::Send("fragment vanished mid-fetch".to_owned()))?;
        buf.extend_from_slice(&frag);
    }
    Ok(buf)
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
            let data = fetch_chunk(&share_id, addr, &rk, &call).await.unwrap();
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
        assert!(matches!(err, VeilidNetError::Send(_)));
    }
}
