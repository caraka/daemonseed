//! Share-fetch envelope (ISC-19, unified mechanism).
//!
//! Public and CoT shares ride the **same** [`CircleOfTrust.Subscribe`][cot]
//! bidirectional stream as chat circles. What rides inside `CotFrame.payload`
//! differs per asset kind:
//!
//! - **Chat circles** carry a [`prost`]-encoded signed [`RoomMessage`][circle-msg],
//!   AES-256-GCM-sealed under the circle's `cot_key` ([`crate::circle::message`]).
//! - **Public shares** carry a [`ShareFrame`] encoded by [`ShareFrame::encode`],
//!   plain (ISC-C19 makes public-share content server-visible by design).
//! - **CoT shares** (post-MVP) will carry [`ShareFrame::encode`] output further
//!   sealed under a share-CoT key, using the same `seal_message`/`open_message`
//!   pair already used for chat. **Same wire mechanism, additional encryption
//!   layer — the unified-design property pins.**
//!
//! Keeping the envelope in a [`Vec<u8>`] codec rather than a new proto message
//! does two things at once:
//!
//! 1. The relay's wire surface (`cot.proto`) stays minimal — `CotFrame { asset_
//!    address, payload }` only. The relay decodes nothing about share traffic;
//!    A-S2 structural opacity holds for both chat and share traffic.
//! 2. M11 stays inside the impl plan's *"0 new ISCs + integration of all prior"*
//!    constraint for §M11 (line 132). The share envelope is a `daemonseed-core`
//!    detail, documented in LAMA, not a new wire schema.
//!
//! ## Wire shape
//!
//! Every encoded `ShareFrame` starts with a one-byte discriminator. All
//! multi-byte integer fields are **big-endian** (network byte order). Strings
//! are UTF-8 with a `u16` BE length prefix; chunk addresses are the raw
//! 48-byte [`crate::storage::cas::ChunkAddr`] bytes.
//!
//! ```text
//!   ManifestRequest  := [0x00]
//!   ManifestResponse := [0x01 | count(u32 BE) | entry × count ]
//!   ChunkRequest     := [0x02 | chunk_addr(48) ]
//!   ChunkResponse    := [0x03 | chunk_addr(48) | data ]
//!
//!   entry            := [ rel_path_len(u16 BE) | rel_path_utf8 |
//!                         size(u64 BE) |
//!                         chunk_count(u32 BE) | chunk_addr(48) × chunk_count ]
//! ```
//!
//! ### ⚠️ M16 in-place format change — alpha compatibility WAIVED
//!
//! The `entry` encoding above is the **M16 sub-file-chunking shape**: each
//! entry carries an ordered per-chunk address list instead of the single
//! whole-file `chunk_addr` the M11..M15 alpha encoded. This is a breaking,
//! in-place change to the `ManifestResponse` body — an old client decoding a
//! new manifest (or vice versa) fails closed as `Truncated`/garbage, by
//! design. The compatibility waiver is deliberate: the alpha test population
//! is the in-house daemon group, both ends rebuild from the same commit, and
//! the relay never decodes `CotFrame.payload` (ISC-A-S2 structural opacity),
//! so deployed relays — including the live fra1 relay — keep working
//! unchanged. `ChunkRequest` / `ChunkResponse` wire shapes are UNCHANGED.
//!
//! Why chunks at all: the single-chunk-per-file alpha put an entire file's
//! bytes into ONE `ChunkResponse`, hence one gRPC frame — an 8.9 MB file
//! blew past tonic's default 4 MB per-message decode cap at the relay and
//! the fetch hung (the live ISC-C73 / ISC-A-C35 gap). Fixed-size
//! [`crate::share_serve::CHUNK_SIZE`] (1 MiB) chunks keep every frame
//! relay-safe regardless of file size, make serve/fetch memory O(1 MiB),
//! and make per-chunk SHA-384 verification cheap.
//!
//! ## Failure modes
//!
//! Decode is fail-closed:
//!
//! - An unknown discriminator → [`DecodeError::UnknownKind`].
//! - A truncated buffer or a length prefix that runs past the buffer →
//!   [`DecodeError::Truncated`].
//! - An invalid UTF-8 `rel_path` → [`DecodeError::BadUtf8`].
//! - A garbage frame from a hostile relay never panics or short-reads;
//!   the fetcher treats any decode failure as "this frame is foreign noise"
//!   (same posture chat already takes per `open_message` returning `Err`).
//!
//! ## Chunk verification (ISC-19)
//!
//! On every `ChunkResponse`, the fetcher MUST re-compute
//! [`crate::storage::cas::chunk_addr`] over `data` and compare against the
//! frame's `chunk_addr`. A mismatch is fatal for that chunk: a relay (or a
//! hostile sharer) cannot serve falsified content to a verifying fetcher
//! without the verifier rejecting it. This is the file-side analog of A-S2's
//! "the relay never decrypts a payload" — here the relay (and even the
//! sharer) cannot mutate a payload undetected.
//!
//! [cot]: crate::cot
//! [circle-msg]: crate::circle::message

use core::fmt;

use crate::storage::cas::{CHUNK_ADDR_LEN, ChunkAddr};

/// One file's entry in a [`ShareFrame::ManifestResponse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// The file's path relative to the share root.
    pub rel_path: String,
    /// The file's size in bytes (advisory — the fetcher's authoritative
    /// integrity check is the per-chunk re-derived SHA-384 match on every
    /// [`ShareFrame::ChunkResponse`]).
    pub size: u64,
    /// The file's **ordered** chunk addresses (ISC-C73 / ISC-A-C35).
    /// The file's bytes are the concatenation of the chunks in this order;
    /// chunk `i` covers `[i*CHUNK_SIZE, min((i+1)*CHUNK_SIZE, size))` with
    /// [`crate::share_serve::CHUNK_SIZE`] fixed at 1 MiB, so only the last
    /// chunk may be short. Each address is the SHA-384
    /// ([`crate::storage::cas::chunk_addr`]) of **that chunk's** bytes — the
    /// fetcher verifies every chunk independently, never buffering more than
    /// one chunk to do so. An empty file is `size: 0, chunks: []` (nothing to
    /// request — the fetcher materializes an empty file).
    pub chunks: Vec<ChunkAddr>,
}

/// One application-level frame inside a [`crate::cot::AssetAddr`]-routed
/// `CotFrame.payload` on the share-fetch path (ISC-19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareFrame {
    /// Fetcher → sharer: "send me the manifest for this share."
    ManifestRequest,
    /// Sharer → fetcher: every file in the share, one entry per file.
    ManifestResponse { entries: Vec<ManifestEntry> },
    /// Fetcher → sharer: "send me the chunk addressed by `chunk_addr`."
    ChunkRequest { chunk_addr: ChunkAddr },
    /// Sharer → fetcher: the chunk's bytes. The fetcher MUST re-derive
    /// SHA-384 over `data` and reject any frame whose recomputed address
    /// does not match `chunk_addr`.
    ChunkResponse {
        chunk_addr: ChunkAddr,
        data: Vec<u8>,
    },
}

const KIND_MANIFEST_REQUEST: u8 = 0x00;
const KIND_MANIFEST_RESPONSE: u8 = 0x01;
const KIND_CHUNK_REQUEST: u8 = 0x02;
const KIND_CHUNK_RESPONSE: u8 = 0x03;

/// Failure modes for [`ShareFrame::decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The discriminator byte did not match a known kind.
    UnknownKind(u8),
    /// The buffer ended before the parser expected; either the frame is
    /// truncated on the wire, or a length prefix names more bytes than the
    /// buffer holds. Treat as foreign / hostile noise.
    Truncated,
    /// A `rel_path` length prefix named bytes that do not decode as UTF-8.
    BadUtf8,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnknownKind(b) => write!(f, "unknown ShareFrame kind: {b:#x}"),
            DecodeError::Truncated => f.write_str("ShareFrame truncated"),
            DecodeError::BadUtf8 => f.write_str("ShareFrame manifest entry rel_path not UTF-8"),
        }
    }
}

impl core::error::Error for DecodeError {}

impl ShareFrame {
    /// Serialize the frame to its on-wire bytes — what rides inside
    /// `CotFrame.payload` for a share asset.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ShareFrame::ManifestRequest => vec![KIND_MANIFEST_REQUEST],
            ShareFrame::ManifestResponse { entries } => {
                // 1 (kind) + 4 (count) + sum(per-entry overhead) + data
                let mut out = Vec::with_capacity(
                    1 + 4
                        + entries
                            .iter()
                            .map(|e| 2 + e.rel_path.len() + 8 + 4 + e.chunks.len() * CHUNK_ADDR_LEN)
                            .sum::<usize>(),
                );
                out.push(KIND_MANIFEST_RESPONSE);
                let count = entries.len() as u32;
                out.extend_from_slice(&count.to_be_bytes());
                for e in entries {
                    let path_bytes = e.rel_path.as_bytes();
                    let path_len = path_bytes.len() as u16;
                    out.extend_from_slice(&path_len.to_be_bytes());
                    out.extend_from_slice(path_bytes);
                    out.extend_from_slice(&e.size.to_be_bytes());
                    // M16: ordered per-chunk address list (see the module
                    // docs' compatibility waiver — this replaced the single
                    // whole-file address in place).
                    let chunk_count = e.chunks.len() as u32;
                    out.extend_from_slice(&chunk_count.to_be_bytes());
                    for addr in &e.chunks {
                        out.extend_from_slice(addr.as_bytes());
                    }
                }
                out
            }
            ShareFrame::ChunkRequest { chunk_addr } => {
                let mut out = Vec::with_capacity(1 + CHUNK_ADDR_LEN);
                out.push(KIND_CHUNK_REQUEST);
                out.extend_from_slice(chunk_addr.as_bytes());
                out
            }
            ShareFrame::ChunkResponse { chunk_addr, data } => {
                let mut out = Vec::with_capacity(1 + CHUNK_ADDR_LEN + data.len());
                out.push(KIND_CHUNK_RESPONSE);
                out.extend_from_slice(chunk_addr.as_bytes());
                out.extend_from_slice(data);
                out
            }
        }
    }

    /// Parse a `CotFrame.payload` into a [`ShareFrame`]. Fail-closed on any
    /// malformed input — the caller treats decode failure as foreign noise.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let kind = r.read_u8()?;
        match kind {
            KIND_MANIFEST_REQUEST => Ok(ShareFrame::ManifestRequest),
            KIND_MANIFEST_RESPONSE => {
                let count = r.read_u32_be()? as usize;
                let mut entries = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    let path_len = r.read_u16_be()? as usize;
                    let path_bytes = r.read_slice(path_len)?;
                    let rel_path = core::str::from_utf8(path_bytes)
                        .map_err(|_| DecodeError::BadUtf8)?
                        .to_owned();
                    let size = r.read_u64_be()?;
                    // M16: ordered per-chunk address list. A chunk_count that
                    // names more addresses than the buffer holds fails closed
                    // as Truncated on the first short read — a hostile count
                    // cannot force a large allocation (capacity is bounded).
                    let chunk_count = r.read_u32_be()? as usize;
                    let mut chunks = Vec::with_capacity(chunk_count.min(1024));
                    for _ in 0..chunk_count {
                        let addr_bytes = r.read_slice(CHUNK_ADDR_LEN)?;
                        let mut addr = [0u8; CHUNK_ADDR_LEN];
                        addr.copy_from_slice(addr_bytes);
                        chunks.push(ChunkAddr::from_bytes(addr));
                    }
                    entries.push(ManifestEntry {
                        rel_path,
                        size,
                        chunks,
                    });
                }
                Ok(ShareFrame::ManifestResponse { entries })
            }
            KIND_CHUNK_REQUEST => {
                let addr_bytes = r.read_slice(CHUNK_ADDR_LEN)?;
                let mut addr = [0u8; CHUNK_ADDR_LEN];
                addr.copy_from_slice(addr_bytes);
                Ok(ShareFrame::ChunkRequest {
                    chunk_addr: ChunkAddr::from_bytes(addr),
                })
            }
            KIND_CHUNK_RESPONSE => {
                let addr_bytes = r.read_slice(CHUNK_ADDR_LEN)?;
                let mut addr = [0u8; CHUNK_ADDR_LEN];
                addr.copy_from_slice(addr_bytes);
                let data = r.remaining().to_vec();
                Ok(ShareFrame::ChunkResponse {
                    chunk_addr: ChunkAddr::from_bytes(addr),
                    data,
                })
            }
            other => Err(DecodeError::UnknownKind(other)),
        }
    }
}

/// A small bounds-checked reader over a byte slice. Every read advances the
/// cursor and returns [`DecodeError::Truncated`] on short reads.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_slice(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        if end > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_slice(1)?[0])
    }

    fn read_u16_be(&mut self) -> Result<u16, DecodeError> {
        let s = self.read_slice(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn read_u32_be(&mut self) -> Result<u32, DecodeError> {
        let s = self.read_slice(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_u64_be(&mut self) -> Result<u64, DecodeError> {
        let s = self.read_slice(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }

    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::cas::chunk_addr;

    fn addr(bytes: &[u8]) -> ChunkAddr {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        chunk_addr(bytes).unwrap()
    }

    #[test]
    fn manifest_request_roundtrip_is_single_byte() {
        let enc = ShareFrame::ManifestRequest.encode();
        assert_eq!(enc, vec![0x00]);
        assert_eq!(
            ShareFrame::decode(&enc).unwrap(),
            ShareFrame::ManifestRequest
        );
    }

    #[test]
    fn manifest_response_roundtrips_multiple_entries() {
        let a = addr(b"alpha content");
        let b = addr(b"bravo content");
        let frame = ShareFrame::ManifestResponse {
            entries: vec![
                ManifestEntry {
                    rel_path: "a.txt".to_owned(),
                    size: 13,
                    chunks: vec![a],
                },
                ManifestEntry {
                    rel_path: "sub/b.txt".to_owned(),
                    size: 13,
                    chunks: vec![b],
                },
            ],
        };
        let enc = frame.encode();
        let dec = ShareFrame::decode(&enc).unwrap();
        assert_eq!(dec, frame);
    }

    /// M16 (ISC-C73 / ISC-A-C35) — an entry whose file spans several chunks
    /// round-trips its ordered address list exactly (order is load-bearing:
    /// the file's bytes are the concatenation of the chunks in this order).
    #[test]
    fn manifest_response_roundtrips_multi_chunk_entry() {
        let c0 = addr(b"chunk zero");
        let c1 = addr(b"chunk one");
        let c2 = addr(b"chunk two (short last)");
        let frame = ShareFrame::ManifestResponse {
            entries: vec![ManifestEntry {
                rel_path: "big.bin".to_owned(),
                size: 2 * 1024 * 1024 + 7,
                chunks: vec![c0, c1, c2],
            }],
        };
        let dec = ShareFrame::decode(&frame.encode()).unwrap();
        assert_eq!(dec, frame);
        match dec {
            ShareFrame::ManifestResponse { entries } => {
                assert_eq!(entries[0].chunks, vec![c0, c1, c2], "order preserved");
            }
            other => panic!("expected ManifestResponse, got {other:?}"),
        }
    }

    /// M16 — an empty file is `size: 0, chunks: []` and round-trips the
    /// envelope (the fetcher materializes it without requesting any chunk).
    #[test]
    fn manifest_response_roundtrips_empty_file_entry() {
        let frame = ShareFrame::ManifestResponse {
            entries: vec![ManifestEntry {
                rel_path: "empty.txt".to_owned(),
                size: 0,
                chunks: Vec::new(),
            }],
        };
        let dec = ShareFrame::decode(&frame.encode()).unwrap();
        assert_eq!(dec, frame);
    }

    #[test]
    fn chunk_request_roundtrip() {
        let a = addr(b"x");
        let frame = ShareFrame::ChunkRequest { chunk_addr: a };
        assert_eq!(ShareFrame::decode(&frame.encode()).unwrap(), frame);
    }

    #[test]
    fn chunk_response_roundtrips_with_data() {
        let data = b"hello world".to_vec();
        let a = addr(&data);
        let frame = ShareFrame::ChunkResponse {
            chunk_addr: a,
            data: data.clone(),
        };
        let dec = ShareFrame::decode(&frame.encode()).unwrap();
        assert_eq!(dec, frame);
    }

    #[test]
    fn unknown_discriminator_is_rejected() {
        let bytes = [0xFFu8];
        assert_eq!(
            ShareFrame::decode(&bytes),
            Err(DecodeError::UnknownKind(0xFF))
        );
    }

    #[test]
    fn empty_buffer_is_truncated() {
        assert_eq!(ShareFrame::decode(&[]), Err(DecodeError::Truncated));
    }

    #[test]
    fn chunk_request_short_addr_is_truncated() {
        let mut bytes = vec![KIND_CHUNK_REQUEST];
        bytes.extend_from_slice(&[0u8; CHUNK_ADDR_LEN - 1]); // 47 bytes, need 48
        assert_eq!(ShareFrame::decode(&bytes), Err(DecodeError::Truncated));
    }

    #[test]
    fn manifest_response_truncated_count_is_caught() {
        let bytes = vec![KIND_MANIFEST_RESPONSE, 0u8, 0u8, 0u8]; // 3 of 4 count bytes
        assert_eq!(ShareFrame::decode(&bytes), Err(DecodeError::Truncated));
    }

    #[test]
    fn manifest_response_overrun_count_is_caught() {
        // count=1 but no entry bytes follow.
        let mut bytes = vec![KIND_MANIFEST_RESPONSE];
        bytes.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(ShareFrame::decode(&bytes), Err(DecodeError::Truncated));
    }

    #[test]
    fn manifest_entry_bad_utf8_path_is_rejected() {
        // Hand-craft a manifest response with one entry whose rel_path bytes
        // are not valid UTF-8.
        let mut bytes = vec![KIND_MANIFEST_RESPONSE];
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes()); // path_len = 2
        bytes.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        bytes.extend_from_slice(&0u64.to_be_bytes()); // size
        bytes.extend_from_slice(&0u32.to_be_bytes()); // chunk_count = 0
        assert_eq!(ShareFrame::decode(&bytes), Err(DecodeError::BadUtf8));
    }

    /// M16 — a chunk_count that names more addresses than the buffer holds
    /// fails closed as Truncated (a hostile relay cannot smuggle a short
    /// chunk list past the parser, nor force a huge allocation).
    #[test]
    fn manifest_entry_truncated_chunk_list_is_caught() {
        let mut bytes = vec![KIND_MANIFEST_RESPONSE];
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes()); // path_len = 1
        bytes.push(b'f');
        bytes.extend_from_slice(&100u64.to_be_bytes()); // size
        bytes.extend_from_slice(&2u32.to_be_bytes()); // chunk_count = 2 …
        bytes.extend_from_slice(&[0u8; CHUNK_ADDR_LEN]); // … but only 1 addr
        assert_eq!(ShareFrame::decode(&bytes), Err(DecodeError::Truncated));
    }

    /// ISC-19: a fetcher verifies a ChunkResponse by recomputing the
    /// SHA-384 of `data` and comparing against the frame's `chunk_addr`. A
    /// chunk forwarded byte-identically passes; a tampered chunk fails closed.
    #[test]
    fn chunk_response_verification_matches_against_recomputed_address() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let original = b"the quick brown fox jumps over the lazy dog";
        let advertised = chunk_addr(original).unwrap();

        // A faithful forward (identical bytes) verifies.
        let faithful = ShareFrame::ChunkResponse {
            chunk_addr: advertised,
            data: original.to_vec(),
        };
        let dec = match ShareFrame::decode(&faithful.encode()).unwrap() {
            ShareFrame::ChunkResponse { chunk_addr, data } => (chunk_addr, data),
            _ => panic!("expected ChunkResponse"),
        };
        let recomputed = chunk_addr(&dec.1).unwrap();
        assert_eq!(recomputed, dec.0, "faithful forward verifies");

        // A tampered chunk (one bit flipped) fails the recompute check —
        // the chunk_addr in the frame still names the original content, but
        // the data hashes differently.
        let mut tampered = original.to_vec();
        tampered[0] ^= 0x01;
        let hostile = ShareFrame::ChunkResponse {
            chunk_addr: advertised, // unchanged, advertising the original
            data: tampered.clone(),
        };
        let dec = match ShareFrame::decode(&hostile.encode()).unwrap() {
            ShareFrame::ChunkResponse { chunk_addr, data } => (chunk_addr, data),
            _ => panic!("expected ChunkResponse"),
        };
        let recomputed = chunk_addr(&dec.1).unwrap();
        assert_ne!(recomputed, dec.0, "tampered chunk fails closed");
    }

    /// Empty `data` on a ChunkResponse is allowed (zero-byte file is a valid
    /// share entry); decode still produces an empty Vec rather than failing.
    #[test]
    fn chunk_response_with_empty_data_roundtrips() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let a = chunk_addr(&[]).unwrap();
        let frame = ShareFrame::ChunkResponse {
            chunk_addr: a,
            data: Vec::new(),
        };
        let dec = ShareFrame::decode(&frame.encode()).unwrap();
        assert_eq!(dec, frame);
    }
}
