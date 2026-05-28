//! Share-fetch envelope (M11 — ISC-19, F23 unified mechanism).
//!
//! Public and CoT shares ride the **same** [`CircleOfTrust.Subscribe`][cot]
//! bidirectional stream as chat circles. What rides inside `CotFrame.payload`
//! differs per asset kind:
//!
//! - **Chat circles** carry a [`prost`]-encoded [`CircleMessage`][circle-msg],
//!   AES-256-GCM-sealed under the circle's `cot_key` ([`crate::circle::message`]).
//! - **Public shares** carry a [`ShareFrame`] encoded by [`ShareFrame::encode`],
//!   plain (ISC-C19 makes public-share content server-visible by design).
//! - **CoT shares** (post-MVP) will carry [`ShareFrame::encode`] output further
//!   sealed under a share-CoT key, using the same `seal_message`/`open_message`
//!   pair already used for chat. **Same wire mechanism, additional encryption
//!   layer — the unified-design property F23 pins.**
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
//!                         chunk_addr(48) | size(u64 BE) ]
//! ```
//!
//! Each frame fits inside a single `CotFrame.payload`. The relay enforces
//! whatever per-frame size limit it likes; the largest realistic frame is a
//! `ChunkResponse` whose chunk-bytes payload is bounded by the file-relay
//! chunk-size policy (single-chunk-per-file alpha; tunable, post-MVP).
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
//! ## Chunk verification (ISC-19 / F23)
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
    /// The chunk address ([`crate::storage::cas::ChunkAddr`]) the fetcher
    /// requests to download this file (1 file = 1 chunk for the M11 alpha;
    /// multi-chunk-per-file is post-MVP, layered on without wire change).
    pub chunk_addr: ChunkAddr,
    /// The file's size in bytes (advisory — the fetcher's authoritative size
    /// check is `data.len()` from the [`ShareFrame::ChunkResponse`] vs the
    /// re-derived SHA-384 match).
    pub size: u64,
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
                let mut out = Vec::with_capacity(1 + 4 + entries.len() * (2 + CHUNK_ADDR_LEN + 8));
                out.push(KIND_MANIFEST_RESPONSE);
                let count = entries.len() as u32;
                out.extend_from_slice(&count.to_be_bytes());
                for e in entries {
                    let path_bytes = e.rel_path.as_bytes();
                    let path_len = path_bytes.len() as u16;
                    out.extend_from_slice(&path_len.to_be_bytes());
                    out.extend_from_slice(path_bytes);
                    out.extend_from_slice(e.chunk_addr.as_bytes());
                    out.extend_from_slice(&e.size.to_be_bytes());
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
                    let addr_bytes = r.read_slice(CHUNK_ADDR_LEN)?;
                    let mut addr = [0u8; CHUNK_ADDR_LEN];
                    addr.copy_from_slice(addr_bytes);
                    let size = r.read_u64_be()?;
                    entries.push(ManifestEntry {
                        rel_path,
                        chunk_addr: ChunkAddr::from_bytes(addr),
                        size,
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
        let _ = oxicrypt_module::initialize();
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
                    chunk_addr: a,
                    size: 13,
                },
                ManifestEntry {
                    rel_path: "sub/b.txt".to_owned(),
                    chunk_addr: b,
                    size: 13,
                },
            ],
        };
        let enc = frame.encode();
        let dec = ShareFrame::decode(&enc).unwrap();
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
        bytes.extend_from_slice(&[0u8; CHUNK_ADDR_LEN]);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(ShareFrame::decode(&bytes), Err(DecodeError::BadUtf8));
    }

    /// ISC-19 / F23: a fetcher verifies a ChunkResponse by recomputing the
    /// SHA-384 of `data` and comparing against the frame's `chunk_addr`. A
    /// chunk forwarded byte-identically passes; a tampered chunk fails closed.
    #[test]
    fn chunk_response_verification_matches_against_recomputed_address() {
        let _ = oxicrypt_module::initialize();
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
        let _ = oxicrypt_module::initialize();
        let a = chunk_addr(&[]).unwrap();
        let frame = ShareFrame::ChunkResponse {
            chunk_addr: a,
            data: Vec::new(),
        };
        let dec = ShareFrame::decode(&frame.encode()).unwrap();
        assert_eq!(dec, frame);
    }
}
