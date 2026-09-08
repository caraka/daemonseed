//! Content-addressed chunk store — the third storage layer.
//!
//! daemonseed splits at-rest state three ways: the encrypted seeds blob
//! ([`super::seeds`]), the redb-backed indexed state (M8+), and this
//! content-addressed chunk filesystem. A *chunk* is an opaque, already-
//! encrypted byte run; the store neither knows nor cares what a chunk
//! decrypts to. Chunks are named by their own hash, so an address both
//! locates a chunk and authenticates it: a fetched chunk whose re-hash does
//! not match the address it was requested under is corrupt or substituted,
//! and the caller drops it.
//!
//! ## Addressing — `SHA-384(chunk)` (F23, resolved 2026-05-26)
//!
//! A [`ChunkAddr`] is the 48-byte SHA-384 of the chunk's bytes — the same
//! hash primitive used for public-space content addresses
//! ([`crate::public_space::ContentAddress`]) and handles, keeping one hash
//! across the whole protocol per the CNSA 2.0 ≥192-bit floor. SHA-256 was
//! considered (Demonsaw-era plan 7c) and rejected: a second primitive buys
//! nothing and widens the audit surface.
//!
//! ## Reference counting (ISC-4 / ISC-A-S5)
//!
//! The same chunk may back several shares or arrive from several producers,
//! so the store dedups by address and tracks a per-chunk reference count.
//! [`ChunkStore::put`] inserts-or-increments; [`ChunkStore::unref`] decrements
//! and reports whether references remain ([`Unref::StillReferenced`]) or the
//! last one was released and the bytes were dropped ([`Unref::Dropped`]).
//! On a relay this is the mechanism behind the server-blind lifecycle: a
//! subscribe takes a reference, a disconnect releases it, and the asset
//! ceases to exist at zero — the relay retains nothing once the last
//! interested party leaves (ISC-A-S5).
//!
//! ## Constant-time presence (ISC-3 / ISC-A-S2)
//!
//! [`ChunkStore::has`] is the relay's answer to "do you hold chunk X?" — a
//! query an adversary controls. A variable-time answer (the natural hash-map
//! lookup) leaks presence through timing: a hit and a miss take measurably
//! different times, letting a prober confirm which chunks a relay holds and
//! thereby what a circle is sharing. [`MemoryChunkStore::has`] therefore
//! compares the queried address against *every* stored address in constant
//! time per comparison, folding the results into a single accumulator with
//! no data-dependent early return (`ct_eq`). Its running time depends only
//! on how many chunks the store holds, never on whether — or where — the
//! queried address sits among them. `get` and `unref` keep the O(1) map
//! lookup: they are operations by authorized participants holding the
//! address already, not adversary probes, so the timing side-channel
//! (ISC-A-S2) does not apply to them.
//!
//! ## Two implementations
//!
//! - [`MemoryChunkStore`] — ephemeral, refcounted, in-memory. The relay's
//!   cas backing: nothing touches disk, so an offline circle leaves no trace
//!   (ISC-A-S5). This is the store whose `has()` carries the constant-time
//!   guarantee.
//! - [`FileChunkStore`] — persistent, on-disk, refcounted via an ASCII
//!   sidecar. The client's own chunk cache: a sharer's chunks survive process
//!   restarts (ISC-6), which is what makes an offline sharer's content
//!   *temporarily unavailable* rather than *lost*. Its `has()` is best-effort
//!   only — filesystem `stat` timing is the OS's to leak, not ours — so it
//!   carries no constant-time claim; the A-S2 threat is a relay threat and
//!   the relay runs the in-memory store.

use core::fmt;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use oxicrypt_module::Error as OxicryptError;
use oxicrypt_sha::sha384;

/// Length of a SHA-384 chunk address, in bytes.
pub const CHUNK_ADDR_LEN: usize = 48;

/// A `SHA-384(chunk)` content address (F23).
///
/// The address is *derived* from the chunk's bytes, never read off the wire
/// and trusted — re-hashing a fetched chunk and comparing to the address it
/// was requested under is what detects a corrupt or substituted chunk. The
/// derived `==` is used for equality elsewhere; the constant-time path is
/// `ct_eq`, used deliberately by [`MemoryChunkStore::has`] (see module docs).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkAddr([u8; CHUNK_ADDR_LEN]);

impl ChunkAddr {
    /// The raw 48-byte digest.
    pub fn as_bytes(&self) -> &[u8; CHUNK_ADDR_LEN] {
        &self.0
    }

    /// Reconstruct an address from raw bytes — e.g. a fetch request that
    /// names the chunk it wants by address. The bytes are not re-validated
    /// (an address is just a 48-byte name); authentication happens when the
    /// fetched chunk is re-hashed against this address.
    pub fn from_bytes(bytes: [u8; CHUNK_ADDR_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for ChunkAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for ChunkAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ChunkAddr")
            .field(&hex::encode(self.0))
            .finish()
    }
}

/// Compute a chunk's address: `SHA-384(chunk)` (ISC-2 / F23).
///
/// Returns the underlying oxicrypt error only if SHA-384's power-up self-test
/// has not yet passed (first hash in a fresh process).
pub fn chunk_addr(chunk: &[u8]) -> Result<ChunkAddr, OxicryptError> {
    let digest = sha384(chunk)?;
    let mut out = [0u8; CHUNK_ADDR_LEN];
    out.copy_from_slice(&digest[..CHUNK_ADDR_LEN]);
    Ok(ChunkAddr(out))
}

/// Constant-time byte-slice equality.
///
/// No data-dependent early return: every byte is XOR-folded into one
/// accumulator, so the running time is independent of *where* (or whether) a
/// mismatch occurs. [`core::hint::black_box`] stops the optimizer from
/// reintroducing a short-circuit. The length check is intentionally
/// variable-time — chunk-address lengths are fixed (48) and public, so they
/// carry no secret. This closes the timing side-channel (ISC-A-S2) a naive
/// compare would open on the relay's presence query (ISC-3).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

/// Outcome of releasing one reference to a chunk (ISC-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unref {
    /// One reference released; others remain, so the chunk bytes are retained.
    StillReferenced {
        /// References remaining after the decrement (always ≥ 1).
        remaining: u32,
    },
    /// The last reference was released; the chunk bytes were dropped from the
    /// store. On a relay this is the server-blind teardown of ISC-A-S5.
    Dropped,
}

/// Failure modes for a [`ChunkStore`] operation.
#[derive(Debug)]
pub enum CasError {
    /// SHA-384 hashing failed — oxicrypt's power-up self-test has not passed
    /// in this process. Only [`ChunkStore::put`] can raise it (it is the only
    /// operation that hashes).
    Hash(OxicryptError),
    /// Filesystem I/O failed. [`FileChunkStore`] only; [`MemoryChunkStore`]
    /// never raises it.
    Io(std::io::Error),
    /// An on-disk refcount sidecar was missing or unparseable while its chunk
    /// file was present — a corrupt store, surfaced rather than guessed at.
    CorruptRefcount,
}

impl fmt::Display for CasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CasError::Hash(e) => write!(f, "chunk hashing failed: {e:?}"),
            CasError::Io(e) => write!(f, "chunk store I/O failed: {e}"),
            CasError::CorruptRefcount => {
                f.write_str("chunk store corrupt: refcount sidecar missing or unparseable")
            }
        }
    }
}

impl core::error::Error for CasError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            CasError::Io(e) => Some(e),
            CasError::Hash(_) | CasError::CorruptRefcount => None,
        }
    }
}

/// A content-addressed, reference-counted chunk store (ISC-1).
///
/// `put` inserts a chunk (or increments an existing one's refcount) and
/// returns its derived address; `get` fetches bytes by address; `has` answers
/// presence; `unref` releases one reference and reports whether the chunk
/// survived. Implementations choose their durability and timing properties —
/// see [`MemoryChunkStore`] and [`FileChunkStore`].
pub trait ChunkStore {
    /// Store `chunk`, returning its [`ChunkAddr`]. If the chunk is already
    /// present (same bytes ⟹ same address) its reference count is incremented
    /// and the bytes are not re-stored.
    fn put(&mut self, chunk: &[u8]) -> Result<ChunkAddr, CasError>;

    /// Fetch a chunk's bytes by address. `Ok(None)` if absent.
    fn get(&self, addr: &ChunkAddr) -> Result<Option<Vec<u8>>, CasError>;

    /// Presence test. See [`MemoryChunkStore::has`] for the constant-time
    /// guarantee that closes ISC-A-S2.
    fn has(&self, addr: &ChunkAddr) -> Result<bool, CasError>;

    /// Release one reference. Returns [`Unref::StillReferenced`] if others
    /// remain, or [`Unref::Dropped`] if this was the last (the bytes are then
    /// gone). Unref-ing an absent chunk is a no-op that reports
    /// [`Unref::Dropped`] — the post-condition "not in store" already holds.
    fn unref(&mut self, addr: &ChunkAddr) -> Result<Unref, CasError>;
}

// ── In-memory, refcounted store (relay cas backing, ISC-A-S5) ─────────────

struct MemEntry {
    bytes: Vec<u8>,
    refs: u32,
}

/// Ephemeral, reference-counted, in-memory chunk store — the relay's backing
/// (ISC-A-S5). Holds nothing on disk: when the last reference to a chunk is
/// released the bytes vanish, and when the process ends the whole store does,
/// so an offline circle leaves no trace on the relay.
#[derive(Default)]
pub struct MemoryChunkStore {
    chunks: HashMap<[u8; CHUNK_ADDR_LEN], MemEntry>,
}

impl MemoryChunkStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ChunkStore for MemoryChunkStore {
    fn put(&mut self, chunk: &[u8]) -> Result<ChunkAddr, CasError> {
        let addr = chunk_addr(chunk).map_err(CasError::Hash)?;
        self.chunks
            .entry(addr.0)
            .and_modify(|e| e.refs += 1)
            .or_insert_with(|| MemEntry {
                bytes: chunk.to_vec(),
                refs: 1,
            });
        Ok(addr)
    }

    fn get(&self, addr: &ChunkAddr) -> Result<Option<Vec<u8>>, CasError> {
        Ok(self.chunks.get(&addr.0).map(|e| e.bytes.clone()))
    }

    /// Constant-time with respect to whether `addr` is present: every stored
    /// address is compared via `ct_eq` and the results folded into one
    /// accumulator with no early return, so a hit and a miss take the same
    /// time for a given store size (ISC-3 / ISC-A-S2). This deliberately
    /// forgoes the O(1) hash-map lookup `get`/`unref` use.
    fn has(&self, addr: &ChunkAddr) -> Result<bool, CasError> {
        let mut found = false;
        for key in self.chunks.keys() {
            // Bitwise OR (not `||`) so every comparison runs; no branch on the
            // running result.
            found |= ct_eq(key, addr.as_bytes());
        }
        Ok(found)
    }

    fn unref(&mut self, addr: &ChunkAddr) -> Result<Unref, CasError> {
        match self.chunks.get_mut(&addr.0) {
            Some(entry) if entry.refs > 1 => {
                entry.refs -= 1;
                Ok(Unref::StillReferenced {
                    remaining: entry.refs,
                })
            }
            Some(_) => {
                self.chunks.remove(&addr.0);
                Ok(Unref::Dropped)
            }
            None => Ok(Unref::Dropped),
        }
    }
}

// ── On-disk, persistent store (client chunk cache, ISC-6) ─────────────────

/// Persistent, reference-counted, on-disk chunk store — the client's own
/// chunk cache (ISC-6). Each chunk is one file named by its hex address; its
/// refcount lives in an adjacent `<hex>.rc` ASCII sidecar so dedup survives
/// process restarts. A sharer's chunks persisting here is what makes an
/// offline sharer's content temporarily *unavailable* rather than *lost*.
///
/// `has()` is best-effort only: filesystem `stat` timing is the OS's to leak.
/// The ISC-A-S2 constant-time guarantee belongs to [`MemoryChunkStore`], which
/// is what a relay runs; this store is local to one client.
pub struct FileChunkStore {
    root: PathBuf,
}

impl FileChunkStore {
    /// Open (creating if needed) a chunk store rooted at `root`. Reopening an
    /// existing root recovers every chunk and refcount written before — the
    /// basis of cross-launch persistence (ISC-6).
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CasError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(CasError::Io)?;
        Ok(Self { root })
    }

    fn chunk_path(&self, addr: &ChunkAddr) -> PathBuf {
        self.root.join(hex::encode(addr.0))
    }

    fn rc_path(&self, addr: &ChunkAddr) -> PathBuf {
        self.root.join(format!("{}.rc", hex::encode(addr.0)))
    }

    fn read_rc(path: &Path) -> Result<u32, CasError> {
        let raw = std::fs::read_to_string(path).map_err(|_| CasError::CorruptRefcount)?;
        raw.trim()
            .parse::<u32>()
            .map_err(|_| CasError::CorruptRefcount)
    }

    fn write_rc(path: &Path, n: u32) -> Result<(), CasError> {
        std::fs::write(path, n.to_string()).map_err(CasError::Io)
    }
}

impl ChunkStore for FileChunkStore {
    fn put(&mut self, chunk: &[u8]) -> Result<ChunkAddr, CasError> {
        let addr = chunk_addr(chunk).map_err(CasError::Hash)?;
        let chunk_path = self.chunk_path(&addr);
        let rc_path = self.rc_path(&addr);
        if chunk_path.exists() {
            let n = Self::read_rc(&rc_path)?;
            Self::write_rc(&rc_path, n.saturating_add(1))?;
        } else {
            std::fs::write(&chunk_path, chunk).map_err(CasError::Io)?;
            Self::write_rc(&rc_path, 1)?;
        }
        Ok(addr)
    }

    fn get(&self, addr: &ChunkAddr) -> Result<Option<Vec<u8>>, CasError> {
        match std::fs::read(self.chunk_path(addr)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CasError::Io(e)),
        }
    }

    /// Best-effort presence test (a filesystem existence check). Unlike
    /// [`MemoryChunkStore::has`] this carries no constant-time guarantee — see
    /// the type docs.
    fn has(&self, addr: &ChunkAddr) -> Result<bool, CasError> {
        Ok(self.chunk_path(addr).exists())
    }

    fn unref(&mut self, addr: &ChunkAddr) -> Result<Unref, CasError> {
        let chunk_path = self.chunk_path(addr);
        if !chunk_path.exists() {
            return Ok(Unref::Dropped);
        }
        let rc_path = self.rc_path(addr);
        let n = Self::read_rc(&rc_path)?;
        if n <= 1 {
            std::fs::remove_file(&chunk_path).map_err(CasError::Io)?;
            // Best-effort sidecar cleanup; a stray .rc without its chunk is
            // harmless (a future put re-creates it).
            let _ = std::fs::remove_file(&rc_path);
            Ok(Unref::Dropped)
        } else {
            Self::write_rc(&rc_path, n - 1)?;
            Ok(Unref::StillReferenced { remaining: n - 1 })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHUNK_A: &[u8] = b"the quick brown fox";
    const CHUNK_B: &[u8] = b"jumps over the lazy dog";

    // ── addressing (ISC-2) ────────────────────────────────────────────────

    /// ISC-2 — the address is exactly `SHA-384(chunk)` over the chunk bytes.
    #[test]
    fn chunk_addr_is_sha384_of_bytes() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let addr = chunk_addr(CHUNK_A).unwrap();
        let expected = sha384(CHUNK_A).unwrap();
        assert_eq!(addr.as_bytes(), &expected);
        assert_eq!(CHUNK_ADDR_LEN, 48);
    }

    /// Distinct chunks get distinct addresses; identical bytes collide (the
    /// dedup invariant).
    #[test]
    fn addressing_is_content_deterministic() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        assert_eq!(chunk_addr(CHUNK_A).unwrap(), chunk_addr(CHUNK_A).unwrap());
        assert_ne!(chunk_addr(CHUNK_A).unwrap(), chunk_addr(CHUNK_B).unwrap());
    }

    // ── ct_eq (ISC-3 helper correctness) ──────────────────────────────────

    /// The constant-time compare detects a single-bit difference and accepts
    /// equal inputs (correctness; the timing property is structural).
    #[test]
    fn ct_eq_detects_single_bit_difference() {
        let mut a = [0xa5u8; CHUNK_ADDR_LEN];
        let b = a;
        assert!(ct_eq(&a, &b));
        a[CHUNK_ADDR_LEN - 1] ^= 0x01;
        assert!(!ct_eq(&a, &b));
    }

    /// Length mismatch is rejected (the only intentionally variable-time path).
    #[test]
    fn ct_eq_rejects_length_mismatch() {
        assert!(!ct_eq(&[0u8; 48], &[0u8; 47]));
    }

    // ── MemoryChunkStore (ISC-1 / ISC-3 / ISC-4 / ISC-5 mechanism) ─────────

    /// ISC-1 — put/get round-trips a chunk through the in-memory store.
    #[test]
    fn memory_put_get_roundtrip() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let mut store = MemoryChunkStore::new();
        let addr = store.put(CHUNK_A).unwrap();
        assert_eq!(store.get(&addr).unwrap().as_deref(), Some(CHUNK_A));
    }

    /// ISC-3 — `has` answers presence correctly for both a stored and an
    /// absent address.
    #[test]
    fn memory_has_present_and_absent() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let mut store = MemoryChunkStore::new();
        let present = store.put(CHUNK_A).unwrap();
        let absent = chunk_addr(CHUNK_B).unwrap();
        assert!(store.has(&present).unwrap());
        assert!(!store.has(&absent).unwrap());
    }

    /// ISC-3 — `has` on an empty store never short-circuits to a wrong answer.
    #[test]
    fn memory_has_on_empty_store_is_false() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let store = MemoryChunkStore::new();
        assert!(!store.has(&chunk_addr(CHUNK_A).unwrap()).unwrap());
    }

    /// ISC-4 / ISC-5 — refcount decrements to StillReferenced, then Dropped at
    /// zero; the chunk is gone afterward (the server-blind teardown mechanism).
    #[test]
    fn memory_unref_decrements_then_drops() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let mut store = MemoryChunkStore::new();
        let addr = store.put(CHUNK_A).unwrap();
        let addr2 = store.put(CHUNK_A).unwrap(); // dedups, refs == 2
        assert_eq!(addr, addr2);
        assert_eq!(
            store.unref(&addr).unwrap(),
            Unref::StillReferenced { remaining: 1 }
        );
        assert!(store.has(&addr).unwrap());
        assert_eq!(store.unref(&addr).unwrap(), Unref::Dropped);
        assert!(!store.has(&addr).unwrap());
        assert_eq!(store.get(&addr).unwrap(), None);
    }

    /// Dedup stores one copy: the second put of identical bytes only bumps the
    /// count, it does not double-store.
    #[test]
    fn memory_dedup_single_copy() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let mut store = MemoryChunkStore::new();
        store.put(CHUNK_A).unwrap();
        store.put(CHUNK_A).unwrap();
        assert_eq!(store.chunks.len(), 1);
        assert_eq!(store.chunks.values().next().unwrap().refs, 2);
    }

    /// Unref-ing an absent chunk is a no-op reporting Dropped.
    #[test]
    fn memory_unref_absent_is_dropped() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let mut store = MemoryChunkStore::new();
        assert_eq!(
            store.unref(&chunk_addr(CHUNK_A).unwrap()).unwrap(),
            Unref::Dropped
        );
    }

    // ── FileChunkStore (ISC-6 / ISC-4 on disk) ─────────────────────────────

    /// ISC-6 — chunks persist across "process launches": a chunk written by
    /// one store handle is readable by a fresh handle reopened over the same
    /// root (simulating a restart).
    #[test]
    fn file_persists_across_reopen() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let addr = {
            let mut store = FileChunkStore::open(dir.path()).unwrap();
            store.put(CHUNK_A).unwrap()
        };
        // Fresh handle over the same root == a new process opening the cache.
        let store = FileChunkStore::open(dir.path()).unwrap();
        assert!(store.has(&addr).unwrap());
        assert_eq!(store.get(&addr).unwrap().as_deref(), Some(CHUNK_A));
    }

    /// ISC-4 — on disk, unref drops the chunk (and its sidecar) at zero refs.
    #[test]
    fn file_unref_drops_at_zero() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = FileChunkStore::open(dir.path()).unwrap();
        let addr = store.put(CHUNK_A).unwrap();
        assert_eq!(store.unref(&addr).unwrap(), Unref::Dropped);
        assert!(!store.has(&addr).unwrap());
        assert_eq!(store.get(&addr).unwrap(), None);
    }

    /// ISC-4 / ISC-6 — the refcount itself persists: two puts then a reopen
    /// still need two unrefs to drop.
    #[test]
    fn file_refcount_persists_across_reopen() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let addr = {
            let mut store = FileChunkStore::open(dir.path()).unwrap();
            store.put(CHUNK_A).unwrap();
            store.put(CHUNK_A).unwrap()
        };
        let mut store = FileChunkStore::open(dir.path()).unwrap();
        assert_eq!(
            store.unref(&addr).unwrap(),
            Unref::StillReferenced { remaining: 1 }
        );
        assert_eq!(store.unref(&addr).unwrap(), Unref::Dropped);
        assert!(!store.has(&addr).unwrap());
    }

    /// A round-trip address survives `as_bytes` → `from_bytes` (the form a
    /// fetch request names a chunk by).
    #[test]
    fn chunk_addr_bytes_roundtrip() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let addr = chunk_addr(CHUNK_A).unwrap();
        assert_eq!(ChunkAddr::from_bytes(*addr.as_bytes()), addr);
    }
}
