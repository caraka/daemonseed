//! Encrypted, incremental share index — the redb-backed indexed-state layer
//! (M8, ISC-C21 / ISC-A-C6 / ISC-A-C7).
//!
//! A daemon that shares a folder keeps a persistent index of what's in it
//! (one [`ShareEntry`] per file: relative path, size, mtime). The index lives
//! in [redb] — an embedded, pure-Rust b-tree store — so updates are
//! **incremental**: adding, changing, or removing one file rewrites one entry,
//! never the whole index (ISC-A-C7, the Pi-4 civility floor). It is read back
//! on the next launch rather than rebuilt from a cold rescan (ISC-C21).
//!
//! ## Encryption at rest (ISC-A-C6)
//!
//! redb stores opaque bytes; daemonseed encrypts before storing:
//!
//! - **Key** (the redb key, not the crypto key): `SHA-384(index_key ‖ rel_path)`
//!   truncated to 32 bytes. Keyed by the secret `index_key`, so it is neither
//!   reversible *nor confirmable* without that key — an attacker with the raw
//!   redb file cannot test "is `/home/me/taxes.pdf` indexed?". It is
//!   deterministic, so update/remove of a known path hits the same slot.
//! - **Value**: `AES-256-GCM(index_key, random nonce, padded-metadata)`. The
//!   `index_key` is derived `Argon2id(passphrase, salt=profile_id) →
//!   HKDF-SHA384(info = "daemonseed/share-index/<profile-id>")` — the seeds-blob
//!   chain with a distinct info string (see [`crate::kdf::info::share_index`]).
//!
//! ## Why values are padded (forward-composition with at-rest folder encryption)
//!
//! AES-GCM ciphertext length tracks plaintext length, so an unpadded value
//! would leak its `rel_path`'s length to anyone with raw disk access — and the
//! entry count would leak the file count. That silently undermines a future
//! "encrypt the share folder at rest" feature, whose whole point is hiding
//! names and counts. So every value is padded to a fixed 256-byte bucket before
//! encryption ([`BUCKET_STEP`]): two paths in the same bucket produce
//! byte-identical ciphertext lengths. The residual at-rest leak collapses to
//! the *bucket* an entry falls in, the entry count, and write timing — file
//! sizes never leak (a fixed-width field), and contents are ciphertext. Hiding
//! the count too would need decoy entries (out of MVP scope).
//!
//! The index records the **logical** view — the paths a user actually shares.
//! A future at-rest folder-encryption feature must therefore present decrypted
//! names to the indexer (decrypt-on-access); pointing it at raw on-disk
//! ciphertext would index obfuscated names, which is wrong, not a crash.
//!
//! ## Value format v3 (table-name bump, M16 sub-file chunking)
//!
//! M16 first extended [`ShareEntry`] with one cached whole-file address (the
//! `share-index-v2` table), then — same milestone — switched share transfer
//! to fixed 1 MiB sub-file chunks (ISC-C73 / ISC-A-C35), making a file's
//! cache value the **ordered concatenation of all its per-chunk 48-byte
//! SHA-384 addresses** ([`ShareEntry::chunk_addrs`]). Each format change is
//! handled by **bumping the redb table name** — now `share-index-v3`: older
//! tables (`share-index`, and `share-index-v2`, whose rows are single-addr
//! shaped) are simply abandoned in place — never read, never migrated — and
//! the v3 table starts empty. Alpha backward-compatibility is waived by
//! design; a re-scan repopulates the index (it is a cache over the
//! filesystem, not a record).

use std::path::Path;

use oxicrypt_aes::{Aes256Key, gcm_decrypt, gcm_encrypt};
use oxicrypt_sha::sha384;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use zeroize::{Zeroize, Zeroizing};

/// AES-256-GCM key length.
pub const INDEX_KEY_LEN: usize = 32;
/// AES-256-GCM nonce length (NIST SP 800-38D §8.2.1).
const NONCE_LEN: usize = 12;
/// AES-256-GCM tag length.
const TAG_LEN: usize = 16;
/// Length of the opaque redb key (truncated SHA-384).
const OPAQUE_KEY_LEN: usize = 32;
/// Padding granularity for index values (ISC-A-C6 forward-composition). Plain
/// metadata is zero-padded up to the next multiple of this before encryption,
/// so ciphertext length reveals only which bucket an entry falls in.
pub const BUCKET_STEP: usize = 256;

/// The v3 table (see the module docs): the value format changed again within
/// M16 (single whole-file addr → ordered multi-chunk addr blob), so the table
/// name was bumped and any v1/v2 table is abandoned.
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("share-index-v3");

/// One indexed file in a shared folder: the relative path plus the cheap
/// `stat` metadata the indexer tracks. Contents are never read into the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEntry {
    /// Path relative to the share root (the logical name a user shares).
    pub rel_path: String,
    /// File size in bytes.
    pub size: u64,
    /// Last-modified time, milliseconds since the Unix epoch.
    pub mtime_unix_ms: u64,
    /// Cached content addresses — the **ordered concatenation** of the
    /// file's per-chunk 48-byte SHA-384 addresses
    /// ([`crate::storage::cas::chunk_addr`] over each fixed
    /// [`crate::share_serve::CHUNK_SIZE`] chunk, M16 — ISC-C73/ISC-A-C35)
    /// from the last hash pass, or `None` after a metadata-only scan. The
    /// blob's length is therefore a multiple of 48, with
    /// `len/48 == ceil(size/CHUNK_SIZE)` (and `Some(empty)` for a hashed
    /// empty file — distinct from `None`, never-hashed). Valid only while
    /// `size` and `mtime_unix_ms` still match the file (the reuse test
    /// `indexer::cached_or_hash` applies); a metadata change invalidates it.
    pub chunk_addrs: Option<Vec<u8>>,
}

/// Failure modes for [`ShareIndex`] operations.
#[derive(Debug)]
pub enum IndexError {
    /// A redb storage / transaction / table error. Boxed because `redb::Error`
    /// is large and would bloat every `Result` in this module otherwise.
    Db(Box<redb::Error>),
    /// AES-256-GCM init, seal, or open failed. On read this includes
    /// authentication failure — a wrong `index_key` or a tampered value fails
    /// closed here rather than returning garbage.
    Crypto,
    /// A stored value did not decode to a well-formed entry (corrupt store or
    /// a value written by an incompatible version).
    Corrupt,
    /// Entropy source failed while generating a nonce.
    Entropy,
}

impl core::fmt::Display for IndexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IndexError::Db(e) => write!(f, "share-index storage error: {e}"),
            IndexError::Crypto => f.write_str("share-index AES-256-GCM operation failed"),
            IndexError::Corrupt => f.write_str("share-index stored value is malformed"),
            IndexError::Entropy => f.write_str("share-index nonce entropy source failed"),
        }
    }
}

impl core::error::Error for IndexError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            IndexError::Db(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// An open, encrypted, incremental share index backed by a redb file.
pub struct ShareIndex {
    db: Database,
    index_key: Zeroizing<[u8; INDEX_KEY_LEN]>,
}

/// The stable, per-share index FILENAME for a share rooted at `root`:
/// `share-index-<12hex>.redb`, where `<12hex>` is the first 6 bytes of SHA-384
/// over the share's canonical absolute path. One redb file per share, so a
/// publish's cache pass over one share can never evict another share's cached
/// chunk addresses (a single shared index cross-prunes on every publish, forcing
/// a multi-share user to re-hash every share on every launch — #81). The path is
/// canonicalized for stability, so `/a/b`, `/a/b/`, and a symlinked equivalent
/// all map to one file; if canonicalization fails (e.g. the root was removed)
/// the raw path bytes are hashed, still stable for an identical path string.
pub fn per_share_index_filename(root: &Path) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let path_bytes = canonical.as_os_str().as_encoded_bytes();
    // SHA-384 is the keyed-free path digest. The only failure is an uninitialized
    // oxicrypt module — which never happens on a real publish path — but a constant
    // fallback would collide every share into one file (the very bug this prevents),
    // so degrade to a deterministic std hash of the same bytes instead: still stable
    // and distinct per path.
    let stem: Vec<u8> = match sha384(path_bytes) {
        Ok(digest) => digest[..6].to_vec(),
        Err(_) => {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            path_bytes.hash(&mut h);
            h.finish().to_le_bytes()[..6].to_vec()
        }
    };
    let mut name = String::with_capacity("share-index-".len() + 12 + ".redb".len());
    name.push_str("share-index-");
    for b in &stem {
        name.push(HEX[(b >> 4) as usize] as char);
        name.push(HEX[(b & 0x0f) as usize] as char);
    }
    name.push_str(".redb");
    name
}

impl ShareIndex {
    /// Open (creating if absent) the index at `path`, encrypting under
    /// `index_key`. Reopening an existing file recovers every entry written
    /// before — the basis of cross-launch persistence (ISC-C21 / ISC-18).
    pub fn open(
        path: impl AsRef<Path>,
        index_key: [u8; INDEX_KEY_LEN],
    ) -> Result<Self, IndexError> {
        let db = Database::create(path).map_err(|e| IndexError::Db(Box::new(e.into())))?;
        // Materialize the table so a fresh DB has it before any read txn.
        let wtxn = db
            .begin_write()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        {
            wtxn.open_table(TABLE)
                .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        }
        wtxn.commit()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        Ok(Self {
            db,
            index_key: Zeroizing::new(index_key),
        })
    }

    /// Insert or replace one file's entry — a single-entry write (ISC-A-C7: no
    /// share-wide rewrite).
    pub fn put(&self, entry: &ShareEntry) -> Result<(), IndexError> {
        let opaque = self.opaque_key(&entry.rel_path)?;
        let value = self.seal(entry)?;
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        {
            let mut table = wtxn
                .open_table(TABLE)
                .map_err(|e| IndexError::Db(Box::new(e.into())))?;
            table
                .insert(opaque.as_slice(), value.as_slice())
                .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        }
        wtxn.commit()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        Ok(())
    }

    /// Fetch one file's entry by its relative path. `Ok(None)` if absent.
    pub fn get(&self, rel_path: &str) -> Result<Option<ShareEntry>, IndexError> {
        let opaque = self.opaque_key(rel_path)?;
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        let table = rtxn
            .open_table(TABLE)
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        match table
            .get(opaque.as_slice())
            .map_err(|e| IndexError::Db(Box::new(e.into())))?
        {
            Some(guard) => Ok(Some(self.open_value(guard.value())?)),
            None => Ok(None),
        }
    }

    /// Remove one file's entry (a single-entry write). Removing an absent entry
    /// is a no-op.
    pub fn remove(&self, rel_path: &str) -> Result<(), IndexError> {
        let opaque = self.opaque_key(rel_path)?;
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        {
            let mut table = wtxn
                .open_table(TABLE)
                .map_err(|e| IndexError::Db(Box::new(e.into())))?;
            table
                .remove(opaque.as_slice())
                .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        }
        wtxn.commit()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        Ok(())
    }

    /// Delete every entry in one write transaction (the table is dropped and
    /// re-created atomically). The clear-then-rescan move: latest-wins
    /// semantics for a share whose root changed wholesale, without tracking
    /// per-entry staleness.
    pub fn clear(&self) -> Result<(), IndexError> {
        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        {
            wtxn.delete_table(TABLE)
                .map_err(|e| IndexError::Db(Box::new(e.into())))?;
            // Re-materialize so a subsequent read txn finds the (empty) table.
            wtxn.open_table(TABLE)
                .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        }
        wtxn.commit()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        Ok(())
    }

    /// Number of indexed files.
    pub fn len(&self) -> Result<usize, IndexError> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        let table = rtxn
            .open_table(TABLE)
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        Ok(table
            .len()
            .map_err(|e| IndexError::Db(Box::new(e.into())))? as usize)
    }

    /// Whether the index holds no entries.
    pub fn is_empty(&self) -> Result<bool, IndexError> {
        Ok(self.len()? == 0)
    }

    /// Decrypt and return every entry (unordered). The relative paths come from
    /// the decrypted values, never from the opaque keys.
    pub fn entries(&self) -> Result<Vec<ShareEntry>, IndexError> {
        let rtxn = self
            .db
            .begin_read()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        let table = rtxn
            .open_table(TABLE)
            .map_err(|e| IndexError::Db(Box::new(e.into())))?;
        let mut out = Vec::new();
        for row in table
            .iter()
            .map_err(|e| IndexError::Db(Box::new(e.into())))?
        {
            let (_key, value) = row.map_err(|e| IndexError::Db(Box::new(e.into())))?;
            out.push(self.open_value(value.value())?);
        }
        Ok(out)
    }

    /// `SHA-384(index_key ‖ rel_path)[..32]` — the keyed, non-reversible,
    /// deterministic redb key for a path. The transient `index_key ‖ path`
    /// buffer is zeroed after hashing (it carries the index key).
    fn opaque_key(&self, rel_path: &str) -> Result<[u8; OPAQUE_KEY_LEN], IndexError> {
        let mut input = Vec::with_capacity(INDEX_KEY_LEN + rel_path.len());
        input.extend_from_slice(self.index_key.as_slice());
        input.extend_from_slice(rel_path.as_bytes());
        let digest = sha384(&input);
        input.zeroize();
        let digest = digest.map_err(|_| IndexError::Crypto)?;
        let mut out = [0u8; OPAQUE_KEY_LEN];
        out.copy_from_slice(&digest[..OPAQUE_KEY_LEN]);
        Ok(out)
    }

    /// Seal an entry: pad to a bucket, then AES-256-GCM. Output is
    /// `nonce ‖ ciphertext ‖ tag`.
    fn seal(&self, entry: &ShareEntry) -> Result<Vec<u8>, IndexError> {
        let plaintext = frame_and_pad(entry);

        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| IndexError::Entropy)?;

        let aes = Aes256Key::new(&self.index_key).map_err(|_| IndexError::Crypto)?;
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; TAG_LEN];
        gcm_encrypt(&aes, &nonce, b"", &plaintext, &mut ciphertext, &mut tag)
            .map_err(|_| IndexError::Crypto)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Open a stored value: AES-256-GCM decrypt (fails closed on wrong key /
    /// tamper), then unpad + decode.
    fn open_value(&self, stored: &[u8]) -> Result<ShareEntry, IndexError> {
        if stored.len() < NONCE_LEN + TAG_LEN {
            return Err(IndexError::Corrupt);
        }
        let nonce: &[u8; NONCE_LEN] = stored[..NONCE_LEN].try_into().unwrap();
        let rest = &stored[NONCE_LEN..];
        let ct_len = rest.len() - TAG_LEN;
        let ciphertext = &rest[..ct_len];
        let tag: &[u8; TAG_LEN] = rest[ct_len..].try_into().unwrap();

        let aes = Aes256Key::new(&self.index_key).map_err(|_| IndexError::Crypto)?;
        let mut plaintext = vec![0u8; ct_len];
        gcm_decrypt(&aes, nonce, b"", ciphertext, tag, &mut plaintext)
            .map_err(|_| IndexError::Crypto)?;

        unframe(&plaintext).ok_or(IndexError::Corrupt)
    }
}

/// Encode an entry's metadata (v3): `[path_len u16][path][size u64]
/// [mtime u64][has_addrs u8][addrs_len u32][addrs]`, little-endian.
/// `has_addrs` is `0` for a metadata-only entry (no length/blob follows) or
/// `1` for a hashed one — an explicit presence byte rather than a zero
/// length, because a hashed **empty** file legitimately caches an empty addr
/// blob (`Some(vec![])`, zero chunks) and must stay distinguishable from
/// never-hashed (`None`). `addrs_len` is `u32` (not the v2 `u8`): a
/// multi-chunk blob is `48 × ceil(size/CHUNK_SIZE)` bytes, which outgrows a
/// byte at files > ~5 MiB.
fn encode_entry(entry: &ShareEntry) -> Vec<u8> {
    let path = entry.rel_path.as_bytes();
    let addrs = entry.chunk_addrs.as_deref();
    let mut buf = Vec::with_capacity(2 + path.len() + 16 + 1 + addrs.map_or(0, |a| 4 + a.len()));
    buf.extend_from_slice(&(path.len() as u16).to_le_bytes());
    buf.extend_from_slice(path);
    buf.extend_from_slice(&entry.size.to_le_bytes());
    buf.extend_from_slice(&entry.mtime_unix_ms.to_le_bytes());
    match addrs {
        Some(addrs) => {
            buf.push(1);
            buf.extend_from_slice(&(addrs.len() as u32).to_le_bytes());
            buf.extend_from_slice(addrs);
        }
        None => buf.push(0),
    }
    buf
}

/// Frame an entry as `[content_len u32][content][zero pad]`, padded up to the
/// next multiple of [`BUCKET_STEP`] so the ciphertext length leaks only the
/// bucket, not the exact path length.
fn frame_and_pad(entry: &ShareEntry) -> Vec<u8> {
    let content = encode_entry(entry);
    let framed_len = 4 + content.len();
    let padded_len = framed_len.div_ceil(BUCKET_STEP) * BUCKET_STEP;
    let mut buf = Vec::with_capacity(padded_len);
    buf.extend_from_slice(&(content.len() as u32).to_le_bytes());
    buf.extend_from_slice(&content);
    buf.resize(padded_len, 0);
    buf
}

/// Inverse of [`frame_and_pad`]: read the length prefix, decode that many
/// content bytes, ignore the padding. Returns `None` on any malformed framing.
fn unframe(padded: &[u8]) -> Option<ShareEntry> {
    if padded.len() < 4 {
        return None;
    }
    let content_len = u32::from_le_bytes(padded[..4].try_into().ok()?) as usize;
    let content = padded.get(4..4 + content_len)?;

    let path_len = u16::from_le_bytes(content.get(..2)?.try_into().ok()?) as usize;
    let path_bytes = content.get(2..2 + path_len)?;
    let rel_path = String::from_utf8(path_bytes.to_vec()).ok()?;
    let after_path = content.get(2 + path_len..)?;
    let size = u64::from_le_bytes(after_path.get(..8)?.try_into().ok()?);
    let mtime_unix_ms = u64::from_le_bytes(after_path.get(8..16)?.try_into().ok()?);
    let chunk_addrs = match *after_path.get(16)? {
        0 => {
            if after_path.len() != 17 {
                return None;
            }
            None
        }
        1 => {
            let addrs_len = u32::from_le_bytes(after_path.get(17..21)?.try_into().ok()?) as usize;
            let addr_bytes = after_path.get(21..)?;
            if addr_bytes.len() != addrs_len {
                return None;
            }
            Some(addr_bytes.to_vec())
        }
        _ => return None,
    };
    Some(ShareEntry {
        rel_path,
        size,
        mtime_unix_ms,
        chunk_addrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; INDEX_KEY_LEN] = [0x42; INDEX_KEY_LEN];

    fn entry(path: &str) -> ShareEntry {
        ShareEntry {
            rel_path: path.to_owned(),
            size: 4096,
            mtime_unix_ms: 1_700_000_000_000,
            chunk_addrs: None,
        }
    }

    /// An entry carrying a cached multi-chunk addr blob (M16 v3 format):
    /// two concatenated 48-byte addresses, ordered.
    fn entry_with_addr(path: &str) -> ShareEntry {
        let mut blob = vec![0xab; 48];
        blob.extend_from_slice(&[0xcd; 48]);
        ShareEntry {
            chunk_addrs: Some(blob),
            ..entry(path)
        }
    }

    // ── framing / padding (ISC-A-C6) ──────────────────────────────────────

    /// frame → unframe round-trips an entry exactly — without a cached blob,
    /// with a multi-addr blob, and with a hashed-empty blob (`Some(vec![])`,
    /// which must stay distinct from `None` — the three v3 value shapes).
    #[test]
    fn frame_unframe_roundtrips() {
        let e = entry("docs/report.pdf");
        assert_eq!(unframe(&frame_and_pad(&e)), Some(e));
        let e = entry_with_addr("docs/report.pdf");
        assert_eq!(unframe(&frame_and_pad(&e)), Some(e));
        // Hashed empty file: zero chunks, but HASHED — not the same as None.
        let e = ShareEntry {
            chunk_addrs: Some(Vec::new()),
            size: 0,
            ..entry("empty.bin")
        };
        let back = unframe(&frame_and_pad(&e));
        assert_eq!(back, Some(e));
        assert_eq!(
            back.unwrap().chunk_addrs,
            Some(Vec::new()),
            "Some(empty) survives the round-trip (presence byte, not zero-length sentinel)"
        );
    }

    /// Two short paths of *different* length pad to the *same* ciphertext-input
    /// length, so the stored value length can't leak the path length (ISC-A-C6).
    #[test]
    fn padding_hides_path_length_within_a_bucket() {
        let short = frame_and_pad(&entry("a"));
        let longer = frame_and_pad(&entry("a/much/longer/relative/path/file.txt"));
        assert_eq!(short.len(), BUCKET_STEP);
        assert_eq!(short.len(), longer.len(), "both fall in the first bucket");
        assert_eq!(short.len() % BUCKET_STEP, 0);
    }

    /// A path that overflows one bucket lands in the next, still a clean
    /// multiple of the step.
    #[test]
    fn padding_grows_by_whole_buckets() {
        let big = frame_and_pad(&entry(&"x".repeat(300)));
        assert_eq!(big.len() % BUCKET_STEP, 0);
        assert!(big.len() >= 2 * BUCKET_STEP);
    }

    // ── store behaviour (ISC-18 / ISC-A-C6 / ISC-A-C7) ─────────────────────

    fn open_temp(key: [u8; INDEX_KEY_LEN]) -> (tempfile::TempDir, ShareIndex) {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let idx = ShareIndex::open(dir.path().join("index.redb"), key).unwrap();
        (dir, idx)
    }

    /// put → get round-trips an entry through encryption + redb.
    #[test]
    fn put_get_roundtrip() {
        let (_dir, idx) = open_temp(KEY);
        let e = entry("photos/2026/trip.jpg");
        idx.put(&e).unwrap();
        assert_eq!(idx.get("photos/2026/trip.jpg").unwrap(), Some(e));
        assert_eq!(idx.get("not/there.txt").unwrap(), None);
    }

    /// M16 — a cached multi-chunk addr blob round-trips through encryption +
    /// redb (ordered, len % 48 == 0), and a re-put without one (a
    /// metadata-only rescan) drops it.
    #[test]
    fn chunk_addrs_roundtrip_and_are_replaceable() {
        let (_dir, idx) = open_temp(KEY);
        let e = entry_with_addr("a.txt");
        assert_eq!(e.chunk_addrs.as_ref().unwrap().len() % 48, 0);
        idx.put(&e).unwrap();
        assert_eq!(idx.get("a.txt").unwrap(), Some(e));

        idx.put(&entry("a.txt")).unwrap();
        assert_eq!(idx.get("a.txt").unwrap().unwrap().chunk_addrs, None);
    }

    /// M16 — `clear` empties the index in one transaction; it stays usable
    /// (the clear-then-rescan move) and clearing an empty index is a no-op.
    #[test]
    fn clear_empties_index() {
        let (_dir, idx) = open_temp(KEY);
        idx.put(&entry("a.txt")).unwrap();
        idx.put(&entry_with_addr("b.txt")).unwrap();
        idx.clear().unwrap();
        assert_eq!(idx.len().unwrap(), 0);
        assert_eq!(idx.get("a.txt").unwrap(), None);

        // Still writable afterward (the table was re-created), and a second
        // clear of the now-empty index succeeds.
        idx.put(&entry("c.txt")).unwrap();
        assert_eq!(idx.len().unwrap(), 1);
        idx.clear().unwrap();
        assert!(idx.is_empty().unwrap());
    }

    /// ISC-18 / ISC-C21 — entries persist across a reopen (a fresh process
    /// reading the same file), so the indexer reuses rather than cold-rescans.
    #[test]
    fn persists_across_reopen() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("index.redb");
        {
            let idx = ShareIndex::open(&path, KEY).unwrap();
            idx.put(&entry("a.txt")).unwrap();
            idx.put(&entry("b.txt")).unwrap();
        }
        let idx = ShareIndex::open(&path, KEY).unwrap();
        assert_eq!(idx.len().unwrap(), 2);
        assert_eq!(idx.get("a.txt").unwrap(), Some(entry("a.txt")));
    }

    /// ISC-A-C7 — a single remove is a single-entry write; the rest survive.
    #[test]
    fn remove_is_single_entry() {
        let (_dir, idx) = open_temp(KEY);
        idx.put(&entry("a.txt")).unwrap();
        idx.put(&entry("b.txt")).unwrap();
        idx.remove("a.txt").unwrap();
        assert_eq!(idx.get("a.txt").unwrap(), None);
        assert_eq!(idx.get("b.txt").unwrap(), Some(entry("b.txt")));
        assert_eq!(idx.len().unwrap(), 1);
        idx.remove("absent.txt").unwrap(); // no-op
    }

    /// `entries()` recovers paths from the decrypted *values*, not the opaque
    /// keys.
    #[test]
    fn entries_lists_all() {
        let (_dir, idx) = open_temp(KEY);
        idx.put(&entry("a.txt")).unwrap();
        idx.put(&entry("b.txt")).unwrap();
        let mut paths: Vec<String> = idx
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.rel_path)
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["a.txt".to_owned(), "b.txt".to_owned()]);
    }

    /// ISC-A-C6 — a wrong index key cannot read entries written under the right
    /// one. Because the redb key is itself keyed by the index key, a wrong key
    /// derives a different opaque key, so the lookup *misses* (Ok(None)) — a
    /// wrong-key holder can't even locate an entry, let alone read it, and never
    /// gets garbage back.
    #[test]
    fn wrong_key_cannot_read_entries() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("index.redb");
        {
            let idx = ShareIndex::open(&path, KEY).unwrap();
            idx.put(&entry("secret.txt")).unwrap();
        }
        let wrong = ShareIndex::open(&path, [0x99; INDEX_KEY_LEN]).unwrap();
        assert_eq!(
            wrong.get("secret.txt").unwrap(),
            None,
            "wrong key can't even locate the entry (keyed opaque key)"
        );
        // The entry count is still visible (the accepted structural leak), but
        // its contents are not readable.
        assert_eq!(wrong.len().unwrap(), 1);
    }

    /// ISC-A-C6 — tampering with a stored value fails closed at GCM auth, never
    /// returns garbage. (Exercises the decrypt path directly, since a keyed
    /// opaque key means a wrong key never reaches decrypt.)
    #[test]
    fn tampered_value_fails_closed() {
        let (_dir, idx) = open_temp(KEY);
        let e = entry("x.txt");
        let sealed = idx.seal(&e).unwrap();
        assert_eq!(idx.open_value(&sealed).unwrap(), e, "untampered opens fine");

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1; // flip a tag byte
        tampered[last] ^= 0x01;
        assert!(
            matches!(idx.open_value(&tampered), Err(IndexError::Crypto)),
            "a tampered value must fail closed at GCM auth"
        );
    }

    /// The opaque redb key is keyed by the index key: the same path under two
    /// different keys maps to two different slots (not confirmable without the
    /// key).
    #[test]
    fn opaque_key_is_keyed() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let dir = tempfile::TempDir::new().unwrap();
        let a = ShareIndex::open(dir.path().join("a.redb"), [0x01; INDEX_KEY_LEN]).unwrap();
        let b = ShareIndex::open(dir.path().join("b.redb"), [0x02; INDEX_KEY_LEN]).unwrap();
        assert_ne!(
            a.opaque_key("same/path").unwrap(),
            b.opaque_key("same/path").unwrap()
        );
    }
}
