//! Profile-local store of confirmed-manifest digests (download-subsystem
//! redesign, step 8 — `docs/design/download-subsystem.md` §Part 3).
//!
//! A verified resume binds to the *stored confirmed* manifest (DL-ISC-20). The
//! manifest itself is persisted inside the fetch's staging area
//! ([`super::fetched::StagingArea::persist_manifest`]), but the downloads root is
//! co-resident-writable, so its integrity cannot anchor there. This store keeps
//! the manifest's SHA-384 digest in the **client's own trusted state** (a redb
//! file under the profile dir, like [`super::share_index`]): before any reuse the
//! staging copy is re-serialized, re-digested, and compared to the digest stored
//! here ([`super::fetched::verify_stored_manifest`]). Without the profile-anchored
//! digest, a co-resident tamper of the staging manifest plus a colluding sharer
//! serving the matching manifest would bypass the confirm gate.
//!
//! The value is a bare 48-byte digest — no encryption (unlike the share index): a
//! digest is not secret, and the store's job is integrity anchoring, not
//! confidentiality. Keyed by `share_id` — also plaintext, which leaks no more than
//! the fetcher already exposes at rest by design (the `downloads.idx` manifest and
//! the `.dspart/<hex(share_id)>/` staging tree both carry the `share_id` +
//! `rel_path`s in the clear). The share index encrypts because it protects the
//! *sharer's* passive index of a private folder — a different concern.

use std::path::{Path, PathBuf};

use redb::{Database, TableDefinition};

use super::fetched::MANIFEST_DIGEST_LEN;

/// The digest table. Bump the version suffix (abandoning any prior table) on an
/// incompatible value-format change, mirroring [`super::share_index`]'s discipline.
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("download-manifest-digests-v1");

/// Why a [`ManifestDigestStore`] operation failed.
#[derive(Debug)]
pub enum DigestStoreError {
    /// A redb storage / transaction / table error. Boxed because `redb::Error` is
    /// large and would bloat every `Result` otherwise.
    Db(Box<redb::Error>),
    /// A stored value was not exactly [`MANIFEST_DIGEST_LEN`] bytes — a corrupt
    /// store or a value written by an incompatible version. Fails closed rather
    /// than returning a truncated/garbage digest.
    Corrupt,
    /// Failed to acquire (or open) the advisory lock that serializes store access
    /// across concurrent openers (F8). The store is not opened rather than risk a
    /// racing `DatabaseAlreadyOpen`, or a split-brain lock through a tampered symlink.
    Lock(String),
}

impl core::fmt::Display for DigestStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DigestStoreError::Db(e) => write!(f, "manifest-digest store error: {e}"),
            DigestStoreError::Corrupt => {
                f.write_str("manifest-digest store value is not a 48-byte digest")
            }
            DigestStoreError::Lock(m) => write!(f, "manifest-digest store lock error: {m}"),
        }
    }
}

impl core::error::Error for DigestStoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            DigestStoreError::Db(e) => Some(e.as_ref()),
            DigestStoreError::Corrupt | DigestStoreError::Lock(_) => None,
        }
    }
}

fn db_err(e: impl Into<redb::Error>) -> DigestStoreError {
    DigestStoreError::Db(Box::new(e.into()))
}

/// Blocks until an exclusive advisory lock on `<db_path>.lock` is held, serializing
/// opens of the redb digest store (F8). `Database::create` takes an exclusive OS lock
/// and FAILS FAST (`DatabaseAlreadyOpen`) on a second opener, so without this two
/// concurrent downloads in one process — or a co-resident GUI and TUI sharing one
/// profile — would spuriously fail a healthy download. The blocking flock turns that
/// fail-fast into a serialized wait. Mirrors `super::fetched`'s `IdxLock`.
struct StoreLock {
    _file: std::fs::File,
}

impl StoreLock {
    fn acquire(db_path: &Path) -> Result<Self, DigestStoreError> {
        use fs4::fs_std::FileExt;
        let mut lock_path = db_path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        // Refuse a symlink at the lock path: a co-resident attacker could point it at a
        // different inode so two openers lock different files, defeating serialization.
        // (An atomic `O_NOFOLLOW` open would close the residual check-then-open window;
        // that hardening is tracked, as for `IdxLock`.)
        if std::fs::symlink_metadata(&lock_path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(DigestStoreError::Lock(format!(
                "{} is a symlink; refusing to lock through it",
                lock_path.display()
            )));
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| DigestStoreError::Lock(format!("open {}: {e}", lock_path.display())))?;
        file.lock_exclusive()
            .map_err(|e| DigestStoreError::Lock(format!("lock {}: {e}", lock_path.display())))?;
        Ok(Self { _file: file })
    }
}

/// An open, redb-backed store mapping `share_id` → the 48-byte SHA-384 of the
/// fetch's confirmed manifest. Kept under the profile dir (the client's own
/// trusted state), so it anchors the manifest's integrity independently of the
/// co-resident-writable downloads root.
///
/// Access is serialized by a `<path>.lock` advisory flock held for the store's
/// lifetime (F8). Field order is load-bearing: `db` is declared before `_lock`, so on
/// drop the redb `Database` (releasing redb's own exclusive lock) drops BEFORE the
/// advisory flock releases — a waiter blocked on the flock therefore always finds the
/// redb lock already free when its own `Database::create` runs.
pub struct ManifestDigestStore {
    db: Database,
    _lock: StoreLock,
}

impl ManifestDigestStore {
    /// Open (creating if absent) the digest store at `path`. Reopening recovers
    /// every digest written before. Blocks while another opener holds the store's
    /// advisory lock (F8), then proceeds — concurrent opens serialize, never collide.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DigestStoreError> {
        let path = path.as_ref();
        // Acquire the advisory lock BEFORE Database::create so a concurrent opener
        // blocks here instead of hitting redb's fail-fast DatabaseAlreadyOpen.
        let lock = StoreLock::acquire(path)?;
        let db = Database::create(path).map_err(db_err)?;
        // Materialize the table so a fresh DB has it before any read txn.
        let wtxn = db.begin_write().map_err(db_err)?;
        {
            wtxn.open_table(TABLE).map_err(db_err)?;
        }
        wtxn.commit().map_err(db_err)?;
        Ok(Self { db, _lock: lock })
    }

    /// Record (insert or replace) the confirmed-manifest digest for `share_id`.
    pub fn record_digest(
        &self,
        share_id: &str,
        digest: &[u8; MANIFEST_DIGEST_LEN],
    ) -> Result<(), DigestStoreError> {
        let wtxn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = wtxn.open_table(TABLE).map_err(db_err)?;
            table
                .insert(share_id.as_bytes(), digest.as_slice())
                .map_err(db_err)?;
        }
        wtxn.commit().map_err(db_err)?;
        Ok(())
    }

    /// Fetch the stored digest for `share_id`. `Ok(None)` if none was recorded;
    /// [`DigestStoreError::Corrupt`] if a stored value is not 48 bytes.
    ///
    /// A resume MUST treat `Ok(None)` as HALT — never synthesize a digest or proceed
    /// to verify without one. With no recorded digest there is no anchor, so a
    /// co-resident tamper of the staging manifest (plus a colluding sharer serving the
    /// matching manifest) would bypass the confirm gate. Fail closed on a store miss.
    pub fn get_digest(
        &self,
        share_id: &str,
    ) -> Result<Option<[u8; MANIFEST_DIGEST_LEN]>, DigestStoreError> {
        let rtxn = self.db.begin_read().map_err(db_err)?;
        let table = rtxn.open_table(TABLE).map_err(db_err)?;
        match table.get(share_id.as_bytes()).map_err(db_err)? {
            Some(guard) => {
                let value = guard.value();
                if value.len() != MANIFEST_DIGEST_LEN {
                    return Err(DigestStoreError::Corrupt);
                }
                let mut out = [0u8; MANIFEST_DIGEST_LEN];
                out.copy_from_slice(value);
                Ok(Some(out))
            }
            None => Ok(None),
        }
    }

    /// Remove the stored digest for `share_id`. Removing an absent entry is a
    /// no-op.
    pub fn remove(&self, share_id: &str) -> Result<(), DigestStoreError> {
        let wtxn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = wtxn.open_table(TABLE).map_err(db_err)?;
            table.remove(share_id.as_bytes()).map_err(db_err)?;
        }
        wtxn.commit().map_err(db_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ManifestDigestStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = ManifestDigestStore::open(dir.path().join("digests.redb")).unwrap();
        (dir, store)
    }

    #[test]
    fn record_then_get_round_trips_the_digest() {
        let (_dir, store) = store();
        let d = [7u8; MANIFEST_DIGEST_LEN];
        store.record_digest("share-a", &d).unwrap();
        assert_eq!(store.get_digest("share-a").unwrap(), Some(d));
    }

    #[test]
    fn get_absent_is_none() {
        let (_dir, store) = store();
        assert_eq!(store.get_digest("nope").unwrap(), None);
    }

    #[test]
    fn record_replaces_an_existing_digest() {
        let (_dir, store) = store();
        store
            .record_digest("s", &[1u8; MANIFEST_DIGEST_LEN])
            .unwrap();
        store
            .record_digest("s", &[2u8; MANIFEST_DIGEST_LEN])
            .unwrap();
        assert_eq!(
            store.get_digest("s").unwrap(),
            Some([2u8; MANIFEST_DIGEST_LEN])
        );
    }

    #[test]
    fn remove_deletes_the_entry() {
        let (_dir, store) = store();
        store
            .record_digest("s", &[9u8; MANIFEST_DIGEST_LEN])
            .unwrap();
        store.remove("s").unwrap();
        assert_eq!(store.get_digest("s").unwrap(), None);
        // Removing an absent entry is a no-op.
        store.remove("s").unwrap();
    }

    #[test]
    fn digests_reopen_across_store_instances() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("digests.redb");
        let d = [3u8; MANIFEST_DIGEST_LEN];
        {
            let store = ManifestDigestStore::open(&path).unwrap();
            store.record_digest("persist", &d).unwrap();
        }
        let store = ManifestDigestStore::open(&path).unwrap();
        assert_eq!(store.get_digest("persist").unwrap(), Some(d));
    }

    #[test]
    fn concurrent_opens_serialize_rather_than_collide() {
        // Four threads open the SAME store path concurrently. With the advisory flock
        // they serialize (each blocks until the prior drops) and ALL succeed; pre-fix,
        // a second `Database::create` on the still-open file returned
        // `DatabaseAlreadyOpen` and the thread would have panicked here (F8).
        let dir = tempfile::TempDir::new().unwrap();
        let path = std::sync::Arc::new(dir.path().join("digests.redb"));
        let mut handles = Vec::new();
        for i in 0..4u8 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                let store = ManifestDigestStore::open(path.as_ref()).unwrap();
                store
                    .record_digest(&format!("s{i}"), &[i; MANIFEST_DIGEST_LEN])
                    .unwrap();
                // store (db + flock) drops here, freeing the next waiter.
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Every thread got exclusive access in turn, so all four writes landed.
        let store = ManifestDigestStore::open(path.as_ref()).unwrap();
        for i in 0..4u8 {
            assert_eq!(
                store.get_digest(&format!("s{i}")).unwrap(),
                Some([i; MANIFEST_DIGEST_LEN])
            );
        }
    }
}
