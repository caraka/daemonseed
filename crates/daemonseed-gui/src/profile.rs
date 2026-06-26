//! Unlocked-profile persistence (round 6).
//!
//! The Slint-free holder for an *unlocked* identity: the at-rest [`Seeds`] payload,
//! its cached [`SealingKey`], the profile root on disk, and the stable display
//! handle the user presents under. It is the GUI's M13 "write-through" surface —
//! when the user joins a circle, the phrase is recorded in [`Seeds`], the blob is
//! re-sealed under the cached key, and the refreshed bytes are written back so the
//! circle silently re-joins next launch.
//!
//! Held behind an `Option` on [`crate::state::GuiState`]: `None` on the ephemeral /
//! pre-unlock path (the shell still works, just nothing survives relaunch), `Some`
//! once first-start or Unlock produces [`SessionMaterials`].
//!
//! **What persists, what does not.** Only the at-rest *settings* payload: the
//! display name and the set of circle PHRASES (never a derived key — the key is
//! re-derived from the phrase on rejoin). No message/transcript history is ever
//! written — the no-client-history property holds (config persistence ≠ history).
//!
//! Slint-free + I/O-isolated here so [`crate::state`] stays a pure RAM model and the
//! persistence is unit-testable against a temp profile root with no UI or relay.

use std::path::PathBuf;

use daemonseed_core::first_start::SessionMaterials;
use daemonseed_core::identity::keys::{
    Identity, KeyDerivationError, SignKeypair, derive_identity_keys,
};
use daemonseed_core::profile::persist::write_seeds_blob;
use daemonseed_core::storage::seeds::{IndexKey, SealingKey, Seeds};

/// An unlocked identity + its on-disk profile root, with the write-through path.
pub struct Profile {
    /// Profile root the `seeds.blob` lives under (re-sealed in place on mutate).
    root: PathBuf,
    /// The decrypted at-rest payload: mnemonic, display name, circle membership.
    seeds: Seeds,
    /// The cached AEAD key the blob was opened under — re-seals every mutation
    /// without re-deriving from the passphrase (M13).
    seal_key: SealingKey,
    /// The stable presented name (the user's chosen display name, or the formatted
    /// handle for a legacy profile with none). Decoupled from the ephemeral
    /// connection key — this is the *display* identity that survives relaunch.
    display_handle: String,
    /// (#81) the share-index key from [`SessionMaterials`] — the sibling of the
    /// at-rest [`SealingKey`] that opens the persisted redb share index under the
    /// profile root. Retained so the net actor can open the SAME index across
    /// launches and reuse its chunk-address cache (no from-scratch re-hash on
    /// publish / connect-time republish). A session secret on par with the at-rest
    /// key — never logged or persisted on its own (it is re-derived each unlock).
    index_key: IndexKey,
}

/// A persisted circle to silently re-join: its canonicalized phrase + client-local
/// label, as stored in the at-rest blob.
pub type PersistedCircle = (String, String);

impl Profile {
    /// Adopt the materials a first-start or Unlock produced. The display handle is
    /// the chosen display name; a legacy profile with none falls back to the
    /// formatted handle so the user still presents under a stable string.
    pub fn from_materials(materials: SessionMaterials, root: PathBuf) -> Self {
        let display_handle = materials
            .display_name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| materials.handle.to_string());
        Self {
            root,
            seeds: materials.seeds,
            seal_key: materials.seal_key,
            display_handle,
            index_key: materials.index_key,
        }
    }

    /// The stable presented name.
    pub fn display_handle(&self) -> &str {
        &self.display_handle
    }

    /// (#92) Derive the STABLE persistent identity signing keypair from the
    /// unlocked profile's mnemonic — `derive_identity_keys(.., Identity::Primary)`,
    /// the SAME key behind the `name#hash` handle an operator whitelists. This is
    /// the key the signer-gated composer gates on and signs MOTD/announcements
    /// with, NOT the per-launch ephemeral connection-proof key (which proves the
    /// connection but is unknown to any whitelist). Deriving runs crypto, so the
    /// caller derives ONCE on unlock/connect and hands the key to the net actor to
    /// hold — never per keystroke.
    pub fn stable_signing_key(&self) -> Result<SignKeypair, KeyDerivationError> {
        derive_identity_keys(&self.seeds.mnemonic, Identity::Primary).map(|k| k.signing)
    }

    /// (#81) The persisted-index home + key the net actor opens per-share indexes
    /// under: `(profile_root_dir, index_key)`. The net actor derives a per-share
    /// filename (`share-index-<12hex(root)>.redb`) under this DIR for each published
    /// share — one redb file per share — so a share's cache pass never evicts
    /// another's. The key is cloned (a `Zeroizing` newtype on par with the at-rest
    /// key — the caller zeroizes its copy after opening the index).
    pub fn index_params(&self) -> (PathBuf, IndexKey) {
        (self.root.clone(), self.index_key.clone())
    }

    /// Circles recorded in the blob (canonical phrase + label) — the rejoin set.
    pub fn circles(&self) -> Vec<PersistedCircle> {
        self.seeds
            .circles()
            .iter()
            .map(|c| (c.entropy.clone(), c.label.clone()))
            .collect()
    }

    /// Record a newly-joined circle and re-seal the blob to disk (M13 write-through).
    /// Returns `Ok(true)` if it was newly added (so the caller can skip a redundant
    /// re-seal on an idempotent rejoin), `Ok(false)` if already present. A disk /
    /// seal failure is surfaced as `Err(reason)` — the caller decides how loud to
    /// be; the circle still works in RAM this session regardless.
    pub fn persist_circle(&mut self, phrase: &str, label: &str) -> Result<bool, String> {
        let added = self.seeds.add_circle(phrase, label);
        if added {
            self.reseal()?;
        }
        Ok(added)
    }

    /// Published shares recorded in the blob — the M16 auto-republish set read at
    /// next launch, as `(root, optional wire-facing name)` pairs. The republish
    /// path keys on the root and uses the persisted `name` when present, else the
    /// root's basename (see `republish_name` in `net`). `name` is `None` until a
    /// name-a-share UI exists, but the slot is consumed end-to-end now.
    pub fn published(&self) -> Vec<(String, Option<String>)> {
        self.seeds
            .published()
            .iter()
            .map(|p| (p.root.clone(), p.name.clone()))
            .collect()
    }

    /// Remember a published share root (a directory path) and re-seal the blob to
    /// disk, so the share auto-republishes next launch (M16 write-through). Returns
    /// `Ok(true)` if newly remembered, `Ok(false)` if already present. A disk / seal
    /// failure is surfaced as `Err(reason)`; the share still serves in RAM this
    /// session regardless.
    pub fn persist_published(&mut self, root: &str) -> Result<bool, String> {
        // name = None until a name-a-share UI exists; the slot round-trips in the
        // blob (daemonseed_core::storage::seeds::PublishedShare).
        let added = self.seeds.add_published(root, None);
        if added {
            self.reseal()?;
        }
        Ok(added)
    }

    /// Forget a published share root and re-seal. Returns `Ok(true)` if one was
    /// removed, `Ok(false)` if it wasn't remembered.
    pub fn unpersist_published(&mut self, root: &str) -> Result<bool, String> {
        let removed = self.seeds.remove_published(root);
        if removed {
            self.reseal()?;
        }
        Ok(removed)
    }

    /// (#93) The per-relay last-seen announcements/MOTD content hash for
    /// `server_id`, or `None` if this relay was never marked seen.
    pub fn announce_seen(&self, server_id: &str) -> Option<&str> {
        self.seeds.announce_seen(server_id)
    }

    /// (#93) Record `hash` as the last-seen announcements/MOTD content hash for
    /// `server_id` and re-seal the blob to disk (unread-gating write-through).
    /// Returns `Ok(true)` if the stored value changed, `Ok(false)` if unchanged
    /// (idempotent — no re-seal). A disk / seal failure is surfaced as
    /// `Err(reason)`; the unread state is non-critical, so the caller decides how
    /// loud to be.
    pub fn persist_announce_seen(&mut self, server_id: &str, hash: &str) -> Result<bool, String> {
        let changed = self.seeds.set_announce_seen(server_id, hash);
        if changed {
            self.reseal()?;
        }
        Ok(changed)
    }

    /// #66: rename this identity — set a new display name in the at-rest blob and
    /// re-seal it (M13 write-through), so the chosen name persists across unlock.
    /// Also the recovery path for a profile created nameless before #65: it sets a
    /// name on an existing identity. The cryptographic identity (the handle hash) is
    /// unchanged — only the presented name. Rejects an invalid name
    /// (`is_valid_display_name`: non-empty, no line breaks, length-bounded); on a
    /// disk/seal failure the live handle still reflects the rename (it persists on
    /// the next write-through, mirroring `persist_circle`). Returns the new handle.
    pub fn rename(&mut self, new_name: &str) -> Result<&str, String> {
        if !daemonseed_core::handle::display_name::is_valid_display_name(new_name) {
            return Err("invalid display name (empty, too long, or contains a line break)".into());
        }
        if !self.seeds.set_display_name(Some(new_name.to_owned())) {
            return Err("the seeds layer rejected the display name".into());
        }
        self.display_handle = new_name.to_owned();
        self.reseal()?;
        Ok(&self.display_handle)
    }

    /// Re-seal the current [`Seeds`] under the cached key and overwrite `seeds.blob`.
    fn reseal(&self) -> Result<(), String> {
        let bytes = self
            .seal_key
            .seal(&self.seeds)
            .map_err(|e| format!("re-seal failed: {e}"))?;
        write_seeds_blob(&self.root, &bytes).map_err(|e| format!("write seeds.blob failed: {e}"))
    }
}
