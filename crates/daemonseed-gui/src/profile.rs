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
use daemonseed_core::profile::persist::write_seeds_blob;
use daemonseed_core::storage::seeds::{SealingKey, Seeds};

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
        }
    }

    /// The stable presented name.
    pub fn display_handle(&self) -> &str {
        &self.display_handle
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

    /// Published-share roots (directory paths) recorded in the blob — the M16
    /// auto-republish set read at next launch.
    pub fn published(&self) -> Vec<String> {
        // The net republish path keys on the root path; the optional wire-facing
        // name (PublishedShare::name) is persisted but not yet consumed here (the
        // republish-uses-persisted-name wiring + naming UI are a follow-up).
        self.seeds
            .published()
            .iter()
            .map(|p| p.root.clone())
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

    /// Re-seal the current [`Seeds`] under the cached key and overwrite `seeds.blob`.
    fn reseal(&self) -> Result<(), String> {
        let bytes = self
            .seal_key
            .seal(&self.seeds)
            .map_err(|e| format!("re-seal failed: {e}"))?;
        write_seeds_blob(&self.root, &bytes).map_err(|e| format!("write seeds.blob failed: {e}"))
    }
}
