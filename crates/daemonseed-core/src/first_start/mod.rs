//! First-start orchestrator (ISC-C29 / C30 / C31 / C32 / C33 / C34 / C37).
//!
//! `FirstStart<State>` is a compile-time-gated state machine for the cold
//! enrollment flow. The ordering invariant is **identity-recoverable-
//! before-identity-exposed** (ISC-A-C15): no method on any state can
//! initiate a network connection, and the [`Ready`] terminal — the only
//! state that yields [`SessionMaterials`] for the wire layer (M4a+) — is
//! reachable only via [`Sealed`] → [`BackupVerified`] → [`Ready`].
//!
//! Phases (each `Sealed → BackupVerified → Ready` transition consumes the
//! prior state; no skip path):
//!
//! ```text
//!   FirstStart<Welcome>
//!     .initialize(passphrase, argon2_params)        // C29 steps 1-3
//!   → FirstStart<Sealed>
//!     .display_phrase()                              // C31 copy-friendly
//!     .issue_type_back_challenge(rng)                // C34 helper
//!     .verify_round_trip(saved)                      // C33  OR
//!     .verify_type_back(challenge, answers)          // C34
//!   → FirstStart<BackupVerified>
//!     .finalize(display_name, bootstrap)             // C29 steps 5-7
//!   → FirstStart<Ready>
//!     .into_session_materials()                      // handoff to M4a
//! ```
//!
//! There is **no** `Ready::skip_backup_verification` toggle (forbidden by
//! ISC-A-C13). There is no network call anywhere in this module
//! (forbidden by ISC-A-C14). The orchestrator never touches the
//! filesystem — callers (CLI / TUI) take the returned blob/recovery
//! bytes and write them to the profile root.

mod orchestrator;
mod verify;

pub use orchestrator::{
    BackupVerified, FirstStart, FirstStartError, Ready, Sealed, SessionMaterials, Welcome,
};
pub use verify::TypeBackChallenge;
