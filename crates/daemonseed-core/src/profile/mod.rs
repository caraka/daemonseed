//! Profile substrate — profile-id, Argon2 params persistence, and the
//! ISC-C35 profile-root resolution rules.
//!
//! Every daemonseed install ("profile") has:
//! - A stable UUID v4 [`profile_id`](ProfileConfig::profile_id) drawn at
//!   first-start from cryptographic randomness (ISC-C36, ISC-A-C16).
//! - Per-profile [Argon2 params](ArgonParams) chosen at first-start,
//!   persisted in `daemonseed.toml`, never silently changed (ISC-C14,
//!   ISC-A-C17).
//! - A *profile root* — the directory containing `daemonseed.toml`, the
//!   at-rest seeds blob (ISC-C3), the recovery file (ISC-C32), and any
//!   per-profile cached state. Resolved per ISC-C35.

pub mod config;
pub mod resolve;

pub use config::{ArgonParams, ProfileConfig, ProfileConfigError};
pub use resolve::{ResolveArgs, ResolveError, ResolvedProfileRoot};
