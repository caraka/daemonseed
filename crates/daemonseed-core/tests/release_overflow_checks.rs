//! The profile this was compiled under panics on integer overflow (#258).
//!
//! `overflow-checks` is on by default in dev and **off** by default in release, so
//! the workspace `Cargo.toml` turns it back on for release. That line is one word
//! away from being silently inert — a mistyped key, the wrong profile name, or a
//! member overriding the profile would all leave a green build behind — and there
//! is no way to interrogate the effective profile from stable cargo
//! (`cargo config get` is nightly-only). So the setting is verified the only way
//! that cannot lie: by overflowing on purpose and requiring the panic.
//!
//! This is deliberately in an integration test rather than a unit test, so it
//! compiles as its own crate under the profile being asserted about, and its file
//! name says what it holds.
//!
//! Scope: one crate's compilation proves the profile reached that crate. The
//! setting is declared workspace-wide in `[profile.release]`, which cargo applies
//! to every member and dependency, so this is representative rather than
//! exhaustive — it would not catch a *member-specific* override elsewhere.

/// Overflow panics in whatever profile this test was built under.
///
/// In dev this passes because `debug-assertions` implies `overflow-checks`. In
/// release it passes only because the workspace sets `overflow-checks = true`;
/// remove that line and the addition wraps silently, no panic is raised, and this
/// test fails. That failure is the point — it is what makes the profile line
/// enforced rather than merely present.
///
/// Both operands and the result go through [`std::hint::black_box`] so the
/// expression cannot be constant-folded. Without it rustc evaluates `u64::MAX + 1`
/// at compile time and refuses to build at all (`this arithmetic operation will
/// overflow`), which would be a compile error rather than the runtime panic the
/// profile is responsible for.
#[test]
#[should_panic(expected = "attempt to add with overflow")]
fn integer_overflow_panics_in_the_profile_this_was_built_under() {
    let max = std::hint::black_box(u64::MAX);
    let one = std::hint::black_box(1u64);
    let _ = std::hint::black_box(max + one);
}
