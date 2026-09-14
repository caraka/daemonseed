//! The OS CSPRNG, adapted to the fill signatures the tree's draws take.
//!
//! A draw that takes its entropy read as a parameter can be driven by a failing
//! fill from a test, so its degrade becomes an ordinary branch. Production passes
//! one of these.

/// The production entropy source for an eight-byte draw.
///
/// The error is discarded rather than carried: no caller can act on *why* the
/// CSPRNG failed, and the degrade is the same either way.
pub(crate) fn os_fill(buf: &mut [u8; 8]) -> Result<(), ()> {
    getrandom::fill(buf).map_err(|_| ())
}

/// The same source, slice-typed, for callers that draw buffers of more than one
/// size — key generation and encapsulation seeds alongside an interval draw.
///
/// One definition rather than a second `getrandom` call beside each of them: the
/// production entropy source and its discarded error belong in one place, and a
/// module that grew its own would be the copy nobody keeps in step.
pub(crate) fn os_fill_bytes(buf: &mut [u8]) -> Result<(), ()> {
    getrandom::fill(buf).map_err(|_| ())
}
