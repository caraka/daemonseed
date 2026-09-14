//! Error surface for the Veilid transport layer.

/// Errors from bringing up or operating the daemonseed Veilid node.
#[derive(Debug, thiserror::Error)]
pub enum VeilidNetError {
    #[error("veilid startup failed: {0}")]
    Startup(String),

    #[error("node did not become public-internet-ready in time")]
    NotReady,

    #[error("routing error: {0}")]
    Routing(String),

    #[error("send failed: {0}")]
    Send(String),

    /// A network call that ran out of time: an open or a read cut off at its
    /// bound, a call Veilid itself answered with `Timeout`, or a write the
    /// network had not taken when its confirmation budget ran out. Told apart
    /// from [`Self::Routing`] and [`Self::Send`] where the timeout is first seen,
    /// so a caller counting failures can count it as one.
    #[error("timed out: {0}")]
    TimedOut(String),

    /// A failure that never left this node: a runtime that cannot carry the
    /// call, a record this node expected to hold and does not, a write the
    /// scheduler never took because it is gone, or a call Veilid refused before
    /// sending it (`NotInitialized`, `AlreadyInitialized`, `Shutdown`,
    /// `Unimplemented`, `ParseError`, `InvalidArgument`, `MissingArgument` or
    /// `TransactionNotFound`).
    #[error("refused locally: {0}")]
    Local(String),

    /// The peer ANSWERED, but does not serve the requested share/chunk — it was
    /// withdrawn (unpublished via `stop_serve`) or never offered. Distinct from a
    /// transport error (`Send` / offline / slow / dead route): this is an
    /// authoritative negative from a reachable owner, so the client can report
    /// "withdrawn" immediately instead of leaving the user to guess through
    /// timeouts (the Demonsaw failed-vs-slow-vs-withdrawn ambiguity).
    #[error("the peer no longer serves this share (withdrawn or never offered)")]
    NotServed,

    /// The sharer served content that failed verification: a SHA-384
    /// content-address mismatch (ISC-S28 / ISC-A-S20), a chunk-address mismatch,
    /// or a malformed / oversized response frame. Distinct from a transport error
    /// (`Send`) because the route is fine — the *content* is hostile — so the
    /// download engine treats it as FATAL for the share (never persisted, never
    /// resumed past), not as a resumable blip (#205: both were `Send(String)`).
    #[error("share content failed verification: {0}")]
    Integrity(String),

    #[error("invalid node identity: {0}")]
    Identity(String),

    /// The actor task is gone or dropped a reply before answering a command.
    #[error("actor channel error: {0}")]
    Actor(String),

    /// A Phase 2+ surface (circles / shares / presence / announcements) that
    /// this crate does not implement yet.
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, VeilidNetError>;

/// How a Veilid API call failed, from the variant of its error alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VeilidFailure {
    /// The call ran out of time.
    TimedOut,
    /// The call was refused before it left this node.
    Local,
    /// The network, or this node's view of it, refused the call.
    Refused,
}

/// Every variant of `VeilidAPIError` (`veilid-core-0.5.7
/// src/veilid_api/error.rs:128-216`), classed once, here.
///
/// Local: the API not attached or already attached, shutting down, a feature
/// this build lacks, an argument that would not parse, was rejected or was
/// missing, and a transaction handle already completed
/// (`src/veilid_api/dht_transaction.rs:74`). None of these can have reached the
/// network. Refused: retry later, an unreachable target, no connection, a record
/// this node does not hold, Veilid's generic error, and an internal failure,
/// which Veilid also raises after a fanout has run
/// (`src/storage_manager/inspect_record.rs:249,649`,
/// `src/storage_manager/open_record.rs:266`,
/// `src/rpc_processor/fanout/fanout_call.rs:365`,
/// `src/rpc_processor/fanout/fanout_queue.rs:274`). The match names every
/// variant, so a variant a later Veilid adds does not compile until it is
/// classed.
pub(crate) fn veilid_failure(error: &veilid_core::VeilidAPIError) -> VeilidFailure {
    use veilid_core::VeilidAPIError as E;
    match error {
        E::Timeout => VeilidFailure::TimedOut,
        E::NotInitialized => VeilidFailure::Local,
        E::AlreadyInitialized => VeilidFailure::Local,
        E::Shutdown => VeilidFailure::Local,
        E::Internal { .. } => VeilidFailure::Refused,
        E::Unimplemented { .. } => VeilidFailure::Local,
        E::ParseError { .. } => VeilidFailure::Local,
        E::InvalidArgument { .. } => VeilidFailure::Local,
        E::MissingArgument { .. } => VeilidFailure::Local,
        E::TransactionNotFound { .. } => VeilidFailure::Local,
        E::TryAgain { .. } => VeilidFailure::Refused,
        E::InvalidTarget { .. } => VeilidFailure::Refused,
        E::NoConnection { .. } => VeilidFailure::Refused,
        E::KeyNotFound { .. } => VeilidFailure::Refused,
        E::Generic { .. } => VeilidFailure::Refused,
    }
}

impl VeilidNetError {
    /// `error` from the call `what`, as [`veilid_failure`] classes it: a timeout
    /// as [`Self::TimedOut`], a local refusal as [`Self::Local`], and anything
    /// else as `refused` builds it.
    pub(crate) fn from_veilid(
        what: &str,
        error: veilid_core::VeilidAPIError,
        refused: fn(String) -> VeilidNetError,
    ) -> Self {
        let text = format!("{what}: {error}");
        match veilid_failure(&error) {
            VeilidFailure::TimedOut => Self::TimedOut(text),
            VeilidFailure::Local => Self::Local(text),
            VeilidFailure::Refused => refused(text),
        }
    }
}

/// Coarse class of a fetch-path failure. The download engine switches on this to
/// decide resume vs abort vs surface, WITHOUT switching on error *message
/// strings* — the #205 blocker was that a transient timeout and a content
/// integrity failure were indistinguishable, both `Send(String)`. The class is
/// derived at the site where the knowledge exists (the SHA-384 verify, the
/// malformed-frame guards, the retry loop), never re-inferred downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchErrorClass {
    /// Transport / route failure — a fragment timed out after its retry budget,
    /// the route died or would not import, or a reply went absent mid-stream.
    /// RESUMABLE: verified units are retained and the share stays Unresolved
    /// (#180 park semantics).
    Transient,
    /// The sharer served content that failed verification — SHA-384
    /// content-address mismatch, chunk-address mismatch, or a malformed /
    /// oversized frame. FATAL for the share: never persisted, never resumed past.
    Integrity,
    /// The reachable owner answered that it does not serve this share/chunk
    /// (withdrawn or never offered) — an authoritative negative, not an error of
    /// the route.
    NotServed,
    /// A local fault on the fetcher (path sanitize, disk create/write, index
    /// write). The route is unaffected and verified units are retained. This
    /// class is contributed by the download engine's own filesystem failures, so
    /// [`VeilidNetError::fetch_class`] never returns it.
    Local,
}

impl VeilidNetError {
    /// Classify this transport error for the download engine's resume/abort
    /// decision (DL-ISC-10). Never returns [`FetchErrorClass::Local`] — that
    /// class originates in the engine's own disk/path failures, not the wire.
    pub fn fetch_class(&self) -> FetchErrorClass {
        match self {
            VeilidNetError::Integrity(_) => FetchErrorClass::Integrity,
            VeilidNetError::NotServed => FetchErrorClass::NotServed,
            // Every transport / route / actor / config failure is treated as a
            // resumable transient at the fetch boundary. A local identity or
            // not-yet-implemented fault must NEVER poison-abort a share, so it
            // classifies transient (surfaced, route untouched), not integrity.
            VeilidNetError::Send(_)
            | VeilidNetError::Routing(_)
            | VeilidNetError::TimedOut(_)
            | VeilidNetError::Local(_)
            | VeilidNetError::Actor(_)
            | VeilidNetError::NotReady
            | VeilidNetError::Startup(_)
            | VeilidNetError::Identity(_)
            | VeilidNetError::Unimplemented(_) => FetchErrorClass::Transient,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DL-ISC-10: the fetch boundary types transient-transport, integrity, and
    /// not-served failures apart; the SHA-384 mismatch (an `Integrity`) is the
    /// headline case that #205 could not distinguish from a timeout.
    #[test]
    fn fetch_class_maps_each_variant_to_its_class() {
        assert_eq!(
            VeilidNetError::Integrity("sha-384 mismatch".into()).fetch_class(),
            FetchErrorClass::Integrity,
        );
        assert_eq!(
            VeilidNetError::NotServed.fetch_class(),
            FetchErrorClass::NotServed,
        );
        for e in [
            VeilidNetError::Send("Timeout".into()),
            VeilidNetError::TimedOut("open_only: Timeout".into()),
            VeilidNetError::Local("open_only: Shutdown".into()),
            VeilidNetError::Routing("no route".into()),
            VeilidNetError::Actor("actor gone".into()),
            VeilidNetError::NotReady,
            VeilidNetError::Startup("boot".into()),
            VeilidNetError::Identity("bad identity".into()),
            VeilidNetError::Unimplemented("phase-2"),
        ] {
            assert_eq!(e.fetch_class(), FetchErrorClass::Transient, "{e:?}");
        }
    }

    /// DL-ISC-10: `Local` is engine-contributed; no transport error yields it.
    #[test]
    fn fetch_class_never_returns_local_from_a_transport_error() {
        let all = [
            VeilidNetError::Integrity("x".into()),
            VeilidNetError::NotServed,
            VeilidNetError::Send("x".into()),
            VeilidNetError::TimedOut("x".into()),
            VeilidNetError::Local("x".into()),
            VeilidNetError::Routing("x".into()),
            VeilidNetError::Actor("x".into()),
            VeilidNetError::NotReady,
            VeilidNetError::Startup("x".into()),
            VeilidNetError::Identity("x".into()),
            VeilidNetError::Unimplemented("x"),
        ];
        assert!(all
            .iter()
            .all(|e| e.fetch_class() != FetchErrorClass::Local));
    }

    /// Every variant of veilid-core 0.5.7's `VeilidAPIError` is classed as the
    /// source says it can have failed: out of time, before it left this node, or
    /// refused by the network. The class reaches the error the call reports.
    #[test]
    fn every_veilid_failure_is_classified_by_its_variant() {
        use veilid_core::{BareOpaqueRecordKey, OpaqueRecordKey, VeilidAPIError as E};
        let text = || "x".to_owned();
        let table = [
            (E::Timeout, VeilidFailure::TimedOut),
            (E::NotInitialized, VeilidFailure::Local),
            (E::AlreadyInitialized, VeilidFailure::Local),
            (E::Shutdown, VeilidFailure::Local),
            (E::Internal { message: text() }, VeilidFailure::Refused),
            (E::Unimplemented { message: text() }, VeilidFailure::Local),
            (
                E::ParseError {
                    message: text(),
                    value: text(),
                },
                VeilidFailure::Local,
            ),
            (
                E::InvalidArgument {
                    context: text(),
                    argument: text(),
                    value: text(),
                },
                VeilidFailure::Local,
            ),
            (
                E::MissingArgument {
                    context: text(),
                    argument: text(),
                },
                VeilidFailure::Local,
            ),
            (
                E::TransactionNotFound { message: text() },
                VeilidFailure::Local,
            ),
            (E::TryAgain { message: text() }, VeilidFailure::Refused),
            (E::InvalidTarget { message: text() }, VeilidFailure::Refused),
            (E::NoConnection { message: text() }, VeilidFailure::Refused),
            (
                E::KeyNotFound {
                    key: OpaqueRecordKey::new(
                        veilid_core::CRYPTO_KIND_VLD0,
                        BareOpaqueRecordKey::new(&[0u8; 32]),
                    ),
                },
                VeilidFailure::Refused,
            ),
            (E::Generic { message: text() }, VeilidFailure::Refused),
        ];
        assert_eq!(
            table.len(),
            15,
            "one row per variant of veilid-core 0.5.7's VeilidAPIError"
        );
        for (error, expected) in table {
            let shown = error.to_string();
            assert_eq!(veilid_failure(&error), expected, "{shown}");
            let reported = match VeilidNetError::from_veilid("call", error, VeilidNetError::Routing)
            {
                VeilidNetError::TimedOut(_) => VeilidFailure::TimedOut,
                VeilidNetError::Local(_) => VeilidFailure::Local,
                VeilidNetError::Routing(_) => VeilidFailure::Refused,
                other => panic!("{shown} is reported as an unexpected variant: {other:?}"),
            };
            assert_eq!(reported, expected, "{shown} is reported as its class");
        }
    }
}
