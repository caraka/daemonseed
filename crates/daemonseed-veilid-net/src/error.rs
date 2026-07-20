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
}
