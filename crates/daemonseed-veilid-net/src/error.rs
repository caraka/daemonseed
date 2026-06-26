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
