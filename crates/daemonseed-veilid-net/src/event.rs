//! Typed events the transport actor emits, mapped from raw `VeilidUpdate`s so
//! the app/UI never touches veilid types directly.

/// A daemonseed-facing transport event.
#[derive(Debug)]
pub enum VeilidNetEvent {
    /// Attachment state changed; `public_internet_ready` gates all operations.
    /// `reliable_peers` / `live_peers` are the current attach peer counts (the
    /// DHT-warmup progress indicator, #144) — they climb during the cold-start.
    Attachment {
        public_internet_ready: bool,
        reliable_peers: u32,
        live_peers: u32,
    },

    /// An opaque, sealed inbound message arrived off the wire. The app opens it
    /// with the relevant circle/room key — this layer never sees plaintext.
    Inbound { bytes: Vec<u8> },

    /// A private route we allocated or imported died/changed and may need
    /// re-allocation (Veilid private routing is a moving target).
    RouteChanged,

    /// A watched DHT value changed — Phase 2+ (circles / presence / shares).
    ValueChanged,
}
