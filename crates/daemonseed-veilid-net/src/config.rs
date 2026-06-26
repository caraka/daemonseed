//! Bring-up configuration for the daemonseed Veilid node.

use daemonseed_core::identity::keys::VeilidNodeSeed;

/// Configuration to start a daemonseed Veilid transport node.
pub struct VeilidNetConfig {
    /// Node identity seed (D3), derived from the daemonseed mnemonic.
    pub identity_seed: VeilidNodeSeed,

    /// Bootstrap entries used to join the network — the baked-in fra1 seed plus
    /// the public Veilid bootstrap (D4). Empty = veilid's built-in defaults.
    pub bootstrap: Vec<String>,

    /// Storage directory for veilid's protected store + DHT cache.
    pub storage_dir: String,

    /// Private-route hop count (D5). daemonseed default is > 1 to harden
    /// unlinkability (latency vs anonymity). Carried for the planned safety-route
    /// dial-up; NOT yet applied — Phase 1 uses Veilid's default routing context
    /// (a 1-hop safety route). Wired into `SafetySpec.hop_count` when the higher
    /// hop count is turned on via `with_safety(Safe { .. })`.
    pub hop_count: usize,

    /// Program namespace — lets multiple nodes coexist (tests, subnodes).
    pub namespace: String,

    /// UDP/TCP/WS listen address (e.g. `":5150"`). `None` = veilid's defaults.
    /// Set a distinct port per node when running several on one host (tests,
    /// multi-node bring-up).
    pub listen_address: Option<String>,
}

impl VeilidNetConfig {
    /// A node config with daemonseed defaults: public network (no bootstrap
    /// override yet), hop_count = 2 (D5: > 1).
    pub fn new(identity_seed: VeilidNodeSeed, storage_dir: impl Into<String>) -> Self {
        Self {
            identity_seed,
            bootstrap: Vec::new(),
            storage_dir: storage_dir.into(),
            hop_count: 2,
            namespace: "daemonseed".to_owned(),
            listen_address: None,
        }
    }
}
