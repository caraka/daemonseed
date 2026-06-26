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
    /// dial-up; NOT applied while Phase 1 uses the spike-proven Unsafe routing
    /// context (no safety route). Wired into `SafetySpec.hop_count` when Safe
    /// routing is turned on.
    pub hop_count: usize,

    /// Program namespace — lets multiple nodes coexist (tests, subnodes).
    pub namespace: String,
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
        }
    }
}
