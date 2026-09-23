//! Bring-up configuration for the daemonseed Veilid node.

use daemonseed_core::identity::keys::VeilidNodeSeed;
use zeroize::Zeroizing;

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

    /// The password Veilid's table store protects its device encryption key
    /// under, so the key is not kept in the clear beside the tables it opens.
    /// Set by [`Self::protect_with_profile`]. `None` draws a fresh random one
    /// at start, under the namespace with [`NO_PROFILE_SUFFIX`] appended, and
    /// fails the start where the operating system gives no randomness. Storage
    /// whose key does not open under it is cleared and recreated at start.
    /// Never logged.
    pub device_key_password: Option<Zeroizing<String>>,
}

/// What a start without a profile appends to the namespace. No profile's
/// namespace ends in it: [`VeilidNetConfig::protect_with_profile`] appends a
/// hex tag.
pub const NO_PROFILE_SUFFIX: &str = "-noprofile";

impl VeilidNetConfig {
    /// A node config with daemonseed defaults: public network (no bootstrap
    /// override), hop_count = 2 (D5: > 1), and no profile.
    pub fn new(identity_seed: VeilidNodeSeed, storage_dir: impl Into<String>) -> Self {
        Self {
            identity_seed,
            bootstrap: Vec::new(),
            storage_dir: storage_dir.into(),
            hop_count: 2,
            namespace: "daemonseed".to_owned(),
            listen_address: None,
            device_key_password: None,
        }
    }

    /// Protect Veilid's device encryption key under the password derived
    /// from `profile_secret`, the profile's unlocked at-rest key
    /// ([`daemonseed_core::kdf::veilid_device_key_password`]), and append the
    /// profile's tag ([`daemonseed_core::kdf::veilid_namespace_tag`]) to the
    /// namespace, so the profile's storage opens on every launch of it and two
    /// profiles sharing a directory never share a namespace. Call it after the
    /// namespace is otherwise set.
    pub fn protect_with_profile(
        &mut self,
        profile_secret: &[u8],
    ) -> Result<(), daemonseed_core::kdf::KdfError> {
        let tag = daemonseed_core::kdf::veilid_namespace_tag(profile_secret)?;
        self.device_key_password = Some(daemonseed_core::kdf::veilid_device_key_password(
            profile_secret,
        )?);
        self.namespace = format!("{}-{tag}", self.namespace);
        Ok(())
    }
}

/// Thirty-two bytes from `fill`, as lowercase hex, or `None` where `fill`
/// gives none.
pub(crate) fn random_password(
    fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Option<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    fill(&mut *bytes).ok()?;
    let mut password = Zeroizing::new(String::with_capacity(64));
    for byte in bytes.iter() {
        password.push(char::from_digit(u32::from(byte >> 4), 16).expect("a nibble"));
        password.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("a nibble"));
    }
    Some(password)
}
