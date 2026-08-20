//! HKDF-rooted ML-DSA-87 + ML-KEM-1024 keypair derivation (ISC-C1).
//!
//! Given a [`Mnemonic`] and an [`Identity`] (Primary or per-Device), this
//! module deterministically produces the daemon's signature and KEM
//! keypairs. The derivation chain is:
//!
//! ```text
//! BIP-39 mnemonic
//!   → bip39::to_seed("")                                    // 64-byte seed
//!   → HkdfSha384::extract(salt=IDENTITY_ROOT_SALT, ikm=seed)// PRK
//!   → expand(info=primary("sign"))   → ml_dsa_seed  → keygen(ml_dsa_seed)
//!   → expand(info=primary("kem-d"))  → kem_d
//!   → expand(info=primary("kem-z"))  → kem_z         → keygen(kem_d, kem_z)
//! ```
//!
//! Same mnemonic + same Identity = byte-identical keypair on every machine.
//! That deterministic property is what makes recovery-from-mnemonic work
//! across devices (ISC-C32 round-trip).

use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::mnemonic::Mnemonic;
use crate::kdf::info;
use crate::secret_seed::redacted_secret_newtype;

/// ML-DSA-87 seed length in bytes (FIPS 204 §5.1). The raw seed a server
/// persists (see `daemonseed-server::identity`) is exactly this long, which
/// is why [`SignKeypair::from_ml_dsa_seed`] takes a `&[u8; ML_DSA_SEED_LEN]`.
pub const ML_DSA_SEED_LEN: usize = 32;
const ML_KEM_SEED_LEN: usize = 32;

/// Identity context the user is presenting in (ISC-C1, ISC-C13).
///
/// `Primary` is the default presentation across all devices (same keypair
/// derived everywhere the user enrolls). `Device { uuid }` is the per-device
/// keypair the user can opt into when distinguishing their own machines
/// within a circle.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identity {
    Primary,
    Device { uuid: Uuid },
}

impl Identity {
    /// Build the HKDF info string for this identity and domain
    /// (`info::DOMAIN_SIGN` / `DOMAIN_KEM_D` / `DOMAIN_KEM_Z`).
    fn info_for(&self, domain: &str) -> String {
        match self {
            Identity::Primary => info::primary(domain),
            Identity::Device { uuid } => info::device(&uuid.to_string(), domain),
        }
    }
}

/// Errors surfaced by key derivation.
#[derive(Debug)]
pub enum KeyDerivationError {
    Hkdf(oxicrypt_kdf::KdfError),
    MlDsa(oxicrypt_module::Error),
    MlKem(oxicrypt_module::Error),
}

impl core::fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyDerivationError::Hkdf(e) => write!(f, "HKDF failed: {e:?}"),
            KeyDerivationError::MlDsa(e) => write!(f, "ML-DSA-87 keygen failed: {e:?}"),
            KeyDerivationError::MlKem(e) => write!(f, "ML-KEM-1024 keygen failed: {e:?}"),
        }
    }
}

impl std::error::Error for KeyDerivationError {}

/// ML-DSA-87 signing keypair derived for an [`Identity`].
///
/// The secret key zeroes on drop. The public key is non-secret.
#[derive(ZeroizeOnDrop)]
pub struct SignKeypair {
    #[zeroize(skip)]
    public_key: Box<[u8; ml_dsa::PK_LEN]>,
    secret_key: Box<[u8; ml_dsa::SK_LEN]>,
}

impl SignKeypair {
    /// 2592-byte ML-DSA-87 public key.
    pub fn public_key(&self) -> &[u8; ml_dsa::PK_LEN] {
        &self.public_key
    }

    /// 4896-byte ML-DSA-87 secret key. Caller must keep this in RAM only;
    /// it zeroes when this struct drops.
    pub fn secret_key(&self) -> &[u8; ml_dsa::SK_LEN] {
        &self.secret_key
    }

    /// Build a `SignKeypair` directly from a raw 32-byte ML-DSA-87 seed
    /// (FIPS 204 §5.1) via `oxicrypt_ml_dsa::keygen`.
    ///
    /// Clients derive their keypair from a BIP-39 mnemonic through
    /// [`derive_identity_keys`]; a relay **server**, by contrast, persists a
    /// bare 32-byte seed (`daemonseed-server::identity`) and re-derives its
    /// long-term keypair on every boot. This constructor is that path — it
    /// lets the server mint the `SignKeypair` its identity-proof envelope is
    /// signed with (ISC-S11 / ISC-S19) without routing through the mnemonic
    /// machinery. The derivation is deterministic: the same seed always
    /// yields the same keypair. Requires the oxicrypt module to be
    /// operational.
    pub fn from_ml_dsa_seed(seed: &[u8; ML_DSA_SEED_LEN]) -> Result<Self, KeyDerivationError> {
        let (pk_arr, sk_arr) = ml_dsa::keygen(seed).map_err(KeyDerivationError::MlDsa)?;
        Ok(Self {
            public_key: Box::new(pk_arr),
            secret_key: Box::new(sk_arr),
        })
    }

    /// Produce a detached ML-DSA-87 signature over `message`.
    ///
    /// Uses an empty FIPS-204 context string: daemonseed performs its own
    /// domain separation inside the signed bytes (the identity-proof envelope
    /// prepends the TLS channel-binding value, which already carries the
    /// `"daemonseed/identity-proof/v1"` exporter label — see
    /// [`crate::connection`]). Requires the oxicrypt module to be operational.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ml_dsa::SIG_LEN], SignatureError> {
        ml_dsa::sign(&self.secret_key, message, &[]).map_err(SignatureError::Module)
    }
}

/// Failure verifying a detached ML-DSA-87 signature.
#[derive(Debug)]
pub enum SignatureError {
    /// The oxicrypt module was not operational, or its active profile
    /// disallows the ML-DSA sign/verify service.
    Module(oxicrypt_module::Error),
    /// The signature did not verify under the supplied public key. This is the
    /// uniform failure for a tampered message, a wrong key, or a forged
    /// signature — verifiers MUST NOT distinguish the sub-cause (ISC-A-S12 /
    /// ISC-A-C18 uniform close-shape).
    BadSignature,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignatureError::Module(e) => write!(f, "oxicrypt module unavailable: {e:?}"),
            SignatureError::BadSignature => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Verify a detached ML-DSA-87 `signature` over `message` under `public_key`.
///
/// Returns `Ok(())` only on a valid signature. A bad signature, a wrong key,
/// and a tampered message all collapse to `Err(SignatureError::BadSignature)`
/// — the caller cannot tell which, by design (ISC-A-S12 / ISC-A-C18). Uses an
/// empty FIPS-204 context to match [`SignKeypair::sign`].
pub fn verify_signature(
    public_key: &[u8; ml_dsa::PK_LEN],
    message: &[u8],
    signature: &[u8; ml_dsa::SIG_LEN],
) -> Result<(), SignatureError> {
    match ml_dsa::verify(public_key, message, &[], signature) {
        Ok(()) => Ok(()),
        Err(_) => Err(SignatureError::BadSignature),
    }
}

impl core::fmt::Debug for SignKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignKeypair")
            .field("public_key", &"<ML-DSA-87 pubkey>")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

/// ML-KEM-1024 KEM keypair derived for an [`Identity`].
///
/// The decapsulation key zeroes on drop. The encapsulation key is
/// non-secret.
#[derive(ZeroizeOnDrop)]
pub struct KemKeypair {
    #[zeroize(skip)]
    encapsulation_key: Box<[u8; ml_kem::EK_LEN]>,
    decapsulation_key: Box<[u8; ml_kem::DK_LEN]>,
}

impl KemKeypair {
    /// 1568-byte ML-KEM-1024 encapsulation (public) key.
    pub fn encapsulation_key(&self) -> &[u8; ml_kem::EK_LEN] {
        &self.encapsulation_key
    }

    /// 3168-byte ML-KEM-1024 decapsulation (secret) key.
    pub fn decapsulation_key(&self) -> &[u8; ml_kem::DK_LEN] {
        &self.decapsulation_key
    }
}

impl core::fmt::Debug for KemKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KemKeypair")
            .field("encapsulation_key", &"<ML-KEM-1024 pubkey>")
            .field("decapsulation_key", &"<redacted>")
            .finish()
    }
}

/// Length of the share-root identity IKM (#156). A dedicated 32-byte secret,
/// the FOURTH expansion of the identity PRK, from which per-share hiding nonces
/// (`share_announce::derive_share_root_nonce`) are derived. Pinned length —
/// a second implementation must reproduce it exactly or every `share_id` re-mints.
pub const SHARE_ROOT_IKM_LEN: usize = 32;

/// Length of the Veilid node identity seed — VLD0 is Ed25519, so these 32
/// bytes ARE the node's secret seed and the public node key is its Ed25519
/// verifying key (D3).
pub const VEILID_NODE_SEED_LEN: usize = 32;

/// Length of the DM doorbell slot secret (#233) — see [`DmDoorbellSlotSecret`].
pub const DM_DOORBELL_SLOT_SECRET_LEN: usize = 32;

redacted_secret_newtype! {
    /// The share-root identity IKM (#156). A dedicated secret derived from the same
    /// mnemonic as the ML-DSA/ML-KEM identity but under a domain-separated HKDF label
    /// (`info::DOMAIN_SHARE_ROOT_IKM`), a sibling of [`VeilidNodeSeed`]. It is the ONE
    /// normative IKM for the receiver-verifiable `share_id` binding: every publish
    /// re-derives the per-share hiding nonce from `(this IKM, root)`, so a republish
    /// re-asserts the SAME `share_id` (no `#112`/`#118` ghost-share re-mint). The
    /// ML-DSA secret key is deliberately NOT this IKM — an SK-vs-entropy or GUI-vs-TUI
    /// split would fork the nonce and re-mint the id (both crypto reviews' top risk).
    /// It is identity-scoped (via `info_for`), so a Primary and a Device presentation
    /// of the same folder yield DIFFERENT commitments (no cross-presentation
    /// folder-linkage). Content NEVER derives from this — it binds only the share-id
    /// commitment nonce. Zeroizes on drop; never persisted, never on the wire.
    ///
    /// Its newtype hygiene (inline `[u8; 32]`, `Clone`, zeroize-on-drop, redacted
    /// `Debug`) is the shared `redacted_secret_newtype!` `inline` shape; its
    /// DERIVATION is distinct (the fourth expansion of the identity PRK, in
    /// [`derive_identity_keys`]) and is NOT shared with the boxed rendezvous-owner
    /// seeds.
    inline pub struct ShareRootIkm([u8; SHARE_ROOT_IKM_LEN]);
}

redacted_secret_newtype! {
    /// The Veilid node identity seed (D3). Derived from the same mnemonic as the
    /// ML-DSA/ML-KEM identity but under a domain-separated HKDF label
    /// (`info::DOMAIN_VEILID_NODE`), so one recovery phrase yields one identity
    /// across both the content layer and the Veilid transport layer while sharing
    /// no key material with the content/identity keys. Zeroizes on drop.
    ///
    /// On the `inline_scoped` arm rather than `inline`, so the bytes are reached
    /// through `with_bytes` and the type is not `Clone` (#271). This seed is the
    /// **node identity** — a strictly larger capability than any one record's write
    /// access, with the whole process as its blast radius — and the borrowing
    /// accessor plus `Clone` were two cheap paths to a plain non-zeroizing copy.
    /// [`ShareRootIkm`] stays on `inline`: it is a content-key root, not a
    /// capability.
    ///
    /// # The surface, pinned at the type
    ///
    /// The macro arm's shape is checked in `secret_seed.rs`, but that check reads
    /// the arm's *text* and cannot see this declaration — a call-site derive lands
    /// on the generated struct through `$(#[$meta])*`, and an inherent `impl` in
    /// this module reaches the private field. So the properties that matter are
    /// asserted here, against the type, where a compile is the oracle.
    ///
    /// **Positive control first.** Every case below is `compile_fail`, and a
    /// `compile_fail` block passes when the code is broken *for any reason* — a
    /// misspelt path would make all of them pass while proving nothing. This one
    /// must compile, so the path is known good:
    ///
    /// ```
    /// fn reachable(s: &daemonseed_core::identity::keys::VeilidNodeSeed) -> usize {
    ///     s.with_bytes(|b| b.len())
    /// }
    /// ```
    ///
    /// Not `Clone` — a clone is a plain non-zeroizing copy of the node identity:
    ///
    /// ```compile_fail
    /// fn needs_clone<T: Clone>() {}
    /// needs_clone::<daemonseed_core::identity::keys::VeilidNodeSeed>();
    /// ```
    ///
    /// No borrowing accessor, under this name:
    ///
    /// ```compile_fail
    /// fn borrows(s: &daemonseed_core::identity::keys::VeilidNodeSeed) {
    ///     let _ = s.as_bytes();
    /// }
    /// ```
    ///
    /// No `Deref` — the escape the scoped accessor exists to close:
    ///
    /// ```compile_fail
    /// fn needs_deref<T: core::ops::Deref>() {}
    /// needs_deref::<daemonseed_core::identity::keys::VeilidNodeSeed>();
    /// ```
    ///
    /// And no `AsRef<[u8]>`, which would hand back the same borrow by another door:
    ///
    /// ```compile_fail
    /// fn needs_as_ref<T: AsRef<[u8]>>() {}
    /// needs_as_ref::<daemonseed_core::identity::keys::VeilidNodeSeed>();
    /// ```
    ///
    /// **What this does not reach:** a borrowing accessor added under some *other*
    /// name, or a blanket impl in a third crate. Neither is expressible as a
    /// bound over a name that does not yet exist. The arm-text check in
    /// `secret_seed.rs` catches the first when it is added to the macro; added
    /// directly to this type, it is caught by review alone.
    inline_scoped pub struct VeilidNodeSeed([u8; VEILID_NODE_SEED_LEN]);
}

redacted_secret_newtype! {
    /// The DM doorbell slot secret (#233). Derived from the same mnemonic as the
    /// ML-DSA/ML-KEM identity but under a domain-separated, identity-scoped label
    /// (`info::DOMAIN_DM_DOORBELL_SLOT`), a sibling of [`VeilidNodeSeed`] and
    /// [`ShareRootIkm`]. It is the sole input — with the recipient's public
    /// identity key — to [`crate::dm::doorbell::slot_for`].
    ///
    /// Two properties make it load-bearing, and both come from what it is rather
    /// than how it is used. Because it is **mnemonic-derived**, the sender's slot
    /// is stable across reinstalls and restores, so a retried first contact
    /// overwrites its own previous entry rather than orphaning it. Because it is
    /// **secret**, the doorbell slot is not observer-computable: a storage node
    /// co-hosting the record cannot test "slot 14 is occupied, and slot 14 is
    /// where pubkey X would land", which is what keeps the doorbell sender-blind.
    ///
    /// Deriving it from the ML-DSA secret key instead would work cryptographically
    /// and is deliberately NOT done — same key-separation reasoning as
    /// [`ShareRootIkm`]. Content NEVER derives from this; it selects a slot index
    /// and nothing else. Zeroizes on drop; never persisted, never on the wire.
    inline pub struct DmDoorbellSlotSecret([u8; DM_DOORBELL_SLOT_SECRET_LEN]);
}

/// Both keypairs an [`Identity`] produces, derived deterministically from a
/// mnemonic, plus the Veilid node identity seed (D3).
#[derive(Debug)]
pub struct IdentityKeys {
    pub identity: Identity,
    pub signing: SignKeypair,
    pub kem: KemKeypair,
    /// Veilid node identity seed (D3) — see [`VeilidNodeSeed`].
    pub veilid_node_seed: VeilidNodeSeed,
    /// Share-root identity IKM (#156) — see [`ShareRootIkm`].
    pub share_root_ikm: ShareRootIkm,
    /// DM doorbell slot secret (#233) — see [`DmDoorbellSlotSecret`].
    pub dm_doorbell_slot_secret: DmDoorbellSlotSecret,
}

/// Derive the signing + KEM keypair for one [`Identity`] from a mnemonic.
///
/// Walks the chain `mnemonic → BIP-39 seed → HKDF-Extract → 3× expand →
/// ML-DSA-87 + ML-KEM-1024 keygen`. All intermediate seed buffers are
/// zeroed via Drop before returning; the returned keypairs zero on their
/// own drop.
pub fn derive_identity_keys(
    mnemonic: &Mnemonic,
    identity: Identity,
) -> Result<IdentityKeys, KeyDerivationError> {
    // BIP-39 → 64-byte seed. The `to_seed` function returns a stack array
    // we wrap in a struct-with-Drop to zero after use.
    let mut bip39_seed = SecretBuffer::<64>::new(mnemonic.to_seed(""));

    // HKDF-Extract pins the daemonseed identity-root salt so this BIP-39
    // seed cannot collide with any other consumer's HKDF context.
    let hkdf = HkdfSha384::extract(Some(info::IDENTITY_ROOT_SALT), &*bip39_seed)
        .map_err(KeyDerivationError::Hkdf)?;
    bip39_seed.zeroize();

    // ML-DSA-87 seed → keygen.
    let mut ml_dsa_seed = SecretBuffer::<ML_DSA_SEED_LEN>::zero();
    hkdf.expand(
        identity.info_for(info::DOMAIN_SIGN).as_bytes(),
        &mut *ml_dsa_seed,
    )
    .map_err(KeyDerivationError::Hkdf)?;
    let (pk_arr, sk_arr) = ml_dsa::keygen(&ml_dsa_seed).map_err(KeyDerivationError::MlDsa)?;
    let signing = SignKeypair {
        public_key: Box::new(pk_arr),
        secret_key: Box::new(sk_arr),
    };

    // ML-KEM-1024 takes two independent seeds (`d` and `z` per FIPS 203).
    let mut kem_d = SecretBuffer::<ML_KEM_SEED_LEN>::zero();
    let mut kem_z = SecretBuffer::<ML_KEM_SEED_LEN>::zero();
    hkdf.expand(
        identity.info_for(info::DOMAIN_KEM_D).as_bytes(),
        &mut *kem_d,
    )
    .map_err(KeyDerivationError::Hkdf)?;
    hkdf.expand(
        identity.info_for(info::DOMAIN_KEM_Z).as_bytes(),
        &mut *kem_z,
    )
    .map_err(KeyDerivationError::Hkdf)?;
    let (ek_arr, dk_arr) = ml_kem::keygen(&kem_d, &kem_z).map_err(KeyDerivationError::MlKem)?;
    let kem = KemKeypair {
        encapsulation_key: Box::new(ek_arr),
        decapsulation_key: Box::new(dk_arr),
    };

    // Veilid node seed (D3): one more expansion of the SAME PRK under a
    // domain-separated label. VLD0 = Ed25519, so this 32-byte output is the
    // node's secret seed directly. Copied into a self-zeroizing wrapper before
    // the transient buffer drops and zeroes.
    let mut veilid_seed = SecretBuffer::<VEILID_NODE_SEED_LEN>::zero();
    hkdf.expand(
        identity.info_for(info::DOMAIN_VEILID_NODE).as_bytes(),
        &mut *veilid_seed,
    )
    .map_err(KeyDerivationError::Hkdf)?;
    let veilid_node_seed = VeilidNodeSeed(*veilid_seed);

    // Share-root IKM (#156): a FOURTH expansion of the SAME PRK under a
    // domain-separated, identity-scoped label. This 32-byte secret is the ONE
    // normative IKM for per-share hiding nonces (share_announce), so GUI and TUI
    // — both re-deriving from the same (mnemonic, identity) — produce the
    // byte-identical nonce, and a republish re-asserts the same share_id. It
    // shares no key material with the content/identity keys. Copied into a
    // self-zeroizing wrapper before the transient buffer drops and zeroes.
    let mut share_root_ikm_buf = SecretBuffer::<SHARE_ROOT_IKM_LEN>::zero();
    hkdf.expand(
        identity.info_for(info::DOMAIN_SHARE_ROOT_IKM).as_bytes(),
        &mut *share_root_ikm_buf,
    )
    .map_err(KeyDerivationError::Hkdf)?;
    let share_root_ikm = ShareRootIkm(*share_root_ikm_buf);

    // DM doorbell slot secret (#233): a FIFTH expansion of the SAME PRK under a
    // domain-separated, identity-scoped label. Picks which of a recipient's 32
    // doorbell slots this sender knocks on. Mnemonic-rooted so the slot survives a
    // reinstall (a retry overwrites its own entry); secret so a doorbell co-host
    // cannot map slots back to senders. Copied into a self-zeroizing wrapper
    // before the transient buffer drops and zeroes.
    let mut dm_doorbell_slot_buf = SecretBuffer::<DM_DOORBELL_SLOT_SECRET_LEN>::zero();
    hkdf.expand(
        identity.info_for(info::DOMAIN_DM_DOORBELL_SLOT).as_bytes(),
        &mut *dm_doorbell_slot_buf,
    )
    .map_err(KeyDerivationError::Hkdf)?;
    let dm_doorbell_slot_secret = DmDoorbellSlotSecret(*dm_doorbell_slot_buf);

    Ok(IdentityKeys {
        identity,
        signing,
        kem,
        veilid_node_seed,
        share_root_ikm,
        dm_doorbell_slot_secret,
    })
}

/// Stack-allocated byte buffer that zeroes on drop. Used to hold transient
/// seed material between HKDF expansion and keygen so the values don't
/// linger in stack frames past their useful lifetime.
struct SecretBuffer<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> SecretBuffer<N> {
    fn new(value: [u8; N]) -> Self {
        Self { inner: value }
    }

    fn zero() -> Self {
        Self { inner: [0u8; N] }
    }
}

impl<const N: usize> core::ops::Deref for SecretBuffer<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const N: usize> core::ops::DerefMut for SecretBuffer<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<const N: usize> Zeroize for SecretBuffer<N> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<const N: usize> Drop for SecretBuffer<N> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_oxicrypt_initialized() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    const ALL_ZEROS_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn primary_derivation_is_deterministic() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let a = derive_identity_keys(&m, Identity::Primary).unwrap();
        let b = derive_identity_keys(&m, Identity::Primary).unwrap();
        assert_eq!(a.signing.public_key(), b.signing.public_key());
        assert_eq!(a.signing.secret_key(), b.signing.secret_key());
        assert_eq!(a.kem.encapsulation_key(), b.kem.encapsulation_key());
        assert_eq!(a.kem.decapsulation_key(), b.kem.decapsulation_key());
    }

    #[test]
    fn primary_and_device_diverge() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let primary = derive_identity_keys(&m, Identity::Primary).unwrap();
        let device = derive_identity_keys(&m, Identity::Device { uuid: Uuid::nil() }).unwrap();
        // Same mnemonic, different identity → different keys via HKDF info.
        assert_ne!(primary.signing.public_key(), device.signing.public_key());
        assert_ne!(
            primary.kem.encapsulation_key(),
            device.kem.encapsulation_key()
        );
    }

    #[test]
    fn different_devices_diverge() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let uuid_a = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let uuid_b = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let a = derive_identity_keys(&m, Identity::Device { uuid: uuid_a }).unwrap();
        let b = derive_identity_keys(&m, Identity::Device { uuid: uuid_b }).unwrap();
        assert_ne!(a.signing.public_key(), b.signing.public_key());
    }

    #[test]
    fn different_mnemonics_diverge() {
        ensure_oxicrypt_initialized();
        let m1 = Mnemonic::generate().unwrap();
        let m2 = Mnemonic::generate().unwrap();
        let a = derive_identity_keys(&m1, Identity::Primary).unwrap();
        let b = derive_identity_keys(&m2, Identity::Primary).unwrap();
        assert_ne!(a.signing.public_key(), b.signing.public_key());
        assert_ne!(a.kem.encapsulation_key(), b.kem.encapsulation_key());
    }

    #[test]
    fn signing_key_lengths_match_ml_dsa_87() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        assert_eq!(keys.signing.public_key().len(), ml_dsa::PK_LEN);
        assert_eq!(keys.signing.secret_key().len(), ml_dsa::SK_LEN);
    }

    #[test]
    fn kem_key_lengths_match_ml_kem_1024() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        assert_eq!(keys.kem.encapsulation_key().len(), ml_kem::EK_LEN);
        assert_eq!(keys.kem.decapsulation_key().len(), ml_kem::DK_LEN);
    }

    #[test]
    fn sign_then_verify_round_trips() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        let msg = b"daemonseed identity-proof envelope bytes";
        let sig = keys.signing.sign(msg).unwrap();
        verify_signature(keys.signing.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn from_ml_dsa_seed_matches_keygen_and_round_trips() {
        // The server's identity is a raw 32-byte ML-DSA-87 seed (not a
        // BIP-39 mnemonic), so it builds its SignKeypair via this
        // constructor. The pubkey MUST match a direct `keygen` of the same
        // seed, and the keypair must sign+verify.
        ensure_oxicrypt_initialized();
        let seed = [7u8; ML_DSA_SEED_LEN];
        let kp = SignKeypair::from_ml_dsa_seed(&seed).unwrap();
        let (expected_pk, _expected_sk) = ml_dsa::keygen(&seed).unwrap();
        assert_eq!(kp.public_key(), &expected_pk);
        let msg = b"server identity-proof envelope";
        let sig = kp.sign(msg).unwrap();
        verify_signature(kp.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn from_ml_dsa_seed_is_deterministic() {
        ensure_oxicrypt_initialized();
        let seed = [42u8; ML_DSA_SEED_LEN];
        let a = SignKeypair::from_ml_dsa_seed(&seed).unwrap();
        let b = SignKeypair::from_ml_dsa_seed(&seed).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.secret_key(), b.secret_key());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        let sig = keys.signing.sign(b"original message").unwrap();
        assert!(verify_signature(keys.signing.public_key(), b"tampered message", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let a = derive_identity_keys(&m, Identity::Primary).unwrap();
        let b = derive_identity_keys(&m, Identity::Device { uuid: Uuid::nil() }).unwrap();
        let msg = b"signed by a, verified against b";
        let sig = a.signing.sign(msg).unwrap();
        assert!(verify_signature(b.signing.public_key(), msg, &sig).is_err());
    }

    #[test]
    fn debug_redacts_secret_keys() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        let sign_dbg = format!("{:?}", keys.signing);
        let kem_dbg = format!("{:?}", keys.kem);
        assert!(sign_dbg.contains("<redacted>"));
        assert!(kem_dbg.contains("<redacted>"));
        // Sanity: actual bytes don't leak (very-loose check — look for any
        // long lowercase hex run that would indicate raw bytes).
        assert!(!sign_dbg.contains("0x"));
        assert!(!kem_dbg.contains("0x"));
    }

    #[test]
    fn veilid_node_seed_is_deterministic() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let a = derive_identity_keys(&m, Identity::Primary).unwrap();
        let b = derive_identity_keys(&m, Identity::Primary).unwrap();
        assert_eq!(
            a.veilid_node_seed.with_bytes(|b| *b),
            b.veilid_node_seed.with_bytes(|b| *b)
        );
    }

    #[test]
    fn veilid_node_seed_is_derived_not_zero() {
        // The HKDF expansion actually ran (not a left-over zeroed buffer).
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        assert_ne!(
            keys.veilid_node_seed.with_bytes(|b| *b),
            [0u8; VEILID_NODE_SEED_LEN]
        );
    }

    #[test]
    fn veilid_node_seed_diverges_by_identity() {
        // Domain separation across identities: same mnemonic, different identity
        // → different node seed (the HKDF info carries the identity), the same
        // mechanism that separates the node seed's DOMAIN_VEILID_NODE label from
        // the ML-DSA / ML-KEM content-key labels.
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let primary = derive_identity_keys(&m, Identity::Primary).unwrap();
        let device = derive_identity_keys(&m, Identity::Device { uuid: Uuid::nil() }).unwrap();
        assert_ne!(
            primary.veilid_node_seed.with_bytes(|b| *b),
            device.veilid_node_seed.with_bytes(|b| *b)
        );
    }

    #[test]
    fn veilid_node_seed_diverges_by_mnemonic() {
        ensure_oxicrypt_initialized();
        let m1 = Mnemonic::generate().unwrap();
        let m2 = Mnemonic::generate().unwrap();
        let a = derive_identity_keys(&m1, Identity::Primary).unwrap();
        let b = derive_identity_keys(&m2, Identity::Primary).unwrap();
        assert_ne!(
            a.veilid_node_seed.with_bytes(|b| *b),
            b.veilid_node_seed.with_bytes(|b| *b)
        );
    }

    /// #156: the share-root IKM is deterministic for a given (mnemonic, identity)
    /// — the property the receiver-verifiable `share_id` binding rests on (a
    /// republish re-derives the SAME nonce → SAME id). It is a real expansion (not
    /// a left-over zeroed buffer) and never collides with the node seed.
    #[test]
    fn share_root_ikm_is_deterministic_derived_and_distinct() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let a = derive_identity_keys(&m, Identity::Primary).unwrap();
        let b = derive_identity_keys(&m, Identity::Primary).unwrap();
        assert_eq!(a.share_root_ikm.as_bytes(), b.share_root_ikm.as_bytes());
        assert_ne!(a.share_root_ikm.as_bytes(), &[0u8; SHARE_ROOT_IKM_LEN]);
        // Domain separation: the share-root IKM is NOT the node seed.
        assert_ne!(
            a.share_root_ikm.as_bytes().as_slice(),
            a.veilid_node_seed.with_bytes(|b| *b).as_slice()
        );
    }

    /// #156: distinct mnemonics AND distinct identities (Primary vs Device) both
    /// diverge — so the same folder shared under two presentations yields two
    /// different commitments (no cross-presentation folder-linkage), and no two
    /// users ever share a nonce.
    #[test]
    fn share_root_ikm_diverges_by_mnemonic_and_identity() {
        ensure_oxicrypt_initialized();
        let m1 = Mnemonic::generate().unwrap();
        let m2 = Mnemonic::generate().unwrap();
        let a = derive_identity_keys(&m1, Identity::Primary).unwrap();
        let b = derive_identity_keys(&m2, Identity::Primary).unwrap();
        assert_ne!(a.share_root_ikm.as_bytes(), b.share_root_ikm.as_bytes());

        let primary = derive_identity_keys(&m1, Identity::Primary).unwrap();
        let device = derive_identity_keys(&m1, Identity::Device { uuid: Uuid::nil() }).unwrap();
        assert_ne!(
            primary.share_root_ikm.as_bytes(),
            device.share_root_ikm.as_bytes()
        );
    }

    /// #233 — the DM doorbell slot secret must be deterministic in the mnemonic
    /// (a reinstalled sender re-lands on its own doorbell slot rather than
    /// orphaning the previous knock) and must not equal any sibling secret.
    #[test]
    fn dm_doorbell_slot_secret_is_deterministic_derived_and_distinct() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let first = derive_identity_keys(&m, Identity::Primary).unwrap();
        let second = derive_identity_keys(&m, Identity::Primary).unwrap();
        assert_eq!(
            first.dm_doorbell_slot_secret.as_bytes(),
            second.dm_doorbell_slot_secret.as_bytes(),
            "re-deriving from one phrase must reproduce the slot secret — this is \
             what makes a retried first contact idempotent"
        );
        assert_ne!(first.dm_doorbell_slot_secret.as_bytes(), &[0u8; 32]);
        assert_ne!(
            first.dm_doorbell_slot_secret.as_bytes(),
            first.share_root_ikm.as_bytes()
        );
        assert_ne!(
            first.dm_doorbell_slot_secret.as_bytes(),
            &first.veilid_node_seed.with_bytes(|b| *b)
        );
    }

    /// #233 — the slot secret is identity-SCOPED, not mnemonic-global. This is the
    /// tripwire for the decision recorded in `ISA.md` (2026-07-28, the fifth
    /// identity-PRK expansion): the frozen design's "multi-device-consistent"
    /// wording, read literally, would bypass `Identity::info_for` so every
    /// presentation of one mnemonic shared a slot. A Primary and a Device are two
    /// identities with different long-term keys — hence two senders to a recipient
    /// — so a shared slot would make them silently overwrite each other's knocks.
    /// Without this test, "simplifying" the derivation back to a bare label passes
    /// the whole workspace.
    #[test]
    fn dm_doorbell_slot_secret_diverges_by_mnemonic_and_identity() {
        ensure_oxicrypt_initialized();
        let m1 = Mnemonic::generate().unwrap();
        let m2 = Mnemonic::generate().unwrap();
        assert_ne!(
            derive_identity_keys(&m1, Identity::Primary)
                .unwrap()
                .dm_doorbell_slot_secret
                .as_bytes(),
            derive_identity_keys(&m2, Identity::Primary)
                .unwrap()
                .dm_doorbell_slot_secret
                .as_bytes()
        );

        let primary = derive_identity_keys(&m1, Identity::Primary).unwrap();
        let device = derive_identity_keys(&m1, Identity::Device { uuid: Uuid::nil() }).unwrap();
        assert_ne!(
            primary.dm_doorbell_slot_secret.as_bytes(),
            device.dm_doorbell_slot_secret.as_bytes(),
            "Primary and Device are distinct senders and must not share a slot"
        );
    }

    #[test]
    fn debug_redacts_share_root_ikm() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        let dbg = format!("{:?}", keys.share_root_ikm);
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("0x"));
    }

    /// #135 KAT — byte-identity guard for the two identity-rooted inline secrets
    /// after migrating their newtype boilerplate to the shared macro. Fixed
    /// (mnemonic, identity) → fixed bytes, captured from the pre-refactor code. The
    /// derivation itself is unchanged (only the newtype hygiene was consolidated),
    /// so a drift here would flag an accidental change to the identity chain.
    #[test]
    fn identity_secret_kat_byte_identity() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        assert_eq!(
            hex::encode(keys.veilid_node_seed.with_bytes(|b| *b)),
            "0c874e8deb6413ba9f6f8457fdcb89a57741812a8936dde45f23e7b64e5ec837",
        );
        assert_eq!(
            hex::encode(keys.share_root_ikm.as_bytes()),
            "e7d6ad2e24b9248f5e12c1b81a8c0a99eccae11c61d8213552cad7e91dc26c32",
        );
        // #233 — the doorbell slot secret joins the guard. Its vector was captured
        // from this implementation (it is new here, not pre-existing), so it pins
        // the derivation against future drift rather than against a prior release.
        assert_eq!(
            hex::encode(keys.dm_doorbell_slot_secret.as_bytes()),
            "ef02a92a7fa93125671e70e2922da90f5490e5709922e3245540ca767030c7d5",
        );
    }

    /// #135 — the shared macro's `inline` redacted `Debug` renders
    /// `"<Name>(<redacted>)"` for both identity-rooted secrets (ISC-A-C1). This is
    /// the one observable change from the consolidation: the previous
    /// `debug_struct` rendering (`ShareRootIkm { ikm: "<redacted>" }` /
    /// `VeilidNodeSeed { seed: "<redacted>" }`) is now the uniform tuple form the
    /// six rendezvous-owner seeds already used. Both remain fully redacted.
    #[test]
    fn identity_secret_debug_is_redacted_tuple_form() {
        ensure_oxicrypt_initialized();
        let m = Mnemonic::from_phrase(ALL_ZEROS_PHRASE).unwrap();
        let keys = derive_identity_keys(&m, Identity::Primary).unwrap();
        assert_eq!(
            format!("{:?}", keys.veilid_node_seed),
            "VeilidNodeSeed(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", keys.share_root_ikm),
            "ShareRootIkm(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", keys.dm_doorbell_slot_secret),
            "DmDoorbellSlotSecret(<redacted>)"
        );
    }
}
