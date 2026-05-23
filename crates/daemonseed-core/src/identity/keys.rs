//! HKDF-rooted ML-DSA-87 + ML-KEM-1024 keypair derivation (ISC-C1).
//!
//! Given a [`Mnemonic`] and an [`Identity`] (Primary or per-Device), this
//! module deterministically produces the daemon's signature and KEM
//! keypairs. The derivation chain is:
//!
//! ```text
//! BIP-39 mnemonic
//!   → bip39::to_seed("")                                    // 64-byte seed
//!   → HkdfSha256::extract(salt=IDENTITY_ROOT_SALT, ikm=seed)// PRK
//!   → expand(info=primary("sign"))   → ml_dsa_seed  → keygen(ml_dsa_seed)
//!   → expand(info=primary("kem-d"))  → kem_d
//!   → expand(info=primary("kem-z"))  → kem_z         → keygen(kem_d, kem_z)
//! ```
//!
//! Same mnemonic + same Identity = byte-identical keypair on every machine.
//! That deterministic property is what makes recovery-from-mnemonic work
//! across devices (ISC-C32 round-trip).

use oxicrypt_kdf::HkdfSha256;
use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::mnemonic::Mnemonic;
use crate::kdf::info;

const ML_DSA_SEED_LEN: usize = 32;
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
    /// 4896-byte ML-DSA-87 public key.
    pub fn public_key(&self) -> &[u8; ml_dsa::PK_LEN] {
        &self.public_key
    }

    /// 4032-byte ML-DSA-87 secret key. Caller must keep this in RAM only;
    /// it zeroes when this struct drops.
    pub fn secret_key(&self) -> &[u8; ml_dsa::SK_LEN] {
        &self.secret_key
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

/// Both keypairs an [`Identity`] produces, derived deterministically from a
/// mnemonic.
#[derive(Debug)]
pub struct IdentityKeys {
    pub identity: Identity,
    pub signing: SignKeypair,
    pub kem: KemKeypair,
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
    let hkdf = HkdfSha256::extract(Some(info::IDENTITY_ROOT_SALT), &*bip39_seed)
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

    Ok(IdentityKeys {
        identity,
        signing,
        kem,
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
        let _ = oxicrypt_module::initialize();
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
}
