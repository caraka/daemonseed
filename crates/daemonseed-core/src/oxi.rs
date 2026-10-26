//! The oxicrypt cryptographic module, reached through the `oxicrypt` binding.
//!
//! The module is a separately built and signed shared library
//! (`liboxicrypt_ffi`); the `oxicrypt` crate links the program to it and
//! exposes its services as methods on an [`oxicrypt::Module`] token. This
//! module holds that token for the process and presents the services as free
//! functions and small types, so a call site names a primitive without
//! threading the token through.
//!
//! [`initialize_module`] must succeed before any other function here is
//! called; until it has, none of them performs a cryptographic operation. Each
//! returns [`Error::NotOperational`], except that `gcm_encrypt` and
//! `gcm_decrypt` refuse a nonce that is not 12 bytes with
//! [`Error::InvalidIvLength`] first. The library
//! runs its own integrity test and power-up self-tests when it is
//! initialised, so no inventory of known-answer tests is assembled here.
//!
//! ML-DSA secret keys, ML-KEM decapsulation keys and ML-KEM shared secrets
//! are held in the binding's own types, re-exported here, which zero
//! themselves when dropped. Public keys, ciphertexts and signatures are plain
//! arrays.

use std::sync::{Arc, OnceLock};

pub use oxicrypt::{Error, MlDsa87SecretKey, MlKem1024DecapsulationKey, SharedSecret};
use oxicrypt::{HkdfPrk, InitError, Module, Profile};

/// The initialised module, set once by [`initialize_module`].
static MODULE: OnceLock<Module> = OnceLock::new();

/// Initialises the oxicrypt library under the CNSA 2.0 profile.
///
/// Idempotent: a later call returns `Ok` without initialising again, so every
/// entry point and every test may call it unconditionally. The first call
/// runs the library's integrity test and power-up self-tests and blocks for
/// their duration. A failure is terminal for the process.
#[allow(clippy::result_large_err)] // called once per process; the size is immaterial
pub fn initialize_module() -> Result<(), InitError> {
    if MODULE.get().is_some() {
        return Ok(());
    }
    let module = Module::init(Profile::Cnsa2)?;
    // A concurrent first call may have set it already; both hold the same
    // library's one initialisation.
    let _ = MODULE.set(module);
    Ok(())
}

/// The module token, or [`Error::NotOperational`] before
/// [`initialize_module`] has succeeded.
fn module() -> Result<Module, Error> {
    MODULE.get().copied().ok_or(Error::NotOperational)
}

/// SHA-384 digest length.
pub const SHA384_LEN: usize = oxicrypt::SHA384_LEN;

/// SHA-384 of `data`.
pub fn sha384(data: &[u8]) -> Result<[u8; SHA384_LEN], Error> {
    module()?.sha384(data)
}

/// HKDF with HMAC-SHA-384 (RFC 5869), holding the pseudorandom key.
pub struct HkdfSha384 {
    prk: HkdfPrk,
}

impl HkdfSha384 {
    /// HKDF-Extract. A `None` salt means 48 zero bytes.
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Result<Self, Error> {
        let prk = module()?.hkdf_sha384_extract(salt, ikm)?;
        Ok(Self { prk })
    }

    /// An instance over a pseudorandom key derived elsewhere. A key that is
    /// not 48 bytes is refused with [`Error::InvalidInput`].
    pub fn from_prk(prk: &[u8]) -> Result<Self, Error> {
        module()?;
        let prk: &[u8; oxicrypt::HKDF_SHA384_PRK_LEN] =
            prk.try_into().map_err(|_| Error::InvalidInput)?;
        Ok(Self {
            prk: HkdfPrk::from_bytes(prk),
        })
    }

    /// HKDF-Expand into `okm`, filling all of it. An empty `okm` is left
    /// as it is.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
        let module = module()?;
        if okm.is_empty() {
            return Ok(());
        }
        let out = module.hkdf_sha384_expand(&self.prk, info, okm.len())?;
        okm.copy_from_slice(out.as_bytes());
        Ok(())
    }
}

/// An AES-256 key schedule held by the library. Clones share one schedule,
/// which the library frees and zeroes when the last clone is dropped.
#[derive(Clone, Debug)]
pub struct Aes256Key(Arc<oxicrypt::Aes256Key>);

impl Aes256Key {
    /// The key schedule for `key`.
    pub fn new(key: &[u8; oxicrypt::AES256_KEY_LEN]) -> Result<Self, Error> {
        Ok(Self(Arc::new(module()?.aes256_key(key)?)))
    }
}

/// The AES-256-GCM nonce `iv` as the 12-byte array the library takes.
fn gcm_nonce(iv: &[u8]) -> Result<&[u8; oxicrypt::AES256_GCM_NONCE_LEN], Error> {
    iv.try_into().map_err(|_| Error::InvalidIvLength)
}

/// AES-256-GCM encryption of `plaintext` into `ciphertext_out`, which must be
/// the same length, writing the tag to `tag_out`. `iv` must be 12 bytes.
pub fn gcm_encrypt(
    key: &Aes256Key,
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext_out: &mut [u8],
    tag_out: &mut [u8; oxicrypt::AES256_GCM_TAG_LEN],
) -> Result<(), Error> {
    let nonce = gcm_nonce(iv)?;
    *tag_out = module()?.aes256_gcm_encrypt(&key.0, nonce, aad, plaintext, ciphertext_out)?;
    Ok(())
}

/// AES-256-GCM decryption of `ciphertext` into `plaintext_out`, which must be
/// the same length. A tag that does not verify is [`Error::TagMismatch`], and
/// `plaintext_out` is then zeroed.
pub fn gcm_decrypt(
    key: &Aes256Key,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; oxicrypt::AES256_GCM_TAG_LEN],
    plaintext_out: &mut [u8],
) -> Result<(), Error> {
    let nonce = gcm_nonce(iv)?;
    module()?.aes256_gcm_decrypt(&key.0, nonce, aad, ciphertext, plaintext_out, tag)
}

/// ML-DSA-87 (FIPS 204).
pub mod ml_dsa {
    use oxicrypt::{MlDsa87KeySeed, MlDsa87SecretKey};

    use super::{Error, module};

    /// Public key length.
    pub const PK_LEN: usize = oxicrypt::ML_DSA_87_PUBLIC_KEY_LEN;
    /// Secret key length.
    pub const SK_LEN: usize = oxicrypt::ML_DSA_87_SECRET_KEY_LEN;
    /// Signature length.
    pub const SIG_LEN: usize = oxicrypt::ML_DSA_87_SIGNATURE_LEN;
    /// Key-generation seed length.
    pub const SEED_LEN: usize = oxicrypt::ML_DSA_87_SEED_LEN;

    /// The key pair generated from seed `xi`.
    pub fn keygen(xi: &[u8; SEED_LEN]) -> Result<([u8; PK_LEN], MlDsa87SecretKey), Error> {
        module()?.ml_dsa_87_keygen(MlDsa87KeySeed::from_bytes(xi))
    }

    /// The deterministic signature of `message` under context `ctx`.
    pub fn sign(sk: &MlDsa87SecretKey, message: &[u8], ctx: &[u8]) -> Result<[u8; SIG_LEN], Error> {
        module()?.ml_dsa_87_sign(sk, message, ctx)
    }

    /// Verifies `sig` over `message` under context `ctx`. A signature that
    /// does not verify is [`Error::SignatureInvalid`].
    pub fn verify(
        pk: &[u8; PK_LEN],
        message: &[u8],
        ctx: &[u8],
        sig: &[u8; SIG_LEN],
    ) -> Result<(), Error> {
        module()?.ml_dsa_87_verify(pk, message, ctx, sig)
    }
}

/// ML-KEM-1024 (FIPS 203).
pub mod ml_kem {
    use oxicrypt::{
        MlKem1024DecapsulationKey, MlKem1024EncapsSeed, MlKem1024KeySeedD, MlKem1024KeySeedZ,
        SharedSecret,
    };

    use super::{Error, module};

    /// Encapsulation key length.
    pub const EK_LEN: usize = oxicrypt::ML_KEM_1024_ENCAPSULATION_KEY_LEN;
    /// Decapsulation key length.
    pub const DK_LEN: usize = oxicrypt::ML_KEM_1024_DECAPSULATION_KEY_LEN;
    /// Ciphertext length.
    pub const CT_LEN: usize = oxicrypt::ML_KEM_1024_CIPHERTEXT_LEN;
    /// Seed length, for each of `d`, `z` and `m`.
    pub const SEED_LEN: usize = oxicrypt::ML_KEM_1024_SEED_LEN;
    /// Shared secret length.
    pub const SHARED_SECRET_LEN: usize = oxicrypt::ML_KEM_1024_SHARED_SECRET_LEN;

    /// The key pair generated from seeds `d` and `z`.
    pub fn keygen(
        d: &[u8; SEED_LEN],
        z: &[u8; SEED_LEN],
    ) -> Result<([u8; EK_LEN], MlKem1024DecapsulationKey), Error> {
        module()?.ml_kem_1024_keygen(
            MlKem1024KeySeedD::from_bytes(d),
            MlKem1024KeySeedZ::from_bytes(z),
        )
    }

    /// Encapsulates against `ek` with randomness `m`, returning the shared
    /// secret and the ciphertext.
    pub fn encapsulate(
        ek: &[u8; EK_LEN],
        m: &[u8; SEED_LEN],
    ) -> Result<(SharedSecret, [u8; CT_LEN]), Error> {
        module()?.ml_kem_1024_encapsulate(ek, MlKem1024EncapsSeed::from_bytes(m))
    }

    /// Decapsulates `ct` with `dk`. A modified ciphertext yields the
    /// implicit-rejection secret, not an error.
    pub fn decapsulate(
        dk: &MlKem1024DecapsulationKey,
        ct: &[u8; CT_LEN],
    ) -> Result<SharedSecret, Error> {
        module()?.ml_kem_1024_decapsulate(dk, ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        initialize_module().expect("oxicrypt init");
    }

    #[test]
    fn initializing_twice_is_ok() {
        initialize_module().expect("first initialization");
        initialize_module().expect("second initialization");
    }

    #[test]
    fn sha384_matches_the_fips_180_abc_vector() {
        init();
        assert_eq!(
            hex::encode(sha384(b"abc").unwrap()),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn hkdf_from_prk_expands_as_the_extracted_key() {
        init();
        let a = HkdfSha384::extract(Some(b"salt"), b"ikm").unwrap();
        let b = HkdfSha384::from_prk(a.prk.as_bytes()).unwrap();
        let (mut x, mut y) = ([0u8; 80], [0u8; 80]);
        a.expand(b"info", &mut x).unwrap();
        b.expand(b"info", &mut y).unwrap();
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 80]);
        assert_eq!(
            HkdfSha384::from_prk(&[0u8; 47]).err(),
            Some(Error::InvalidInput)
        );
    }

    #[test]
    fn gcm_round_trips_and_a_flipped_tag_is_tag_mismatch() {
        init();
        let key = Aes256Key::new(&[7u8; 32]).unwrap();
        let clone = key.clone();
        let iv = [1u8; 12];
        let mut ct = [0u8; 5];
        let mut tag = [0u8; 16];
        gcm_encrypt(&key, &iv, b"aad", b"hello", &mut ct, &mut tag).unwrap();
        let mut pt = [0u8; 5];
        gcm_decrypt(&clone, &iv, b"aad", &ct, &tag, &mut pt).unwrap();
        assert_eq!(&pt, b"hello");
        tag[0] ^= 1;
        assert_eq!(
            gcm_decrypt(&key, &iv, b"aad", &ct, &tag, &mut pt),
            Err(Error::TagMismatch)
        );
        assert_eq!(
            gcm_encrypt(&key, &[0u8; 11], b"", b"hello", &mut ct, &mut tag),
            Err(Error::InvalidIvLength)
        );
    }

    #[test]
    fn ml_dsa_signs_and_rejects_a_changed_message() {
        init();
        let (pk, sk) = ml_dsa::keygen(&[3u8; ml_dsa::SEED_LEN]).unwrap();
        let sig = ml_dsa::sign(&sk, b"msg", b"ctx").unwrap();
        ml_dsa::verify(&pk, b"msg", b"ctx", &sig).unwrap();
        assert_eq!(
            ml_dsa::verify(&pk, b"msh", b"ctx", &sig),
            Err(Error::SignatureInvalid)
        );
    }

    // Fixed vectors: for fixed seeds, messages, keys and nonces, the exact ML-DSA
    // public key and signature, ML-KEM encapsulation key, ciphertext and shared
    // secret, AES-GCM ciphertext and tag, and HKDF output this facade produces.
    // Keys and derived values that daemonseed stores or sends depend on these
    // bytes, so a change to any of them fails here. Large outputs are pinned by
    // their SHA-384.

    #[test]
    fn ml_dsa_signature_matches_the_fixed_vector() {
        init();
        let (pk, sk) = ml_dsa::keygen(&[0x11u8; ml_dsa::SEED_LEN]).unwrap();
        let sig = ml_dsa::sign(&sk, b"daemonseed fixed vector", b"ctx").unwrap();
        assert_eq!(
            hex::encode(sha384(&pk).unwrap()),
            "20f770922140453f4705b8af53e4150cc2fdfbddfab5a15abaebaeddf7ad6c9f\
             3edf4d623bd540e45e88e5f47ec34ba5"
        );
        assert_eq!(
            hex::encode(sha384(&sig).unwrap()),
            "77ee39105e00cd59f923bb007a67848a86d49e55cc0f6b7129896211812c4810\
             661953cc7717e57aa8f81cfbc5f8040f"
        );
    }

    #[test]
    fn ml_kem_encapsulation_matches_the_fixed_vector() {
        init();
        let (ek, dk) = ml_kem::keygen(&[0x22u8; 32], &[0x33u8; 32]).unwrap();
        let (ss, ct) = ml_kem::encapsulate(&ek, &[0x44u8; 32]).unwrap();
        assert_eq!(
            hex::encode(sha384(&ek).unwrap()),
            "622a3f17d17352da4908a653eea38c6808ff7bcbf80b82ffd90732efcf26cb1b\
             3f40cbc040062cef80643e682ebb8b61"
        );
        assert_eq!(
            hex::encode(sha384(&ct).unwrap()),
            "64f2734c93cc6079de225f15757d58fd4f284360f057a8df2a5029fefc014fa7\
             6008b464f83ca92e1c32b9655844ff85"
        );
        let expected_ss = "349fb8de2bd63208d870d24991c29195de754b1da8d1f8483f9a891f890a926b";
        assert_eq!(hex::encode(ss.as_bytes()), expected_ss);
        assert_eq!(
            hex::encode(ml_kem::decapsulate(&dk, &ct).unwrap().as_bytes()),
            expected_ss
        );
    }

    #[test]
    fn gcm_ciphertext_and_tag_match_the_fixed_vector() {
        init();
        let key = Aes256Key::new(&[0x55u8; 32]).unwrap();
        let plaintext = b"daemonseed fixed plaintext";
        let mut ct = [0u8; 26];
        let mut tag = [0u8; 16];
        gcm_encrypt(
            &key,
            &[0x66u8; 12],
            b"fixed aad",
            plaintext,
            &mut ct,
            &mut tag,
        )
        .unwrap();
        assert_eq!(
            hex::encode(ct),
            "5bdcdb3f1a725a2ca50d3063ced09b060f440733541ad52d1fff"
        );
        assert_eq!(hex::encode(tag), "b27fc46c3cb4feca97fd25ba2c228ef3");
    }

    #[test]
    fn hkdf_expand_matches_the_fixed_vector() {
        init();
        let hkdf = HkdfSha384::extract(Some(b"fixed salt"), b"fixed input key material").unwrap();
        let mut okm = [0u8; 80];
        hkdf.expand(b"fixed info", &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "ebb36270c0f2fa84518062ac37726c258dbfb89f210c7bc389815777322e1407\
             4e43404906b46e310dcd9329b0e480ced4d0554cd341723b61632793dd0fd7b9\
             10b03a5fc9196bdb7f0d46bdac43ed88"
        );
    }

    #[test]
    fn ml_kem_encapsulation_and_decapsulation_agree() {
        init();
        let (ek, dk) = ml_kem::keygen(&[4u8; 32], &[5u8; 32]).unwrap();
        let (ss, ct) = ml_kem::encapsulate(&ek, &[6u8; 32]).unwrap();
        assert_eq!(
            ml_kem::decapsulate(&dk, &ct).unwrap().as_bytes(),
            ss.as_bytes()
        );
    }
}
