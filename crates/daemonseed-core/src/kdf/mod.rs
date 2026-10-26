//! Key-derivation helpers and the load-bearing HKDF info-string registry.
//!
//! All HKDF info strings used anywhere in daemonseed live in [`info`] as
//! `pub const &str`s. Pinning them in one source-of-truth module means a
//! wire-visible regression test (D5 §5, lands in M4a) can byte-compare the
//! constants against the spec and trip immediately on drift.

pub mod info;

use crate::oxi::HkdfSha384;
use zeroize::Zeroizing;

/// Bytes of HKDF output the Veilid device-key password is encoded from.
const VEILID_DEVICE_KEY_PASSWORD_LEN: usize = 32;

/// Bytes of HKDF output the Veilid namespace tag is encoded from.
const VEILID_NAMESPACE_TAG_LEN: usize = 8;

/// `len` bytes of HKDF-SHA384 over `profile_secret`, under
/// [`info::VEILID_STORAGE_SALT`] and `label`, as lowercase hex.
fn veilid_storage_hex(
    profile_secret: &[u8],
    label: &str,
    len: usize,
) -> Result<Zeroizing<String>, oxicrypt::Error> {
    let prk = HkdfSha384::extract(Some(info::VEILID_STORAGE_SALT), profile_secret)?;
    let mut okm = Zeroizing::new(vec![0u8; len]);
    prk.expand(label.as_bytes(), &mut okm)?;
    let mut hex = Zeroizing::new(String::with_capacity(2 * len));
    for byte in okm.iter() {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("a nibble"));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("a nibble"));
    }
    Ok(hex)
}

/// The password Veilid's table store protects its device encryption key
/// under, for a node started by the profile whose unlocked at-rest key is
/// `profile_secret`: 32 bytes under [`info::VEILID_DEVICE_KEY_PASSWORD`], as
/// lowercase hex. The same profile gives the same password on every launch,
/// and two profiles give different ones.
pub fn veilid_device_key_password(
    profile_secret: &[u8],
) -> Result<Zeroizing<String>, oxicrypt::Error> {
    veilid_storage_hex(
        profile_secret,
        info::VEILID_DEVICE_KEY_PASSWORD,
        VEILID_DEVICE_KEY_PASSWORD_LEN,
    )
}

/// The tag a profile's Veilid namespace carries: 8 bytes under
/// [`info::VEILID_NAMESPACE_TAG`], as lowercase hex. Unrelated to the
/// password, so a namespace visible on disk says nothing of it.
pub fn veilid_namespace_tag(profile_secret: &[u8]) -> Result<String, oxicrypt::Error> {
    Ok(veilid_storage_hex(
        profile_secret,
        info::VEILID_NAMESPACE_TAG,
        VEILID_NAMESPACE_TAG_LEN,
    )?
    .as_str()
    .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One profile secret gives one password on every call, and another
    /// profile's secret gives another. The password is hex of the whole
    /// output.
    #[test]
    fn a_device_key_password_is_fixed_per_profile_and_differs_across_profiles() {
        let _ = crate::oxi::initialize_module();
        let one = veilid_device_key_password(&[0x11; 32]).unwrap();
        let again = veilid_device_key_password(&[0x11; 32]).unwrap();
        let other = veilid_device_key_password(&[0x12; 32]).unwrap();
        assert_eq!(*one, *again, "deterministic for one profile");
        assert_ne!(*one, *other, "distinct across profiles");
        assert_eq!(one.len(), 2 * VEILID_DEVICE_KEY_PASSWORD_LEN);
        assert!(one.bytes().all(|b| b.is_ascii_hexdigit()));
        let tag = veilid_namespace_tag(&[0x11; 32]).unwrap();
        assert_eq!(tag, veilid_namespace_tag(&[0x11; 32]).unwrap());
        assert_ne!(tag, veilid_namespace_tag(&[0x12; 32]).unwrap());
        assert_eq!(tag.len(), 16);
        assert!(!one.contains(&tag), "the tag is not part of the password");
    }
}
