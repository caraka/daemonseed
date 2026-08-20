//! Least-authority `RouteAdvertSigner` — wraps the profile's stable ML-DSA-87
//! identity key and signs ONLY share route adverts (D-3.5).
//!
//! The identity secret stays in the app: veilid-net receives this as an
//! `Arc<dyn RouteAdvertSigner>` and can invoke route-advert signing (e.g. to
//! re-sign on `RouteChanged`), but never holds or reads the key, and the
//! capability is scoped to route adverts alone — not a general signing oracle.
//! The signed bytes are defined once in veilid-net (`route_provenance_input`);
//! this type only applies the key, so sign and verify can never drift.

use std::sync::Arc;

use daemonseed_core::identity::keys::SignKeypair;
use daemonseed_veilid_net::{RouteAdvertSigner, VeilidNetError, route_provenance_input};

/// Signs a share's route advert with the held stable identity key.
///
/// The key is held behind an `Arc` because [`SignKeypair`] is intentionally NOT
/// `Clone` (it zeroes its secret on drop), yet the app must keep the one identity
/// key in two roles at once: sealing share announcements (`&SignKeypair`) AND
/// handing veilid-net this route-advert capability. Sharing the single key via
/// `Arc` is the only way to do both without a second copy of the secret — see
/// [`Self::from_arc`].
pub struct IdentityRouteAdvertSigner {
    key: Arc<SignKeypair>,
}

impl IdentityRouteAdvertSigner {
    /// Wrap the profile's stable signing key as a route-advert capability,
    /// taking sole ownership of the key.
    pub fn new(key: SignKeypair) -> Self {
        Self { key: Arc::new(key) }
    }

    /// Wrap a SHARED reference to the stable signing key — for a caller (the GUI /
    /// TUI net actor) that retains the same `Arc<SignKeypair>` to seal share
    /// announcements with. Cheap `Arc` clone, no second copy of the secret.
    pub fn from_arc(key: Arc<SignKeypair>) -> Self {
        Self { key }
    }

    /// As the `Arc<dyn RouteAdvertSigner>` that `VeilidNetHandle::publish_share` takes.
    pub fn into_arc(self) -> Arc<dyn RouteAdvertSigner> {
        Arc::new(self)
    }
}

impl RouteAdvertSigner for IdentityRouteAdvertSigner {
    fn sign_route_advert(
        &self,
        share_id: &str,
        route_blob: &[u8],
    ) -> daemonseed_veilid_net::Result<Vec<u8>> {
        self.key
            .sign(&route_provenance_input(share_id, route_blob))
            .map(|s| s.to_vec())
            .map_err(|e| VeilidNetError::Send(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_veilid_net::verify_route_advert;

    fn keypair(seed: u8) -> SignKeypair {
        let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
        SignKeypair::from_ml_dsa_seed(&[seed; 32]).unwrap()
    }

    #[test]
    fn signs_an_advert_the_core_verifier_accepts() {
        let kp = keypair(7);
        let pubkey = *kp.public_key();
        let signer = IdentityRouteAdvertSigner::new(kp);
        let share_id = "0123456789abcdef0123456789abcdef";
        let blob = vec![0xAB; 256];
        let sig = signer.sign_route_advert(share_id, &blob).unwrap();
        assert!(verify_route_advert(&pubkey, share_id, &blob, &sig));
        // A swapped blob fails (the adapter binds share_id ‖ route_blob).
        assert!(!verify_route_advert(
            &pubkey,
            share_id,
            &vec![0xCD; 256],
            &sig
        ));
    }

    #[test]
    fn from_arc_shares_the_key_and_signs_identically() {
        let kp = keypair(8);
        let pubkey = *kp.public_key();
        // The same Arc the actor keeps for sealing announcements is handed to the
        // signer — no second copy of the secret.
        let shared = Arc::new(kp);
        let signer = IdentityRouteAdvertSigner::from_arc(shared.clone());
        let share_id = "0123456789abcdef0123456789abcdef";
        let blob = vec![0x5A; 256];
        let sig = signer.sign_route_advert(share_id, &blob).unwrap();
        assert!(verify_route_advert(&pubkey, share_id, &blob, &sig));
        // The retained Arc still signs the same way (the sealing role still works).
        let sig2 = shared
            .sign(&route_provenance_input(share_id, &blob))
            .unwrap();
        assert_eq!(sig, sig2.to_vec());
    }
}
