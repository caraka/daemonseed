//! The DM **doorbell** — where a stranger knocks (ISC-C41).
//!
//! DM's only unauthenticated write surface, and the one record a party writes
//! that it does not own. Its shape follows from a single unavoidable fact: cold
//! first contact needs an address a stranger can compute from nothing but the
//! recipient's public identity, and under Veilid's DFLT schema a world-derivable
//! address means a world-derivable *owner* — so the record is world-writable.
//! Everything here is built around bounding that, since it cannot be removed.
//!
//! Three properties carry the design (`docs/design/direct-messaging.md` DRAFT v6
//! § The doorbell, § R5/V4-5, § R7 sizing):
//!
//! 1. **Recipient-keyed address.** The owner seed is
//!    `HKDF(salt = DM_DOORBELL_SALT, ikm = PK_lt_B, info = DM_DOORBELL_OWNER)`,
//!    so B sweeps one record it can always find, and any sender can reach it.
//!    Keying the address on the *pair* `(PK_lt_A, PK_lt_B)` is refuted: a
//!    world-derivable pairwise address is a contact-graph oracle — anyone could
//!    test whether A had ever written to B.
//! 2. **Sender-blind slot.** Within the record, A writes at
//!    `slot_for(sender_secret_A, PK_lt_B)`. The secret is A's, so a storage node
//!    co-hosting the doorbell cannot map an occupied slot back to a candidate
//!    sender. It learns how many slots are occupied and how often they change —
//!    the accepted anonymized in-degree residual (ISC-A-C23). It is *blindness*,
//!    not anonymity: the slot cannot be DERIVED from any public input, but a knock
//!    is still an activity-timed write, so the accepted F1 lobby-rhythm
//!    intersection remains out of scope rather than excluded.
//! 3. **Stable across restarts.** The secret is mnemonic-derived
//!    ([`crate::identity::keys::DmDoorbellSlotSecret`]), so a reinstalled sender
//!    lands on the same slot and its retry *overwrites its own* previous entry.
//!    A per-session secret would scatter one sender's retries across slots and
//!    orphan every earlier one — the `#118` ephemeral-key bug class, avoided here
//!    from birth rather than fixed later.
//!
//! **32 slots, and the number is a consequence, not a preference.** A DFLT
//! record's per-subkey cap is `min(32768, 1 MiB / o_cnt)`, and frozen build-contract
//! item (iv) requires the entry's top padding bucket to be ≤ 32768 — so the subkey
//! must hold a full 32768-byte bucket, which needs `o_cnt ≤ 32`. (The base entry is
//! ~18 KB and a token-bearing one ~23 KB; sizing on those alone would have allowed
//! more slots, which is why the padding bucket is the binding constraint and not
//! the entry itself.) A `dflt(256)` subkey caps at 4096 B and could not hold an
//! entry at all. The cost is priced and accepted: with 32 slots,
//! birthday collision among *concurrent unknown* senders starts to bite around 7.
//! Colliders overwrite each other, both re-seed, and B sweeps the whole record, so
//! a collision usually costs latency rather than delivery — though under sustained
//! collision it degrades to the design's best-effort first-contact limit and
//! surfaces honestly as undelivered, never as a false "delivered". Established
//! contacts leave the doorbell entirely, so steady-state occupancy stays low.
//! Splitting the entry into a doorbell pointer plus a sender-owned body is the
//! post-alpha lever if a recipient's popularity ever exceeds this.
//!
//! This module is addressing only. The entry's contents, sealing, and admission
//! checks live alongside it as the rest of #233 lands.

use oxicrypt_kdf::HkdfSha384;
use oxicrypt_ml_dsa as ml_dsa;

use crate::dm::domain;
use crate::identity::keys::DmDoorbellSlotSecret;
use crate::secret_seed::{derive_boxed_seed, redacted_secret_newtype};

/// Byte length of the Veilid owner seed this module derives.
pub const DM_DOORBELL_OWNER_SEED_LEN: usize = 32;

/// Number of slots in a doorbell record — the `o_cnt` of its `dflt(o_cnt)`
/// schema, and therefore part of the record's address.
///
/// Pinned at 32 by the padding-bucket arithmetic: see the module docs. Changing it
/// changes both the address and the per-subkey cap, so it is FROZEN.
///
/// **A writer MUST build its `RecordShape` from this constant**, never from a
/// hand-typed literal — `o_cnt` is part of the deterministic record address, so a
/// shape that disagrees with it addresses a record nobody sweeps, silently and
/// with no error on any surface. That is the defect class `RendezvousHandle`
/// exists to close (ISC-C100).
pub const DOORBELL_SLOTS: u16 = 32;

redacted_secret_newtype! {
    /// The Veilid record-owner seed for an identity's doorbell.
    ///
    /// Carries the secret-newtype hygiene (zeroize-on-drop, redacted `Debug`) for
    /// consistency with its siblings, but like
    /// [`crate::dm::keyrec::DmKeyRecordOwnerSeed`] it is deliberately
    /// **world-derivable**: every sender computes it, which is the entire point.
    /// Holding it confers write access, so the doorbell's safety rests on the
    /// entry being sealed and on the recipient verifying it — never on ownership.
    boxed pub struct DmDoorbellOwnerSeed([u8; DM_DOORBELL_OWNER_SEED_LEN]);
}

/// Anything that can go wrong deriving a doorbell address or slot.
#[derive(Debug, PartialEq, Eq)]
pub enum DmDoorbellError {
    /// HKDF failed — an unrecoverable crypto-module condition.
    Kdf(oxicrypt_kdf::KdfError),
}

impl std::fmt::Display for DmDoorbellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "doorbell key derivation failed: {e}"),
        }
    }
}

impl std::error::Error for DmDoorbellError {}

/// Derive the world-derivable Veilid owner seed for `recipient_pubkey`'s
/// doorbell: `HKDF-SHA-384(salt = DM_DOORBELL_SALT, ikm = PK_lt_B, info = DM_DOORBELL_OWNER)`.
///
/// Deterministic and pure — no clock, no randomness, no network. The recipient
/// derives it to sweep its own doorbell; every sender derives the same value to
/// knock. Note this takes the same `ikm` as
/// [`crate::dm::keyrec::derive_owner_seed`] and yields a different address purely
/// because the salt and info labels differ; that separation is the whole reason
/// the labels are distinct and prefix-free.
pub fn derive_owner_seed(
    recipient_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Result<DmDoorbellOwnerSeed, DmDoorbellError> {
    let hkdf = HkdfSha384::extract(Some(domain::DM_DOORBELL_SALT), recipient_pubkey)
        .map_err(DmDoorbellError::Kdf)?;
    let seed = derive_boxed_seed::<DM_DOORBELL_OWNER_SEED_LEN>(&hkdf, domain::DM_DOORBELL_OWNER)
        .map_err(DmDoorbellError::Kdf)?;
    Ok(DmDoorbellOwnerSeed(seed))
}

/// Which slot of `recipient_pubkey`'s doorbell this sender knocks on:
/// `HKDF(salt = DM_DOORBELL_SLOT_SALT, ikm = sender_secret, info = DM_DOORBELL_SLOT ‖ lp(PK_lt_B)) % DOORBELL_SLOTS`.
///
/// Deterministic in `(sender_secret, recipient_pubkey)` and nothing else — no
/// clock, no counter, no session state — which is exactly what makes a retry
/// idempotent: it re-lands on the slot it used last time.
///
/// Folding the recipient's key into the derivation means one sender occupies an
/// *unrelated* slot index at each recipient. Without it, a sender would sit at
/// the same index everywhere, and two co-hosting storage nodes could correlate
/// "slot 14 is busy on both of these doorbells" into a cross-recipient
/// fingerprint of one sender.
///
/// **No modulo bias:** `DOORBELL_SLOTS` is a power of two and divides `2^64`
/// exactly, so reducing a uniform `u64` leaves every slot equally likely. (A
/// non-power-of-two slot count would need rejection sampling; this is asserted in
/// the tests so a future change to `DOORBELL_SLOTS` cannot silently skew it.)
pub fn slot_for(
    sender_secret: &DmDoorbellSlotSecret,
    recipient_pubkey: &[u8; ml_dsa::PK_LEN],
) -> Result<u16, DmDoorbellError> {
    let hkdf = HkdfSha384::extract(
        Some(domain::DM_DOORBELL_SLOT_SALT),
        sender_secret.as_bytes(),
    )
    .map_err(DmDoorbellError::Kdf)?;

    // Length-prefixed like every other daemonseed preimage (u64 big-endian length
    // ‖ bytes). The pubkey is fixed-length so nothing is actually ambiguous here;
    // the prefix keeps one convention across the codebase rather than inviting a
    // reader to work out whether this particular concatenation is safe.
    let mut info = Vec::with_capacity(domain::DM_DOORBELL_SLOT.len() + 8 + recipient_pubkey.len());
    info.extend_from_slice(domain::DM_DOORBELL_SLOT);
    info.extend_from_slice(&(recipient_pubkey.len() as u64).to_be_bytes());
    info.extend_from_slice(recipient_pubkey);

    let mut out = [0u8; 8];
    hkdf.expand(&info, &mut out).map_err(DmDoorbellError::Kdf)?;
    Ok((u64::from_be_bytes(out) % u64::from(DOORBELL_SLOTS)) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::{Identity, derive_identity_keys};
    use crate::identity::mnemonic::Mnemonic;

    /// Sample count for the two distribution tests.
    const SAMPLES: usize = 24;

    /// How many distinct slots those samples must cover.
    ///
    /// A correct derivation spreads 24 draws over 32 bins and is expected to hit
    /// `32·(1 − (31/32)^24) ≈ 17` of them, so this threshold is deliberately far
    /// below the mean: on correct code it fails with probability ≈ 2.7 × 10⁻⁸, and
    /// it still catches a derivation that has collapsed the slot space (a stray
    /// `% 2` or `% 4` in place of `% DOORBELL_SLOTS` can reach at most 2 or 4). The
    /// earlier `> 1` was ~16× weaker than the samples supported and would have let
    /// such a collapse through. Note the KAT is what pins the modulus exactly;
    /// these tests bound the *shape* of the distribution.
    const MIN_DISTINCT: usize = 8;

    const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon art";
    const PHRASE_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                            zoo zoo zoo zoo zoo zoo zoo vote";

    fn keys(phrase: &str) -> crate::identity::keys::IdentityKeys {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(&Mnemonic::from_phrase(phrase).unwrap(), Identity::Primary).unwrap()
    }

    fn alice() -> crate::identity::keys::IdentityKeys {
        keys(PHRASE_A)
    }

    fn bob() -> crate::identity::keys::IdentityKeys {
        keys(PHRASE_B)
    }

    /// A fresh identity for the distribution tests, which need many samples and
    /// assert only over the SET of outcomes. Every other test uses a fixed vector,
    /// for the reason `keyrec`'s `bob()` records: a random identity cannot make an
    /// inequality spuriously pass, but it makes an intermittent failure
    /// unreplayable from the source.
    fn random_identity() -> crate::identity::keys::IdentityKeys {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap()
    }

    /// **Known-answer vector — the test that actually pins this construction.**
    ///
    /// Every other test here is structural (determinism, inequality, range), and
    /// structural tests cannot see a change that is uniformly wrong: swapping
    /// `to_be_bytes` for `to_le_bytes`, dropping the length prefix, exchanging the
    /// HKDF salt and ikm, or editing a domain label all keep every inequality true
    /// while silently moving every address and slot. Two implementations that
    /// disagree here never see each other's knocks.
    ///
    /// Most importantly this is what pins **sender-blindness**. Keying `slot_for`
    /// off the sender's *public* key instead of the secret would satisfy every
    /// structural assertion below — and hand a doorbell co-host a candidate-set
    /// attack against every sender. It cannot satisfy this one.
    ///
    /// The vectors were captured from this implementation (the frozen design
    /// publishes no test vectors), so they guard against *drift*, not against a
    /// derivation that was wrong from the start. The construction itself is
    /// reviewed against `docs/design/direct-messaging.md`; this locks it down once
    /// reviewed.
    #[test]
    fn doorbell_derivations_match_their_known_answer_vectors() {
        let a = alice();
        let b = bob();

        assert_eq!(
            hex::encode(
                derive_owner_seed(a.signing.public_key())
                    .unwrap()
                    .as_bytes()
            ),
            "a2fae18d98cd579544f5418e8248422d720d5ae545e6ea7f7a49853341bb7dd5",
        );
        assert_eq!(
            hex::encode(
                derive_owner_seed(b.signing.public_key())
                    .unwrap()
                    .as_bytes()
            ),
            "bd149a35e861f1f5aca0161addcaf9dc71acd64196cabc93e00ae65b925c870e",
        );

        // Both directions of the same pair. They differ, so exchanging the two
        // arguments is caught; and 23 is unreachable under any modulus smaller
        // than 24, so a `% 2` / `% 4` / `% 8` / `% 16` slip in place of
        // `% DOORBELL_SLOTS` fails here even though it would satisfy every
        // distribution and range assertion below.
        assert_eq!(
            slot_for(&a.dm_doorbell_slot_secret, b.signing.public_key()).unwrap(),
            6,
        );
        assert_eq!(
            slot_for(&b.dm_doorbell_slot_secret, a.signing.public_key()).unwrap(),
            23,
        );
    }

    /// The address must be a pure function of the recipient's public key — it is
    /// how a stranger finds where to knock.
    #[test]
    fn owner_seed_is_deterministic_in_the_recipient_pubkey() {
        let b = bob();
        let first = derive_owner_seed(b.signing.public_key()).unwrap();
        let second = derive_owner_seed(b.signing.public_key()).unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    /// Distinct identities must never share a doorbell.
    #[test]
    fn owner_seed_separates_distinct_identities() {
        assert_ne!(
            derive_owner_seed(alice().signing.public_key())
                .unwrap()
                .as_bytes(),
            derive_owner_seed(bob().signing.public_key())
                .unwrap()
                .as_bytes()
        );
    }

    /// The doorbell and the key record are derived from the SAME public key and
    /// must still land on different records. Only the domain labels separate
    /// them, so this is the test that catches a label edit that collapses the two
    /// surfaces onto one address.
    #[test]
    fn doorbell_and_key_record_addresses_differ() {
        let b = bob();
        let doorbell = derive_owner_seed(b.signing.public_key()).unwrap();
        let keyrec = crate::dm::keyrec::derive_owner_seed(b.signing.public_key()).unwrap();
        assert_ne!(
            doorbell.as_bytes(),
            keyrec.as_bytes(),
            "the doorbell must not collide with the key record it sits beside"
        );
    }

    /// Idempotent retry across a **reinstall** (design § channel idempotency): the
    /// slot must survive re-deriving the identity from the recovery phrase, so a
    /// retried knock overwrites the sender's own earlier entry instead of orphaning
    /// it in a second slot.
    ///
    /// Deriving the identity twice is the load-bearing part. Calling `slot_for`
    /// twice on ONE `IdentityKeys` would only prove the function is pure, which it
    /// visibly is; it would not notice a slot secret that stopped being
    /// mnemonic-rooted, which is the way this property actually breaks.
    #[test]
    fn slot_survives_re_deriving_the_identity_from_the_phrase() {
        let b = bob();
        let first = slot_for(
            &keys(PHRASE_A).dm_doorbell_slot_secret,
            b.signing.public_key(),
        );
        let second = slot_for(
            &keys(PHRASE_A).dm_doorbell_slot_secret,
            b.signing.public_key(),
        );
        assert_eq!(first.unwrap(), second.unwrap());
    }

    /// A slot index is only meaningful inside its own doorbell: the same sender
    /// must not sit at a predictable common index across recipients, or two
    /// co-hosting storage nodes could fingerprint them by position alone.
    #[test]
    fn one_sender_is_not_pinned_to_one_index_across_recipients() {
        let a = alice();
        let slots: std::collections::BTreeSet<u16> = (0..SAMPLES)
            .map(|_| {
                let b = random_identity();
                slot_for(&a.dm_doorbell_slot_secret, b.signing.public_key()).unwrap()
            })
            .collect();
        assert!(
            slots.len() >= MIN_DISTINCT,
            "one sender hit only {} distinct slots across {SAMPLES} recipients — \
             the recipient key is barely reaching the derivation",
            slots.len()
        );
    }

    /// Sender-blindness, distribution half: distinct senders must spread across the
    /// record rather than pile onto one slot. (The property that the slot is not
    /// *computable* from public inputs is pinned by the KAT above — no
    /// distribution test can see it.)
    #[test]
    fn distinct_senders_derive_independent_slots() {
        let b = bob();
        let slots: std::collections::BTreeSet<u16> = (0..SAMPLES)
            .map(|_| {
                let a = random_identity();
                slot_for(&a.dm_doorbell_slot_secret, b.signing.public_key()).unwrap()
            })
            .collect();
        assert!(
            slots.len() >= MIN_DISTINCT,
            "{SAMPLES} senders hit only {} distinct slots at one recipient — the \
             sender secret is barely reaching the derivation",
            slots.len()
        );
    }

    /// Every derived slot must be addressable in the record.
    #[test]
    fn slots_are_always_in_range() {
        let b = bob();
        for _ in 0..SAMPLES {
            let a = random_identity();
            let slot = slot_for(&a.dm_doorbell_slot_secret, b.signing.public_key()).unwrap();
            assert!(slot < DOORBELL_SLOTS, "slot {slot} is outside the record");
        }
    }

    /// The uniformity argument in `slot_for`'s docs holds only for a power-of-two
    /// slot count. If `DOORBELL_SLOTS` ever changes to one that is not, plain
    /// modulo silently biases toward the low slots and this test is the tripwire.
    #[test]
    fn slot_count_is_a_power_of_two_so_modulo_is_unbiased() {
        assert!(DOORBELL_SLOTS.is_power_of_two());
        assert_eq!(
            DOORBELL_SLOTS, 32,
            "the entry-size derivation pins this at 32"
        );
    }
}
