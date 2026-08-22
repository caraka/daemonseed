//! First-contact **proof of work** — admission option B, the rate bound.
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN) § Decision #2,
//! filled in by the admission specification's decisions D1–D6. The frozen design
//! specified the preimage and never its encoding; this module is that encoding.
//!
//! ## What it is, and what it is not
//!
//! A sender searches for a 64-bit nonce such that SHA-384 of a domain-separated
//! preimage over *this exact entry* has at least [`FC_POW_BITS`] leading zero
//! bits. At 22 bits that is ~4.19 M expected hashes — seconds of one phone core,
//! milliseconds of a GPU.
//!
//! **Stated plainly, because overstating it would be worse than not having it:**
//! this prices casual and broadcast spam and caps the *verifier's* own CPU. It is
//! not a wall against a targeted GPU adversary. Against that adversary the bounds
//! are the doorbell's 32-slot shape, the contact-request gate, the block list, and
//! the invite token ([`super::token`]) — and the frozen design already accepts
//! that first contact degrades to best-effort under a resourced attacker.
//!
//! ## Why hashcash and not something memory-hard
//!
//! The decisive property is **verify-cost asymmetry, not GPU resistance**. The
//! doorbell is world-writable, so invalid entries are free to write and whatever
//! check runs first runs on attacker-chosen garbage on every sweep. Hashcash
//! verification is two short hashes on top of one hash over the entry the verifier
//! had to read anyway. A memory-hard function has **symmetric** cost — checking a
//! candidate means running the whole thing — so 32 garbage slots would cost the
//! recipient's phone 32 full passes per sweep, refreshed by the attacker for free.
//! That inverts the denial of service this module exists to prevent, with the
//! victim paying and the attacker not.
//!
//! ## Difficulty is a fixed constant, deliberately
//!
//! Not advertised in the key record: that record is world-writable and
//! rollback-able, so advertising would hand the attacker perfect knowledge and
//! hand the defender a stale-cache failure mode where an honest sender mints at
//! the old difficulty and is silently dropped. Not adaptive either: adaptivity
//! needs a shared congestion signal and there is no server to carry one.
//! [`super::domain::DM_FC_POW`] is what versions it — see that label's own note.

use oxicrypt_sha::sha384;

use super::domain;
use super::keyrec::DM_KEYREC_OWNER_SEED_LEN;
use super::push_lp;

/// Bytes of the `pow` field on the wire: the nonce, big-endian, and nothing else.
///
/// A fixed width is what makes the field a cheap shape gate — an entry whose
/// `pow` is any other length is dropped before a hash is computed. Eight bytes is
/// 2^42 times the expected search at [`FC_POW_BITS`], so the nonce space is not a
/// constraint at any difficulty this construction would plausibly reach.
pub const FC_POW_LEN: usize = 8;

/// Leading zero bits a first-contact proof of work must exhibit.
///
/// 22, which is ~4.19 M expected SHA-384 evaluations. The number separates three
/// regimes: broadcast spam pays this per victim, sustained flooding of one victim
/// costs about a dedicated desktop core, and an honest one-off knock mints in the
/// background in seconds. Going higher quadruples the honest tail on old hardware
/// per two bits while leaving a GPU attacker's absolute cost negligible, so the
/// extra bits buy almost nothing against the adversary they would be aimed at.
///
/// **Measured, not assumed** (2026-08-21, AMD Ryzen 7 4800H, release profile):
/// SHA-384 over a 151-byte preimage runs at 1.51 MH/s on one core, so the expected
/// mint here is ~2.8 s. Verification of one 27.2 KB entry measured 60 µs, which is
/// the number the sweep budget rests on.
pub const FC_POW_BITS: u32 = 22;

/// Length of the entry hash `H` bound into the preimage — a full SHA-384 digest.
pub const ENTRY_HASH_LEN: usize = 48;

/// The difficulty a mint or a verification runs at.
///
/// **A newtype rather than a bare `u32`, and the reason is the test suite.** A
/// mint at [`FC_POW_BITS`] takes seconds, which no unit test can afford, so tests
/// have to run at a reduced difficulty — and the moment difficulty is an ordinary
/// integer argument, a production call site can pass the wrong one and nothing
/// says so. Here [`Self::PRODUCTION`] is the only value ordinary code can name;
/// `PowDifficulty::reduced_for_test` is compiled only under this crate's `testing`
/// feature, exactly as `VerifiedFirstContact::new_for_test`
/// is, so it is a greppable hole rather than an open door.
///
/// It fails closed regardless: a recipient always verifies at
/// [`Self::PRODUCTION`], so an entry minted at a reduced difficulty is dropped by
/// every real verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PowDifficulty(u32);

impl PowDifficulty {
    /// The shipped difficulty — [`FC_POW_BITS`] leading zero bits.
    pub const PRODUCTION: Self = Self(FC_POW_BITS);

    /// A reduced difficulty, for tests that cannot afford a real mint.
    ///
    /// Test-gated on purpose; see the type's own note. Panics past
    /// [`FC_POW_BITS`], because a "reduced" difficulty above production is a
    /// test that means something other than what it says.
    #[cfg(any(test, feature = "testing"))]
    pub const fn reduced_for_test(bits: u32) -> Self {
        assert!(
            bits <= FC_POW_BITS,
            "a reduced difficulty must be below production"
        );
        Self(bits)
    }

    /// The number of leading zero bits required.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Anything that can go wrong minting a proof of work.
///
/// Verification has no error type at all: it answers a question about
/// attacker-supplied bytes, so every negative answer is the same answer and a
/// verifier that could distinguish them would be an oracle.
#[derive(Debug)]
pub enum PowError {
    /// SHA-384 failed at the module boundary.
    Module(oxicrypt_module::Error),
    /// The OS entropy source failed while drawing the search's starting nonce.
    EntropySource,
    /// The search ran the whole 64-bit nonce space without a hit. Unreachable in
    /// practice at any difficulty this construction supports — 2^64 evaluations
    /// at the measured rate is longer than the age of the universe — and present
    /// so the loop has a terminating arm that is not a panic.
    Exhausted,
}

impl std::fmt::Display for PowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Module(e) => write!(f, "crypto module unavailable: {e:?}"),
            Self::EntropySource => write!(f, "the entropy source failed"),
            Self::Exhausted => write!(f, "the proof-of-work nonce space was exhausted"),
        }
    }
}

impl std::error::Error for PowError {}

/// `H = SHA-384(ct0 ‖ sealed)` — the entry hash the proof of work is spent on.
///
/// **This is what makes precomputation useless.** Change one byte of the seal and
/// the mint is void, so an attacker who computes proofs in advance has shifted
/// *when* the work is spent and not *how much*: there is no entry they can attach
/// a precomputed proof to that they did not already have to seal.
///
/// Takes the two fields as raw bytes in field order rather than a decoded entry,
/// because the verifier reaches this point before it has any reason to trust the
/// decode, and because a re-encode could differ from the bytes that arrived.
///
/// # Precondition the caller must hold: `ct0` is exactly
/// [`super::firstcontact::CT0_LEN`] bytes
///
/// **There is no framing between the two operands, so injectivity is entirely the
/// caller's to supply**, and this function cannot check it — it is handed two
/// slices and has no way to know which split produced them.
///
/// It is not enough that one operand be *usually* fixed. `sealed` has **two** legal
/// widths (the [`super::firstcontact::PAD_BUCKETS`] ladder), so an unpinned `ct0`
/// leaves the split ambiguous by exactly their difference, 5120: `ct0` of 6688 with
/// `sealed` of 20508 concatenates to the same bytes as `ct0` of 1568 with `sealed`
/// of 25628, and **one nonce is then a valid proof for both entries**. That is work
/// carried from one entry to another, which is the exact property the per-entry
/// binding exists to deny.
///
/// [`super::admission`] pins the width at its shape gate, before it ever calls
/// this, and holds that ordering with a test. Any other caller must do the same.
pub fn entry_hash(ct0: &[u8], sealed: &[u8]) -> Result<[u8; ENTRY_HASH_LEN], PowError> {
    let mut buf = Vec::with_capacity(ct0.len() + sealed.len());
    buf.extend_from_slice(ct0);
    buf.extend_from_slice(sealed);
    sha384(&buf).map_err(PowError::Module)
}

/// The proof-of-work preimage:
/// `DM_FC_POW ‖ lp(recipient_keyrec_addr) ‖ lp(BE64(fc_epoch)) ‖ lp(H) ‖ lp(BE64(nonce))`.
///
/// Every field is length-prefixed with a big-endian `u64` length, the one
/// convention this build uses everywhere (`super::push_lp`), and both integers
/// are big-endian for the same reason. A uniformly-wrong encoding — little-endian
/// integers, a dropped prefix, two fields transposed — is invisible to every
/// round-trip test in this module, because minting and verifying would agree with
/// each other while agreeing with nobody else. The known-answer test is what
/// catches that class.
///
/// `recipient_keyrec_addr` is the recipient's key-record owner seed, the same
/// value the seal's AAD binds — so the proof and the seal name the recipient
/// identically, and a proof minted for one identity cannot be replayed at another.
pub fn pow_input(
    recipient_keyrec_addr: &[u8; DM_KEYREC_OWNER_SEED_LEN],
    fc_epoch: u64,
    entry_hash: &[u8; ENTRY_HASH_LEN],
    nonce: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(domain::DM_FC_POW.len() + 4 * 8 + 32 + 8 + 48 + 8);
    buf.extend_from_slice(domain::DM_FC_POW);
    push_lp(&mut buf, recipient_keyrec_addr);
    push_lp(&mut buf, &fc_epoch.to_be_bytes());
    push_lp(&mut buf, entry_hash);
    push_lp(&mut buf, &nonce.to_be_bytes());
    buf
}

/// Whether `digest` opens with at least `bits` zero bits, read MSB-first.
///
/// Bit order is the whole content of this function and is the thing most likely to
/// drift between two implementations, so it is spelled out: byte 0 is the most
/// significant, and within a byte the 0x80 bit is the first. A `bits` past the
/// digest's own width answers `false` rather than indexing off the end — an
/// attacker does not choose `bits`, but a caller might get it wrong, and a panic
/// on a sweep path is worse than a rejection.
pub fn has_leading_zero_bits(digest: &[u8], bits: u32) -> bool {
    let whole = (bits / 8) as usize;
    let remainder = bits % 8;
    if whole + usize::from(remainder > 0) > digest.len() {
        return false;
    }
    if digest[..whole].iter().any(|&b| b != 0) {
        return false;
    }
    if remainder == 0 {
        return true;
    }
    // The high `remainder` bits of the next byte must be clear.
    digest[whole] >> (8 - remainder) == 0
}

/// Whether `nonce` is a valid proof for this entry at this epoch and difficulty.
///
/// One function, used by both the minter and the verifier, so the two cannot
/// disagree about what a proof is.
pub fn verify_at_epoch(
    recipient_keyrec_addr: &[u8; DM_KEYREC_OWNER_SEED_LEN],
    fc_epoch: u64,
    entry_hash: &[u8; ENTRY_HASH_LEN],
    nonce: u64,
    difficulty: PowDifficulty,
) -> bool {
    let input = pow_input(recipient_keyrec_addr, fc_epoch, entry_hash, nonce);
    // A module fault answers "not a valid proof". It is the same answer this
    // function gives to garbage, which is right for a sweep: a phone whose
    // self-tests are failing must not admit strangers on the strength of a hash
    // it could not compute.
    match sha384(&input) {
        Ok(digest) => has_leading_zero_bits(&digest, difficulty.bits()),
        Err(_) => false,
    }
}

/// Read the wire `pow` field as a nonce. `None` on any length but [`FC_POW_LEN`].
///
/// The shape gate of D10 step 1: it costs a length comparison and runs before any
/// hash, so a flood of wrong-width fields is rejected for nothing.
pub fn nonce_from_field(pow: &[u8]) -> Option<u64> {
    let bytes: [u8; FC_POW_LEN] = pow.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// The wire form of a nonce: big-endian, exactly [`FC_POW_LEN`] bytes.
pub fn nonce_to_field(nonce: u64) -> Vec<u8> {
    nonce.to_be_bytes().to_vec()
}

/// The epochs in the accept window whose proof of work validated.
///
/// **Plural, and the plural is load-bearing.** Almost always exactly one: a nonce
/// is minted for one epoch, and the odds it also clears the threshold for the
/// other are 2^-[`FC_POW_BITS`]. But *almost* is not *never*, and when it does
/// happen at a legitimate previous-epoch knock, trying only the first match would
/// attempt the AEAD at the current epoch, fail, and silently drop a knock that was
/// perfectly valid — a real defect at a rate of one knock in four million, and one
/// that would be undiagnosable in the field.
///
/// Carrying both costs one extra AEAD open in exactly that case and nothing in
/// any other, and it gives up no security: the attacker still gets an AEAD attempt
/// only at an epoch they paid for.
///
/// Fixed-size, so a sweep allocates nothing per slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidEpochs {
    epochs: [u64; 2],
    len: u8,
}

impl ValidEpochs {
    /// The validated epochs, current first. Empty means no valid proof.
    pub fn as_slice(&self) -> &[u64] {
        &self.epochs[..self.len as usize]
    }

    /// Whether no epoch validated — the ordinary rejection.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The first validated epoch, which is the current one when both matched.
    pub fn first(&self) -> Option<u64> {
        self.as_slice().first().copied()
    }

    /// Record a validated epoch, saturating at the array's width.
    ///
    /// **The bound is not decoration.** This runs inside the loop that verifies
    /// attacker-supplied bytes, and today its safety rests entirely on [`verify`]
    /// building at most two candidates — a caller-side invariant that a change to
    /// the accept window would break silently, turning a panic-free sweep into an
    /// index out of bounds on the one code path an attacker can drive. The
    /// `debug_assert!` makes that mistake loud in tests; the saturating write makes
    /// it harmless in release.
    fn push(&mut self, epoch: u64) {
        debug_assert!(
            (self.len as usize) < self.epochs.len(),
            "more validated epochs than the accept window can hold"
        );
        if let Some(slot) = self.epochs.get_mut(self.len as usize) {
            *slot = epoch;
            self.len += 1;
        }
    }
}

/// Verify a wire `pow` field against the accepted epoch window, and answer **which
/// epochs it is a valid proof for**.
///
/// The window is the current epoch and the one immediately before it — the same
/// window [`super::keyrec::fc_epoch_is_current`] defines for the seal, because the
/// proof and the seal bind one epoch value between them. Current is checked first,
/// so it is first in the result.
///
/// **The returned epochs are load-bearing and are not a convenience.** The caller
/// attempts the AEAD at *those epochs only*. An entry whose proof and seal name
/// different epochs is therefore a wasted mint for the attacker and costs the
/// verifier two short hashes — where, before this, staleness was discovered only
/// at AEAD failure, after a decapsulation.
pub fn verify(
    recipient_keyrec_addr: &[u8; DM_KEYREC_OWNER_SEED_LEN],
    current_fc_epoch: u64,
    entry_hash: &[u8; ENTRY_HASH_LEN],
    pow: &[u8],
    difficulty: PowDifficulty,
) -> ValidEpochs {
    let mut valid = ValidEpochs::default();
    let Some(nonce) = nonce_from_field(pow) else {
        return valid;
    };
    let mut candidates = vec![current_fc_epoch];
    if let Some(previous) = current_fc_epoch.checked_sub(1) {
        candidates.push(previous);
    }
    for epoch in candidates {
        if verify_at_epoch(recipient_keyrec_addr, epoch, entry_hash, nonce, difficulty) {
            valid.push(epoch);
        }
    }
    valid
}

/// Search for a nonce satisfying `difficulty`, and return it.
///
/// The search starts from a random 64-bit point and walks forward with wrapping
/// addition. Random rather than zero because a fixed start makes every client's
/// nonce for a given entry the same value, which is a fingerprint on a surface
/// whose entire purpose is to be sender-blind; wrapping rather than saturating so
/// the walk covers the space from wherever it began.
///
/// Synchronous and unbounded. At production difficulty this runs for seconds, so a
/// caller on a UI thread must move it off — thread placement, cancellation on
/// compose-abandon and progress reporting are the composing layer's, deliberately
/// left out of the crypto core.
pub fn mint(
    recipient_keyrec_addr: &[u8; DM_KEYREC_OWNER_SEED_LEN],
    fc_epoch: u64,
    entry_hash: &[u8; ENTRY_HASH_LEN],
    difficulty: PowDifficulty,
) -> Result<u64, PowError> {
    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).map_err(|_| PowError::EntropySource)?;
    let start = u64::from_be_bytes(seed);

    let mut nonce = start;
    loop {
        let input = pow_input(recipient_keyrec_addr, fc_epoch, entry_hash, nonce);
        let digest = sha384(&input).map_err(PowError::Module)?;
        if has_leading_zero_bits(&digest, difficulty.bits()) {
            return Ok(nonce);
        }
        nonce = nonce.wrapping_add(1);
        if nonce == start {
            return Err(PowError::Exhausted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: [u8; DM_KEYREC_OWNER_SEED_LEN] = [0x11; DM_KEYREC_OWNER_SEED_LEN];
    const H: [u8; ENTRY_HASH_LEN] = [0x22; ENTRY_HASH_LEN];
    const EPOCH: u64 = 2_900_000;

    /// Cheap enough to mint thousands of times in a test run, high enough that a
    /// broken threshold check does not pass by luck.
    fn easy() -> PowDifficulty {
        PowDifficulty::reduced_for_test(8)
    }

    fn init() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
    }

    /// Mint at the reduced difficulty until the nonce is **not** also a valid
    /// proof for `avoid`.
    ///
    /// **Why this construction is necessary, and why it is not rigging the
    /// result.** At four or eight bits one nonce in sixteen or in 256 clears an
    /// unrelated tuple's threshold by chance, so a single mint makes a
    /// "must not verify elsewhere" test flake — and a flaky test is worse than
    /// none, because the green runs read as proof. The coincidence is an artefact
    /// of the reduced difficulty (at production's 22 bits it is one in four
    /// million), and it says nothing about whether the preimage binds the field:
    /// the input this test is *about* is a proof that is genuinely invalid at the
    /// other tuple, and that is what this produces. The bound loop is what makes a
    /// broken mint fail loudly rather than spin.
    fn mint_avoiding(
        addr: &[u8; DM_KEYREC_OWNER_SEED_LEN],
        epoch: u64,
        h: &[u8; ENTRY_HASH_LEN],
        difficulty: PowDifficulty,
        avoid: &[(&[u8; DM_KEYREC_OWNER_SEED_LEN], u64)],
    ) -> u64 {
        for _ in 0..256 {
            let nonce = mint(addr, epoch, h, difficulty).unwrap();
            if avoid
                .iter()
                .all(|(a, e)| !verify_at_epoch(a, *e, h, nonce, difficulty))
            {
                return nonce;
            }
        }
        panic!("256 consecutive threshold coincidences — the mint is broken");
    }

    // ── Vector 1: the preimage known-answer test ────────────────────────────

    /// **Known-answer test for the proof-of-work preimage.**
    ///
    /// Every structural test in this module is self-consistent between [`mint`]
    /// and [`verify`], so all of them stay green under a uniformly-wrong
    /// encoding: little-endian integers, a dropped length prefix, the epoch and
    /// the hash transposed, a mistyped label. Any of those makes this
    /// implementation incompatible with every other while proving nothing has
    /// broken. This is the only test that would notice — the same job
    /// `doorbell`'s address KAT does for the doorbell.
    ///
    /// The inputs are chosen so an endianness flip cannot survive: the epoch and
    /// the nonce both have distinct bytes in every position.
    #[test]
    fn the_pow_preimage_matches_its_known_answer_vector() {
        init();
        let epoch = 0x0102_0304_0506_0708u64;
        let nonce = 0x1112_1314_1516_1718u64;
        let input = pow_input(&ADDR, epoch, &H, nonce);

        // The framing, spelled out independently of `push_lp` so a change to that
        // helper cannot silently move this preimage: label, then four
        // (u64-BE length, bytes) pairs.
        let mut expected = Vec::new();
        expected.extend_from_slice(b"daemonseed/dm/fc/pow/v1");
        expected.extend_from_slice(&32u64.to_be_bytes());
        expected.extend_from_slice(&ADDR);
        expected.extend_from_slice(&8u64.to_be_bytes());
        expected.extend_from_slice(&epoch.to_be_bytes());
        expected.extend_from_slice(&48u64.to_be_bytes());
        expected.extend_from_slice(&H);
        expected.extend_from_slice(&8u64.to_be_bytes());
        expected.extend_from_slice(&nonce.to_be_bytes());
        assert_eq!(input, expected, "the preimage framing drifted");
        assert_eq!(input.len(), 23 + 40 + 16 + 56 + 16);

        assert_eq!(
            hex::encode(sha384(&input).unwrap()),
            concat!(
                "61ae8750d615e9a63e3d6ab9f0bbf782312deb933df6b7cc74705051",
                "e9ff5f9e2bc6ceb699a98a5f35f612419409e4bc"
            )
        );
    }

    /// The preimage is unambiguous: no two distinct input tuples produce the same
    /// bytes. The length prefixes are what guarantee it, and this notices if one
    /// is dropped — a dropped prefix would let the address's tail and the epoch's
    /// head be re-split into a different, equally valid pair.
    #[test]
    fn the_pow_preimage_binds_every_field_distinctly() {
        let base = pow_input(&ADDR, EPOCH, &H, 7);
        assert_ne!(
            base,
            pow_input(&[0x12; DM_KEYREC_OWNER_SEED_LEN], EPOCH, &H, 7),
            "the recipient address must be bound"
        );
        assert_ne!(
            base,
            pow_input(&ADDR, EPOCH + 1, &H, 7),
            "the epoch must be bound"
        );
        assert_ne!(
            base,
            pow_input(&ADDR, EPOCH, &[0x23; ENTRY_HASH_LEN], 7),
            "the entry hash must be bound"
        );
        assert_ne!(
            base,
            pow_input(&ADDR, EPOCH, &H, 8),
            "the nonce must be bound"
        );
    }

    /// **`H` is a bare concatenation, so what makes it unambiguous is the shape
    /// gate — not the hash.**
    ///
    /// The ratified preimage is `SHA-384(ct0 ‖ sealed)` with no length prefix
    /// between the two, so `[1,2,3] ‖ [4,5,6]` and `[1,2] ‖ [3,4,5,6]` really do
    /// collide, and this test asserts that rather than pretending otherwise. It is
    /// safe only because `ct0` is pinned to exactly [`super::firstcontact::CT0_LEN`]
    /// bytes at admission's step 1, *before* `H` is computed at step 2 — with a
    /// fixed-width prefix there is exactly one way to split the bytes.
    ///
    /// The dependency is real and is easy to break by reordering two cheap checks,
    /// so `crate::dm::admission` carries the test that holds that ordering. What
    /// is pinned here is the fact that creates the dependency.
    /// **Known-answer test for `H` itself.**
    ///
    /// The bare-concatenation test below asserts a *collision*, which any prefix
    /// or framing change preserves — and the proof-of-work KAT takes `H` as an
    /// input rather than pinning its bytes. So without this, adding a domain label
    /// inside `entry_hash` would change what every implementation computes and no
    /// test in this crate would notice. `H` is on the wire in effect: two clients
    /// that disagree about it cannot verify each other's proofs.
    #[test]
    fn the_entry_hash_matches_its_known_answer_vector() {
        init();
        let ct0 = [0xa5u8; crate::dm::firstcontact::CT0_LEN];
        let sealed = [0x5au8; 25628];
        assert_eq!(
            hex::encode(entry_hash(&ct0, &sealed).unwrap()),
            concat!(
                "e5786958f4f6c9d2b4b237e4d8fa716dedfce959d57c1bb3c380f465",
                "42961b2a03938edae5b66d7872e98d27e96c10cd"
            ),
            "H is SHA-384 over ct0 || sealed with NO label and NO framing"
        );
    }

    #[test]
    fn the_entry_hash_is_a_bare_concatenation_and_relies_on_a_fixed_width_ct0() {
        init();
        // Same bytes, split differently: identical, because there is no prefix.
        assert_eq!(
            entry_hash(&[1, 2, 3], &[4, 5, 6]).unwrap(),
            entry_hash(&[1, 2], &[3, 4, 5, 6]).unwrap(),
            "H has no internal framing — the shape gate is what disambiguates it"
        );
        // At the real width the split is forced, so no second (ct0, sealed) pair
        // of legal shape can reach the same H without the same bytes.
        let ct0 = vec![0xa5u8; crate::dm::firstcontact::CT0_LEN];
        let a = entry_hash(&ct0, &[4, 5, 6]).unwrap();
        let mut moved = ct0.clone();
        moved.push(4);
        assert_ne!(
            a,
            entry_hash(
                &moved[..crate::dm::firstcontact::CT0_LEN],
                &moved[crate::dm::firstcontact::CT0_LEN..]
            )
            .unwrap(),
            "the control must differ, or the assertion above proves nothing"
        );
        // A changed sealed byte always changes H — the property the mint rests on.
        assert_ne!(a, entry_hash(&ct0, &[4, 5, 7]).unwrap());
    }

    // ── Vector 2: the threshold boundary ────────────────────────────────────

    /// **Exactly `bits` zeros passes; `bits - 1` fails.** The off-by-one here is
    /// invisible to a round-trip test, because a minter and a verifier that agree
    /// on the wrong threshold still agree with each other.
    ///
    /// Hand-built digests, so the boundary is exercised at every bit position
    /// rather than at whichever ones a random search happens to produce.
    #[test]
    fn the_threshold_accepts_exactly_bits_zeros_and_refuses_one_fewer() {
        for bits in 0u32..=32 {
            // A digest whose leading zero run is exactly `bits`: clear the first
            // `bits` bits, then set the very next one.
            let mut digest = [0u8; 48];
            for byte in digest.iter_mut() {
                *byte = 0xff;
            }
            for i in 0..bits as usize {
                digest[i / 8] &= !(0x80u8 >> (i % 8));
            }
            assert!(
                has_leading_zero_bits(&digest, bits),
                "a run of exactly {bits} zeros must satisfy {bits} bits"
            );
            assert!(
                !has_leading_zero_bits(&digest, bits + 1),
                "a run of exactly {bits} zeros must NOT satisfy {} bits",
                bits + 1
            );
            if bits > 0 {
                assert!(
                    has_leading_zero_bits(&digest, bits - 1),
                    "a run of exactly {bits} zeros must satisfy {} bits",
                    bits - 1
                );
            }
        }
    }

    /// Bit order is MSB-first, within the byte as well as across bytes. A
    /// implementation reading the 0x01 bit first would pass every round-trip and
    /// interoperate with nothing.
    #[test]
    fn the_threshold_reads_bits_most_significant_first() {
        // 0b0000_0001 has seven leading zeros read MSB-first, zero read LSB-first.
        let digest = [0x01u8; 48];
        assert!(has_leading_zero_bits(&digest, 7));
        assert!(!has_leading_zero_bits(&digest, 8));
        // 0b1000_0000 has none.
        let digest = [0x80u8; 48];
        assert!(!has_leading_zero_bits(&digest, 1));
        assert!(has_leading_zero_bits(&digest, 0));
    }

    /// A `bits` past the digest's own width answers false rather than indexing
    /// off the end. An all-zero digest is the case that would otherwise walk past
    /// the buffer, because every byte it reads satisfies the check.
    #[test]
    fn a_threshold_wider_than_the_digest_is_refused_not_a_panic() {
        let zeros = [0u8; 48];
        assert!(has_leading_zero_bits(&zeros, 384));
        assert!(!has_leading_zero_bits(&zeros, 385));
        assert!(!has_leading_zero_bits(&zeros, u32::MAX));
        assert!(!has_leading_zero_bits(&[], 1));
        assert!(has_leading_zero_bits(&[], 0));
    }

    // ── Vector 3: mint / verify round trip ──────────────────────────────────

    /// The mint produces something the verifier accepts, at the same epoch, for
    /// the same entry.
    #[test]
    fn a_minted_proof_verifies() {
        init();
        let nonce = mint(&ADDR, EPOCH, &H, easy()).unwrap();
        assert!(verify_at_epoch(&ADDR, EPOCH, &H, nonce, easy()));
        assert_eq!(
            verify(&ADDR, EPOCH, &H, &nonce_to_field(nonce), easy()).first(),
            Some(EPOCH),
            "the accepted epoch must be reported back"
        );
    }

    /// **The production difficulty, minted for real.** Ignored by default: at the
    /// measured 1.51 MH/s this is ~2.8 s of one core, which is too long for the
    /// ordinary suite and is exactly what the shipped constant costs a sender.
    /// Run it with `--ignored` when the constant changes.
    #[test]
    #[ignore = "mints at production difficulty — seconds, not milliseconds"]
    fn a_proof_at_production_difficulty_mints_and_verifies() {
        init();
        let nonce = mint(&ADDR, EPOCH, &H, PowDifficulty::PRODUCTION).unwrap();
        assert!(verify_at_epoch(
            &ADDR,
            EPOCH,
            &H,
            nonce,
            PowDifficulty::PRODUCTION
        ));
    }

    /// The shipped constant, pinned by its own assertion so a change to it is a
    /// deliberate edit here rather than a number that drifted.
    #[test]
    fn the_production_difficulty_is_pinned() {
        assert_eq!(FC_POW_BITS, 22);
        assert_eq!(PowDifficulty::PRODUCTION.bits(), 22);
        assert_eq!(FC_POW_LEN, 8);
    }

    /// A proof is spent on ONE entry. Change the entry hash and the same nonce is
    /// worthless — which is what makes precomputation buy scheduling rather than
    /// amplification.
    #[test]
    fn a_proof_does_not_carry_to_another_entry() {
        init();
        let other_h = [0x23u8; ENTRY_HASH_LEN];
        let nonce = loop {
            let n = mint(&ADDR, EPOCH, &H, easy()).unwrap();
            // The reduced difficulty admits a coincidence one time in sixteen;
            // the input this test is about is a proof genuinely invalid for the
            // other entry. See `mint_avoiding` for the full reasoning.
            if !verify_at_epoch(&ADDR, EPOCH, &other_h, n, easy()) {
                break n;
            }
        };
        // Control: it really does verify for the entry it was minted for, so the
        // refusal below is the changed hash and not a broken mint.
        assert!(verify_at_epoch(&ADDR, EPOCH, &H, nonce, easy()));
        assert!(!verify_at_epoch(&ADDR, EPOCH, &other_h, nonce, easy()));
    }

    // ── Vector 5: the epoch window ──────────────────────────────────────────

    /// **The accept window is current and previous, and nothing else** — the same
    /// window the seal's AAD uses, mirroring `keyrec::fc_epoch_is_current`. A
    /// future epoch is refused as firmly as an ancient one: an attacker reads the
    /// same wall clock we do and could otherwise mint arbitrarily far ahead.
    #[test]
    fn the_pow_epoch_window_accepts_current_and_previous_only() {
        init();
        let current = EPOCH;
        for offered in [current, current - 1] {
            // Minted so the nonce clears ONLY the offered epoch. Without that, a
            // proof for `current - 1` that also clears `current` — one time in 256
            // at this difficulty — makes `first()` return `current` and this arm
            // fail intermittently. The coincidence is a real and correct outcome
            // (see `a_previous_epoch_knock_whose_proof_also_clears_the_current_epoch`
            // in `crate::dm::admission`); it is simply not what this arm measures.
            let avoid: Vec<(&[u8; DM_KEYREC_OWNER_SEED_LEN], u64)> = [current, current - 1]
                .into_iter()
                .filter(|&e| e != offered)
                .map(|e| (&ADDR, e))
                .collect();
            let nonce = mint_avoiding(&ADDR, offered, &H, easy(), &avoid);
            let valid = verify(&ADDR, current, &H, &nonce_to_field(nonce), easy());
            assert_eq!(
                valid.as_slice(),
                [offered],
                "epoch {offered} must be inside the window and reported as itself"
            );
        }
        for offered in [current - 2, current + 1] {
            // The nonce must be invalid at the two epochs IN the window, or the
            // reduced difficulty admits it by coincidence rather than by the
            // window — see `mint_avoiding`.
            let nonce = mint_avoiding(
                &ADDR,
                offered,
                &H,
                easy(),
                &[(&ADDR, current), (&ADDR, current - 1)],
            );
            assert_eq!(
                verify(&ADDR, current, &H, &nonce_to_field(nonce), easy()).first(),
                None,
                "epoch {offered} must be outside the window"
            );
        }
    }

    /// Epoch zero has no predecessor, and `u64::MAX` must not wrap into one.
    /// Mirrors `keyrec`'s own overflow test: the epoch arrives on the wire inside
    /// the proof, so it is attacker-controlled.
    #[test]
    fn the_pow_epoch_window_neither_underflows_nor_wraps() {
        init();
        let at_zero = mint(&ADDR, 0, &H, easy()).unwrap();
        assert_eq!(
            verify(&ADDR, 0, &H, &nonce_to_field(at_zero), easy()).first(),
            Some(0),
            "epoch 0 is its own current epoch"
        );
        let at_max = mint_avoiding(&ADDR, u64::MAX, &H, easy(), &[(&ADDR, 0)]);
        assert_eq!(
            verify(&ADDR, 0, &H, &nonce_to_field(at_max), easy()).first(),
            None,
            "u64::MAX must not be accepted as the epoch before 0"
        );
        // And the window at the top of the range still admits its predecessor,
        // so the guard above is not simply refusing everything near the edge.
        // Membership, not `first()`: a nonce that also clears `u64::MAX` is a
        // correct outcome at this difficulty and would make an assertion on
        // `first()` flake one time in 256.
        let below_max = mint(&ADDR, u64::MAX - 1, &H, easy()).unwrap();
        assert!(
            verify(&ADDR, u64::MAX, &H, &nonce_to_field(below_max), easy())
                .as_slice()
                .contains(&(u64::MAX - 1)),
            "the predecessor of the top epoch must be inside the window"
        );
    }

    // ── Vector 6: cross-recipient ───────────────────────────────────────────

    /// A proof minted naming one recipient is worthless at another, because the
    /// recipient's key-record address is inside the preimage. This is what stops
    /// one mint being sprayed across every doorbell an attacker can address.
    #[test]
    fn a_proof_minted_for_one_recipient_fails_at_another() {
        init();
        let other = [0x99u8; DM_KEYREC_OWNER_SEED_LEN];
        // BOTH epochs of the other recipient's window must be avoided, not just
        // the current one: `verify` below checks `{EPOCH, EPOCH - 1}`, so a nonce
        // that happens to clear `EPOCH - 1` at the other address makes this arm
        // fail for a reason that has nothing to do with the address binding. That
        // gap was a live 1-in-256 flake — measured at 2 failures in 500 runs of
        // the `dm::` subset — and it is the exact shape the window makes easy to
        // miss: the avoid-list has to cover what `verify` searches, not what the
        // mint named.
        let nonce = mint_avoiding(
            &ADDR,
            EPOCH,
            &H,
            easy(),
            &[(&other, EPOCH), (&other, EPOCH - 1)],
        );
        // Control: valid where it was minted.
        assert_eq!(
            verify(&ADDR, EPOCH, &H, &nonce_to_field(nonce), easy()).first(),
            Some(EPOCH)
        );
        assert_eq!(
            verify(&other, EPOCH, &H, &nonce_to_field(nonce), easy()).first(),
            None,
            "a proof must not carry to another recipient"
        );
    }

    // ── Vector 7: the field gate ────────────────────────────────────────────

    /// The `pow` field is exactly eight bytes. Absent, short and long are each
    /// refused, and the refusal costs a length comparison — no hash is computed
    /// for any of them.
    #[test]
    fn a_pow_field_of_the_wrong_width_is_refused() {
        init();
        let nonce = mint(&ADDR, EPOCH, &H, easy()).unwrap();
        let good = nonce_to_field(nonce);
        assert_eq!(good.len(), FC_POW_LEN);
        // Control: the correct width is accepted, so the refusals below are the
        // width and not something else about these bytes.
        assert_eq!(verify(&ADDR, EPOCH, &H, &good, easy()).first(), Some(EPOCH));

        for bad in [
            Vec::new(),
            good[..7].to_vec(),
            [good.clone(), vec![0]].concat(),
        ] {
            assert_eq!(nonce_from_field(&bad), None, "{} bytes", bad.len());
            assert_eq!(
                verify(&ADDR, EPOCH, &H, &bad, easy()).first(),
                None,
                "{} bytes must not verify",
                bad.len()
            );
        }
    }

    /// The nonce crosses the wire big-endian, and the round trip is exact.
    #[test]
    fn the_nonce_field_is_big_endian() {
        let nonce = 0x0102_0304_0506_0708u64;
        assert_eq!(nonce_to_field(nonce), vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(nonce_from_field(&nonce_to_field(nonce)), Some(nonce));
    }

    /// Two mints for the same entry do not produce the same nonce, because the
    /// search starts from OS entropy. A fixed start would make a client's nonce
    /// for a given entry a constant — a fingerprint on the one surface whose whole
    /// purpose is sender-blindness.
    ///
    /// At 8 bits roughly one nonce in 256 is a hit, so two independent random
    /// starts colliding is ~2^-56; a fixed start collides always.
    #[test]
    fn the_nonce_search_starts_from_entropy_not_from_zero() {
        init();
        let a = mint(&ADDR, EPOCH, &H, easy()).unwrap();
        let b = mint(&ADDR, EPOCH, &H, easy()).unwrap();
        assert_ne!(a, b, "two mints for one entry produced the same nonce");
        // Both are genuinely valid — the difference is not one of them failing.
        assert!(verify_at_epoch(&ADDR, EPOCH, &H, a, easy()));
        assert!(verify_at_epoch(&ADDR, EPOCH, &H, b, easy()));
    }
}
