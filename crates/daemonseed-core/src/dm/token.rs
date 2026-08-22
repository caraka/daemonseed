//! The **grantee-bound one-time invite token** — admission option C.
//!
//! Design of record: `docs/design/direct-messaging.md` (FROZEN) § Decision #2 and
//! the invite-token paragraphs, made byte-precise by the admission specification's
//! decisions D7–D9. An `invite_only` identity admits a stranger's knock only if it
//! carries a token that identity itself issued, to that exact stranger, unspent.
//!
//! ## Three properties, and each is carried by a different piece
//!
//! **It is not a bearer secret.** The token names its grantee — the grantee's
//! long-term public key is inside the signed preimage and is *not* carried in the
//! token bytes. The verifier takes that key from the knock's own `pk_lt` and
//! rebuilds the preimage, so an intercepted or forwarded token is inert: it only
//! ever verifies stapled to the identity it names, and reaching that identity
//! means holding its secret key, which `bind_lt` and `msg_sig` already prove.
//!
//! **It cannot be forged, and issuer binding costs no field.** The verifier checks
//! the signature against **its own** long-term public key. A token minted by
//! anyone else fails closed, so there is nothing to carry and nothing to trust.
//!
//! **It expires, and the grantee cannot extend it.** The expiry is inside the
//! signed preimage rather than beside it.
//!
//! ## One-time-ness is local, and that is complete rather than a compromise
//!
//! There is no server, so there is no global nonce set — and none is needed, since
//! only the issuer ever verifies its own tokens. [`SpentTokenSet`] is therefore the
//! whole of the enforcement. Consumption happens at **admission** (when the knock
//! is surfaced or auto-accepted), not at establishment, so a declined stranger
//! cannot re-knock on the same token; decline is regret, and the block list is what
//! makes it stick. Consumption is ordered strictly **after** full verification, so
//! a forged entry naming a real token can never burn it.
//!
//! Revoking an issued-but-unspent token is inserting its nonce early — no message
//! to anyone, no state to publish.
//!
//! The set is lost on recovery-from-mnemonic. That is the frozen design's accepted
//! residual: a recovered profile re-admits a token it had already spent, which is
//! bounded by the token's own expiry.

use oxicrypt_ml_dsa as ml_dsa;

use crate::identity::keys::{SignKeypair, SignatureError, verify_signature};

use super::domain;
use super::keyrec::FC_PERIOD_SECS;
use super::push_lp;

/// Bytes of a token's nonce, drawn from OS entropy at mint.
pub const TOKEN_NONCE_LEN: usize = 32;

/// Bytes of a `TokenV1` on the wire: `nonce_t(32) ‖ BE64(expiry) ‖ sig(4627)`.
///
/// Fixed, which is what lets the field be a cheap shape gate before any signature
/// is verified.
pub const TOKEN_LEN: usize = TOKEN_NONCE_LEN + 8 + ml_dsa::SIG_LEN;

/// How long a freshly minted token stays redeemable, in seconds — 30 days.
///
/// Long enough that an async grantee who is offline for weeks can still redeem it,
/// short enough to bound both [`SpentTokenSet`] and the window in which a regretted
/// grant is still live. A mint-time UI may choose a shorter expiry; nothing here
/// requires this value, it is the default a caller with no opinion gets.
pub const TOKEN_VALIDITY_SECS: u64 = 30 * 24 * 60 * 60;

/// How long past its expiry a spent nonce must be retained before it can be
/// pruned: `expiry + 2 · FC_PERIOD_SECS`.
///
/// **The two epochs are the reason, and dropping them would reopen one-time-ness.**
/// A knock is accepted at the current or the previous first-contact epoch, so an
/// entry composed just before a token expired can legitimately arrive up to two
/// epochs later. Pruning at the expiry itself would let that entry — and a replay
/// of it — find an empty spent-set.
pub const SPENT_RETENTION_SECS: u64 = 2 * FC_PERIOD_SECS;

/// Anything that can go wrong minting or verifying an invite token.
///
/// The verify-path variants are deliberately coarse where an attacker chooses the
/// input: a caller learns *that* a token was refused, and the admission path
/// answers every refusal with the same silent drop. They are separate variants
/// because an issuer debugging its own grant flow needs to tell "expired" from
/// "not mine", and that caller is not an adversary.
/// No `PartialEq`: [`Self::Signing`] carries a [`SignatureError`], which has
/// none. Tests match on the variant.
#[derive(Debug)]
pub enum TokenError {
    /// The bytes are not [`TOKEN_LEN`] long.
    Malformed { expected: usize, actual: usize },
    /// The token's expiry has passed.
    Expired { expiry: u64, now: u64 },
    /// The signature did not verify under the issuer's key for the claimed
    /// grantee. Covers a forgery, a token issued by somebody else, a token for a
    /// different grantee, and a tampered expiry — uniformly, because from the
    /// verifier's side those are the same event.
    Signature,
    /// This nonce has already been consumed.
    Spent,
    /// A local signing operation failed while MINTING. Carries its cause: there
    /// is no adversary on this path.
    Signing(SignatureError),
    /// The OS entropy source failed while drawing the nonce.
    EntropySource,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { expected, actual } => {
                write!(f, "an invite token is {expected} bytes, got {actual}")
            }
            Self::Expired { expiry, now } => {
                write!(f, "the invite token expired at {expiry}, now {now}")
            }
            Self::Signature => write!(f, "the invite token did not verify"),
            Self::Spent => write!(f, "the invite token has already been used"),
            Self::Signing(e) => write!(f, "could not sign the invite token: {e}"),
            Self::EntropySource => write!(f, "the entropy source failed"),
        }
    }
}

impl std::error::Error for TokenError {}

/// The signed preimage:
/// `DM_TOKEN ‖ lp(grantee_pk_lt) ‖ lp(nonce_t) ‖ lp(BE64(expiry))`.
///
/// Length-prefixed with big-endian `u64` lengths and a big-endian expiry — this
/// build's one convention (`super::push_lp`) — so the concatenation is
/// unambiguous and no adjacent pair can be re-split into a different, equally
/// valid tuple.
///
/// **The grantee's key is here and nowhere else.** It is what the verifier
/// supplies from the knock rather than reads from the token, which is the whole of
/// the theft resistance: the bytes prove nothing on their own.
pub fn token_input(
    grantee_pk_lt: &[u8; ml_dsa::PK_LEN],
    nonce: &[u8; TOKEN_NONCE_LEN],
    expiry_unix_secs: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(domain::DM_TOKEN.len() + ml_dsa::PK_LEN + 3 * 8 + 48);
    buf.extend_from_slice(domain::DM_TOKEN);
    push_lp(&mut buf, grantee_pk_lt);
    push_lp(&mut buf, nonce);
    push_lp(&mut buf, &expiry_unix_secs.to_be_bytes());
    buf
}

/// A grantee-bound one-time invite token.
///
/// Constructible from bytes without verifying anything — [`Self::decode`] gates
/// only the shape — because the admission path deliberately checks the cheap
/// fields (width, expiry, spent) before spending an ML-DSA verification on the
/// signature. Holding one is therefore **not** a claim that it is valid;
/// [`Self::verify`] is.
#[derive(Clone)]
pub struct TokenV1 {
    nonce: [u8; TOKEN_NONCE_LEN],
    expiry_unix_secs: u64,
    signature: Box<[u8; ml_dsa::SIG_LEN]>,
}

impl std::fmt::Debug for TokenV1 {
    /// The nonce is redacted. It is not a secret in the sense `ss0` is — an
    /// adversary who has it still cannot use it — but it is the value that
    /// identifies one grant, so logging it links a grant to a knock across every
    /// log line either appears in.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenV1")
            .field("nonce", &"<redacted>")
            .field("expiry_unix_secs", &self.expiry_unix_secs)
            .field("signature", &"<ML-DSA-87 sig>")
            .finish()
    }
}

impl TokenV1 {
    /// Issue a token to `grantee_pk_lt`, valid until `expiry_unix_secs`.
    ///
    /// `issuer_signing` is the issuer's LONG-TERM identity key — the same key its
    /// key record is addressed by — because the verifier is the issuer and checks
    /// against its own public half.
    pub fn mint(
        issuer_signing: &SignKeypair,
        grantee_pk_lt: &[u8; ml_dsa::PK_LEN],
        expiry_unix_secs: u64,
    ) -> Result<Self, TokenError> {
        let mut nonce = [0u8; TOKEN_NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| TokenError::EntropySource)?;
        let signature = issuer_signing
            .sign(&token_input(grantee_pk_lt, &nonce, expiry_unix_secs))
            .map_err(TokenError::Signing)?;
        Ok(Self {
            nonce,
            expiry_unix_secs,
            signature: Box::new(signature),
        })
    }

    /// Issue a token valid for [`TOKEN_VALIDITY_SECS`] from `now_unix_secs`.
    ///
    /// Saturating, so a clock far in the future cannot wrap the expiry back into
    /// the past and mint something that is born expired.
    pub fn mint_default(
        issuer_signing: &SignKeypair,
        grantee_pk_lt: &[u8; ml_dsa::PK_LEN],
        now_unix_secs: u64,
    ) -> Result<Self, TokenError> {
        Self::mint(
            issuer_signing,
            grantee_pk_lt,
            now_unix_secs.saturating_add(TOKEN_VALIDITY_SECS),
        )
    }

    /// The nonce that identifies this grant — what [`SpentTokenSet`] holds.
    pub fn nonce(&self) -> &[u8; TOKEN_NONCE_LEN] {
        &self.nonce
    }

    /// When this token stops being redeemable, in Unix seconds.
    pub fn expiry_unix_secs(&self) -> u64 {
        self.expiry_unix_secs
    }

    /// The wire form: `nonce_t(32) ‖ BE64(expiry) ‖ sig(4627)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TOKEN_LEN);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.expiry_unix_secs.to_be_bytes());
        buf.extend_from_slice(self.signature.as_ref());
        debug_assert_eq!(buf.len(), TOKEN_LEN);
        buf
    }

    /// Read the wire form. Gates the width and nothing else — see the type's note.
    pub fn decode(bytes: &[u8]) -> Result<Self, TokenError> {
        if bytes.len() != TOKEN_LEN {
            return Err(TokenError::Malformed {
                expected: TOKEN_LEN,
                actual: bytes.len(),
            });
        }
        let mut nonce = [0u8; TOKEN_NONCE_LEN];
        nonce.copy_from_slice(&bytes[..TOKEN_NONCE_LEN]);
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&bytes[TOKEN_NONCE_LEN..TOKEN_NONCE_LEN + 8]);
        let mut signature = Box::new([0u8; ml_dsa::SIG_LEN]);
        signature.copy_from_slice(&bytes[TOKEN_NONCE_LEN + 8..]);
        Ok(Self {
            nonce,
            expiry_unix_secs: u64::from_be_bytes(expiry),
            signature,
        })
    }

    /// Whether the token is still within its validity, at `now_unix_secs`.
    ///
    /// Its own function because the admission path checks it **before** the
    /// signature: an expired-token flood should cost an integer comparison, not an
    /// ML-DSA verification.
    pub fn is_current(&self, now_unix_secs: u64) -> bool {
        self.expiry_unix_secs >= now_unix_secs
    }

    /// Verify the signature under the ISSUER's own long-term key, for the grantee
    /// the knock claims to be.
    ///
    /// `grantee_pk_lt` comes from the knock's `body.pk_lt`, never from the token —
    /// so this call is what refuses a stolen token, a token minted by a third
    /// party, and a tampered expiry, all through the one check.
    ///
    /// Expiry is **not** checked here; [`Self::is_current`] is, and the admission
    /// path runs it first because it is free.
    pub fn verify(
        &self,
        issuer_pk_lt: &[u8; ml_dsa::PK_LEN],
        grantee_pk_lt: &[u8; ml_dsa::PK_LEN],
    ) -> Result<(), TokenError> {
        verify_signature(
            issuer_pk_lt,
            &token_input(grantee_pk_lt, &self.nonce, self.expiry_unix_secs),
            self.signature.as_ref(),
        )
        .map_err(|_| TokenError::Signature)
    }
}

/// The recipient-local set of consumed token nonces.
///
/// **Local state is complete enforcement here, not a weakened form of it.** Only
/// the issuer ever verifies its own tokens, so there is no second party whose view
/// could disagree — which is what makes the absence of a server irrelevant rather
/// than a gap.
///
/// Stores each nonce with the expiry of the token it came from, because pruning
/// needs to know when the nonce stops mattering and the token itself is gone by
/// then. Insertion of a nonce already present is a no-op that keeps the LATER
/// expiry, so an early revocation followed by the real consumption cannot shorten
/// the retention window.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SpentTokenSet {
    /// `nonce -> the expiry of the token it came from`.
    entries: std::collections::BTreeMap<[u8; TOKEN_NONCE_LEN], u64>,
}

impl SpentTokenSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many nonces are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether this nonce has been consumed.
    pub fn contains(&self, nonce: &[u8; TOKEN_NONCE_LEN]) -> bool {
        self.entries.contains_key(nonce)
    }

    /// Record a nonce as consumed. Returns `false` if it was already present —
    /// which is what a caller checking one-time-ness after the fact would read.
    pub fn insert(&mut self, nonce: [u8; TOKEN_NONCE_LEN], expiry_unix_secs: u64) -> bool {
        match self.entries.entry(nonce) {
            std::collections::btree_map::Entry::Occupied(mut held) => {
                // Keep the later expiry: an early revocation must never shorten
                // the window the real consumption would have set.
                if expiry_unix_secs > *held.get() {
                    held.insert(expiry_unix_secs);
                }
                false
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(expiry_unix_secs);
                true
            }
        }
    }

    /// Revoke an issued-but-unspent token: insert its nonce early.
    ///
    /// The same operation as consumption, named for what it means at the call
    /// site. There is nothing to publish and nobody to tell — the grantee learns
    /// only that the knock was not answered, which is the same thing every
    /// declined knock looks like.
    pub fn revoke(&mut self, token: &TokenV1) -> bool {
        self.insert(*token.nonce(), token.expiry_unix_secs())
    }

    /// Drop every nonce whose token expired more than [`SPENT_RETENTION_SECS`]
    /// ago. Returns how many were dropped.
    ///
    /// Saturating on the addition so an absurd expiry cannot wrap into the past
    /// and prune a live nonce — the expiry is signed by us, but a corrupt
    /// persisted set is not.
    pub fn prune(&mut self, now_unix_secs: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, expiry| expiry.saturating_add(SPENT_RETENTION_SECS) >= now_unix_secs);
        before - self.entries.len()
    }

    /// The durable form: each entry as `nonce(32) ‖ BE64(expiry)`, in nonce order.
    ///
    /// Deterministic — a `BTreeMap` iterates in key order — so two runs over the
    /// same set produce identical bytes and the sealed record's ciphertext does
    /// not change when nothing did.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.entries.len() * (TOKEN_NONCE_LEN + 8));
        for (nonce, expiry) in &self.entries {
            buf.extend_from_slice(nonce);
            buf.extend_from_slice(&expiry.to_be_bytes());
        }
        buf
    }

    /// Read the durable form. `None` on any length that is not a whole number of
    /// entries — a truncated set is refused rather than silently short.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        const STRIDE: usize = TOKEN_NONCE_LEN + 8;
        if !bytes.len().is_multiple_of(STRIDE) {
            return None;
        }
        let mut entries = std::collections::BTreeMap::new();
        for chunk in bytes.chunks_exact(STRIDE) {
            let mut nonce = [0u8; TOKEN_NONCE_LEN];
            nonce.copy_from_slice(&chunk[..TOKEN_NONCE_LEN]);
            let mut expiry = [0u8; 8];
            expiry.copy_from_slice(&chunk[TOKEN_NONCE_LEN..]);
            entries.insert(nonce, u64::from_be_bytes(expiry));
        }
        Some(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::{Identity, IdentityKeys, derive_identity_keys};
    use crate::identity::mnemonic::Mnemonic;

    const NOW: u64 = 1_700_000_000;

    fn identity() -> IdentityKeys {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap()
    }

    // ── Vector 8: the token known-answer test and its rejections ────────────

    /// **Known-answer test for the token preimage.** Same job as the
    /// proof-of-work KAT: mint and verify are self-consistent, so a uniformly
    /// wrong encoding is invisible to every other test here.
    #[test]
    fn the_token_preimage_matches_its_known_answer_vector() {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let grantee = [0x33u8; ml_dsa::PK_LEN];
        let nonce = [0x44u8; TOKEN_NONCE_LEN];
        let expiry = 0x0102_0304_0506_0708u64;
        let input = token_input(&grantee, &nonce, expiry);

        // The framing spelled out independently of `push_lp`.
        let mut expected = Vec::new();
        expected.extend_from_slice(b"daemonseed/dm/token/v1");
        expected.extend_from_slice(&(ml_dsa::PK_LEN as u64).to_be_bytes());
        expected.extend_from_slice(&grantee);
        expected.extend_from_slice(&32u64.to_be_bytes());
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&8u64.to_be_bytes());
        expected.extend_from_slice(&expiry.to_be_bytes());
        assert_eq!(input, expected, "the token preimage framing drifted");

        assert_eq!(
            hex::encode(oxicrypt_sha::sha384(&input).unwrap()),
            concat!(
                "6839091c34d0e9ce1bc1c15fd0d17442dd553881d14d6c1bf02472df",
                "435dc2be27c40219b0b7edd1bd579dff5f901930"
            )
        );
    }

    /// The wire form is exactly 4667 bytes, laid out as the design says, and the
    /// round trip is exact.
    #[test]
    fn a_token_encodes_to_its_fixed_wire_length_and_decodes_back() {
        let issuer = identity();
        let grantee = identity();
        let token = TokenV1::mint(
            &issuer.signing,
            grantee.signing.public_key(),
            NOW + TOKEN_VALIDITY_SECS,
        )
        .unwrap();

        let bytes = token.encode();
        assert_eq!(bytes.len(), TOKEN_LEN);
        assert_eq!(TOKEN_LEN, 4667, "the wire length is a frozen constant");
        assert_eq!(&bytes[..TOKEN_NONCE_LEN], &token.nonce()[..]);
        assert_eq!(
            &bytes[TOKEN_NONCE_LEN..TOKEN_NONCE_LEN + 8],
            &(NOW + TOKEN_VALIDITY_SECS).to_be_bytes()[..],
            "the expiry crosses the wire big-endian"
        );

        let back = TokenV1::decode(&bytes).unwrap();
        assert_eq!(back.nonce(), token.nonce());
        assert_eq!(back.expiry_unix_secs(), token.expiry_unix_secs());
        assert_eq!(back.encode(), bytes);
    }

    /// A minted token verifies for its grantee under its issuer.
    #[test]
    fn a_minted_token_verifies_for_its_grantee() {
        let issuer = identity();
        let grantee = identity();
        let token =
            TokenV1::mint_default(&issuer.signing, grantee.signing.public_key(), NOW).unwrap();
        assert_eq!(
            token.expiry_unix_secs(),
            NOW + TOKEN_VALIDITY_SECS,
            "the default validity is 30 days"
        );
        assert!(token.is_current(NOW));
        token
            .verify(issuer.signing.public_key(), grantee.signing.public_key())
            .unwrap();
    }

    /// **A token for X presented in a body claiming Y is refused.** This is the
    /// theft resistance: the grantee's key is not in the token, so the verifier
    /// rebuilds the preimage from whoever is actually knocking, and an intercepted
    /// token verifies for nobody but its grantee.
    #[test]
    fn a_token_does_not_verify_for_a_different_grantee() {
        let issuer = identity();
        let grantee = identity();
        let thief = identity();
        let token =
            TokenV1::mint_default(&issuer.signing, grantee.signing.public_key(), NOW).unwrap();

        // Control: valid for the grantee it names.
        token
            .verify(issuer.signing.public_key(), grantee.signing.public_key())
            .unwrap();

        assert!(
            matches!(
                token.verify(issuer.signing.public_key(), thief.signing.public_key()),
                Err(TokenError::Signature)
            ),
            "a stolen token must be inert"
        );
    }

    /// A token minted by anyone but the verifier fails closed. Issuer binding
    /// costs no field precisely because the verifier checks against its own key.
    #[test]
    fn a_token_minted_by_someone_else_does_not_verify() {
        let us = identity();
        let stranger = identity();
        let grantee = identity();
        let token =
            TokenV1::mint_default(&stranger.signing, grantee.signing.public_key(), NOW).unwrap();

        // Control: it is a real token, valid at its own issuer.
        token
            .verify(stranger.signing.public_key(), grantee.signing.public_key())
            .unwrap();

        assert!(matches!(
            token.verify(us.signing.public_key(), grantee.signing.public_key()),
            Err(TokenError::Signature)
        ));
    }

    /// The expiry is inside the signed preimage, so a grantee cannot extend it:
    /// editing the wire bytes breaks the signature rather than buying more time.
    #[test]
    fn a_tampered_expiry_breaks_the_signature() {
        let issuer = identity();
        let grantee = identity();
        let token = TokenV1::mint(&issuer.signing, grantee.signing.public_key(), NOW + 10).unwrap();
        let mut bytes = token.encode();

        // Control: unedited, it verifies.
        TokenV1::decode(&bytes)
            .unwrap()
            .verify(issuer.signing.public_key(), grantee.signing.public_key())
            .unwrap();

        // Push the expiry a year out.
        bytes[TOKEN_NONCE_LEN..TOKEN_NONCE_LEN + 8]
            .copy_from_slice(&(NOW + 31_536_000).to_be_bytes());
        let tampered = TokenV1::decode(&bytes).unwrap();
        assert_eq!(
            tampered.expiry_unix_secs(),
            NOW + 31_536_000,
            "the edit really did change the value being checked"
        );
        assert!(matches!(
            tampered.verify(issuer.signing.public_key(), grantee.signing.public_key()),
            Err(TokenError::Signature)
        ));
    }

    /// An expired token is refused, and the check costs an integer comparison —
    /// it is separate from the signature so an expired-token flood is cheap.
    #[test]
    fn an_expired_token_is_not_current() {
        let issuer = identity();
        let grantee = identity();
        let token = TokenV1::mint(&issuer.signing, grantee.signing.public_key(), NOW).unwrap();
        assert!(token.is_current(NOW), "expiry is inclusive at the boundary");
        assert!(token.is_current(NOW - 1));
        assert!(!token.is_current(NOW + 1));
        // Still signature-valid — expiry and authenticity are separate questions.
        token
            .verify(issuer.signing.public_key(), grantee.signing.public_key())
            .unwrap();
    }

    /// The width gate: absent, short and long are each refused before anything is
    /// verified.
    #[test]
    fn a_token_of_the_wrong_width_is_refused_at_decode() {
        let issuer = identity();
        let grantee = identity();
        let good = TokenV1::mint_default(&issuer.signing, grantee.signing.public_key(), NOW)
            .unwrap()
            .encode();
        // Control: the correct width decodes, so the refusals below are the width
        // and not something else about these bytes.
        assert!(TokenV1::decode(&good).is_ok());
        for bad in [
            Vec::new(),
            good[..TOKEN_LEN - 1].to_vec(),
            [good.clone(), vec![0]].concat(),
        ] {
            let len = bad.len();
            assert!(
                matches!(
                    TokenV1::decode(&bad),
                    Err(TokenError::Malformed { expected, actual })
                        if expected == TOKEN_LEN && actual == len
                ),
                "{len} bytes must not decode"
            );
        }
    }

    /// The nonce never reaches a log through `Debug`. It is the value that links
    /// one grant to one knock.
    #[test]
    fn a_token_never_debug_prints_its_nonce() {
        let issuer = identity();
        let grantee = identity();
        let token =
            TokenV1::mint_default(&issuer.signing, grantee.signing.public_key(), NOW).unwrap();
        let rendered = format!("{token:?}");
        assert!(!rendered.contains(&hex::encode(token.nonce())));
        assert!(rendered.contains("<redacted>"));
        // Control: the expiry, which is not sensitive, IS shown — so the test is
        // reading a real rendering and not an empty one.
        assert!(rendered.contains(&token.expiry_unix_secs().to_string()));
    }

    // ── Vector 9: one-time-ness and the spent set ───────────────────────────

    /// Insert, contain, and the second insert answering `false`.
    #[test]
    fn a_spent_nonce_is_remembered_and_re_insertion_reports_it() {
        let mut set = SpentTokenSet::new();
        assert!(set.is_empty());
        let nonce = [7u8; TOKEN_NONCE_LEN];
        assert!(!set.contains(&nonce));
        assert!(set.insert(nonce, NOW), "the first insert is new");
        assert!(set.contains(&nonce));
        assert!(!set.insert(nonce, NOW), "the second insert is not");
        assert_eq!(set.len(), 1, "a re-insert must not duplicate");
    }

    /// Revoking an issued-but-unspent token is inserting its nonce early, and the
    /// grantee's later knock then finds it spent.
    #[test]
    fn revocation_is_an_early_insert() {
        let issuer = identity();
        let grantee = identity();
        let token =
            TokenV1::mint_default(&issuer.signing, grantee.signing.public_key(), NOW).unwrap();
        let mut set = SpentTokenSet::new();
        assert!(!set.contains(token.nonce()));
        assert!(set.revoke(&token));
        assert!(set.contains(token.nonce()));
    }

    /// **Retention is `expiry + 2 · FC_PERIOD_SECS`, and the two epochs are
    /// load-bearing.** A nonce pruned at its expiry could be replayed by an entry
    /// that is still inside the accept window, so the boundary is asserted on both
    /// sides rather than only on the drop.
    #[test]
    fn a_spent_nonce_is_pruned_only_after_two_epochs_past_expiry() {
        let mut set = SpentTokenSet::new();
        let nonce = [9u8; TOKEN_NONCE_LEN];
        let expiry = NOW;
        set.insert(nonce, expiry);

        assert_eq!(set.prune(expiry), 0, "not at the expiry itself");
        assert_eq!(
            set.prune(expiry + SPENT_RETENTION_SECS),
            0,
            "not at exactly two epochs past — the last instant it can still matter"
        );
        assert!(set.contains(&nonce), "still held right up to the boundary");
        assert_eq!(
            set.prune(expiry + SPENT_RETENTION_SECS + 1),
            1,
            "dropped one second later"
        );
        assert!(!set.contains(&nonce));
        assert_eq!(SPENT_RETENTION_SECS, 2 * 604_800);
    }

    /// A prune drops only what is past the boundary, never the whole set.
    #[test]
    fn a_prune_keeps_what_is_still_live() {
        let mut set = SpentTokenSet::new();
        set.insert([1u8; TOKEN_NONCE_LEN], NOW - SPENT_RETENTION_SECS - 100);
        set.insert([2u8; TOKEN_NONCE_LEN], NOW);
        set.insert([3u8; TOKEN_NONCE_LEN], NOW + 1000);
        assert_eq!(set.len(), 3);
        assert_eq!(set.prune(NOW), 1);
        assert_eq!(set.len(), 2);
        assert!(!set.contains(&[1u8; TOKEN_NONCE_LEN]));
        assert!(set.contains(&[2u8; TOKEN_NONCE_LEN]));
        assert!(set.contains(&[3u8; TOKEN_NONCE_LEN]));
    }

    /// An early revocation followed by a real consumption keeps the LATER expiry,
    /// so the retention window cannot be shortened by the revocation.
    #[test]
    fn re_inserting_a_nonce_keeps_the_later_expiry() {
        let mut set = SpentTokenSet::new();
        let nonce = [5u8; TOKEN_NONCE_LEN];
        set.insert(nonce, NOW);
        set.insert(nonce, NOW + 10_000);
        assert_eq!(set.prune(NOW + SPENT_RETENTION_SECS + 1), 0);
        assert!(set.contains(&nonce));
        assert_eq!(set.prune(NOW + 10_000 + SPENT_RETENTION_SECS + 1), 1);
    }

    /// **The set survives a restart.** Its durable form round-trips exactly,
    /// including the expiries the prune depends on — a set that came back without
    /// them would prune everything or nothing.
    #[test]
    fn the_spent_set_survives_a_round_trip_through_its_durable_form() {
        let mut set = SpentTokenSet::new();
        for i in 0..8u8 {
            set.insert([i; TOKEN_NONCE_LEN], NOW + u64::from(i) * 1000);
        }
        let bytes = set.encode();
        assert_eq!(bytes.len(), 8 * (TOKEN_NONCE_LEN + 8));

        let back = SpentTokenSet::decode(&bytes).unwrap();
        assert_eq!(back, set);
        for i in 0..8u8 {
            assert!(back.contains(&[i; TOKEN_NONCE_LEN]));
        }
        // The expiries came back too, which the prune boundary proves.
        let mut back = back;
        assert_eq!(back.prune(NOW + SPENT_RETENTION_SECS + 1), 1);

        // Deterministic: encoding an unchanged set twice gives identical bytes.
        assert_eq!(set.encode(), bytes);
        assert_eq!(SpentTokenSet::decode(&[]).unwrap(), SpentTokenSet::new());
    }

    /// **Known-answer test for the durable form's byte layout.**
    ///
    /// The round-trip test above is symmetric: swap `nonce ‖ BE64(expiry)` for
    /// `BE64(expiry) ‖ nonce` in both [`SpentTokenSet::encode`] and
    /// [`SpentTokenSet::decode`] and every other test in this module stays green,
    /// while every previously written file becomes unreadable — silently, as a set
    /// of nonces that are not the ones we spent. This is the restart evidence for
    /// one-time-ness, so its layout is the thing that most needs pinning.
    #[test]
    fn the_durable_form_matches_its_known_answer_vector() {
        let mut set = SpentTokenSet::new();
        set.insert([0x01; TOKEN_NONCE_LEN], 0x0203_0405_0607_0809);
        set.insert([0x02; TOKEN_NONCE_LEN], 0x1112_1314_1516_1718);
        let bytes = set.encode();

        let mut expected = Vec::new();
        // Nonce FIRST, then the expiry big-endian; entries in ascending nonce
        // order, which is what makes the encoding deterministic.
        expected.extend_from_slice(&[0x01; TOKEN_NONCE_LEN]);
        expected.extend_from_slice(&0x0203_0405_0607_0809u64.to_be_bytes());
        expected.extend_from_slice(&[0x02; TOKEN_NONCE_LEN]);
        expected.extend_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes());
        assert_eq!(bytes, expected, "the durable layout drifted");
        assert_eq!(hex::encode(&bytes[..TOKEN_NONCE_LEN]), "01".repeat(32));
        assert_eq!(
            hex::encode(&bytes[TOKEN_NONCE_LEN..TOKEN_NONCE_LEN + 8]),
            "0203040506070809",
            "the expiry follows the nonce, big-endian"
        );
    }

    /// **The prune's `saturating_add` is load-bearing.** The expiries come off
    /// disk, so a corrupt or hostile set can hold `u64::MAX`; a wrapping add would
    /// send the retention boundary back to near zero and prune a nonce that is
    /// still very much live — silently un-spending a consumed grant.
    #[test]
    fn a_prune_cannot_be_wrapped_into_dropping_a_live_nonce() {
        let mut set = SpentTokenSet::new();
        let nonce = [0xee; TOKEN_NONCE_LEN];
        set.insert(nonce, u64::MAX);
        assert_eq!(
            set.prune(u64::MAX),
            0,
            "an expiry at u64::MAX must never be prunable"
        );
        assert!(set.contains(&nonce));
        // Control: an ordinary expiry past the boundary IS pruned by the same
        // call, so the retention above is the saturation and not a dead prune.
        set.insert([0x01; TOKEN_NONCE_LEN], 0);
        assert_eq!(set.prune(u64::MAX), 1);
        assert!(set.contains(&nonce));
    }

    /// **`mint_default`'s `saturating_add` is load-bearing.** A clock near
    /// `u64::MAX` would otherwise wrap the expiry into the past and mint a token
    /// that is born expired — refused by [`TokenV1::is_current`] at the instant it
    /// was issued, with nothing to say why.
    #[test]
    fn a_default_mint_near_the_end_of_time_is_not_born_expired() {
        let issuer = identity();
        let grantee = identity();
        let token =
            TokenV1::mint_default(&issuer.signing, grantee.signing.public_key(), u64::MAX).unwrap();
        assert_eq!(token.expiry_unix_secs(), u64::MAX);
        assert!(
            token.is_current(u64::MAX),
            "a token minted at u64::MAX must be current at u64::MAX"
        );
        // Control: an ordinary mint still gets the full 30 days.
        let ordinary =
            TokenV1::mint_default(&issuer.signing, grantee.signing.public_key(), NOW).unwrap();
        assert_eq!(ordinary.expiry_unix_secs(), NOW + TOKEN_VALIDITY_SECS);
    }

    /// A truncated durable form is refused rather than silently read short. A
    /// short read would drop the last nonce, which is precisely the one a
    /// crash-during-write would have been recording.
    #[test]
    fn a_truncated_durable_form_is_refused() {
        let mut set = SpentTokenSet::new();
        set.insert([1u8; TOKEN_NONCE_LEN], NOW);
        let bytes = set.encode();
        // Control.
        assert!(SpentTokenSet::decode(&bytes).is_some());
        assert!(SpentTokenSet::decode(&bytes[..bytes.len() - 1]).is_none());
        assert!(SpentTokenSet::decode(&bytes[..1]).is_none());
    }
}
