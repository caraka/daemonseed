//! **Admission** — the ordered verification of one doorbell slot.
//!
//! Design of record: the admission specification's D10, which fixes the order and
//! the reason for it. This module is that order, made executable.
//!
//! ## The problem it solves is the verifier's own CPU
//!
//! The doorbell is world-writable, so *invalid* entries are free to write. A
//! recipient sweeping 32 slots runs whatever check comes first on attacker-chosen
//! garbage, every sweep, forever. So the ordering is not tidiness: each step is
//! strictly cheaper than the one it guards, and the two expensive tiers —
//! ML-KEM decapsulation with the AEAD open, and the ML-DSA verifications — are
//! reachable only behind a paid proof of work.
//!
//! Per slot, cheapest first:
//!
//! | # | Step | Cost |
//! |---|---|---|
//! | 0 | unchanged-slot skip | ~0 |
//! | 1 | shape gates — decode, `ct0` 1568, `pow` 8, `sealed` within a legal envelope | ~µs |
//! | 2 | entry hash `H`, and the per-epoch seen-set | one hash over ≤27.3 KB (~60 µs) |
//! | 3 | proof of work, current epoch then previous | ≤2 short hashes |
//! | 4 | decapsulate `ct0` | ~100 µs |
//! | 5 | AEAD open, **at the proof-validated epoch only** | ~50 µs |
//! | 6 | cheap body gates — recipient hash, `seq`, selector, body cap | ~0 |
//! | 7 | idempotent re-accept | ~0 |
//! | 8 | token field gates — width, expiry, spent | ~0 |
//! | 9 | signatures, token first under invite-only | ~1 ms each |
//! | 10 | admit, consuming the token nonce | — |
//!
//! **Step 3's detail is the one that is easy to get backwards.** An entry enters
//! the seen-set only *after* its proof of work passes. That way a flood of
//! proof-less garbage can never occupy seen-set memory, and a proof-valid entry
//! that turns out to be malformed still enters it, so it is never reprocessed. The
//! set's memory is therefore bounded by what the attacker paid for, not by what
//! they wrote.
//!
//! **Step 9's ordering is worth a sentence too.** Under invite-only the token's
//! signature is checked before `bind_lt` and `msg_sig`, so a flood of entries
//! carrying invalid tokens costs one ML-DSA verification rather than three.
//!
//! ## What is deliberately not here
//!
//! The sweep itself — cadence, which records are read, how step 0's per-slot
//! byte comparison is stored — is the transport slice's. This module takes bytes
//! and answers a verdict.

use oxicrypt_ml_dsa as ml_dsa;
use oxicrypt_ml_kem as ml_kem;
use prost::Message;

use daemonseed_proto::v1 as wire;

use crate::circle::message::{NONCE_LEN, TAG_LEN};

use super::firstcontact::{
    self, BodyGateView, FirstContactError, MAX_ENTRY_LEN, VerifiedFirstContact,
};
use super::keyrec::DM_KEYREC_OWNER_SEED_LEN;
use super::pow::{self, ENTRY_HASH_LEN, PowDifficulty};
use super::token::{SpentTokenSet, TOKEN_LEN, TokenV1};

/// How many entry hashes are retained per live first-contact epoch.
///
/// Two epochs are live at once, and an entry only reaches the set having paid a
/// proof of work — so filling one epoch's set costs an attacker 1024 mints, and
/// the whole structure is under 100 KB at 48 bytes an entry. Tunable without
/// design impact: it trades memory against how much re-verification a very busy
/// doorbell does.
pub const SEEN_SET_CAPACITY: usize = 1024;

/// The recipient's live first-contact policy.
///
/// **Live, never the advert.** The key record's `invite_only` field is what a
/// sender reads to know what to compose; this is what the recipient enforces. They
/// can disagree — a record is world-writable and rollback-able, and a policy can
/// change after a sender has cached the record — and when they do, the recipient
/// wins and the sender's knock ages to undelivered. That is the frozen design's
/// accepted policy-change semantics: the recipient never sends a rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionPolicy {
    /// Anyone may knock. **The token field is ignored entirely** — never decoded,
    /// never verified, never consumed. Consuming a nonce that gated nothing would
    /// silently burn a grant the recipient had not asked to spend.
    Open,
    /// Only a valid, unexpired, unspent, grantee-bound invite token admits.
    InviteOnly,
}

/// Why an entry was dropped. Every one of these is a **silent** drop on the wire —
/// nothing is sent back — and the variant exists for the recipient's own logs,
/// metrics and tests, never for an answer to the sender.
///
/// The order of the variants is the order of the pipeline, which is what makes a
/// test asserting "it stopped here" also an assertion about what was *not* reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropReason {
    /// Step 0: the slot holds the same bytes as the last sweep.
    Unchanged,
    /// Step 1: not a decodable entry, or a length-gated field was the wrong size.
    Shape,
    /// Step 2: this exact entry was already processed this epoch.
    Seen,
    /// Step 3: no valid proof of work at either live epoch.
    Pow,
    /// Steps 4–6: the seal did not open at the proof-validated epoch, or the body
    /// failed a cheap gate. Uniform, deliberately — a wrong key, a wrong AAD, a
    /// foreign recipient hash and tampered bytes must not be distinguishable.
    Seal,
    /// Step 8: invite-only, and the token was absent, the wrong width, expired, or
    /// already spent.
    Token,
    /// Step 9: a signature did not verify — the token's, `bind_lt`, or `msg_sig`.
    Signature,
    /// The crypto module was not operational. Not an attacker's doing, and the
    /// only variant that says something about this machine rather than the entry.
    Module,
}

/// What one slot's verification produced.
pub enum AdmissionOutcome {
    /// Fully verified. `token_nonce` is the grant to consume, present only when
    /// the policy was invite-only and this was not an idempotent re-accept.
    Admitted {
        /// The verified knock.
        verified: Box<VerifiedFirstContact>,
        /// The nonce [`Admitter::admit`] has already recorded as spent.
        token_nonce: Option<[u8; super::token::TOKEN_NONCE_LEN]>,
        /// Whether this was an idempotent re-accept of a knock already admitted —
        /// a re-sealed retry, or the same knock in the next epoch. The caller must
        /// not re-init a ratchet or surface a second contact request for one.
        idempotent: bool,
        /// `SHA-384(ct0 ‖ sealed)` over the entry these bytes were, as step 2
        /// computed it.
        ///
        /// **Carried out because it cannot be recomputed from the outside.**
        /// [`pow::entry_hash`] takes the two halves already split, and the split
        /// is this module's own shape gate's, which is private precisely so no caller can
        /// perform it with an unpinned `ct0` width — the ambiguity that would
        /// let one nonce prove two entries. A recipient naming a request by the
        /// exact entry it was shown therefore has to be handed the value rather
        /// than derive it.
        entry_hash: [u8; ENTRY_HASH_LEN],
    },
    /// Silently dropped, at the named step.
    Dropped(DropReason),
}

impl AdmissionOutcome {
    /// The step this entry was dropped at, or `None` if it was admitted.
    ///
    /// Present so a caller — a metrics sink, a trust-event classifier, a test —
    /// can ask the question without destructuring the admitted arm it does not
    /// care about.
    pub fn drop_reason(&self) -> Option<DropReason> {
        match self {
            Self::Dropped(reason) => Some(*reason),
            Self::Admitted { .. } => None,
        }
    }
}

impl std::fmt::Debug for AdmissionOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admitted {
                token_nonce,
                idempotent,
                ..
            } => f
                .debug_struct("Admitted")
                .field("verified", &"<VerifiedFirstContact>")
                .field("token_nonce", &token_nonce.map(|_| "<redacted>"))
                .field("idempotent", idempotent)
                .field("entry_hash", &"<redacted>")
                .finish(),
            Self::Dropped(reason) => f.debug_tuple("Dropped").field(reason).finish(),
        }
    }
}

/// How much work a sweep actually did.
///
/// **Unconditional, not test-only.** These are the numbers the whole ordering
/// exists to hold down, and a claim that the expensive tiers sit behind a paid
/// proof of work is only checkable if something counts them. A test asserting
/// `decap_attempts == 0` after a bad-proof entry is proving that the
/// decapsulation was not reached — which no assertion about the *outcome* can
/// prove on its own, since a wrong key produces the same `Dropped(Seal)` whether
/// or not the proof was checked first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdmissionCounters {
    /// Slots whose bytes matched the previous sweep.
    pub unchanged: u64,
    /// Entries that failed a shape gate.
    pub shape_rejects: u64,
    /// Entries already in the seen-set.
    pub seen_skips: u64,
    /// Entry hashes computed — one per entry that got past the shape gates.
    pub entry_hashes: u64,
    /// Entries that failed the proof of work at both live epochs.
    pub pow_rejects: u64,
    /// ML-KEM decapsulations performed. The expensive tier the proof of work
    /// guards.
    pub decap_attempts: u64,
    /// ML-DSA verifications performed, across the token, `bind_lt` and `msg_sig`.
    pub sig_verifies: u64,
    /// Entries admitted.
    pub admitted: u64,
}

/// The recipient's side of admission: keys, policy, and the state that persists
/// between sweeps.
///
/// Borrows the mutable state rather than owning it, so the caller decides where
/// the spent-token set lives and when it is written back — this module has no
/// opinion about the store.
pub struct Admitter<'a> {
    /// The recipient's own decapsulation key.
    pub recipient_dk: &'a [u8; ml_kem::DK_LEN],
    /// The recipient's own long-term public key. Also what an invite token's
    /// signature is checked against, since the verifier is the issuer.
    pub recipient_pk_lt: &'a [u8; ml_dsa::PK_LEN],
    /// The recipient's key-record owner seed — what the proof of work binds.
    pub recipient_keyrec_addr: &'a [u8; DM_KEYREC_OWNER_SEED_LEN],
    /// The clock-derived current first-contact epoch.
    pub current_fc_epoch: u64,
    /// Unix seconds, for the token expiry check.
    pub now_unix_secs: u64,
    /// The live policy — see [`AdmissionPolicy`].
    pub policy: AdmissionPolicy,
    /// The difficulty to verify at. Production has only
    /// [`PowDifficulty::PRODUCTION`] to name.
    pub difficulty: PowDifficulty,
    /// Entries already processed at each live epoch.
    pub seen: &'a mut SeenSet,
    /// Consumed token nonces.
    pub spent: &'a mut SpentTokenSet,
    /// Work done, accumulated across every call.
    pub counters: AdmissionCounters,
}

impl<'a> Admitter<'a> {
    /// Verify one doorbell slot, in the order the module documents.
    ///
    /// `previous_bytes` is what this slot held at the last sweep, for step 0; pass
    /// `None` on the first sweep or where the caller keeps no such record.
    ///
    /// `already_known` answers "do I already have an established or provisional
    /// channel, or a pending request, with this identity?" — step 7. It is a
    /// closure because the answer lives in the contact cache and the channel
    /// store, neither of which this module should reach into. It is consulted with
    /// the **claimed** `pk_lt`, before `bind_lt` has been verified, which is safe
    /// because a false claim can only cost the attacker their own admission: the
    /// signatures still have to verify afterwards.
    pub fn admit<K>(
        &mut self,
        entry_bytes: &[u8],
        previous_bytes: Option<&[u8]>,
        already_known: K,
    ) -> AdmissionOutcome
    where
        K: Fn(&[u8; ml_dsa::PK_LEN]) -> bool,
    {
        // ── 0. Unchanged slot ───────────────────────────────────────────────
        if previous_bytes == Some(entry_bytes) {
            self.counters.unchanged += 1;
            return AdmissionOutcome::Dropped(DropReason::Unchanged);
        }

        // ── 1. Shape gates ──────────────────────────────────────────────────
        let Some(shape) = decode_shape(entry_bytes) else {
            self.counters.shape_rejects += 1;
            return AdmissionOutcome::Dropped(DropReason::Shape);
        };

        // ── 2. Entry hash ───────────────────────────────────────────────────
        let Ok(h) = pow::entry_hash(&shape.ct0, &shape.sealed) else {
            return AdmissionOutcome::Dropped(DropReason::Module);
        };
        self.counters.entry_hashes += 1;
        if self.seen.contains(&h) {
            self.counters.seen_skips += 1;
            return AdmissionOutcome::Dropped(DropReason::Seen);
        }

        // ── 3. Proof of work, and only then the seen-set insert ─────────────
        let pow_epochs = pow::verify(
            self.recipient_keyrec_addr,
            self.current_fc_epoch,
            &h,
            &shape.pow,
            self.difficulty,
        );
        let Some(first_epoch) = pow_epochs.first() else {
            self.counters.pow_rejects += 1;
            // Deliberately NOT inserted into the seen-set: an entry that never
            // paid must never occupy the memory the set costs.
            return AdmissionOutcome::Dropped(DropReason::Pow);
        };
        // Paid, so it is recorded now — whatever happens below. A proof-valid but
        // malformed entry is never reprocessed on the next sweep.
        self.seen.insert(first_epoch, h);

        // ── 4-9. Decapsulate, open at the proved epoch, gate, verify ────────
        //
        // `open_at_epochs` runs 4, 5, 6, then the gate below (7 and 8, plus the
        // token signature of 9), then `bind_lt` and `msg_sig`. Splitting it any
        // other way would put one of those checks on the wrong side of an
        // expensive one.
        self.counters.decap_attempts += 1;

        let mut idempotent = false;
        // The nonce AND the expiry it came from: the prune needs both, and the
        // only place the expiry is known is inside the gate, where the token was
        // decoded. Re-decoding it afterwards would need a fallback for a case
        // that cannot happen, and a fallback for an impossible case is a wrong
        // value waiting for the case to become possible.
        let mut consumed: Option<([u8; super::token::TOKEN_NONCE_LEN], u64)> = None;
        let mut token_verifies = 0u64;
        // Set by the gate when the refusal was the token's. The wire answer stays
        // uniform — every drop is the same silence — but the RECIPIENT is entitled
        // to know why its own machinery refused, for its logs and its tests, and
        // it learns nothing here an attacker could not already infer from having
        // sent the token.
        let mut token_refused = false;

        let mut open_sig_attempts = 0u64;

        let outcome = firstcontact::open_at_epochs(
            entry_bytes,
            self.recipient_dk,
            self.recipient_pk_lt,
            pow_epochs.as_slice(),
            &mut open_sig_attempts,
            |view: &BodyGateView<'_>| {
                // ── 7. Idempotent re-accept ─────────────────────────────────
                //
                // Before token gating, so a re-sealed retry of an
                // already-admitted knock is never rejected as token-spent — its
                // nonce is in the set precisely because we admitted it.
                if already_known(view.pk_lt) {
                    idempotent = true;
                    return Ok(());
                }

                // ── 8-9a. Token gates, then the token signature ─────────────
                match self.policy {
                    // Under an open policy the field is not looked at at all.
                    AdmissionPolicy::Open => Ok(()),
                    AdmissionPolicy::InviteOnly => {
                        if view.token.len() != TOKEN_LEN {
                            token_refused = true;
                            return Err(token_refusal());
                        }
                        let Ok(token) = TokenV1::decode(view.token) else {
                            token_refused = true;
                            return Err(token_refusal());
                        };
                        if !token.is_current(self.now_unix_secs) {
                            token_refused = true;
                            return Err(token_refusal());
                        }
                        if self.spent.contains(token.nonce()) {
                            token_refused = true;
                            return Err(token_refusal());
                        }
                        // The one expensive check in this gate, and it runs
                        // before `bind_lt` and `msg_sig` so an invalid-token
                        // flood costs one verification rather than three.
                        token_verifies += 1;
                        token
                            .verify(self.recipient_pk_lt, view.pk_lt)
                            .map_err(|_| FirstContactError::Signature)?;
                        consumed = Some((*token.nonce(), token.expiry_unix_secs()));
                        Ok(())
                    }
                }
            },
        );

        // Attempts, not successes. `open_at_epochs` reports what it actually ran,
        // so a knock refused BY `bind_lt` still shows that verification as spent —
        // which is what lets a test distinguish "the gate ran first" from "the
        // signatures ran first and then the gate refused". Counting only the
        // success path makes every failure read zero and every ordering assertion
        // vacuous.
        self.counters.sig_verifies += token_verifies + open_sig_attempts;

        let verified = match outcome {
            Ok(v) => v,
            Err(e) => {
                return AdmissionOutcome::Dropped(if token_refused {
                    DropReason::Token
                } else {
                    classify(e)
                });
            }
        };

        // ── 10. Admit, consuming the nonce ──────────────────────────────────
        //
        // Strictly after every verification, which is what stops a forged entry
        // naming a real token from burning it.
        if let Some((nonce, expiry)) = consumed {
            self.spent.insert(nonce, expiry);
        }
        self.counters.admitted += 1;
        AdmissionOutcome::Admitted {
            verified: Box::new(verified),
            token_nonce: consumed.map(|(nonce, _)| nonce),
            idempotent,
            entry_hash: h,
        }
    }
}

/// The uniform token refusal. Every reason a token fails the free gates — absent,
/// wrong width, expired, spent — produces the same value, because from the
/// sender's side they are the same silent drop and a verifier that distinguished
/// them would be an oracle for which nonces have been spent.
fn token_refusal() -> FirstContactError {
    FirstContactError::Malformed
}

/// Map an open failure onto the step it belongs to.
fn classify(e: FirstContactError) -> DropReason {
    match e {
        FirstContactError::Signature => DropReason::Signature,
        FirstContactError::Kdf(_) | FirstContactError::Module(_) => DropReason::Module,
        // Everything else — a failed AEAD, a foreign recipient hash, a bad
        // sequence, an unknown selector, an over-long body, a malformed body, and
        // the gate's own uniform token refusal — is one indistinguishable drop.
        _ => DropReason::Seal,
    }
}

/// The shape gates of step 1: is this even the right shape to be an entry?
///
/// Returns the decoded message so the caller can borrow its fields; every refusal
/// here costs a decode and three length comparisons — no hash, no decapsulation,
/// no signature. The caller re-passes the original bytes to
/// [`firstcontact::open_at_epoch`], which decodes a second time; that is
/// microseconds against the ~150 µs of the tier it guards, and it is what keeps
/// `open` a self-contained function rather than one that trusts a caller's decode.
///
/// The `sealed` widths are derived from [`firstcontact::PAD_BUCKETS`] rather than
/// written out, so the gate cannot drift from the ladder the composer pads to.
fn decode_shape(entry_bytes: &[u8]) -> Option<wire::FirstContactEntry> {
    // A slot larger than the subkey cap could not have been written through the
    // network's own write guard, so it is refused before prost is asked to walk it.
    if entry_bytes.len() > MAX_ENTRY_LEN {
        return None;
    }
    let entry = wire::FirstContactEntry::decode(entry_bytes).ok()?;
    if entry.ct0.len() != firstcontact::CT0_LEN {
        return None;
    }
    if entry.pow.len() != pow::FC_POW_LEN {
        return None;
    }
    if !is_legal_sealed_len(entry.sealed.len()) {
        return None;
    }
    Some(entry)
}

/// Whether a `sealed` field is one of the legal padded envelopes: a padding bucket
/// plus the AEAD's own nonce and tag.
///
/// An entry sealing anything other than a full bucket is refused here rather than
/// at the AEAD, which saves a decapsulation on the whole class — and there are only
/// two legal widths, so the check is two comparisons.
fn is_legal_sealed_len(len: usize) -> bool {
    firstcontact::PAD_BUCKETS
        .iter()
        .any(|&bucket| len == NONCE_LEN + bucket + TAG_LEN)
}

/// Entry hashes already processed, held per live first-contact epoch.
///
/// **Per epoch, and only two epochs are live.** A proof of work binds an epoch, so
/// an entry can only be presented at the two epochs its proof covers; keying the
/// set that way means the whole structure retires itself as the clock advances,
/// with no separate expiry pass and no unbounded growth.
///
/// Bounded and insertion-ordered: at [`SEEN_SET_CAPACITY`] the oldest entry for
/// that epoch is evicted. Eviction costs the attacker a re-verification of one
/// entry, and costs them 1024 mints per epoch to provoke at all.
#[derive(Debug, Default)]
pub struct SeenSet {
    /// `(epoch, insertion order)` per hash, so eviction is by age within an epoch.
    epochs: std::collections::BTreeMap<u64, EpochSeen>,
}

#[derive(Debug, Default)]
struct EpochSeen {
    order: std::collections::VecDeque<[u8; ENTRY_HASH_LEN]>,
    members: std::collections::HashSet<[u8; ENTRY_HASH_LEN]>,
}

impl SeenSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this entry hash has been processed at any live epoch.
    ///
    /// Across epochs rather than within one: the same entry is legitimately
    /// presentable at both of the epochs its proof covers, and processing it twice
    /// would surface the same contact request twice.
    pub fn contains(&self, hash: &[u8; ENTRY_HASH_LEN]) -> bool {
        self.epochs.values().any(|e| e.members.contains(hash))
    }

    /// Record an entry hash at `epoch`, evicting that epoch's oldest if it is
    /// full. Returns `false` if it was already held.
    pub fn insert(&mut self, epoch: u64, hash: [u8; ENTRY_HASH_LEN]) -> bool {
        if self.contains(&hash) {
            return false;
        }
        let slot = self.epochs.entry(epoch).or_default();
        if slot.order.len() >= SEEN_SET_CAPACITY
            && let Some(oldest) = slot.order.pop_front()
        {
            slot.members.remove(&oldest);
        }
        slot.order.push_back(hash);
        slot.members.insert(hash);
        true
    }

    /// Forget one entry hash, at every epoch that holds it.
    ///
    /// **For a caller that ABANDONED an entry's verification, not for one that
    /// finished it.** The set's contract is "this entry has been processed", and
    /// `admit` records a hash the moment its proof of work passes — before the
    /// decapsulation, the body gates and the caller's own `already_known`
    /// closure have run. A caller whose closure could not answer, and which
    /// therefore declines to act on the entry at all, has not processed it:
    /// leaving the hash in would make the entry a `Seen` drop on every later
    /// sweep, permanently, for a knock nobody ever decided about.
    ///
    /// Returns whether anything was removed. **The eviction order is not
    /// repaired** — the hash stays in its epoch's order queue until it ages out
    /// — because that queue only bounds memory, and one stale entry in it
    /// costs one slot of a thousand rather than a wrong answer.
    ///
    /// It is not a general undo. Forgetting a hash the caller *did* act on
    /// re-opens the double-surface this set exists to prevent, so the call site
    /// has to be one that took no decision.
    pub fn forget(&mut self, hash: &[u8; ENTRY_HASH_LEN]) -> bool {
        let mut removed = false;
        for epoch in self.epochs.values_mut() {
            removed |= epoch.members.remove(hash);
        }
        removed
    }

    /// Drop every epoch outside the accept window for `current_fc_epoch` — that
    /// is, everything before `current - 1`. Returns how many epochs were dropped.
    ///
    /// Cheap and idempotent; a caller runs it once a sweep. Without it the set
    /// would retain hashes for epochs no proof can any longer name.
    pub fn retire(&mut self, current_fc_epoch: u64) -> usize {
        let floor = current_fc_epoch.saturating_sub(1);
        let before = self.epochs.len();
        self.epochs.retain(|&epoch, _| epoch >= floor);
        before - self.epochs.len()
    }

    /// How many hashes are held, across every live epoch.
    pub fn len(&self) -> usize {
        self.epochs.values().map(|e| e.members.len()).sum()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::firstcontact::{FirstContactRequest, build};
    use crate::dm::keyrec;
    use crate::identity::keys::{Identity, IdentityKeys, derive_identity_keys};
    use crate::identity::mnemonic::Mnemonic;

    const EPOCH: u64 = 2_900_000;
    const SENT: i64 = 1_700_000_000_000;
    const NOW: u64 = 1_700_000_000;

    /// Four bits — sixteen expected hashes. Production is ~4.19 M, which is
    /// seconds; `crate::dm::pow` carries the `#[ignore]`d test that mints at it.
    fn bits() -> PowDifficulty {
        PowDifficulty::reduced_for_test(4)
    }

    fn identity() -> IdentityKeys {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        derive_identity_keys(&Mnemonic::generate().unwrap(), Identity::Primary).unwrap()
    }

    /// One composed knock plus everything the recipient needs to judge it.
    struct Scenario {
        sender: IdentityKeys,
        recipient: IdentityKeys,
        entry: Vec<u8>,
    }

    fn compose(
        sender: &IdentityKeys,
        recipient: &IdentityKeys,
        epoch: u64,
        token: Option<&TokenV1>,
        body: &str,
    ) -> Vec<u8> {
        let pc = identity();
        build(FirstContactRequest {
            signing_lt: &sender.signing,
            signing_pc: &pc.signing,
            recipient_pk_lt: recipient.signing.public_key(),
            kem_ek_b: recipient.kem.encapsulation_key(),
            fc_epoch: epoch,
            sent_unix_ms: SENT,
            body,
            token,
            difficulty: bits(),
        })
        .unwrap()
        .0
    }

    fn scenario(token: Option<&TokenV1>) -> Scenario {
        let sender = identity();
        let recipient = identity();
        let entry = compose(&sender, &recipient, EPOCH, token, "hello");
        Scenario {
            sender,
            recipient,
            entry,
        }
    }

    /// A fresh admitter over the scenario's recipient. `seen` and `spent` are the
    /// caller's, so a test can drive several sweeps against one set.
    fn admitter<'a>(
        s: &'a Scenario,
        policy: AdmissionPolicy,
        seen: &'a mut SeenSet,
        spent: &'a mut SpentTokenSet,
        addr: &'a keyrec::DmKeyRecordOwnerSeed,
    ) -> Admitter<'a> {
        Admitter {
            recipient_dk: s.recipient.kem.decapsulation_key(),
            recipient_pk_lt: s.recipient.signing.public_key(),
            recipient_keyrec_addr: addr.as_bytes(),
            current_fc_epoch: EPOCH,
            now_unix_secs: NOW,
            policy,
            difficulty: bits(),
            seen,
            spent,
            counters: AdmissionCounters::default(),
        }
    }

    fn addr_of(k: &IdentityKeys) -> keyrec::DmKeyRecordOwnerSeed {
        keyrec::derive_owner_seed(k.signing.public_key()).unwrap()
    }

    fn nobody(_: &[u8; ml_dsa::PK_LEN]) -> bool {
        false
    }

    /// The entry hash of `entry`, computed the way step 2 computes it — through
    /// the same private shape gate, so the halves are split at the one pinned
    /// width and this is not an independent re-implementation of the split.
    fn expected_entry_hash(entry: &[u8]) -> [u8; ENTRY_HASH_LEN] {
        let shape = decode_shape(entry).expect("the fixture entry is well-shaped");
        pow::entry_hash(&shape.ct0, &shape.sealed).expect("hash")
    }

    // ── The happy path, which is the control for everything below ───────────

    /// A well-formed knock at an open-policy recipient is admitted, and the
    /// counters say what it cost: one entry hash, one decapsulation, two
    /// signature verifications and no token work at all.
    #[test]
    fn a_valid_knock_is_admitted_and_the_costs_are_what_the_ordering_claims() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);

        let outcome = a.admit(&s.entry, None, nobody);
        let AdmissionOutcome::Admitted {
            verified,
            token_nonce,
            idempotent,
            entry_hash,
        } = outcome
        else {
            panic!("expected an admission, got {outcome:?}");
        };
        assert_eq!(verified.body(), "hello");
        assert_eq!(&verified.pk_lt()[..], &s.sender.signing.public_key()[..]);
        assert_eq!(token_nonce, None);
        assert!(!idempotent);
        // The carried hash is the one step 2 computed over this exact entry —
        // recomputed here from the same halves the shape gate pinned, so a
        // field wired to some other value fails rather than merely differing.
        assert_eq!(
            entry_hash,
            expected_entry_hash(&s.entry),
            "the carried entry hash is not this entry's"
        );

        assert_eq!(a.counters.entry_hashes, 1);
        assert_eq!(a.counters.decap_attempts, 1);
        assert_eq!(
            a.counters.sig_verifies, 2,
            "an untokened knock costs bind_lt and msg_sig, and nothing else"
        );
        assert_eq!(a.counters.admitted, 1);
        assert_eq!(a.counters.pow_rejects, 0);
    }

    /// `drop_reason` answers `None` for an admission. Every ordering test in this
    /// module reads its verdict through this method, so a version that returned
    /// `Some(_)` unconditionally would make all of them assert against a constant.
    #[test]
    fn drop_reason_is_none_for_an_admitted_entry() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        let outcome = a.admit(&s.entry, None, nobody);
        assert!(matches!(outcome, AdmissionOutcome::Admitted { .. }));
        assert_eq!(
            outcome.drop_reason(),
            None,
            "an admission has no drop reason, or every test reading this is vacuous"
        );
        // Control: a genuine drop does report one.
        assert_eq!(
            a.admit(&s.entry, Some(&s.entry), nobody).drop_reason(),
            Some(DropReason::Unchanged)
        );
    }

    // ── Vector 4: epoch consistency, decap provably not reached ─────────────

    /// **A proof minted for epoch *e* on an entry sealed at *e+1* is refused at
    /// step 3, and the decapsulation is never reached.**
    ///
    /// The counter is the proof. The outcome alone cannot carry it: an entry that
    /// reached step 4 and failed the AEAD reports `Dropped(Seal)`, and one that
    /// never got there reports `Dropped(Pow)` — but a pipeline that ran the
    /// decapsulation *and then* rejected on the proof would also report
    /// `Dropped(Pow)`. Only `decap_attempts == 0` distinguishes them.
    #[test]
    fn a_proof_for_the_wrong_epoch_is_refused_before_any_decapsulation() {
        let sender = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);
        // Sealed at EPOCH, so its proof is minted for EPOCH too. Composed until
        // that proof is genuinely invalid at the two epochs the second half
        // verifies against: at four bits a nonce clears an unrelated epoch's
        // threshold one time in sixteen, which is an artefact of the reduced
        // difficulty and would make this flake. At production's 22 bits the same
        // coincidence is one in four million.
        let mut chosen = None;
        for _ in 0..64 {
            let entry = compose(&sender, &recipient, EPOCH, None, "hello");
            let decoded = wire::FirstContactEntry::decode(&entry[..]).unwrap();
            let h = pow::entry_hash(&decoded.ct0, &decoded.sealed).unwrap();
            if pow::verify(addr.as_bytes(), EPOCH + 2, &h, &decoded.pow, bits()).is_empty() {
                chosen = Some(entry);
                break;
            }
        }
        let entry = chosen.expect("64 consecutive threshold coincidences is not a thing");
        let s = Scenario {
            sender,
            recipient,
            entry,
        };

        // Positive control FIRST: at a recipient whose clock says EPOCH, the proof
        // and the seal agree and the knock is admitted.
        {
            let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
            let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
            assert!(
                matches!(
                    a.admit(&s.entry, None, nobody),
                    AdmissionOutcome::Admitted { .. }
                ),
                "the control must pass, or the refusal below proves nothing"
            );
            assert_eq!(a.counters.decap_attempts, 1, "the control DID decapsulate");
        }

        // Now the same entry at a recipient two epochs ahead: EPOCH is outside
        // the window {EPOCH+2, EPOCH+1}, so the proof fails at step 3.
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        a.current_fc_epoch = EPOCH + 2;
        assert_eq!(
            a.admit(&s.entry, None, nobody).drop_reason(),
            Some(DropReason::Pow)
        );
        assert_eq!(
            a.counters.decap_attempts, 0,
            "the decapsulation must not be reached when the proof fails"
        );
        assert_eq!(a.counters.sig_verifies, 0);
        assert_eq!(a.counters.pow_rejects, 1);
    }

    /// A proof valid at the PREVIOUS epoch still admits — the window is two wide,
    /// and the seal is opened at the epoch the proof named rather than at the
    /// recipient's own.
    #[test]
    fn a_knock_from_the_previous_epoch_is_admitted_at_its_own_epoch() {
        let sender = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);
        let entry = compose(&sender, &recipient, EPOCH - 1, None, "from last week");
        let s = Scenario {
            sender,
            recipient,
            entry,
        };
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        let outcome = a.admit(&s.entry, None, nobody);
        assert!(
            matches!(outcome, AdmissionOutcome::Admitted { .. }),
            "got {outcome:?}"
        );
    }

    /// **A previous-epoch knock whose nonce ALSO clears the current epoch's
    /// threshold is still admitted.**
    ///
    /// This is the case that makes `ValidEpochs` plural. Trying only the first
    /// match would attempt the AEAD at the current epoch, fail, and silently drop
    /// a legitimate knock. At production difficulty it is one knock in four
    /// million — rare enough to never be diagnosed in the field, and common enough
    /// to happen. At the reduced test difficulty it is one in sixteen, which is
    /// why it is reachable here at all: the loop below composes until it finds
    /// one, and asserts it was found rather than assuming it.
    #[test]
    fn a_previous_epoch_knock_whose_proof_also_clears_the_current_epoch_still_admits() {
        let sender = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);

        let mut both = None;
        for _ in 0..512 {
            let entry = compose(&sender, &recipient, EPOCH - 1, None, "from last week");
            let decoded = wire::FirstContactEntry::decode(&entry[..]).unwrap();
            let h = pow::entry_hash(&decoded.ct0, &decoded.sealed).unwrap();
            let valid = pow::verify(addr.as_bytes(), EPOCH, &h, &decoded.pow, bits());
            if valid.as_slice() == [EPOCH, EPOCH - 1] {
                both = Some(entry);
                break;
            }
        }
        let entry = both.expect(
            "no double-clearing nonce in 512 mints at 4 bits — the search is broken, \
             because the expected wait is sixteen",
        );
        let s = Scenario {
            sender,
            recipient,
            entry,
        };

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        let outcome = a.admit(&s.entry, None, nobody);
        assert!(
            matches!(outcome, AdmissionOutcome::Admitted { .. }),
            "a knock whose proof clears both epochs must still open at its own: {outcome:?}"
        );
    }

    // ── Vector 6: cross-recipient, before decapsulation ─────────────────────

    /// **A fully valid entry addressed to B is refused at C on the proof of work,
    /// before C spends a decapsulation on it.**
    ///
    /// This is what stops one mint being sprayed across every doorbell an attacker
    /// can address: the proof binds the recipient's key-record owner seed, so it is
    /// worthless at any other address. Without it the entry would still be refused
    /// — but only after C had decapsulated and failed an AEAD open, which is
    /// precisely the work the ordering exists to avoid.
    ///
    /// **The reduced test difficulty forces a construction step, and it is worth
    /// stating rather than hiding.** At four bits roughly one nonce in sixteen
    /// also satisfies an unrelated address's threshold by chance, so a single
    /// composed entry lands on `Pow` only ~94% of the time and the test would be
    /// flaky. That is an artefact of the difficulty, not of the binding: at
    /// production's 22 bits the same coincidence is one in four million. So the
    /// entry is composed until its nonce is genuinely invalid at C — which is the
    /// input this test is *about* — and the second half asserts the property that
    /// holds at every difficulty: **no entry addressed to B is ever admitted at
    /// C**, whichever step catches it.
    #[test]
    fn an_entry_for_another_recipient_fails_the_proof_before_decapsulation() {
        let stranger = identity();
        let stranger_addr = addr_of(&stranger);

        let mut chosen: Option<Scenario> = None;
        let mut coincidences = 0u32;
        for _ in 0..64 {
            let s = scenario(None);
            let entry = wire::FirstContactEntry::decode(&s.entry[..]).unwrap();
            let h = pow::entry_hash(&entry.ct0, &entry.sealed).unwrap();
            if pow::verify(stranger_addr.as_bytes(), EPOCH, &h, &entry.pow, bits()).is_empty() {
                chosen = Some(s);
                break;
            }
            coincidences += 1;
        }
        let s = chosen.expect("64 consecutive threshold coincidences is not a thing");
        assert!(
            coincidences < 64,
            "sanity: the loop found an entry, {coincidences} were coincidences"
        );

        // Control: at its real recipient it IS admitted, so the refusal below is
        // the address binding and not a broken entry.
        {
            let addr = addr_of(&s.recipient);
            let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
            let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
            assert!(matches!(
                a.admit(&s.entry, None, nobody),
                AdmissionOutcome::Admitted { .. }
            ));
            assert_eq!(a.counters.decap_attempts, 1);
        }

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = Admitter {
            recipient_dk: stranger.kem.decapsulation_key(),
            recipient_pk_lt: stranger.signing.public_key(),
            recipient_keyrec_addr: stranger_addr.as_bytes(),
            current_fc_epoch: EPOCH,
            now_unix_secs: NOW,
            policy: AdmissionPolicy::Open,
            difficulty: bits(),
            seen: &mut seen,
            spent: &mut spent,
            counters: AdmissionCounters::default(),
        };
        assert_eq!(
            a.admit(&s.entry, None, nobody).drop_reason(),
            Some(DropReason::Pow)
        );
        assert_eq!(
            a.counters.decap_attempts, 0,
            "a foreign entry must not cost a decapsulation"
        );

        // The difficulty-independent half: over many fresh entries, not one is
        // ever ADMITTED at the wrong recipient — a threshold coincidence buys the
        // attacker a decapsulation, never an admission.
        for _ in 0..16 {
            let other = scenario(None);
            let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
            let mut a = Admitter {
                recipient_dk: stranger.kem.decapsulation_key(),
                recipient_pk_lt: stranger.signing.public_key(),
                recipient_keyrec_addr: stranger_addr.as_bytes(),
                current_fc_epoch: EPOCH,
                now_unix_secs: NOW,
                policy: AdmissionPolicy::Open,
                difficulty: bits(),
                seen: &mut seen,
                spent: &mut spent,
                counters: AdmissionCounters::default(),
            };
            // Destructured rather than read through `drop_reason()`: `is_some()`
            // on that method is satisfied by any value, so a `drop_reason` that
            // always answered `Some(_)` would make this loop assert nothing.
            let outcome = a.admit(&other.entry, None, nobody);
            assert!(
                matches!(outcome, AdmissionOutcome::Dropped(_)),
                "an entry for another recipient must never be admitted: {outcome:?}"
            );
        }
    }

    // ── Vector 7: the field gates ───────────────────────────────────────────

    /// A `pow` field that is absent, seven bytes or nine bytes is refused at step
    /// 1 — before the entry hash, so it costs neither a hash nor a decapsulation.
    #[test]
    fn a_pow_field_of_the_wrong_width_is_refused_at_the_shape_gate() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let good = wire::FirstContactEntry::decode(&s.entry[..]).unwrap();

        for pow in [
            Vec::new(),
            good.pow[..7].to_vec(),
            [good.pow.clone(), vec![0]].concat(),
        ] {
            let len = pow.len();
            let mut mangled = good.clone();
            mangled.pow = pow;
            let bytes = mangled.encode_to_vec();

            let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
            let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
            assert_eq!(
                a.admit(&bytes, None, nobody).drop_reason(),
                Some(DropReason::Shape),
                "a {len}-byte pow must be refused at the shape gate"
            );
            assert_eq!(
                a.counters.entry_hashes, 0,
                "a {len}-byte pow must not cost an entry hash"
            );
            assert_eq!(a.counters.decap_attempts, 0);
            assert!(seen.is_empty(), "and it must not enter the seen-set");
        }

        // Control: the unmangled entry, through the same path, IS admitted — so
        // the refusals above are the width and not the re-encode.
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert!(matches!(
            a.admit(&good.encode_to_vec(), None, nobody),
            AdmissionOutcome::Admitted { .. }
        ));
    }

    /// A `ct0` of the wrong width is refused at step 1 too — and it has to be,
    /// because `H` is a bare concatenation of `ct0` and `sealed` with no framing
    /// between them. This is the ordering `crate::dm::pow`'s entry-hash test
    /// points at: move this check after step 2 and two differently-split entries
    /// would collide on `H`.
    #[test]
    fn a_ct0_of_the_wrong_width_is_refused_before_the_entry_hash() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let mut mangled = wire::FirstContactEntry::decode(&s.entry[..]).unwrap();
        // Move one byte across the ct0/sealed boundary — the exact shape that
        // would collide on H if the width were not pinned first.
        let moved = mangled.ct0.pop().unwrap();
        mangled.sealed.insert(0, moved);
        let bytes = mangled.encode_to_vec();

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert_eq!(
            a.admit(&bytes, None, nobody).drop_reason(),
            Some(DropReason::Shape)
        );
        assert_eq!(
            a.counters.entry_hashes, 0,
            "the width must be pinned BEFORE H is computed"
        );
    }

    /// **The `ct0` width gate, pinned on its own — the sole guarantor of
    /// `entry_hash` injectivity, and nothing else covers it.**
    ///
    /// `H = SHA-384(ct0 ‖ sealed)` has no framing between the operands, and
    /// `sealed` has TWO legal widths, so the split is ambiguous by exactly
    /// `PAD_BUCKETS[1] - PAD_BUCKETS[0]` = 5120 unless `ct0` is pinned: an entry
    /// with `ct0` of 6688 and `sealed` of 20508 hashes identically to one with
    /// `ct0` of 1568 and `sealed` of 25628, and **one nonce is a valid proof for
    /// both** — work carried from one entry to another, which is the property the
    /// per-entry binding exists to deny.
    ///
    /// The neighbouring test moves a byte ACROSS the boundary, which makes `sealed`
    /// illegal too — so the sealed gate catches it and deleting the `ct0` gate
    /// leaves that test green. This one changes `ct0` alone, leaving `sealed` and
    /// `pow` untouched, so the `ct0` gate is the only thing that can reject it and
    /// removing that line makes this fail.
    #[test]
    fn the_ct0_width_gate_alone_rejects_a_ct0_that_is_one_byte_off() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let good = wire::FirstContactEntry::decode(&s.entry[..]).unwrap();
        assert_eq!(good.ct0.len(), firstcontact::CT0_LEN);

        for delta in [-1i32, 1] {
            let mut mangled = good.clone();
            if delta < 0 {
                mangled.ct0.pop();
            } else {
                mangled.ct0.push(0);
            }
            let width = mangled.ct0.len();
            // `sealed` and `pow` are untouched and still legal, so nothing but the
            // ct0 gate stands between this entry and the entry hash.
            assert!(is_legal_sealed_len(mangled.sealed.len()));
            assert_eq!(mangled.pow.len(), pow::FC_POW_LEN);
            assert!(
                decode_shape(&mangled.encode_to_vec()).is_none(),
                "a {width}-byte ct0 must be refused at the shape gate"
            );

            let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
            let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
            assert_eq!(
                a.admit(&mangled.encode_to_vec(), None, nobody)
                    .drop_reason(),
                Some(DropReason::Shape),
                "a {width}-byte ct0 must never reach the entry hash"
            );
            assert_eq!(a.counters.entry_hashes, 0);
        }

        // Control: the untouched entry, through the same path, IS admitted — so
        // the refusals above are the width and not the re-encode.
        assert!(decode_shape(&good.encode_to_vec()).is_some());
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert!(matches!(
            a.admit(&good.encode_to_vec(), None, nobody),
            AdmissionOutcome::Admitted { .. }
        ));
    }

    /// A `sealed` field that is not one of the two legal padded envelopes is
    /// refused at step 1, so the whole class costs no decapsulation.
    #[test]
    fn a_sealed_field_outside_the_padding_ladder_is_refused_at_the_shape_gate() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let mut mangled = wire::FirstContactEntry::decode(&s.entry[..]).unwrap();
        mangled.sealed.push(0);
        let bytes = mangled.encode_to_vec();

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert_eq!(
            a.admit(&bytes, None, nobody).drop_reason(),
            Some(DropReason::Shape)
        );
        assert_eq!(a.counters.decap_attempts, 0);

        // Both legal widths ARE accepted by the gate itself.
        assert!(is_legal_sealed_len(NONCE_LEN + 20480 + TAG_LEN));
        assert!(is_legal_sealed_len(NONCE_LEN + 25600 + TAG_LEN));
        assert!(!is_legal_sealed_len(NONCE_LEN + 25600 + TAG_LEN + 1));
        assert!(!is_legal_sealed_len(0));
    }

    /// Step 0: an unchanged slot costs nothing at all.
    #[test]
    fn an_unchanged_slot_is_skipped_before_anything_is_computed() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert_eq!(
            a.admit(&s.entry, Some(&s.entry), nobody).drop_reason(),
            Some(DropReason::Unchanged)
        );
        assert_eq!(a.counters.entry_hashes, 0);
        assert_eq!(a.counters.unchanged, 1);
        // Control: with a DIFFERENT previous value the same slot is processed.
        assert!(matches!(
            a.admit(&s.entry, Some(b"something else"), nobody),
            AdmissionOutcome::Admitted { .. }
        ));
    }

    // ── Vector 13: the seen-set is gated on the proof ───────────────────────

    /// **A proof-less entry never enters the seen-set; a proof-valid but malformed
    /// one does.**
    ///
    /// This is what keeps the set's memory bounded by what the attacker *paid
    /// for*. If a bad-proof entry were recorded, 32 slots of free garbage,
    /// refreshed every sweep, would fill it — and the set exists precisely so
    /// re-verification is bounded.
    #[test]
    fn the_seen_set_admits_only_entries_that_paid_their_proof() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);

        // (a) A proof-less entry: valid shape, and a nonce PROVEN not to be a
        // valid proof rather than merely assumed to be one. At the reduced test
        // difficulty a fixed nonce clears the threshold one time in sixteen, so
        // an assumed-bad nonce makes this test flake — and a flaky test that
        // passes is indistinguishable from one that works.
        let mut bad = wire::FirstContactEntry::decode(&s.entry[..]).unwrap();
        let bad_h = pow::entry_hash(&bad.ct0, &bad.sealed).unwrap();
        let bad_nonce = (0u64..)
            .find(|&n| {
                pow::verify(
                    addr.as_bytes(),
                    EPOCH,
                    &bad_h,
                    &pow::nonce_to_field(n),
                    bits(),
                )
                .is_empty()
            })
            .expect("some nonce is not a valid proof");
        bad.pow = pow::nonce_to_field(bad_nonce);
        let bad_bytes = bad.encode_to_vec();
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert_eq!(
            a.admit(&bad_bytes, None, nobody).drop_reason(),
            Some(DropReason::Pow)
        );
        assert_eq!(a.counters.entry_hashes, 1, "it DID cost an entry hash");
        assert!(
            seen.is_empty(),
            "but an entry that never paid must not occupy seen-set memory"
        );

        // (b) A proof-VALID entry whose body is unopenable: the seal is corrupted
        // after the proof was minted over the corrupted bytes, so the proof is
        // genuinely valid and the AEAD genuinely fails.
        let mut mangled = wire::FirstContactEntry::decode(&s.entry[..]).unwrap();
        mangled.sealed[100] ^= 0xff;
        let h = pow::entry_hash(&mangled.ct0, &mangled.sealed).unwrap();
        let nonce = pow::mint(addr.as_bytes(), EPOCH, &h, bits()).unwrap();
        mangled.pow = pow::nonce_to_field(nonce);
        let mangled_bytes = mangled.encode_to_vec();

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert_eq!(
            a.admit(&mangled_bytes, None, nobody).drop_reason(),
            Some(DropReason::Seal)
        );
        assert_eq!(a.counters.decap_attempts, 1);
        assert_eq!(
            seen.len(),
            1,
            "a PAID entry is recorded even though it failed"
        );

        // And on the next sweep it is skipped without a second decapsulation.
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert_eq!(
            a.admit(&mangled_bytes, None, nobody).drop_reason(),
            Some(DropReason::Seen)
        );
        assert_eq!(
            a.counters.decap_attempts, 0,
            "a seen entry must not be reprocessed"
        );
    }

    /// A successfully admitted entry is in the set too, so the same slot re-read
    /// on the next sweep does not surface a second contact request.
    #[test]
    fn an_admitted_entry_is_not_reprocessed() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        {
            let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
            assert!(matches!(
                a.admit(&s.entry, None, nobody),
                AdmissionOutcome::Admitted { .. }
            ));
        }
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert_eq!(
            a.admit(&s.entry, None, nobody).drop_reason(),
            Some(DropReason::Seen)
        );
        assert_eq!(a.counters.decap_attempts, 0);
    }

    /// The set is bounded, evicts oldest-first within an epoch, and retires whole
    /// epochs once they leave the accept window.
    #[test]
    fn the_seen_set_is_bounded_and_retires_stale_epochs() {
        let mut set = SeenSet::new();
        for i in 0..SEEN_SET_CAPACITY {
            let mut h = [0u8; ENTRY_HASH_LEN];
            h[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(set.insert(EPOCH, h));
        }
        assert_eq!(set.len(), SEEN_SET_CAPACITY);
        let first = {
            let mut h = [0u8; ENTRY_HASH_LEN];
            h[..8].copy_from_slice(&0u64.to_be_bytes());
            h
        };
        assert!(set.contains(&first));

        // One past capacity evicts the oldest.
        let mut extra = [0u8; ENTRY_HASH_LEN];
        extra[..8].copy_from_slice(&(SEEN_SET_CAPACITY as u64).to_be_bytes());
        assert!(set.insert(EPOCH, extra));
        assert_eq!(set.len(), SEEN_SET_CAPACITY, "the set stays bounded");
        assert!(!set.contains(&first), "the oldest was evicted");
        assert!(set.contains(&extra));

        // A re-insert of a held hash is a no-op.
        assert!(!set.insert(EPOCH, extra));
        assert_eq!(set.len(), SEEN_SET_CAPACITY);

        // Retirement drops epochs outside {current, current - 1}.
        set.insert(EPOCH + 1, [0xaa; ENTRY_HASH_LEN]);
        assert_eq!(set.retire(EPOCH + 1), 0, "EPOCH is still the previous one");
        assert_eq!(set.retire(EPOCH + 2), 1, "now EPOCH is two behind");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&[0xaa; ENTRY_HASH_LEN]));
    }

    /// **A previous-epoch entry is filed in the seen-set under ITS OWN epoch, not
    /// the sweeper's.** Filing it under the current epoch retires it a week early
    /// — `retire` drops everything before `current - 1`, so the hash disappears
    /// while the entry is still presentable, and the knock is reprocessed and
    /// re-surfaced. Nothing else in this module notices which epoch was used.
    #[test]
    fn a_previous_epoch_entry_is_filed_under_its_own_epoch() {
        let sender = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);
        // Composed until the proof clears ONLY the previous epoch, so the epoch
        // filed is unambiguous.
        let mut chosen = None;
        for _ in 0..64 {
            let entry = compose(&sender, &recipient, EPOCH - 1, None, "from last week");
            let decoded = wire::FirstContactEntry::decode(&entry[..]).unwrap();
            let h = pow::entry_hash(&decoded.ct0, &decoded.sealed).unwrap();
            if pow::verify(addr.as_bytes(), EPOCH, &h, &decoded.pow, bits()).as_slice()
                == [EPOCH - 1]
            {
                chosen = Some(entry);
                break;
            }
        }
        let entry = chosen.expect("64 consecutive coincidences is not a thing");
        let s = Scenario {
            sender,
            recipient,
            entry,
        };

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        {
            let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
            assert!(matches!(
                a.admit(&s.entry, None, nobody),
                AdmissionOutcome::Admitted { .. }
            ));
        }
        assert_eq!(seen.len(), 1);

        // Retiring at the sweeper's own epoch must NOT drop it: EPOCH - 1 is still
        // inside the accept window, so the entry is still presentable.
        seen.retire(EPOCH);
        assert_eq!(
            seen.len(),
            1,
            "an entry filed under the current epoch instead of its own is retired \
             a week early and gets reprocessed"
        );
        // Control: one epoch further on, it IS retired.
        seen.retire(EPOCH + 1);
        assert_eq!(seen.len(), 0);
    }

    /// **D10 step 1's FIRST gate: a slot larger than the subkey cap is refused
    /// before prost is asked to walk it.**
    ///
    /// The padding must be something prost would *accept*, or the test proves
    /// nothing: zero bytes encode field number 0, which is invalid protobuf, so a
    /// zero-padded buffer is rejected by the decoder whether the length guard
    /// exists or not — and deleting the guard leaves such a test green. The
    /// padding here is a well-formed unknown length-delimited field, which prost
    /// skips silently, so the buffer decodes cleanly and the length guard is the
    /// only thing standing between an attacker-chosen slot of any size and the
    /// decoder.
    #[test]
    fn an_entry_larger_than_the_subkey_cap_is_refused_before_it_is_decoded() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        assert!(s.entry.len() <= MAX_ENTRY_LEN);
        // Control: at the cap it decodes.
        assert!(decode_shape(&s.entry).is_some());

        // Field 15, wire type 2 (length-delimited): tag (15 << 3) | 2 = 0x7a,
        // then a varint length, then the payload. `FirstContactEntry` has no
        // field 15, so prost skips it.
        let padding_len = MAX_ENTRY_LEN;
        let mut oversized = s.entry.clone();
        oversized.push(0x7a);
        let mut n = padding_len as u64;
        while n >= 0x80 {
            oversized.push((n as u8) | 0x80);
            n >>= 7;
        }
        oversized.push(n as u8);
        oversized.extend(std::iter::repeat_n(0xabu8, padding_len));
        assert!(oversized.len() > MAX_ENTRY_LEN);

        // The control that makes this test mean anything: prost DOES decode these
        // bytes, and every other shape gate passes on them. Only the length guard
        // can reject them.
        let decoded = wire::FirstContactEntry::decode(&oversized[..])
            .expect("the padding must be well-formed protobuf prost will skip");
        assert_eq!(decoded.ct0.len(), firstcontact::CT0_LEN);
        assert_eq!(decoded.pow.len(), pow::FC_POW_LEN);
        assert!(is_legal_sealed_len(decoded.sealed.len()));

        assert!(
            decode_shape(&oversized).is_none(),
            "an over-length slot must be refused before the decode"
        );

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert_eq!(
            a.admit(&oversized, None, nobody).drop_reason(),
            Some(DropReason::Shape)
        );
        assert_eq!(a.counters.entry_hashes, 0);
        assert_eq!(
            a.counters.shape_rejects, 1,
            "and it is counted as a shape reject"
        );
    }

    /// **`retire`'s `saturating_sub` is load-bearing.** At epoch 0 there is no
    /// previous epoch; a wrapping subtraction gives a floor of `u64::MAX` and
    /// retires the entire live set on the first sweep after a clock reset, so
    /// every pending knock is reprocessed and re-surfaced.
    #[test]
    fn retire_at_epoch_zero_does_not_wrap_and_drop_the_live_set() {
        let mut set = SeenSet::new();
        set.insert(0, [0x11; ENTRY_HASH_LEN]);
        assert_eq!(set.retire(0), 0, "epoch 0 is its own floor");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&[0x11; ENTRY_HASH_LEN]));
        // Control: an epoch genuinely below the floor IS retired.
        set.insert(5, [0x22; ENTRY_HASH_LEN]);
        assert_eq!(set.retire(5), 1);
        assert_eq!(set.len(), 1);
        assert!(set.contains(&[0x22; ENTRY_HASH_LEN]));
    }

    /// `seen_skips` is asserted somewhere, so the counter is not write-only.
    /// A metrics field nothing reads drifts silently.
    #[test]
    fn the_seen_skip_counter_is_incremented() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        {
            let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
            assert!(matches!(
                a.admit(&s.entry, None, nobody),
                AdmissionOutcome::Admitted { .. }
            ));
            assert_eq!(a.counters.seen_skips, 0, "the first sweep skips nothing");
        }
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert_eq!(
            a.admit(&s.entry, None, nobody).drop_reason(),
            Some(DropReason::Seen)
        );
        assert_eq!(a.counters.seen_skips, 1);
    }

    // ── Vector 11: the open policy ignores the token entirely ───────────────

    /// **Under an open policy the token field is never verified and never
    /// consumed.** Consuming a nonce that gated nothing would silently burn a
    /// grant the recipient never asked to spend — and the grantee would find it
    /// spent the next time it mattered.
    #[test]
    fn an_open_policy_ignores_the_token_field_entirely() {
        let sender = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);
        let token =
            TokenV1::mint_default(&recipient.signing, sender.signing.public_key(), NOW).unwrap();
        let nonce = *token.nonce();
        let entry = compose(&sender, &recipient, EPOCH, Some(&token), "hello");
        let s = Scenario {
            sender,
            recipient,
            entry,
        };

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        let outcome = a.admit(&s.entry, None, nobody);
        let AdmissionOutcome::Admitted { token_nonce, .. } = outcome else {
            panic!("expected an admission, got {outcome:?}");
        };
        assert_eq!(token_nonce, None, "no token was consumed");
        let counters = a.counters;
        assert!(spent.is_empty(), "the spent set must be untouched");
        assert_eq!(
            counters.sig_verifies, 2,
            "no ML-DSA verification was spent on the token"
        );

        // Control: the SAME entry under invite-only DOES consume it, so the
        // assertion above is the policy and not a token that never worked.
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(
            &s,
            AdmissionPolicy::InviteOnly,
            &mut seen,
            &mut spent,
            &addr,
        );
        let outcome = a.admit(&s.entry, None, nobody);
        let AdmissionOutcome::Admitted { token_nonce, .. } = outcome else {
            panic!("expected an admission, got {outcome:?}");
        };
        assert_eq!(token_nonce, Some(nonce));
        let counters = a.counters;
        assert!(spent.contains(&nonce));
        assert_eq!(counters.sig_verifies, 3, "token, bind_lt, msg_sig");
    }

    // ── Vector 9: one-time-ness, and the ordering that protects it ──────────

    /// **A spent nonce is refused, and a forged entry naming a real token cannot
    /// burn it.**
    ///
    /// The forgery is an entry claiming the grantee's identity while signing with
    /// a key it does not hold — so it fails at `bind_lt`, which runs strictly
    /// after the token gates. If consumption happened at the gate rather than at
    /// admission, that failure would still have spent the nonce, and the real
    /// grantee's knock would then be refused forever by a stranger's forgery.
    #[test]
    fn a_forged_entry_naming_a_real_token_cannot_burn_it() {
        let grantee = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);
        let token =
            TokenV1::mint_default(&recipient.signing, grantee.signing.public_key(), NOW).unwrap();
        let nonce = *token.nonce();

        // The forgery: an impostor composes with the SAME token, so the token
        // itself is genuine and only the identity is wrong.
        let impostor = identity();
        let forged = compose(&impostor, &recipient, EPOCH, Some(&token), "let me in");
        let genuine = compose(&grantee, &recipient, EPOCH, Some(&token), "hello");

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let s = Scenario {
            sender: grantee,
            recipient,
            entry: genuine.clone(),
        };

        // The forgery is refused — at the token signature, because the token names
        // the grantee and the impostor's `pk_lt` is not the grantee's.
        {
            let mut a = admitter(
                &s,
                AdmissionPolicy::InviteOnly,
                &mut seen,
                &mut spent,
                &addr,
            );
            assert_eq!(
                a.admit(&forged, None, nobody).drop_reason(),
                Some(DropReason::Signature)
            );
        }
        assert!(
            !spent.contains(&nonce),
            "a refused entry must not have burned the grant"
        );

        // **The positive control: the real grantee still gets in afterwards.**
        // Without it, "the nonce was not burned" could be true while the token had
        // been broken some other way.
        {
            let mut a = admitter(
                &s,
                AdmissionPolicy::InviteOnly,
                &mut seen,
                &mut spent,
                &addr,
            );
            let outcome = a.admit(&genuine, None, nobody);
            let AdmissionOutcome::Admitted { token_nonce, .. } = outcome else {
                panic!("the genuine grantee must still be admitted, got {outcome:?}");
            };
            assert_eq!(token_nonce, Some(nonce));
        }
        assert!(spent.contains(&nonce), "and NOW it is spent");

        // A second, distinct knock on the same token is refused as spent.
        let again = compose(&s.sender, &s.recipient, EPOCH, Some(&token), "again");
        assert_ne!(again, genuine, "a fresh compose is a distinct entry");
        let mut a = admitter(
            &s,
            AdmissionPolicy::InviteOnly,
            &mut seen,
            &mut spent,
            &addr,
        );
        assert_eq!(
            a.admit(&again, None, nobody).drop_reason(),
            Some(DropReason::Token)
        );
        assert_eq!(
            a.counters.sig_verifies, 0,
            "a spent nonce is caught before any signature is verified"
        );
    }

    /// **Consumption is ordered after EVERY verification — and this is the probe
    /// that can actually tell.**
    ///
    /// The neighbouring forged-entry test uses an impostor whose `pk_lt` is not the
    /// grantee's, so it is refused by the TOKEN signature: `consumed` is never
    /// staged under either the correct ordering or a broken one, and the test
    /// therefore proves grantee binding rather than ordering. Moving the insert
    /// into the gate leaves it green.
    ///
    /// This entry gets past the token gate and dies after it. It claims the
    /// grantee's `pk_lt`, carries the grantee's **genuine** token — so the token
    /// verifies, `consumed` is staged — and then fails `bind_lt`. Constructible by
    /// anyone: the doorbell is world-writable and the writer chose `ss0`, so it
    /// holds the seal key.
    ///
    /// `sig_verifies == 1` is what proves the token gate was passed rather than
    /// skipped; the unburned nonce is what proves consumption waited. Under a
    /// mutation that consumes inside the gate, a stranger burns a real grant and
    /// the genuine grantee is locked out for ever by someone else's forgery.
    #[test]
    fn a_genuine_token_on_an_entry_with_a_broken_binding_does_not_burn_the_grant() {
        let grantee = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);
        let token =
            TokenV1::mint_default(&recipient.signing, grantee.signing.public_key(), NOW).unwrap();
        let nonce = *token.nonce();

        let pc = identity();
        let eph = identity();
        let forged = firstcontact::seal_hand_built_for_test(
            recipient.signing.public_key(),
            recipient.kem.encapsulation_key(),
            EPOCH,
            bits(),
            |ss0| {
                let rcpt = firstcontact::recipient_hash(recipient.signing.public_key()).unwrap();
                let roots = firstcontact::derive_channel_roots(ss0).unwrap();
                let eph_ek = eph.kem.encapsulation_key();
                // `msg_sig` is signed correctly under a pseudonym the attacker
                // really holds, so `bind_lt` is the only thing that can catch this
                // — which is what puts the failure strictly AFTER the token gate.
                let msg_sig = pc
                    .signing
                    .sign(&firstcontact::msg_sig_input(
                        firstcontact::FRAME_KIND_FIRST_CONTACT,
                        &roots.chan_id,
                        crate::dm::ratchet::Direction::AToB.label(),
                        0,
                        eph_ek,
                        &rcpt,
                        pc.signing.public_key(),
                        grantee.signing.public_key(),
                        SENT,
                        "let me in",
                    ))
                    .unwrap();
                wire::FirstContactBody {
                    intended_recipient_hash: rcpt.to_vec(),
                    pk_lt: grantee.signing.public_key().to_vec(),
                    pk_pc: pc.signing.public_key().to_vec(),
                    // Right length, wrong bytes: it passes the exact-length gate
                    // and fails the verification.
                    bind_lt: vec![0u8; ml_dsa::SIG_LEN],
                    key_selector: wire::KeySelector::Static as i32,
                    seq: 0,
                    sent_unix_ms: SENT,
                    body: "let me in".to_owned(),
                    eph_ek: eph_ek.to_vec(),
                    msg_sig: msg_sig.to_vec(),
                    token: token.encode(),
                }
            },
        );

        let s = Scenario {
            sender: grantee,
            recipient,
            entry: forged.clone(),
        };
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        {
            let mut a = admitter(
                &s,
                AdmissionPolicy::InviteOnly,
                &mut seen,
                &mut spent,
                &addr,
            );
            assert_eq!(
                a.admit(&forged, None, nobody).drop_reason(),
                Some(DropReason::Signature),
                "the broken binding must be what refuses it"
            );
            assert_eq!(
                a.counters.sig_verifies, 2,
                "the token's verification AND bind_lt's — proving the token gate \
                 PASSED (which is the state in which ordering is decidable at all) \
                 and that msg_sig was never reached"
            );
        }
        assert!(
            !spent.contains(&nonce),
            "a knock refused after the token gate must not have burned the grant"
        );

        // **Positive control: the real grantee still gets in afterwards.** Without
        // it, "the nonce is unspent" could be true while the grant had been broken
        // some other way.
        let genuine = compose(&s.sender, &s.recipient, EPOCH, Some(&token), "hello");
        let mut a = admitter(
            &s,
            AdmissionPolicy::InviteOnly,
            &mut seen,
            &mut spent,
            &addr,
        );
        let outcome = a.admit(&genuine, None, nobody);
        let AdmissionOutcome::Admitted { token_nonce, .. } = outcome else {
            panic!("the genuine grantee must still be admitted, got {outcome:?}");
        };
        assert_eq!(token_nonce, Some(nonce));
        assert!(spent.contains(&nonce), "and only NOW is it spent");
    }

    /// Invite-only with no token at all: refused at the token gate, and the
    /// refusal costs no ML-DSA verification.
    #[test]
    fn invite_only_refuses_a_tokenless_knock_before_any_signature() {
        let s = scenario(None);
        let addr = addr_of(&s.recipient);
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(
            &s,
            AdmissionPolicy::InviteOnly,
            &mut seen,
            &mut spent,
            &addr,
        );
        assert_eq!(
            a.admit(&s.entry, None, nobody).drop_reason(),
            Some(DropReason::Token)
        );
        assert_eq!(a.counters.sig_verifies, 0);
        assert_eq!(
            a.counters.decap_attempts, 1,
            "the token rides inside the seal, so this class is only reachable after decap"
        );

        // Control: the same entry under an open policy is admitted.
        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(&s, AdmissionPolicy::Open, &mut seen, &mut spent, &addr);
        assert!(matches!(
            a.admit(&s.entry, None, nobody),
            AdmissionOutcome::Admitted { .. }
        ));
    }

    /// An expired token is refused at the free gate, before its signature is
    /// verified — so an expired-token flood costs an integer comparison.
    #[test]
    fn invite_only_refuses_an_expired_token_before_verifying_it() {
        let sender = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);
        let token = TokenV1::mint(&recipient.signing, sender.signing.public_key(), NOW).unwrap();
        let entry = compose(&sender, &recipient, EPOCH, Some(&token), "hello");
        let s = Scenario {
            sender,
            recipient,
            entry,
        };

        // Control: at NOW it is current and admits.
        {
            let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
            let mut a = admitter(
                &s,
                AdmissionPolicy::InviteOnly,
                &mut seen,
                &mut spent,
                &addr,
            );
            assert!(matches!(
                a.admit(&s.entry, None, nobody),
                AdmissionOutcome::Admitted { .. }
            ));
        }

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        let mut a = admitter(
            &s,
            AdmissionPolicy::InviteOnly,
            &mut seen,
            &mut spent,
            &addr,
        );
        a.now_unix_secs = NOW + 1;
        assert_eq!(
            a.admit(&s.entry, None, nobody).drop_reason(),
            Some(DropReason::Token)
        );
        assert_eq!(
            a.counters.sig_verifies, 0,
            "expiry is checked before the token signature"
        );
    }

    /// A revoked-but-unspent token is refused, which is all revocation is.
    #[test]
    fn a_revoked_token_is_refused() {
        let sender = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);
        let token =
            TokenV1::mint_default(&recipient.signing, sender.signing.public_key(), NOW).unwrap();
        let entry = compose(&sender, &recipient, EPOCH, Some(&token), "hello");
        let s = Scenario {
            sender,
            recipient,
            entry,
        };

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        spent.revoke(&token);
        let mut a = admitter(
            &s,
            AdmissionPolicy::InviteOnly,
            &mut seen,
            &mut spent,
            &addr,
        );
        assert_eq!(
            a.admit(&s.entry, None, nobody).drop_reason(),
            Some(DropReason::Token)
        );
    }

    // ── Vector 10: the idempotent re-accept ─────────────────────────────────

    /// **A knock from an identity we already have a channel with is admitted
    /// idempotently, without consulting the token at all.**
    ///
    /// The ordering matters: step 7 runs before step 8, so a re-sealed retry of an
    /// an already-admitted knock is never rejected as token-spent — and its nonce
    /// IS in the spent set, precisely because we admitted it the first time.
    #[test]
    fn an_already_known_correspondent_re_admits_idempotently_on_a_spent_token() {
        let sender = identity();
        let recipient = identity();
        let addr = addr_of(&recipient);
        let token =
            TokenV1::mint_default(&recipient.signing, sender.signing.public_key(), NOW).unwrap();
        let sender_pk = *sender.signing.public_key();
        let first = compose(&sender, &recipient, EPOCH, Some(&token), "hello");
        // A re-sealed retry in the NEXT epoch: a genuinely different entry, so the
        // seen-set cannot be what admits it.
        let retry = compose(&sender, &recipient, EPOCH + 1, Some(&token), "hello");
        let s = Scenario {
            sender,
            recipient,
            entry: first.clone(),
        };

        let (mut seen, mut spent) = (SeenSet::new(), SpentTokenSet::new());
        {
            let mut a = admitter(
                &s,
                AdmissionPolicy::InviteOnly,
                &mut seen,
                &mut spent,
                &addr,
            );
            let outcome = a.admit(&first, None, nobody);
            let AdmissionOutcome::Admitted { idempotent, .. } = outcome else {
                panic!("expected an admission, got {outcome:?}");
            };
            assert!(!idempotent, "the first admission is not idempotent");
        }
        assert!(spent.contains(token.nonce()));

        // Control: a STRANGER presenting the same token now is refused as spent —
        // so the spent set really is in the way.
        {
            let stranger = identity();
            let their_token =
                TokenV1::mint_default(&s.recipient.signing, stranger.signing.public_key(), NOW)
                    .unwrap();
            let _ = their_token;
            let mut a = admitter(
                &s,
                AdmissionPolicy::InviteOnly,
                &mut seen,
                &mut spent,
                &addr,
            );
            let again = compose(&s.sender, &s.recipient, EPOCH, Some(&token), "again");
            assert_eq!(
                a.admit(&again, None, nobody).drop_reason(),
                Some(DropReason::Token),
                "an unknown correspondent on a spent token is refused"
            );
        }

        // The known correspondent's retry, at the next epoch, is admitted
        // idempotently and consumes nothing.
        let mut a = admitter(
            &s,
            AdmissionPolicy::InviteOnly,
            &mut seen,
            &mut spent,
            &addr,
        );
        a.current_fc_epoch = EPOCH + 1;
        let outcome = a.admit(&retry, None, |pk| pk == &sender_pk);
        let AdmissionOutcome::Admitted {
            token_nonce,
            idempotent,
            ..
        } = outcome
        else {
            panic!("a known correspondent's retry must be admitted, got {outcome:?}");
        };
        assert!(idempotent, "and it must be flagged as a re-accept");
        assert_eq!(token_nonce, None, "nothing is consumed a second time");
        let counters = a.counters;
        assert_eq!(spent.len(), 1, "the spent set did not grow");
        assert_eq!(
            counters.sig_verifies, 2,
            "no token verification on the idempotent path"
        );
    }

    /// `forget` un-records one hash and leaves its neighbours alone.
    ///
    /// The neighbour is the control: a `forget` that cleared the epoch would
    /// satisfy the first assertion and silently re-open every other entry.
    #[test]
    fn forget_removes_one_hash_and_only_that_one() {
        let mut seen = SeenSet::new();
        let a = [1u8; ENTRY_HASH_LEN];
        let b = [2u8; ENTRY_HASH_LEN];
        assert!(seen.insert(7, a));
        assert!(seen.insert(7, b));
        assert!(
            seen.contains(&a) && seen.contains(&b),
            "the fixture is empty"
        );

        assert!(seen.forget(&a), "forget reported no removal");
        assert!(!seen.contains(&a), "the hash is still held");
        assert!(seen.contains(&b), "forget took a neighbour with it");
        assert!(!seen.forget(&a), "a second forget reported a removal");
    }
}
