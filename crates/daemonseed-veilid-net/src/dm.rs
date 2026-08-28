//! Direct-messaging helpers shared by both frontend net actors.
//!
//! The GUI and TUI actors drive identical DM network behaviour; only their local
//! session-state types differ. Anything that would otherwise be copy-pasted
//! between `daemonseed-gui/src/veilid_net.rs` and `daemonseed-tui/src/veilid_net.rs`
//! belongs here instead, taking its inputs as plain borrows rather than either
//! crate's private state struct. This is the same de-duplication direction as
//! #200 / #210, applied from the start rather than retrofitted.

use daemonseed_core::dm::ack::AckState;
use daemonseed_core::dm::ack_record::{self, DmAckAddress};
use daemonseed_core::dm::firstcontact::ROOT_LEN;
use daemonseed_core::dm::keyrec::{self, KemEncapsulationKey};
use daemonseed_core::dm::paging::ADDRESS_ROOT_LEN;
use daemonseed_core::dm::ratchet::Direction;
use daemonseed_core::identity::keys::SignKeypair;

use crate::actor::VeilidNetHandle;

/// Publish this identity's DM key record, off the caller's loop (ISC-C40, #232).
///
/// Signs `{version, kem_ek, invite_only}` under the stable identity key and writes
/// it to the `dflt(1)` record whose owner seed derives from that identity's own
/// public key — so any peer holding the pubkey, which rides every
/// provenance-signed artifact, can find and verify it.
///
/// **A no-op unless BOTH halves of the identity are present.** An ephemeral /
/// no-profile session has no persistent key and is genuinely not DM-reachable;
/// publishing a record would claim otherwise. Requiring both here — rather than
/// trusting the caller's capture step — also means a partial capture (one
/// derivation succeeding while the other failed) can never produce a record.
///
/// Failures are traced, never surfaced. The record re-seeds on a slow cadence, so
/// a missed write costs reachability until the next tick, never correctness.
///
/// `caller` is a short tag for the trace line (`"gui"` / `"tui"`).
pub fn spawn_dm_key_record_publish(
    handle: &VeilidNetHandle,
    caller: &'static str,
    signing: Option<&SignKeypair>,
    kem_ek: Option<&KemEncapsulationKey>,
) {
    let (Some(signing), Some(kem_ek)) = (signing, kem_ek) else {
        return;
    };
    let bytes = match keyrec::build_encoded(
        signing,
        kem_ek,
        keyrec::DM_KEY_RECORD_VERSION,
        keyrec::DM_KEY_RECORD_INVITE_ONLY,
    ) {
        Ok(b) => b,
        Err(e) => {
            crate::vtrace!("{caller} dm: key-record build failed: {e}");
            return;
        }
    };
    let owner_seed = match keyrec::derive_owner_seed(signing.public_key()) {
        Ok(seed) => *seed.as_bytes(),
        Err(e) => {
            crate::vtrace!("{caller} dm: key-record owner derivation failed: {e}");
            return;
        }
    };
    let handle = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = handle.publish_dm_key_record(owner_seed, bytes).await {
            crate::vtrace!("{caller} dm: key-record publish failed: {e}");
        }
    });
}

/// Publish one direction's acknowledgement record, off the caller's loop
/// (ISC-C39, #235).
///
/// Signs `state` under the conversation's pseudonym key, seals it under
/// `K_ack(direction)`, and writes it to the `dflt(1)` record whose owner seed
/// derives from the same address root and direction — so the correspondent, and
/// only the correspondent, can find and open it.
///
/// `direction` is the direction of the **messages being acknowledged**, not of the
/// acknowledgement itself: a party collecting `a2b` publishes the `a2b` record.
/// Take it from `Ratchet::recv_direction` rather than mapping a role by hand.
///
/// **This decides nothing about WHEN to write.** The jittered standalone cadence
/// and the client-global allowance are the caller's, and a caller that spawns this
/// on every collected message writes at the rate messages arrive.
///
/// Failures are traced, never surfaced. An acknowledgement is monotonic and
/// re-written, so a missed write costs a round of re-seeding by the sender, never
/// correctness — the fail-safe direction.
///
/// `caller` is a short tag for the trace line (`"gui"` / `"tui"`).
pub fn spawn_dm_ack_publish(
    handle: &VeilidNetHandle,
    caller: &'static str,
    state: &AckState,
    chan_id: &[u8; ROOT_LEN],
    direction: Direction,
    address_root: &[u8; ADDRESS_ROOT_LEN],
    signing_pc: &SignKeypair,
) {
    let bytes = match ack_record::build_encoded(state, chan_id, direction, address_root, signing_pc)
    {
        Ok(b) => b,
        Err(e) => {
            crate::vtrace!("{caller} dm: ack-record build failed: {e}");
            return;
        }
    };
    // The address, never a bare seed: an acknowledgement record's owner seed is
    // the conversation's write capability, so it travels inside the zeroizing
    // `DmAckAddress` all the way to the write (#244), carrying the direction it
    // was derived for with it.
    let address = match DmAckAddress::for_direction(address_root, direction) {
        Ok(address) => address,
        Err(e) => {
            crate::vtrace!("{caller} dm: ack-record owner derivation failed: {e}");
            return;
        }
    };
    let handle = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = handle.publish_dm_ack(address, bytes).await {
            crate::vtrace!("{caller} dm: ack-record publish failed: {e}");
        }
    });
}
