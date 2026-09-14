//! Delivery — whether a message this side wrote to its own channel has reached
//! the other side, how often to look at its slot while it has not, and what a
//! client hands the transport when it deletes a conversation.
//!
//! Serves FC1.
//!
//! `docs/design/direct-messaging.md` § Delivery gives the cursor rule, the
//! backoff and the teardown; § On-disk records gives the two local records
//! [`finish_delete`] removes.
//!
//! A teardown is three acts in the design's order, and the middle one is the
//! caller's: [`prepare_delete`] names the channel record to erase,
//! the caller's transport erases it — after writing the closed marker, where
//! one was asked for — and [`finish_delete`] then drops the local records. The
//! caller stops polling the correspondence once [`finish_delete`] returns.
//!
//! Nothing here reads a clock, draws entropy of its own, or touches the
//! network: the current time is a parameter, jitter arrives as a fill
//! function, and the erase is returned as a [`ChannelErase`] value.
//!
//! Re-establishment after a delete is not handled here: the deleting side
//! treats a later hello from the same correspondent as a new first contact,
//! which is the first-contact path's business.

use core::time::Duration;

use crate::dm::channel::{ChannelOpening, Control};
use crate::dm::drop::HELLO_LOOKUP_KEY_LEN;
use crate::dm::store::{LoadedConv, Store, StoreError};
use crate::storage::dm_store::CorrespondenceLabel;

pub use crate::dm::advert::{POLL_INTERVAL_MAX, POLL_INTERVAL_MIN};
pub use crate::dm::channel::collected;

/// How long a message stays in the normal band before the poll backs off to
/// [`BACKOFF_POLL_INTERVAL`]: seven days, in seconds.
pub const BACKOFF_AFTER_SECS: u64 = 7 * 24 * 60 * 60;

/// The interval a message outstanding for [`BACKOFF_AFTER_SECS`] or longer is
/// polled on: once a day, unjittered — the cadence
/// `docs/design/direct-messaging.md` § Eviction detection describes, where the
/// poll is itself the keep-alive that stops the record being evicted.
pub const BACKOFF_POLL_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// How long to wait before the next look at an outstanding message's slot.
///
/// `outstanding_since_secs` is when the message became outstanding and
/// `now_secs` is the caller's clock, both in seconds on the same scale. Below
/// [`BACKOFF_AFTER_SECS`] of age the interval is drawn from
/// [`POLL_INTERVAL_MIN`]..=[`POLL_INTERVAL_MAX`] through `fill`, so the record
/// carries no recognisable cadence; at or above it the interval is
/// [`BACKOFF_POLL_INTERVAL`] and `fill` is not drawn from at all. The band is
/// the advert poll's, re-exported rather than restated so the layer has one
/// pre-backoff cadence and one definition of it.
///
/// A `fill` error degrades to the band's fixed midpoint, as
/// [`crate::dm::advert::next_poll_interval`] does: a poll is liveness, not a
/// key, and the next draw recovers.
///
/// A `now_secs` below `outstanding_since_secs` — a clock that has gone
/// backwards — reads as age zero and so as the normal band, which is the
/// frequent end of the range rather than the sparse one.
///
/// The protocol never gives up: this returns an interval for every age, and
/// nothing here stops polling. Only a completed teardown does that.
pub fn next_poll_interval(
    outstanding_since_secs: u64,
    now_secs: u64,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Duration {
    if now_secs.saturating_sub(outstanding_since_secs) >= BACKOFF_AFTER_SECS {
        return BACKOFF_POLL_INTERVAL;
    }
    crate::presence::interval_in_band(POLL_INTERVAL_MIN, POLL_INTERVAL_MAX, move |buf| {
        fill(buf.as_mut_slice())
    })
}

/// [`next_poll_interval`] over the OS CSPRNG — the production draw, for a
/// caller outside this crate, which has no route to the crate's own jitter
/// source.
pub fn next_poll_interval_os(outstanding_since_secs: u64, now_secs: u64) -> Duration {
    next_poll_interval(
        outstanding_since_secs,
        now_secs,
        crate::jitter::os_fill_bytes,
    )
}

/// The send time of a conversation's oldest message still owed to the
/// correspondent, in Unix seconds, or `None` where nothing is owed.
///
/// Read from the entries [`Store::load`] reports as outstanding, so a message
/// the correspondent has collected, or any message of a conversation marked for
/// delete, does not count. `now` minus this is how long the oldest owed message
/// has been uncollected, which a caller can measure a poll's backoff or a nudge
/// against.
pub fn oldest_uncollected_at(conv: &LoadedConv) -> Option<u64> {
    conv.outstanding_outbox
        .iter()
        .map(|entry| entry.sent_at)
        .min()
}

/// Whether a conversation's oldest uncollected message has been waiting for
/// `threshold_secs` or longer at `now_secs`.
///
/// `oldest_uncollected_at` is [`oldest_uncollected_at`]'s answer, and nothing
/// owed is never due. The threshold is the caller's: the design leaves its
/// value open, so there is no default here. A clock that reads earlier than the
/// send time reads as age zero. This reports and does nothing else: nothing in
/// this crate deletes a conversation because a message has waited.
pub fn nudge_due(oldest_uncollected_at: Option<u64>, now_secs: u64, threshold_secs: u64) -> bool {
    oldest_uncollected_at.is_some_and(|at| now_secs.saturating_sub(at) >= threshold_secs)
}

/// The "closed" marker a deleting client may leave in its channel's control
/// subkey.
///
/// The marker is a [`Control`] with [`Control::closed`] set, and this names the
/// one field the store can supply for it. The caller builds the record with
/// [`ClosedMarker::control`] and seals it with
/// [`crate::dm::channel::seal_control`]; neither the sealing key nor the
/// channel opening is in the conversation record, so neither is reachable from
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosedMarker {
    /// This side's cursor over the correspondent's messages, as the control
    /// record's `collected_cursor`, as it stood when [`prepare_delete`] read
    /// it.
    pub collected_cursor: u64,
}

impl ClosedMarker {
    /// The control record to seal, given the opening the caller still holds.
    ///
    /// `opening` is an argument rather than a field because a control record
    /// written without one erases the opening from the channel, and the store
    /// keeps no copy of it to default to. `None` is correct only where the
    /// opening is going with the record.
    pub fn control(&self, opening: Option<ChannelOpening>) -> Control {
        Control {
            opening,
            collected_cursor: self.collected_cursor,
            closed: true,
        }
    }
}

/// The erase of one channel record, for the transport to carry out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelErase {
    /// The lookup key of the channel this side writes — the record to erase.
    pub lookup_key: [u8; HELLO_LOOKUP_KEY_LEN],
    /// The marker to write to the control subkey before the erase, where one
    /// was asked for.
    pub marker: Option<ClosedMarker>,
}

/// Mark the conversation delete-pending and name the channel erase a teardown
/// performs.
///
/// Sets [`crate::dm::store::ConvState::delete_pending`] in the critical section that reads the
/// conversation, through [`Store::mark_delete_pending`], and builds the
/// transport's value from that read. The mark reaches disk before the caller
/// erases anything, so a stop anywhere after this is visible to the next
/// launch in [`Store::pending_deletes`], [`Store::load`] offers none of the
/// conversation's outbox for rewriting, and every flow that writes for a
/// conversation refuses it with
/// [`crate::dm::flows::FlowError::DeletePending`]:
/// [`crate::dm::flows::send_message`], [`crate::dm::flows::collect_batch`],
/// [`crate::dm::flows::recognise_acceptance`], [`crate::dm::flows::accept`] on
/// an existing record, [`crate::dm::flows::continue_acceptance`],
/// [`crate::dm::flows::continue_first_contact`], and through it
/// [`crate::dm::flows::first_contact`] to a marked identity,
/// [`crate::dm::flows::resume_first_contact`] and
/// [`crate::dm::flows::refresh_first_contact`].
///
/// `send_message`, `collect_batch` and `recognise_acceptance` re-check the mark
/// in the critical section that commits their state, which comes before any
/// network write they make, and a refused commit writes nothing, so a flow that
/// loaded the conversation before the mark is refused at its commit. What that
/// leaves for those three is the gap between a commit and the network write
/// that follows it: one message slot, one cursor write, or the erase of a
/// collected hello slot, and `collect_batch`'s local record of the cursor it
/// published, which follows that write. The other flows check the mark once, at
/// their load: `resume_first_contact` leaves the gap between that check and its
/// hello write, and `accept`, `continue_acceptance`, `first_contact`,
/// `continue_first_contact` and `refresh_first_contact` leave the whole of the
/// work they do after it. A teardown and a flow on the same conversation are
/// therefore not run at once; that is the caller's to keep.
///
/// [`crate::dm::flows::collect`] still makes one network write for a marked,
/// established conversation: a rewritten hello from the correspondent is
/// surfaced as already collected, and its slot in this side's own drop is
/// erased. That is this side's drop, never the channel being erased.
///
/// The local records are
/// still there when this returns, and [`finish_delete`] is what removes them,
/// because the design erases the channel record before dropping local state:
/// an erase performed against a conversation already deleted is one whose
/// lookup key has been thrown away. Calling this again on a marked
/// conversation marks it again and names the same erase.
///
/// The marker's cursor is this side's `my_collected` as read here. A
/// collection landing between this and the erase is not in the marker, which
/// costs the correspondent one cursor's worth of staleness in a conversation
/// being torn down.
///
/// Returns [`StoreError::MissingConversation`] where the correspondence holds
/// no conversation record.
pub fn prepare_delete(
    store: &Store,
    peer: &CorrespondenceLabel,
    closed_marker: bool,
) -> Result<ChannelErase, StoreError> {
    let state = store.mark_delete_pending(peer)?;
    Ok(ChannelErase {
        lookup_key: state.outgoing_lookup_key,
        marker: closed_marker.then_some(ClosedMarker {
            collected_cursor: state.my_collected,
        }),
    })
}

/// Drop the local records once the caller's transport has performed the erase.
///
/// [`Store::delete_conv`] removes the conversation and outbox records
/// together, and the delete-pending mark goes with the conversation record.
/// The caller stops polling the correspondence once this returns.
///
/// A stop between [`prepare_delete`] and here leaves the conversation record
/// on disk carrying the delete-pending mark, whether or not the erase ran. The
/// next launch finds it in [`Store::pending_deletes`]; [`Store::load`] offers
/// none of its outbox, the flows [`prepare_delete`] names refuse it, and the
/// caller re-runs the erase and this, the erase
/// being idempotent — a record erased twice is erased. Resuming the teardown
/// rather than polling the conversation is the caller's part.
pub fn finish_delete(store: &Store, peer: &CorrespondenceLabel) -> Result<(), StoreError> {
    store.delete_conv(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dm::advert;
    use crate::dm::chain::initiate;
    use crate::dm::store::ConvState;
    use crate::identity::keys::SignKeypair;
    use crate::storage::dm_store::RecordKind;
    use crate::storage::seeds::AEAD_KEY_LEN;

    /// A moment inside every advert's usability window.
    const NOW: u64 = 1_700_000_000;

    /// Seconds in a day, for the ages the backoff is read at.
    const DAY: u64 = 24 * 60 * 60;

    /// A deterministic fill, so a failing run replays from the source alone.
    fn counting_fill(byte: u8) -> impl FnMut(&mut [u8]) -> Result<(), ()> {
        let mut counter = byte;
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = counter;
                counter = counter.wrapping_add(1);
            }
            Ok(())
        }
    }

    /// A shared secret by the real path: `AdvertSharedSecret` is constructible
    /// only by encapsulating to or decapsulating an advert key.
    fn shared_secret(seed: u8) -> advert::AdvertSharedSecret {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let signer = SignKeypair::from_ml_dsa_seed(&[seed; 32]).expect("derive a signer");
        let keys = advert::AdvertKeys::new(NOW, counting_fill(seed)).expect("advert keys");
        let bytes = keys.advert_bytes(&signer).expect("advert bytes");
        let verified = advert::verify(signer.public_key(), &bytes).expect("verify the advert");
        advert::encapsulate_to(&verified, NOW, counting_fill(seed ^ 0x5a))
            .expect("encapsulate")
            .shared_secret
    }

    /// The lookup key the fixture's own channel is addressed by.
    const OUTGOING: [u8; HELLO_LOOKUP_KEY_LEN] = [0xa1; HELLO_LOOKUP_KEY_LEN];

    /// This side's cursor over the correspondent's messages, which a marker
    /// carries.
    const MY_COLLECTED: u64 = 4;

    /// The sequence the fixture's outbox entry holds.
    const OWED_SEQ: u64 = 2;

    /// The advert serial the fixture's opening is signed over.
    const OPENING_SERIAL: u64 = 7;

    /// What a fixture hands a test: the store and the correspondence it holds,
    /// with the channel opening that correspondence's control subkey carries.
    struct Fixture {
        _tmp: tempfile::TempDir,
        store: Store,
        peer: CorrespondenceLabel,
        opening: ChannelOpening,
    }

    /// A store in a fresh temporary directory holding one correspondence: a
    /// conversation record, an outbox entry for a message still owed, and a
    /// signed opening over the conversation's own first ratchet key.
    fn fixture() -> Fixture {
        let _ = crate::kats::initialize_module_unsigned_test_binary();
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let store = Store::open(tmp.path().join("dm"), &[0x2c; AEAD_KEY_LEN]).expect("open");
        let peer = CorrespondenceLabel::from_bytes([0x9e; 32]);

        let writer = SignKeypair::from_ml_dsa_seed(&[0x41; 32]).expect("derive the writer");
        let recipient = SignKeypair::from_ml_dsa_seed(&[0x42; 32]).expect("derive the recipient");
        let conversation = initiate(&shared_secret(0x21), counting_fill(0x11)).expect("initiate");
        let opening = ChannelOpening::build(
            &writer,
            recipient.public_key(),
            &OUTGOING,
            &conversation.ratchet_pk,
            OPENING_SERIAL,
        )
        .expect("sign the opening");

        let state = ConvState {
            peer_identity_pk: Box::new(*recipient.public_key()),
            outgoing_lookup_key: OUTGOING,
            incoming_lookup_key: [0xb1; HELLO_LOOKUP_KEY_LEN],
            generation: 3,
            conversation: conversation.conversation.snapshot(),
            send_seq: 3,
            peer_collected: 1,
            my_collected: MY_COLLECTED,
            cursor_published: MY_COLLECTED,
            awaiting_acceptance: false,
            acceptance_pending: false,
            outstanding_hello: None,
            own_hello_secret: None,
            own_hello_kem_ct: None,
            own_control_key: None,
            peer_control_key: None,
            peer_advert_serial: None,
            own_opening: None,
            delete_pending: false,
        };
        store.create_conv(&peer, &state).expect("create");
        store
            .persist_outbox(&peer, OWED_SEQ, &[0x5f; 64], NOW)
            .expect("persist an owed ciphertext");
        Fixture {
            _tmp: tmp,
            store,
            peer,
            opening,
        }
    }

    /// The path a record kind occupies for one correspondence.
    fn record_path(
        store: &Store,
        peer: &CorrespondenceLabel,
        kind: RecordKind,
    ) -> std::path::PathBuf {
        store
            .records()
            .root()
            .join(hex::encode(peer.as_bytes()))
            .join(kind.file_name())
    }

    /// Whether both of a correspondence's record files are on disk.
    fn records_present(store: &Store, peer: &CorrespondenceLabel) -> (bool, bool) {
        (
            record_path(store, peer, RecordKind::Conversation).exists(),
            record_path(store, peer, RecordKind::ConversationOutbox).exists(),
        )
    }

    // ── the cursor rule ─────────────────────────────────────────────────────

    /// The boundary the whole of delivery turns on: a cursor equal to the
    /// sequence has not reached it, and one above it has.
    #[test]
    fn a_cursor_collects_only_the_sequences_below_it() {
        assert!(
            !collected(5, 5),
            "a cursor equal to the sequence collected it"
        );
        assert!(collected(5, 6), "a cursor one above did not collect it");
        assert!(
            !collected(0, 0),
            "an empty cursor collected the first message"
        );
        // The control at the same boundary: the first cursor a reader can
        // publish does collect sequence 0.
        assert!(collected(0, 1));
    }

    // ── the poll schedule ───────────────────────────────────────────────────

    /// The backoff, read at three ages with the clock paused.
    #[test]
    fn the_poll_backs_off_to_daily_after_seven_days() {
        let since = NOW;
        let at = |age: u64| next_poll_interval(since, since + age, counting_fill(0x33));

        let day_6 = at(6 * DAY);
        assert_ne!(
            day_6, BACKOFF_POLL_INTERVAL,
            "the poll went daily before seven days"
        );
        assert!(
            (POLL_INTERVAL_MIN..=POLL_INTERVAL_MAX).contains(&day_6),
            "day 6 fell outside the normal band: {day_6:?}"
        );

        let just_before = at(7 * DAY - 1);
        assert!(
            (POLL_INTERVAL_MIN..=POLL_INTERVAL_MAX).contains(&just_before),
            "a second before seven days fell outside the normal band: {just_before:?}"
        );

        assert_eq!(
            at(7 * DAY),
            BACKOFF_POLL_INTERVAL,
            "the poll was not daily at seven days"
        );
        assert_eq!(
            at(30 * DAY),
            BACKOFF_POLL_INTERVAL,
            "the poll was not daily at thirty days"
        );
    }

    /// The mirror: a message that has just become outstanding is polled on the
    /// normal band, so the assertion above is about the age and not about the
    /// function always returning one value.
    #[test]
    fn a_fresh_message_is_polled_on_the_normal_band() {
        let fresh = next_poll_interval(NOW, NOW, counting_fill(0x44));
        assert!(
            (POLL_INTERVAL_MIN..=POLL_INTERVAL_MAX).contains(&fresh),
            "a fresh message fell outside the normal band: {fresh:?}"
        );
        assert_ne!(fresh, BACKOFF_POLL_INTERVAL);
        // A clock that has run backwards reads as age zero, not as an age past
        // the backoff.
        let backwards = next_poll_interval(NOW, NOW - 30 * DAY, counting_fill(0x44));
        assert_eq!(backwards, fresh);
    }

    /// The design's own figures, pinned as values rather than against the
    /// constants the schedule returns: an assertion that compares the
    /// function's output to the constant it returns moves both sides at once.
    #[test]
    fn the_poll_intervals_hold_their_design_values() {
        assert_eq!(POLL_INTERVAL_MIN, Duration::from_secs(40 * 60));
        assert_eq!(POLL_INTERVAL_MAX, Duration::from_secs(60 * 60));
        assert_eq!(BACKOFF_POLL_INTERVAL, Duration::from_secs(DAY));
        assert_eq!(BACKOFF_AFTER_SECS, 7 * DAY);
    }

    /// The normal-band interval is drawn from `fill`, so a fixed cadence —
    /// which the band assertions alone would accept — fails here.
    #[test]
    fn the_normal_band_interval_is_drawn_from_fill() {
        let a = next_poll_interval(NOW, NOW, counting_fill(0x01));
        let b = next_poll_interval(NOW, NOW, counting_fill(0x9c));
        assert_ne!(a, b, "the normal-band poll returned a fixed cadence");
        let floor = next_poll_interval(NOW, NOW, |buf: &mut [u8]| {
            buf.fill(0);
            Ok(())
        });
        assert_eq!(
            floor, POLL_INTERVAL_MIN,
            "a zero draw did not sit on the band floor"
        );
    }

    /// A fill that fails degrades to the band's fixed midpoint rather than
    /// refusing to schedule a poll.
    #[test]
    fn a_failing_fill_degrades_to_the_bands_midpoint() {
        let degraded = next_poll_interval(NOW, NOW, |_| Err(()));
        let span = POLL_INTERVAL_MAX.as_millis() as u64 - POLL_INTERVAL_MIN.as_millis() as u64;
        assert_eq!(
            degraded,
            POLL_INTERVAL_MIN + Duration::from_millis(span / 2)
        );
    }

    /// The protocol never gives up: a message outstanding for any length of
    /// time is still polled, daily, and stays owed until a cursor passes it,
    /// with no age entering that decision.
    #[test]
    fn an_outstanding_message_is_polled_and_owed_however_old_it_is() {
        for age in [7 * DAY, 60 * DAY, 365 * DAY, 10 * 365 * DAY] {
            assert_eq!(
                next_poll_interval(NOW, NOW + age, counting_fill(0x55)),
                BACKOFF_POLL_INTERVAL,
                "no daily poll at an age of {} days",
                age / DAY
            );
        }
        assert_eq!(
            next_poll_interval(0, u64::MAX, counting_fill(0x55)),
            BACKOFF_POLL_INTERVAL,
            "no daily poll at the largest age a clock can report"
        );

        let f = fixture();
        let owed = |store: &Store| -> Vec<u64> {
            store.load().expect("load").convs[0]
                .outstanding_outbox
                .iter()
                .map(|entry| entry.seq)
                .collect()
        };
        assert_eq!(
            owed(&f.store),
            vec![OWED_SEQ],
            "control: the message is owed"
        );
        f.store
            .delete_outbox_through(&f.peer, OWED_SEQ)
            .expect("a cursor at the sequence");
        assert_eq!(
            owed(&f.store),
            vec![OWED_SEQ],
            "a cursor equal to the sequence released the message"
        );
        f.store
            .delete_outbox_through(&f.peer, OWED_SEQ + 1)
            .expect("a cursor past the sequence");
        assert!(
            owed(&f.store).is_empty(),
            "a cursor past the sequence did not release the message"
        );
    }

    // ── the age of what is owed ─────────────────────────────────────────────

    /// The oldest uncollected send time is the earliest of the entries still
    /// owed, wherever it sits among them: a collected entry does not count, and
    /// a conversation marked for delete reports none.
    #[test]
    fn the_oldest_uncollected_send_time_is_the_earliest_outstanding_entry() {
        let f = fixture();
        f.store
            .update_conv(&f.peer, |state| state.send_seq = 4)
            .expect("four sequences sent");
        f.store
            .persist_outbox(&f.peer, 1, &[0x51; 64], NOW + 50)
            .expect("persist sequence 1");
        f.store
            .persist_outbox(&f.peer, 3, &[0x53; 64], NOW + 80)
            .expect("persist sequence 3");
        f.store
            .persist_outbox(&f.peer, 0, &[0x50; 64], NOW - 100)
            .expect("persist a sequence the correspondent collected");
        let loaded = || {
            f.store
                .load()
                .expect("load")
                .convs
                .into_iter()
                .next()
                .expect("the conversation")
        };
        let conv = loaded();
        assert_eq!(
            conv.outstanding_outbox
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            vec![1, OWED_SEQ, 3],
            "the control: sequences 1 to 3 are owed, and 0 was collected"
        );
        assert_eq!(
            conv.outstanding_outbox
                .iter()
                .map(|entry| entry.sent_at)
                .collect::<Vec<_>>(),
            vec![NOW + 50, NOW, NOW + 80],
            "the control: the oldest owed entry is neither the first nor the last"
        );
        assert_eq!(
            oldest_uncollected_at(&conv),
            Some(NOW),
            "the oldest owed send time is not the earliest outstanding entry's"
        );

        prepare_delete(&f.store, &f.peer, false).expect("prepare");
        assert_eq!(
            oldest_uncollected_at(&loaded()),
            None,
            "a conversation being deleted reported an age"
        );
    }

    /// The nudge check on explicit times: not due below the threshold, due at
    /// it and above it, never due with nothing owed, and a clock earlier than
    /// the send time reads as age zero.
    #[test]
    fn a_nudge_is_due_at_the_threshold_and_not_before() {
        let threshold = 3 * DAY;
        assert!(
            !nudge_due(Some(NOW), NOW + threshold - 1, threshold),
            "due below the threshold"
        );
        assert!(
            nudge_due(Some(NOW), NOW + threshold, threshold),
            "not due at the threshold"
        );
        assert!(
            nudge_due(Some(NOW), NOW + threshold + 1, threshold),
            "not due above the threshold"
        );
        assert!(
            !nudge_due(None, NOW + 365 * DAY, threshold),
            "due with nothing owed"
        );
        assert!(
            !nudge_due(Some(NOW), NOW - DAY, threshold),
            "a clock earlier than the send time read as an age"
        );
        assert!(
            nudge_due(Some(NOW), NOW - DAY, 0),
            "a threshold of zero was not due on a clock earlier than the send time"
        );
        assert!(
            !nudge_due(Some(u64::MAX - 1), u64::MAX, 2),
            "an age below the threshold at the top of the clock was due"
        );
        assert!(
            nudge_due(Some(u64::MAX - 2), u64::MAX, 2),
            "an age at the threshold at the top of the clock was not due"
        );
    }

    // ── the teardown ────────────────────────────────────────────────────────

    /// Preparing a teardown names the channel and the marker and removes
    /// nothing; finishing it removes both records.
    #[test]
    fn the_records_go_only_once_the_erase_has_been_performed() {
        let f = fixture();
        assert_eq!(records_present(&f.store, &f.peer), (true, true), "control");

        let erase = prepare_delete(&f.store, &f.peer, true).expect("prepare");

        assert_eq!(erase.lookup_key, OUTGOING);
        assert_eq!(
            erase.marker,
            Some(ClosedMarker {
                collected_cursor: MY_COLLECTED
            }),
            "a requested marker did not carry this side's cursor"
        );
        // The control on the order: the caller has not erased anything yet, so
        // the conversation it is about to erase is still readable.
        assert_eq!(
            records_present(&f.store, &f.peer),
            (true, true),
            "prepare_delete removed a record before the erase"
        );
        assert!(
            f.store.load_conv(&f.peer).expect("load_conv").is_some(),
            "prepare_delete dropped the conversation"
        );
        assert_eq!(
            f.store.load().expect("load").convs.len(),
            1,
            "a launch no longer reads a conversation that has not been erased"
        );

        // The marker the transport writes, carrying the opening the caller
        // still holds.
        let control = erase
            .marker
            .expect("the marker")
            .control(Some(f.opening.clone()));
        assert!(control.closed, "the marker's control record was not closed");
        assert_eq!(control.collected_cursor, MY_COLLECTED);
        assert_eq!(
            control.opening.as_ref(),
            Some(&f.opening),
            "the marker dropped the opening the caller passed"
        );

        finish_delete(&f.store, &f.peer).expect("finish");

        assert!(
            f.store.load_conv(&f.peer).expect("load_conv").is_none(),
            "the conversation survived the teardown"
        );
        assert!(
            f.store.load().expect("load").convs.is_empty(),
            "a launch still reads the deleted conversation, so it would still be polled"
        );
        assert_eq!(
            records_present(&f.store, &f.peer),
            (false, false),
            "a record file remains after the teardown"
        );
    }

    /// The erasing case: a marker written as the channel record goes carries
    /// no opening, because the record it opened is going with it.
    #[test]
    fn an_erasing_marker_carries_no_opening() {
        let f = fixture();
        let erase = prepare_delete(&f.store, &f.peer, true).expect("prepare");
        let control = erase.marker.expect("the marker").control(None);
        assert!(control.closed);
        assert_eq!(control.opening, None);
        assert_eq!(control.collected_cursor, MY_COLLECTED);
    }

    /// Without a marker the erase carries none, and the records go all the
    /// same.
    #[test]
    fn a_delete_without_a_marker_carries_none() {
        let f = fixture();

        let erase = prepare_delete(&f.store, &f.peer, false).expect("prepare");
        assert_eq!(erase.lookup_key, OUTGOING);
        assert_eq!(erase.marker, None, "a marker was named unasked");

        finish_delete(&f.store, &f.peer).expect("finish");
        assert!(f.store.load_conv(&f.peer).expect("load_conv").is_none());
        assert_eq!(records_present(&f.store, &f.peer), (false, false));
    }

    /// A correspondence holding no conversation is refused rather than
    /// reported as a teardown of nothing.
    #[test]
    fn preparing_an_unknown_conversation_is_refused() {
        let f = fixture();
        prepare_delete(&f.store, &f.peer, false).expect("prepare");
        finish_delete(&f.store, &f.peer).expect("finish");
        assert!(matches!(
            prepare_delete(&f.store, &f.peer, false),
            Err(StoreError::MissingConversation)
        ));
    }
}
