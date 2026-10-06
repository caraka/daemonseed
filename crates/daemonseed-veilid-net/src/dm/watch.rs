//! Watches on the channel records this node reads.
//!
//! A correspondent writes its side of a conversation to a channel record this
//! node opens read-only. A Veilid watch on that record has the node told of
//! every change to it through the update callback, with the new value inside
//! the report where one subkey changed. `ChannelWatches` is the map from a
//! watched record to the lookup key its conversation names that record by,
//! held once per node and shared by the record store, which registers the
//! watches, and the update callback, which hands each change on a watched
//! record to the direct-messaging inbox as a [`PushInbound::Changed`] and to
//! nothing else. A change on any other record goes to the rendezvous
//! mapping.
//!
//! A record whose watch was cancelled stays known for `RETIRED_FOR` after,
//! so a change Veilid reported before the cancel took effect is dropped here
//! rather than reaching the rendezvous mapping as a record of its own.
//!
//! Only records this node reads are watched: this node writes its own
//! channels, so a change to one is never news to it. One watch
//! is registered per record, over every subkey, because Veilid holds one watch
//! per record and the control subkey and the message slots change alike.
//!
//! Registration can be turned off for a run by setting [`WATCH_OFF_ENV`] to
//! `1` before the node starts. Nothing is registered then, so every change
//! reaches this node only by a push or by a read the schedule makes, which is
//! how the delivery a watch adds is measured against the delivery without it.
//! The variable is read once, when the node starts, and a trace line says it
//! is set.
//!
//! Serves FC7.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use daemonseed_core::dm::drop::HELLO_LOOKUP_KEY_LEN;
use veilid_core::{RecordKey, VeilidValueChange};

use crate::dm::push::PushInbound;

/// How long a record stays known after its watch is cancelled, during which a
/// change reported on it is dropped.
pub(crate) const RETIRED_FOR: Duration = Duration::from_secs(300);

/// The most records known as cancelled at once; the one cancelled longest ago
/// gives way to a newer one.
pub(crate) const RETIRED_MAX: usize = 256;

/// The environment variable that, set to `1` before the node starts, turns
/// channel watch registration off for the whole run.
pub const WATCH_OFF_ENV: &str = "DAEMONSEED_DM_WATCH_OFF";

/// Whether a value of [`WATCH_OFF_ENV`] turns registration off: exactly `1`.
pub(crate) fn off_from(value: Option<&str>) -> bool {
    value == Some("1")
}

/// Whether [`WATCH_OFF_ENV`] turns registration off for this process.
pub(crate) fn off_from_env() -> bool {
    off_from(std::env::var(WATCH_OFF_ENV).ok().as_deref())
}

/// The first two bytes of a lookup key in hex, which is how a trace names a
/// watched channel.
pub(crate) fn channel_tag(lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN]) -> String {
    let [a, b, ..] = *lookup_key;
    format!("{a:02x}{b:02x}")
}

/// The watched channel records of one node, by record, and whether
/// registration is on.
///
/// `K` is the record's address: a Veilid [`RecordKey`] on a node, and any
/// other key a record store without a node addresses its records by.
#[derive(Debug)]
pub(crate) struct ChannelWatches<K> {
    watched: Arc<Mutex<HashMap<K, [u8; HELLO_LOOKUP_KEY_LEN]>>>,
    /// Records whose watch was cancelled, and when.
    retired: Arc<Mutex<HashMap<K, Instant>>>,
    off: bool,
}

impl<K> Clone for ChannelWatches<K> {
    fn clone(&self) -> Self {
        Self {
            watched: Arc::clone(&self.watched),
            retired: Arc::clone(&self.retired),
            off: self.off,
        }
    }
}

impl<K: Eq + Hash + Clone> ChannelWatches<K> {
    /// An empty map; `off` turns registration off.
    pub(crate) fn new(off: bool) -> Self {
        Self {
            watched: Arc::default(),
            retired: Arc::default(),
            off,
        }
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<K, [u8; HELLO_LOOKUP_KEY_LEN]>> {
        self.watched.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn retired(&self) -> std::sync::MutexGuard<'_, HashMap<K, Instant>> {
        self.retired.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether registration is off.
    pub(crate) fn is_off(&self) -> bool {
        self.off
    }

    /// Whether a channel record just opened is to be watched: registration is
    /// on, the record is not one this node owns, and it is not watched yet.
    pub(crate) fn wants(&self, record: &K, own: bool) -> bool {
        !own && !self.off && !self.map().contains_key(record)
    }

    /// Note `record`, read under `lookup_key`, as watched.
    pub(crate) fn registered(&self, record: K, lookup_key: [u8; HELLO_LOOKUP_KEY_LEN]) {
        self.retired().remove(&record);
        self.map().insert(record, lookup_key);
        let short = channel_tag(&lookup_key);
        crate::vtrace!("dm watch: registered {short}");
    }

    /// Note the watch on the record read under `lookup_key` registered again.
    pub(crate) fn reregistered(&self, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN]) {
        let short = channel_tag(lookup_key);
        crate::vtrace!("dm watch: re-registered {short}");
    }

    /// The watched record read under `lookup_key`, if one is.
    pub(crate) fn record_of(&self, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN]) -> Option<K> {
        self.map()
            .iter()
            .find(|(_, key)| *key == lookup_key)
            .map(|(record, _)| record.clone())
    }

    /// The lookup key a watched `record` is read under, if it is watched.
    pub(crate) fn lookup_of(&self, record: &K) -> Option<[u8; HELLO_LOOKUP_KEY_LEN]> {
        self.map().get(record).copied()
    }

    /// Stop treating the record read under `lookup_key` as watched, returning
    /// it where it was. The record is known as cancelled for [`RETIRED_FOR`].
    pub(crate) fn forget(&self, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN]) -> Option<K> {
        self.forget_at(lookup_key, Instant::now())
    }

    fn forget_at(&self, lookup_key: &[u8; HELLO_LOOKUP_KEY_LEN], now: Instant) -> Option<K> {
        let record = self.record_of(lookup_key)?;
        self.map().remove(&record);
        {
            let mut retired = self.retired();
            retired.retain(|_, at| now.saturating_duration_since(*at) < RETIRED_FOR);
            if retired.len() >= RETIRED_MAX {
                let oldest = retired
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(record, _)| record.clone());
                if let Some(oldest) = oldest {
                    retired.remove(&oldest);
                }
            }
            retired.insert(record.clone(), now);
        }
        let short = channel_tag(lookup_key);
        crate::vtrace!("dm watch: removed {short}");
        Some(record)
    }

    /// Whether the watch on `record` was cancelled less than [`RETIRED_FOR`]
    /// before `now`.
    fn is_retired_at(&self, record: &K, now: Instant) -> bool {
        self.retired()
            .get(record)
            .is_some_and(|at| now.saturating_duration_since(*at) < RETIRED_FOR)
    }

    /// How many records are watched.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map().len()
    }
}

/// The inbox entry a value change on a watched channel record becomes, `None`
/// where the record's watch was cancelled less than [`RETIRED_FOR`] ago, or
/// the change itself where its record is neither.
///
/// The value is passed on as Veilid reports it: present only for the first
/// subkey, and only where a single subkey changed. An empty subkey set or a
/// remaining count of zero is Veilid reporting that the watch died.
pub(crate) fn claim(
    watches: &ChannelWatches<RecordKey>,
    change: Box<VeilidValueChange>,
) -> Result<Option<PushInbound>, Box<VeilidValueChange>> {
    let Some(lookup_key) = watches.lookup_of(&change.key) else {
        if watches.is_retired_at(&change.key, Instant::now()) {
            crate::vtrace!("dm watch: a change on a channel no longer watched, dropped");
            return Ok(None);
        }
        return Err(change);
    };
    Ok(Some(PushInbound::Changed {
        lookup_key,
        first_subkey: change.subkeys.nth_subkey(0).unwrap_or(0),
        single: change.subkeys.len() == 1,
        dead: change.subkeys.is_empty() || change.count == 0,
        value: change
            .value
            .map(|value| (u32::from(value.seq()), value.data().to_vec())),
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use veilid_core::{
        BareOpaqueRecordKey, BarePublicKey, BareRecordKey, PublicKey, ValueData,
        ValueSubkeyRangeSet, CRYPTO_KIND_VLD0,
    };

    /// A record key made from one byte.
    pub(crate) fn record(byte: u8) -> RecordKey {
        RecordKey::new(
            CRYPTO_KIND_VLD0,
            BareRecordKey::new(BareOpaqueRecordKey::new(&[byte; 32]), None),
        )
    }

    /// A change on `key` naming `subkeys`, with `count` left, carrying `value`
    /// at sequence 7.
    pub(crate) fn change(
        key: RecordKey,
        subkeys: ValueSubkeyRangeSet,
        count: u32,
        value: Option<&[u8]>,
    ) -> Box<VeilidValueChange> {
        Box::new(VeilidValueChange {
            key,
            subkeys,
            count,
            value: value.map(|bytes| {
                ValueData::new_with_seq(
                    7.into(),
                    bytes.to_vec(),
                    PublicKey::new(CRYPTO_KIND_VLD0, BarePublicKey::new(&[9; 32])),
                )
                .expect("a value")
            }),
        })
    }

    #[test]
    fn only_exactly_one_turns_registration_off() {
        assert!(off_from(Some("1")));
        for value in [None, Some(""), Some("0"), Some("true"), Some("11")] {
            assert!(!off_from(value), "{value:?}");
        }
    }

    #[test]
    fn a_record_is_wanted_once_and_never_when_own_or_off() {
        let watches = ChannelWatches::<u8>::new(false);
        assert!(watches.wants(&1, false), "a record read and not watched");
        assert!(!watches.wants(&1, true), "a record this node owns");
        watches.registered(1, [1; HELLO_LOOKUP_KEY_LEN]);
        assert!(!watches.wants(&1, false), "a record already watched");
        assert!(watches.wants(&2, false), "another record");
        let off = ChannelWatches::<u8>::new(true);
        assert!(off.is_off());
        assert!(!off.wants(&1, false), "registration off");
    }

    #[test]
    fn a_forgotten_channel_is_no_longer_watched() {
        let watches = ChannelWatches::<u8>::new(false);
        watches.registered(1, [1; HELLO_LOOKUP_KEY_LEN]);
        watches.registered(2, [2; HELLO_LOOKUP_KEY_LEN]);
        assert_eq!(watches.len(), 2);
        assert_eq!(watches.record_of(&[1; HELLO_LOOKUP_KEY_LEN]), Some(1));
        assert_eq!(watches.forget(&[1; HELLO_LOOKUP_KEY_LEN]), Some(1));
        assert_eq!(watches.len(), 1);
        assert_eq!(watches.lookup_of(&1), None);
        assert_eq!(watches.lookup_of(&2), Some([2; HELLO_LOOKUP_KEY_LEN]));
        assert_eq!(watches.forget(&[1; HELLO_LOOKUP_KEY_LEN]), None);
    }

    #[test]
    fn a_forgotten_record_is_known_as_cancelled_for_a_while_and_within_a_bound() {
        let watches = ChannelWatches::<u16>::new(false);
        let start = Instant::now();
        watches.registered(1, [1; HELLO_LOOKUP_KEY_LEN]);
        assert!(!watches.is_retired_at(&1, start), "a watched record");
        assert_eq!(
            watches.forget_at(&[1; HELLO_LOOKUP_KEY_LEN], start),
            Some(1)
        );
        assert!(watches.is_retired_at(&1, start + RETIRED_FOR / 2));
        assert!(!watches.is_retired_at(&1, start + RETIRED_FOR), "expired");
        watches.registered(1, [1; HELLO_LOOKUP_KEY_LEN]);
        assert!(
            !watches.is_retired_at(&1, start),
            "a record watched again is not cancelled"
        );

        let max = u16::try_from(RETIRED_MAX).expect("a small bound");
        for record in 2..max + 3 {
            let mut lookup_key = [0; HELLO_LOOKUP_KEY_LEN];
            lookup_key[..2].copy_from_slice(&record.to_be_bytes());
            watches.registered(record, lookup_key);
            let at = start + Duration::from_millis(u64::from(record));
            assert_eq!(watches.forget_at(&lookup_key, at), Some(record));
        }
        let now = start + Duration::from_secs(1);
        assert_eq!(
            watches.retired().len(),
            RETIRED_MAX,
            "held within the bound"
        );
        assert!(!watches.is_retired_at(&2, now), "the oldest gave way");
        assert!(watches.is_retired_at(&(max + 2), now), "the newest is held");
    }

    #[test]
    fn a_change_on_a_watched_record_is_claimed_with_its_shape() {
        let watches = ChannelWatches::new(false);
        let lookup_key = [3; HELLO_LOOKUP_KEY_LEN];
        watches.registered(record(3), lookup_key);

        let single = claim(
            &watches,
            change(record(3), ValueSubkeyRangeSet::single(5), 10, Some(b"slot")),
        );
        let Ok(Some(PushInbound::Changed {
            lookup_key: claimed,
            first_subkey,
            single,
            dead,
            value,
        })) = single
        else {
            panic!("a watched record's change is claimed: {single:?}");
        };
        assert_eq!(claimed, lookup_key);
        assert_eq!(first_subkey, 5);
        assert!(single && !dead);
        assert_eq!(value, Some((7, b"slot".to_vec())));

        let several = claim(
            &watches,
            change(record(3), ValueSubkeyRangeSet::single_range(2, 4), 10, None),
        );
        assert!(
            matches!(
                several,
                Ok(Some(PushInbound::Changed {
                    first_subkey: 2,
                    single: false,
                    dead: false,
                    value: None,
                    ..
                }))
            ),
            "{several:?}"
        );

        for (subkeys, count) in [
            (ValueSubkeyRangeSet::new(), 10),
            (ValueSubkeyRangeSet::single(0), 0),
        ] {
            let died = claim(&watches, change(record(3), subkeys, count, None));
            assert!(
                matches!(died, Ok(Some(PushInbound::Changed { dead: true, .. }))),
                "{died:?}"
            );
        }
    }

    #[test]
    fn a_change_on_an_unwatched_record_is_handed_back_whole() {
        let watches = ChannelWatches::new(false);
        watches.registered(record(3), [3; HELLO_LOOKUP_KEY_LEN]);
        let unclaimed = claim(
            &watches,
            change(
                record(4),
                ValueSubkeyRangeSet::single(1),
                10,
                Some(b"lobby"),
            ),
        );
        let Err(back) = unclaimed else {
            panic!("an unwatched record's change is not claimed: {unclaimed:?}");
        };
        assert_eq!(back.key, record(4));
        assert_eq!(
            back.value.map(|v| v.data().to_vec()),
            Some(b"lobby".to_vec())
        );
    }
}
