//! The DHT seam the DM driver runs against.
//!
//! Production is [`VeilidNetHandle`], each method forwarding to the handle method
//! of the same name; the oracle is a counting mock, so the whole driver runs in
//! paused time with no live DHT.

use std::future::Future;
use std::pin::Pin;

use daemonseed_core::dm::ack_record::DmAckAddress;
use daemonseed_core::dm::paging::{DmPageAddress, Receiving, Sending};

use crate::actor::{DmPageSweep, DoorbellDispatch, DoorbellSweep, VeilidNetHandle};
use crate::Result;

/// The future one [`DmDht`] call returns: owns its inputs and is `'static`, so the
/// driver shell spawns it off its loop exactly as the scheduler spawns a
/// [`crate::schedule::DispatchFuture`].
pub type DmDhtFuture<T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'static>>;

/// The seam over the DHT operations the DM driver performs.
///
/// Signatures are [`VeilidNetHandle`]'s verbatim. The address types carry the
/// conversation's write capability as a boxed zeroizing seed and are neither
/// `Clone` nor constructible from bytes outside `daemonseed_core::dm::paging`, so
/// a narrowed seam could only be honoured by copying the secret out (#244).
///
/// `publish_dm_key_record` is deliberately absent: both front ends already spawn
/// that write at connect through [`crate::dm::spawn_dm_key_record_publish`], and
/// putting it here would give one write two production owners.
pub trait DmDht: Send + Sync + 'static {
    /// Fetch a correspondent's key record; `Ok(None)` is the awaiting-key state.
    fn fetch_dm_key_record(&self, owner_seed: [u8; 32]) -> DmDhtFuture<Option<Vec<u8>>>;

    /// Knock: write one sealed first-contact entry into `slot` of a recipient's
    /// doorbell.
    fn publish_doorbell_entry(
        &self,
        owner_seed: [u8; 32],
        slot: u16,
        entry: Vec<u8>,
        dispatch: DoorbellDispatch,
    ) -> DmDhtFuture<()>;

    /// Sweep our own doorbell; empty is ordinary, `outcome.failed > 0` is record
    /// health.
    fn sweep_doorbell(&self, owner_seed: [u8; 32]) -> DmDhtFuture<DoorbellSweep>;

    /// Publish one sealed channel frame at the slot the address names.
    fn publish_dm_page(&self, address: DmPageAddress<Sending>, frame: Vec<u8>) -> DmDhtFuture<()>;

    /// Sweep one receiving page; empty is the ordinary state of an unwritten page.
    fn sweep_dm_page(&self, address: DmPageAddress<Receiving>) -> DmDhtFuture<DmPageSweep>;

    /// Publish one direction's acknowledgement record.
    fn publish_dm_ack(&self, address: DmAckAddress, record: Vec<u8>) -> DmDhtFuture<()>;

    /// Fetch the correspondent's acknowledgement; `Ok(None)` is no confirmation yet.
    fn fetch_dm_ack(&self, address: DmAckAddress) -> DmDhtFuture<Option<Vec<u8>>>;
}

/// The production seam. Each method clones the handle into the returned future,
/// which is what makes the future `'static` and therefore spawnable off the loop.
impl DmDht for VeilidNetHandle {
    fn fetch_dm_key_record(&self, owner_seed: [u8; 32]) -> DmDhtFuture<Option<Vec<u8>>> {
        let h = self.clone();
        Box::pin(async move { h.fetch_dm_key_record(owner_seed).await })
    }

    fn publish_doorbell_entry(
        &self,
        owner_seed: [u8; 32],
        slot: u16,
        entry: Vec<u8>,
        dispatch: DoorbellDispatch,
    ) -> DmDhtFuture<()> {
        let h = self.clone();
        Box::pin(async move {
            h.publish_doorbell_entry(owner_seed, slot, entry, dispatch)
                .await
        })
    }

    fn sweep_doorbell(&self, owner_seed: [u8; 32]) -> DmDhtFuture<DoorbellSweep> {
        let h = self.clone();
        Box::pin(async move { h.sweep_doorbell(owner_seed).await })
    }

    fn publish_dm_page(&self, address: DmPageAddress<Sending>, frame: Vec<u8>) -> DmDhtFuture<()> {
        let h = self.clone();
        Box::pin(async move { h.publish_dm_page(address, frame).await })
    }

    fn sweep_dm_page(&self, address: DmPageAddress<Receiving>) -> DmDhtFuture<DmPageSweep> {
        let h = self.clone();
        Box::pin(async move { h.sweep_dm_page(address).await })
    }

    fn publish_dm_ack(&self, address: DmAckAddress, record: Vec<u8>) -> DmDhtFuture<()> {
        let h = self.clone();
        Box::pin(async move { h.publish_dm_ack(address, record).await })
    }

    fn fetch_dm_ack(&self, address: DmAckAddress) -> DmDhtFuture<Option<Vec<u8>>> {
        let h = self.clone();
        Box::pin(async move { h.fetch_dm_ack(address).await })
    }
}
