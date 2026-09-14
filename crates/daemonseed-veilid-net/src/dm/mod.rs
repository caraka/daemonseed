//! Direct messaging over the Veilid distributed hash table.
//!
//! [`records`] implements `daemonseed_core::dm::flows::Records` over real DHT
//! records, and [`runner`] is the task a front end spawns to drive one
//! identity's conversations over that record store.

pub mod records;
pub mod runner;

pub use records::{RecordsError, VeilidRecords, VeilidRecordsParts, WriteCountsSnapshot};
