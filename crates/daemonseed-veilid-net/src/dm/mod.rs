//! Direct messaging over the Veilid distributed hash table.
//!
//! [`records`] implements `daemonseed_core::dm::flows::Records` over real DHT
//! records, [`runner`] is the task a front end spawns to drive one identity's
//! conversations over that record store, and [`view`] folds what the runner
//! reports into the state a front end draws.

pub mod records;
pub mod runner;
pub mod view;

pub use records::{RecordsError, VeilidRecords, VeilidRecordsParts, WriteCountsSnapshot};
