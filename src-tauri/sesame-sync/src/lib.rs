#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod canonical;
pub mod capabilities;
pub mod checkpoint;
pub mod conflict_backup;
pub mod coordinator;
pub mod devicelist;
pub mod engine;
pub mod floor;
pub mod flow;
pub mod header;
pub mod identity;
pub mod key_change;
pub mod keys;
pub mod pairing;
pub mod pake;
pub mod platform;
pub mod protection;
pub mod rekey_journal;
pub mod request;
pub mod server_address;
pub mod server_trust;
pub mod state;
pub mod version;
pub mod wire;
pub mod xwing;

pub use platform::{ANDROID_PLATFORM, DESKTOP_PLATFORM};
pub use protection::DeviceProtector;

#[cfg(any(test, fuzzing, feature = "fuzz-entry"))]
pub mod fuzz_entry;

#[cfg(test)]
mod engine_tests;

#[cfg(test)]
mod fuzz_entry_tests;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod v3_contract_tests;
