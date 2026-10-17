//! Vaults are encrypted here and only ciphertext leaves; nothing here returns key material or reaches the webview.

pub mod canonical;
pub mod checkpoint;
pub mod devicelist;
pub mod engine;
pub mod floor;
pub mod header;
pub mod identity;
pub mod keys;
pub mod pairing;
pub mod pake;
pub mod request;
pub mod state;

pub(crate) use crate::adapters::network::sync as client;
pub mod conflict_backup;
pub mod coordinator;

#[cfg(any(test, fuzzing))]
pub mod fuzz_entry;

#[cfg(test)]
mod fuzz_entry_tests;

#[cfg(test)]
mod v3_contract_tests;

#[cfg(test)]
mod engine_tests;

#[cfg(test)]
mod e2e_tests;
