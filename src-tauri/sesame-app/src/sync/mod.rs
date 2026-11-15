//! Vaults are encrypted here and only ciphertext leaves; nothing here returns key material or reaches the webview.

pub mod conflict_backup;
pub mod floor;
pub mod identity;
pub mod rekey_journal;
pub mod state;

pub use sesame_sync::{
    canonical, checkpoint, coordinator, devicelist, engine, header, key_change, keys, pairing,
    pake, request, xwing,
};

mod protection;

pub mod client;

#[cfg(test)]
mod e2e_tests;
