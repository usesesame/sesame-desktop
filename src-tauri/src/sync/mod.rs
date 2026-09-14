//! Sesame Sync client; not enabled, and the service refuses every route while `cloud_sync_available` is false.
//! Vaults are encrypted here and only ciphertext leaves; nothing here returns key material or reaches the webview.

pub mod envelope;
pub mod identity;
pub mod keys;
pub mod state;

/// Compiled only under `sync-preview`: a release binary has no Sync code path at all.
#[cfg(feature = "sync-preview")]
pub(crate) use crate::adapters::network::sync as client;
/// Reachable only through Sync commands, so these compile only where those commands do.
#[cfg(feature = "sync-preview")]
pub mod conflict_backup;
#[cfg(feature = "sync-preview")]
pub mod coordinator;
#[cfg(feature = "sync-preview")]
pub mod peers;

#[cfg(test)]
pub(crate) fn contract_fixture(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("contracts")
        .join("sync")
        .join("v2")
        .join(name);
    let bytes = std::fs::read(&path).expect("read the cross-language Sync fixture");
    serde_json::from_slice(&bytes).expect("parse the cross-language Sync fixture")
}
