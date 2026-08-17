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
