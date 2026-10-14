//! Reusable HTTP clients and remote-service protocol adapters.

pub(crate) mod account_api;
pub(crate) mod account_service;
pub(crate) mod breach;
pub(crate) mod capabilities;
pub(crate) mod public_updates;
pub(crate) mod server_address;
pub(crate) mod server_trust;
#[cfg(feature = "sync-preview")]
pub(crate) mod sync;
#[cfg(test)]
pub(crate) mod test_server;
pub(crate) mod trusted_time;
pub(crate) mod website_icons;

pub(crate) fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
