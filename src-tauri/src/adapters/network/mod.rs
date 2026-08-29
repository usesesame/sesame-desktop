//! Reusable HTTP clients and remote-service protocol adapters.

pub(crate) mod account_api;
pub(crate) mod account_service;
pub(crate) mod breach;
pub(crate) mod capabilities;
pub(crate) mod public_updates;
#[cfg(feature = "sync-preview")]
pub(crate) mod sync;
pub(crate) mod website_icons;

pub(crate) fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
