//! Reusable HTTP clients and remote-service protocol adapters.

pub mod account_service;
pub mod breach;
pub mod capabilities;
pub mod server_address;
pub mod server_trust;
pub mod time;

#[cfg(any(test, feature = "test-support"))]
pub mod test_server;

pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
