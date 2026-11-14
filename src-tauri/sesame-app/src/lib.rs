//! The Sesame application rules, shared by any interface that can supply their desktop effects.

#![cfg_attr(
    any(test, feature = "test-support"),
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod application;
pub mod browser_protocol;
pub mod network;
pub mod release;
pub mod session_activity;
pub mod sync;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod vault;
