//! The platform-independent half of the vault boundary; AppHandle-to-path resolution stays in the desktop crate.

pub mod recovery_health;
pub mod storage;

#[allow(unused_imports)]
pub use sesame_core::backup;
#[allow(unused_imports)]
pub use sesame_core::crypto;
#[allow(unused_imports)]
pub use sesame_core::history;
#[allow(unused_imports)]
pub use sesame_core::imports;
#[allow(unused_imports)]
pub use sesame_core::migration;
#[allow(unused_imports)]
pub use sesame_core::password_analysis;
#[allow(unused_imports)]
pub use sesame_core::pending_import;
#[allow(unused_imports)]
pub use sesame_core::platform;
#[allow(unused_imports)]
pub use sesame_core::snapshot;
#[allow(unused_imports)]
pub use sesame_core::throttle;
#[allow(unused_imports)]
pub use sesame_core::trash;
#[allow(unused_imports)]
pub use sesame_core::types;
#[allow(unused_imports)]
pub use sesame_core::util;
#[allow(unused_imports)]
pub use sesame_core::windows_hello;

#[allow(unused_imports)]
pub use sesame_core::backup::*;
#[allow(unused_imports)]
pub use sesame_core::crypto::*;
#[allow(unused_imports)]
pub use sesame_core::history::*;
#[allow(unused_imports)]
pub use sesame_core::imports::*;
#[allow(unused_imports)]
pub use sesame_core::migration::*;
#[allow(unused_imports)]
pub use sesame_core::password_analysis::*;
#[allow(unused_imports)]
pub use sesame_core::pending_import::*;
#[allow(unused_imports)]
pub use sesame_core::platform::*;
#[allow(unused_imports)]
pub use sesame_core::snapshot::*;
#[allow(unused_imports)]
pub use sesame_core::throttle::*;
#[allow(unused_imports)]
pub use sesame_core::trash::*;
#[allow(unused_imports)]
pub use sesame_core::types::*;
#[allow(unused_imports)]
pub use sesame_core::util::*;
#[allow(unused_imports)]
pub use storage::*;

#[allow(unused_imports)]
pub use sesame_core::{
    payload_aad_for_file, HelloWrap, PinWrap, UnlockedVault, VaultKey, VaultResult, VaultState,
    FORMAT_9_PAYLOAD_AAD, HELLO_KEY_NAME_PREFIX, LEGACY_PAYLOAD_AAD, MAX_BACKUP_BYTES,
    MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB, MAX_KDF_PARALLELISM, MAX_VAULT_FILE_BYTES, PAYLOAD_AAD,
    PENDING_SETUP_PAYLOAD_AAD, PIN_WRAP_AAD, RECOVERY_WRAP_AAD, SERVICE_CONNECTION_FORMAT_VERSION,
    VAULT_FORMAT_VERSION, WRAP_AAD,
};
