//! The platform-agnostic vault, crypto, migration, item, and Sync boundary.
//! [`CORE_API_VERSION`] is the compatibility contract: fields are only ever added, never removed or repurposed.

pub mod api;
pub mod backup;
pub mod crypto;
pub mod ffi;
pub mod history;
pub mod imports;
pub mod migration;
pub mod password_analysis;
pub mod pending_import;
pub mod platform;
pub mod record_store;
pub mod snapshot;
pub mod storage;
pub mod throttle;
pub mod trash;
pub mod types;
pub mod util;
pub mod windows_hello;

#[allow(unused_imports)]
pub use backup::*;
#[allow(unused_imports)]
pub use crypto::*;
// `capabilities` stays in the desktop crate: it reaches out over HTTP, which a mobile build would not need.
#[allow(unused_imports)]
pub use history::*;
#[allow(unused_imports)]
pub use imports::*;
#[allow(unused_imports)]
pub use migration::*;
#[allow(unused_imports)]
pub use password_analysis::*;
#[allow(unused_imports)]
pub use pending_import::*;
#[allow(unused_imports)]
pub use platform::*;
#[allow(unused_imports)]
pub use record_store::*;
#[allow(unused_imports)]
pub use snapshot::*;
#[allow(unused_imports)]
pub use storage::*;
#[allow(unused_imports)]
pub use throttle::*;
#[allow(unused_imports)]
pub use trash::*;
#[allow(unused_imports)]
pub use types::*;
#[allow(unused_imports)]
pub use util::*;

use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex,
};

use zeroize::Zeroizing;

pub const CORE_API_VERSION: u32 = 1;

/// The later format generations bind the cleartext format and setup state into the payload AEAD.
pub const VAULT_FORMAT_VERSION: u8 = 10;
pub const WRAP_AAD: &[u8] = b"sesame:wrapped-vault-key:v1";
pub const RECOVERY_WRAP_AAD: &[u8] = b"sesame:recovery-wrapped-vault-key:v1";
pub const PIN_WRAP_AAD: &[u8] = b"sesame:pin-wrapped-vault-key:v1";
pub const LEGACY_PAYLOAD_AAD: &[u8] = b"sesame:vault-payload:v1";
pub const FORMAT_9_PAYLOAD_AAD: &[u8] = b"sesame:vault-payload:format:9";
pub const PENDING_SETUP_PAYLOAD_AAD: &[u8] = b"sesame:vault-payload:format:10:setup:pending";
pub const PAYLOAD_AAD: &[u8] = b"sesame:vault-payload:format:10:setup:complete";
/// CNG key-name prefix; never a secret, names a device-local key.
pub const HELLO_KEY_NAME_PREFIX: &str = "sesame-vault-hello-";
pub const MAX_BACKUP_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_VAULT_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_KDF_MEMORY_KIB: u32 = 1_048_576;
pub const MAX_KDF_ITERATIONS: u32 = 20;
pub const MAX_KDF_PARALLELISM: u32 = 16;
pub const SERVICE_CONNECTION_FORMAT_VERSION: u8 = 1;

pub type VaultResult<T> = Result<T, String>;

/// Every format generation must get its own label here, or header-downgrade ambiguity returns.
pub fn payload_aad_for_file(
    format_version: u8,
    setup_complete: bool,
) -> VaultResult<&'static [u8]> {
    match (format_version, setup_complete) {
        (2..=8, true) => Ok(LEGACY_PAYLOAD_AAD),
        (9, true) => Ok(FORMAT_9_PAYLOAD_AAD),
        (VAULT_FORMAT_VERSION, false) => Ok(PENDING_SETUP_PAYLOAD_AAD),
        (VAULT_FORMAT_VERSION, true) => Ok(PAYLOAD_AAD),
        _ => Err("This vault uses a format Sesame does not understand yet.".into()),
    }
}

pub struct VaultState {
    pub session: Mutex<Option<UnlockedVault>>,
    /// Parsed import entries; never reach the interface, dropped on lock.
    pub pending_import: Mutex<Option<pending_import::PendingImport>>,
    pub pin_guard: Mutex<throttle::PinAttemptGuard>,
    pin_status_loaded: AtomicBool,
    pin_throttle_loaded: AtomicBool,
    pin_unlock_available: AtomicBool,
    hello_status_loaded: AtomicBool,
    hello_unlock_available: AtomicBool,
    auto_lock_minutes: AtomicU64,
    session_epoch: AtomicU64,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            session: Mutex::new(None),
            pending_import: Mutex::new(None),
            pin_guard: Mutex::new(throttle::PinAttemptGuard::default()),
            pin_status_loaded: AtomicBool::new(false),
            pin_throttle_loaded: AtomicBool::new(false),
            pin_unlock_available: AtomicBool::new(false),
            hello_status_loaded: AtomicBool::new(false),
            hello_unlock_available: AtomicBool::new(false),
            auto_lock_minutes: AtomicU64::new(5),
            session_epoch: AtomicU64::new(1),
        }
    }
}

impl VaultState {
    /// Monotonic: an approval cannot survive a lock, restore, deletion, or re-unlock.
    pub fn session_epoch(&self) -> u64 {
        self.session_epoch.load(Ordering::Acquire)
    }

    pub fn advance_session_epoch(&self) -> u64 {
        self.session_epoch.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn cached_pin_unlock(&self) -> Option<bool> {
        self.pin_status_loaded
            .load(Ordering::Acquire)
            .then(|| self.pin_unlock_available.load(Ordering::Acquire))
    }

    pub fn cache_pin_unlock(&self, available: bool) {
        self.pin_unlock_available
            .store(available, Ordering::Release);
        self.pin_status_loaded.store(true, Ordering::Release);
    }

    pub fn pin_throttle_loaded(&self) -> bool {
        self.pin_throttle_loaded.load(Ordering::Acquire)
    }

    pub fn mark_pin_throttle_loaded(&self) {
        self.pin_throttle_loaded.store(true, Ordering::Release);
    }

    pub fn cached_hello_unlock(&self) -> Option<bool> {
        self.hello_status_loaded
            .load(Ordering::Acquire)
            .then(|| self.hello_unlock_available.load(Ordering::Acquire))
    }

    pub fn cache_hello_unlock(&self, available: bool) {
        self.hello_unlock_available
            .store(available, Ordering::Release);
        self.hello_status_loaded.store(true, Ordering::Release);
    }

    pub fn discard_pending_import(&self) {
        if let Ok(mut pending) = self.pending_import.lock() {
            *pending = None;
        }
    }

    pub fn auto_lock_minutes(&self) -> u64 {
        self.auto_lock_minutes.load(Ordering::Acquire)
    }

    pub fn set_auto_lock_minutes(&self, minutes: u64) {
        self.auto_lock_minutes.store(minutes, Ordering::Release);
    }

    /// Held across file replacement, serializes against every other mutation command.
    pub fn begin_destructive_lifecycle_change(
        &self,
    ) -> VaultResult<std::sync::MutexGuard<'_, Option<UnlockedVault>>> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| "Sesame could not close the current vault session.".to_string())?;
        *session = None;
        self.discard_pending_import();
        self.advance_session_epoch();
        Ok(session)
    }

    pub fn lock_for_lifecycle(&self) -> VaultResult<()> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| "Sesame could not lock the vault session.".to_string())?;
        *session = None;
        drop(session);
        // Parsed import entries are secrets; they never outlive an unlocked vault.
        self.discard_pending_import();
        self.advance_session_epoch();
        Ok(())
    }
}

pub struct UnlockedVault {
    pub path: PathBuf,
    pub key: Zeroizing<[u8; 32]>,
    pub kdf: KdfParams,
    pub key_wrap: CipherBlob,
    pub legacy_device_wrap: Option<String>,
    pub recovery_kdf: Option<KdfParams>,
    pub recovery_wrap: Option<CipherBlob>,
    pub pin_wrap: Option<PinWrap>,
    pub hello_wrap: Option<HelloWrap>,
    pub setup_complete: bool,
    records: record_store::VaultRecordStore,
}

impl UnlockedVault {
    pub fn from_opened(path: PathBuf, opened: &api::OpenedVault) -> VaultResult<Self> {
        Ok(Self {
            path,
            key: opened.key.clone(),
            kdf: opened.file.kdf.clone(),
            key_wrap: opened.file.key_wrap.clone(),
            legacy_device_wrap: opened.file.legacy_device_wrap.clone(),
            recovery_kdf: opened.file.recovery_kdf.clone(),
            recovery_wrap: opened.file.recovery_wrap.clone(),
            pin_wrap: opened.file.pin_wrap.clone(),
            hello_wrap: opened.file.hello_wrap.clone(),
            setup_complete: opened.file.setup_complete,
            records: record_store::VaultRecordStore::from_payload(&opened.payload)?,
        })
    }

    pub fn open_payload(&self) -> VaultResult<record_store::OpenedPayload> {
        self.records.open_payload()
    }

    pub fn open_item(&self, id: &str) -> VaultResult<record_store::OpenedItem> {
        self.records.open_item(id)
    }

    pub fn snapshot(&self) -> VaultSnapshot {
        self.records.snapshot()
    }

    pub fn trash_item_preview(&self, id: &str) -> VaultResult<ItemPreview> {
        self.records.trash_item_preview(id)
    }

    pub fn history_item_preview(&self, id: &str) -> VaultResult<ItemPreview> {
        self.records.history_item_preview(id)
    }
}
