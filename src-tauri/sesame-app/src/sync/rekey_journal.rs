use std::path::Path;

use sesame_core::VaultResult;

use super::protection::DEVICE_PROTECTOR;

pub use sesame_sync::rekey_journal::*;

pub trait JournalFiles {
    fn save(&self, path: &Path) -> VaultResult<()>;
    fn load(path: &Path) -> VaultResult<Self>
    where
        Self: Sized;
}

impl JournalFiles for Journal {
    fn save(&self, path: &Path) -> VaultResult<()> {
        self.save_with(path, &DEVICE_PROTECTOR)
    }

    fn load(path: &Path) -> VaultResult<Self> {
        Journal::load_with(path, &DEVICE_PROTECTOR)
    }
}
