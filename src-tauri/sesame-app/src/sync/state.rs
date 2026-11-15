use std::collections::BTreeMap;
use std::path::Path;

use sesame_core::VaultResult;

use super::protection::DEVICE_PROTECTOR;

pub use sesame_sync::state::*;

pub trait StateNames {
    fn remembered_names(&self) -> BTreeMap<String, String>;
    fn remember_names(&mut self, names: &BTreeMap<String, String>) -> VaultResult<()>;
}

impl StateNames for SyncState {
    fn remembered_names(&self) -> BTreeMap<String, String> {
        self.remembered_names_with(&DEVICE_PROTECTOR)
    }

    fn remember_names(&mut self, names: &BTreeMap<String, String>) -> VaultResult<()> {
        self.remember_names_with(names, &DEVICE_PROTECTOR)
    }
}

pub fn read_tagged(path: &Path, label: &[u8]) -> Option<Vec<u8>> {
    read_tagged_with(path, label, &DEVICE_PROTECTOR)
}

pub fn write_tagged(path: &Path, label: &[u8], body: &[u8]) -> VaultResult<()> {
    write_tagged_with(path, label, body, &DEVICE_PROTECTOR)
}

pub fn write_protected(path: &Path, base: &SyncState) -> VaultResult<()> {
    write_protected_with(path, base, &DEVICE_PROTECTOR)
}

pub fn read_protected(path: &Path) -> Option<SyncState> {
    read_protected_with(path, &DEVICE_PROTECTOR)
}
