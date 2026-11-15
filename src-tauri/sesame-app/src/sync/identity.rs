use std::path::Path;

use sesame_core::VaultResult;

use super::protection::DEVICE_PROTECTOR;

pub use sesame_sync::identity::*;

pub trait IdentityFiles {
    fn save(&self, path: &Path) -> VaultResult<()>;
    fn load(path: &Path) -> VaultResult<Self>
    where
        Self: Sized;
}

impl IdentityFiles for DeviceIdentity {
    fn save(&self, path: &Path) -> VaultResult<()> {
        self.save_with(path, &DEVICE_PROTECTOR)
    }

    fn load(path: &Path) -> VaultResult<Self> {
        DeviceIdentity::load_with(path, &DEVICE_PROTECTOR)
    }
}

pub fn load_or_create(path: &Path) -> VaultResult<DeviceIdentity> {
    sesame_sync::identity::load_or_create_with(path, &DEVICE_PROTECTOR)
}
