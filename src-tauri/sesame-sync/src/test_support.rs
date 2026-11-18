use std::path::PathBuf;

use sesame_core::VaultResult;

use crate::DeviceProtector;

pub(crate) struct TestProtector;

impl DeviceProtector for TestProtector {
    fn ensure_available(&self) -> VaultResult<()> {
        Ok(())
    }

    fn protect(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn unprotect(&self, protected: &[u8]) -> VaultResult<Vec<u8>> {
        Ok(protected.to_vec())
    }
}

pub(crate) fn scratch_dir(prefix: &str, name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
