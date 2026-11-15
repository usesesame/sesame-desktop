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
