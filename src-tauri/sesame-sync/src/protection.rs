use sesame_core::VaultResult;

pub trait DeviceProtector: Send + Sync {
    fn ensure_available(&self) -> VaultResult<()>;
    fn protect(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>>;
    fn unprotect(&self, protected: &[u8]) -> VaultResult<Vec<u8>>;
}
