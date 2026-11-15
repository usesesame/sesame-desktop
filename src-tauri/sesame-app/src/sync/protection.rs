use sesame_core::VaultResult;
use sesame_sync::DeviceProtector;

pub(crate) struct DesktopDeviceProtector;

pub(crate) static DEVICE_PROTECTOR: DesktopDeviceProtector = DesktopDeviceProtector;

impl DeviceProtector for DesktopDeviceProtector {
    fn ensure_available(&self) -> VaultResult<()> {
        #[cfg(any(test, feature = "test-support"))]
        {
            Ok(())
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            crate::vault::platform::ensure_device_protection()
        }
    }

    fn protect(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        #[cfg(any(test, feature = "test-support"))]
        {
            Ok(plaintext.to_vec())
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            crate::vault::platform::protect_for_device(plaintext)
        }
    }

    fn unprotect(&self, protected: &[u8]) -> VaultResult<Vec<u8>> {
        #[cfg(any(test, feature = "test-support"))]
        {
            Ok(protected.to_vec())
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            crate::vault::platform::unprotect_for_device(protected)
        }
    }
}
