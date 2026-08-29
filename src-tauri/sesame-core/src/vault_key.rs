use std::sync::Mutex;

use zeroize::Zeroize;

use crate::VaultResult;

pub struct VaultKey {
    inner: Mutex<platform::StoredKey>,
}

impl VaultKey {
    pub fn new(mut key: [u8; 32]) -> VaultResult<Self> {
        let stored = platform::StoredKey::new(key)?;
        key.zeroize();
        Ok(Self {
            inner: Mutex::new(stored),
        })
    }

    pub fn expose<T>(&self, operation: impl FnOnce(&[u8; 32]) -> VaultResult<T>) -> VaultResult<T> {
        self.inner
            .lock()
            .map_err(|_| "Sesame could not read the protected vault key.".to_string())?
            .expose(operation)
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    use windows_sys::Win32::{
        Security::Cryptography::{
            CryptProtectMemory, CryptUnprotectMemory, CRYPTPROTECTMEMORY_SAME_PROCESS,
        },
        System::Memory::{VirtualLock, VirtualUnlock},
    };
    use zeroize::Zeroize;

    use crate::VaultResult;

    const KEY_BYTES: u32 = 32;

    pub struct StoredKey {
        bytes: Box<[u8; KEY_BYTES as usize]>,
        locked: bool,
        protected: bool,
    }

    impl StoredKey {
        pub fn new(mut key: [u8; KEY_BYTES as usize]) -> VaultResult<Self> {
            let mut bytes = Box::new(key);
            key.zeroize();
            let locked =
                unsafe { VirtualLock(bytes.as_mut_ptr().cast::<c_void>(), KEY_BYTES as usize) }
                    != 0;
            if !locked {
                bytes.zeroize();
                return Err("Windows could not keep the vault key out of the page file.".into());
            }
            if protect(&mut bytes).is_err() {
                bytes.zeroize();
                unsafe {
                    VirtualUnlock(bytes.as_mut_ptr().cast::<c_void>(), KEY_BYTES as usize);
                }
                return Err("Windows could not protect the unlocked vault key in memory.".into());
            }
            Ok(Self {
                bytes,
                locked,
                protected: true,
            })
        }

        pub fn expose<T>(
            &mut self,
            operation: impl FnOnce(&[u8; KEY_BYTES as usize]) -> VaultResult<T>,
        ) -> VaultResult<T> {
            if !self.protected {
                return Err(
                    "The protected vault key is no longer available. Lock and unlock Sesame again."
                        .into(),
                );
            }
            if unsafe {
                CryptUnprotectMemory(
                    self.bytes.as_mut_ptr().cast::<c_void>(),
                    KEY_BYTES,
                    CRYPTPROTECTMEMORY_SAME_PROCESS,
                )
            } == 0
            {
                self.bytes.zeroize();
                self.protected = false;
                return Err("Windows could not open the protected vault key in memory. Lock and unlock Sesame again.".into());
            }
            self.protected = false;

            let mut exposure = Exposure {
                bytes: &mut self.bytes,
                protected: &mut self.protected,
                finished: false,
            };
            let result = operation(&exposure.bytes);
            let protected = exposure.seal();
            if let Err(error) = protected {
                return Err(error);
            }
            result
        }
    }

    impl Drop for StoredKey {
        fn drop(&mut self) {
            if self.protected {
                let _ = unsafe {
                    CryptUnprotectMemory(
                        self.bytes.as_mut_ptr().cast::<c_void>(),
                        KEY_BYTES,
                        CRYPTPROTECTMEMORY_SAME_PROCESS,
                    )
                };
            }
            self.bytes.zeroize();
            if self.locked {
                unsafe {
                    VirtualUnlock(self.bytes.as_mut_ptr().cast::<c_void>(), KEY_BYTES as usize);
                }
            }
        }
    }

    fn protect(bytes: &mut [u8; KEY_BYTES as usize]) -> VaultResult<()> {
        if unsafe {
            CryptProtectMemory(
                bytes.as_mut_ptr().cast::<c_void>(),
                KEY_BYTES,
                CRYPTPROTECTMEMORY_SAME_PROCESS,
            )
        } == 0
        {
            Err("Windows could not protect the unlocked vault key in memory.".into())
        } else {
            Ok(())
        }
    }

    struct Exposure<'a> {
        bytes: &'a mut [u8; KEY_BYTES as usize],
        protected: &'a mut bool,
        finished: bool,
    }

    impl Exposure<'_> {
        fn seal(&mut self) -> VaultResult<()> {
            let result = protect(self.bytes);
            *self.protected = result.is_ok();
            if result.is_err() {
                self.bytes.zeroize();
            }
            self.finished = true;
            result
        }
    }

    impl Drop for Exposure<'_> {
        fn drop(&mut self) {
            if self.finished {
                return;
            }
            let result = protect(self.bytes);
            *self.protected = result.is_ok();
            if result.is_err() {
                self.bytes.zeroize();
            }
        }
    }

    #[cfg(test)]
    impl StoredKey {
        pub fn is_plaintext(&self, expected: &[u8; KEY_BYTES as usize]) -> bool {
            self.bytes.as_ref() == expected
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use zeroize::Zeroizing;

    use crate::VaultResult;

    pub struct StoredKey(Zeroizing<[u8; 32]>);

    impl StoredKey {
        pub fn new(key: [u8; 32]) -> VaultResult<Self> {
            Ok(Self(Zeroizing::new(key)))
        }

        pub fn expose<T>(
            &mut self,
            operation: impl FnOnce(&[u8; 32]) -> VaultResult<T>,
        ) -> VaultResult<T> {
            operation(&self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_the_key_only_inside_the_operation() {
        let key = VaultKey::new([7_u8; 32]).expect("protected key");

        let observed = key
            .expose(|bytes| Ok(bytes.iter().copied().sum::<u8>()))
            .expect("exposed key");

        assert_eq!(observed, 224);
    }

    #[test]
    fn operation_errors_survive_the_key_guard() {
        let key = VaultKey::new([7_u8; 32]).expect("protected key");

        let result = key.expose::<()>(|_| Err("fictional operation failed".into()));

        assert_eq!(result, Err("fictional operation failed".into()));
        assert!(key.expose(|bytes| Ok(bytes[0] == 7)).expect("reopened key"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_storage_is_not_plaintext_between_operations() {
        let expected = [7_u8; 32];
        let key = VaultKey::new(expected).expect("protected key");

        let stored = key.inner.lock().expect("key lock");

        assert!(!stored.is_plaintext(&expected));
    }

    #[cfg(windows)]
    #[test]
    fn windows_storage_is_protected_after_an_operation_panics() {
        let expected = [7_u8; 32];
        let key = VaultKey::new(expected).expect("protected key");

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = key.expose::<()>(|_| panic!("fictional operation panic"));
        }));

        assert!(panicked.is_err());
        let stored = key.inner.lock().expect("key lock");
        assert!(!stored.is_plaintext(&expected));
    }
}
