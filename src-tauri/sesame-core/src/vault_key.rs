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
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::c_void;
    use std::sync::OnceLock;

    use zeroize::{Zeroize, Zeroizing};

    use crate::VaultResult;

    const KEY_BYTES: usize = 32;

    enum Storage {
        Locked(LockedRegion),
        Zeroized(Zeroizing<[u8; KEY_BYTES]>),
    }

    pub struct StoredKey {
        storage: Storage,
        locked: bool,
    }

    impl StoredKey {
        pub fn new(mut key: [u8; KEY_BYTES]) -> VaultResult<Self> {
            match LockedRegion::allocate(page_size()) {
                Ok(mut region) => {
                    region.copy_from(&key);
                    key.zeroize();
                    Ok(Self {
                        storage: Storage::Locked(region),
                        locked: true,
                    })
                }
                Err(_) => {
                    let stored = Zeroizing::new(key);
                    Ok(Self {
                        storage: Storage::Zeroized(stored),
                        locked: false,
                    })
                }
            }
        }

        pub fn expose<T>(
            &mut self,
            operation: impl FnOnce(&[u8; KEY_BYTES]) -> VaultResult<T>,
        ) -> VaultResult<T> {
            match &mut self.storage {
                Storage::Locked(region) => operation(region.bytes()),
                Storage::Zeroized(stored) => operation(&stored),
            }
        }

        #[cfg(test)]
        pub fn is_locked(&self) -> bool {
            self.locked
        }
    }

    impl Drop for StoredKey {
        fn drop(&mut self) {
            if let Storage::Locked(region) = &mut self.storage {
                region.release();
            }
        }
    }

    #[cfg(test)]
    impl StoredKey {
        pub fn is_plaintext(&self, expected: &[u8; KEY_BYTES]) -> bool {
            match &self.storage {
                Storage::Locked(region) => region.bytes_immutable() == expected,
                Storage::Zeroized(stored) => &**stored == expected,
            }
        }

        pub fn locked_region(&self) -> Option<(usize, usize)> {
            match &self.storage {
                Storage::Locked(region) => Some((region.address as usize, region.length)),
                Storage::Zeroized(_) => None,
            }
        }
    }

    struct LockedRegion {
        address: *mut u8,
        length: usize,
    }

    unsafe impl Send for LockedRegion {}

    impl LockedRegion {
        fn allocate(length: usize) -> VaultResult<Self> {
            let address = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if address == libc::MAP_FAILED {
                return Err("Linux could not reserve protected memory for the vault key.".into());
            }
            let address = address.cast::<u8>();
            if unsafe { libc::mlock(address.cast::<c_void>(), length) } != 0 {
                unsafe {
                    std::slice::from_raw_parts_mut(address, length).zeroize();
                    libc::munmap(address.cast::<c_void>(), length);
                }
                return Err("Linux could not keep the vault key out of the page file.".into());
            }
            unsafe {
                libc::madvise(address.cast::<c_void>(), length, libc::MADV_DONTDUMP);
                libc::madvise(address.cast::<c_void>(), length, libc::MADV_WIPEONFORK);
            }
            Ok(Self { address, length })
        }

        fn bytes(&mut self) -> &mut [u8; KEY_BYTES] {
            unsafe { &mut *self.address.cast::<[u8; KEY_BYTES]>() }
        }

        #[cfg(test)]
        fn bytes_immutable(&self) -> &[u8; KEY_BYTES] {
            unsafe { &*self.address.cast::<[u8; KEY_BYTES]>() }
        }

        fn copy_from(&mut self, key: &[u8; KEY_BYTES]) {
            self.bytes().copy_from_slice(key);
        }

        fn release(&mut self) {
            if self.address.is_null() {
                return;
            }
            unsafe {
                std::slice::from_raw_parts_mut(self.address, self.length).zeroize();
                libc::munlock(self.address.cast::<c_void>(), self.length);
                libc::munmap(self.address.cast::<c_void>(), self.length);
            }
            self.address = std::ptr::null_mut();
            self.length = 0;
        }
    }

    fn page_size() -> usize {
        static PAGE: OnceLock<usize> = OnceLock::new();
        *PAGE.get_or_init(|| {
            let reported = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            usize::try_from(reported).unwrap_or(4096).max(1)
        })
    }

    #[cfg(test)]
    pub(super) fn vm_lck_kib() -> usize {
        let status = std::fs::read_to_string("/proc/self/status")
            .expect("Linux test needs /proc/self/status");
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmLck:") {
                return rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse().ok())
                    .expect("VmLck carries a size");
            }
        }
        panic!("VmLck missing from /proc/self/status");
    }

    #[cfg(test)]
    pub(super) fn allocate_fails_for(length: usize) -> bool {
        LockedRegion::allocate(length).is_err()
    }

    #[cfg(test)]
    pub(super) fn mapping_flags(address: usize, length: usize) -> Option<String> {
        let maps = std::fs::read_to_string("/proc/self/smaps").ok()?;
        let mut in_range = false;
        let mut flags = String::new();
        for line in maps.lines() {
            if let Some((range, _rest)) = line.split_once(' ') {
                if let Some((start, end)) = range.split_once('-') {
                    let start = usize::from_str_radix(start, 16).ok()?;
                    let end = usize::from_str_radix(end, 16).ok()?;
                    in_range = address >= start && address + length <= end;
                    continue;
                }
            }
            if in_range {
                if let Some(found) = line.strip_prefix("VmFlags:") {
                    if flags.is_empty() {
                        flags = found.trim().to_string();
                    }
                }
            }
        }
        if flags.is_empty() {
            None
        } else {
            Some(flags)
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
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

    #[test]
    fn operation_panics_do_not_block_later_key_access() {
        let key = VaultKey::new([7_u8; 32]).expect("protected key");

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = key.expose::<()>(|_| panic!("fictional operation panic"));
        }));

        assert!(panicked.is_err());
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
        assert!(key
            .expose(|bytes| Ok(bytes == &expected))
            .expect("reopened key"));
        let stored = key
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!stored.is_plaintext(&expected));
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use std::sync::{Mutex, MutexGuard, OnceLock};

        fn lock_counter() -> MutexGuard<'static, ()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        #[test]
        fn linux_locked_region_is_pinned_and_unmapped_after_drop() {
            let _guard = lock_counter();
            let key = VaultKey::new([7_u8; 32]).expect("stored key");
            let Some((address, length)) = key
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .locked_region()
            else {
                return;
            };

            let flags = platform::mapping_flags(address, length).expect("the key region is mapped");
            assert!(flags.split_whitespace().any(|flag| flag == "lo"));

            drop(key);
            assert!(platform::mapping_flags(address, length).is_none());
        }

        #[test]
        fn linux_allocation_failure_is_reported_without_keeping_pages() {
            let _guard = lock_counter();
            assert!(platform::allocate_fails_for(usize::MAX));
        }

        #[test]
        fn linux_fallback_still_exposes_the_key() {
            let expected = [7_u8; 32];
            let key = VaultKey::new(expected).expect("stored key");
            assert!(key
                .expose(|bytes| Ok(bytes == &expected))
                .expect("exposed key"));
            let stored = key
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(stored.is_plaintext(&expected));
            if stored.is_locked() {
                let (address, length) = stored.locked_region().expect("locked region");
                let flags = platform::mapping_flags(address, length).expect("mapped");
                assert!(flags.split_whitespace().any(|flag| flag == "lo"));
            }
        }

        #[test]
        fn linux_key_stays_readable_and_stored_through_panics() {
            let expected = [7_u8; 32];
            let key = VaultKey::new(expected).expect("stored key");

            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = key.expose::<()>(|_| panic!("fictional operation panic"));
            }));

            assert!(panicked.is_err());
            assert!(key
                .expose(|bytes| Ok(bytes == &expected))
                .expect("reopened key"));
            let stored = key
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(stored.is_plaintext(&expected));
        }
    }
}
