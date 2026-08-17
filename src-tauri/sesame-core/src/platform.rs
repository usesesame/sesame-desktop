#[allow(unused_imports)]
use std::fs;
use std::path::Path;

use crate::VaultResult;

#[cfg(windows)]
pub fn protect_for_windows_profile(data: &[u8]) -> VaultResult<Vec<u8>> {
    use std::ptr::null;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let protected = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if protected == 0 {
        return Err("Windows could not protect this vault for the current profile.".into());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(result)
}

#[cfg(windows)]
pub fn unprotect_for_windows_profile(data: &[u8]) -> VaultResult<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let unprotected = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if unprotected == 0 {
        return Err("Windows could not unlock this vault for the current profile.".into());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(result)
}

#[cfg(not(windows))]
pub fn protect_for_windows_profile(_data: &[u8]) -> VaultResult<Vec<u8>> {
    Err("Device unlock is currently available on Windows only.".into())
}

#[cfg(not(windows))]
pub fn unprotect_for_windows_profile(_data: &[u8]) -> VaultResult<Vec<u8>> {
    Err("Device unlock is currently available on Windows only.".into())
}

#[cfg(windows)]
pub fn replace_file(source: &Path, destination: &Path) -> VaultResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err("Sesame could not complete the local vault save.".into());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn replace_file(source: &Path, destination: &Path) -> VaultResult<()> {
    fs::rename(source, destination)
        .map_err(|_| "Sesame could not complete the local vault save.".to_string())
}

/// Best-effort secure deletion: overwrites with random bytes; wear-leveled storage cannot be guaranteed.
pub fn securely_delete(path: &Path) -> VaultResult<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)
            .map_err(|_| "Sesame could not read a staged vault directory.".to_string())?
        {
            let entry =
                entry.map_err(|_| "Sesame could not read a staged vault entry.".to_string())?;
            securely_delete(&entry.path())?;
        }
        fs::remove_dir(path)
            .map_err(|_| "Sesame could not remove a staged vault directory.".to_string())?;
    } else if path.is_file() {
        overwrite_file(path)?;
        fs::remove_file(path)
            .map_err(|_| "Sesame could not remove a staged vault file.".to_string())?;
    }
    Ok(())
}

fn overwrite_file(path: &Path) -> VaultResult<()> {
    use rand::RngCore;
    use std::io::Write;

    let metadata = fs::metadata(path)
        .map_err(|_| "Sesame could not inspect a staged vault file.".to_string())?;
    let len = metadata.len() as usize;
    if len == 0 {
        return Ok(());
    }

    const PASS_COUNT: usize = 3;
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut chunk = vec![0u8; CHUNK_SIZE.min(len)];

    for pass in 0..PASS_COUNT {
        if pass == 0 {
            rand::rng().fill_bytes(&mut chunk);
        } else if pass == 1 {
            chunk.fill(0xFF);
        } else {
            chunk.fill(0x00);
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| "Sesame could not open a staged vault file for deletion.".to_string())?;
        let mut remaining = len;
        while remaining > 0 {
            let to_write = chunk.len().min(remaining);
            file.write_all(&chunk[..to_write])
                .map_err(|_| "Sesame could not overwrite a staged vault file.".to_string())?;
            remaining -= to_write;
        }
        file.flush()
            .map_err(|_| "Sesame could not flush an overwrite pass.".to_string())?;
        file.sync_all()
            .map_err(|_| "Sesame could not sync an overwrite pass to disk.".to_string())?;
    }
    Ok(())
}
