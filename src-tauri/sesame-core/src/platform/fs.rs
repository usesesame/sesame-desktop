use std::fs;
use std::path::Path;

use crate::VaultResult;

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

#[cfg(unix)]
pub fn create_private_dir(path: &Path) -> VaultResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path)
        .map_err(|_| "Sesame could not prepare its local vault folder.".to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "Sesame could not protect its local vault folder.".to_string())
}

#[cfg(not(unix))]
pub fn create_private_dir(path: &Path) -> VaultResult<()> {
    fs::create_dir_all(path)
        .map_err(|_| "Sesame could not prepare its local vault folder.".to_string())
}

#[cfg(unix)]
pub fn open_private_file(path: &Path) -> VaultResult<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "Sesame could not prepare the file.".to_string())
}

#[cfg(not(unix))]
pub fn open_private_file(path: &Path) -> VaultResult<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|_| "Sesame could not prepare the file.".to_string())
}

#[cfg(unix)]
pub fn copy_private_file(source: &Path, destination: &Path) -> VaultResult<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut output = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(destination)
        .map_err(|_| "Sesame could not write the vault copy.".to_string())?;
    let mut input = std::fs::File::open(source)
        .map_err(|_| "Sesame could not read the vault copy.".to_string())?;
    std::io::copy(&mut input, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|_| "Sesame could not write the vault copy.".to_string())
}

#[cfg(not(unix))]
pub fn copy_private_file(source: &Path, destination: &Path) -> VaultResult<()> {
    fs::copy(source, destination)
        .map(|_| ())
        .map_err(|_| "Sesame could not write the vault copy.".to_string())
}

#[cfg(windows)]
pub fn same_file_identity(source: &Path, destination: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    // std keeps Windows file identity unstable, so two open handles are
    // compared by volume serial number and file index.
    fn file_identity(path: &Path) -> Option<(u32, u64)> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let queried = unsafe { GetFileInformationByHandle(handle, &mut information) };
        unsafe { CloseHandle(handle) };
        if queried == 0 {
            return None;
        }
        Some((
            information.dwVolumeSerialNumber,
            ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
        ))
    }

    match (file_identity(source), file_identity(destination)) {
        (Some(source), Some(destination)) => source == destination,
        _ => false,
    }
}

#[cfg(unix)]
pub fn same_file_identity(source: &Path, destination: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::metadata(source), fs::metadata(destination)) {
        (Ok(source), Ok(destination)) => {
            source.dev() == destination.dev() && source.ino() == destination.ino()
        }
        _ => false,
    }
}

#[cfg(not(any(unix, windows)))]
pub fn same_file_identity(_source: &Path, _destination: &Path) -> bool {
    false
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
    use rand::Rng;
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
