//! Windows process-wide DLL search-order hardening: never load from CWD or PATH.

#[cfg(windows)]
pub fn harden_process() -> std::io::Result<()> {
    use windows_sys::Win32::System::LibraryLoader::{
        SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
    };

    // SAFETY: changes only this process's documented default DLL search policy.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn harden_process() -> std::io::Result<()> {
    Ok(())
}
