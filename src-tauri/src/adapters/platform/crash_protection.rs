//! Avoid ordinary Windows Error Reporting heap and local-dump collection.
//! A privacy control, not anti-debugging: a debugger or EDR can still inspect the process.

#[cfg(windows)]
pub fn harden_process() -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::ErrorReporting::{
        WerAddExcludedApplication, WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP,
    };

    // Process-local; do it before Tauri creates threads that could fault.
    if unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let executable = std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_os_string()))
        .ok_or_else(|| std::io::Error::other("missing executable name"))?;
    let mut name: Vec<u16> = executable.encode_wide().collect();
    name.push(0);

    // Per-user HKCU control excluding the current executable from WER.
    if unsafe { WerAddExcludedApplication(name.as_ptr(), 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn harden_process() -> std::io::Result<()> {
    Ok(())
}
