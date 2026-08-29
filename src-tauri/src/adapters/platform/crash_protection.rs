#[cfg(windows)]
pub fn harden_process() -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::ErrorReporting::{
        WerAddExcludedApplication, WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP,
    };
    use windows_sys::Win32::System::{
        Diagnostics::Debug::{CheckRemoteDebuggerPresent, IsDebuggerPresent},
        Threading::GetCurrentProcess,
    };

    if unsafe { IsDebuggerPresent() } != 0 {
        return Err(debugger_attached());
    }
    let mut remote_debugger = 0;
    if unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote_debugger) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if remote_debugger != 0 {
        return Err(debugger_attached());
    }

    if unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let executable = std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_os_string()))
        .ok_or_else(|| std::io::Error::other("missing executable name"))?;
    let mut name: Vec<u16> = executable.encode_wide().collect();
    name.push(0);

    if unsafe { WerAddExcludedApplication(name.as_ptr(), 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn debugger_attached() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "a process debugger is attached",
    )
}

#[cfg(all(target_os = "linux", not(debug_assertions)))]
pub fn harden_process() -> std::io::Result<()> {
    harden_linux_process()
}

#[cfg(all(target_os = "linux", debug_assertions))]
pub fn harden_process() -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn harden_process() -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(target_os = "linux", any(not(debug_assertions), test)))]
fn harden_linux_process() -> std::io::Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    if tracer_pid(&status)? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "a process tracer is attached",
        ));
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_TASK_PERF_EVENTS_DISABLE) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", any(not(debug_assertions), test)))]
fn tracer_pid(status: &str) -> std::io::Result<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing TracerPid"))?
        .trim()
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid TracerPid"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_tracer_state_without_accepting_malformed_status() {
        assert_eq!(tracer_pid("Name:\tsesame\nTracerPid:\t0\n").unwrap(), 0);
        assert!(tracer_pid("Name:\tsesame\n").is_err());
        assert!(tracer_pid("TracerPid:\tunknown\n").is_err());
    }

    #[test]
    fn linux_hardening_disables_process_dumps() {
        let previous = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert!(previous >= 0);

        harden_linux_process().unwrap();
        let hardened = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        let restored = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, previous) };
        let perf_restored = unsafe { libc::prctl(libc::PR_TASK_PERF_EVENTS_ENABLE) };

        assert_eq!(hardened, 0);
        assert_eq!(restored, 0);
        assert_eq!(perf_restored, 0);
    }
}
