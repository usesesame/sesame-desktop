//! Small local transport between the browser native host and the running app.
//! The pipe rejects remote clients; its DACL grants access only to LocalSystem and the current Windows account.

#[cfg(not(any(windows, target_os = "linux")))]
use std::{io, path::Path};
#[cfg(not(any(windows, target_os = "linux")))]
use zeroize::Zeroizing;

pub const MAX_PIPE_MESSAGE_BYTES: usize = 16 * 1024;

#[cfg(windows)]
mod windows {
    use std::{
        ffi::{c_void, OsStr, OsString},
        fs,
        io::{self, ErrorKind},
        mem::size_of,
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::{Path, PathBuf},
        ptr,
        time::Duration,
    };

    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING,
            ERROR_PIPE_CONNECTED, ERROR_TIMEOUT, GENERIC_READ, GENERIC_WRITE, HANDLE,
            INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
            OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
        },
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
                GetNamedPipeServerProcessId, PeekNamedPipe, WaitNamedPipeW, PIPE_READMODE_BYTE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{
                CreateEventW, GetCurrentProcess, GetCurrentProcessId, OpenProcess,
                OpenProcessToken, QueryFullProcessImageNameW, WaitForSingleObject,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
            IO::{CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED},
        },
    };

    use super::MAX_PIPE_MESSAGE_BYTES;
    use zeroize::Zeroizing;

    const CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
    const IO_TIMEOUT: Duration = Duration::from_secs(2);
    // Standard Windows SYNCHRONIZE access right, required before WaitForSingleObject.
    const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;
    // The app can wait up to 30 seconds for approval; this transport deadline is slightly longer.
    const RESPONSE_TIMEOUT: Duration = Duration::from_secs(32);
    const PIPE_BUFFER_BYTES: u32 = MAX_PIPE_MESSAGE_BYTES as u32 + 4;
    // Long enough for a transient name collision, short enough to report a name held indefinitely.
    const MAX_CREATE_RETRIES: u32 = 150;
    const CREATE_RETRY_DELAY: Duration = Duration::from_millis(200);

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn new(handle: HANDLE) -> io::Result<Self> {
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(handle))
            }
        }

        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    struct UserIdentity {
        sid: String,
        pipe_name: Vec<u16>,
    }

    pub struct PipePeer {
        pipe: HANDLE,
        process: OwnedHandle,
    }

    impl PipePeer {
        /// False as soon as the host exits or closes its end; never reads client data.
        pub fn is_connected(&self) -> bool {
            if unsafe { WaitForSingleObject(self.process.raw(), 0) } != WAIT_TIMEOUT {
                return false;
            }
            let mut available = 0_u32;
            unsafe {
                PeekNamedPipe(
                    self.pipe,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    &mut available,
                    ptr::null_mut(),
                ) != 0
            }
        }
    }

    pub fn request(payload: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        validate_payload_size(payload)?;
        let identity = current_user_identity()?;
        if unsafe { WaitNamedPipeW(identity.pipe_name.as_ptr(), millis(CONNECT_TIMEOUT)) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let pipe = OwnedHandle::new(unsafe {
            CreateFileW(
                identity.pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        })?;
        let expected_server =
            fs::canonicalize(std::env::current_exe()?.with_file_name("sesame.exe"))?;
        // Verified handle kept alive for the exchange; a same-name squatter is rejected up front.
        let _server = verified_server(pipe.raw(), &expected_server)?;

        write_frame(pipe.raw(), payload, IO_TIMEOUT)?;
        read_frame(pipe.raw(), RESPONSE_TIMEOUT).map(Zeroizing::new)
    }

    pub fn serve_forever<F>(expected_client: &Path, handler: F) -> io::Result<()>
    where
        F: Fn(Vec<u8>, &PipePeer) -> Zeroizing<Vec<u8>>,
    {
        let identity = current_user_identity()?;
        let expected_client = fs::canonicalize(expected_client)?;
        let mut consecutive_create_failures = 0_u32;
        loop {
            let descriptor = security_descriptor_for_sid(&identity.sid)?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: 0,
            };
            // First-instance flags make a squatter's name grab fail loudly; a lost race is retried, not fatal.
            let created = OwnedHandle::new(unsafe {
                CreateNamedPipeW(
                    identity.pipe_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    PIPE_BUFFER_BYTES,
                    PIPE_BUFFER_BYTES,
                    millis(IO_TIMEOUT),
                    &attributes,
                )
            });
            // The descriptor only needs to live through CreateNamedPipeW.
            drop(descriptor);
            let pipe = match created {
                Ok(pipe) => {
                    consecutive_create_failures = 0;
                    pipe
                }
                Err(error) => {
                    consecutive_create_failures += 1;
                    if consecutive_create_failures > MAX_CREATE_RETRIES {
                        return Err(error);
                    }
                    std::thread::sleep(CREATE_RETRY_DELAY);
                    continue;
                }
            };

            if !connect_with_timeout(pipe.raw(), CONNECT_TIMEOUT)? {
                continue;
            }
            let peer = match verified_peer(pipe.raw(), &expected_client) {
                Ok(peer) => peer,
                Err(_) => continue,
            };
            let request = match read_frame(pipe.raw(), IO_TIMEOUT) {
                Ok(request) => request,
                Err(_) => continue,
            };
            let response = handler(request, &peer);
            if validate_payload_size(&response).is_err() {
                continue;
            }
            let _ = write_frame(pipe.raw(), &response, IO_TIMEOUT);
            // Dropping the server handle ends this one request; the next gets a fresh instance.
        }
    }

    fn verified_peer(pipe: HANDLE, expected_client: &Path) -> io::Result<PipePeer> {
        let mut process_id = 0_u32;
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "browser pipe client identity unavailable",
            ));
        }
        let process = verified_process(process_id, expected_client)?;
        Ok(PipePeer { pipe, process })
    }

    fn verified_server(pipe: HANDLE, expected_server: &Path) -> io::Result<OwnedHandle> {
        let mut process_id = 0_u32;
        if unsafe { GetNamedPipeServerProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "browser pipe server identity unavailable",
            ));
        }
        verified_process(process_id, expected_server)
    }

    fn verified_process(process_id: u32, expected: &Path) -> io::Result<OwnedHandle> {
        let process = OwnedHandle::new(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                process_id,
            )
        })?;
        let mut buffer = vec![0_u16; 32_768];
        let mut length = buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process.raw(), 0, buffer.as_mut_ptr(), &mut length) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(length as usize);
        let actual = fs::canonicalize(PathBuf::from(OsString::from_wide(&buffer)))?;
        if !actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy())
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "browser pipe client executable rejected",
            ));
        }
        let mut peer_session_id = 0_u32;
        if unsafe { ProcessIdToSessionId(process_id, &mut peer_session_id) } == 0
            || peer_session_id != current_session_id()?
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "browser pipe peer session rejected",
            ));
        }
        Ok(process)
    }

    fn current_session_id() -> io::Result<u32> {
        let mut session_id = 0_u32;
        if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(session_id)
    }

    fn connect_with_timeout(pipe: HANDLE, timeout: Duration) -> io::Result<bool> {
        let event = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };
        if unsafe { ConnectNamedPipe(pipe, &mut overlapped) } != 0 {
            return Ok(true);
        }
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => Ok(true),
            ERROR_IO_PENDING => match finish_overlapped(pipe, &mut overlapped, timeout) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == ErrorKind::TimedOut => Ok(false),
                Err(error) => Err(error),
            },
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn read_frame(pipe: HANDLE, timeout: Duration) -> io::Result<Vec<u8>> {
        let mut header = [0_u8; 4];
        read_exact(pipe, &mut header, timeout)?;
        let size = u32::from_le_bytes(header) as usize;
        if size == 0 || size > MAX_PIPE_MESSAGE_BYTES {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid browser pipe message size",
            ));
        }
        let mut payload = vec![0_u8; size];
        read_exact(pipe, &mut payload, timeout)?;
        Ok(payload)
    }

    fn write_frame(pipe: HANDLE, payload: &[u8], timeout: Duration) -> io::Result<()> {
        validate_payload_size(payload)?;
        let header = (payload.len() as u32).to_le_bytes();
        write_all(pipe, &header, timeout)?;
        write_all(pipe, payload, timeout)
    }

    fn validate_payload_size(payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() || payload.len() > MAX_PIPE_MESSAGE_BYTES {
            Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid browser pipe payload size",
            ))
        } else {
            Ok(())
        }
    }

    fn read_exact(pipe: HANDLE, mut buffer: &mut [u8], timeout: Duration) -> io::Result<()> {
        while !buffer.is_empty() {
            let count = read_once(pipe, buffer, timeout)?;
            if count == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "browser pipe closed",
                ));
            }
            buffer = &mut buffer[count..];
        }
        Ok(())
    }

    fn write_all(pipe: HANDLE, mut buffer: &[u8], timeout: Duration) -> io::Result<()> {
        while !buffer.is_empty() {
            let count = write_once(pipe, buffer, timeout)?;
            if count == 0 {
                return Err(io::Error::new(ErrorKind::WriteZero, "browser pipe closed"));
            }
            buffer = &buffer[count..];
        }
        Ok(())
    }

    fn read_once(pipe: HANDLE, buffer: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let event = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };
        let mut transferred = 0_u32;
        let started = unsafe {
            ReadFile(
                pipe,
                buffer.as_mut_ptr(),
                buffer.len().min(u32::MAX as usize) as u32,
                &mut transferred,
                &mut overlapped,
            )
        };
        if started != 0 {
            return Ok(transferred as usize);
        }
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(io::Error::last_os_error());
        }
        finish_overlapped(pipe, &mut overlapped, timeout).map(|value| value as usize)
    }

    fn write_once(pipe: HANDLE, buffer: &[u8], timeout: Duration) -> io::Result<usize> {
        let event = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };
        let mut transferred = 0_u32;
        let started = unsafe {
            WriteFile(
                pipe,
                buffer.as_ptr(),
                buffer.len().min(u32::MAX as usize) as u32,
                &mut transferred,
                &mut overlapped,
            )
        };
        if started != 0 {
            return Ok(transferred as usize);
        }
        if unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(io::Error::last_os_error());
        }
        finish_overlapped(pipe, &mut overlapped, timeout).map(|value| value as usize)
    }

    fn finish_overlapped(
        handle: HANDLE,
        overlapped: &mut OVERLAPPED,
        timeout: Duration,
    ) -> io::Result<u32> {
        let mut transferred = 0_u32;
        if unsafe {
            GetOverlappedResultEx(handle, overlapped, &mut transferred, millis(timeout), 0)
        } != 0
        {
            return Ok(transferred);
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_TIMEOUT {
            return Err(io::Error::from_raw_os_error(error as i32));
        }

        // The OVERLAPPED and event are stack-owned, so cancellation must be drained first.
        unsafe {
            CancelIoEx(handle, overlapped);
            GetOverlappedResult(handle, overlapped, &mut transferred, 1);
        }
        Err(io::Error::new(
            ErrorKind::TimedOut,
            "browser pipe operation timed out",
        ))
    }

    fn current_user_identity() -> io::Result<UserIdentity> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle::new(token)?;

        let mut byte_count = 0_u32;
        unsafe {
            GetTokenInformation(token.raw(), TokenUser, ptr::null_mut(), 0, &mut byte_count);
        }
        if byte_count == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::last_os_error());
        }
        let words = (byte_count as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        if unsafe {
            GetTokenInformation(
                token.raw(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                byte_count,
                &mut byte_count,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let user = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
        let mut sid_pointer = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_pointer) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid_allocation = LocalAllocation(sid_pointer.cast());
        let mut length = 0_usize;
        unsafe {
            while *sid_pointer.add(length) != 0 {
                length += 1;
            }
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_pointer, length) })
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid current-user SID"))?;
        drop(sid_allocation);

        let session_id = current_session_id()?;
        let pipe_name = wide(&format!(r"\\.\pipe\Sesame.Browser.{sid}.{session_id}"));
        Ok(UserIdentity { sid, pipe_name })
    }

    fn security_descriptor_for_sid(sid: &str) -> io::Result<LocalAllocation> {
        // Protected DACL: only this logon user and LocalSystem have access.
        let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"));
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(LocalAllocation(descriptor))
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    fn millis(duration: Duration) -> u32 {
        duration.as_millis().min(u32::MAX as u128) as u32
    }
}

#[cfg(windows)]
pub use windows::{request, serve_forever, PipePeer};

#[cfg(target_os = "linux")]
pub use unix::{request, serve_forever, PipePeer};

pub fn is_supported() -> bool {
    cfg!(any(windows, target_os = "linux"))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn request(_payload: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "browser filling is not supported on this operating system",
    ))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub struct PipePeer;

#[cfg(not(any(windows, target_os = "linux")))]
impl PipePeer {
    pub fn is_connected(&self) -> bool {
        false
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn serve_forever<F>(_expected_client: &Path, _handler: F) -> io::Result<()>
where
    F: Fn(Vec<u8>, &PipePeer) -> Zeroizing<Vec<u8>>,
{
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "browser filling is not supported on this operating system",
    ))
}

#[cfg(target_os = "linux")]
mod unix {
    use std::fs;
    use std::io::{self, ErrorKind, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use zeroize::Zeroizing;

    use super::MAX_PIPE_MESSAGE_BYTES;

    const IO_TIMEOUT: Duration = Duration::from_millis(1_500);
    const RESPONSE_TIMEOUT: Duration = Duration::from_secs(180);
    const MAX_ACCEPT_RETRIES: u32 = 150;
    const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(200);
    const SOCKET_DIRECTORY_MODE: u32 = 0o700;
    const SOCKET_MODE: u32 = 0o600;

    pub struct PipePeer {
        pid: u32,
        start_time: u64,
    }

    impl PipePeer {
        pub fn is_connected(&self) -> bool {
            process_start_time(self.pid).is_some_and(|current| current == self.start_time)
        }
    }

    pub fn request(payload: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let expected_server = fs::canonicalize(std::env::current_exe()?.with_file_name("sesame"))?;
        request_at(&socket_path()?, &expected_server, payload)
    }

    fn request_at(
        path: &Path,
        expected_server: &Path,
        payload: &[u8],
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        validate_payload_size(payload)?;
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(RESPONSE_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;

        verify_peer(&stream, expected_server)?;

        write_frame(&mut stream, payload)?;
        read_frame(&mut stream).map(Zeroizing::new)
    }

    pub fn serve_forever<F>(expected_client: &Path, handler: F) -> io::Result<()>
    where
        F: Fn(Vec<u8>, &PipePeer) -> Zeroizing<Vec<u8>>,
    {
        serve_at(&socket_path()?, expected_client, handler)
    }

    fn serve_at<F>(path: &Path, expected_client: &Path, handler: F) -> io::Result<()>
    where
        F: Fn(Vec<u8>, &PipePeer) -> Zeroizing<Vec<u8>>,
    {
        let expected_client = fs::canonicalize(expected_client)?;
        let listener = bind_exclusive(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;

        let mut consecutive_accept_failures = 0_u32;
        loop {
            // Exhausted descriptors fail every accept; without the delay this
            // would spin instead of letting whatever leaked them recover.
            let mut stream = match listener.accept() {
                Ok((stream, _)) => {
                    consecutive_accept_failures = 0;
                    stream
                }
                Err(error) => {
                    consecutive_accept_failures += 1;
                    if consecutive_accept_failures > MAX_ACCEPT_RETRIES {
                        return Err(error);
                    }
                    std::thread::sleep(ACCEPT_RETRY_DELAY);
                    continue;
                }
            };
            if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
                || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
            {
                continue;
            }
            let Ok(peer) = verify_peer(&stream, &expected_client) else {
                continue;
            };
            let Ok(request) = read_frame(&mut stream) else {
                continue;
            };
            let response = handler(request, &peer);
            if validate_payload_size(&response).is_err() {
                continue;
            }
            let _ = stream.set_write_timeout(Some(RESPONSE_TIMEOUT));
            let _ = write_frame(&mut stream, &response);
        }
    }

    fn bind_exclusive(path: &Path) -> io::Result<UnixListener> {
        if let Some(directory) = path.parent() {
            fs::create_dir_all(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE))?;
        }
        match UnixListener::bind(path) {
            Ok(listener) => Ok(listener),
            Err(error) if error.kind() == ErrorKind::AddrInUse => {
                if UnixStream::connect(path).is_ok() {
                    return Err(io::Error::new(
                        ErrorKind::AddrInUse,
                        "another Sesame already serves the browser socket",
                    ));
                }
                fs::remove_file(path)?;
                UnixListener::bind(path)
            }
            Err(error) => Err(error),
        }
    }

    fn socket_path() -> io::Result<PathBuf> {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "no per-user runtime directory"))?;
        Ok(base.join("sesame").join("browser.sock"))
    }

    fn verify_peer(stream: &UnixStream, expected: &Path) -> io::Result<PipePeer> {
        let (uid, pid) = peer_credentials(stream)?;
        // SAFETY: geteuid cannot fail and touches no memory.
        if uid != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "browser socket peer belongs to another user",
            ));
        }
        if pid == 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "browser socket peer identity unavailable",
            ));
        }

        let start_time = process_start_time(pid).ok_or_else(|| {
            io::Error::new(
                ErrorKind::PermissionDenied,
                "browser socket peer is no longer running",
            )
        })?;
        let executable = fs::canonicalize(format!("/proc/{pid}/exe"))?;
        if executable != expected {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "browser socket peer executable rejected",
            ));
        }
        Ok(PipePeer { pid, start_time })
    }

    fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, u32)> {
        let mut credentials = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `length` bytes, which is this value's own size.
        let queried = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::from_mut(&mut credentials).cast(),
                &mut length,
            )
        };
        if queried != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((credentials.uid, credentials.pid.max(0) as u32))
    }

    /// Counted from after the comm field: the process name is unquoted and may
    /// itself contain spaces and brackets.
    fn process_start_time(pid: u32) -> Option<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_comm = stat.rsplit_once(')')?.1;
        after_comm.split_whitespace().nth(19)?.parse().ok()
    }

    fn validate_payload_size(payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() || payload.len() > MAX_PIPE_MESSAGE_BYTES {
            Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid browser pipe payload size",
            ))
        } else {
            Ok(())
        }
    }

    fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
        validate_payload_size(payload)?;
        stream.write_all(&(payload.len() as u32).to_le_bytes())?;
        stream.write_all(payload)?;
        stream.flush()
    }

    fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header)?;
        let size = u32::from_le_bytes(header) as usize;
        if size == 0 || size > MAX_PIPE_MESSAGE_BYTES {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid browser pipe message size",
            ));
        }
        let mut payload = vec![0_u8; size];
        stream.read_exact(&mut payload)?;
        Ok(payload)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn this_process_reports_a_stable_start_time() {
            let pid = std::process::id();
            let first = process_start_time(pid);
            assert!(first.is_some());
            assert_eq!(first, process_start_time(pid));
        }

        #[test]
        fn a_pid_that_is_not_running_has_no_start_time() {
            assert_eq!(process_start_time(u32::MAX), None);
        }

        #[test]
        fn an_empty_or_oversized_payload_is_refused() {
            assert!(validate_payload_size(&[]).is_err());
            assert!(validate_payload_size(&vec![0_u8; MAX_PIPE_MESSAGE_BYTES + 1]).is_err());
            assert!(validate_payload_size(&[1]).is_ok());
        }

        #[test]
        fn the_socket_lives_under_the_per_user_runtime_directory() {
            let path = socket_path().expect("a runtime directory");
            assert!(path.ends_with("sesame/browser.sock"));
        }

        fn scratch_socket(name: &str) -> PathBuf {
            let path = std::env::temp_dir()
                .join(format!("sesame-pipe-test-{}-{name}", std::process::id()))
                .join("browser.sock");
            let _ = fs::remove_file(&path);
            path
        }

        fn serve_in_background(socket: &Path, expected_client: PathBuf) {
            let served = socket.to_path_buf();
            std::thread::spawn(move || {
                let _ = serve_at(&served, &expected_client, |request, _peer| {
                    Zeroizing::new(request)
                });
            });
            for _ in 0..200 {
                if socket.exists() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("the test server never bound its socket");
        }

        #[test]
        fn a_peer_running_the_expected_executable_is_served() {
            let socket = scratch_socket("accepts");
            let this = std::env::current_exe().expect("this test binary");
            serve_in_background(&socket, this.clone());

            let response = request_at(&socket, &this, b"round trip").expect("a served response");
            assert_eq!(response.as_slice(), b"round trip");
        }

        /// The client is this test binary, so naming any other executable is the
        /// impostor case the peer check exists to refuse.
        #[test]
        fn a_peer_running_another_executable_is_refused() {
            let socket = scratch_socket("refuses");
            let this = std::env::current_exe().expect("this test binary");
            serve_in_background(&socket, PathBuf::from("/bin/sh"));

            assert!(request_at(&socket, &this, b"round trip").is_err());
        }

        #[test]
        fn the_server_refuses_a_socket_another_server_still_owns() {
            let socket = scratch_socket("exclusive");
            let this = std::env::current_exe().expect("this test binary");
            serve_in_background(&socket, this);

            let second = bind_exclusive(&socket);
            assert!(second.is_err());
        }

        #[test]
        fn a_socket_left_by_a_crash_is_replaced() {
            let socket = scratch_socket("stale");
            if let Some(directory) = socket.parent() {
                fs::create_dir_all(directory).expect("a scratch directory");
            }
            drop(UnixListener::bind(&socket).expect("a first listener"));
            fs::write(&socket, []).ok();

            assert!(bind_exclusive(&socket).is_ok());
        }
    }
}
