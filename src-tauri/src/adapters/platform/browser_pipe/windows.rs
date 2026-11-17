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
            CreateEventW, GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
            QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
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
// Long enough for a transient name collision, short enough to report a name held indefinitely.
const MAX_CREATE_RETRIES: u32 = 150;
const CREATE_RETRY_DELAY: Duration = Duration::from_millis(200);

pub struct Channel {
    pub(super) label: &'static str,
    pub(super) pipe_prefix: &'static str,
    pub(super) max_request_bytes: usize,
    pub(super) max_reply_bytes: usize,
    pub(super) connect_deadline: Duration,
    pub(super) request_deadline: Duration,
    pub(super) reply_deadline: Duration,
}

pub const BROWSER: Channel = Channel {
    label: "browser",
    pipe_prefix: "Sesame.Browser",
    max_request_bytes: MAX_PIPE_MESSAGE_BYTES,
    max_reply_bytes: MAX_PIPE_MESSAGE_BYTES,
    connect_deadline: CONNECT_TIMEOUT,
    request_deadline: IO_TIMEOUT,
    reply_deadline: RESPONSE_TIMEOUT,
};

impl Channel {
    fn buffer_bytes(&self, max_bytes: usize) -> u32 {
        (max_bytes + 4).min(u32::MAX as usize) as u32
    }
}

pub(super) struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    pub(super) fn raw(&self) -> HANDLE {
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

pub(super) struct LocalAllocation(pub(super) *mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

pub(super) struct UserIdentity {
    pub(super) sid: String,
    pub(super) pipe_name: Vec<u16>,
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
    let expected_server = fs::canonicalize(std::env::current_exe()?.with_file_name("sesame.exe"))?;
    let (pipe, _server) = connect_verified(&BROWSER, &expected_server, payload)?;
    read_frame_on(
        &BROWSER,
        pipe.raw(),
        BROWSER.max_reply_bytes,
        BROWSER.reply_deadline,
    )
    .map(Zeroizing::new)
}

pub(super) fn connect_verified(
    channel: &Channel,
    expected_server: &Path,
    payload: &[u8],
) -> io::Result<(OwnedHandle, OwnedHandle)> {
    validate_size_on(channel, payload, channel.max_request_bytes)?;
    let identity = current_user_identity(channel)?;
    if unsafe {
        WaitNamedPipeW(
            identity.pipe_name.as_ptr(),
            millis(channel.connect_deadline),
        )
    } == 0
    {
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
    // Verified handle kept alive for the exchange; a same-name squatter is rejected up front.
    let server = verified_server(channel, pipe.raw(), expected_server)?;

    write_frame_on(
        channel,
        pipe.raw(),
        payload,
        channel.max_request_bytes,
        channel.request_deadline,
    )?;
    Ok((pipe, server))
}

pub fn serve_forever<F>(expected_client: &Path, handler: F) -> io::Result<()>
where
    F: Fn(Vec<u8>, &PipePeer) -> Zeroizing<Vec<u8>>,
{
    let channel = &BROWSER;
    let identity = current_user_identity(channel)?;
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
                channel.buffer_bytes(channel.max_reply_bytes),
                channel.buffer_bytes(channel.max_request_bytes),
                millis(channel.request_deadline),
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

        if !connect_with_timeout(pipe.raw(), channel.connect_deadline)? {
            continue;
        }
        let peer = match verified_peer(channel, pipe.raw(), &expected_client) {
            Ok(peer) => peer,
            Err(_) => continue,
        };
        let request = match read_frame_on(
            channel,
            pipe.raw(),
            channel.max_request_bytes,
            channel.request_deadline,
        ) {
            Ok(request) => request,
            Err(_) => continue,
        };
        let response = handler(request, &peer);
        if validate_size_on(channel, &response, channel.max_reply_bytes).is_err() {
            continue;
        }
        let _ = write_frame_on(
            channel,
            pipe.raw(),
            &response,
            channel.max_reply_bytes,
            channel.request_deadline,
        );
        // Dropping the server handle ends this one request; the next gets a fresh instance.
    }
}

pub(super) fn verified_peer(
    channel: &Channel,
    pipe: HANDLE,
    expected_client: &Path,
) -> io::Result<PipePeer> {
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{} pipe client identity unavailable", channel.label),
        ));
    }
    let process = verified_process(channel, process_id, expected_client)?;
    Ok(PipePeer { pipe, process })
}

fn verified_server(
    channel: &Channel,
    pipe: HANDLE,
    expected_server: &Path,
) -> io::Result<OwnedHandle> {
    let mut process_id = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{} pipe server identity unavailable", channel.label),
        ));
    }
    verified_process(channel, process_id, expected_server)
}

fn verified_process(
    channel: &Channel,
    process_id: u32,
    expected: &Path,
) -> io::Result<OwnedHandle> {
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
            format!("{} pipe client executable rejected", channel.label),
        ));
    }
    let mut peer_session_id = 0_u32;
    if unsafe { ProcessIdToSessionId(process_id, &mut peer_session_id) } == 0
        || peer_session_id != current_session_id()?
    {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{} pipe peer session rejected", channel.label),
        ));
    }
    Ok(process)
}

pub(super) fn current_session_id() -> io::Result<u32> {
    let mut session_id = 0_u32;
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(session_id)
}

pub(super) fn connect_with_timeout(pipe: HANDLE, timeout: Duration) -> io::Result<bool> {
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

pub(super) fn read_frame_on(
    channel: &Channel,
    pipe: HANDLE,
    max_bytes: usize,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    read_exact(channel, pipe, &mut header, timeout)?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > max_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid {} pipe message size", channel.label),
        ));
    }
    let mut payload = vec![0_u8; size];
    read_exact(channel, pipe, &mut payload, timeout)?;
    Ok(payload)
}

pub(super) fn write_frame_on(
    channel: &Channel,
    pipe: HANDLE,
    payload: &[u8],
    max_bytes: usize,
    timeout: Duration,
) -> io::Result<()> {
    validate_size_on(channel, payload, max_bytes)?;
    let header = (payload.len() as u32).to_le_bytes();
    write_all(channel, pipe, &header, timeout)?;
    write_all(channel, pipe, payload, timeout)
}

pub(super) fn validate_size_on(
    channel: &Channel,
    payload: &[u8],
    max_bytes: usize,
) -> io::Result<()> {
    if payload.is_empty() || payload.len() > max_bytes {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid {} pipe payload size", channel.label),
        ))
    } else {
        Ok(())
    }
}

fn read_exact(
    channel: &Channel,
    pipe: HANDLE,
    mut buffer: &mut [u8],
    timeout: Duration,
) -> io::Result<()> {
    while !buffer.is_empty() {
        let count = read_once(pipe, buffer, timeout)?;
        if count == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                format!("{} pipe closed", channel.label),
            ));
        }
        buffer = &mut buffer[count..];
    }
    Ok(())
}

fn write_all(
    channel: &Channel,
    pipe: HANDLE,
    mut buffer: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    while !buffer.is_empty() {
        let count = write_once(pipe, buffer, timeout)?;
        if count == 0 {
            return Err(io::Error::new(
                ErrorKind::WriteZero,
                format!("{} pipe closed", channel.label),
            ));
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
    if unsafe { GetOverlappedResultEx(handle, overlapped, &mut transferred, millis(timeout), 0) }
        != 0
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

pub(super) fn current_user_identity(channel: &Channel) -> io::Result<UserIdentity> {
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
    let pipe_name = wide(&format!(
        r"\\.\pipe\{}.{sid}.{session_id}",
        channel.pipe_prefix
    ));
    Ok(UserIdentity { sid, pipe_name })
}

pub(super) fn security_descriptor_for_sid(sid: &str) -> io::Result<LocalAllocation> {
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

pub(super) fn millis(duration: Duration) -> u32 {
    duration.as_millis().min(u32::MAX as u128) as u32
}
