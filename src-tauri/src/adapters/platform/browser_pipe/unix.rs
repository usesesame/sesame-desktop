use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::{MAX_PIPE_MESSAGE_BYTES, SERVED_ELSEWHERE, TERMINAL_SERVED_ELSEWHERE};
use crate::browser_host::appimage::{self, ExecutableIdentity};
use crate::cli_protocol::{MAX_CLI_REPLY_BYTES, MAX_CLI_REQUEST_BYTES};

const IO_TIMEOUT: Duration = Duration::from_millis(1_500);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_ACCEPT_RETRIES: u32 = 150;
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(200);
const SOCKET_DIRECTORY_MODE: u32 = 0o700;
const SOCKET_MODE: u32 = 0o600;

pub struct Channel {
    pub(super) label: &'static str,
    pub(super) socket_file: &'static str,
    pub(super) max_request_bytes: usize,
    pub(super) max_reply_bytes: usize,
    pub(super) request_deadline: Duration,
    pub(super) reply_deadline: Duration,
    pub(super) served_elsewhere: &'static AtomicBool,
    pub(super) verified_contents: &'static Mutex<Option<VerifiedProcess>>,
}

pub const BROWSER: Channel = Channel {
    label: "browser",
    socket_file: "browser.sock",
    max_request_bytes: MAX_PIPE_MESSAGE_BYTES,
    max_reply_bytes: MAX_PIPE_MESSAGE_BYTES,
    request_deadline: IO_TIMEOUT,
    reply_deadline: RESPONSE_TIMEOUT,
    served_elsewhere: &SERVED_ELSEWHERE,
    verified_contents: &VERIFIED_BROWSER_CONTENTS,
};

const TERMINAL_REPLY_TIMEOUT: Duration = Duration::from_secs(200);
pub const MAX_TERMINAL_CONNECTIONS: usize = 4;

pub const TERMINAL: Channel = Channel {
    label: "terminal",
    socket_file: "cli.sock",
    max_request_bytes: MAX_CLI_REQUEST_BYTES,
    max_reply_bytes: MAX_CLI_REPLY_BYTES,
    request_deadline: IO_TIMEOUT,
    reply_deadline: TERMINAL_REPLY_TIMEOUT,
    served_elsewhere: &TERMINAL_SERVED_ELSEWHERE,
    verified_contents: &VERIFIED_TERMINAL_CONTENTS,
};

pub(super) enum PeerIdentity {
    SameUser,
    Path(PathBuf),
    Contents(ExecutableIdentity),
}

impl PeerIdentity {
    pub(super) fn of_executable(path: &Path) -> io::Result<Self> {
        if appimage::running_from_appimage() {
            Ok(Self::Contents(ExecutableIdentity::of_file(path)?))
        } else {
            Ok(Self::Path(fs::canonicalize(path)?))
        }
    }
}

pub(super) type VerifiedProcess = (u32, u64, u64, u64, u64, [u8; 32]);

static VERIFIED_BROWSER_CONTENTS: Mutex<Option<VerifiedProcess>> = Mutex::new(None);
static VERIFIED_TERMINAL_CONTENTS: Mutex<Option<VerifiedProcess>> = Mutex::new(None);

pub struct PipePeer {
    pid: u32,
    start_time: u64,
}

impl PipePeer {
    pub fn is_connected(&self) -> bool {
        process_start_time(self.pid).is_some_and(|current| current == self.start_time)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn start_time(&self) -> u64 {
        self.start_time
    }
}

pub fn request(payload: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    request_at(&socket_path()?, &PeerIdentity::SameUser, payload)
}

fn request_at(
    path: &Path,
    expected_server: &PeerIdentity,
    payload: &[u8],
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut stream = connect_verified(&BROWSER, path, expected_server, payload)?;
    read_frame_on(
        &BROWSER,
        &mut stream,
        BROWSER.max_reply_bytes,
        Instant::now() + BROWSER.reply_deadline,
    )
    .map(Zeroizing::new)
}

pub(super) fn connect_verified(
    channel: &Channel,
    path: &Path,
    expected_server: &PeerIdentity,
    payload: &[u8],
) -> io::Result<UnixStream> {
    validate_size_on(channel, payload, channel.max_request_bytes)?;
    let mut stream = UnixStream::connect(path)?;
    stream.set_write_timeout(Some(channel.request_deadline))?;

    verify_peer_on(channel, &stream, expected_server)?;

    write_frame_on(channel, &mut stream, payload, channel.max_request_bytes)?;
    Ok(stream)
}

pub fn serve_forever<F>(expected_client: &Path, handler: F) -> io::Result<()>
where
    F: Fn(Vec<u8>, &PipePeer) -> Zeroizing<Vec<u8>>,
{
    let expected_client = PeerIdentity::of_executable(expected_client)?;
    serve_at(&socket_path()?, &expected_client, handler)
}

fn serve_at<F>(path: &Path, expected_client: &PeerIdentity, handler: F) -> io::Result<()>
where
    F: Fn(Vec<u8>, &PipePeer) -> Zeroizing<Vec<u8>>,
{
    let listener = bind_exclusive(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;

    let mut consecutive_accept_failures = 0_u32;
    loop {
        let mut stream = match accept_with_retry(&listener, &mut consecutive_accept_failures)? {
            Some(stream) => stream,
            None => continue,
        };
        if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
        {
            continue;
        }
        let Ok(peer) = verify_peer(&stream, expected_client) else {
            continue;
        };
        let Ok(request) = read_frame(&mut stream, Instant::now() + IO_TIMEOUT) else {
            continue;
        };
        let response = match catch_unwind(AssertUnwindSafe(|| handler(request, &peer))) {
            Ok(response) => response,
            Err(_) => continue,
        };
        if validate_payload_size(&response).is_err() {
            continue;
        }
        let _ = stream.set_write_timeout(Some(RESPONSE_TIMEOUT));
        let _ = write_frame(&mut stream, &response);
    }
}

pub(super) fn accept_with_retry(
    listener: &UnixListener,
    consecutive_failures: &mut u32,
) -> io::Result<Option<UnixStream>> {
    // Exhausted descriptors fail every accept; without the delay this
    // would spin instead of letting whatever leaked them recover.
    match listener.accept() {
        Ok((stream, _)) => {
            *consecutive_failures = 0;
            Ok(Some(stream))
        }
        Err(error) => {
            *consecutive_failures += 1;
            if *consecutive_failures > MAX_ACCEPT_RETRIES {
                return Err(error);
            }
            std::thread::sleep(ACCEPT_RETRY_DELAY);
            Ok(None)
        }
    }
}

fn bind_exclusive(path: &Path) -> io::Result<UnixListener> {
    bind_exclusive_on(&BROWSER, path)
}

pub(super) fn bind_exclusive_on(channel: &Channel, path: &Path) -> io::Result<UnixListener> {
    if let Some(directory) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(SOCKET_DIRECTORY_MODE)
            .create(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE))?;
    }
    match UnixListener::bind(path) {
        Ok(listener) => Ok(listener),
        Err(error) if error.kind() == ErrorKind::AddrInUse => {
            if UnixStream::connect(path).is_ok() {
                channel.served_elsewhere.store(true, Ordering::Relaxed);
                return Err(io::Error::new(
                    ErrorKind::AddrInUse,
                    format!("another Sesame already serves the {} socket", channel.label),
                ));
            }
            if !fs::symlink_metadata(path)?.file_type().is_socket() {
                return Err(io::Error::new(
                    ErrorKind::AddrInUse,
                    format!(
                        "something other than a socket holds the {} socket path",
                        channel.label
                    ),
                ));
            }
            fs::remove_file(path)?;
            UnixListener::bind(path)
        }
        Err(error) => Err(error),
    }
}

fn socket_path() -> io::Result<PathBuf> {
    socket_path_on(&BROWSER)
}

pub(super) fn socket_path_on(channel: &Channel) -> io::Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "no per-user runtime directory"))?;
    Ok(base.join("sesame").join(channel.socket_file))
}

fn verify_peer(stream: &UnixStream, expected: &PeerIdentity) -> io::Result<PipePeer> {
    verify_peer_on(&BROWSER, stream, expected)
}

pub(super) fn verify_peer_on(
    channel: &Channel,
    stream: &UnixStream,
    expected: &PeerIdentity,
) -> io::Result<PipePeer> {
    let label = channel.label;
    let (uid, pid) = peer_credentials(stream)?;
    // SAFETY: geteuid cannot fail and touches no memory.
    if uid != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{label} socket peer belongs to another user"),
        ));
    }
    if pid == 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{label} socket peer identity unavailable"),
        ));
    }

    let start_time = process_start_time(pid).ok_or_else(|| {
        io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{label} socket peer is no longer running"),
        )
    })?;
    let accepted = match expected {
        PeerIdentity::SameUser => true,
        PeerIdentity::Path(path) => fs::canonicalize(format!("/proc/{pid}/exe"))? == *path,
        PeerIdentity::Contents(identity) => contents_match(channel, identity, pid, start_time)?,
    };
    if !accepted {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{label} socket peer executable rejected"),
        ));
    }
    Ok(PipePeer { pid, start_time })
}

pub struct TerminalConnection {
    stream: Mutex<UnixStream>,
    peer: PipePeer,
}

impl TerminalConnection {
    pub fn peer(&self) -> &PipePeer {
        &self.peer
    }

    pub fn is_connected(&self) -> bool {
        if !self.peer.is_connected() {
            return false;
        }
        let stream = self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut watched = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        };
        // SAFETY: poll reads and writes only the one pollfd passed with a count of one.
        let ready = unsafe { libc::poll(&mut watched, 1, 0) };
        ready == 0
            || (ready > 0
                && watched.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) == 0)
    }

    pub fn send(&self, payload: &[u8]) -> io::Result<()> {
        let mut stream = self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        write_frame_on(&TERMINAL, &mut stream, payload, TERMINAL.max_reply_bytes)
    }
}

pub struct TerminalClient {
    stream: UnixStream,
    deadline: Instant,
}

impl TerminalClient {
    pub fn next_frame(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
        read_frame_on(
            &TERMINAL,
            &mut self.stream,
            TERMINAL.max_reply_bytes,
            self.deadline,
        )
        .map(Zeroizing::new)
    }
}

pub fn open_terminal_request(payload: &[u8]) -> io::Result<TerminalClient> {
    open_terminal_request_at(
        &socket_path_on(&TERMINAL)?,
        &PeerIdentity::SameUser,
        payload,
    )
}

fn open_terminal_request_at(
    path: &Path,
    expected_server: &PeerIdentity,
    payload: &[u8],
) -> io::Result<TerminalClient> {
    let stream = connect_verified(&TERMINAL, path, expected_server, payload)?;
    Ok(TerminalClient {
        stream,
        deadline: Instant::now() + TERMINAL.reply_deadline,
    })
}

pub fn serve_terminal<F>(
    expected_client: &Path,
    listening: impl FnOnce(),
    handler: F,
) -> io::Result<()>
where
    F: Fn(Vec<u8>, &TerminalConnection) + Send + Sync + 'static,
{
    let expected_client = PeerIdentity::of_executable(expected_client)?;
    serve_terminal_at(
        &socket_path_on(&TERMINAL)?,
        expected_client,
        listening,
        handler,
    )
}

struct OpenConnection(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_terminal_at<F>(
    path: &Path,
    expected_client: PeerIdentity,
    listening: impl FnOnce(),
    handler: F,
) -> io::Result<()>
where
    F: Fn(Vec<u8>, &TerminalConnection) + Send + Sync + 'static,
{
    let listener = bind_exclusive_on(&TERMINAL, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;
    listening();
    let expected_client = std::sync::Arc::new(expected_client);
    let handler = std::sync::Arc::new(handler);
    let open = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut consecutive_accept_failures = 0_u32;
    loop {
        let Some(stream) = accept_with_retry(&listener, &mut consecutive_accept_failures)? else {
            continue;
        };
        if open.fetch_add(1, Ordering::AcqRel) >= MAX_TERMINAL_CONNECTIONS {
            open.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let slot = OpenConnection(std::sync::Arc::clone(&open));
        let expected_client = std::sync::Arc::clone(&expected_client);
        let handler = std::sync::Arc::clone(&handler);
        let spawned = std::thread::Builder::new()
            .name("sesame-terminal-request".into())
            .spawn(move || {
                let _slot = slot;
                serve_terminal_connection(stream, &expected_client, handler.as_ref());
            });
        if spawned.is_err() {
            continue;
        }
    }
}

fn serve_terminal_connection<F>(mut stream: UnixStream, expected_client: &PeerIdentity, handler: &F)
where
    F: Fn(Vec<u8>, &TerminalConnection),
{
    if stream
        .set_read_timeout(Some(TERMINAL.request_deadline))
        .is_err()
        || stream
            .set_write_timeout(Some(TERMINAL.request_deadline))
            .is_err()
    {
        return;
    }
    let Ok(peer) = verify_peer_on(&TERMINAL, &stream, expected_client) else {
        return;
    };
    let Ok(request) = read_frame_on(
        &TERMINAL,
        &mut stream,
        TERMINAL.max_request_bytes,
        Instant::now() + TERMINAL.request_deadline,
    ) else {
        return;
    };
    let connection = TerminalConnection {
        stream: Mutex::new(stream),
        peer,
    };
    let _ = catch_unwind(AssertUnwindSafe(|| handler(request, &connection)));
}

fn contents_match(
    channel: &Channel,
    identity: &ExecutableIdentity,
    pid: u32,
    start_time: u64,
) -> io::Result<bool> {
    let file = fs::File::open(format!("/proc/{pid}/exe"))?;
    let metadata = file.metadata()?;
    let (bytes, sha256) = identity.key();
    let key = (
        pid,
        start_time,
        metadata.dev(),
        metadata.ino(),
        bytes,
        sha256,
    );
    let mut verified = channel
        .verified_contents
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *verified == Some(key) {
        return Ok(true);
    }
    let matched = identity.matches_file(file)?;
    if matched && process_start_time(pid) == Some(start_time) {
        *verified = Some(key);
        return Ok(true);
    }
    Ok(false)
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
pub(super) fn process_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

fn validate_payload_size(payload: &[u8]) -> io::Result<()> {
    validate_size_on(&BROWSER, payload, MAX_PIPE_MESSAGE_BYTES)
}

fn validate_size_on(channel: &Channel, payload: &[u8], max_bytes: usize) -> io::Result<()> {
    if payload.is_empty() || payload.len() > max_bytes {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid {} pipe payload size", channel.label),
        ))
    } else {
        Ok(())
    }
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    write_frame_on(&BROWSER, stream, payload, MAX_PIPE_MESSAGE_BYTES)
}

pub(super) fn write_frame_on(
    channel: &Channel,
    stream: &mut UnixStream,
    payload: &[u8],
    max_bytes: usize,
) -> io::Result<()> {
    validate_size_on(channel, payload, max_bytes)?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

fn read_frame(stream: &mut UnixStream, deadline: Instant) -> io::Result<Vec<u8>> {
    read_frame_on(&BROWSER, stream, MAX_PIPE_MESSAGE_BYTES, deadline)
}

pub(super) fn read_frame_on(
    channel: &Channel,
    stream: &mut UnixStream,
    max_bytes: usize,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    read_exact_until(channel, stream, &mut header, deadline)?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > max_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid {} pipe message size", channel.label),
        ));
    }
    let mut payload = vec![0_u8; size];
    read_exact_until(channel, stream, &mut payload, deadline)?;
    Ok(payload)
}

fn read_exact_until(
    channel: &Channel,
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("{} pipe frame deadline exceeded", channel.label),
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("{} pipe closed", channel.label),
                ));
            }
            Ok(count) => filled += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
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

    fn path_identity(path: &Path) -> PeerIdentity {
        PeerIdentity::Path(fs::canonicalize(path).expect("an existing executable"))
    }

    fn serve_in_background(socket: &Path, expected_client: PeerIdentity) {
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
        serve_in_background(&socket, path_identity(&this));

        let response =
            request_at(&socket, &path_identity(&this), b"round trip").expect("a served response");
        assert_eq!(response.as_slice(), b"round trip");
    }

    /// The client is this test binary, so naming any other executable is the
    /// impostor case the peer check exists to refuse.
    #[test]
    fn a_peer_running_another_executable_is_refused() {
        let socket = scratch_socket("refuses");
        let this = std::env::current_exe().expect("this test binary");
        serve_in_background(&socket, path_identity(Path::new("/bin/sh")));

        assert!(request_at(&socket, &path_identity(&this), b"round trip").is_err());
    }

    fn this_executable_contents() -> PeerIdentity {
        PeerIdentity::Contents(
            ExecutableIdentity::of_file(Path::new("/proc/self/exe")).expect("an identity"),
        )
    }

    #[test]
    fn a_same_user_server_is_trusted_without_reading_its_executable() {
        let socket = scratch_socket("same-user");
        let this = std::env::current_exe().expect("this test binary");
        serve_in_background(&socket, path_identity(&this));

        let response =
            request_at(&socket, &PeerIdentity::SameUser, b"round trip").expect("a served response");
        assert_eq!(response.as_slice(), b"round trip");
    }

    #[test]
    fn a_peer_with_the_expected_executable_contents_is_served_by_contents_alone() {
        let socket = scratch_socket("contents-accepts");
        serve_in_background(&socket, this_executable_contents());

        let response = request_at(&socket, &this_executable_contents(), b"round trip")
            .expect("a served response");
        assert_eq!(response.as_slice(), b"round trip");
    }

    #[test]
    fn a_peer_whose_executable_contents_differ_is_refused() {
        let socket = scratch_socket("contents-refuses");
        let other = ExecutableIdentity::of_file(Path::new("/bin/sh")).expect("an identity");
        serve_in_background(&socket, PeerIdentity::Contents(other.clone()));

        assert!(request_at(&socket, &this_executable_contents(), b"round trip").is_err());
        assert!(request_at(&socket, &PeerIdentity::Contents(other), b"round trip").is_err());
    }

    #[test]
    fn the_server_refuses_a_socket_another_server_still_owns() {
        let socket = scratch_socket("exclusive");
        let this = std::env::current_exe().expect("this test binary");
        serve_in_background(&socket, path_identity(&this));

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

    struct UmaskGuard(libc::mode_t);

    impl UmaskGuard {
        fn permissive() -> Self {
            // SAFETY: umask reads and writes a process attribute and touches no memory.
            Self(unsafe { libc::umask(0) })
        }
    }

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            // SAFETY: restores the mode returned by the matching umask call.
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path)
            .expect("metadata for a created path")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn a_second_sesame_leaves_a_live_socket_alone_and_records_that_it_was_refused() {
        let socket = scratch_socket("second");
        let this = std::env::current_exe().expect("this test binary");
        serve_in_background(&socket, path_identity(&this));
        let first =
            request_at(&socket, &path_identity(&this), b"first").expect("a served response");
        assert_eq!(first.as_slice(), b"first");

        let refused = bind_exclusive(&socket).expect_err("a live socket is not taken over");
        assert_eq!(refused.kind(), ErrorKind::AddrInUse);
        assert!(crate::browser_pipe::served_elsewhere());
        let still = request_at(&socket, &path_identity(&this), b"still").expect("still served");
        assert_eq!(still.as_slice(), b"still");
    }

    #[test]
    fn a_permissive_umask_leaves_the_socket_directory_and_socket_private() {
        let root =
            std::env::temp_dir().join(format!("sesame-pipe-test-{}-modes", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let socket = root.join(".cache").join("sesame").join("browser.sock");
        let this = std::env::current_exe().expect("this test binary");
        let umask = UmaskGuard::permissive();
        serve_in_background(&socket, path_identity(&this));
        let response =
            request_at(&socket, &path_identity(&this), b"round trip").expect("a served response");
        assert_eq!(response.as_slice(), b"round trip");
        drop(umask);

        assert_eq!(mode_of(&root.join(".cache")), 0o700);
        assert_eq!(mode_of(socket.parent().expect("a socket directory")), 0o700);
        assert_eq!(mode_of(&socket), 0o600);
    }

    #[test]
    fn a_dribbled_frame_is_dropped_at_the_frame_deadline() {
        let socket = scratch_socket("dribble");
        let this = std::env::current_exe().expect("this test binary");
        serve_in_background(&socket, path_identity(&this));

        let mut stream = UnixStream::connect(&socket).expect("a connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .expect("a read timeout");
        let mut writer = stream.try_clone().expect("a cloned stream");
        let started = Instant::now();
        let dribble = std::thread::spawn(move || {
            let mut frame = Vec::from(8_u32.to_le_bytes());
            frame.extend_from_slice(&[7_u8; 8]);
            for byte in frame {
                if writer.write_all(&[byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(400));
            }
        });

        let mut buffer = [0_u8; 32];
        let read = stream.read(&mut buffer);
        let elapsed = started.elapsed();
        dribble.join().expect("the dribbling writer");

        let dropped = match read {
            Ok(0) => true,
            Err(error) => error.kind() == ErrorKind::ConnectionReset,
            Ok(_) => false,
        };
        assert!(dropped, "the broker did not drop the dribbled frame");
        assert!(
            elapsed < Duration::from_secs(3),
            "the broker held the dribbled frame for {elapsed:?}"
        );
    }

    #[test]
    fn a_panicking_handler_does_not_end_the_loop() {
        let socket = scratch_socket("panic");
        let this = std::env::current_exe().expect("this test binary");
        let served = socket.clone();
        let client = path_identity(&this);
        std::thread::spawn(move || {
            let panicked = std::sync::atomic::AtomicBool::new(false);
            let _ = serve_at(&served, &client, move |request, _peer| {
                if !panicked.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    panic!("fictional handler panic");
                }
                Zeroizing::new(request)
            });
        });
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(request_at(&socket, &path_identity(&this), b"first").is_err());
        let second = request_at(&socket, &path_identity(&this), b"second")
            .expect("the broker survives a handler panic");
        assert_eq!(second.as_slice(), b"second");
    }
}

#[cfg(test)]
mod terminal_tests {
    use super::*;

    fn scratch_socket(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!(
                "sesame-terminal-test-{}-{name}",
                std::process::id()
            ))
            .join("cli.sock");
        let _ = fs::remove_file(&path);
        path
    }

    fn this_executable() -> PeerIdentity {
        PeerIdentity::Path(
            fs::canonicalize(std::env::current_exe().expect("this test binary"))
                .expect("a canonical path"),
        )
    }

    fn wait_for(socket: &Path) {
        for _ in 0..200 {
            if socket.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the test server never bound its socket");
    }

    fn serve_terminal_ready<F>(socket: &Path, expected_client: PeerIdentity, handler: F)
    where
        F: Fn(Vec<u8>, &TerminalConnection) + Send + Sync + 'static,
    {
        let served = socket.to_path_buf();
        let (ready, listening) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = serve_terminal_at(
                &served,
                expected_client,
                move || {
                    let _ = ready.send(());
                },
                handler,
            );
        });
        listening
            .recv_timeout(Duration::from_secs(10))
            .expect("the test server never started listening");
    }

    fn serve_echo(socket: &Path, expected_client: PeerIdentity) {
        serve_terminal_ready(socket, expected_client, |request, connection| {
            let _ = connection.send(b"waiting");
            let _ = connection.send(&request);
        });
    }

    fn refused_after_connecting(socket: &Path) {
        match open_terminal_request_at(socket, &this_executable(), b"fictional") {
            Ok(mut client) => assert!(client.next_frame().is_err()),
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                ),
                "{error}"
            ),
        }
    }

    fn dropped(stream: &mut UnixStream) -> bool {
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .expect("a read timeout");
        let mut buffer = [0_u8; 32];
        match stream.read(&mut buffer) {
            Ok(0) => true,
            Err(error) => error.kind() == ErrorKind::ConnectionReset,
            Ok(_) => false,
        }
    }

    #[test]
    fn the_terminal_socket_is_separate_from_the_browser_socket() {
        let terminal = socket_path_on(&TERMINAL).expect("a runtime directory");
        let browser = socket_path_on(&BROWSER).expect("a runtime directory");
        assert!(terminal.ends_with("sesame/cli.sock"));
        assert_ne!(terminal, browser);
        assert_eq!(TERMINAL.max_request_bytes, 4 * 1024);
        assert_eq!(TERMINAL.max_reply_bytes, 64 * 1024);
        assert_eq!(TERMINAL.request_deadline, Duration::from_millis(1_500));
        assert_eq!(TERMINAL.reply_deadline, Duration::from_secs(200));
    }

    #[test]
    fn the_expected_client_gets_every_frame_of_its_reply() {
        let socket = scratch_socket("served");
        serve_echo(&socket, this_executable());

        let mut client =
            open_terminal_request_at(&socket, &this_executable(), b"fictional request")
                .expect("a verified server");
        assert_eq!(client.next_frame().expect("first").as_slice(), b"waiting");
        assert_eq!(
            client.next_frame().expect("second").as_slice(),
            b"fictional request"
        );
    }

    #[test]
    fn a_client_running_another_executable_is_refused_before_any_read() {
        let socket = scratch_socket("wrong-client");
        serve_echo(&socket, PeerIdentity::Path(PathBuf::from("/bin/sh")));

        refused_after_connecting(&socket);
    }

    #[test]
    fn a_client_whose_executable_contents_differ_is_refused() {
        let socket = scratch_socket("wrong-contents");
        let other = ExecutableIdentity::of_file(Path::new("/bin/sh")).expect("an identity");
        serve_echo(&socket, PeerIdentity::Contents(other));

        refused_after_connecting(&socket);
    }

    #[test]
    fn oversized_empty_and_bodiless_frames_are_dropped_and_the_next_client_is_served() {
        let socket = scratch_socket("frames");
        serve_echo(&socket, this_executable());

        let mut oversized = UnixStream::connect(&socket).expect("a connection");
        oversized
            .write_all(&((MAX_CLI_REQUEST_BYTES + 1) as u32).to_le_bytes())
            .expect("a header");
        assert!(dropped(&mut oversized));

        let mut empty = UnixStream::connect(&socket).expect("a connection");
        empty.write_all(&0_u32.to_le_bytes()).expect("a header");
        assert!(dropped(&mut empty));

        let started = Instant::now();
        let mut bodiless = UnixStream::connect(&socket).expect("a connection");
        bodiless.write_all(&8_u32.to_le_bytes()).expect("a header");
        assert!(dropped(&mut bodiless));
        assert!(started.elapsed() < Duration::from_secs(3));

        assert!(open_terminal_request_at(
            &socket,
            &this_executable(),
            &[b'x'; MAX_CLI_REQUEST_BYTES + 1]
        )
        .is_err());
        let mut client =
            open_terminal_request_at(&socket, &this_executable(), b"next").expect("still served");
        assert_eq!(client.next_frame().expect("first").as_slice(), b"waiting");
    }

    #[test]
    fn a_dribbled_request_is_dropped_at_the_request_deadline() {
        let socket = scratch_socket("dribble");
        serve_echo(&socket, this_executable());

        let mut stream = UnixStream::connect(&socket).expect("a connection");
        let mut writer = stream.try_clone().expect("a cloned stream");
        let started = Instant::now();
        let dribble = std::thread::spawn(move || {
            let mut frame = Vec::from(8_u32.to_le_bytes());
            frame.extend_from_slice(&[7_u8; 8]);
            for byte in frame {
                if writer.write_all(&[byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(400));
            }
        });
        assert!(dropped(&mut stream));
        assert!(started.elapsed() < Duration::from_secs(3));
        dribble.join().expect("the dribbling writer");
    }

    #[test]
    fn at_most_four_connections_are_open_at_once() {
        let socket = scratch_socket("limit");
        let release = std::sync::Arc::new(AtomicBool::new(false));
        let held = std::sync::Arc::clone(&release);
        serve_terminal_ready(&socket, this_executable(), move |_request, connection| {
            let _ = connection.send(b"waiting");
            while !held.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = connection.send(b"done");
        });

        let mut open = Vec::new();
        for _ in 0..MAX_TERMINAL_CONNECTIONS {
            let mut client =
                open_terminal_request_at(&socket, &this_executable(), b"held").expect("served");
            assert_eq!(client.next_frame().expect("waiting").as_slice(), b"waiting");
            open.push(client);
        }
        let mut fifth = UnixStream::connect(&socket).expect("a connection");
        assert!(dropped(&mut fifth));

        release.store(true, Ordering::SeqCst);
        for mut client in open {
            assert_eq!(client.next_frame().expect("done").as_slice(), b"done");
        }
    }

    #[test]
    fn a_panicking_terminal_handler_does_not_end_the_listener() {
        let socket = scratch_socket("panic");
        let panicked = AtomicBool::new(false);
        serve_terminal_ready(&socket, this_executable(), move |request, connection| {
            if !panicked.swap(true, Ordering::SeqCst) {
                panic!("fictional handler panic");
            }
            let _ = connection.send(&request);
        });

        let mut first =
            open_terminal_request_at(&socket, &this_executable(), b"first").expect("written");
        assert!(first.next_frame().is_err());
        let mut second =
            open_terminal_request_at(&socket, &this_executable(), b"second").expect("written");
        assert_eq!(second.next_frame().expect("served").as_slice(), b"second");
    }

    fn this_executable_contents() -> PeerIdentity {
        PeerIdentity::Contents(
            ExecutableIdentity::of_file(Path::new("/proc/self/exe")).expect("an identity"),
        )
    }

    fn copy_of_this_executable(name: &str, change_one_byte: bool) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "sesame-terminal-test-{}-{name}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("a scratch directory");
        let copy = directory.join("sesame");
        let mut bytes = fs::read("/proc/self/exe").expect("this test binary");
        if change_one_byte {
            let middle = bytes.len() / 2;
            bytes[middle] ^= 0x01;
        }
        fs::write(&copy, bytes).expect("a copy");
        copy
    }

    #[test]
    fn a_copy_of_the_expected_executable_with_one_byte_changed_is_refused() {
        let changed = copy_of_this_executable("one-byte", true);
        let expected = ExecutableIdentity::of_file(&changed).expect("an identity");
        let original =
            ExecutableIdentity::of_file(Path::new("/proc/self/exe")).expect("an identity");
        assert_eq!(expected.key().0, original.key().0);
        assert_ne!(expected.key().1, original.key().1);
        let socket = scratch_socket("one-byte");
        serve_echo(&socket, PeerIdentity::Contents(expected));

        refused_after_connecting(&socket);

        let unchanged = copy_of_this_executable("same-bytes", false);
        let socket = scratch_socket("same-bytes");
        serve_echo(
            &socket,
            PeerIdentity::Contents(ExecutableIdentity::of_file(&unchanged).expect("an identity")),
        );
        let mut client = open_terminal_request_at(&socket, &this_executable(), b"fictional")
            .expect("the request is written");
        assert_eq!(client.next_frame().expect("served").as_slice(), b"waiting");
    }

    #[test]
    fn a_terminal_contents_check_does_not_wait_for_the_browser_cache() {
        let socket = scratch_socket("own-cache");
        serve_echo(&socket, this_executable_contents());
        let browser_entry = VERIFIED_BROWSER_CONTENTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let (sender, receiver) = std::sync::mpsc::channel();
        let client_socket = socket.clone();
        std::thread::spawn(move || {
            let reply = open_terminal_request_at(&client_socket, &this_executable(), b"fictional")
                .and_then(|mut client| client.next_frame());
            let _ = sender.send(reply.map(|frame| frame.to_vec()));
        });
        let reply = receiver
            .recv_timeout(Duration::from_secs(20))
            .expect("the terminal check waited for the browser cache");
        drop(browser_entry);
        assert_eq!(reply.expect("served"), b"waiting".to_vec());
        let terminal_entry = VERIFIED_TERMINAL_CONTENTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            terminal_entry.map(|entry| entry.0),
            Some(std::process::id())
        );
    }

    #[test]
    fn a_tool_request_on_the_browser_socket_is_refused_there() {
        let socket = std::env::temp_dir()
            .join(format!(
                "sesame-terminal-test-{}-tool-on-browser",
                std::process::id()
            ))
            .join("browser.sock");
        let _ = fs::remove_file(&socket);
        let served = socket.clone();
        std::thread::spawn(move || {
            let _ = serve_at(&served, &this_executable(), |payload, _peer| {
                match crate::browser_fill::parse_pipe_request(&payload) {
                    Ok(_) => Zeroizing::new(b"accepted".to_vec()),
                    Err(refusal) => refusal,
                }
            });
        });
        wait_for(&socket);

        let tool = crate::cli_protocol::CliCommand::Get {
            item: "Northwind mail".to_string(),
            field: Some("password".to_string()),
            copy: false,
        }
        .to_request("3f9a0c1e5b7d2a4c6e8f0a1b2c3d4e5f")
        .to_bytes()
        .expect("encodes");
        let reply = request_at(&socket, &this_executable(), &tool).expect("a reply");
        let reply = String::from_utf8(reply.to_vec()).expect("utf8");
        assert!(reply.contains("Invalid browser request."), "{reply}");

        let capabilities = serde_json::to_vec(&serde_json::json!({
            "version": crate::browser_protocol::CAPABILITIES_PROTOCOL_VERSION,
            "type": "capabilities",
            "requestId": "fictional-capabilities-1",
        }))
        .expect("encodes");
        let reply = request_at(&socket, &this_executable(), &capabilities).expect("a reply");
        assert_eq!(reply.as_slice(), b"accepted");
    }

    #[test]
    fn a_browser_request_on_the_tool_socket_is_refused_there() {
        let socket = scratch_socket("browser-on-tool");
        serve_terminal_ready(&socket, this_executable(), |payload, connection| {
            let reply = match crate::application::cli_requests::parse_or_refuse(&payload) {
                Ok(_) => b"accepted".to_vec(),
                Err(refusal) => refusal.to_bytes().expect("encodes").to_vec(),
            };
            let _ = connection.send(&reply);
        });

        for (browser_request, refused_as) in [
            (
                serde_json::json!({
                    "version": crate::browser_protocol::PROTOCOL_VERSION,
                    "type": "activate",
                    "requestId": "fictional-activate-1",
                }),
                crate::cli_protocol::CliErrorCode::Invalid,
            ),
            (
                serde_json::json!({
                    "version": crate::browser_protocol::CAPABILITIES_PROTOCOL_VERSION,
                    "type": "capabilities",
                    "requestId": "fictional-capabilities-2",
                }),
                crate::cli_protocol::CliErrorCode::UnsupportedVersion,
            ),
        ] {
            let bytes = serde_json::to_vec(&browser_request).expect("encodes");
            assert!(crate::browser_fill::parse_pipe_request(&bytes).is_ok());
            let mut client = open_terminal_request_at(&socket, &this_executable(), &bytes)
                .expect("the request is written");
            let reply = crate::cli_protocol::parse_reply(&client.next_frame().expect("a reply"))
                .expect("a protocol reply");
            assert_eq!(reply.error_code(), Some(refused_as));
        }

        let list = crate::cli_protocol::CliCommand::List
            .to_request("3f9a0c1e5b7d2a4c6e8f0a1b2c3d4e5f")
            .to_bytes()
            .expect("encodes");
        let mut client = open_terminal_request_at(&socket, &this_executable(), &list)
            .expect("the request is written");
        assert_eq!(
            client.next_frame().expect("a reply").as_slice(),
            b"accepted"
        );
    }

    #[test]
    fn a_second_sesame_leaves_a_live_terminal_socket_alone_and_says_so() {
        let socket = scratch_socket("terminal-second");
        serve_echo(&socket, this_executable());

        let refused = bind_exclusive_on(&TERMINAL, &socket).expect_err("a live socket is kept");
        assert_eq!(refused.kind(), ErrorKind::AddrInUse);
        assert!(crate::browser_pipe::terminal_served_elsewhere());
        let mut client =
            open_terminal_request_at(&socket, &this_executable(), b"still").expect("still served");
        assert_eq!(client.next_frame().expect("waiting").as_slice(), b"waiting");
    }

    #[test]
    fn a_file_that_is_not_a_socket_at_the_terminal_path_is_left_alone() {
        let socket = scratch_socket("regular-file");
        if let Some(directory) = socket.parent() {
            fs::create_dir_all(directory).expect("a scratch directory");
        }
        fs::write(&socket, b"fictional notes").expect("a regular file");
        let refused = bind_exclusive_on(&TERMINAL, &socket).expect_err("a regular file is kept");
        assert_eq!(refused.kind(), ErrorKind::AddrInUse);
        assert_eq!(fs::read(&socket).expect("still there"), b"fictional notes");

        let target = socket.with_file_name("elsewhere.sock");
        let _ = fs::remove_file(&target);
        drop(UnixListener::bind(&target).expect("a stale socket elsewhere"));
        fs::remove_file(&socket).expect("the regular file removed");
        std::os::unix::fs::symlink(&target, &socket).expect("a symlink");
        assert!(bind_exclusive_on(&TERMINAL, &socket).is_err());
        assert!(fs::symlink_metadata(&socket)
            .expect("the link is kept")
            .file_type()
            .is_symlink());

        fs::remove_file(&socket).expect("the link removed");
        drop(UnixListener::bind(&socket).expect("a stale socket"));
        assert!(bind_exclusive_on(&TERMINAL, &socket).is_ok());
    }

    #[test]
    fn a_terminal_that_closed_its_end_reads_as_disconnected_while_its_process_lives() {
        let socket = scratch_socket("hang-up");
        let (closed, seen) = std::sync::mpsc::channel();
        let (opened, open_seen) = std::sync::mpsc::channel();
        let report = Mutex::new((opened, closed));
        serve_terminal_ready(&socket, this_executable(), move |_request, connection| {
            let report = report
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _ = report.0.send(connection.is_connected());
            let _ = connection.send(b"waiting");
            let until = Instant::now() + Duration::from_secs(5);
            while connection.is_connected() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = report.1.send(connection.is_connected());
        });
        let mut client = open_terminal_request_at(&socket, &this_executable(), b"fictional")
            .expect("the request is written");
        assert!(open_seen
            .recv_timeout(Duration::from_secs(5))
            .expect("the handler ran"));
        assert_eq!(client.next_frame().expect("waiting").as_slice(), b"waiting");
        drop(client);
        assert!(!seen
            .recv_timeout(Duration::from_secs(10))
            .expect("the handler noticed"));
    }
}
