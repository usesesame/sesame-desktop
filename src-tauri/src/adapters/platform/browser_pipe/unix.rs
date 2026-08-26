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
