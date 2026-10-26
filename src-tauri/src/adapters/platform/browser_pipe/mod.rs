//! Small local transport between the browser native host and the running app.
//! The pipe rejects remote clients; its DACL grants access only to LocalSystem and the current Windows account.

#[cfg(not(any(windows, target_os = "linux")))]
use std::{io, path::Path};
#[cfg(not(any(windows, target_os = "linux")))]
use zeroize::Zeroizing;

pub const MAX_PIPE_MESSAGE_BYTES: usize = 16 * 1024;

static SERVED_ELSEWHERE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True once another Sesame already held the connection when this one tried to take it.
pub fn served_elsewhere() -> bool {
    SERVED_ELSEWHERE.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "linux")]
fn note_served_elsewhere() {
    SERVED_ELSEWHERE.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{request, serve_forever, PipePeer};

#[cfg(target_os = "linux")]
mod unix;
#[cfg(target_os = "linux")]
pub use unix::{request, serve_forever, PipePeer};

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
