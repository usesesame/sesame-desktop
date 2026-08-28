use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::browser_protocol::{
    supported_protocol_version, BrowserRequest, BrowserResponse, MAX_NATIVE_MESSAGE_BYTES,
};

const HOST_NAME: &str = "app.usesesame.browser";
const PINNED_CHROMIUM_EXTENSION_ID: &str = "idbkfhhjnniibleeanchljhakfhecnlg";
const PINNED_CHROMIUM_LAUNCHER_ORIGIN: &str = "chrome-extension://idbkfhhjnniibleeanchljhakfhecnlg";
const PINNED_FIREFOX_EXTENSION_ID: &str = "sesame@usesesame.app";

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(windows, target_os = "linux")))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
use windows::{
    commit, erase, launch_desktop_app, matches, plan, registry_keys, unsupported_error,
    verification_failed_code,
};
#[cfg(windows)]
pub use windows::{is_supported, HOST_FILE_NAME};

#[cfg(target_os = "linux")]
use linux::{
    commit, erase, launch_desktop_app, matches, plan, registry_keys, unsupported_error,
    verification_failed_code,
};
#[cfg(target_os = "linux")]
pub use linux::{is_supported, HOST_FILE_NAME};

#[cfg(not(any(windows, target_os = "linux")))]
use unsupported::{
    commit, erase, launch_desktop_app, matches, plan, registry_keys, unsupported_error,
    verification_failed_code,
};
#[cfg(not(any(windows, target_os = "linux")))]
pub use unsupported::{is_supported, HOST_FILE_NAME};

#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct BrowserIntegrationStatus {
    supported: bool,
    host_available: bool,
    manifest_ready: bool,
    chrome_registered: bool,
    edge_registered: bool,
    firefox_registered: bool,
    ready: bool,
    #[ts(
        type = "'ready' | 'hostMissing' | 'manifestMissing' | 'registrationMissing' | 'unsupported'"
    )]
    code: &'static str,
}

#[derive(Default)]
struct BrowserStatusInputs {
    supported: bool,
    host_available: bool,
    manifest_ready: bool,
    chrome_registered: bool,
    edge_registered: bool,
    firefox_registered: bool,
}

struct RegistrationPlan {
    host: PathBuf,
    chrome: Vec<PathBuf>,
    edge: Vec<PathBuf>,
    firefox: Vec<PathBuf>,
}

struct RegistrationState {
    manifest_ready: bool,
    chrome_registered: bool,
    edge_registered: bool,
    firefox_registered: bool,
}

#[derive(Debug)]
pub struct RegistrationLocations {
    pub manifests: Vec<PathBuf>,
    pub registry_keys: Vec<&'static str>,
}

#[derive(Debug)]
pub struct RegistrationError {
    diagnostic_code: &'static str,
    message: &'static str,
}

impl RegistrationError {
    fn new(diagnostic_code: &'static str, message: &'static str) -> Self {
        Self {
            diagnostic_code,
            message,
        }
    }

    pub fn diagnostic_code(&self) -> &'static str {
        self.diagnostic_code
    }

    pub fn message(&self) -> &'static str {
        self.message
    }
}

pub fn install() -> Result<BrowserIntegrationStatus, RegistrationError> {
    install_registration()
}

pub fn repair() -> Result<BrowserIntegrationStatus, RegistrationError> {
    install_registration()
}

pub fn uninstall() -> Result<(), RegistrationError> {
    if !is_supported() {
        return Err(unsupported_error());
    }
    let locations = locations()?;
    erase_registration(&locations)
}

pub fn locations() -> Result<RegistrationLocations, RegistrationError> {
    if !is_supported() {
        return Err(unsupported_error());
    }
    let plan = plan()?;
    Ok(RegistrationLocations {
        manifests: manifest_paths(&plan),
        registry_keys: registry_keys().to_vec(),
    })
}

fn install_registration() -> Result<BrowserIntegrationStatus, RegistrationError> {
    if !is_supported() {
        return Err(unsupported_error());
    }
    let plan = plan()?;
    if !plan.host.is_file() {
        return Err(RegistrationError::new(
            "registration_host_missing",
            "Sesame's browser helper is missing from this build.",
        ));
    }
    write_plan_manifests(&plan)?;
    commit(&plan)?;
    let status = status();
    if !status.ready {
        return Err(RegistrationError::new(
            verification_failed_code(),
            "Sesame could not verify its browser connection.",
        ));
    }
    Ok(status)
}

fn manifest_paths(plan: &RegistrationPlan) -> Vec<PathBuf> {
    plan.chrome
        .iter()
        .chain(&plan.edge)
        .chain(&plan.firefox)
        .cloned()
        .collect()
}

fn erase_registration(locations: &RegistrationLocations) -> Result<(), RegistrationError> {
    let cleanup_failed = || {
        RegistrationError::new(
            "registration_cleanup_failed",
            "Sesame could not remove its browser connection.",
        )
    };
    for path in &locations.manifests {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(cleanup_failed()),
        }
    }
    erase(&locations.registry_keys)
}

pub fn status() -> BrowserIntegrationStatus {
    if !is_supported() {
        return browser_status(BrowserStatusInputs::default());
    }
    let Ok(plan) = plan() else {
        return browser_status(BrowserStatusInputs {
            supported: true,
            ..Default::default()
        });
    };
    let RegistrationState {
        manifest_ready,
        chrome_registered,
        edge_registered,
        firefox_registered,
    } = matches(&plan);
    browser_status(BrowserStatusInputs {
        supported: true,
        host_available: plan.host.is_file(),
        manifest_ready,
        chrome_registered,
        edge_registered,
        firefox_registered,
    })
}

pub fn run() {
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    match first.as_deref().and_then(|value| value.to_str()) {
        Some("unregister") => {
            finish_verb(uninstall(), "unregister_ok");
            return;
        }
        Some("register") => {
            finish_verb(install().map(|_| ()), "registration_ok");
            return;
        }
        _ => {}
    }
    crate::diagnostics::record_browser_host_process("host_started");
    let second = args.next();
    if !launcher_allowed(first.as_deref(), second.as_deref()) {
        crate::diagnostics::record_browser_host_process("host_origin_rejected");
        return;
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    match serve(stdin.lock(), stdout.lock()) {
        Ok(response_count) if response_count > 0 => {
            crate::diagnostics::record_browser_host_process("host_response_sent")
        }
        Ok(_) => crate::diagnostics::record_browser_host_process("host_no_request"),
        Err(error) if error.kind() == ErrorKind::InvalidData => {
            crate::diagnostics::record_browser_host_process("host_protocol_error")
        }
        Err(_) => crate::diagnostics::record_browser_host_process("host_io_error"),
    }
}

fn finish_verb(result: Result<(), RegistrationError>, ok_code: &'static str) {
    let code = match &result {
        Ok(()) => ok_code,
        Err(error) => error.diagnostic_code(),
    };
    crate::diagnostics::record_browser_host_process(code);
    if result.is_err() {
        std::process::exit(1);
    }
}

/// Chromium passes the calling extension origin first. Firefox passes the manifest
/// path first and the extension id second, so each browser is checked where it speaks.
/// This stays an explicit two-entry allowlist; it is never widened to a wildcard.
fn launcher_allowed(first: Option<&std::ffi::OsStr>, second: Option<&std::ffi::OsStr>) -> bool {
    launcher_origin_allowed(first) || firefox_launcher_allowed(second)
}

fn firefox_launcher_allowed(extension_id: Option<&std::ffi::OsStr>) -> bool {
    extension_id.is_some_and(|value| value == std::ffi::OsStr::new(PINNED_FIREFOX_EXTENSION_ID))
}

fn launcher_origin_allowed(origin: Option<&std::ffi::OsStr>) -> bool {
    // Chrome registers the origin with a trailing slash but launches it bare; accept only those two spellings.
    origin.is_some_and(|value| {
        value == std::ffi::OsStr::new(PINNED_CHROMIUM_LAUNCHER_ORIGIN)
            || value == std::ffi::OsStr::new(&format!("{PINNED_CHROMIUM_LAUNCHER_ORIGIN}/"))
    })
}

fn manifest_write_failed<E>(_: E) -> RegistrationError {
    RegistrationError::new(
        "registration_manifest_failed",
        "Sesame could not save its browser connection.",
    )
}

fn write_manifest_file(path: &Path, bytes: &[u8]) -> Result<(), RegistrationError> {
    let folder = path.parent().ok_or_else(|| {
        RegistrationError::new(
            "registration_manifest_failed",
            "Sesame could not prepare its browser connection.",
        )
    })?;
    std::fs::create_dir_all(folder).map_err(manifest_write_failed)?;
    std::fs::write(path, bytes).map_err(manifest_write_failed)?;
    Ok(())
}

fn write_plan_manifests(plan: &RegistrationPlan) -> Result<(), RegistrationError> {
    let chromium_bytes = manifest_bytes(&plan.host).map_err(manifest_write_failed)?;
    let firefox_bytes = firefox_manifest_bytes(&plan.host).map_err(manifest_write_failed)?;
    for path in plan.chrome.iter().chain(&plan.edge) {
        write_manifest_file(path, &chromium_bytes)?;
    }
    for path in &plan.firefox {
        write_manifest_file(path, &firefox_bytes)?;
    }
    Ok(())
}

#[cfg(any(windows, target_os = "linux"))]
fn plan_registration(plan: &RegistrationPlan) -> (bool, bool, bool) {
    let chrome = plan
        .chrome
        .iter()
        .all(|target| manifest_matches(target, &plan.host));
    let edge = plan
        .edge
        .iter()
        .all(|target| manifest_matches(target, &plan.host));
    let firefox = plan
        .firefox
        .iter()
        .all(|target| firefox_manifest_matches(target, &plan.host));
    (chrome, edge, firefox)
}

fn browser_status(inputs: BrowserStatusInputs) -> BrowserIntegrationStatus {
    let BrowserStatusInputs {
        supported,
        host_available,
        manifest_ready,
        chrome_registered,
        edge_registered,
        firefox_registered,
    } = inputs;
    let ready = supported
        && host_available
        && manifest_ready
        && chrome_registered
        && edge_registered
        && firefox_registered;
    let code = if !supported {
        "unsupported"
    } else if !host_available {
        "hostMissing"
    } else if !manifest_ready {
        "manifestMissing"
    } else if !chrome_registered || !edge_registered || !firefox_registered {
        "registrationMissing"
    } else {
        "ready"
    };
    BrowserIntegrationStatus {
        supported,
        host_available,
        manifest_ready,
        chrome_registered,
        edge_registered,
        firefox_registered,
        ready,
        code,
    }
}

fn manifest_bytes(host: &Path) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "name": HOST_NAME,
        "description": "Sesame Browser Helper native host",
        "path": host,
        "type": "stdio",
        "allowed_origins": [
            format!("chrome-extension://{PINNED_CHROMIUM_EXTENSION_ID}/")
        ]
    }))
}

fn firefox_manifest_bytes(host: &Path) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "name": HOST_NAME,
        "description": "Sesame Browser Helper native host",
        "path": host,
        "type": "stdio",
        "allowed_extensions": [PINNED_FIREFOX_EXTENSION_ID]
    }))
}

#[cfg(any(windows, target_os = "linux"))]
fn firefox_manifest_matches(manifest_path: &Path, host: &Path) -> bool {
    let Ok(bytes) = std::fs::read(manifest_path) else {
        return false;
    };
    let Ok(actual) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    let Ok(expected) = firefox_manifest_bytes(host)
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes))
    else {
        return false;
    };
    actual == expected
}

#[cfg(any(windows, target_os = "linux"))]
fn manifest_matches(manifest_path: &Path, host: &Path) -> bool {
    let Ok(bytes) = std::fs::read(manifest_path) else {
        return false;
    };
    let Ok(actual) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    let Ok(expected) =
        manifest_bytes(host).and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes))
    else {
        return false;
    };
    actual == expected
}

fn serve<R: Read, W: Write>(mut input: R, mut output: W) -> io::Result<usize> {
    serve_with_relay(&mut input, &mut output, desktop_response)
}

fn serve_with_relay<R, W, F>(input: &mut R, output: &mut W, mut relay: F) -> io::Result<usize>
where
    R: Read,
    W: Write,
    F: FnMut(&BrowserRequest) -> BrowserResponse,
{
    let mut response_count = 0;
    loop {
        let mut size_bytes = [0_u8; 4];
        match input.read_exact(&mut size_bytes) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(response_count),
            Err(error) => return Err(error),
        }
        let size = u32::from_le_bytes(size_bytes) as usize;
        if size == 0 || size > MAX_NATIVE_MESSAGE_BYTES {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid native message size",
            ));
        }
        let mut payload = vec![0_u8; size];
        input.read_exact(&mut payload)?;
        let request = match serde_json::from_slice::<BrowserRequest>(&payload) {
            Ok(request) => request,
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid native message",
                ));
            }
        };
        if !supported_protocol_version(request.version) {
            write_message(
                output,
                &BrowserResponse::error(&request.request_id, "Unsupported protocol version."),
            )?;
            response_count += 1;
            continue;
        }
        if !request.validate() {
            write_message(
                output,
                &BrowserResponse::error(&request.request_id, "Invalid browser request."),
            )?;
            response_count += 1;
            continue;
        }

        // This process never opens a vault or derives a key; it relays the broker's closed schema.
        let response = relay(&request);
        if !response.validate_for(&request) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid desktop broker response",
            ));
        }
        write_message(output, &response)?;
        response_count += 1;
    }
}

fn desktop_response(request: &BrowserRequest) -> BrowserResponse {
    let request_bytes = match serde_json::to_vec(request) {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_NATIVE_MESSAGE_BYTES => bytes,
        _ => return unavailable_without_desktop(request),
    };
    let response_bytes = match crate::browser_pipe::request(&request_bytes) {
        Ok(bytes) => bytes,
        Err(_) => return unavailable_without_desktop(request),
    };
    match serde_json::from_slice::<BrowserResponse>(&response_bytes) {
        Ok(response) if response.validate_for(request) => response,
        _ => unavailable_without_desktop(request),
    }
}

fn unavailable_without_desktop(request: &BrowserRequest) -> BrowserResponse {
    if request.message_type == "capabilities" {
        BrowserResponse::capabilities(&request.request_id, false, true)
    } else if request.message_type == "activate" {
        BrowserResponse::activated(&request.request_id, launch_desktop_app())
    } else {
        if request.message_type == "card" {
            BrowserResponse::card_unavailable(&request.request_id, "desktopUnavailable")
        } else {
            BrowserResponse::unavailable(&request.request_id, "desktopUnavailable")
        }
    }
}

fn write_message<W: Write>(output: &mut W, response: &BrowserResponse) -> io::Result<()> {
    let bytes = response.to_zeroizing_bytes().map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            "native response could not be encoded",
        )
    })?;
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_MESSAGE_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "native response too large",
        ));
    }
    output.write_all(&(bytes.len() as u32).to_le_bytes())?;
    output.write_all(&bytes)?;
    output.flush()
}

#[cfg(test)]
mod launcher_tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn the_pinned_chromium_origin_is_accepted_bare_and_with_a_slash() {
        assert!(launcher_allowed(
            Some(OsStr::new(PINNED_CHROMIUM_LAUNCHER_ORIGIN)),
            None
        ));
        assert!(launcher_allowed(
            Some(OsStr::new(&format!("{PINNED_CHROMIUM_LAUNCHER_ORIGIN}/"))),
            None
        ));
    }

    /// Firefox passes the manifest path first and the extension id second.
    #[test]
    fn the_pinned_firefox_extension_id_is_accepted_in_the_second_argument() {
        assert!(launcher_allowed(
            Some(OsStr::new(
                r"C:\Users\someone\AppData\Local\Sesame\host.json"
            )),
            Some(OsStr::new(PINNED_FIREFOX_EXTENSION_ID)),
        ));
    }

    #[test]
    fn another_extension_is_refused_in_either_position() {
        assert!(!launcher_allowed(
            Some(OsStr::new(
                "chrome-extension://aaaabbbbccccddddeeeeffffgggghhhh"
            )),
            None
        ));
        assert!(!launcher_allowed(
            Some(OsStr::new("/path/to/host.json")),
            Some(OsStr::new("someone-else@example.test")),
        ));
    }

    #[test]
    fn a_launch_with_no_arguments_is_refused() {
        assert!(!launcher_allowed(None, None));
    }

    /// The firefox id must not be honoured where Chromium states its origin.
    #[test]
    fn the_firefox_id_is_not_accepted_in_the_chromium_position() {
        assert!(!launcher_allowed(
            Some(OsStr::new(PINNED_FIREFOX_EXTENSION_ID)),
            None
        ));
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::*;

    #[test]
    fn the_chromium_manifest_pins_the_host_and_the_extension_origin() {
        let bytes = manifest_bytes(Path::new("/opt/sesame/sesame-browser-host")).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(manifest["name"], HOST_NAME);
        assert_eq!(manifest["path"], "/opt/sesame/sesame-browser-host");
        assert_eq!(manifest["type"], "stdio");
        assert_eq!(
            manifest["allowed_origins"],
            serde_json::json!([format!(
                "chrome-extension://{PINNED_CHROMIUM_EXTENSION_ID}/"
            )])
        );
    }

    #[test]
    fn the_firefox_manifest_names_the_pinned_extension() {
        let bytes = firefox_manifest_bytes(Path::new("/opt/sesame/sesame-browser-host")).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(manifest["name"], HOST_NAME);
        assert_eq!(manifest["type"], "stdio");
        assert_eq!(
            manifest["allowed_extensions"],
            serde_json::json!([PINNED_FIREFOX_EXTENSION_ID])
        );
        assert!(manifest.get("allowed_origins").is_none());
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn scratch_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "sesame-host-lifecycle-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a scratch directory");
        root
    }

    #[test]
    fn cleanup_removes_every_manifest_and_tolerates_missing_ones() {
        let root = scratch_root("missing-tolerated");
        let written = root.join("written.json");
        let never_written = root.join("never-written.json");
        std::fs::write(&written, b"manifest").expect("a manifest");

        let locations = RegistrationLocations {
            manifests: vec![written.clone(), never_written],
            registry_keys: Vec::new(),
        };
        erase_registration(&locations).expect("cleanup succeeds");

        assert!(!written.exists());
    }

    #[test]
    fn cleanup_fails_when_a_manifest_cannot_be_removed() {
        let root = scratch_root("undeletable");
        let directory = root.join("a-directory");
        std::fs::create_dir_all(&directory).expect("a stand-in manifest");

        let locations = RegistrationLocations {
            manifests: vec![directory],
            registry_keys: Vec::new(),
        };
        assert!(erase_registration(&locations).is_err());
    }

    #[test]
    fn the_verb_words_are_never_valid_launcher_arguments() {
        assert!(!launcher_allowed(
            Some(std::ffi::OsStr::new("register")),
            None
        ));
        assert!(!launcher_allowed(
            Some(std::ffi::OsStr::new("unregister")),
            None
        ));
    }
}
