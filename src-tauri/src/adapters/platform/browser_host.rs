use std::io::{self, ErrorKind, Read, Write};
#[cfg(any(windows, target_os = "linux"))]
use std::path::{Path, PathBuf};

use serde::Serialize;
#[cfg(windows)]
use tauri::Manager;

use crate::browser_protocol::{
    supported_protocol_version, BrowserRequest, BrowserResponse, MAX_NATIVE_MESSAGE_BYTES,
};

#[cfg(any(windows, target_os = "linux"))]
const HOST_NAME: &str = "app.usesesame.browser";
#[cfg(windows)]
pub const HOST_FILE_NAME: &str = "sesame-browser-host.exe";
#[cfg(not(windows))]
pub const HOST_FILE_NAME: &str = "sesame-browser-host";
#[cfg(any(windows, target_os = "linux"))]
const PINNED_CHROMIUM_EXTENSION_ID: &str = "idbkfhhjnniibleeanchljhakfhecnlg";
const PINNED_CHROMIUM_LAUNCHER_ORIGIN: &str = "chrome-extension://idbkfhhjnniibleeanchljhakfhecnlg";
const PINNED_FIREFOX_EXTENSION_ID: &str = "sesame@usesesame.app";

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

#[cfg(any(windows, target_os = "linux"))]
struct RegistrationPlan {
    host: PathBuf,
    chrome: Vec<PathBuf>,
    edge: Vec<PathBuf>,
    firefox: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct RegistrationError {
    diagnostic_code: &'static str,
    message: &'static str,
}

pub fn is_supported() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(target_os = "linux")]
    {
        linux_install_supported(std::env::var_os("APPIMAGE").as_deref())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn linux_install_supported(appimage: Option<&std::ffi::OsStr>) -> bool {
    appimage.is_none()
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

pub fn run() {
    crate::diagnostics::record_browser_host_process("host_started");
    let mut args = std::env::args_os().skip(1);
    let (first, second) = (args.next(), args.next());
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

#[cfg(windows)]
fn registration_plan(app: &tauri::AppHandle) -> Result<RegistrationPlan, RegistrationError> {
    let app_executable = std::env::current_exe().map_err(|_| {
        RegistrationError::new(
            "registration_host_missing",
            "Sesame could not locate its browser helper.",
        )
    })?;
    let folder = app
        .path()
        .app_local_data_dir()
        .map_err(|_| {
            RegistrationError::new(
                "registration_manifest_failed",
                "Sesame could not locate its browser connection folder.",
            )
        })?
        .join("native-messaging");
    let manifest = folder.join(format!("{HOST_NAME}.json"));
    let firefox_manifest = folder.join(format!("{HOST_NAME}.firefox.json"));
    Ok(RegistrationPlan {
        host: app_executable.with_file_name(HOST_FILE_NAME),
        chrome: vec![manifest.clone()],
        edge: vec![manifest],
        firefox: vec![firefox_manifest],
    })
}

#[cfg(target_os = "linux")]
fn registration_plan(_app: &tauri::AppHandle) -> Result<RegistrationPlan, RegistrationError> {
    let host = std::env::current_exe()
        .map(|executable| executable.with_file_name(HOST_FILE_NAME))
        .map_err(|_| {
            RegistrationError::new(
                "registration_host_missing",
                "Sesame could not locate its browser helper.",
            )
        })?;
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        RegistrationError::new(
            "registration_manifest_failed",
            "Sesame could not locate your home directory.",
        )
    })?;
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let file = format!("{HOST_NAME}.json");
    let chromium = |vendor: &str| config.join(vendor).join("NativeMessagingHosts").join(&file);
    Ok(RegistrationPlan {
        host,
        chrome: vec![chromium("google-chrome"), chromium("chromium")],
        edge: vec![chromium("microsoft-edge")],
        firefox: vec![home
            .join(".mozilla")
            .join("native-messaging-hosts")
            .join(&file)],
    })
}

#[cfg(any(windows, target_os = "linux"))]
fn manifest_write_failed<E>(_: E) -> RegistrationError {
    RegistrationError::new(
        "registration_manifest_failed",
        "Sesame could not save its browser connection.",
    )
}

#[cfg(any(windows, target_os = "linux"))]
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

#[cfg(any(windows, target_os = "linux"))]
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

#[cfg(windows)]
fn write_plan_registry(plan: &RegistrationPlan) -> Result<(), RegistrationError> {
    let registry_failed = || {
        RegistrationError::new(
            "registration_registry_failed",
            "Sesame could not register its browser connection.",
        )
    };
    let chrome_manifest = plan.chrome.first().ok_or_else(registry_failed)?;
    let edge_manifest = plan.edge.first().ok_or_else(registry_failed)?;
    let firefox_manifest = plan.firefox.first().ok_or_else(registry_failed)?;
    for (registry_path, manifest) in [
        (chrome_registry_path(), chrome_manifest),
        (edge_registry_path(), edge_manifest),
        (firefox_registry_path(), firefox_manifest),
    ] {
        write_registry_default(registry_path, manifest).map_err(|_| registry_failed())?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn register(app: &tauri::AppHandle) -> Result<BrowserIntegrationStatus, RegistrationError> {
    if !is_supported() {
        return Err(RegistrationError::new(
            "registration_unsupported",
            "Browser connection requires an installed Linux package.",
        ));
    }
    register_from_plan(app)
}

#[cfg(windows)]
pub fn register(app: &tauri::AppHandle) -> Result<BrowserIntegrationStatus, RegistrationError> {
    register_from_plan(app)
}

#[cfg(any(windows, target_os = "linux"))]
fn register_from_plan(
    app: &tauri::AppHandle,
) -> Result<BrowserIntegrationStatus, RegistrationError> {
    let plan = registration_plan(app)?;
    if !plan.host.is_file() {
        return Err(RegistrationError::new(
            "registration_host_missing",
            "Sesame's browser helper is missing from this build.",
        ));
    }
    write_plan_manifests(&plan)?;
    #[cfg(windows)]
    write_plan_registry(&plan)?;

    let status = status(app);
    if !status.ready {
        #[cfg(windows)]
        let code = "registration_registry_failed";
        #[cfg(target_os = "linux")]
        let code = "registration_manifest_failed";
        return Err(RegistrationError::new(
            code,
            "Sesame could not verify its browser connection.",
        ));
    }
    Ok(status)
}

#[cfg(target_os = "linux")]
pub fn status(app: &tauri::AppHandle) -> BrowserIntegrationStatus {
    if !is_supported() {
        return browser_status(BrowserStatusInputs::default());
    }
    let Ok(plan) = registration_plan(app) else {
        return browser_status(BrowserStatusInputs {
            supported: true,
            ..Default::default()
        });
    };
    let host_available = plan.host.is_file();
    let (chrome_registered, edge_registered, firefox_registered) = plan_registration(&plan);
    browser_status(BrowserStatusInputs {
        supported: true,
        host_available,
        manifest_ready: host_available,
        chrome_registered,
        edge_registered,
        firefox_registered,
    })
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn register(_app: &tauri::AppHandle) -> Result<BrowserIntegrationStatus, RegistrationError> {
    Err(RegistrationError::new(
        "registration_unsupported",
        "Sesame browser integration is not available on this operating system.",
    ))
}

#[cfg(windows)]
pub fn status(app: &tauri::AppHandle) -> BrowserIntegrationStatus {
    let Ok(plan) = registration_plan(app) else {
        return browser_status(BrowserStatusInputs {
            supported: true,
            ..Default::default()
        });
    };
    let host_available = plan.host.is_file();
    let (manifest_files_match, _, firefox_manifest_match) = plan_registration(&plan);
    let manifest_ready = manifest_files_match && firefox_manifest_match;
    let chrome_registered = plan
        .chrome
        .first()
        .is_some_and(|manifest| registry_default_matches(chrome_registry_path(), manifest));
    let edge_registered = plan
        .edge
        .first()
        .is_some_and(|manifest| registry_default_matches(edge_registry_path(), manifest));
    let firefox_registered = plan
        .firefox
        .first()
        .is_some_and(|manifest| registry_default_matches(firefox_registry_path(), manifest));
    browser_status(BrowserStatusInputs {
        supported: true,
        host_available,
        manifest_ready,
        chrome_registered,
        edge_registered,
        firefox_registered,
    })
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn status(_app: &tauri::AppHandle) -> BrowserIntegrationStatus {
    browser_status(BrowserStatusInputs::default())
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

#[cfg(any(windows, target_os = "linux"))]
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

#[cfg(any(windows, target_os = "linux"))]
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

#[cfg(windows)]
fn chrome_registry_path() -> &'static str {
    r"Software\Google\Chrome\NativeMessagingHosts\app.usesesame.browser"
}

#[cfg(windows)]
fn edge_registry_path() -> &'static str {
    r"Software\Microsoft\Edge\NativeMessagingHosts\app.usesesame.browser"
}

#[cfg(windows)]
fn firefox_registry_path() -> &'static str {
    r"Software\Mozilla\NativeMessagingHosts\app.usesesame.browser"
}

#[cfg(windows)]
fn write_registry_default(subkey: &str, value: &Path) -> Result<(), u32> {
    use std::{ffi::OsStr, ptr};

    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE,
            REG_OPTION_NON_VOLATILE, REG_SZ,
        },
    };

    let subkey = wide(OsStr::new(subkey));
    let value = wide(value.as_os_str());
    let mut key: HKEY = ptr::null_mut();
    let create_result = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    if create_result != ERROR_SUCCESS {
        return Err(create_result);
    }
    let set_result = unsafe {
        RegSetValueExW(
            key,
            ptr::null(),
            0,
            REG_SZ,
            value.as_ptr().cast::<u8>(),
            (value.len() * size_of::<u16>()) as u32,
        )
    };
    unsafe {
        RegCloseKey(key);
    }
    if set_result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(set_result)
    }
}

#[cfg(windows)]
fn registry_default_matches(subkey: &str, expected: &Path) -> bool {
    use std::{ffi::OsStr, os::windows::ffi::OsStringExt, ptr};

    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE,
            REG_SZ,
        },
    };

    let subkey = wide(OsStr::new(subkey));
    let mut key: HKEY = ptr::null_mut();
    let open_result = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if open_result != ERROR_SUCCESS {
        return false;
    }

    let mut value_type = 0;
    let mut byte_count = 0;
    let size_result = unsafe {
        RegQueryValueExW(
            key,
            ptr::null(),
            ptr::null(),
            &mut value_type,
            ptr::null_mut(),
            &mut byte_count,
        )
    };
    if size_result != ERROR_SUCCESS || value_type != REG_SZ || byte_count < 2 {
        unsafe {
            RegCloseKey(key);
        }
        return false;
    }

    let mut value = vec![0_u16; (byte_count as usize).div_ceil(size_of::<u16>())];
    let query_result = unsafe {
        RegQueryValueExW(
            key,
            ptr::null(),
            ptr::null(),
            &mut value_type,
            value.as_mut_ptr().cast::<u8>(),
            &mut byte_count,
        )
    };
    unsafe {
        RegCloseKey(key);
    }
    if query_result != ERROR_SUCCESS || value_type != REG_SZ {
        return false;
    }
    while value.last() == Some(&0) {
        value.pop();
    }
    std::ffi::OsString::from_wide(&value).as_os_str() == expected.as_os_str()
}

#[cfg(windows)]
fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().chain(Some(0)).collect()
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

#[cfg(windows)]
fn launch_desktop_app() -> bool {
    let Ok(host_executable) = std::env::current_exe() else {
        return false;
    };
    let app_executable = desktop_executable_for(&host_executable);
    app_executable.is_file() && std::process::Command::new(app_executable).spawn().is_ok()
}

#[cfg(target_os = "linux")]
fn launch_desktop_app() -> bool {
    let Ok(host_executable) = std::env::current_exe() else {
        return false;
    };
    let app_executable = host_executable.with_file_name("sesame");
    app_executable.is_file() && std::process::Command::new(app_executable).spawn().is_ok()
}

#[cfg(not(any(windows, target_os = "linux")))]
fn launch_desktop_app() -> bool {
    false
}

#[cfg(windows)]
fn desktop_executable_for(host_executable: &Path) -> PathBuf {
    host_executable.with_file_name("sesame.exe")
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

    #[cfg(target_os = "linux")]
    #[test]
    fn an_appimage_mount_is_not_registered_as_a_persistent_browser_host() {
        assert!(linux_install_supported(None));
        assert!(!linux_install_supported(Some(OsStr::new(
            "/tmp/Sesame.AppImage"
        ))));
    }
}
