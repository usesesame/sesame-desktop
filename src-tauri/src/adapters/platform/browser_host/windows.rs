use std::path::{Path, PathBuf};

use super::{plan_registration, RegistrationError, RegistrationPlan, RegistrationState, HOST_NAME};

use crate::app_identity::APP_IDENTIFIER;

pub const HOST_FILE_NAME: &str = "sesame-browser-host.exe";

pub fn is_supported() -> bool {
    true
}

pub fn unsupported_error() -> RegistrationError {
    RegistrationError::new(
        "registration_unsupported",
        "Sesame browser integration is not available on this operating system.",
    )
}

pub fn plan() -> Result<RegistrationPlan, RegistrationError> {
    let app_executable = std::env::current_exe().map_err(|_| {
        RegistrationError::new(
            "registration_host_missing",
            "Sesame could not locate its browser helper.",
        )
    })?;
    let folder = local_data_dir()?.join("native-messaging");
    let manifest = folder.join(format!("{HOST_NAME}.json"));
    let firefox_manifest = folder.join(format!("{HOST_NAME}.firefox.json"));
    Ok(RegistrationPlan {
        host: app_executable.with_file_name(HOST_FILE_NAME),
        chrome: vec![manifest.clone()],
        edge: vec![manifest],
        firefox: vec![firefox_manifest],
    })
}

fn local_data_dir() -> Result<PathBuf, RegistrationError> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|directory| directory.join(APP_IDENTIFIER))
        .ok_or_else(|| {
            RegistrationError::new(
                "registration_manifest_failed",
                "Sesame could not locate its browser connection folder.",
            )
        })
}

pub fn commit(plan: &RegistrationPlan) -> Result<(), RegistrationError> {
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
        (CHROME_REGISTRY_KEY, chrome_manifest),
        (EDGE_REGISTRY_KEY, edge_manifest),
        (FIREFOX_REGISTRY_KEY, firefox_manifest),
    ] {
        write_registry_default(registry_path, manifest).map_err(|_| registry_failed())?;
    }
    Ok(())
}

pub fn matches(plan: &RegistrationPlan) -> RegistrationState {
    let (chromium_manifests_match, _, firefox_manifests_match) = plan_registration(plan);
    RegistrationState {
        manifest_ready: chromium_manifests_match && firefox_manifests_match,
        chrome_registered: plan
            .chrome
            .first()
            .is_some_and(|manifest| registry_default_matches(CHROME_REGISTRY_KEY, manifest)),
        edge_registered: plan
            .edge
            .first()
            .is_some_and(|manifest| registry_default_matches(EDGE_REGISTRY_KEY, manifest)),
        firefox_registered: plan
            .firefox
            .first()
            .is_some_and(|manifest| registry_default_matches(FIREFOX_REGISTRY_KEY, manifest)),
    }
}

pub fn verification_failed_code() -> &'static str {
    "registration_registry_failed"
}

pub fn launch_desktop_app() -> bool {
    let Ok(host_executable) = std::env::current_exe() else {
        return false;
    };
    let app_executable = desktop_executable_for(&host_executable);
    app_executable.is_file() && std::process::Command::new(app_executable).spawn().is_ok()
}

fn desktop_executable_for(host_executable: &Path) -> PathBuf {
    host_executable.with_file_name("sesame.exe")
}

const CHROME_REGISTRY_KEY: &str =
    r"Software\Google\Chrome\NativeMessagingHosts\app.usesesame.browser";
const EDGE_REGISTRY_KEY: &str =
    r"Software\Microsoft\Edge\NativeMessagingHosts\app.usesesame.browser";
const FIREFOX_REGISTRY_KEY: &str = r"Software\Mozilla\NativeMessagingHosts\app.usesesame.browser";

pub fn registry_keys() -> &'static [&'static str] {
    &[CHROME_REGISTRY_KEY, EDGE_REGISTRY_KEY, FIREFOX_REGISTRY_KEY]
}

pub fn erase(keys: &[&str]) -> Result<(), RegistrationError> {
    let cleanup_failed = || {
        RegistrationError::new(
            "registration_cleanup_failed",
            "Sesame could not remove its browser connection.",
        )
    };
    for key in keys {
        delete_registry_key(key).map_err(|_| cleanup_failed())?;
    }
    Ok(())
}

fn delete_registry_key(subkey: &str) -> Result<(), u32> {
    use std::{ffi::OsStr, ptr};

    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::{RegDeleteTreeW, HKEY, HKEY_CURRENT_USER},
    };

    let subkey = wide(OsStr::new(subkey));
    let delete_result = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr()) };
    if delete_result == ERROR_SUCCESS || delete_result == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(delete_result)
    }
}

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

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().chain(Some(0)).collect()
}
