use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE, LPARAM, WIN32_ERROR,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegGetValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    RRF_RT_REG_SZ,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};

use crate::machine_path::{
    plan_add, plan_remove, registry_bytes, string_data, Mode, Plan, Request, EXIT_CHANGED,
    EXIT_FAILED, EXIT_REFUSED, EXIT_UNCHANGED,
};

const ENVIRONMENT_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const CURRENT_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
const PRODUCT_FOLDER: &str = "Sesame";
const ATTEMPTS: usize = 3;
const BROADCAST_TIMEOUT_MILLISECONDS: u32 = 5_000;

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn is_elevated() -> bool {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut length = 0_u32;
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            ptr::addr_of_mut!(elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    read != 0 && elevation.TokenIsElevated != 0
}

fn program_files() -> Option<String> {
    let key = wide(CURRENT_VERSION_KEY);
    let name = wide("ProgramFilesDir");
    let mut size = 0_u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS || size == 0 {
        return None;
    }
    let mut buffer = vec![0_u16; (size as usize).div_ceil(2)];
    let mut filled = u32::try_from(buffer.len() * 2).ok()?;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut filled,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..end]).ok()
}

struct Install {
    program_files: String,
    folder: String,
}

fn own_install() -> Result<Install, String> {
    let program_files = program_files()
        .ok_or_else(|| "Sesame could not read where Program Files is.".to_string())?;
    let program_files = program_files.trim_end_matches('\\');
    if program_files.is_empty() {
        return Err("Sesame could not read where Program Files is.".to_string());
    }
    let folder = format!(r"{program_files}\{PRODUCT_FOLDER}\cli");
    let expected = Path::new(&folder).join("sesame.exe");
    let installed = match (
        std::env::current_exe().and_then(std::fs::canonicalize),
        std::fs::canonicalize(&expected),
    ) {
        (Ok(running), Ok(expected)) => running == expected,
        _ => false,
    };
    if installed {
        Ok(Install {
            program_files: program_files.to_string(),
            folder,
        })
    } else {
        Err(format!(
            "Only the copy of sesame.exe installed at {} can change the system Path.",
            expected.display()
        ))
    }
}

fn read_value(key: &Key, name: &[u16]) -> Result<(REG_VALUE_TYPE, Vec<u8>), WIN32_ERROR> {
    for _ in 0..8 {
        let mut kind: REG_VALUE_TYPE = 0;
        let mut size = 0_u32;
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                &mut size,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(status);
        }
        let mut buffer = vec![0_u8; size as usize + 2];
        let mut filled = u32::try_from(buffer.len()).map_err(|_| ERROR_MORE_DATA)?;
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                buffer.as_mut_ptr(),
                &mut filled,
            )
        };
        if status == ERROR_MORE_DATA {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(status);
        }
        buffer.truncate(filled as usize);
        return Ok((kind, buffer));
    }
    Err(ERROR_MORE_DATA)
}

fn broadcast() {
    let environment = wide("Environment");
    let mut result = 0_usize;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            environment.as_ptr() as LPARAM,
            SMTO_ABORTIFHUNG,
            BROADCAST_TIMEOUT_MILLISECONDS,
            &mut result,
        );
    }
}

fn left_alone(plan: &Plan, folder: &str) -> String {
    match plan {
        Plan::AlreadyPresent => {
            format!("The system Path already holds {folder}, so Sesame left it as it was.")
        }
        Plan::Absent => {
            format!("The system Path does not hold {folder}, so Sesame left it as it was.")
        }
        Plan::NotSesameForm => format!(
            "The system Path holds {folder} in a form Sesame did not add, so Sesame left it."
        ),
        Plan::Duplicated => format!(
            "The system Path holds {folder} more than once, so Sesame left it. Remove the entries you no longer need by hand."
        ),
        Plan::Write(_) => String::new(),
    }
}

fn change(mode: Mode, install: &Install) -> i32 {
    let folder = install.folder.as_str();
    let folder_units: Vec<u16> = folder.encode_utf16().collect();
    let key_name = wide(ENVIRONMENT_KEY);
    let mut raw: HKEY = ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_name.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            &mut raw,
        )
    };
    if status != ERROR_SUCCESS {
        eprintln!("Sesame could not open the system environment, error {status}.");
        return EXIT_FAILED;
    }
    let key = Key(raw);
    let value_name = wide("Path");
    for _ in 0..ATTEMPTS {
        let (kind, bytes) = match read_value(&key, &value_name) {
            Ok(read) => read,
            Err(ERROR_FILE_NOT_FOUND) => {
                eprintln!("The system has no Path value, so Sesame left it as it was.");
                return EXIT_FAILED;
            }
            Err(code) => {
                eprintln!("Sesame could not read the system Path, error {code}.");
                return EXIT_FAILED;
            }
        };
        if kind != REG_SZ && kind != REG_EXPAND_SZ {
            eprintln!("The system Path is not a text value, so Sesame left it as it was.");
            return EXIT_FAILED;
        }
        let Some(units) = string_data(&bytes) else {
            eprintln!("The system Path is not one text value, so Sesame left it as it was.");
            return EXIT_FAILED;
        };
        let expands = kind == REG_EXPAND_SZ;
        let lookup = |name: &str| {
            if !expands {
                None
            } else if name.eq_ignore_ascii_case("ProgramFiles")
                || name.eq_ignore_ascii_case("ProgramW6432")
            {
                Some(install.program_files.clone())
            } else {
                std::env::var(name).ok()
            }
        };
        let plan = match mode {
            Mode::Add => plan_add(&units, &folder_units, &lookup),
            Mode::Remove => plan_remove(&units, &folder_units, &lookup),
        };
        let written = match plan {
            Plan::Write(written) => written,
            other => {
                eprintln!("{}", left_alone(&other, folder));
                return EXIT_UNCHANGED;
            }
        };
        match read_value(&key, &value_name) {
            Ok((again_kind, again)) if again_kind == kind && again == bytes => {}
            Ok(_) => continue,
            Err(code) => {
                eprintln!("Sesame could not read the system Path again, error {code}.");
                return EXIT_FAILED;
            }
        }
        let data = registry_bytes(&written);
        let Ok(length) = u32::try_from(data.len()) else {
            eprintln!("The new system Path is too large to write.");
            return EXIT_FAILED;
        };
        let status =
            unsafe { RegSetValueExW(key.0, value_name.as_ptr(), 0, kind, data.as_ptr(), length) };
        if status != ERROR_SUCCESS {
            eprintln!("Sesame could not write the system Path, error {status}.");
            return EXIT_FAILED;
        }
        broadcast();
        return EXIT_CHANGED;
    }
    eprintln!("Another program kept changing the system Path, so Sesame left it as it was.");
    EXIT_FAILED
}

pub fn run(request: Request) -> i32 {
    let mode = match request {
        Request::Run(mode) => mode,
        Request::Malformed => {
            eprintln!("This command takes no other arguments.");
            return EXIT_REFUSED;
        }
    };
    if !is_elevated() {
        eprintln!(
            "Only the Sesame installer, running as an administrator, can change the system Path."
        );
        return EXIT_REFUSED;
    }
    match own_install() {
        Ok(install) => change(mode, &install),
        Err(problem) => {
            eprintln!("{problem}");
            EXIT_REFUSED
        }
    }
}
