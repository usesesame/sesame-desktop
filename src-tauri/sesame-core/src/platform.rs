#[allow(unused_imports)]
use std::fs;
use std::path::Path;

use crate::VaultResult;

#[cfg(windows)]
pub fn protect_for_device(data: &[u8]) -> VaultResult<Vec<u8>> {
    use std::ptr::null;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let protected = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if protected == 0 {
        return Err("Windows could not protect this vault for the current profile.".into());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(result)
}

#[cfg(windows)]
pub fn unprotect_for_device(data: &[u8]) -> VaultResult<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let unprotected = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if unprotected == 0 {
        return Err("Windows could not unlock this vault for the current profile.".into());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(result)
}

#[cfg(windows)]
pub fn device_protection_available() -> bool {
    true
}

#[cfg(target_os = "linux")]
const TRUSTED_BINARY_DIRECTORIES: [&str; 4] = [
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    "/run/current-system/sw/bin",
];
#[cfg(target_os = "linux")]
const SECRET_TOOL: &str = "secret-tool";
#[cfg(target_os = "linux")]
const KDE_SECRET_SERVICE: &str = "ksecretd";
#[cfg(target_os = "linux")]
const DEVICE_KEY_HEADER: &[u8] = b"sesame:linux-device-key:v1\0";
#[cfg(target_os = "linux")]
const DEVICE_KEY_AAD: &[u8] = b"sesame:linux-device-protection:v1";

#[cfg(target_os = "linux")]
fn trusted_binary_in(
    directories: &[&str],
    name: &str,
) -> Option<std::path::PathBuf> {
    directories
        .iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(target_os = "linux")]
fn secret_tool_path() -> Option<std::path::PathBuf> {
    trusted_binary_in(&TRUSTED_BINARY_DIRECTORIES, SECRET_TOOL)
}

#[cfg(target_os = "linux")]
pub fn device_protection_available() -> bool {
    secret_tool_path().is_some()
}

#[cfg(target_os = "linux")]
const SECRET_SERVICE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(target_os = "linux")]
const SECRET_SERVICE_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

#[cfg(target_os = "linux")]
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: std::time::Duration,
) -> VaultResult<std::process::Output> {
    use std::io::Read;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = pipe.read_to_end(&mut stdout);
                }
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_end(&mut stderr);
                }
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {}
            Err(_) => return Err("Sesame could not read the Linux credential store.".into()),
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Sesame could not reach a Linux Secret Service wallet within the time allowed. Unlock your system wallet and try again.".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(target_os = "linux")]
fn run_linux_device_key_lookup(
    secret_tool: &Path,
    timeout: std::time::Duration,
) -> VaultResult<std::process::Output> {
    use std::process::Stdio;

    let child = std::process::Command::new(secret_tool)
        .args([
            "lookup",
            "application",
            "app.usesesame.desktop",
            "purpose",
            "device-protection-v1",
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "Sesame could not open the Linux credential store.".to_string())?;
    wait_with_timeout(child, timeout)
}

#[cfg(target_os = "linux")]
fn start_kde_secret_service() {
    use std::process::{Command, Stdio};

    let Some(service) = trusted_binary_in(&TRUSTED_BINARY_DIRECTORIES, KDE_SECRET_SERVICE) else {
        return;
    };
    let Ok(mut child) = Command::new(service)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

#[cfg(target_os = "linux")]
fn device_key_lookup_settled(output: &std::process::Output) -> bool {
    output.status.success() || output.stderr.iter().all(u8::is_ascii_whitespace)
}

#[cfg(target_os = "linux")]
fn lookup_linux_device_key(secret_tool: &Path) -> VaultResult<std::process::Output> {
    lookup_linux_device_key_within(secret_tool, SECRET_SERVICE_TOTAL_TIMEOUT)
}

#[cfg(target_os = "linux")]
fn lookup_linux_device_key_within(
    secret_tool: &Path,
    budget: std::time::Duration,
) -> VaultResult<std::process::Output> {
    let deadline = std::time::Instant::now() + budget;
    let mut output = run_linux_device_key_lookup(secret_tool, SECRET_SERVICE_TIMEOUT.min(budget))?;
    if device_key_lookup_settled(&output) {
        return Ok(output);
    }
    start_kde_secret_service();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok(output);
        }
        std::thread::sleep(std::time::Duration::from_millis(100).min(remaining));
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok(output);
        }
        output = run_linux_device_key_lookup(secret_tool, remaining.min(SECRET_SERVICE_TIMEOUT))?;
        if device_key_lookup_settled(&output) {
            return Ok(output);
        }
    }
}

#[cfg(target_os = "linux")]
fn read_linux_device_key(
    secret_tool: &Path,
) -> VaultResult<Option<zeroize::Zeroizing<[u8; 32]>>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let output = lookup_linux_device_key(secret_tool)?;
    if !output.status.success() {
        if output.stderr.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err("Sesame could not reach a Linux Secret Service wallet. Start KWallet, GNOME Keyring, or another Secret Service provider and try again.".into());
        }
        return Ok(None);
    }
    let encoded = std::str::from_utf8(&output.stdout)
        .map_err(|_| "The Sesame device key in the Linux credential store is invalid.")?
        .trim();
    let mut decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "The Sesame device key in the Linux credential store is invalid.")?;
    let key: Result<[u8; 32], _> = decoded.as_slice().try_into();
    use zeroize::Zeroize;
    decoded.zeroize();
    let key = key.map_err(|_| {
        "The Sesame device key in the Linux credential store is invalid.".to_string()
    })?;
    Ok(Some(zeroize::Zeroizing::new(key)))
}

#[cfg(target_os = "linux")]
fn create_linux_device_key(secret_tool: &Path) -> VaultResult<zeroize::Zeroizing<[u8; 32]>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand::RngCore;
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut key = zeroize::Zeroizing::new([0_u8; 32]);
    rand::rng().fill_bytes(key.as_mut());
    let mut encoded = URL_SAFE_NO_PAD.encode(key.as_slice());
    let mut child = Command::new(secret_tool)
        .args([
            "store",
            "--label=Sesame device protection",
            "application",
            "app.usesesame.desktop",
            "purpose",
            "device-protection-v1",
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "Sesame could not open the Linux credential store.".to_string())?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        use zeroize::Zeroize;
        encoded.zeroize();
        return Err("Sesame could not write to the Linux credential store.".into());
    };
    let write_result = stdin.write_all(encoded.as_bytes());
    drop(stdin);
    use zeroize::Zeroize;
    encoded.zeroize();
    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Sesame could not write to the Linux credential store.".into());
    }
    if !wait_with_timeout(child, SECRET_SERVICE_TIMEOUT)?.status.success() {
        return Err(
            "Sesame could not save the Linux device key. Unlock your system wallet and try again."
                .into(),
        );
    }
    Ok(key)
}

#[cfg(target_os = "linux")]
fn linux_device_key(create: bool) -> VaultResult<zeroize::Zeroizing<[u8; 32]>> {
    let Some(secret_tool) = secret_tool_path() else {
        return Err("Linux PIN unlock requires Secret Service support from libsecret and your desktop wallet.".into());
    };
    match read_linux_device_key(&secret_tool)? {
        Some(key) => Ok(key),
        None if create => create_linux_device_key(&secret_tool),
        None => Err(
            "The Linux device key is unavailable. Use your master password or recovery kit.".into(),
        ),
    }
}

#[cfg(target_os = "linux")]
fn protect_with_linux_key(data: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> VaultResult<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };

    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: data,
                aad: DEVICE_KEY_AAD,
            },
        )
        .map_err(|_| "Sesame could not protect data with the Linux credential store.")?;
    let mut protected =
        Vec::with_capacity(DEVICE_KEY_HEADER.len() + nonce.len() + ciphertext.len());
    protected.extend_from_slice(DEVICE_KEY_HEADER);
    protected.extend_from_slice(nonce);
    protected.extend_from_slice(&ciphertext);
    Ok(protected)
}

#[cfg(target_os = "linux")]
fn unprotect_with_linux_key(data: &[u8], key: &[u8; 32]) -> VaultResult<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };

    let payload = data
        .strip_prefix(DEVICE_KEY_HEADER)
        .ok_or("This device-protected value was created on another operating system.")?;
    let (nonce, ciphertext) = payload
        .split_at_checked(24)
        .ok_or("The Linux device-protected value is invalid.")?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: DEVICE_KEY_AAD,
            },
        )
        .map_err(|_| "The Linux device-protected value could not be opened.".to_string())
}

#[cfg(target_os = "linux")]
pub fn protect_for_device(data: &[u8]) -> VaultResult<Vec<u8>> {
    use rand::RngCore;

    let key = linux_device_key(true)?;
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    protect_with_linux_key(data, &key, &nonce)
}

#[cfg(target_os = "linux")]
pub fn unprotect_for_device(data: &[u8]) -> VaultResult<Vec<u8>> {
    let key = linux_device_key(false)?;
    unprotect_with_linux_key(data, &key)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn device_protection_available() -> bool {
    false
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn protect_for_device(_data: &[u8]) -> VaultResult<Vec<u8>> {
    Err("Device protection is not available on this operating system.".into())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn unprotect_for_device(_data: &[u8]) -> VaultResult<Vec<u8>> {
    Err("Device protection is not available on this operating system.".into())
}

#[cfg(windows)]
pub fn replace_file(source: &Path, destination: &Path) -> VaultResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err("Sesame could not complete the local vault save.".into());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn replace_file(source: &Path, destination: &Path) -> VaultResult<()> {
    fs::rename(source, destination)
        .map_err(|_| "Sesame could not complete the local vault save.".to_string())
}

#[cfg(unix)]
pub fn create_private_dir(path: &Path) -> VaultResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path)
        .map_err(|_| "Sesame could not prepare its local vault folder.".to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| "Sesame could not protect its local vault folder.".to_string())
}

#[cfg(not(unix))]
pub fn create_private_dir(path: &Path) -> VaultResult<()> {
    fs::create_dir_all(path).map_err(|_| "Sesame could not prepare its local vault folder.".to_string())
}

#[cfg(unix)]
pub fn open_private_file(path: &Path) -> VaultResult<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "Sesame could not prepare the file.".to_string())
}

#[cfg(not(unix))]
pub fn open_private_file(path: &Path) -> VaultResult<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|_| "Sesame could not prepare the file.".to_string())
}

#[cfg(unix)]
pub fn copy_private_file(source: &Path, destination: &Path) -> VaultResult<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut output = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(destination)
        .map_err(|_| "Sesame could not write the vault copy.".to_string())?;
    let mut input = std::fs::File::open(source)
        .map_err(|_| "Sesame could not read the vault copy.".to_string())?;
    std::io::copy(&mut input, &mut output)
        .and_then(|_| output.sync_all())
        .map_err(|_| "Sesame could not write the vault copy.".to_string())
}

#[cfg(not(unix))]
pub fn copy_private_file(source: &Path, destination: &Path) -> VaultResult<()> {
    fs::copy(source, destination)
        .map(|_| ())
        .map_err(|_| "Sesame could not write the vault copy.".to_string())
}

/// Best-effort secure deletion: overwrites with random bytes; wear-leveled storage cannot be guaranteed.
pub fn securely_delete(path: &Path) -> VaultResult<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)
            .map_err(|_| "Sesame could not read a staged vault directory.".to_string())?
        {
            let entry =
                entry.map_err(|_| "Sesame could not read a staged vault entry.".to_string())?;
            securely_delete(&entry.path())?;
        }
        fs::remove_dir(path)
            .map_err(|_| "Sesame could not remove a staged vault directory.".to_string())?;
    } else if path.is_file() {
        overwrite_file(path)?;
        fs::remove_file(path)
            .map_err(|_| "Sesame could not remove a staged vault file.".to_string())?;
    }
    Ok(())
}

fn overwrite_file(path: &Path) -> VaultResult<()> {
    use rand::RngCore;
    use std::io::Write;

    let metadata = fs::metadata(path)
        .map_err(|_| "Sesame could not inspect a staged vault file.".to_string())?;
    let len = metadata.len() as usize;
    if len == 0 {
        return Ok(());
    }

    const PASS_COUNT: usize = 3;
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut chunk = vec![0u8; CHUNK_SIZE.min(len)];

    for pass in 0..PASS_COUNT {
        if pass == 0 {
            rand::rng().fill_bytes(&mut chunk);
        } else if pass == 1 {
            chunk.fill(0xFF);
        } else {
            chunk.fill(0x00);
        }

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| "Sesame could not open a staged vault file for deletion.".to_string())?;
        let mut remaining = len;
        while remaining > 0 {
            let to_write = chunk.len().min(remaining);
            file.write_all(&chunk[..to_write])
                .map_err(|_| "Sesame could not overwrite a staged vault file.".to_string())?;
            remaining -= to_write;
        }
        file.flush()
            .map_err(|_| "Sesame could not flush an overwrite pass.".to_string())?;
        file.sync_all()
            .map_err(|_| "Sesame could not sync an overwrite pass to disk.".to_string())?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn linux_device_protection_round_trips_and_authenticates() -> VaultResult<()> {
        let key = [7_u8; 32];
        let nonce = [9_u8; 24];
        let protected = protect_with_linux_key(b"pepper", &key, &nonce)?;
        assert_eq!(unprotect_with_linux_key(&protected, &key)?, b"pepper");

        let mut tampered = protected;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(unprotect_with_linux_key(&tampered, &key).is_err());
        Ok(())
    }

    #[test]
    fn wait_with_timeout_returns_output_from_a_process_that_exits_in_time() -> VaultResult<()> {
        use std::process::{Command, Stdio};

        let child = Command::new("printf")
            .arg("hello")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "could not spawn printf".to_string())?;
        let output = wait_with_timeout(child, std::time::Duration::from_secs(5))?;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"hello");
        Ok(())
    }

    #[test]
    fn a_wallet_binary_is_found_outside_usr_bin() -> VaultResult<()> {
        let directory = std::env::temp_dir().join(format!("sesame-trusted-{}", std::process::id()));
        fs::create_dir_all(&directory)
            .map_err(|_| "could not create the probe directory".to_string())?;
        let binary = directory.join("secret-tool");
        fs::write(&binary, b"#!/bin/sh\n")
            .map_err(|_| "could not write the probe binary".to_string())?;

        let directories = [directory.to_string_lossy().into_owned()];
        let borrowed: Vec<&str> = directories.iter().map(String::as_str).collect();
        assert_eq!(trusted_binary_in(&borrowed, "secret-tool"), Some(binary));
        assert_eq!(trusted_binary_in(&borrowed, "ksecretd"), None);

        let _ = fs::remove_dir_all(&directory);
        Ok(())
    }

    #[test]
    fn a_settled_lookup_is_one_that_succeeded_or_failed_quietly() {
        use std::os::unix::process::ExitStatusExt;

        let settled = std::process::Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: b"  \n".to_vec(),
        };
        assert!(device_key_lookup_settled(&settled));

        let unsettled = std::process::Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: b"The name is not activatable".to_vec(),
        };
        assert!(!device_key_lookup_settled(&unsettled));
    }

    #[test]
    fn a_wallet_that_keeps_failing_gives_up_inside_the_total_budget() -> VaultResult<()> {
        let directory = std::env::temp_dir().join(format!("sesame-budget-{}", std::process::id()));
        fs::create_dir_all(&directory)
            .map_err(|_| "could not create the probe directory".to_string())?;
        let binary = directory.join("secret-tool");
        fs::write(&binary, b"#!/bin/sh\necho 'not activatable' >&2\nexit 1\n")
            .map_err(|_| "could not write the probe binary".to_string())?;
        fs::set_permissions(&binary, PermissionsExt::from_mode(0o755))
            .map_err(|_| "could not make the probe binary executable".to_string())?;

        let budget = std::time::Duration::from_secs(1);
        let started = std::time::Instant::now();
        let output = lookup_linux_device_key_within(&binary, budget)?;
        let elapsed = started.elapsed();

        assert!(!output.status.success());
        assert!(elapsed >= budget);
        assert!(elapsed < budget + std::time::Duration::from_secs(10));

        let _ = fs::remove_dir_all(&directory);
        Ok(())
    }

    #[test]
    fn wait_with_timeout_kills_and_errors_on_a_process_that_never_exits() -> VaultResult<()> {
        use std::process::{Command, Stdio};

        let child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "could not spawn sleep".to_string())?;
        let pid = child.id();
        let started = std::time::Instant::now();
        let result = wait_with_timeout(child, std::time::Duration::from_millis(200));
        assert!(result.is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        Ok(())
    }
}
