use std::path::{Path, PathBuf};

use crate::VaultResult;

const TRUSTED_BINARY_DIRECTORIES: [&str; 4] = [
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    "/run/current-system/sw/bin",
];
const SECRET_TOOL: &str = "secret-tool";
const KDE_SECRET_SERVICE: &str = "ksecretd";
const GNOME_KEYRING_DAEMON: &str = "gnome-keyring-daemon";
/// `--start` asks an activatable wallet to come up and exit; a bare
/// gnome-keyring-daemon would stay in the foreground.
const WALLET_DAEMONS: [(&str, &[&str]); 2] = [
    (KDE_SECRET_SERVICE, &[]),
    (GNOME_KEYRING_DAEMON, &["--start", "--components=secrets"]),
];
const DEVICE_KEY_HEADER: &[u8] = b"sesame:linux-device-key:v1\0";
const DEVICE_KEY_AAD: &[u8] = b"sesame:linux-device-protection:v1";

const SECRET_SERVICE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const SECRET_SERVICE_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

fn trusted_binary_in(directories: &[&str], name: &str) -> Option<PathBuf> {
    directories
        .iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|candidate| candidate.is_file())
}

fn secret_tool_path() -> Option<PathBuf> {
    trusted_binary_in(&TRUSTED_BINARY_DIRECTORIES, SECRET_TOOL)
}

pub fn device_protection_available() -> bool {
    secret_tool_path().is_some()
}

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

fn start_wallet_daemons() {
    start_wallet_daemons_in(&TRUSTED_BINARY_DIRECTORIES);
}

fn start_wallet_daemons_in(directories: &[&str]) {
    use std::process::{Command, Stdio};

    for (daemon, arguments) in WALLET_DAEMONS {
        let Some(binary) = trusted_binary_in(directories, daemon) else {
            continue;
        };
        let Ok(mut child) = Command::new(binary)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

fn device_key_lookup_settled(output: &std::process::Output) -> bool {
    output.status.success() || output.stderr.iter().all(u8::is_ascii_whitespace)
}

fn lookup_linux_device_key(secret_tool: &Path) -> VaultResult<std::process::Output> {
    lookup_linux_device_key_within(secret_tool, SECRET_SERVICE_TOTAL_TIMEOUT)
}

fn lookup_linux_device_key_within(
    secret_tool: &Path,
    budget: std::time::Duration,
) -> VaultResult<std::process::Output> {
    let deadline = std::time::Instant::now() + budget;
    let mut output = run_linux_device_key_lookup(secret_tool, SECRET_SERVICE_TIMEOUT.min(budget))?;
    if device_key_lookup_settled(&output) {
        return Ok(output);
    }
    start_wallet_daemons();
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

fn read_linux_device_key(secret_tool: &Path) -> VaultResult<Option<zeroize::Zeroizing<[u8; 32]>>> {
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

pub fn protect_for_device(data: &[u8]) -> VaultResult<Vec<u8>> {
    use rand::RngCore;

    let key = linux_device_key(true)?;
    let mut nonce = [0_u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    protect_with_linux_key(data, &key, &nonce)
}

pub fn unprotect_for_device(data: &[u8]) -> VaultResult<Vec<u8>> {
    let key = linux_device_key(false)?;
    unprotect_with_linux_key(data, &key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
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
    fn wallet_remediation_starts_every_daemon_it_finds() -> VaultResult<()> {
        let directory = std::env::temp_dir().join(format!("sesame-wallets-{}", std::process::id()));
        fs::create_dir_all(&directory)
            .map_err(|_| "could not create the probe directory".to_string())?;
        let mut markers = Vec::new();
        for (daemon, _) in WALLET_DAEMONS {
            let marker = directory.join(format!("{daemon}.started"));
            let script = format!("#!/bin/sh\ntouch '{}'\n", marker.to_string_lossy());
            let binary = directory.join(daemon);
            fs::write(&binary, script.as_bytes())
                .map_err(|_| "could not write the probe binary".to_string())?;
            fs::set_permissions(&binary, PermissionsExt::from_mode(0o755))
                .map_err(|_| "could not make the probe binary executable".to_string())?;
            markers.push(marker);
        }

        let directories = [directory.to_string_lossy().into_owned()];
        let borrowed: Vec<&str> = directories.iter().map(String::as_str).collect();
        start_wallet_daemons_in(&borrowed);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !markers.iter().all(|marker| marker.exists()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the wallet daemons never ran"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

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
