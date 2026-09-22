use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use super::ensure_crypto_provider;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use tauri::{AppHandle, Manager};
use zeroize::Zeroize;

use crate::vault::platform::unprotect_for_device;
use crate::vault::types::ServiceConnectionFile;
use crate::vault::{VaultResult, SERVICE_CONNECTION_FORMAT_VERSION};

/// Rust-only URL: the webview CSP never includes it in `connect-src`.
pub fn service_api_base_url() -> VaultResult<String> {
    let configured = option_env!("SESAME_API_BASE_URL")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Desktop account service is not configured for this build. For local development, create src-tauri/.env.local from src-tauri/.env.example. Release builds require SESAME_API_BASE_URL.".to_string())?;
    let parsed = url::Url::parse(configured)
        .map_err(|_| "Sesame account service URL is invalid.".to_string())?;
    let loopback_http = parsed.scheme() == "http"
        && parsed
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if (parsed.scheme() != "https" && !loopback_http)
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("Sesame account service URL must be an HTTPS origin (or a loopback HTTP development origin).".into());
    }
    Ok(parsed.origin().ascii_serialization())
}

pub fn service_client() -> VaultResult<reqwest::Client> {
    let base_url = service_api_base_url()?;
    let parsed = url::Url::parse(&base_url)
        .map_err(|_| "Sesame account service URL is invalid.".to_string())?;
    let loopback_http = parsed.scheme() == "http"
        && parsed
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if parsed.scheme() != "https" && !loopback_http {
        return Err("Sesame refuses to send an account token over an insecure network URL.".into());
    }
    ensure_crypto_provider();
    reqwest::Client::builder()
        .https_only(!loopback_http)
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| "Sesame could not prepare its account connection.".to_string())
}

fn service_connection_path(app: &AppHandle) -> VaultResult<PathBuf> {
    let mut path = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
    path.push("service-connection.json");
    Ok(path)
}

pub fn write_service_connection(
    app: &AppHandle,
    connection: &ServiceConnectionFile,
) -> VaultResult<()> {
    let path = service_connection_path(app)?;
    let parent = path
        .parent()
        .ok_or("Sesame could not find its local data folder.")?;
    fs::create_dir_all(parent)
        .map_err(|_| "Sesame could not prepare its local data folder.".to_string())?;
    let bytes = serde_json::to_vec(connection)
        .map_err(|_| "Sesame could not save the desktop connection.".to_string())?;
    crate::vault::storage::atomic_replace(&path, &bytes)
}

pub fn read_service_connection(app: &AppHandle) -> VaultResult<ServiceConnectionFile> {
    read_service_connection_at(&service_connection_path(app)?, &service_api_base_url()?)
}

fn read_service_connection_at(
    path: &std::path::Path,
    expected_api_base_url: &str,
) -> VaultResult<ServiceConnectionFile> {
    let bytes = crate::vault::util::require_file_with_limit(
        path,
        64 * 1024,
        "No desktop account connection is stored on this device.",
    )?;
    parse_service_connection(&bytes, expected_api_base_url)
}

fn parse_service_connection(
    bytes: &[u8],
    expected_api_base_url: &str,
) -> VaultResult<ServiceConnectionFile> {
    let connection: ServiceConnectionFile = serde_json::from_slice(bytes)
        .map_err(|_| "The desktop account connection is invalid.".to_string())?;
    if connection.format_version != SERVICE_CONNECTION_FORMAT_VERSION
        || connection.api_base_url != expected_api_base_url
        || connection.protected_token.is_empty()
        || connection.device_id.is_empty()
        || connection.device_name.is_empty()
    {
        return Err("The desktop account connection is invalid.".into());
    }
    Ok(connection)
}

pub fn read_service_token(connection: &ServiceConnectionFile) -> VaultResult<String> {
    let protected = URL_SAFE_NO_PAD
        .decode(&connection.protected_token)
        .map_err(|_| "The desktop account connection is invalid.".to_string())?;
    let mut token = unprotect_for_device(&protected)?;
    let result = std::str::from_utf8(&token)
        .map(str::to_owned)
        .map_err(|_| "The desktop account connection is invalid.".to_string());
    token.zeroize();
    result
}

pub fn remove_service_connection(app: &AppHandle) -> VaultResult<()> {
    let path = service_connection_path(app)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not remove the desktop account connection.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const API_BASE_URL: &str = "https://api.example.test";

    fn connection() -> ServiceConnectionFile {
        ServiceConnectionFile {
            format_version: SERVICE_CONNECTION_FORMAT_VERSION,
            api_base_url: API_BASE_URL.to_string(),
            protected_token: "cHJvdGVjdGVk".to_string(),
            device_id: "device-1".to_string(),
            device_name: "Linux desktop".to_string(),
        }
    }

    fn parse(value: &ServiceConnectionFile) -> VaultResult<ServiceConnectionFile> {
        parse_service_connection(&serde_json::to_vec(value).unwrap(), API_BASE_URL)
    }

    #[test]
    fn a_stored_connection_round_trips() {
        let parsed = parse(&connection()).unwrap();
        assert_eq!(parsed.api_base_url, API_BASE_URL);
        assert_eq!(parsed.device_id, "device-1");
        assert_eq!(parsed.device_name, "Linux desktop");
    }

    #[test]
    fn a_connection_written_for_another_service_is_refused() {
        let mut value = connection();
        value.api_base_url = "https://api.other.test".to_string();
        assert!(parse(&value).is_err());
    }

    #[test]
    fn an_unsupported_connection_format_is_refused() {
        let mut value = connection();
        value.format_version = SERVICE_CONNECTION_FORMAT_VERSION + 1;
        assert!(parse(&value).is_err());
    }

    #[test]
    fn blank_connection_fields_are_refused() {
        for blank in [
            |value: &mut ServiceConnectionFile| value.protected_token.clear(),
            |value: &mut ServiceConnectionFile| value.device_id.clear(),
            |value: &mut ServiceConnectionFile| value.device_name.clear(),
        ] {
            let mut value = connection();
            blank(&mut value);
            assert!(parse(&value).is_err());
        }
    }

    #[test]
    fn a_malformed_connection_is_refused() {
        assert!(parse_service_connection(b"{", API_BASE_URL).is_err());
        assert!(parse_service_connection(b"", API_BASE_URL).is_err());
    }

    #[test]
    fn an_oversized_connection_file_is_refused() {
        let directory = std::env::temp_dir().join(format!(
            "sesame-account-connection-{}",
            crate::vault::util::random_id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("service-connection.json");
        std::fs::write(&path, vec![b' '; 64 * 1024 + 1]).unwrap();
        assert!(read_service_connection_at(&path, API_BASE_URL).is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
