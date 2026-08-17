use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use tauri::{AppHandle, Manager};
use zeroize::Zeroize;

use crate::vault::platform::unprotect_for_windows_profile;
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
    let path = service_connection_path(app)?;
    let bytes = crate::vault::util::require_file_with_limit(
        &path,
        64 * 1024,
        "No desktop account connection is stored on this device.",
    )?;
    let connection: ServiceConnectionFile = serde_json::from_slice(&bytes)
        .map_err(|_| "The desktop account connection is invalid.".to_string())?;
    if connection.format_version != SERVICE_CONNECTION_FORMAT_VERSION
        || connection.api_base_url != service_api_base_url()?
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
    let mut token = unprotect_for_windows_profile(&protected)?;
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
