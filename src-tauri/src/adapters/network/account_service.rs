use std::fs;
use std::path::PathBuf;

use tauri::{AppHandle, Manager};

use crate::vault::types::ServiceConnectionFile;
use crate::vault::VaultResult;

pub(crate) use sesame_app::network::account_service::*;

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
    read_service_connection_at(
        &service_connection_path(app)?,
        service_api_base_url().ok().as_deref(),
    )
}

pub fn remove_service_connection(app: &AppHandle) -> VaultResult<()> {
    let path = service_connection_path(app)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not remove the desktop account connection.".into()),
    }
}
