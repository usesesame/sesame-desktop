use tauri::AppHandle;

use crate::sync::client::SyncClient;
use crate::vault::VaultResult;

use super::account_service::{read_service_connection, read_service_token, service_target};

pub async fn connect(app: &AppHandle) -> VaultResult<SyncClient> {
    use tauri::Manager;
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
    super::sync_floor::require_sync_allowed(&data_dir).await?;
    let connection = read_service_connection(app)?;
    let target = service_target(&connection)?;
    let token = read_service_token(&connection)?;
    SyncClient::for_target(&target, token).await
}
