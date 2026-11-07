#[tauri::command]
pub async fn sync_list_conflict_backups(app: AppHandle, state: tauri::State<'_, VaultState>) -> Result<Vec<SyncBackupView>, String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    crate::application::sync_recovery::list_conflict_backups_in_state(&state, &store)
}

#[tauri::command]
pub async fn sync_restore_conflict_backup(app: AppHandle, state: tauri::State<'_, VaultState>, name: String) -> Result<SyncTransferResult, String> {
    let store = SyncStore::new(local_data_dir(&app)?);
    crate::application::sync_recovery::restore_conflict_backup_in_state(
        &state,
        &store,
        &DesktopHostEffects::new(&app),
        &name,
    )
}
