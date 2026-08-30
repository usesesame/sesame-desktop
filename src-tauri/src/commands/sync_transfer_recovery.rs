#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncBackupView { pub name: String, pub side: String, pub revision: i64, pub entry_count: usize, pub created_at: String }

#[tauri::command]
pub async fn sync_list_conflict_backups(app: AppHandle, state: tauri::State<'_, VaultState>) -> Result<Vec<SyncBackupView>, String> {
    let directory = crate::sync::conflict_backup::backup_dir(&local_data_dir(&app)?);
    let session = state.session.lock().map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
    let vault = session.as_ref().ok_or("Unlock Sesame to see your recovery copies.")?;
    Ok(crate::sync::conflict_backup::list(&directory, &vault.key).into_iter().map(|entry| SyncBackupView { name: entry.file_name, side: entry.side, revision: entry.revision, entry_count: entry.entry_count, created_at: entry.created_at }).collect())
}

#[tauri::command]
pub async fn sync_restore_conflict_backup(app: AppHandle, state: tauri::State<'_, VaultState>, name: String) -> Result<SyncTransferResult, String> {
    if name.is_empty() || name.len() > 128 || name.contains(['/', '\\', ':']) || name.contains("..") || !name.ends_with(".sesame") { return Err("That recovery copy could not be found.".into()); }
    let data_dir = local_data_dir(&app)?; let directory = crate::sync::conflict_backup::backup_dir(&data_dir); let path = directory.join(&name);
    let mut session = state.session.lock().map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
    let vault = session.as_mut().ok_or("Unlock Sesame before restoring a recovery copy.")?;
    let contents = crate::sync::conflict_backup::read_verified(&path, &vault.key)?;
    let payload: crate::vault::types::VaultPayload = serde_json::from_slice(&contents.payload).map_err(|_| "That recovery copy could not be read.".to_string())?;
    let entry_count = payload.entries.len();
    let current = vault.open_payload()?;
    let current_payload = serde_json::to_vec(&*current).map_err(|_| "Sesame could not read the local vault.".to_string())?;
    let written = crate::sync::conflict_backup::write_verified(&directory, vault, crate::sync::conflict_backup::Side::ThisDevice, contents.revision, &current_payload, &backup_stamp())?;
    crate::vault::storage::commit_payload_change(vault, payload)?;
    state.advance_session_epoch();
    drop(session);
    crate::browser_fill::cancel_pending_approvals(&app);
    crate::sync::state::forget_protected(&crate::sync::state::state_path(&data_dir))?;
    crate::sync::conflict_backup::prune(&directory, &[written]);
    Ok(SyncTransferResult { revision: contents.revision, vault_epoch: 0, entry_count })
}
