use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{encrypt_bytes, serialize_payload};
use crate::loader::{Credential, VaultLoader};
use crate::platform::{
    copy_private_file, create_private_dir, open_private_file, replace_file, unprotect_for_device,
};
use crate::{
    types::*,
    util::{random_id, unix_timestamp},
};
use crate::{VaultFile, VaultPayload, VaultResult};

pub fn unwrap_vault_key(file: &VaultFile, secret: &str) -> VaultResult<Zeroizing<[u8; 32]>> {
    VaultLoader::unwrap_key(file, Credential::PasswordOrRecoveryKit(secret)).map_err(Into::into)
}

pub fn authenticate_vault_file(file: &VaultFile, secret: &str) -> VaultResult<()> {
    VaultLoader::authenticate(file, Credential::PasswordOrRecoveryKit(secret))
        .map(|_| ())
        .map_err(Into::into)
}

pub fn verify_backup_file(path: &Path, secret: &str) -> VaultResult<BackupVerification> {
    let file = read_backup_file(path)?;
    let authenticated =
        VaultLoader::authenticate(&file, Credential::PasswordOrRecoveryKit(secret))?;
    let payload = authenticated.payload();
    Ok(BackupVerification {
        file_name: path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
            .ok_or("Sesame could not read the backup file name.")?,
        format_version: file.format_version,
        vault_name: payload.vault_name.clone(),
        entry_count: payload.entries.len(),
        vault_id: payload.vault_id.clone(),
        revision: payload.revision,
    })
}

/// Device-bound material on another profile can never be used again.
fn usable_on_this_profile(protected: &str) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(protected) else {
        return false;
    };
    match unprotect_for_device(&bytes) {
        Ok(mut plain) => {
            plain.zeroize();
            true
        }
        Err(_) => false,
    }
}

/// A restored vault must never advertise an unlock method that must fail.
pub fn strip_unusable_device_material(file: &mut VaultFile) {
    if file
        .pin_wrap
        .as_ref()
        .is_some_and(|pin_wrap| !usable_on_this_profile(&pin_wrap.protected_pepper))
    {
        file.pin_wrap = None;
    }
    if file
        .legacy_device_wrap
        .as_deref()
        .is_some_and(|wrap| !usable_on_this_profile(wrap))
    {
        file.legacy_device_wrap = None;
    }
    if file
        .hello_wrap
        .as_ref()
        .is_some_and(|wrap| !crate::windows_hello::key_exists(&wrap.key_name))
    {
        file.hello_wrap = None;
    }
}

pub const RECOVERY_HEALTH_FILE: &str = "recovery-health.sesame";

pub fn managed_vault_paths(vault: &Path) -> Vec<PathBuf> {
    let parent = vault.parent().unwrap_or_else(|| Path::new(""));
    vec![
        vault.to_path_buf(),
        vault.with_extension("sesame.prev"),
        vault.with_extension("sesame.tmp"),
        parent.join(crate::storage::PIN_THROTTLE_FILE),
        parent.join(RECOVERY_HEALTH_FILE),
        parent.join("backups"),
    ]
}

pub fn stage_managed_vault_files(vault: &Path, parent: &Path) -> VaultResult<StagedVaultFiles> {
    stage_managed_vault_files_with(vault, parent, |from, to| fs::rename(from, to))
}

pub fn stage_managed_vault_files_with<F>(
    vault: &Path,
    parent: &Path,
    mut move_path: F,
) -> VaultResult<StagedVaultFiles>
where
    F: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    let staging_dir = parent.join(format!(".sesame-delete-{}", random_id()));
    fs::create_dir(&staging_dir).map_err(|_| {
        "Sesame could not prepare the local vault for deletion. The vault was left unchanged."
            .to_string()
    })?;

    let mut moved = Vec::new();
    for source in managed_vault_paths(vault) {
        if !source.exists() {
            continue;
        }
        let name = source
            .file_name()
            .ok_or("Sesame could not prepare the local vault for deletion.")?;
        let destination = staging_dir.join(name);
        match move_path(&source, &destination) {
            Ok(()) => moved.push((source, destination)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                let rollback_ok =
                    moved
                        .iter()
                        .rev()
                        .fold(true, |all_restored, (original, staged)| {
                            fs::rename(staged, original).is_ok() && all_restored
                        });
                let _ = fs::remove_dir(&staging_dir);
                if rollback_ok {
                    return Err("Sesame could not prepare every local vault file for deletion. The vault was left unchanged.".into());
                }
                return Err("Sesame could not prepare every local vault file for deletion, and could not fully restore the staged files. Do not restart Sesame; contact support with this error.".into());
            }
        }
    }

    Ok(StagedVaultFiles { staging_dir })
}

pub fn csv_export_bytes(payload: &VaultPayload) -> VaultResult<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "name",
            "url",
            "username",
            "email",
            "password",
            "folder",
            "totp",
            "backup_codes",
            "recovery_email",
            "recovery_phone",
            "recovery_not_applicable",
            "notes",
        ])
        .map_err(|_| "Sesame could not prepare the readable export.".to_string())?;
    for entry in &payload.entries {
        let title = safe_csv_cell(&entry.title);
        let url = safe_csv_cell(&entry.url);
        let username = safe_csv_cell(&entry.username);
        let email = safe_csv_cell(&entry.email);
        let password = safe_csv_cell(&entry.password);
        let folder_name = crate::snapshot::folder_name_for(payload, entry);
        let folder = safe_csv_cell(&folder_name);
        let totp = safe_csv_cell(entry.totp.as_deref().unwrap_or_default());
        let joined_backup_codes = entry.backup_codes.join("\n");
        let backup_codes = safe_csv_cell(&joined_backup_codes);
        let recovery_email = safe_csv_cell(entry.recovery_email.as_deref().unwrap_or_default());
        let recovery_phone = safe_csv_cell(entry.recovery_phone.as_deref().unwrap_or_default());
        let notes = safe_csv_cell(entry.notes.as_deref().unwrap_or_default());
        writer
            .write_record([
                title.as_ref(),
                url.as_ref(),
                username.as_ref(),
                email.as_ref(),
                password.as_ref(),
                folder.as_ref(),
                totp.as_ref(),
                backup_codes.as_ref(),
                recovery_email.as_ref(),
                recovery_phone.as_ref(),
                if entry.recovery_not_applicable {
                    "true"
                } else {
                    "false"
                },
                notes.as_ref(),
            ])
            .map_err(|_| "Sesame could not prepare the readable export.".to_string())?;
    }
    writer
        .into_inner()
        .map_err(|_| "Sesame could not prepare the readable export.".to_string())
}

pub fn identities_csv_bytes(payload: &VaultPayload) -> VaultResult<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "label",
            "full_name",
            "email",
            "phone",
            "address_line1",
            "address_line2",
            "city",
            "region",
            "postal_code",
            "country",
        ])
        .map_err(|_| "Sesame could not prepare the readable export.".to_string())?;
    for identity in &payload.identities {
        let label = safe_csv_cell(&identity.label);
        let full_name = safe_csv_cell(&identity.full_name);
        let email = safe_csv_cell(&identity.email);
        let phone = safe_csv_cell(&identity.phone);
        let address_line1 = safe_csv_cell(&identity.address_line1);
        let address_line2 = safe_csv_cell(&identity.address_line2);
        let city = safe_csv_cell(&identity.city);
        let region = safe_csv_cell(&identity.region);
        let postal_code = safe_csv_cell(&identity.postal_code);
        let country = safe_csv_cell(&identity.country);
        writer
            .write_record([
                label.as_ref(),
                full_name.as_ref(),
                email.as_ref(),
                phone.as_ref(),
                address_line1.as_ref(),
                address_line2.as_ref(),
                city.as_ref(),
                region.as_ref(),
                postal_code.as_ref(),
                country.as_ref(),
            ])
            .map_err(|_| "Sesame could not prepare the readable export.".to_string())?;
    }
    writer
        .into_inner()
        .map_err(|_| "Sesame could not prepare the readable export.".to_string())
}

fn safe_csv_cell(value: &str) -> std::borrow::Cow<'_, str> {
    if value
        .chars()
        .next()
        .is_some_and(|character| matches!(character, '=' | '+' | '-' | '@' | '\t' | '\r' | '\n'))
    {
        std::borrow::Cow::Owned(format!("'{value}"))
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

/// Pre-change encrypted copy; the change can be undone by restoring it.
pub fn snapshot_vault_revision(vault: &Path, label: &str) -> VaultResult<Option<String>> {
    if !vault.exists() {
        return Ok(None);
    }
    let backup_dir = vault
        .parent()
        .ok_or("Sesame could not find the vault folder.")?
        .join("backups");
    fs::create_dir_all(&backup_dir)
        .map_err(|_| "Sesame could not prepare a revision before this change.".to_string())?;
    let name = format!(
        "sesame-before-{label}-{}-{}.sesame",
        unix_timestamp(),
        random_id()
    );
    fs::copy(vault, backup_dir.join(&name))
        .map_err(|_| "Sesame could not create a revision before this change.".to_string())?;
    Ok(Some(name))
}

pub struct PreparedRestore {
    file: VaultFile,
    key: Zeroizing<[u8; 32]>,
}

pub struct RestoreInstall {
    pub safety_backup_name: Option<String>,
    pub pin_unlock_available: bool,
    pub hello_unlock_available: bool,
}

pub fn prepare_backup_for_restore(
    source: &Path,
    destination: &Path,
    secret: &str,
) -> VaultResult<PreparedRestore> {
    if same_file(source, destination) {
        return Err("Choose an exported backup, not Sesame's active vault file.".into());
    }

    let source_file = read_backup_file(source)?;
    let opened = VaultLoader::open(&source_file, Credential::PasswordOrRecoveryKit(secret))
        .map_err(|error| match error {
            crate::loader::LoadFailure::RecoveryRequired { format } => migration_error(
                format,
                "its authenticated records need the recovery reader.",
            ),
            error => error.to_string(),
        })?;
    validate_migrated_payload(&opened.payload, opened.migration.source_format)?;
    let mut file = opened.file.clone();
    if file.setup_complete && (file.recovery_kdf.is_none() || file.recovery_wrap.is_none()) {
        return Err(migration_error(
            opened.migration.source_format,
            "its recovery access is incomplete.",
        ));
    }
    strip_unusable_device_material(&mut file);
    let payload = Zeroizing::new(serialize_payload(&opened.payload).map_err(|_| {
        migration_error(
            opened.migration.source_format,
            "its migrated records could not be encoded.",
        )
    })?);
    let aad =
        crate::payload_aad_for_file(file.format_version, file.setup_complete).map_err(|_| {
            migration_error(
                opened.migration.source_format,
                "its current authentication label is invalid.",
            )
        })?;
    file.payload = encrypt_bytes(&opened.key, &payload, aad).map_err(|_| {
        migration_error(
            opened.migration.source_format,
            "its migrated records could not be resealed.",
        )
    })?;
    let sealed = Zeroizing::new(serde_json::to_vec(&file).map_err(|_| {
        migration_error(
            opened.migration.source_format,
            "the upgraded vault file could not be encoded.",
        )
    })?);
    let reopened =
        VaultLoader::load(&sealed, Credential::PasswordOrRecoveryKit(secret)).map_err(|_| {
            migration_error(
                opened.migration.source_format,
                "the resealed vault did not authenticate.",
            )
        })?;
    let reopened_payload = Zeroizing::new(serialize_payload(&reopened.payload).map_err(|_| {
        migration_error(
            opened.migration.source_format,
            "the resealed records could not be checked.",
        )
    })?);
    if reopened.migration.required() || *payload != *reopened_payload {
        return Err(migration_error(
            opened.migration.source_format,
            "the upgraded records changed during validation.",
        ));
    }
    Ok(PreparedRestore {
        file,
        key: Zeroizing::new(*opened.key),
    })
}

pub fn apply_restored_vault_file(
    destination: &Path,
    prepared: &PreparedRestore,
) -> VaultResult<RestoreInstall> {
    apply_restored_vault_file_with_storage(destination, prepared, &mut FileRestoreStorage)
}

fn apply_restored_vault_file_with_storage<S: RestoreStorage>(
    destination: &Path,
    prepared: &PreparedRestore,
    storage: &mut S,
) -> VaultResult<RestoreInstall> {
    let safety_backup_name = if storage.exists(destination) {
        let backup_dir = destination
            .parent()
            .ok_or("Sesame could not find the vault folder. Restart Sesame and try again.")?
            .join("backups");
        storage.create_dir(&backup_dir).map_err(|_| {
            "Sesame could not prepare the safety-backup folder. Check local storage and try again."
                .to_string()
        })?;
        let name = format!(
            "sesame-before-restore-{}-{}.sesame",
            unix_timestamp(),
            random_id()
        );
        let safety = backup_dir.join(&name);
        if let Err(error) = storage.copy_safety(destination, &safety).and_then(|()| {
            let active = storage.read(destination)?;
            let copied = storage.read(&safety)?;
            if active.as_slice() == copied.as_slice() {
                Ok(())
            } else {
                Err("Sesame could not verify the safety backup. The active vault was not changed. Check local storage and try again.".to_string())
            }
        }) {
            storage.remove(&safety);
            return Err(error);
        }
        Some(name)
    } else {
        None
    };

    let bytes = Zeroizing::new(serde_json::to_vec(&prepared.file).map_err(|_| {
        "Sesame could not prepare the restored vault. Keep the original backup and try again."
            .to_string()
    })?);
    let parent = destination
        .parent()
        .ok_or("Sesame could not find the vault folder. Restart Sesame and try again.")?;
    storage.create_dir(parent).map_err(|_| {
        "Sesame could not prepare the vault folder. Check local storage and try again.".to_string()
    })?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Sesame could not read the local vault file name. Restart Sesame and try again.")?;
    let temporary = parent.join(format!(".{name}.{}.restore.tmp", random_id()));
    let staged = storage
        .write_temporary(&temporary, &bytes)
        .and_then(|()| storage.sync_temporary(&temporary))
        .and_then(|()| {
            let stored = storage.read(&temporary)?;
            if stored.as_slice() != bytes.as_slice() {
                return Err("Sesame could not verify the restored vault write. The active vault was not changed. Check local storage and try again.".to_string());
            }
            let reopened = VaultLoader::load(&stored, Credential::VaultKey(&prepared.key))?;
            if reopened.migration.required() {
                return Err("Sesame could not validate the restored vault write. The active vault was not changed. Keep the original backup and try again.".to_string());
            }
            Ok(())
        });
    if let Err(error) = staged {
        storage.remove(&temporary);
        return Err(error);
    }
    if let Err(error) = storage.replace(&temporary, destination) {
        storage.remove(&temporary);
        return Err(error);
    }

    let pin_unlock_available = prepared.file.pin_wrap.is_some();
    let hello_unlock_available = prepared.file.hello_wrap.is_some();
    Ok(RestoreInstall {
        safety_backup_name,
        pin_unlock_available,
        hello_unlock_available,
    })
}

/// Single-step authenticate-and-apply; the restore command splits the phases itself.
pub fn restore_backup_to(
    source: &Path,
    destination: &Path,
    secret: &str,
) -> VaultResult<RestoreInstall> {
    let prepared = prepare_backup_for_restore(source, destination, secret)?;
    apply_restored_vault_file(destination, &prepared)
}

fn same_file(source: &Path, destination: &Path) -> bool {
    if source == destination {
        return true;
    }
    let same_metadata = match (fs::metadata(source), fs::metadata(destination)) {
        (Ok(source), Ok(destination)) => same_file_metadata(&source, &destination),
        _ => false,
    };
    if same_metadata {
        return true;
    }
    match (fs::canonicalize(source), fs::canonicalize(destination)) {
        (Ok(source), Ok(destination)) => source == destination,
        _ => false,
    }
}

#[cfg(unix)]
fn same_file_metadata(source: &fs::Metadata, destination: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    source.dev() == destination.dev() && source.ino() == destination.ino()
}

#[cfg(windows)]
fn same_file_metadata(source: &fs::Metadata, destination: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    match (
        (source.volume_serial_number(), source.file_index()),
        (destination.volume_serial_number(), destination.file_index()),
    ) {
        (
            (Some(source_volume), Some(source_index)),
            (Some(destination_volume), Some(destination_index)),
        ) => source_volume == destination_volume && source_index == destination_index,
        _ => false,
    }
}

#[cfg(not(any(unix, windows)))]
fn same_file_metadata(_source: &fs::Metadata, _destination: &fs::Metadata) -> bool {
    false
}

fn validate_migrated_payload(payload: &VaultPayload, source_format: u8) -> VaultResult<()> {
    if payload
        .vault_id
        .as_deref()
        .is_none_or(|id| id.trim().is_empty())
        || payload.revision == 0
    {
        return Err(migration_error(
            source_format,
            "its vault identity or revision is invalid.",
        ));
    }
    let mut folder_ids = HashSet::new();
    let mut folder_names = HashSet::new();
    for folder in &payload.folders {
        if folder.id.trim().is_empty()
            || folder.name.trim().is_empty()
            || !folder_ids.insert(folder.id.as_str())
            || !folder_names.insert(folder.name.to_ascii_lowercase())
        {
            return Err(migration_error(source_format, "its folders are invalid."));
        }
    }
    let mut item_ids = HashSet::new();
    for item in payload.item_views() {
        if item.id().trim().is_empty()
            || item_revision(&item) == 0
            || !item_ids.insert(item.id().to_string())
        {
            return Err(migration_error(
                source_format,
                "its item identifiers are invalid.",
            ));
        }
        if item
            .metadata()
            .item_folder_id()
            .is_some_and(|folder_id| !folder_ids.contains(folder_id))
        {
            return Err(migration_error(
                source_format,
                "an item refers to a missing folder.",
            ));
        }
    }
    let mut history_ids = HashSet::new();
    for entry in &payload.history {
        if entry.id.trim().is_empty()
            || entry.item.id().trim().is_empty()
            || item_revision(&entry.item) == 0
            || entry.captured_at == 0
            || entry
                .item
                .metadata()
                .item_folder_id()
                .is_some_and(str::is_empty)
            || !history_ids.insert(entry.id.as_str())
        {
            return Err(migration_error(
                source_format,
                "its history identifiers are invalid.",
            ));
        }
    }
    let mut trash_ids = HashSet::new();
    for entry in &payload.trash {
        let id = entry.item.id();
        if id.trim().is_empty()
            || item_revision(&entry.item) == 0
            || entry.deleted_at == 0
            || entry
                .item
                .metadata()
                .item_folder_id()
                .is_some_and(str::is_empty)
            || item_ids.contains(id)
            || !trash_ids.insert(id)
        {
            return Err(migration_error(
                source_format,
                "its trash identifiers are invalid.",
            ));
        }
    }
    serialize_payload(payload)
        .map(|_| ())
        .map_err(|_| migration_error(source_format, "its records could not be encoded."))
}

fn item_revision(item: &TaggedItem) -> u32 {
    match item {
        TaggedItem::Login(item) => item.revision,
        TaggedItem::Identity(item) => item.revision,
        TaggedItem::SecureNote(item) => item.revision,
        TaggedItem::Card(item) => item.revision,
        TaggedItem::WifiNetwork(item) => item.revision,
        TaggedItem::SshKey(item) => item.revision,
        TaggedItem::SoftwareLicense(item) => item.revision,
        TaggedItem::Document(item) => item.revision,
        TaggedItem::CustomRecord(item) => item.revision,
    }
}

fn migration_error(source_format: u8, reason: &str) -> String {
    format!(
        "Sesame authenticated vault format {source_format}, but could not upgrade it because {reason} Keep the original backup and contact support."
    )
}

trait RestoreStorage {
    fn exists(&self, path: &Path) -> bool;
    fn create_dir(&mut self, path: &Path) -> VaultResult<()>;
    fn copy_safety(&mut self, source: &Path, destination: &Path) -> VaultResult<()>;
    fn read(&mut self, path: &Path) -> VaultResult<Zeroizing<Vec<u8>>>;
    fn write_temporary(&mut self, path: &Path, bytes: &[u8]) -> VaultResult<()>;
    fn sync_temporary(&mut self, path: &Path) -> VaultResult<()>;
    fn replace(&mut self, source: &Path, destination: &Path) -> VaultResult<()>;
    fn remove(&mut self, path: &Path);
}

struct FileRestoreStorage;

impl RestoreStorage for FileRestoreStorage {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn create_dir(&mut self, path: &Path) -> VaultResult<()> {
        create_private_dir(path)
    }

    fn copy_safety(&mut self, source: &Path, destination: &Path) -> VaultResult<()> {
        copy_private_file(source, destination)
            .map_err(|_| "Sesame could not create the safety backup. The active vault was not changed. Check available disk space and try again.".to_string())
    }

    fn read(&mut self, path: &Path) -> VaultResult<Zeroizing<Vec<u8>>> {
        VaultLoader::read_bytes(path).map_err(|_| {
            "Sesame could not verify the restored vault file. Check local storage and try again."
                .to_string()
        })
    }

    fn write_temporary(&mut self, path: &Path, bytes: &[u8]) -> VaultResult<()> {
        let mut file = open_private_file(path).map_err(|_| {
            "Sesame could not prepare the restored vault file. The active vault was not changed. Check local storage and try again."
                .to_string()
        })?;
        file.write_all(bytes)
            .map_err(|_| "Sesame could not write the restored vault. The active vault was not changed. Check available disk space and try again.".to_string())
    }

    fn sync_temporary(&mut self, path: &Path) -> VaultResult<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Sesame could not sync the restored vault. The active vault was not changed. Check local storage and try again.".to_string())
    }

    fn replace(&mut self, source: &Path, destination: &Path) -> VaultResult<()> {
        replace_file(source, destination).map_err(|_| {
            "Sesame could not replace the active vault. The active vault was not changed. Check local storage and try again."
                .to_string()
        })
    }

    fn remove(&mut self, path: &Path) {
        let _ = fs::remove_file(path);
    }
}

pub fn read_backup_file(path: &Path) -> VaultResult<VaultFile> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("sesame") {
        return Err("Choose a Sesame backup with a .sesame extension.".into());
    }
    VaultLoader::read(path).map_err(Into::into)
}

pub fn validate_backup_file(file: &VaultFile) -> VaultResult<()> {
    VaultLoader::validate(file).map_err(Into::into)
}

#[cfg(test)]
mod restore_fault_tests {
    use super::*;
    use crate::{UnlockedVault, VaultState};

    const PASSWORD: &str = "fictional master password 01";
    const RECOVERY_KIT: &str = "QCSZU-SRJ6G-WP527-YRKXJ-GBS8A";
    const SOURCE: &[u8] = include_bytes!("../tests/fixtures/compatibility/v0.1.0.sesame");
    const ACTIVE: &[u8] = include_bytes!("../tests/fixtures/compatibility/v0.2.2.sesame");

    #[derive(Clone, Copy)]
    enum Fault {
        SafetyInterrupted,
        SafetyNoSpace,
        SafetyCorrupt,
        TemporaryInterrupted,
        TemporaryNoSpace,
        TemporarySync,
        Replacement,
    }

    struct FaultStorage {
        filesystem: FileRestoreStorage,
        fault: Fault,
    }

    impl RestoreStorage for FaultStorage {
        fn exists(&self, path: &Path) -> bool {
            self.filesystem.exists(path)
        }

        fn create_dir(&mut self, path: &Path) -> VaultResult<()> {
            self.filesystem.create_dir(path)
        }

        fn copy_safety(&mut self, source: &Path, destination: &Path) -> VaultResult<()> {
            match self.fault {
                Fault::SafetyInterrupted => {
                    fs::write(destination, &ACTIVE[..ACTIVE.len() / 2])
                        .map_err(|_| "fault setup failed".to_string())?;
                    Err("interrupted safety copy".into())
                }
                Fault::SafetyNoSpace => Err("low disk space during safety copy".into()),
                Fault::SafetyCorrupt => {
                    self.filesystem.copy_safety(source, destination)?;
                    fs::write(destination, b"corrupt safety copy")
                        .map_err(|_| "fault setup failed".to_string())
                }
                _ => self.filesystem.copy_safety(source, destination),
            }
        }

        fn read(&mut self, path: &Path) -> VaultResult<Zeroizing<Vec<u8>>> {
            self.filesystem.read(path)
        }

        fn write_temporary(&mut self, path: &Path, bytes: &[u8]) -> VaultResult<()> {
            match self.fault {
                Fault::TemporaryInterrupted => {
                    fs::write(path, &bytes[..bytes.len() / 2])
                        .map_err(|_| "fault setup failed".to_string())?;
                    Err("interrupted temporary write".into())
                }
                Fault::TemporaryNoSpace => Err("low disk space during temporary write".into()),
                _ => self.filesystem.write_temporary(path, bytes),
            }
        }

        fn sync_temporary(&mut self, path: &Path) -> VaultResult<()> {
            if matches!(self.fault, Fault::TemporarySync) {
                Err("interrupted temporary sync".into())
            } else {
                self.filesystem.sync_temporary(path)
            }
        }

        fn replace(&mut self, source: &Path, destination: &Path) -> VaultResult<()> {
            if matches!(self.fault, Fault::Replacement) {
                Err("replacement failed".into())
            } else {
                self.filesystem.replace(source, destination)
            }
        }

        fn remove(&mut self, path: &Path) {
            self.filesystem.remove(path);
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("sesame-restore-{}", random_id()));
            fs::create_dir(&path).expect("test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn every_failed_write_phase_preserves_the_source_and_active_vault() {
        let directory = TestDirectory::new();
        let source = directory.0.join("source.sesame");
        let destination = directory.0.join("active.sesame");
        fs::write(&source, SOURCE).expect("source");
        fs::write(&destination, ACTIVE).expect("active");
        let prepared =
            prepare_backup_for_restore(&source, &destination, PASSWORD).expect("prepared restore");

        for fault in [
            Fault::SafetyInterrupted,
            Fault::SafetyNoSpace,
            Fault::SafetyCorrupt,
            Fault::TemporaryInterrupted,
            Fault::TemporaryNoSpace,
            Fault::TemporarySync,
            Fault::Replacement,
        ] {
            let mut storage = FaultStorage {
                filesystem: FileRestoreStorage,
                fault,
            };
            assert!(
                apply_restored_vault_file_with_storage(&destination, &prepared, &mut storage)
                    .is_err()
            );
            assert_eq!(fs::read(&source).expect("source preserved"), SOURCE);
            assert_eq!(fs::read(&destination).expect("active preserved"), ACTIVE);
            assert!(fs::read_dir(&directory.0)
                .expect("directory")
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".restore.tmp")));
        }
    }

    #[test]
    fn rejected_restore_inputs_preserve_source_and_active_vault() {
        let directory = TestDirectory::new();
        let source = directory.0.join("source.sesame");
        let destination = directory.0.join("active.sesame");
        fs::write(&destination, ACTIVE).expect("active");

        for (bytes, secret) in [
            (b"{".to_vec(), PASSWORD),
            (relabelled_source(), PASSWORD),
            (SOURCE.to_vec(), "fictional wrong password"),
        ] {
            fs::write(&source, &bytes).expect("source case");
            assert!(prepare_backup_for_restore(&source, &destination, secret).is_err());
            assert_eq!(fs::read(&source).expect("source preserved"), bytes);
            assert_eq!(fs::read(&destination).expect("active preserved"), ACTIVE);
        }

        let future = future_schema_source();
        fs::write(&source, &future).expect("future source");
        let error = prepare_backup_for_restore(&source, &destination, PASSWORD)
            .err()
            .expect("future schema rejected");
        assert!(error.contains("vault format 10"));
        assert!(error.contains("Keep the original backup and contact support."));
        assert_eq!(fs::read(&source).expect("future source preserved"), future);
        assert_eq!(fs::read(&destination).expect("active preserved"), ACTIVE);

        fs::write(&source, SOURCE).expect("same source");
        assert!(prepare_backup_for_restore(&source, &source, PASSWORD).is_err());
        assert_eq!(fs::read(&source).expect("same source preserved"), SOURCE);
        let linked_source = directory.0.join("linked-source.sesame");
        fs::hard_link(&source, &linked_source).expect("linked source");
        assert!(prepare_backup_for_restore(&linked_source, &source, PASSWORD).is_err());
        assert_eq!(
            fs::read(&linked_source).expect("linked source preserved"),
            SOURCE
        );
        assert_eq!(
            fs::read(&destination).expect("active still preserved"),
            ACTIVE
        );
    }

    #[test]
    fn invalid_authenticated_migrations_are_rejected_with_recovery_guidance() {
        let directory = TestDirectory::new();
        let source = directory.0.join("source.sesame");
        let destination = directory.0.join("active.sesame");
        fs::write(&destination, ACTIVE).expect("active");
        let opened =
            VaultLoader::load(SOURCE, Credential::MasterPassword(PASSWORD)).expect("opened source");

        for change in [
            invalid_vault_identity as fn(&mut VaultPayload),
            invalid_folder,
            duplicate_active_id,
            zero_active_revision,
            dangling_active_folder,
            duplicate_history_id,
            zero_history_revision,
            active_id_in_trash,
            zero_trash_timestamp,
        ] {
            let mut payload = opened.payload.clone();
            change(&mut payload);
            let error = validate_migrated_payload(&payload, opened.migration.source_format)
                .err()
                .expect("invalid migration rejected");
            assert!(error.contains("vault format 10"));
            assert!(error.contains("Keep the original backup and contact support."));
        }

        let mut file = VaultLoader::parse(SOURCE).expect("source file");
        file.recovery_kdf = None;
        file.recovery_wrap = None;
        let bytes = serde_json::to_vec(&file).expect("source without recovery");
        fs::write(&source, &bytes).expect("recovery source");
        let error = prepare_backup_for_restore(&source, &destination, PASSWORD)
            .err()
            .expect("missing recovery rejected");
        assert!(error.contains("recovery access is incomplete"));
        assert_eq!(fs::read(&source).expect("source preserved"), bytes);
        assert_eq!(fs::read(&destination).expect("active preserved"), ACTIVE);
    }

    fn relabelled_source() -> Vec<u8> {
        let mut file = VaultLoader::parse(SOURCE).expect("source file");
        file.format_version = 9;
        serde_json::to_vec(&file).expect("relabelled source")
    }

    fn future_schema_source() -> Vec<u8> {
        let mut file = VaultLoader::parse(SOURCE).expect("source file");
        let key = VaultLoader::unwrap_key(&file, Credential::MasterPassword(PASSWORD))
            .expect("source key");
        let aad = crate::payload_aad_for_file(file.format_version, file.setup_complete)
            .expect("payload label");
        file.payload = encrypt_bytes(&key, br#"{"items":[{"kind":"future-record"}]}"#, aad)
            .expect("future payload");
        serde_json::to_vec(&file).expect("future source")
    }

    fn duplicate_active_id(payload: &mut VaultPayload) {
        payload.identities[0].id = payload.entries[0].id.clone();
    }

    fn invalid_vault_identity(payload: &mut VaultPayload) {
        payload.vault_id = None;
    }

    fn invalid_folder(payload: &mut VaultPayload) {
        payload.folders[0].name.clear();
    }

    fn dangling_active_folder(payload: &mut VaultPayload) {
        payload.identities[0].folder_id = Some("missing-folder".into());
    }

    fn zero_active_revision(payload: &mut VaultPayload) {
        payload.identities[0].revision = 0;
    }

    fn duplicate_history_id(payload: &mut VaultPayload) {
        payload.history.push(payload.history[0].clone());
    }

    fn zero_history_revision(payload: &mut VaultPayload) {
        if let TaggedItem::Login(item) = &mut payload.history[0].item {
            item.revision = 0;
        }
    }

    fn active_id_in_trash(payload: &mut VaultPayload) {
        payload.trash.push(TrashedItem {
            item: TaggedItem::Login(payload.entries[0].clone()),
            deleted_at: unix_timestamp(),
        });
    }

    fn zero_trash_timestamp(payload: &mut VaultPayload) {
        payload.trash[0].deleted_at = 0;
    }

    #[test]
    fn lifecycle_state_is_cleared_only_after_replacement_succeeds() {
        let directory = TestDirectory::new();
        let source = directory.0.join("source.sesame");
        let destination = directory.0.join("active.sesame");
        fs::write(&source, SOURCE).expect("source");
        fs::write(&destination, ACTIVE).expect("active");
        let opened = VaultLoader::load(SOURCE, Credential::MasterPassword(PASSWORD))
            .expect("opened fixture");
        let state = VaultState::default();
        *state.session.lock().expect("session") =
            Some(UnlockedVault::from_opened(destination.clone(), &opened).expect("session vault"));
        let epoch = state.session_epoch();

        let failed: VaultResult<()> =
            state.apply_lifecycle_replacement(|| Err("replacement failed".into()));
        assert!(failed.is_err());
        assert!(state
            .session
            .lock()
            .expect("session after failure")
            .is_some());
        assert_eq!(state.session_epoch(), epoch);

        let prepared =
            prepare_backup_for_restore(&source, &destination, PASSWORD).expect("prepared restore");
        state
            .apply_lifecycle_replacement(|| {
                apply_restored_vault_file(&destination, &prepared).map(|_| ())
            })
            .expect("replacement success");
        assert!(state
            .session
            .lock()
            .expect("session after success")
            .is_none());
        assert_eq!(state.session_epoch(), epoch + 1);

        let restarted_file = VaultLoader::read(&destination).expect("restart read");
        let restarted = VaultLoader::open(&restarted_file, Credential::MasterPassword(PASSWORD))
            .expect("restart password");
        VaultLoader::open(&restarted_file, Credential::RecoveryKit(RECOVERY_KIT))
            .expect("restart recovery");
        let restarted_state = VaultState::default();
        *restarted_state.session.lock().expect("restart session") = Some(
            UnlockedVault::from_opened(destination, &restarted).expect("restarted session vault"),
        );
        assert_eq!(
            restarted_state
                .session
                .lock()
                .expect("restarted session")
                .as_ref()
                .expect("unlocked after restart")
                .snapshot()
                .vault_id,
            restarted.payload.vault_id
        );
    }
}
