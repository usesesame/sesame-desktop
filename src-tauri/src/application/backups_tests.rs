use std::path::{Path, PathBuf};

use crate::application::file_choices::{FilePurpose, FileSelectionState};
use crate::commands::test_support::TestVault;
use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
use crate::vault::recovery_health::RecoveryHealth;
use crate::vault::{random_id, Identity, RestoreBackupRequest, VaultState};

use super::backups::{
    create_backup_in_state, delete_local_vault_in_state, export_backup_in_state,
    export_recovery_kit_in_state, export_vault_csv_in_state, export_vault_json_in_state,
    inspect_backup_in_state, recovery_health_in_state, require_json_extension,
    restore_backup_in_state, verify_backup_in_state,
};
use super::tests::{Effect, FakeEffects};

const MASTER_PASSWORD: &str = "fictional master password";
const WRONG_PASSWORD: &str = "fictional wrong password";
const STALE_CHOICE: &str = "That file choice expired or was already used. Choose the file again.";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("sesame-backups-{label}-{}", random_id()));
        std::fs::create_dir_all(&path).expect("temp directory");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn grant(vault: &TestVault, presence: &ReleasePresence) {
    let session = vault.state.session.lock().expect("session lock");
    presence
        .grant_with_password(
            session.as_ref().expect("session"),
            vault.state.session_epoch(),
            MASTER_PASSWORD,
        )
        .expect("granted presence");
}

fn vault_id(vault: &TestVault) -> String {
    vault
        .state
        .session
        .lock()
        .expect("session lock")
        .as_ref()
        .expect("session")
        .snapshot()
        .vault_id
        .expect("vault id")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("file bytes")
}

fn issue(selection: &FileSelectionState, purpose: FilePurpose, path: &Path) -> String {
    selection
        .issue(purpose, path.to_path_buf())
        .expect("issued token")
}

fn restore_request(token: &str) -> RestoreBackupRequest {
    RestoreBackupRequest {
        token: Some(token.to_string()),
        source: None,
        secret: MASTER_PASSWORD.to_string(),
        confirm_older: false,
    }
}

fn backup_of(vault: &TestVault) -> PathBuf {
    let name = create_backup_in_state(&vault.state).expect("created backup");
    vault
        .path()
        .parent()
        .expect("vault parent")
        .join("backups")
        .join(name)
}

#[test]
fn creating_a_backup_needs_an_unlocked_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backups = vault.path().parent().expect("vault parent").join("backups");
    let state = VaultState::default();

    assert_eq!(
        create_backup_in_state(&state),
        Err("Unlock your vault before creating a backup.".to_string())
    );
    assert!(!backups.exists());
}

#[test]
fn creating_a_backup_copies_the_encrypted_vault_beside_it() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");

    let name = create_backup_in_state(&vault.state).expect("created backup");

    assert!(name.starts_with("sesame-backup-"));
    assert!(name.ends_with(".sesame"));
    let backup = vault
        .path()
        .parent()
        .expect("vault parent")
        .join("backups")
        .join(&name);
    assert_eq!(read(&backup), read(vault.path()));
}

#[test]
fn exporting_a_backup_without_presence_writes_nothing() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let selection = FileSelectionState::default();
    let directory = TempDir::new("export-no-presence");
    let destination = directory.join("fictional-backup.sesame");
    let token = issue(&selection, FilePurpose::BackupExport, &destination);

    assert_eq!(
        export_backup_in_state(
            &vault.state,
            &presence,
            &effects,
            &selection,
            Some(&token),
            None,
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(!destination.exists());
    assert!(effects.calls().is_empty());
    let claim = selection
        .claim(&token, FilePurpose::BackupExport)
        .expect("token was not spent");
    selection.release(claim);
}

#[test]
fn exporting_a_backup_to_the_vault_or_beside_the_name_is_refused() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let selection = FileSelectionState::default();
    let before = read(vault.path());

    let own_path = issue(&selection, FilePurpose::BackupExport, vault.path());
    assert_eq!(
        export_backup_in_state(
            &vault.state,
            &presence,
            &effects,
            &selection,
            Some(&own_path),
            None,
        ),
        Err("Choose a different location for the backup.".to_string())
    );
    assert_eq!(read(vault.path()), before);

    let directory = TempDir::new("export-wrong-extension");
    let wrong_extension = directory.join("fictional-backup.csv");
    let token = issue(&selection, FilePurpose::BackupExport, &wrong_extension);
    assert_eq!(
        export_backup_in_state(
            &vault.state,
            &presence,
            &effects,
            &selection,
            Some(&token),
            None,
        ),
        Err("Save the encrypted backup with a .sesame extension.".to_string())
    );
    assert!(!wrong_extension.exists());
    assert!(effects.calls().is_empty());
}

#[test]
fn exporting_a_backup_copies_it_and_records_the_export() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let selection = FileSelectionState::default();
    let directory = TempDir::new("export-backup");
    let destination = directory.join("fictional-backup.sesame");
    let token = issue(&selection, FilePurpose::BackupExport, &destination);
    let expected_id = vault_id(&vault);

    assert_eq!(
        export_backup_in_state(
            &vault.state,
            &presence,
            &effects,
            &selection,
            Some(&token),
            None,
        ),
        Ok("fictional-backup.sesame".to_string())
    );
    assert_eq!(read(&destination), read(vault.path()));
    assert_eq!(
        effects.calls(),
        vec![Effect::RecordRecoveryExport {
            vault_id: expected_id,
            revision: 2,
        }]
    );
    assert_eq!(
        selection.claim(&token, FilePurpose::BackupExport).err(),
        Some(STALE_CHOICE.to_string())
    );
}

#[test]
fn a_presence_granted_before_the_session_changed_is_not_enough_to_export() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    vault.state.advance_session_epoch();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let selection = FileSelectionState::default();
    let directory = TempDir::new("export-stale-presence");
    let destination = directory.join("fictional-backup.sesame");
    let token = issue(&selection, FilePurpose::BackupExport, &destination);

    assert_eq!(
        export_backup_in_state(
            &vault.state,
            &presence,
            &effects,
            &selection,
            Some(&token),
            None,
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(!destination.exists());
    assert!(effects.calls().is_empty());
}

#[test]
fn a_backup_token_issued_for_another_export_is_refused() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let selection = FileSelectionState::default();
    let directory = TempDir::new("export-wrong-purpose");
    let destination = directory.join("fictional-backup.sesame");
    let token = issue(&selection, FilePurpose::CsvExport, &destination);

    assert_eq!(
        export_backup_in_state(
            &vault.state,
            &presence,
            &effects,
            &selection,
            Some(&token),
            None,
        ),
        Err(STALE_CHOICE.to_string())
    );
    assert!(!destination.exists());
    assert!(effects.calls().is_empty());
}

#[test]
fn exporting_readable_files_needs_an_unlocked_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let state = VaultState::default();
    let selection = FileSelectionState::default();
    let directory = TempDir::new("readable-locked");
    let csv = directory.join("fictional-export.csv");
    let json = directory.join("fictional-export.json");

    let csv_token = issue(&selection, FilePurpose::CsvExport, &csv);
    assert_eq!(
        export_vault_csv_in_state(&state, &presence, &selection, Some(&csv_token), None),
        Err("Unlock your vault before exporting it.".to_string())
    );
    let json_token = issue(&selection, FilePurpose::JsonExport, &json);
    assert_eq!(
        export_vault_json_in_state(&state, &presence, &selection, Some(&json_token), None),
        Err("Unlock your vault before exporting it.".to_string())
    );
    assert!(!csv.exists());
    assert!(!json.exists());
}

#[test]
fn readable_exports_without_presence_write_nothing() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    let selection = FileSelectionState::default();
    let directory = TempDir::new("readable-no-presence");
    let csv = directory.join("fictional-export.csv");
    let json = directory.join("fictional-export.json");

    let csv_token = issue(&selection, FilePurpose::CsvExport, &csv);
    assert_eq!(
        export_vault_csv_in_state(&vault.state, &presence, &selection, Some(&csv_token), None),
        Err(PRESENCE_REQUIRED.to_string())
    );
    let json_token = issue(&selection, FilePurpose::JsonExport, &json);
    assert_eq!(
        export_vault_json_in_state(&vault.state, &presence, &selection, Some(&json_token), None),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(!csv.exists());
    assert!(!json.exists());
}

#[test]
fn the_readable_exports_need_their_own_extension() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let selection = FileSelectionState::default();
    let directory = TempDir::new("readable-extensions");
    let csv = directory.join("fictional-export.json");
    let json = directory.join("fictional-export.csv");

    let csv_token = issue(&selection, FilePurpose::CsvExport, &csv);
    assert_eq!(
        export_vault_csv_in_state(&vault.state, &presence, &selection, Some(&csv_token), None),
        Err("Save the readable export with a .csv extension.".to_string())
    );
    let json_token = issue(&selection, FilePurpose::JsonExport, &json);
    assert_eq!(
        export_vault_json_in_state(&vault.state, &presence, &selection, Some(&json_token), None),
        Err("Save the complete export with a .json extension.".to_string())
    );
    assert!(!csv.exists());
    assert!(!json.exists());
}

#[test]
fn the_readable_csv_writes_an_identities_file_beside_it() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    vault.seed(|payload| {
        let mut identity = Identity::default();
        identity.id = "fictional-identity".to_string();
        identity.label = "Fictional identity".to_string();
        payload.identities.push(identity);
    });
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let selection = FileSelectionState::default();
    let directory = TempDir::new("readable-csv");
    let csv = directory.join("fictional-export.csv");
    let token = issue(&selection, FilePurpose::CsvExport, &csv);

    assert_eq!(
        export_vault_csv_in_state(&vault.state, &presence, &selection, Some(&token), None),
        Ok(vec![
            "fictional-export.csv".to_string(),
            "fictional-export-identities.csv".to_string()
        ])
    );
    assert!(!read(&csv).is_empty());
    assert!(!read(&directory.join("fictional-export-identities.csv")).is_empty());
}

#[test]
fn a_failed_readable_csv_removes_the_file_it_created() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    vault.seed(|payload| {
        let mut identity = Identity::default();
        identity.id = "fictional-identity".to_string();
        identity.label = "Fictional identity".to_string();
        payload.identities.push(identity);
    });
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let selection = FileSelectionState::default();
    let directory = TempDir::new("readable-csv-failure");
    let csv = directory.join("fictional-export.csv");
    std::fs::create_dir(directory.join("fictional-export-identities.csv"))
        .expect("blocking directory");
    let token = issue(&selection, FilePurpose::CsvExport, &csv);

    assert!(
        export_vault_csv_in_state(&vault.state, &presence, &selection, Some(&token), None).is_err()
    );
    assert!(!csv.exists());
}

#[test]
fn the_complete_export_writes_every_secret_to_one_file() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let selection = FileSelectionState::default();
    let directory = TempDir::new("readable-json");
    let destination = directory.join("fictional-export.json");
    let token = issue(&selection, FilePurpose::JsonExport, &destination);

    assert_eq!(
        export_vault_json_in_state(&vault.state, &presence, &selection, Some(&token), None),
        Ok("fictional-export.json".to_string())
    );
    let body = String::from_utf8(read(&destination)).expect("utf8 export");
    assert!(body.contains("Fictional vault"));
    assert!(body.contains("fictional-stored-secret"));
}

#[test]
fn the_complete_export_needs_a_json_name() {
    assert!(require_json_extension(Path::new("/tmp/fictional-export.json")).is_ok());
    for refused in [
        "/tmp/fictional-export.csv",
        "/tmp/fictional-export",
        "/tmp/fictional-export.json.exe",
    ] {
        assert!(
            require_json_extension(Path::new(refused)).is_err(),
            "{refused}"
        );
    }
}

#[test]
fn the_recovery_kit_needs_presence_a_session_and_a_kit() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    let selection = FileSelectionState::default();
    let directory = TempDir::new("recovery-kit");
    let destination = directory.join("fictional-recovery-kit.txt");

    let token = issue(&selection, FilePurpose::RecoveryKitExport, &destination);
    assert_eq!(
        export_recovery_kit_in_state(
            &vault.state,
            &presence,
            &selection,
            "fictional kit".to_string(),
            Some(&token),
            None,
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(!destination.exists());

    grant(&vault, &presence);
    let token = issue(&selection, FilePurpose::RecoveryKitExport, &destination);
    assert_eq!(
        export_recovery_kit_in_state(
            &VaultState::default(),
            &presence,
            &selection,
            "fictional kit".to_string(),
            Some(&token),
            None,
        ),
        Err("Unlock your vault before saving the recovery kit.".to_string())
    );
    assert!(!destination.exists());

    let token = issue(&selection, FilePurpose::RecoveryKitExport, &destination);
    assert_eq!(
        export_recovery_kit_in_state(
            &vault.state,
            &presence,
            &selection,
            "   ".to_string(),
            Some(&token),
            None,
        ),
        Err("There is no recovery kit to save.".to_string())
    );
    assert!(!destination.exists());
}

#[test]
fn the_recovery_kit_needs_a_text_name_and_carries_the_kit() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let selection = FileSelectionState::default();
    let directory = TempDir::new("recovery-kit-text");
    let wrong = directory.join("fictional-recovery-kit.sesame");
    let token = issue(&selection, FilePurpose::RecoveryKitExport, &wrong);
    assert_eq!(
        export_recovery_kit_in_state(
            &vault.state,
            &presence,
            &selection,
            "fictional kit".to_string(),
            Some(&token),
            None,
        ),
        Err("Save the recovery kit with a .txt extension.".to_string())
    );
    assert!(!wrong.exists());

    let destination = directory.join("fictional-recovery-kit.txt");
    let token = issue(&selection, FilePurpose::RecoveryKitExport, &destination);
    assert_eq!(
        export_recovery_kit_in_state(
            &vault.state,
            &presence,
            &selection,
            "fictional kit".to_string(),
            Some(&token),
            None,
        ),
        Ok("fictional-recovery-kit.txt".to_string())
    );
    let body = String::from_utf8(read(&destination)).expect("utf8 kit");
    assert!(body.starts_with("Sesame recovery kit"));
    assert!(body.contains("fictional kit"));
}

#[test]
fn inspecting_a_backup_is_refused_while_a_vault_file_exists_behind_a_lock() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::BackupRead, &backup);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let state = VaultState::default();

    assert_eq!(
        inspect_backup_in_state(&state, &effects, &selection, Some(&token), None).err(),
        Some("Unlock your vault before inspecting a backup.".to_string())
    );
    let claim = selection
        .claim(&token, FilePurpose::BackupRead)
        .expect("token was not spent");
    selection.release(claim);
}

#[test]
fn inspecting_a_backup_reads_it_without_spending_the_choice() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    let name = backup
        .file_name()
        .expect("name")
        .to_string_lossy()
        .to_string();
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::BackupRead, &backup);
    let effects = FakeEffects::new(
        std::env::temp_dir().join(format!("fictional-missing-vault-{}", random_id())),
    );
    let state = VaultState::default();

    let inspection = inspect_backup_in_state(&state, &effects, &selection, Some(&token), None)
        .expect("inspected");

    assert_eq!(inspection.file_name, name);
    assert!(inspection.setup_complete);
    let claim = selection
        .claim(&token, FilePurpose::BackupRead)
        .expect("inspection keeps the choice");
    selection.release(claim);
}

#[test]
fn a_verification_needs_an_unlocked_vault_and_the_right_kind_of_choice() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::CsvExport, &backup);
    let effects = FakeEffects::new(vault.path().to_path_buf());

    let wrong_purpose =
        inspect_backup_in_state(&vault.state, &effects, &selection, Some(&token), None);
    assert_eq!(wrong_purpose.err(), Some(STALE_CHOICE.to_string()));

    let mut request = restore_request(&token);
    request.source = Some(backup.to_string_lossy().to_string());
    assert_eq!(
        verify_backup_in_state(&vault.state, &effects, &selection, request).err(),
        Some(STALE_CHOICE.to_string())
    );
    assert!(effects.calls().is_empty());

    let locked = VaultState::default();
    let read_token = issue(&selection, FilePurpose::BackupRead, &backup);
    assert_eq!(
        verify_backup_in_state(&locked, &effects, &selection, restore_request(&read_token)).err(),
        Some("Unlock your vault before verifying a backup.".to_string())
    );
}

#[test]
fn verifying_a_backup_authenticates_it_and_records_the_matching_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    let expected_id = vault_id(&vault);
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::BackupRead, &backup);
    let effects = FakeEffects::new(vault.path().to_path_buf());

    let verification =
        verify_backup_in_state(&vault.state, &effects, &selection, restore_request(&token))
            .expect("verified");

    assert_eq!(verification.vault_id, Some(expected_id.clone()));
    assert_eq!(verification.revision, 2);
    assert_eq!(
        effects.calls(),
        vec![Effect::RecordRecoveryVerification {
            vault_id: expected_id,
            revision: 2,
        }]
    );
}

#[test]
fn a_wrong_password_does_not_verify_a_backup() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::BackupRead, &backup);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let mut request = restore_request(&token);
    request.secret = WRONG_PASSWORD.to_string();

    assert_eq!(
        verify_backup_in_state(&vault.state, &effects, &selection, request).err(),
        Some("That master password or recovery kit does not open this backup.".to_string())
    );
    assert!(effects.calls().is_empty());
}

#[test]
fn restoring_a_backup_with_a_wrong_password_leaves_the_vault_untouched_and_the_choice_reusable() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    let before = read(vault.path());
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::BackupRead, &backup);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let mut request = restore_request(&token);
    request.secret = WRONG_PASSWORD.to_string();

    assert_eq!(
        restore_backup_in_state(&vault.state, &presence, &effects, &selection, request).err(),
        Some("That master password or recovery kit does not open this backup.".to_string())
    );
    assert_eq!(read(vault.path()), before);
    assert!(vault.state.session.lock().expect("session lock").is_some());
    assert!(effects.calls().is_empty());
    let claim = selection
        .claim(&token, FilePurpose::BackupRead)
        .expect("the failed restore released the choice");
    selection.release(claim);
}

#[test]
fn restoring_an_older_backup_needs_confirmation_then_replaces_the_file_once() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    vault.seed(|payload| {
        payload.entries[0].title = "Northwind newer".to_string();
    });
    let newer = read(vault.path());
    let expected_id = vault_id(&vault);
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::BackupRead, &backup);
    let effects = FakeEffects::new(vault.path().to_path_buf());

    assert_eq!(
        restore_backup_in_state(
            &vault.state,
            &presence,
            &effects,
            &selection,
            restore_request(&token)
        )
        .err(),
        Some("olderBackup:2:3".to_string())
    );
    assert_eq!(read(vault.path()), newer);
    assert!(vault.state.session.lock().expect("session lock").is_some());
    assert!(effects.calls().is_empty());
    let reusable = selection
        .claim(&token, FilePurpose::BackupRead)
        .expect("the refused restore released the choice");
    selection.release(reusable);

    let mut confirmed = restore_request(&token);
    confirmed.confirm_older = true;
    let restored =
        restore_backup_in_state(&vault.state, &presence, &effects, &selection, confirmed)
            .expect("restored with confirmation");

    assert_eq!(restored.restored_revision, 2);
    assert_eq!(restored.replaced_revision, Some(3));
    assert!(!restored.pin_unlock_available);
    assert!(!restored.hello_unlock_available);
    assert!(restored.safety_backup_name.is_some());
    assert!(vault.state.session.lock().expect("session lock").is_none());
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ResetRollbackAfterRestore {
                vault_id: Some(expected_id),
                revision: 2,
            },
            Effect::ClearArmedClipboard,
            Effect::ClearPinThrottle,
        ]
    );
    assert_eq!(
        selection.claim(&token, FilePurpose::BackupRead).err(),
        Some(STALE_CHOICE.to_string())
    );
    assert_eq!(vault.stored_login("fictional-login").title, "Northwind");

    let safety = vault
        .path()
        .parent()
        .expect("vault parent")
        .join("backups")
        .join(restored.safety_backup_name.expect("safety backup"));
    assert_eq!(read(&safety), newer);
}

#[test]
fn restoring_another_vaults_backup_is_refused_before_the_file_changes() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let other = TestVault::with_login("fictional-other", "https://example.invalid");
    let backup = backup_of(&other);
    let before = read(vault.path());
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::BackupRead, &backup);
    let effects = FakeEffects::new(vault.path().to_path_buf());

    assert_eq!(
        restore_backup_in_state(
            &vault.state,
            &presence,
            &effects,
            &selection,
            restore_request(&token)
        )
        .err(),
        Some(
            "That backup belongs to a different vault. Sesame did not replace this vault."
                .to_string()
        )
    );
    assert_eq!(read(vault.path()), before);
    assert!(vault.state.session.lock().expect("session lock").is_some());
    assert!(effects.calls().is_empty());
    let claim = selection
        .claim(&token, FilePurpose::BackupRead)
        .expect("the refused restore released the choice");
    selection.release(claim);
}

#[test]
fn restoring_into_an_open_vault_needs_presence() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    let before = read(vault.path());
    let presence = ReleasePresence::default();
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::BackupRead, &backup);
    let effects = FakeEffects::new(vault.path().to_path_buf());

    assert_eq!(
        restore_backup_in_state(
            &vault.state,
            &presence,
            &effects,
            &selection,
            restore_request(&token)
        )
        .err(),
        Some(PRESENCE_REQUIRED.to_string())
    );
    assert_eq!(read(vault.path()), before);
    assert!(vault.state.session.lock().expect("session lock").is_some());
    assert!(effects.calls().is_empty());
    let claim = selection
        .claim(&token, FilePurpose::BackupRead)
        .expect("the refused restore released the choice");
    selection.release(claim);
}

#[test]
fn restoring_while_locked_and_a_vault_exists_is_refused() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    let before = read(vault.path());
    let presence = ReleasePresence::default();
    let selection = FileSelectionState::default();
    let token = issue(&selection, FilePurpose::BackupRead, &backup);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let state = VaultState::default();

    assert_eq!(
        restore_backup_in_state(
            &state,
            &presence,
            &effects,
            &selection,
            restore_request(&token)
        )
        .err(),
        Some("Unlock your vault before restoring a backup.".to_string())
    );
    assert_eq!(read(vault.path()), before);
    assert!(effects.calls().is_empty());
    let claim = selection
        .claim(&token, FilePurpose::BackupRead)
        .expect("the refused restore released the choice");
    selection.release(claim);
}

#[test]
#[cfg(not(feature = "wdio"))]
fn a_restore_without_a_choice_cannot_use_a_raw_path() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let backup = backup_of(&vault);
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let selection = FileSelectionState::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = RestoreBackupRequest {
        token: Some(String::new()),
        source: Some(backup.to_string_lossy().to_string()),
        secret: MASTER_PASSWORD.to_string(),
        confirm_older: false,
    };

    assert_eq!(
        restore_backup_in_state(&vault.state, &presence, &effects, &selection, request).err(),
        Some(STALE_CHOICE.to_string())
    );
    assert!(effects.calls().is_empty());
}

#[test]
fn deleting_the_vault_needs_the_vault_files_password() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    create_backup_in_state(&vault.state).expect("created backup");
    let before = read(vault.path());
    let effects = FakeEffects::new(vault.path().to_path_buf());

    assert_eq!(
        delete_local_vault_in_state(&vault.state, &effects, WRONG_PASSWORD.to_string()),
        Err("That master password is not correct. The vault was not removed.".to_string())
    );
    assert_eq!(read(vault.path()), before);
    assert!(vault.path().exists());
    assert!(vault.state.session.lock().expect("session lock").is_some());
    assert!(effects.calls().is_empty());
}

#[test]
fn deleting_the_vault_stages_every_managed_file_and_clears_the_caches() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    create_backup_in_state(&vault.state).expect("created backup");
    let epoch = vault.state.session_epoch();
    let backup_directory = vault.path().parent().expect("vault parent").join("backups");
    let effects = FakeEffects::new(vault.path().to_path_buf());

    delete_local_vault_in_state(&vault.state, &effects, MASTER_PASSWORD.to_string())
        .expect("deleted the vault");

    assert!(!vault.path().exists());
    assert!(!backup_directory.exists());
    assert!(vault.state.session.lock().expect("session lock").is_none());
    assert_eq!(vault.state.session_epoch(), epoch + 1);
    assert_eq!(vault.state.cached_pin_unlock(), Some(false));
    assert_eq!(vault.state.cached_hello_unlock(), Some(false));
    assert_eq!(
        effects.calls(),
        vec![Effect::ClearArmedClipboard, Effect::ClearPinThrottle]
    );
}

#[test]
fn recovery_health_reads_the_current_vaults_record() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let expected_id = vault_id(&vault);
    let health = RecoveryHealth {
        vault_id: "fictional-health-vault".to_string(),
        last_exported_revision: Some(4),
        ..Default::default()
    };
    let effects = FakeEffects::with_recovery_health(vault.path().to_path_buf(), health.clone());

    let result = recovery_health_in_state(&vault.state, &effects).expect("health");

    assert_eq!(result, health);
    assert_eq!(
        effects.calls(),
        vec![Effect::ReadRecoveryHealth {
            current_vault_id: Some(expected_id),
        }]
    );
}

#[test]
fn recovery_health_asks_for_no_vault_id_while_locked() {
    let state = VaultState::default();
    let effects = FakeEffects::with_recovery_health(
        PathBuf::new(),
        RecoveryHealth {
            vault_id: "fictional-health-vault".to_string(),
            ..Default::default()
        },
    );

    let result = recovery_health_in_state(&state, &effects).expect("health");

    assert_eq!(result.vault_id, "fictional-health-vault");
    assert_eq!(
        effects.calls(),
        vec![Effect::ReadRecoveryHealth {
            current_vault_id: None,
        }]
    );
}
