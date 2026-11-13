use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

use sesame_core::api::{create_vault, open_vault_with_recovery_kit};

use crate::commands::test_support::TestVault;
use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
use crate::vault::backup::RECOVERY_REPLACEMENT_FILE;
use crate::vault::crypto::{default_kdf_params, derive_key, encrypt_bytes};
use crate::vault::storage::{persist_session, write_vault_file, RECOVERY_REPLACEMENT_DELAY_SECS};
use crate::vault::throttle::PersistedPinThrottle;
use crate::vault::types::VaultFile;
use crate::vault::{
    random_id, ChangeMasterPasswordRequest, PinWrap, UnlockedVault, VaultState, PIN_WRAP_AAD,
};

use super::recovery_replacement::{
    begin_recovery_replacement_completion_in_state, begin_recovery_replacement_request_in_state,
    complete_recovery_replacement_in_state, complete_request,
    pending_recovery_replacement_in_state, pending_request, recovery_replacement_status,
    write_recovery_replacement_request_in_state, write_request, RecoveryReplacementStatus,
    TrustedTime,
};
use super::tests::{grant, Effect, FakeEffects};
use super::unlock::{
    accept_rollback_in_state, change_master_password_in_state, complete_recovery_setup_in_state,
    create_vault_in_state, get_vault_status_in_state, remove_unlock_pin_in_state,
    resume_recovery_setup_in_state, set_auto_lock_minutes_in_state, set_unlock_pin_in_state,
    unlock_pin_vault_in_state, unlock_recovery_vault_in_state,
};
use super::DesktopEffects;

const MASTER_PASSWORD: &str = "fictional master password";
const WRONG_PASSWORD: &str = "fictional wrong current password";
const REPLACEMENT_PASSWORD: &str = "fictional new password";
const PIN: &str = "135790";
const WRONG_PIN: &str = "246801";
const REQUESTED_AT: u64 = 1_800_000_000;
const READY_AT: u64 = REQUESTED_AT + RECOVERY_REPLACEMENT_DELAY_SECS;

fn lock_vault(vault: &TestVault) {
    *vault.state.session.lock().expect("session lock") = None;
}

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sesame-recovery-unlock-{}", random_id()));
        std::fs::create_dir_all(&path).expect("test directory");
        Self { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn vault_bytes(vault: &TestVault) -> Vec<u8> {
    std::fs::read(vault.path()).expect("vault bytes")
}

fn store_pin_wrap(vault: &TestVault, pin: &str) {
    let mut session = vault.state.session.lock().expect("session lock");
    let session = session.as_mut().expect("session");
    let kdf = default_kdf_params();
    let protected_pepper = URL_SAFE_NO_PAD.encode([9_u8; 32]);
    let secret = format!("{pin}:{protected_pepper}");
    let wrapping_key = Zeroizing::new(derive_key(&secret, &kdf).expect("derived key"));
    let key_wrap = session
        .expose_vault_key(|key| encrypt_bytes(&wrapping_key, key, PIN_WRAP_AAD))
        .expect("wrapped key");
    session.pin_wrap = Some(PinWrap {
        kdf,
        protected_pepper,
        key_wrap,
    });
    persist_session(session).expect("persisted pin wrap");
}

fn clear_recovery_wrap(vault: &TestVault) {
    let mut session = vault.state.session.lock().expect("session lock");
    let session = session.as_mut().expect("session");
    session.recovery_wrap = None;
    session.recovery_kdf = None;
    persist_session(session).expect("persisted vault without a recovery wrap");
}

fn password_request(current: Option<&str>, kit: Option<&str>) -> ChangeMasterPasswordRequest {
    ChangeMasterPasswordRequest {
        current_password: current.map(str::to_string),
        recovery_kit: kit.map(str::to_string),
        new_password: REPLACEMENT_PASSWORD.to_string(),
    }
}

#[test]
fn unlocking_with_a_recovery_kit_reenables_the_pin_throttle_state() {
    let scratch = Scratch::new();
    let path = scratch.path.join("vault.sesame");
    let (opened, kit) = create_vault(MASTER_PASSWORD, "Fictional vault").expect("created vault");
    write_vault_file(&path, &opened.file).expect("written vault");
    let state = VaultState::default();
    let effects = FakeEffects::new(path);

    unlock_recovery_vault_in_state(&state, &effects, Zeroizing::new(kit))
        .expect("unlocked with the recovery kit");

    assert!(effects.calls().contains(&Effect::WritePinThrottle {
        failures: 0,
        locked_until_unix_ms: None,
    }));
    assert!(state.session.lock().expect("session lock").is_some());
}

#[test]
fn a_wrong_pin_attempt_is_persisted_before_any_key_derivation() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    store_pin_wrap(&vault, PIN);
    lock_vault(&vault);
    let effects =
        FakeEffects::with_pin_throttle(vault.path().to_path_buf(), PersistedPinThrottle::default());
    let epoch = vault.state.session_epoch();

    let error = match unlock_pin_vault_in_state(&vault.state, &effects, WRONG_PIN.to_string()) {
        Ok(_) => panic!("a wrong PIN unlocked the vault"),
        Err(error) => error,
    };

    assert!(!error.is_empty());
    assert_eq!(
        effects.calls(),
        vec![Effect::WritePinThrottle {
            failures: 1,
            locked_until_unix_ms: None,
        }]
    );
    assert_eq!(effects.pin_throttle().map(|state| state.failures), Some(1));
    assert!(vault.state.session.lock().expect("session lock").is_none());
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn a_locked_out_pin_is_refused_before_the_vault_is_read() {
    let state = VaultState::default();
    let effects = FakeEffects::with_pin_throttle(
        PathBuf::from("/fictional/sesame/missing-vault.sesame"),
        PersistedPinThrottle {
            failures: 5,
            locked_until_unix_ms: Some(u64::MAX),
        },
    );
    let epoch = state.session_epoch();

    let error = match unlock_pin_vault_in_state(&state, &effects, PIN.to_string()) {
        Ok(_) => panic!("a locked-out PIN unlocked the vault"),
        Err(error) => error,
    };

    assert!(
        error.starts_with("Too many incorrect PIN attempts. Wait "),
        "{error}"
    );
    assert!(effects.calls().is_empty());
    assert_eq!(effects.pin_throttle().map(|state| state.failures), Some(5));
    assert!(state.session.lock().expect("session lock").is_none());
    assert_eq!(state.session_epoch(), epoch);
}

#[test]
fn changing_the_master_password_with_the_wrong_current_password_leaves_the_file_unchanged() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    clear_recovery_wrap(&vault);
    let before = vault_bytes(&vault);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let epoch = vault.state.session_epoch();

    let error = change_master_password_in_state(
        &vault.state,
        &effects,
        password_request(Some(WRONG_PASSWORD), None),
    )
    .err()
    .expect("the wrong current password was refused");

    assert!(error.contains("master password is not correct"), "{error}");
    assert_eq!(vault_bytes(&vault), before);
    assert!(effects.calls().is_empty());
    assert_eq!(vault.state.session_epoch(), epoch);
}

#[test]
fn a_master_password_change_retires_the_other_unlock_methods() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    clear_recovery_wrap(&vault);
    let before = vault_bytes(&vault);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let epoch = vault.state.session_epoch();

    let result = change_master_password_in_state(
        &vault.state,
        &effects,
        password_request(Some(MASTER_PASSWORD), None),
    )
    .expect("rotated the master password");

    assert!(!result.recovery_kit.is_empty());
    assert_ne!(vault_bytes(&vault), before);
    assert_eq!(vault.state.session_epoch(), epoch + 1);
    assert_eq!(vault.state.cached_pin_unlock(), Some(false));
    assert_eq!(vault.state.cached_hello_unlock(), Some(false));
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ClearPinThrottle,
            Effect::DiscardRecoveryReplacement,
            Effect::ReportKeyPageFallback,
        ]
    );
}

#[test]
fn creating_a_vault_refuses_to_overwrite_an_existing_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let before = vault_bytes(&vault);
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let state = VaultState::default();

    let error = match create_vault_in_state(
        &state,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    ) {
        Ok(_) => panic!("create_vault replaced an existing vault"),
        Err(error) => error,
    };

    assert_eq!(error, "A local Sesame vault already exists on this device.");
    assert_eq!(vault_bytes(&vault), before);
    assert!(state.session.lock().expect("session lock").is_none());
    assert!(effects.calls().is_empty());
}

#[test]
fn completing_a_recovery_replacement_without_a_request_fails() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::with_presence(vault.path().to_path_buf(), &presence);
    let before = vault_bytes(&vault);
    let epoch = vault.state.session_epoch();

    assert_eq!(
        begin_recovery_replacement_completion_in_state(&vault.state, &presence, &effects),
        Err("There is no recovery kit request to complete.".to_string())
    );
    let error = match complete_recovery_replacement_in_state(
        &vault.state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
        REQUESTED_AT,
        false,
    ) {
        Ok(_) => panic!("completed a recovery replacement with no request"),
        Err(error) => error,
    };

    assert_eq!(error, "There is no recovery kit request to complete.");
    assert_eq!(vault_bytes(&vault), before);
    assert!(vault.state.session.lock().expect("session lock").is_some());
    assert_eq!(vault.state.session_epoch(), epoch);
    assert!(effects.calls().is_empty());
}

#[test]
fn a_recovery_request_for_another_vault_is_discarded() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let request = effects
        .recovery_replacement_path()
        .expect("recovery replacement path");
    std::fs::write(
        &request,
        serde_json::json!({
            "vaultId": "fictional-other-vault",
            "sealed": { "nonce": "AAAA", "ciphertext": "AAAA" },
        })
        .to_string(),
    )
    .expect("wrote a foreign request");

    assert_eq!(
        pending_recovery_replacement_in_state(&vault.state, &effects),
        Ok(None)
    );
    assert!(!request.exists());
}

#[test]
fn recovery_replacement_needs_presence_before_reading_or_writing_requests() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    assert_eq!(
        begin_recovery_replacement_request_in_state(&vault.state, &presence, &effects),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert_eq!(
        begin_recovery_replacement_completion_in_state(&vault.state, &presence, &effects),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(!effects
        .recovery_replacement_path()
        .expect("recovery replacement path")
        .exists());
}

#[test]
fn a_request_written_after_the_session_epoch_changed_is_refused() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let effects = FakeEffects::new(vault.path().to_path_buf());
    let captured = vault.state.session_epoch();
    vault.state.advance_session_epoch();

    let error =
        write_recovery_replacement_request_in_state(&vault.state, &effects, REQUESTED_AT, captured)
            .expect_err("a request from an earlier session must not be written");

    assert_eq!(
        error,
        "Sesame changed while preparing the recovery kit request. Request it again."
    );
    assert!(!effects
        .recovery_replacement_path()
        .expect("recovery replacement path")
        .exists());
}

#[test]
fn accept_rollback_needs_an_unlocked_vault() {
    let state = VaultState::default();
    let effects = FakeEffects::new(PathBuf::from("/fictional/sesame/vault.sesame"));

    assert_eq!(
        accept_rollback_in_state(&state, &effects),
        Err("Unlock your vault first.".to_string())
    );
    assert!(effects.calls().is_empty());
}

#[test]
fn accept_rollback_resets_the_record_to_the_open_revision() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let snapshot = vault
        .state
        .session
        .lock()
        .expect("session lock")
        .as_ref()
        .expect("session")
        .snapshot();
    let effects = FakeEffects::new(vault.path().to_path_buf());

    assert_eq!(accept_rollback_in_state(&vault.state, &effects), Ok(()));
    assert_eq!(
        effects.calls(),
        vec![Effect::ResetRollbackRecord {
            vault_id: snapshot.vault_id.expect("vault id"),
            revision: snapshot.revision,
        }]
    );
}

#[test]
fn lifecycle_commands_refuse_a_locked_vault_without_touching_effects() {
    let state = VaultState::default();
    let effects = FakeEffects::new(PathBuf::new());

    assert_eq!(
        resume_recovery_setup_in_state(&state),
        Err("Unlock your vault before resuming recovery setup.".to_string())
    );
    assert_eq!(
        complete_recovery_setup_in_state(&state, Zeroizing::new("fictional kit".to_string())),
        Err("Unlock your vault before completing recovery setup.".to_string())
    );
    assert_eq!(
        set_unlock_pin_in_state(&state, &effects, PIN.to_string()),
        Err("Unlock your vault before setting a PIN.".to_string())
    );
    assert_eq!(
        remove_unlock_pin_in_state(&state, &effects),
        Err("Unlock your vault before removing the PIN.".to_string())
    );
    assert_eq!(
        change_master_password_in_state(
            &state,
            &effects,
            password_request(Some(MASTER_PASSWORD), None)
        )
        .err(),
        Some("Unlock your vault before changing its master password.".to_string())
    );
    assert!(effects.calls().is_empty());
}

#[test]
fn vault_status_for_a_missing_file_clears_the_unlock_method_caches() {
    let state = VaultState::default();
    let path = std::env::temp_dir()
        .join(format!("sesame-missing-{}", random_id()))
        .join("vault.sesame");
    let effects = FakeEffects::new(path);

    let status = get_vault_status_in_state(&state, &effects).expect("status");

    assert!(!status.exists);
    assert!(!status.unlocked);
    assert!(!status.pin_unlock_available);
    assert!(!status.hello_unlock_available);
    assert!(!status.onboarding_required);
    assert_eq!(status.vault_id, None);
    assert_eq!(status.revision, 0);
    assert_eq!(state.cached_pin_unlock(), Some(false));
    assert_eq!(state.cached_hello_unlock(), Some(false));
}

#[test]
fn auto_lock_minutes_are_range_checked() {
    let state = VaultState::default();

    assert_eq!(
        set_auto_lock_minutes_in_state(&state, 0),
        Err("Choose an automatic lock delay between 1 and 60 minutes.".to_string())
    );
    assert_eq!(state.auto_lock_minutes(), 5);
    assert_eq!(
        set_auto_lock_minutes_in_state(&state, 61),
        Err("Choose an automatic lock delay between 1 and 60 minutes.".to_string())
    );
    assert_eq!(set_auto_lock_minutes_in_state(&state, 60), Ok(()));
    assert_eq!(state.auto_lock_minutes(), 60);
}

struct Fixture {
    directory: PathBuf,
    request: PathBuf,
    session: UnlockedVault,
    kit: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn requested() -> Fixture {
    let directory = std::env::temp_dir().join(format!("sesame-recovery-request-{}", random_id()));
    std::fs::create_dir_all(&directory).expect("test directory");
    let (opened, kit) = create_vault(MASTER_PASSWORD, "Fictional vault").expect("created vault");
    let mut session = UnlockedVault::from_opened(directory.join("vault.sesame"), &opened)
        .expect("unlocked vault");
    session.setup_complete = true;
    persist_session(&mut session).expect("persisted vault");
    let request = directory.join(RECOVERY_REPLACEMENT_FILE);
    write_request(&request, &session, REQUESTED_AT).expect("written request");
    Fixture {
        directory,
        request,
        session,
        kit,
    }
}

fn kit_opens(fixture: &Fixture, kit: &str) -> bool {
    let bytes = std::fs::read(fixture.directory.join("vault.sesame")).expect("vault bytes");
    let file: VaultFile = serde_json::from_slice(&bytes).expect("vault file");
    open_vault_with_recovery_kit(&file, kit).is_ok()
}

#[test]
fn a_completed_request_cannot_be_completed_again() {
    let mut fixture = requested();
    let kit = complete_request(
        &fixture.request,
        &mut fixture.session,
        MASTER_PASSWORD,
        READY_AT,
        false,
    )
    .expect("replaced kit")
    .recovery_kit;
    assert!(!fixture.request.exists());
    assert!(complete_request(
        &fixture.request,
        &mut fixture.session,
        MASTER_PASSWORD,
        READY_AT + 60,
        false
    )
    .is_err());
    assert!(kit_opens(&fixture, &kit));
    assert!(!kit_opens(&fixture, &fixture.kit));
}

#[test]
fn a_wrong_master_password_keeps_the_request_and_the_current_kit() {
    let mut fixture = requested();
    let before = std::fs::read(fixture.directory.join("vault.sesame")).expect("vault bytes");

    let error = complete_request(
        &fixture.request,
        &mut fixture.session,
        "fictional wrong password",
        READY_AT,
        false,
    )
    .err()
    .expect("refused");

    assert!(error.contains("master password is not correct"), "{error}");
    assert_eq!(
        std::fs::read(fixture.directory.join("vault.sesame")).expect("vault bytes"),
        before
    );
    assert!(kit_opens(&fixture, &fixture.kit));
    assert_eq!(
        pending_request(&fixture.request, &fixture.session),
        Ok(Some(REQUESTED_AT))
    );
    assert!(complete_request(
        &fixture.request,
        &mut fixture.session,
        MASTER_PASSWORD,
        READY_AT,
        false
    )
    .is_ok());
}

#[test]
fn a_completed_request_prunes_local_backups_only_when_asked() {
    let mut fixture = requested();
    let backups = fixture.directory.join("backups");
    std::fs::create_dir_all(&backups).expect("backup folder");
    let old_copy = std::fs::read(fixture.directory.join("vault.sesame")).expect("vault bytes");
    std::fs::write(backups.join("sesame-backup-fictional.sesame"), &old_copy).expect("backup");

    let kept = complete_request(
        &fixture.request,
        &mut fixture.session,
        MASTER_PASSWORD,
        READY_AT,
        false,
    )
    .expect("replaced kit");
    assert_eq!(kept.backups_remaining, None);
    assert!(backups.join("sesame-backup-fictional.sesame").exists());

    write_request(&fixture.request, &fixture.session, REQUESTED_AT).expect("second request");
    let pruned = complete_request(
        &fixture.request,
        &mut fixture.session,
        MASTER_PASSWORD,
        READY_AT,
        true,
    )
    .expect("replaced kit again");
    assert_eq!(pruned.backups_remaining, Some(0));
    assert!(!backups.join("sesame-backup-fictional.sesame").exists());
}

#[test]
fn an_early_completion_keeps_the_request() {
    let mut fixture = requested();
    assert!(complete_request(
        &fixture.request,
        &mut fixture.session,
        MASTER_PASSWORD,
        READY_AT - 1,
        false
    )
    .is_err());
    assert_eq!(
        pending_request(&fixture.request, &fixture.session),
        Ok(Some(REQUESTED_AT))
    );
}

#[cfg(unix)]
#[test]
fn a_request_that_cannot_be_removed_replaces_nothing() {
    use std::os::unix::fs::PermissionsExt;

    let mut fixture = requested();
    let request_directory = fixture.directory.clone();
    let readable = std::fs::metadata(&request_directory)
        .expect("directory metadata")
        .permissions();
    std::fs::set_permissions(&request_directory, std::fs::Permissions::from_mode(0o500))
        .expect("read-only directory");
    let result = complete_request(
        &fixture.request,
        &mut fixture.session,
        MASTER_PASSWORD,
        READY_AT,
        false,
    );
    std::fs::set_permissions(&request_directory, readable).expect("restored directory");
    assert!(result.is_err());
    assert!(kit_opens(&fixture, &fixture.kit));
    assert_eq!(
        pending_request(&fixture.request, &fixture.session),
        Ok(Some(REQUESTED_AT))
    );
}

#[test]
fn no_request_serializes_without_a_request_time() {
    let json = serde_json::to_value(RecoveryReplacementStatus::default()).expect("status json");
    assert_eq!(
        json,
        serde_json::json!({ "ready": false, "timeConfirmed": false })
    );
}

#[test]
fn a_status_is_ready_only_after_the_wait_and_with_a_confirmed_time() {
    let status = recovery_replacement_status(
        Some(REQUESTED_AT),
        Some(TrustedTime {
            earliest: READY_AT,
            latest: READY_AT + 30,
        }),
    );
    assert_eq!(status.requested_at, Some(REQUESTED_AT));
    assert_eq!(status.available_at, Some(READY_AT));
    assert!(status.ready);
    assert!(status.time_confirmed);

    let early = recovery_replacement_status(
        Some(REQUESTED_AT),
        Some(TrustedTime {
            earliest: READY_AT - 1,
            latest: READY_AT - 1,
        }),
    );
    assert!(!early.ready);
    assert!(early.time_confirmed);

    let unconfirmed = recovery_replacement_status(Some(REQUESTED_AT), None);
    assert!(!unconfirmed.ready);
    assert!(!unconfirmed.time_confirmed);
}
