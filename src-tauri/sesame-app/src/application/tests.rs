use std::path::PathBuf;
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
use crate::sync::coordinator::{Coordinator, ManualRun};
use crate::test_support::TestVault;
use crate::vault::backup::RECOVERY_REPLACEMENT_FILE;
use crate::vault::recovery_health::RecoveryHealth;
use crate::vault::storage::write_vault_file;
use crate::vault::throttle::{PersistedPinThrottle, PinAttemptGuard};
use crate::vault::{
    random_id, Card, TaggedItem, UnlockedVault, VaultResult, VaultSnapshot, VaultState, WifiNetwork,
};

use super::browser_fill::ApprovalKind;
use super::lifecycle::{lock_and_notify, unlock_vault_in_state};
use super::records::{
    login_card_in_state, login_summary_in_state, record_view_in_state, redacted_view,
    vault_snapshot_in_state,
};
use super::reveal::{copy_item_field_in_state, item_field_in_state};
use super::search::search_items_in_state;
use super::sync::SyncStore;
use super::terminal_allowances::TerminalAllowances;
use super::DesktopEffects;

pub(super) use crate::test_support::grant;

const MASTER_PASSWORD: &str = "fictional master password";
const WRONG_PASSWORD: &str = "fictional wrong password";
const EMIT_ERROR: &str = "Sesame could not notify the interface that the vault locked.";
const CANARY: &str = "fictional-secret-canary";
pub(super) const COPY_EPOCH: u64 = 41;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Effect {
    ReportKeyPageFallback,
    ObserveUnlock,
    ObserveLock {
        session_present: bool,
    },
    ClearArmedClipboard,
    CopySecret {
        value: String,
        clear_after_ms: Option<u64>,
    },
    RevokePresence,
    ForgetTerminalAllowances,
    CancelBreachScan,
    EmitVaultLocked,
    RecordRecoveryExport {
        vault_id: String,
        revision: u64,
    },
    RecordRecoveryVerification {
        vault_id: String,
        revision: u64,
    },
    ReadRecoveryHealth {
        current_vault_id: Option<String>,
    },
    ResetRollbackAfterRestore {
        vault_id: Option<String>,
        revision: u64,
    },
    ClearPinThrottle,
    CancelPendingApprovals,
    ReportBackupIoError,
    WritePinThrottle {
        failures: u32,
        locked_until_unix_ms: Option<u64>,
    },
    ResetRollbackRecord {
        vault_id: String,
        revision: u64,
    },
    DiscardRecoveryReplacement,
    RecordBrowserHostRegistration(String),
    EmitBrowserApprovalCancelled {
        kind: ApprovalKind,
        approval_id: String,
        reason: &'static str,
    },
    EmitBreachScanProgress {
        checked: usize,
        total: usize,
    },
    EmitBreachScanFinished,
    CopiedWhileSessionHeld(bool),
}

pub(super) struct FakeEffects<'a> {
    path: PathBuf,
    presence: Option<&'a ReleasePresence>,
    allowances: Option<&'a TerminalAllowances>,
    fail_emit: bool,
    fail_copy: bool,
    copy_epoch: u64,
    health: RecoveryHealth,
    throttle: Mutex<Option<PersistedPinThrottle>>,
    epoch_advance_on_pin_write: Option<&'a VaultState>,
    copy_probe: Option<&'a VaultState>,
    sync: Option<(PathBuf, Coordinator)>,
    calls: Mutex<Vec<Effect>>,
}

impl<'a> FakeEffects<'a> {
    pub(super) fn new(path: PathBuf) -> Self {
        Self {
            path,
            presence: None,
            allowances: None,
            fail_emit: false,
            fail_copy: false,
            copy_epoch: COPY_EPOCH,
            health: RecoveryHealth::default(),
            throttle: Mutex::new(None),
            epoch_advance_on_pin_write: None,
            copy_probe: None,
            sync: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn with_sync(path: PathBuf, data_dir: PathBuf, coordinator: Coordinator) -> Self {
        Self {
            sync: Some((data_dir, coordinator)),
            ..Self::new(path)
        }
    }

    pub(super) fn with_epoch_advance_on_pin_write(path: PathBuf, state: &'a VaultState) -> Self {
        Self {
            epoch_advance_on_pin_write: Some(state),
            ..Self::new(path)
        }
    }

    pub(super) fn with_presence(path: PathBuf, presence: &'a ReleasePresence) -> Self {
        Self {
            presence: Some(presence),
            ..Self::new(path)
        }
    }

    pub(super) fn with_allowances(
        path: PathBuf,
        presence: &'a ReleasePresence,
        allowances: &'a TerminalAllowances,
    ) -> Self {
        Self {
            presence: Some(presence),
            allowances: Some(allowances),
            ..Self::new(path)
        }
    }

    pub(super) fn with_recovery_health(path: PathBuf, health: RecoveryHealth) -> Self {
        Self {
            health,
            ..Self::new(path)
        }
    }

    pub(super) fn with_pin_throttle(path: PathBuf, throttle: PersistedPinThrottle) -> Self {
        Self {
            throttle: Mutex::new(Some(throttle)),
            ..Self::new(path)
        }
    }

    pub(super) fn probing_copies(self, state: &'a VaultState) -> Self {
        Self {
            copy_probe: Some(state),
            ..self
        }
    }

    pub(super) fn failing_copy(path: PathBuf) -> Self {
        Self {
            fail_copy: true,
            ..Self::new(path)
        }
    }

    fn failing_emit(path: PathBuf) -> Self {
        Self {
            fail_emit: true,
            ..Self::new(path)
        }
    }

    pub(super) fn calls(&self) -> Vec<Effect> {
        self.calls.lock().expect("calls lock").clone()
    }

    pub(super) fn pin_throttle(&self) -> Option<PersistedPinThrottle> {
        self.throttle.lock().expect("throttle lock").clone()
    }

    fn record(&self, effect: Effect) {
        self.calls.lock().expect("calls lock").push(effect);
    }
}

impl DesktopEffects for FakeEffects<'_> {
    fn vault_path(&self) -> VaultResult<PathBuf> {
        Ok(self.path.clone())
    }

    fn report_key_page_fallback(&self, _unlocked: &UnlockedVault) {
        self.record(Effect::ReportKeyPageFallback);
    }

    fn observe_unlock(&self, _snapshot: &VaultSnapshot) {
        self.record(Effect::ObserveUnlock);
    }

    fn claim_idle_sync_store(&self) -> Option<(SyncStore, ManualRun)> {
        let (data_dir, coordinator) = self.sync.as_ref()?;
        let run = coordinator.begin_manual()?;
        Some((SyncStore::new(data_dir.clone()), run))
    }

    fn observe_lock(&self, state: &VaultState) {
        let session_present = state.session.lock().expect("session lock").is_some();
        self.record(Effect::ObserveLock { session_present });
    }

    fn clear_armed_clipboard(&self) -> VaultResult<()> {
        self.record(Effect::ClearArmedClipboard);
        Ok(())
    }

    fn copy_secret(
        &self,
        value: Zeroizing<String>,
        clear_after_ms: Option<u64>,
    ) -> VaultResult<u64> {
        if self.fail_copy {
            return Err("Sesame could not copy to the clipboard.".into());
        }
        if let Some(state) = self.copy_probe {
            self.record(Effect::CopiedWhileSessionHeld(
                state.session.try_lock().is_err(),
            ));
        }
        self.record(Effect::CopySecret {
            value: value.to_string(),
            clear_after_ms,
        });
        Ok(self.copy_epoch)
    }

    fn revoke_presence(&self) {
        self.record(Effect::RevokePresence);
        if let Some(presence) = self.presence {
            presence.revoke();
        }
    }

    fn forget_terminal_allowances(&self) {
        self.record(Effect::ForgetTerminalAllowances);
        if let Some(allowances) = self.allowances {
            allowances.forget_all();
        }
    }

    fn cancel_breach_scan(&self) {
        self.record(Effect::CancelBreachScan);
    }

    fn emit_vault_locked(&self) -> Result<(), ()> {
        self.record(Effect::EmitVaultLocked);
        if self.fail_emit {
            Err(())
        } else {
            Ok(())
        }
    }

    fn record_recovery_export(&self, vault_id: &str, revision: u64) {
        self.record(Effect::RecordRecoveryExport {
            vault_id: vault_id.to_string(),
            revision,
        });
    }

    fn record_recovery_verification(&self, vault_id: &str, revision: u64) {
        self.record(Effect::RecordRecoveryVerification {
            vault_id: vault_id.to_string(),
            revision,
        });
    }

    fn recovery_health(&self, current_vault_id: Option<&str>) -> VaultResult<RecoveryHealth> {
        self.record(Effect::ReadRecoveryHealth {
            current_vault_id: current_vault_id.map(str::to_string),
        });
        Ok(self.health.clone())
    }

    fn reset_rollback_after_restore(&self, vault_id: Option<&str>, revision: u64) {
        self.record(Effect::ResetRollbackAfterRestore {
            vault_id: vault_id.map(str::to_string),
            revision,
        });
    }

    fn cancel_pending_approvals(&self) {
        self.record(Effect::CancelPendingApprovals);
    }

    fn report_backup_io_error(&self) {
        self.record(Effect::ReportBackupIoError);
    }

    fn clear_pin_throttle_state(&self) -> VaultResult<()> {
        self.record(Effect::ClearPinThrottle);
        *self.throttle.lock().expect("throttle lock") = None;
        Ok(())
    }

    fn read_pin_throttle_state(&self) -> VaultResult<Option<PersistedPinThrottle>> {
        Ok(self.throttle.lock().expect("throttle lock").clone())
    }

    fn write_pin_throttle_state(&self, guard: &PinAttemptGuard) -> VaultResult<()> {
        let persisted = guard.persisted();
        self.record(Effect::WritePinThrottle {
            failures: persisted.failures,
            locked_until_unix_ms: persisted.locked_until_unix_ms,
        });
        *self.throttle.lock().expect("throttle lock") = Some(persisted);
        if let Some(state) = self.epoch_advance_on_pin_write {
            state.advance_session_epoch();
        }
        Ok(())
    }

    fn recovery_replacement_path(&self) -> VaultResult<PathBuf> {
        let parent = self
            .path
            .parent()
            .ok_or("Sesame could not locate the vault folder.")?;
        Ok(parent.join(RECOVERY_REPLACEMENT_FILE))
    }

    fn discard_recovery_replacement(&self) {
        self.record(Effect::DiscardRecoveryReplacement);
    }

    fn reset_rollback_record(&self, vault_id: &str, revision: u64) -> VaultResult<()> {
        self.record(Effect::ResetRollbackRecord {
            vault_id: vault_id.to_string(),
            revision,
        });
        Ok(())
    }

    fn record_browser_host_registration(&self, code: &'static str) {
        self.record(Effect::RecordBrowserHostRegistration(code.to_string()));
    }

    fn emit_browser_approval_cancelled(
        &self,
        kind: ApprovalKind,
        approval_id: &str,
        reason: &'static str,
    ) {
        self.record(Effect::EmitBrowserApprovalCancelled {
            kind,
            approval_id: approval_id.to_string(),
            reason,
        });
    }

    fn emit_breach_scan_progress(&self, checked: usize, total: usize) {
        self.record(Effect::EmitBreachScanProgress { checked, total });
    }

    fn emit_breach_scan_finished(&self) {
        self.record(Effect::EmitBreachScanFinished);
    }
}

struct TempVault {
    directory: PathBuf,
    path: PathBuf,
}

impl TempVault {
    fn new() -> Self {
        let (opened, _) = sesame_core::api::create_vault(MASTER_PASSWORD, "Fictional vault")
            .expect("created vault");
        let directory = std::env::temp_dir().join(format!("sesame-application-{}", random_id()));
        std::fs::create_dir_all(&directory).expect("temp directory");
        let path = directory.join("vault.sesame");
        write_vault_file(&path, &opened.file).expect("written vault");
        Self { directory, path }
    }
}

impl Drop for TempVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn unlocking_installs_the_session_and_records_the_effects_in_order() {
    let vault = TempVault::new();
    let state = VaultState::default();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(vault.path.clone());
    let before = state.session_epoch();

    let snapshot = unlock_vault_in_state(
        &state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    )
    .expect("unlocked");

    assert!(snapshot.vault_id.is_some());
    assert!(state.session.lock().expect("session lock").is_some());
    assert_eq!(state.session_epoch(), before + 1);
    assert_eq!(state.cached_pin_unlock(), Some(false));
    assert_eq!(state.cached_hello_unlock(), Some(false));
    assert!(presence.require(state.session_epoch()).is_ok());
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ReportKeyPageFallback,
            Effect::ObserveUnlock,
            Effect::WritePinThrottle {
                failures: 0,
                locked_until_unix_ms: None,
            },
        ]
    );
}

struct SyncDigestCase {
    vault: TestVault,
    data_dir: PathBuf,
}

impl SyncDigestCase {
    fn with_stored_digest(digest: impl FnOnce(&crate::vault::VaultPayload) -> String) -> Self {
        let vault = TestVault::with_login("fictional-login", "https://northwind.example");
        let opened = VaultState::default();
        unlock_vault_in_state(
            &opened,
            &ReleasePresence::default(),
            &FakeEffects::new(vault.path().to_path_buf()),
            Zeroizing::new(MASTER_PASSWORD.to_string()),
        )
        .expect("unlocked");
        let stored = {
            let session = opened.session.lock().expect("session lock");
            let payload = session
                .as_ref()
                .expect("unlocked")
                .open_payload()
                .expect("payload");
            digest(&payload)
        };
        let data_dir = std::env::temp_dir().join(format!("sesame-sync-digest-{}", random_id()));
        std::fs::create_dir_all(&data_dir).expect("sync directory");
        let mut local = crate::sync::state::SyncState::new("fictional-vault", "fictional-device");
        local.payload_digest = stored;
        SyncStore::new(data_dir.clone())
            .save_state(&local)
            .expect("saved Sync state");
        Self { vault, data_dir }
    }

    fn stored_digest(&self) -> String {
        SyncStore::new(self.data_dir.clone())
            .load_state()
            .expect("Sync state")
            .expect("saved Sync state")
            .payload_digest
    }

    fn unlock(&self, coordinator: &Coordinator) -> VaultState {
        let state = VaultState::default();
        self.unlock_into(&state, coordinator);
        state
    }

    fn unlock_into(&self, state: &VaultState, coordinator: &Coordinator) {
        let effects = FakeEffects::with_sync(
            self.vault.path().to_path_buf(),
            self.data_dir.clone(),
            coordinator.clone(),
        );
        unlock_vault_in_state(
            state,
            &ReleasePresence::default(),
            &effects,
            Zeroizing::new(MASTER_PASSWORD.to_string()),
        )
        .expect("unlocked");
    }

    fn store(&self) -> SyncStore {
        SyncStore::new(self.data_dir.clone())
    }

    fn change_digest_of(state: &VaultState) -> String {
        let session = state.session.lock().expect("session lock");
        let payload = session
            .as_ref()
            .expect("unlocked")
            .open_payload()
            .expect("payload");
        crate::sync::state::change_digest(&payload).expect("change digest")
    }

    fn use_reads_as_a_change(&self, state: &VaultState) -> bool {
        super::logins::record_item_use_in_state(state, "fictional-login").expect("recorded use");
        let local = self
            .store()
            .load_state()
            .expect("Sync state")
            .expect("saved Sync state");
        let session = state.session.lock().expect("session lock");
        super::sync::vault_has_local_changes(&local, session.as_ref().expect("unlocked"))
            .expect("compared")
    }
}

impl Drop for SyncDigestCase {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn legacy_digest(payload: &crate::vault::VaultPayload) -> String {
    crate::sync::state::payload_digest(&serde_json::to_vec(payload).expect("serialized payload"))
}

#[test]
fn unlocking_upgrades_an_older_sync_digest_so_a_later_use_is_not_a_change() {
    let case = SyncDigestCase::with_stored_digest(legacy_digest);
    let coordinator = Coordinator::new();

    let state = case.unlock(&coordinator);

    let expected = {
        let session = state.session.lock().expect("session lock");
        let payload = session
            .as_ref()
            .expect("unlocked")
            .open_payload()
            .expect("payload");
        crate::sync::state::change_digest(&payload).expect("change digest")
    };
    assert_eq!(case.stored_digest(), expected);
    assert!(coordinator.begin(), "unlocking leaves no Sync run behind");
    coordinator.finish(crate::sync::coordinator::Outcome::AlreadyCurrent);

    super::logins::record_item_use_in_state(&state, "fictional-login").expect("recorded use");
    let local = SyncStore::new(case.data_dir.clone())
        .load_state()
        .expect("Sync state")
        .expect("saved Sync state");
    let session = state.session.lock().expect("session lock");
    assert!(
        !super::sync::vault_has_local_changes(&local, session.as_ref().expect("unlocked"))
            .expect("compared")
    );
}

#[test]
fn unlocking_keeps_an_older_sync_digest_that_does_not_match_the_vault() {
    let case = SyncDigestCase::with_stored_digest(|payload| {
        let mut edited = payload.clone();
        edited.entries[0].username = "fictional-user-edited".into();
        legacy_digest(&edited)
    });
    let before = case.stored_digest();

    case.unlock(&Coordinator::new());

    assert_eq!(case.stored_digest(), before);
}

#[test]
fn unlocking_leaves_the_sync_digest_to_a_run_already_in_progress() {
    let case = SyncDigestCase::with_stored_digest(legacy_digest);
    let before = case.stored_digest();
    let coordinator = Coordinator::new();
    assert!(coordinator.begin());

    case.unlock(&coordinator);

    assert_eq!(case.stored_digest(), before);
}

#[test]
fn a_run_stopped_by_the_lock_upgrades_the_digest_the_unlock_left_to_it() {
    use crate::sync::coordinator::{Outcome, Phase};

    let case = SyncDigestCase::with_stored_digest(legacy_digest);
    let legacy = case.stored_digest();
    let coordinator = Coordinator::new();
    let state = VaultState::default();
    assert!(coordinator.begin());
    let run = Err("sync_locked".to_string());

    case.unlock_into(&state, &coordinator);
    assert_eq!(
        case.stored_digest(),
        legacy,
        "the unlock leaves it to the run"
    );

    super::sync_transfer::finish_run_in_state(&state, Some(&case.store()), &coordinator, run);

    assert_eq!(coordinator.status().phase, Phase::Paused);
    assert_eq!(
        case.stored_digest(),
        SyncDigestCase::change_digest_of(&state)
    );
    assert!(!case.use_reads_as_a_change(&state));
    assert!(coordinator.begin(), "the run released its claim");
    coordinator.finish(Outcome::AlreadyCurrent);
}

#[test]
fn a_run_stopped_by_the_lock_before_the_unlock_leaves_the_upgrade_to_the_unlock() {
    let case = SyncDigestCase::with_stored_digest(legacy_digest);
    let legacy = case.stored_digest();
    let coordinator = Coordinator::new();
    let state = VaultState::default();
    assert!(coordinator.begin());

    super::sync_transfer::finish_run_in_state(
        &state,
        Some(&case.store()),
        &coordinator,
        Err("sync_locked".to_string()),
    );
    assert_eq!(
        case.stored_digest(),
        legacy,
        "a locked vault proves nothing"
    );

    case.unlock_into(&state, &coordinator);

    assert_eq!(
        case.stored_digest(),
        SyncDigestCase::change_digest_of(&state)
    );
    assert!(!case.use_reads_as_a_change(&state));
}

#[test]
fn a_failed_run_keeps_an_older_digest_that_does_not_match_the_vault() {
    let case = SyncDigestCase::with_stored_digest(|payload| {
        let mut edited = payload.clone();
        edited.entries[0].username = "fictional-user-edited".into();
        legacy_digest(&edited)
    });
    let before = case.stored_digest();
    let coordinator = Coordinator::new();
    assert!(coordinator.begin());
    let state = case.unlock(&coordinator);

    super::sync_transfer::finish_run_in_state(
        &state,
        Some(&case.store()),
        &coordinator,
        Err("sync_locked".to_string()),
    );

    assert_eq!(case.stored_digest(), before);
    assert!(case.use_reads_as_a_change(&state));
}

#[test]
fn a_failed_run_never_upgrades_once_a_use_has_changed_the_vault() {
    let case = SyncDigestCase::with_stored_digest(legacy_digest);
    let legacy = case.stored_digest();
    let coordinator = Coordinator::new();
    assert!(coordinator.begin());
    let state = case.unlock(&coordinator);
    super::logins::record_item_use_in_state(&state, "fictional-login").expect("recorded use");

    super::sync_transfer::finish_run_in_state(
        &state,
        Some(&case.store()),
        &coordinator,
        Err("The Sync server could not be reached.".to_string()),
    );

    assert_eq!(case.stored_digest(), legacy);
    assert!(coordinator.begin(), "the run released its claim");
}

#[test]
fn a_finished_run_leaves_the_digest_alone_and_a_run_without_a_store_still_releases() {
    use crate::sync::coordinator::Outcome;

    let case = SyncDigestCase::with_stored_digest(legacy_digest);
    let legacy = case.stored_digest();
    let coordinator = Coordinator::new();
    assert!(coordinator.begin());
    let state = case.unlock(&coordinator);

    super::sync_transfer::finish_run_in_state(
        &state,
        Some(&case.store()),
        &coordinator,
        Ok(Outcome::AlreadyCurrent),
    );
    assert_eq!(case.stored_digest(), legacy);

    assert!(coordinator.begin());
    super::sync_transfer::finish_run_in_state(
        &state,
        None,
        &coordinator,
        Err("sync_locked".to_string()),
    );
    assert_eq!(case.stored_digest(), legacy);
    assert!(coordinator.begin(), "the run released its claim");
}

#[test]
fn a_manual_run_stopped_by_the_lock_upgrades_before_it_lets_go() {
    let case = SyncDigestCase::with_stored_digest(legacy_digest);
    let coordinator = Coordinator::new();
    let run = coordinator.begin_manual().expect("manual run");
    let state = case.unlock(&coordinator);

    super::sync::release_claim_after_failure(&state, &case.store(), || drop(run));

    assert_eq!(
        case.stored_digest(),
        SyncDigestCase::change_digest_of(&state)
    );
    assert!(
        coordinator.begin_manual().is_some(),
        "the run released its claim"
    );
}

struct ReleasedFixture {
    directory: PathBuf,
    password: String,
}

impl ReleasedFixture {
    fn v0_5_3() -> Self {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../sesame-core/tests/fixtures/compatibility");
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(corpus.join("manifest.json")).expect("corpus manifest"),
        )
        .expect("parsed manifest");
        let entry = manifest["fixtures"]
            .as_array()
            .expect("fixture list")
            .iter()
            .find(|fixture| fixture["id"] == "v0.5.3")
            .expect("0.5.3 fixture");
        let directory = std::env::temp_dir().join(format!("sesame-released-{}", random_id()));
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::copy(
            corpus.join(entry["fileName"].as_str().expect("file name")),
            directory.join("vault.sesame"),
        )
        .expect("copied fixture");
        Self {
            directory,
            password: entry["secrets"]["masterPassword"]
                .as_str()
                .expect("password")
                .to_string(),
        }
    }

    fn vault(&self) -> PathBuf {
        self.directory.join("vault.sesame")
    }

    fn data_dir(&self) -> PathBuf {
        self.directory.join("data")
    }

    fn digest_0_5_3_stored(&self) -> String {
        let file = sesame_core::loader::VaultLoader::read(&self.vault()).expect("fixture file");
        assert_eq!(file.format_version, 10);
        let written = sesame_core::loader::VaultLoader::authenticate(
            &file,
            sesame_core::loader::Credential::MasterPassword(&self.password),
        )
        .expect("authenticated fixture");
        let bytes = written.bytes();
        let end = bytes
            .iter()
            .rposition(|byte| *byte != b' ')
            .expect("payload bytes")
            + 1;
        crate::sync::state::payload_digest(&bytes[..end])
    }

    fn unlock(&self, stored: String) -> VaultState {
        let store = SyncStore::new(self.data_dir());
        std::fs::create_dir_all(self.data_dir()).expect("sync directory");
        let mut local = crate::sync::state::SyncState::new("fictional-vault", "fictional-device");
        local.payload_digest = stored;
        store.save_state(&local).expect("saved Sync state");
        let state = VaultState::default();
        unlock_vault_in_state(
            &state,
            &ReleasePresence::default(),
            &FakeEffects::with_sync(self.vault(), self.data_dir(), Coordinator::new()),
            Zeroizing::new(self.password.clone()),
        )
        .expect("unlocked");
        state
    }

    fn unsynced(&self, state: &VaultState) -> bool {
        let local = SyncStore::new(self.data_dir())
            .load_state()
            .expect("Sync state")
            .expect("saved Sync state");
        let session = state.session.lock().expect("session lock");
        super::sync::vault_has_local_changes(&local, session.as_ref().expect("unlocked"))
            .expect("compared")
    }
}

impl Drop for ReleasedFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn the_released_0_5_3_vault_upgrades_without_anything_to_sync() {
    let fixture = ReleasedFixture::v0_5_3();
    let stored = fixture.digest_0_5_3_stored();

    let state = fixture.unlock(stored);

    assert!(!fixture.unsynced(&state));
    let session = state.session.lock().expect("session lock");
    let payload = session
        .as_ref()
        .expect("unlocked")
        .open_payload()
        .expect("payload");
    let login = payload
        .entries
        .iter()
        .find(|entry| entry.id == "login-alpha")
        .expect("fixture login");
    assert!(login.legacy_fields.is_empty());
    assert_eq!(login.custom_fields.len(), 2);
}

#[test]
fn the_released_0_5_3_vault_keeps_an_edit_it_had_not_synced() {
    let fixture = ReleasedFixture::v0_5_3();
    let stored = crate::sync::state::payload_digest(b"fictional earlier vault content");

    let state = fixture.unlock(stored.clone());

    assert!(fixture.unsynced(&state));
    assert_eq!(
        SyncStore::new(fixture.data_dir())
            .load_state()
            .expect("Sync state")
            .expect("saved Sync state")
            .payload_digest,
        stored
    );
}

#[test]
fn unlocking_grants_presence_for_the_epoch_it_installed() {
    let vault = TempVault::new();
    let state = VaultState::default();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::with_epoch_advance_on_pin_write(vault.path.clone(), &state);
    let installed = state.session_epoch() + 1;

    unlock_vault_in_state(
        &state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    )
    .expect("unlocked");

    assert_eq!(state.session_epoch(), installed + 1);
    assert!(presence.require(installed).is_ok());
    assert_eq!(
        presence.require(installed + 1),
        Err(PRESENCE_REQUIRED.to_string())
    );
}

#[test]
fn a_wrong_password_installs_nothing() {
    let vault = TempVault::new();
    let state = VaultState::default();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(vault.path.clone());
    let before = state.session_epoch();

    assert!(unlock_vault_in_state(
        &state,
        &presence,
        &effects,
        Zeroizing::new(WRONG_PASSWORD.to_string()),
    )
    .is_err());

    assert!(state.session.lock().expect("session lock").is_none());
    assert_eq!(state.session_epoch(), before);
    assert_eq!(state.cached_pin_unlock(), None);
    assert_eq!(presence.require(before), Err(PRESENCE_REQUIRED.to_string()));
    assert!(effects.calls().is_empty());
}

#[test]
fn locking_observes_before_clearing_and_records_every_effect_in_order() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);
    let before = vault.state.session_epoch();

    lock_and_notify(&vault.state, &effects).expect("locked");

    assert!(vault.state.session.lock().expect("session lock").is_none());
    assert_eq!(vault.state.session_epoch(), before + 1);
    assert_eq!(presence.require(before), Err(PRESENCE_REQUIRED.to_string()));
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ObserveLock {
                session_present: true
            },
            Effect::ClearArmedClipboard,
            Effect::RevokePresence,
            Effect::ForgetTerminalAllowances,
            Effect::CancelBreachScan,
            Effect::EmitVaultLocked,
        ]
    );
}

#[test]
fn locking_an_already_locked_vault_keeps_the_existing_behavior() {
    let state = VaultState::default();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);
    let before = state.session_epoch();

    lock_and_notify(&state, &effects).expect("locked");

    assert!(state.session.lock().expect("session lock").is_none());
    assert_eq!(state.session_epoch(), before + 1);
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ObserveLock {
                session_present: false
            },
            Effect::ClearArmedClipboard,
            Effect::RevokePresence,
            Effect::ForgetTerminalAllowances,
            Effect::CancelBreachScan,
            Effect::EmitVaultLocked,
        ]
    );
}

#[test]
fn after_locking_reveal_needs_presence_and_search_needs_an_unlocked_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);

    assert_eq!(
        search_items_in_state(&vault.state, "northwind").expect("search"),
        vec!["fictional-login".to_string()]
    );
    assert_eq!(
        item_field_in_state(
            &vault.state,
            &presence,
            "fictional-login",
            "login",
            "password"
        )
        .expect("released")
        .as_str(),
        "fictional-stored-secret"
    );

    lock_and_notify(&vault.state, &effects).expect("locked");

    assert_eq!(
        item_field_in_state(
            &vault.state,
            &presence,
            "fictional-login",
            "login",
            "password"
        )
        .map(|value| value.to_string()),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert_eq!(
        search_items_in_state(&vault.state, "northwind"),
        Err("Unlock your vault first.".to_string())
    );
}

#[test]
fn a_grant_from_before_a_lock_is_rejected_after_the_next_unlock() {
    let vault = TempVault::new();
    let state = VaultState::default();
    let presence = ReleasePresence::default();
    let effects = FakeEffects::with_presence(vault.path.clone(), &presence);

    unlock_vault_in_state(
        &state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    )
    .expect("unlocked");
    let first_epoch = state.session_epoch();
    assert!(presence.require(first_epoch).is_ok());

    lock_and_notify(&state, &effects).expect("locked");
    assert_eq!(
        presence.require(first_epoch),
        Err(PRESENCE_REQUIRED.to_string())
    );

    unlock_vault_in_state(
        &state,
        &presence,
        &effects,
        Zeroizing::new(MASTER_PASSWORD.to_string()),
    )
    .expect("unlocked again");

    assert_eq!(state.session_epoch(), first_epoch + 2);
    assert_eq!(
        presence.require(first_epoch),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(presence.require(state.session_epoch()).is_ok());
}

fn record_view_vault() -> TestVault {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    vault.seed(|payload| {
        let mut card = Card::default();
        card.id = "fictional-card".to_string();
        card.title = "Fictional card".to_string();
        card.number = format!("{CANARY}-number");
        card.security_code = format!("{CANARY}-code");
        payload.cards.push(card);
        let mut network = WifiNetwork::default();
        network.id = "fictional-wifi".to_string();
        network.title = "Fictional network".to_string();
        network.password = format!("{CANARY}-wifi");
        payload.wifi_networks.push(network);
    });
    vault
}

fn card_of(item: &TaggedItem) -> Option<&Card> {
    match item {
        TaggedItem::Card(card) => Some(card),
        _ => None,
    }
}

fn wifi_of(item: &TaggedItem) -> Option<&WifiNetwork> {
    match item {
        TaggedItem::WifiNetwork(network) => Some(network),
        _ => None,
    }
}

#[test]
fn a_redacted_view_names_the_secrets_and_carries_none() {
    let mut card = Card::default();
    card.number = format!("{CANARY}-number");
    card.security_code = format!("{CANARY}-code");
    card.title = "Fictional card".to_string();
    let view = redacted_view(card);
    let json = serde_json::to_string(&view).expect("serialized view");

    assert!(!json.contains(CANARY));
    assert!(json.contains("\"secretFields\":[\"number\",\"securityCode\"]"));
    assert!(json.contains("Fictional card"));
}

#[test]
fn the_snapshot_and_login_views_need_an_unlocked_vault() {
    let state = VaultState::default();

    assert_eq!(
        vault_snapshot_in_state(&state).err(),
        Some("Unlock your vault first.".to_string())
    );
    assert_eq!(
        login_card_in_state(&state, "fictional-login").err(),
        Some("Unlock your vault first.".to_string())
    );
    assert_eq!(
        login_summary_in_state(&state, "fictional-login").err(),
        Some("Unlock your vault first.".to_string())
    );
}

#[test]
fn the_snapshot_and_login_views_read_the_unlocked_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");

    let snapshot = vault_snapshot_in_state(&vault.state).expect("snapshot");
    let card = login_card_in_state(&vault.state, "fictional-login").expect("card");
    let summary = login_summary_in_state(&vault.state, "fictional-login").expect("summary");

    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].id, "fictional-login");
    assert_eq!(card.id, "fictional-login");
    assert!(card.has_password);
    assert_eq!(summary.id, "fictional-login");
    assert_eq!(summary.username, "fictional-user");
}

#[test]
fn record_views_need_an_unlocked_vault() {
    let state = VaultState::default();

    assert_eq!(
        record_view_in_state(&state, "fictional-card", "card", card_of).err(),
        Some("Unlock your vault first.".to_string())
    );
}

#[test]
fn a_record_view_redacts_each_kinds_secret_slots() {
    let vault = record_view_vault();

    let card =
        record_view_in_state(&vault.state, "fictional-card", "card", card_of).expect("card view");
    let card_json = serde_json::to_string(&card).expect("serialized card view");
    assert!(!card_json.contains(CANARY));
    assert!(card_json.contains("\"secretFields\":[\"number\",\"securityCode\"]"));
    assert!(card_json.contains("Fictional card"));

    let network = record_view_in_state(&vault.state, "fictional-wifi", "network", wifi_of)
        .expect("network view");
    let network_json = serde_json::to_string(&network).expect("serialized network view");
    assert!(!network_json.contains(CANARY));
    assert!(network_json.contains("\"secretFields\":[\"password\"]"));
    assert!(network_json.contains("Fictional network"));
}

#[test]
fn a_record_view_for_another_kind_reports_that_it_no_longer_exists() {
    let vault = record_view_vault();

    assert_eq!(
        record_view_in_state(&vault.state, "fictional-card", "network", wifi_of).err(),
        Some("That saved network no longer exists.".to_string())
    );
}

#[test]
fn copying_a_field_without_presence_never_reaches_the_clipboard() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    let effects = FakeEffects::new(PathBuf::new());

    assert_eq!(
        copy_item_field_in_state(
            &vault.state,
            &presence,
            &effects,
            "fictional-login",
            "login",
            "password",
            Some(30_000),
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert!(effects.calls().is_empty());
}

#[test]
fn copying_a_field_passes_the_exact_secret_and_returns_the_effect_epoch() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);

    let epoch = copy_item_field_in_state(
        &vault.state,
        &presence,
        &effects,
        "fictional-login",
        "login",
        "password",
        Some(30_000),
    )
    .expect("copied");

    assert_eq!(epoch, COPY_EPOCH);
    assert_eq!(
        effects.calls(),
        vec![Effect::CopySecret {
            value: "fictional-stored-secret".to_string(),
            clear_after_ms: Some(30_000),
        }]
    );
}

#[test]
fn copying_after_a_lock_fails_and_never_reaches_the_clipboard() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    grant(&vault, &presence);
    let effects = FakeEffects::with_presence(PathBuf::new(), &presence);
    lock_and_notify(&vault.state, &effects).expect("locked");
    let calls_after_lock = effects.calls().len();

    assert_eq!(
        copy_item_field_in_state(
            &vault.state,
            &presence,
            &effects,
            "fictional-login",
            "login",
            "password",
            None,
        ),
        Err(PRESENCE_REQUIRED.to_string())
    );
    assert_eq!(effects.calls().len(), calls_after_lock);
}

#[test]
fn an_emit_failure_returns_the_existing_error_and_still_clears_the_session() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let presence = ReleasePresence::default();
    let effects = FakeEffects::failing_emit(PathBuf::new());

    assert_eq!(
        lock_and_notify(&vault.state, &effects),
        Err(EMIT_ERROR.to_string())
    );
    assert!(vault.state.session.lock().expect("session lock").is_none());
    assert!(presence.require(vault.state.session_epoch()).is_err());
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ObserveLock {
                session_present: true
            },
            Effect::ClearArmedClipboard,
            Effect::RevokePresence,
            Effect::ForgetTerminalAllowances,
            Effect::CancelBreachScan,
            Effect::EmitVaultLocked,
        ]
    );
}
