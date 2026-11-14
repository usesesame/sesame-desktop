use std::path::PathBuf;
use std::time::Instant;

use serde_json::json;

use crate::adapters::network::test_server::{Reply, TestServer};
use crate::application::sync::{
    clean_label, connection_ended_state, coordinator_view, create_vault_in_state,
    device_is_removed, disable_needs_leave, local_payload_bytes, local_status_in_state,
    needs_new_key, prepare_key_change_in_state, refuse_self_removal, reset_vault_in_state,
    sync_status_in_state, upgrade_device_key_in_state, verify_master_password, SyncStore,
    KEY_CHANGE_PENDING,
};
use crate::application::sync_pairing::{
    cancel_pairing, cancelled, clean_join_label, pairing_code, reset_cancellation, take_shown_code,
    verify_master_password_now_in_state,
};
use crate::application::sync_recovery::{
    list_conflict_backups_in_state, restore_conflict_backup_in_state,
};
use crate::application::tests::{Effect, FakeEffects};
use crate::commands::test_support::{block_on, pairing_state_guard, TestVault};
use crate::sync::client::SyncClient;
use crate::sync::conflict_backup::{self, Side};
use crate::sync::identity::DeviceIdentity;
use crate::sync::key_change::PreparedKeyChange;
use crate::sync::pairing::ApproverIdentity;
use crate::sync::state::SyncState;
use crate::vault::{random_id, ServiceConnectionFile, SERVICE_CONNECTION_FORMAT_VERSION};

const PASSWORD: &str = "fictional master password";
const WRONG_PASSWORD: &str = "fictional wrong password";
const VAULT: &str = "fictionalVault00000001";
const DEVICE: &str = "fictionalDevice00001";

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sesame-sync-application-{}", random_id()));
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self { path }
    }

    fn store(&self) -> SyncStore {
        SyncStore::new(self.path.clone())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn locked_vault() -> TestVault {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    *vault.state.session.lock().expect("session lock") = None;
    vault
}

fn saved_state(store: &SyncStore) -> SyncState {
    store
        .load_state()
        .expect("stored state")
        .expect("a stored state")
}

fn state_json(epoch: u64, revision: u64, device_state: &str, activated: u64) -> serde_json::Value {
    json!({
        "vaultId": VAULT,
        "vaultEpoch": epoch,
        "currentRevision": revision,
        "deviceState": device_state,
        "activatedEpoch": activated,
    })
}

#[test]
fn a_locked_vault_reports_its_synced_state_without_reading_the_payload() {
    let vault = locked_vault();
    let scratch = Scratch::new();
    let store = scratch.store();
    let state = SyncState::new(VAULT, DEVICE);
    store.save_state(&state).expect("saved state");

    let view = local_status_in_state(&vault.state, &store).expect("local status");

    assert_eq!(view.state, "approved");
    assert_eq!(view.revision, 0);
    assert!(!view.unsynced);
}

#[test]
fn unsynced_changes_are_reported_only_while_the_vault_is_unlocked() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let mut state = SyncState::new(VAULT, DEVICE);
    let (digest_source, _) = {
        let session = vault.state.session.lock().expect("session lock");
        local_payload_bytes(session.as_ref().expect("unlocked")).expect("payload")
    };
    state.payload_digest = crate::sync::state::payload_digest(&digest_source);
    store.save_state(&state).expect("saved state");

    assert!(
        !local_status_in_state(&vault.state, &store)
            .expect("local status")
            .unsynced
    );

    vault.seed(|payload| payload.vault_name = "Fictional vault edited here".into());
    assert!(
        local_status_in_state(&vault.state, &store)
            .expect("local status")
            .unsynced
    );

    *vault.state.session.lock().expect("session lock") = None;
    assert!(
        !local_status_in_state(&vault.state, &store)
            .expect("local status")
            .unsynced
    );
}

#[test]
fn a_pending_join_is_accepted_for_joining_but_never_for_syncing() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let mut state = SyncState::new(VAULT, DEVICE);
    state.pending_join = Some(ApproverIdentity {
        device_id: "fictionalApprover0001".into(),
        signing_key: "fictional-signing-key".into(),
        vault_id: VAULT.into(),
        head_digest: "fictional-head-digest".into(),
    });
    store.save_state(&state).expect("saved state");

    assert_eq!(
        store
            .load_state()
            .map(|_| ())
            .expect_err("a pending join is not a completed sync state"),
        "Finish joining this vault before syncing. Open Sync and try Join again."
    );
    assert_eq!(store.load_join_state().expect("join state"), Some(state));
}

#[test]
fn the_removed_and_needs_new_key_rules_match_the_reported_device_state() {
    assert!(!needs_new_key("approved", 2, 2, false));
    assert!(needs_new_key("approved", 1, 2, false));
    assert!(needs_new_key("approved", 2, 2, true));
    assert!(!needs_new_key("removed", 1, 2, true));

    assert!(device_is_removed(false, "approved"));
    assert!(device_is_removed(true, "removed"));
    assert!(!device_is_removed(true, "approved"));
}

#[test]
fn the_force_flag_is_the_only_way_to_forget_without_leaving() {
    assert!(disable_needs_leave(true, false));
    assert!(!disable_needs_leave(true, true));
    assert!(!disable_needs_leave(false, false));
    assert!(!disable_needs_leave(false, true));
}

#[test]
fn a_device_cannot_remove_itself_through_the_remove_path() {
    assert_eq!(
        refuse_self_removal("fictionalDevice00001", "fictionalDevice00001"),
        Err("Turn Sesame Sync off on this device instead of removing it.".to_string())
    );
    assert!(refuse_self_removal("fictionalOtherDevice01", "fictionalDevice00001").is_ok());
}

#[test]
fn a_locked_vault_cannot_prepare_a_key_change() {
    let vault = locked_vault();
    let scratch = Scratch::new();
    let store = scratch.store();
    store
        .save_state(&SyncState::new(VAULT, DEVICE))
        .expect("saved state");
    let prepared = PreparedKeyChange::default();

    assert_eq!(
        prepare_key_change_in_state(&vault.state, &store, &prepared, PASSWORD)
            .map(|_| ())
            .expect_err("a locked vault cannot start a key change"),
        "Unlock Sesame before changing the vault key."
    );
    assert!(!prepared.is_staged());
}

#[test]
fn a_wrong_password_or_missing_state_never_stages_a_new_vault_key() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let prepared = PreparedKeyChange::default();

    assert_eq!(
        prepare_key_change_in_state(&vault.state, &store, &prepared, PASSWORD)
            .map(|_| ())
            .expect_err("a device without sync state cannot start a key change"),
        "Set up Sesame Sync on this device first."
    );
    assert!(!prepared.is_staged());

    store
        .save_state(&SyncState::new(VAULT, DEVICE))
        .expect("saved state");
    assert_eq!(
        prepare_key_change_in_state(&vault.state, &store, &prepared, WRONG_PASSWORD)
            .map(|_| ())
            .expect_err("a wrong master password cannot start a key change"),
        "That master password is not correct."
    );
    assert!(!prepared.is_staged());
    assert_eq!(saved_state(&store), SyncState::new(VAULT, DEVICE));
}

#[test]
fn a_pending_key_change_stops_preparation_and_upgrading() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    store
        .save_state(&SyncState::new(VAULT, DEVICE))
        .expect("saved state");
    std::fs::write(store.journal_path(), b"fictional pending journal").expect("journal");

    let prepared = PreparedKeyChange::default();
    assert_eq!(
        prepare_key_change_in_state(&vault.state, &store, &prepared, PASSWORD)
            .map(|_| ())
            .expect_err("a pending key change stops preparation"),
        KEY_CHANGE_PENDING
    );
    assert!(!prepared.is_staged());

    let client = SyncClient::for_tests("http://127.0.0.1:1", "fictional-token", "unused");
    assert_eq!(
        block_on(upgrade_device_key_in_state(&store, &client))
            .expect_err("a pending key change stops an upgrade"),
        KEY_CHANGE_PENDING
    );
    assert_eq!(saved_state(&store), SyncState::new(VAULT, DEVICE));
}

#[test]
fn a_correct_password_stages_one_new_key_without_touching_the_saved_state() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    store
        .save_state(&SyncState::new(VAULT, DEVICE))
        .expect("saved state");
    let prepared = PreparedKeyChange::default();
    let before = saved_state(&store);

    let result =
        prepare_key_change_in_state(&vault.state, &store, &prepared, PASSWORD).expect("prepared");

    assert!(prepared.is_staged());
    assert!(!result.recovery_kit.is_empty());
    let (key, _) = prepared.take(Instant::now()).expect("the staged key");
    assert_ne!(key, [0u8; 32]);
    assert_eq!(saved_state(&store), before);
}

#[test]
fn a_wrong_password_is_refused_before_a_rekey_or_join_can_start() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let session = vault.state.session.lock().expect("session lock");
    let unlocked = session.as_ref().expect("unlocked");
    assert_eq!(
        verify_master_password(unlocked, WRONG_PASSWORD),
        Err("That master password is not correct.".to_string())
    );
    assert!(verify_master_password(unlocked, PASSWORD).is_ok());
}

#[test]
fn already_enrolled_devices_never_contact_the_service_to_create_another_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    store
        .save_state(&SyncState::new(VAULT, DEVICE))
        .expect("saved state");
    let before = saved_state(&store);
    let client = SyncClient::for_tests("http://127.0.0.1:1", "fictional-token", "unused");

    assert_eq!(
        block_on(create_vault_in_state(
            &vault.state,
            &store,
            &client,
            "Fictional laptop"
        ))
        .map(|_| ())
        .expect_err("an enrolled device cannot create a vault"),
        "Sesame Sync is already set up on this device."
    );
    assert_eq!(saved_state(&store), before);
}

#[test]
fn a_locked_vault_does_not_create_a_synced_vault_and_leaves_the_service_untouched() {
    let vault = locked_vault();
    let scratch = Scratch::new();
    let store = scratch.store();
    let server = TestServer::start(|request| {
        assert_eq!(request.path, "/v1/sync/state");
        Reply::json(404, &json!({"error":{"code":"sync_vault_not_found"}}))
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    assert_eq!(
        block_on(create_vault_in_state(
            &vault.state,
            &store,
            &client,
            "Fictional laptop"
        ))
        .map(|_| ())
        .expect_err("a locked vault cannot create a synced vault"),
        "Unlock Sesame before setting up Sync."
    );
    assert!(store.load_state().expect("state").is_none());
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn a_successful_create_stores_the_first_device_and_reports_the_enrolled_status() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let server = TestServer::start(|request| match request.path.as_str() {
        "/v1/sync/state" => Reply::json(404, &json!({"error":{"code":"sync_vault_not_found"}})),
        "/v1/sync/vault" => Reply::bytes(204, Vec::new()),
        other => panic!("unexpected route {other}"),
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    let view = block_on(create_vault_in_state(
        &vault.state,
        &store,
        &client,
        "Fictional laptop",
    ))
    .expect("created");

    assert!(view.enrolled);
    assert_eq!(view.state, "approved");
    assert_eq!(view.vault_epoch, 1);
    let saved = saved_state(&store);
    assert_eq!(saved.entries.len(), 1);
    assert_eq!(saved.activated_epoch, 1);
    assert_eq!(
        saved.device_id,
        store.this_identity().expect("identity").device_id
    );
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|request| request.path == "/v1/sync/vault")
            .count(),
        1
    );
}

#[test]
fn reset_removes_only_the_local_sync_state_after_the_service_accepts() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let identity = DeviceIdentity::generate().expect("identity");
    identity
        .save(&store.identity_path())
        .expect("saved identity");
    store
        .save_state(&SyncState::new(VAULT, DEVICE))
        .expect("saved state");
    let server = TestServer::start(|request| match request.path.as_str() {
        "/v1/sync/state" => Reply::json(200, &state_json(1, 0, "approved", 1)),
        "/v1/sync/reset" => Reply::bytes(204, Vec::new()),
        other => panic!("unexpected route {other}"),
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    block_on(reset_vault_in_state(&store, &client)).expect("reset");

    assert!(store.load_state().expect("state").is_none());
    assert!(store.identity_present());
}

#[test]
fn a_refused_reset_leaves_the_stored_sync_state_unchanged() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let identity = DeviceIdentity::generate().expect("identity");
    identity
        .save(&store.identity_path())
        .expect("saved identity");
    let before = SyncState::new(VAULT, DEVICE);
    store.save_state(&before).expect("saved state");
    let server = TestServer::start(|request| match request.path.as_str() {
        "/v1/sync/state" => Reply::json(200, &state_json(1, 0, "approved", 1)),
        "/v1/sync/reset" => Reply::json(500, &json!({"error":{"code":"sync_failed"}})),
        other => panic!("unexpected route {other}"),
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    assert!(block_on(reset_vault_in_state(&store, &client)).is_err());
    assert_eq!(saved_state(&store), before);
}

fn write_backup(vault: &TestVault, store: &SyncStore, revision: u64) -> String {
    let session = vault.state.session.lock().expect("session lock");
    let unlocked = session.as_ref().expect("unlocked");
    let mut payload = unlocked.open_payload().expect("payload").clone();
    payload.vault_name = "Fictional vault from a recovery copy".into();
    payload.revision = revision;
    let bytes = serde_json::to_vec(&payload).expect("payload bytes");
    let written = conflict_backup::write_verified(
        &store.backup_dir(),
        unlocked,
        Side::ThisDevice,
        i64::try_from(revision).expect("revision"),
        &bytes,
        "1700000000",
    )
    .expect("written backup");
    written
        .file_name()
        .expect("file name")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn a_locked_vault_cannot_list_or_restore_recovery_copies() {
    let vault = locked_vault();
    let scratch = Scratch::new();
    let store = scratch.store();
    store
        .save_state(&SyncState::new(VAULT, DEVICE))
        .expect("saved state");
    let before = saved_state(&store);
    let effects = FakeEffects::new(PathBuf::new());

    assert_eq!(
        list_conflict_backups_in_state(&vault.state, &store)
            .expect_err("a locked vault cannot list copies"),
        "Unlock Sesame to see your recovery copies."
    );
    assert_eq!(
        restore_conflict_backup_in_state(
            &vault.state,
            &store,
            &effects,
            "1700000000-this-device-1-x.sesame"
        )
        .map(|_| ())
        .expect_err("a locked vault cannot restore a copy"),
        "Unlock Sesame before restoring a recovery copy."
    );
    assert_eq!(saved_state(&store), before);
    assert!(effects.calls().is_empty());
}

#[test]
fn an_unsafe_recovery_copy_name_is_refused_before_any_file_is_read() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    store
        .save_state(&SyncState::new(VAULT, DEVICE))
        .expect("saved state");
    let before = saved_state(&store);
    let effects = FakeEffects::new(PathBuf::new());

    for name in [
        "",
        "../outside.sesame",
        "folder/inside.sesame",
        "folder\\inside.sesame",
        "drive:inside.sesame",
        "..hidden.sesame",
        "missing.txt",
    ] {
        assert_eq!(
            restore_conflict_backup_in_state(&vault.state, &store, &effects, name)
                .map(|_| ())
                .expect_err(name),
            "That recovery copy could not be found.",
            "{name}"
        );
    }
    assert_eq!(saved_state(&store), before);
    assert!(effects.calls().is_empty());
}

#[test]
fn a_verified_recovery_copy_is_written_back_and_invalidates_the_sync_digest() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let mut synced = SyncState::new(VAULT, DEVICE);
    synced.payload_digest = "fictional-digest".into();
    store.save_state(&synced).expect("saved state");
    let name = write_backup(&vault, &store, 42);
    let epoch = vault.state.session_epoch();
    let effects = FakeEffects::new(PathBuf::new());

    let result =
        restore_conflict_backup_in_state(&vault.state, &store, &effects, &name).expect("restored");

    assert_eq!(result.revision, 42);
    assert_eq!(result.vault_epoch, 0);
    assert_eq!(result.entry_count, 1);
    let session = vault.state.session.lock().expect("session lock");
    let payload = session
        .as_ref()
        .expect("unlocked")
        .open_payload()
        .expect("payload");
    assert_eq!(payload.vault_name, "Fictional vault from a recovery copy");
    assert!(
        payload.revision > 42,
        "the restored payload keeps its own revision bump"
    );
    drop(session);
    assert_eq!(vault.state.session_epoch(), epoch + 1);
    assert_eq!(saved_state(&store).payload_digest, "");
    assert_eq!(effects.calls(), vec![Effect::CancelPendingApprovals]);
    let listed = list_conflict_backups_in_state(&vault.state, &store).expect("listed");
    assert_eq!(listed.len(), 2, "the previous vault is kept as a copy");
}

#[test]
fn a_damaged_recovery_copy_leaves_the_vault_and_the_sync_state_untouched() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let mut synced = SyncState::new(VAULT, DEVICE);
    synced.payload_digest = "fictional-digest".into();
    store.save_state(&synced).expect("saved state");
    let directory = store.backup_dir();
    std::fs::create_dir_all(&directory).expect("backup directory");
    std::fs::write(
        directory.join("1700000000-this-device-7-damaged.sesame"),
        b"damaged",
    )
    .expect("damaged copy");
    let before = saved_state(&store);
    let session = vault.state.session.lock().expect("session lock");
    let before_payload = session
        .as_ref()
        .expect("unlocked")
        .open_payload()
        .expect("payload")
        .clone();
    drop(session);
    let effects = FakeEffects::new(PathBuf::new());

    assert!(restore_conflict_backup_in_state(
        &vault.state,
        &store,
        &effects,
        "1700000000-this-device-7-damaged.sesame"
    )
    .is_err());
    assert_eq!(saved_state(&store), before);
    let session = vault.state.session.lock().expect("session lock");
    let payload = session
        .as_ref()
        .expect("unlocked")
        .open_payload()
        .expect("payload");
    assert_eq!(payload.vault_name, before_payload.vault_name);
    assert_eq!(payload.revision, before_payload.revision);
    assert!(effects.calls().is_empty());
}

#[test]
fn the_listing_skips_copies_this_key_cannot_open() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let name = write_backup(&vault, &store, 9);
    std::fs::write(
        store
            .backup_dir()
            .join("1700000001-this-device-8-foreign.sesame"),
        b"foreign",
    )
    .expect("foreign copy");

    let listed = list_conflict_backups_in_state(&vault.state, &store).expect("listed");

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, name);
    assert_eq!(listed[0].side, "this-device");
    assert_eq!(listed[0].revision, 9);
    assert_eq!(listed[0].entry_count, 1);
    assert_eq!(listed[0].created_at, "1700000000");
}

#[test]
fn a_shown_pairing_code_is_kept_until_it_is_cancelled_or_replaced() {
    let _pairing = pairing_state_guard();
    let first = pairing_code().expect("a code");
    assert_eq!(first.expires_in_seconds, 600);
    assert_eq!(take_shown_code().expect("shown"), first.code);
    let second = pairing_code().expect("a replacement");
    assert_eq!(take_shown_code().expect("shown"), second.code);

    let third = pairing_code().expect("a code before cancel");
    assert_eq!(take_shown_code().expect("shown"), third.code);

    cancel_pairing().expect("cancelled");
    let gone = take_shown_code().expect_err("a cancelled code is gone");
    let refused = cancelled();
    reset_cancellation();

    assert_eq!(gone, "Show a pairing code on this device first.");
    assert_eq!(refused, Err("Pairing was cancelled.".to_string()));
    let fourth = pairing_code().expect("a new code after cancel");
    assert!(cancelled().is_ok());
    assert_eq!(take_shown_code().expect("shown"), fourth.code);
}

#[test]
fn an_eventually_expired_service_connection_is_reported_as_expired_or_revoked() {
    let mut connection = ServiceConnectionFile {
        format_version: SERVICE_CONNECTION_FORMAT_VERSION,
        api_base_url: "https://api.example.test".into(),
        protected_token: "x".into(),
        device_id: "d".into(),
        device_name: "n".into(),
        expires_at: Some(1_000),
        custom_server: None,
    };
    assert_eq!(connection_ended_state(&connection, 1_000), "expired");
    assert_eq!(connection_ended_state(&connection, 2_000), "expired");
    assert_eq!(connection_ended_state(&connection, 999), "revoked");
    connection.expires_at = None;
    assert_eq!(
        connection_ended_state(&connection, 5_000_000_000),
        "revoked"
    );
}

#[test]
fn a_second_service_connection_is_refused_before_pairing_starts() {
    assert_eq!(
        crate::application::sync::require_no_service_connection(true)
            .expect_err("a connected desktop cannot pair again"),
        "This desktop is already connected. Disconnect it before pairing with another server."
    );
    assert!(crate::application::sync::require_no_service_connection(false).is_ok());
}

#[test]
fn a_device_label_is_trimmed_and_bounded() {
    assert_eq!(
        clean_label("  Fictional laptop  ").expect("trimmed"),
        "Fictional laptop"
    );
    assert_eq!(
        clean_label("   ").expect_err("an empty label is refused"),
        "Give this device a name of 1 to 64 characters."
    );
    let longest = "x".repeat(crate::sync::engine::MAX_LABEL_CHARS);
    assert!(clean_label(&longest).is_ok());
    assert!(clean_label(&format!("{longest}x")).is_err());

    assert_eq!(
        clean_join_label("  Fictional phone  ").expect("trimmed"),
        "Fictional phone"
    );
    assert_eq!(
        clean_join_label("").expect_err("an empty label is refused"),
        "Give this device a short name."
    );
    assert!(clean_join_label(&"x".repeat(crate::sync::pairing::MAX_FIELD_BYTES + 1)).is_err());
}

#[test]
fn a_locked_vault_cannot_join_and_never_checks_the_password() {
    let vault = locked_vault();
    assert_eq!(
        verify_master_password_now_in_state(&vault.state, PASSWORD)
            .expect_err("a locked vault cannot join"),
        "Unlock Sesame before joining a synced vault."
    );
}

#[test]
fn the_coordinator_view_reports_the_halt_without_the_service() {
    use crate::sync::coordinator::{Halt, Phase, Status};

    let status = Status {
        phase: Phase::Halted(Halt::Conflict { server_revision: 7 }),
        pending: true,
        last_success_revision: None,
        consecutive_failures: 3,
        downloads_applied: 2,
    };
    let view = coordinator_view(&status);

    assert_eq!(view.phase, "halted");
    assert_eq!(view.halt, "conflict");
    assert_eq!(view.conflict_revision, 7);
    assert!(view.pending);
    assert_eq!(view.last_success_revision, 0);
    assert_eq!(view.consecutive_failures, 3);
    assert_eq!(view.downloads_applied, 2);
}

#[test]
fn a_reset_service_vault_is_reported_without_touching_the_local_vault() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let local = SyncState::new(VAULT, DEVICE);
    store.save_state(&local).expect("saved state");
    let server = TestServer::start(|request| {
        assert_eq!(request.path, "/v1/sync/state");
        Reply::json(404, &json!({"error":{"code":"sync_vault_not_found"}}))
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    let view = block_on(sync_status_in_state(
        &vault.state,
        &store,
        Some(local.clone()),
        true,
        &client,
    ))
    .expect("status");

    assert_eq!(view.state, "no_vault");
    assert!(view.enrolled);
    assert_eq!(
        view.alarm.as_deref(),
        Some(
            "The service no longer has this vault. It was reset and your local vault is untouched."
        )
    );
    assert_eq!(saved_state(&store), local);
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn a_pending_join_is_reported_as_joining_before_history_is_read() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let mut local = SyncState::new(VAULT, DEVICE);
    local.pending_join = Some(ApproverIdentity {
        device_id: "fictionalApprover0001".into(),
        signing_key: "fictional-signing-key".into(),
        vault_id: VAULT.into(),
        head_digest: "fictional-head-digest".into(),
    });
    store.save_state(&local).expect("saved state");
    let server = TestServer::start(|request| {
        assert_eq!(request.path, "/v1/sync/state");
        Reply::json(200, &state_json(4, 0, "approved", 4))
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    let view = block_on(sync_status_in_state(
        &vault.state,
        &store,
        Some(local),
        true,
        &client,
    ))
    .expect("status");

    assert_eq!(view.state, "joining");
    assert!(!view.enrolled);
    assert_eq!(view.vault_epoch, 4);
    assert_eq!(server.requests().len(), 1);
}
