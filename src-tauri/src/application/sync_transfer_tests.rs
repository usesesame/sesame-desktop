use std::path::PathBuf;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use crate::adapters::network::test_server::{Recorded, Reply, TestServer};
use crate::application::sync::prepare_recovery;
use crate::application::sync::{local_payload_bytes, present, SyncStore};
use crate::application::sync_adopt::{adopt_with, digest_after_commit, finish_adoption_in_state};
use crate::application::sync_transfer::{
    apply_remote_payload, classify_transfer_failure, confirm_unchanged, download_vault_in_state,
    every_member_has_the_newer_key, leave_vault_in_state, reconcile_key_change,
    reconcile_pending_upload_in_state, refused_before_commit, resolve_conflict_in_state,
    survivor_packages, take_new_key_in_state, upload_vault_in_state, KeyChange,
};
use crate::application::tests::{Effect, FakeEffects};
use crate::commands::test_support::{block_on, TestVault};
use crate::sync::client::{SyncClient, SyncError};
use crate::sync::devicelist::{DeviceList, DeviceListEntry};
use crate::sync::engine::{
    add_entry, build_header, create_entry, key_entry, plan_header, remove_entry, rotate_entry,
    seal_label, NewDevice,
};
use crate::sync::header::Header;
use crate::sync::identity::DeviceIdentity;
use crate::sync::key_change::fictional_recovery;
use crate::sync::rekey_journal::{self, Journal};
use crate::sync::request::{KeyPackageV3, Receipt};
use crate::sync::state::{payload_digest, PendingUpload, SyncState};
use crate::vault::crypto::decrypt_bytes;
use crate::vault::{random_id, UnlockedVault, RECOVERY_WRAP_AAD};
use sesame_core::api::create_vault;

const PASSWORD: &str = "fictional master password";
const VAULT: &str = "vaultAAAAAAAAAAAA01";
const DEVICE: &str = "fictionalDevice00001";
const ACCEPTED_AT: &str = "2026-01-01T00:00:00Z";
const ACCEPTED_UNIX: u64 = 1_767_225_600;
const WRONG_PASSWORD: &str = "fictional wrong password";

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("sesame-transfer-{}", random_id()));
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

fn vault_id_of_test_vault(vault: &TestVault) -> String {
    let session = vault.state.session.lock().expect("session lock");
    session
        .as_ref()
        .expect("unlocked")
        .open_payload()
        .expect("payload")
        .vault_id
        .clone()
        .expect("vault id")
}

fn state_json(
    vault_id: &str,
    epoch: u64,
    revision: u64,
    device_state: &str,
    activated: u64,
) -> Value {
    json!({
        "vaultId": vault_id,
        "vaultEpoch": epoch,
        "currentRevision": revision,
        "deviceState": device_state,
        "activatedEpoch": activated,
    })
}

fn labels(vault_id: &str, devices: &[&DeviceIdentity]) -> Vec<DeviceListEntry> {
    labels_sealed_with(&[9u8; 32], vault_id, devices)
}

fn labels_sealed_with(
    label_key: &[u8; 32],
    vault_id: &str,
    devices: &[&DeviceIdentity],
) -> Vec<DeviceListEntry> {
    let mut entries = vec![create_entry(
        devices[0],
        vault_id,
        &seal_label(
            label_key,
            vault_id,
            &devices[0].device_id,
            "Fictional laptop",
        )
        .expect("label"),
    )];
    let mut list = DeviceList::verify(&entries).expect("list");
    for device in &devices[1..] {
        let entry = add_entry(
            devices[0],
            &list,
            &NewDevice {
                device_id: &device.device_id,
                signing_key: &URL_SAFE_NO_PAD.encode(device.signing_public_key()),
                package_key: &URL_SAFE_NO_PAD.encode(device.package_public_key()),
            },
            &seal_label(label_key, vault_id, &device.device_id, "Fictional desktop")
                .expect("label"),
            0,
        )
        .expect("add");
        list.extend(&entry).expect("extend");
        entries.push(entry);
    }
    entries
}

struct ServedRemote {
    header: Header,
    header_json: Value,
    ciphertext: String,
    instance_key: String,
}

fn served_remote(
    identity: &DeviceIdentity,
    list: &DeviceList,
    encryption_key: &[u8; 32],
) -> ServedRemote {
    let plan = plan_header(&identity.device_id, list, None).expect("plan");
    let aad = plan.aad();
    let plaintext = b"fictional payload from another device";
    let blob =
        crate::vault::crypto::encrypt_bytes(encryption_key, plaintext, &aad).expect("encrypted");
    let nonce = URL_SAFE_NO_PAD.decode(&blob.nonce).expect("nonce");
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&blob.ciphertext)
        .expect("ciphertext");
    let header = build_header(identity, &plan, &nonce, &ciphertext);
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let receipt = Receipt {
        vault_id: &header.vault_id,
        revision: header.revision,
        header_digest: &header.digest(),
        vault_epoch: header.vault_epoch,
        accepted_at: ACCEPTED_UNIX,
    };
    let signature = signing.sign(&receipt.signing_payload());
    let mut header_json = serde_json::to_value(&header).expect("header json");
    header_json["digest"] = json!(header.digest());
    header_json["receipt"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    header_json["acceptedAt"] = json!(ACCEPTED_AT);
    ServedRemote {
        header,
        header_json,
        ciphertext: blob.ciphertext,
        instance_key: URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),
    }
}

fn checkpoint_not_found() -> Reply {
    Reply::json(404, &json!({"error":{"code":"sync_not_found"}}))
}

#[test]
fn an_upload_on_a_locked_vault_sends_nothing_and_keeps_the_sync_state() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    *vault.state.session.lock().expect("session lock") = None;
    let scratch = Scratch::new();
    let store = scratch.store();
    let identity = DeviceIdentity::generate().expect("identity");
    identity
        .save(&store.identity_path())
        .expect("saved identity");
    let entries = labels(VAULT, &[&identity]);
    let mut state = SyncState::new(VAULT, &identity.device_id);
    state.entries = entries;
    state.activated_epoch = 1;
    store.save_state(&state).expect("saved state");
    let server = TestServer::start(|request: &Recorded| match request.path.as_str() {
        "/v1/sync/checkpoints" => checkpoint_not_found(),
        "/v1/sync/state" => Reply::json(200, &state_json(VAULT, 1, 0, "approved", 1)),
        path if path.starts_with("/v1/sync/device-list") => {
            Reply::json(200, &json!({"entries": []}))
        }
        other => panic!("unexpected route {other}"),
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    assert_eq!(
        block_on(upload_vault_in_state(&vault.state, &store, &client))
            .expect_err("a locked vault cannot upload"),
        "Unlock Sesame before syncing."
    );
    assert_eq!(store.load_state().expect("state"), Some(state));
    assert!(
        !server
            .paths()
            .iter()
            .any(|path| path == "/v1/sync/snapshots"),
        "a locked vault must send no upload"
    );
}

#[test]
fn a_lost_upload_answer_is_settled_from_the_service_head_instead_of_a_conflict() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let identity = DeviceIdentity::generate().expect("identity");
    identity
        .save(&store.identity_path())
        .expect("saved identity");
    let entries = labels(VAULT, &[&identity]);
    let list = DeviceList::verify(&entries).expect("list");
    let remote = served_remote(&identity, &list, &[42u8; 32]);
    let mut state = SyncState::new(VAULT, &identity.device_id);
    state.entries = entries;
    state.activated_epoch = 1;
    state.pending_upload = Some(PendingUpload {
        header: remote.header.clone(),
        payload_digest: "fictional-digest".into(),
    });
    store.save_state(&state).expect("saved state");
    let server = TestServer::start({
        let header_json = remote.header_json.clone();
        move |request: &Recorded| match request.path.as_str() {
            "/v1/sync/checkpoints" => checkpoint_not_found(),
            "/v1/sync/state" => Reply::json(200, &state_json(VAULT, 1, 1, "approved", 1)),
            path if path.starts_with("/v1/sync/device-list") => {
                Reply::json(200, &json!({"entries": []}))
            }
            path if path.starts_with("/v1/sync/headers") => {
                Reply::json(200, &json!({"headers": [header_json.clone()]}))
            }
            other => panic!("unexpected route {other}"),
        }
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", &remote.instance_key);

    let next = block_on(reconcile_pending_upload_in_state(
        &store,
        &client,
        state.clone(),
    ))
    .expect("the lost answer is settled");

    assert!(next.pending_upload.is_none());
    assert_eq!(next.head, Some(remote.header));
    assert_eq!(next.payload_digest, "fictional-digest");
    assert!(next.receipt.is_some());
    assert_eq!(store.load_state().expect("state"), Some(next));
}

#[test]
fn a_download_whose_payload_does_not_decrypt_leaves_the_vault_file_unchanged() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let vault_id = vault_id_of_test_vault(&vault);
    let scratch = Scratch::new();
    let store = scratch.store();
    let identity = DeviceIdentity::generate().expect("identity");
    identity
        .save(&store.identity_path())
        .expect("saved identity");
    let entries = labels(&vault_id, &[&identity]);
    let list = DeviceList::verify(&entries).expect("list");
    let remote = served_remote(&identity, &list, &[42u8; 32]);
    let mut state = SyncState::new(&vault_id, &identity.device_id);
    state.entries = entries;
    state.activated_epoch = 1;
    let (digest_source, _) = {
        let session = vault.state.session.lock().expect("session lock");
        local_payload_bytes(session.as_ref().expect("unlocked")).expect("payload")
    };
    state.payload_digest = payload_digest(&digest_source);
    store.save_state(&state).expect("saved state");
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let server = TestServer::start({
        let header_json = remote.header_json.clone();
        let ciphertext = remote.ciphertext.clone();
        move |request: &Recorded| match request.path.as_str() {
            "/v1/sync/checkpoints" => checkpoint_not_found(),
            "/v1/sync/state" => Reply::json(200, &state_json(&vault_id, 1, 1, "approved", 1)),
            path if path.starts_with("/v1/sync/device-list") => {
                Reply::json(200, &json!({"entries": []}))
            }
            path if path.starts_with("/v1/sync/headers") => {
                Reply::json(200, &json!({"headers": [header_json.clone()]}))
            }
            "/v1/sync/snapshot" => Reply::json(
                200,
                &json!({
                    "header": header_json.clone(),
                    "acceptedAt": ACCEPTED_AT,
                    "ciphertext": ciphertext.clone(),
                }),
            ),
            other => panic!("unexpected route {other}"),
        }
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", &remote.instance_key);
    let effects = FakeEffects::new(PathBuf::new());

    assert_eq!(
        block_on(download_vault_in_state(
            &vault.state,
            &store,
            &client,
            &effects,
        ))
        .expect_err("the payload must not decrypt"),
        "The vault data could not be authenticated. Restore a known-good encrypted backup."
    );
    assert_eq!(
        std::fs::read(vault.path()).expect("vault bytes"),
        before,
        "a failed decryption must not touch the vault file"
    );
    assert_eq!(store.load_state().expect("state"), Some(state));
    assert!(effects.calls().is_empty());
}

#[test]
fn a_resolution_whose_local_vault_changed_is_refused_and_writes_nothing() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let state = SyncState::new(VAULT, DEVICE);
    store.save_state(&state).expect("saved state");
    let captured = {
        let session = vault.state.session.lock().expect("session lock");
        let unlocked = session.as_ref().expect("unlocked");
        let (bytes, _) = local_payload_bytes(unlocked).expect("payload");
        payload_digest(&bytes)
    };
    vault.seed(|payload| payload.vault_name = "Fictional vault edited after the capture".into());
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let session = vault.state.session.lock().expect("session lock");
    let unlocked = session.as_ref().expect("unlocked");

    assert_eq!(
        confirm_unchanged(unlocked, &captured).expect_err("a changed vault is refused"),
        "This vault changed while you were deciding. Open Sesame Sync and resolve the difference again."
    );
    drop(session);

    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert_eq!(store.load_state().expect("state"), Some(state));
}

#[test]
fn a_take_new_key_resumes_from_an_interrupted_journal() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let vault_id = vault_id_of_test_vault(&vault);
    let scratch = Scratch::new();
    let store = scratch.store();
    let acting = DeviceIdentity::generate().expect("identity");
    let other = DeviceIdentity::generate().expect("identity");
    let entries = labels(&vault_id, &[&acting, &other]);
    let mut committed = DeviceList::verify(&entries[..1]).expect("list");
    committed.extend(&entries[1]).expect("extend");
    let rotation = rotate_entry(&acting, &committed).expect("rotation");
    let mut with_rotation = committed.clone();
    with_rotation.extend(&rotation).expect("extend");
    let mut committed_entries = entries.clone();
    committed_entries.push(rotation.clone());
    let journal_path = store.journal_path();
    Journal::new(
        &rotation,
        committed.head_digest(),
        &[4u8; 32],
        fictional_recovery(),
        1,
    )
    .save(&journal_path)
    .expect("saved journal");
    let mut journal = Journal::load(&journal_path).expect("journal");
    let mut local = SyncState::new(&vault_id, &acting.device_id);
    local.entries = entries;
    local.activated_epoch = 1;
    store.save_state(&local).expect("saved state");
    let refreshed = crate::application::sync::Refreshed {
        server: crate::sync::client::StateView {
            vault_id: vault_id.clone(),
            vault_epoch: rotation.epoch_after,
            current_revision: 0,
            device_state: "approved".into(),
            activated_epoch: 1,
        },
        update: crate::sync::engine::VerifiedUpdate {
            entries: committed_entries,
            list: with_rotation.clone(),
            head: None,
            receipt: None,
        },
        confirmed_at: None,
        peer_checks_skipped: false,
    };
    let effects = FakeEffects::new(PathBuf::new());
    assert!(matches!(
        reconcile_key_change(&journal_path, &with_rotation, 1),
        Ok(KeyChange::Adopt(_))
    ));
    let old_key = {
        let session = vault.state.session.lock().expect("session lock");
        session
            .as_ref()
            .expect("unlocked")
            .expose_vault_key(|key| Ok(*key))
            .expect("key")
    };

    let result = block_on(
        crate::application::sync_transfer::adopt_journal_key_in_state(
            &vault.state,
            &store,
            &effects,
            local.clone(),
            refreshed,
            &mut journal,
            PASSWORD,
        ),
    )
    .expect("the saved key is adopted");

    assert!(result.recovery_kit.is_empty());
    let new_key = {
        let session = vault.state.session.lock().expect("session lock");
        session
            .as_ref()
            .expect("unlocked")
            .expose_vault_key(|key| Ok(*key))
            .expect("key")
    };
    assert_ne!(new_key, old_key);
    assert_eq!(new_key, [4u8; 32]);
    assert!(!rekey_journal::is_pending(&journal_path));
    let saved = store.load_state().expect("state").expect("saved state");
    assert_eq!(saved.activated_epoch, rotation.epoch_after);
    assert_eq!(
        effects.calls(),
        vec![Effect::ClearPinThrottle, Effect::CancelPendingApprovals]
    );
}

#[test]
fn a_device_cannot_remove_itself() {
    let scratch = Scratch::new();
    let store = scratch.store();
    let identity = DeviceIdentity::generate().expect("identity");
    identity
        .save(&store.identity_path())
        .expect("saved identity");
    let server = TestServer::start(|_| panic!("a self removal must not reach the service"));
    let stored = store.this_identity().expect("identity");

    assert_eq!(
        crate::application::sync::refuse_self_removal(&stored.device_id, &identity.device_id)
            .expect_err("a device cannot remove itself"),
        "Turn Sesame Sync off on this device instead of removing it."
    );
    assert!(server.requests().is_empty());
}

#[test]
fn leaving_a_vault_that_the_service_refuses_keeps_the_local_sync_state() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let vault_id = vault_id_of_test_vault(&vault);
    let scratch = Scratch::new();
    let store = scratch.store();
    let acting = DeviceIdentity::generate().expect("identity");
    let other = DeviceIdentity::generate().expect("identity");
    acting.save(&store.identity_path()).expect("saved identity");
    let entries = labels(&vault_id, &[&acting, &other]);
    let mut state = SyncState::new(&vault_id, &acting.device_id);
    state.entries = entries;
    state.activated_epoch = 1;
    store.save_state(&state).expect("saved state");
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let server = TestServer::start(move |request: &Recorded| match request.path.as_str() {
        "/v1/sync/checkpoints" => checkpoint_not_found(),
        "/v1/sync/state" => Reply::json(200, &state_json(&vault_id, 1, 0, "approved", 1)),
        path if path.starts_with("/v1/sync/device-list") => {
            Reply::json(200, &json!({"entries": []}))
        }
        "/v1/sync/devices/remove" => Reply::json(500, &json!({"error":{"code":"sync_failed"}})),
        other => panic!("unexpected route {other}"),
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
    let effects = FakeEffects::new(PathBuf::new());

    assert_eq!(
        block_on(leave_vault_in_state(
            &vault.state,
            &store,
            &effects,
            &client,
            &acting.device_id,
            PASSWORD,
        ))
        .expect_err("the service refused the removal"),
        "Sesame Sync could not complete that request."
    );
    assert_eq!(store.load_state().expect("state"), Some(state));
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert!(!rekey_journal::is_pending(&store.journal_path()));
}

#[test]
fn a_conflict_kind_that_is_not_a_side_writes_nothing() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let state = SyncState::new(VAULT, DEVICE);
    store.save_state(&state).expect("saved state");
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let effects = FakeEffects::new(PathBuf::new());
    let server =
        TestServer::start(|_| panic!("choosing an invalid side must not reach the service"));
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");

    assert_eq!(
        block_on(resolve_conflict_in_state(
            &vault.state,
            &store,
            &effects,
            &client,
            "both".into(),
        ))
        .err()
        .expect("an invalid choice is refused"),
        "Choose which vault to keep."
    );
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert_eq!(store.load_state().expect("state"), Some(state));
    assert!(server.requests().is_empty());
}

#[test]
fn a_locked_vault_cannot_take_a_key() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let vault_id = vault_id_of_test_vault(&vault);
    *vault.state.session.lock().expect("session lock") = None;
    let scratch = Scratch::new();
    let store = scratch.store();
    let identity = DeviceIdentity::generate().expect("identity");
    identity
        .save(&store.identity_path())
        .expect("saved identity");
    let entries = labels(&vault_id, &[&identity]);
    let mut state = SyncState::new(&vault_id, &identity.device_id);
    state.entries = entries;
    state.activated_epoch = 1;
    store.save_state(&state).expect("saved state");
    let server = TestServer::start(move |request: &Recorded| match request.path.as_str() {
        "/v1/sync/checkpoints" => checkpoint_not_found(),
        "/v1/sync/state" => Reply::json(200, &state_json(&vault_id, 2, 0, "approved", 1)),
        path if path.starts_with("/v1/sync/device-list") => {
            Reply::json(200, &json!({"entries": []}))
        }
        other => panic!("unexpected route {other}"),
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
    let effects = FakeEffects::new(PathBuf::new());

    assert!(block_on(take_new_key_in_state(
        &vault.state,
        &store,
        &effects,
        &client,
        PASSWORD.into(),
    ))
    .is_err());
    assert_eq!(store.load_state().expect("state"), Some(state));
    assert!(effects.calls().is_empty());
}

#[test]
fn a_rekey_needs_a_correct_master_password_before_any_service_change() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let scratch = Scratch::new();
    let store = scratch.store();
    let acting = DeviceIdentity::generate().expect("identity");
    let other = DeviceIdentity::generate().expect("identity");
    acting.save(&store.identity_path()).expect("saved identity");
    let entries = labels(VAULT, &[&acting, &other]);
    let mut state = SyncState::new(VAULT, &acting.device_id);
    state.entries = entries;
    state.activated_epoch = 1;
    store.save_state(&state).expect("saved state");
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let server = TestServer::start(|request: &Recorded| match request.path.as_str() {
        "/v1/sync/checkpoints" => checkpoint_not_found(),
        "/v1/sync/state" => Reply::json(200, &state_json(VAULT, 1, 0, "approved", 1)),
        path if path.starts_with("/v1/sync/device-list") => {
            Reply::json(200, &json!({"entries": []}))
        }
        other => panic!("unexpected route {other}"),
    });
    let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
    let effects = FakeEffects::new(PathBuf::new());
    let prepared = crate::sync::key_change::PreparedKeyChange::default();

    assert_eq!(
        block_on(crate::application::sync_transfer::rekey_without_in_state(
            &vault.state,
            &store,
            &effects,
            &client,
            crate::application::sync_transfer::RekeyRequest {
                prepared: &prepared,
                subject: Some(&other.device_id),
                master_password: WRONG_PASSWORD,
                adopt_locally: true,
            },
        ))
        .expect_err("a wrong password is refused"),
        "That master password is not correct."
    );
    assert_eq!(store.load_state().expect("state"), Some(state));
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert!(!rekey_journal::is_pending(&store.journal_path()));
    assert!(effects.calls().is_empty());
    assert!(
        !server
            .paths()
            .iter()
            .any(|path| path == "/v1/sync/devices/remove"),
        "a refused password must not post a removal"
    );
}

#[test]
fn joining_a_synced_vault_keeps_a_copy_and_reports_every_effect_in_order() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let vault_id = vault_id_of_test_vault(&vault);
    let scratch = Scratch::new();
    let store = scratch.store();
    let effects = FakeEffects::new(PathBuf::new());
    let payload = {
        let session = vault.state.session.lock().expect("session lock");
        session
            .as_ref()
            .expect("unlocked")
            .open_payload()
            .expect("payload")
            .clone()
    };
    let epoch = vault.state.session_epoch();

    let kit = finish_adoption_in_state(
        &vault.state,
        &store,
        &effects,
        [5u8; 32],
        payload,
        PASSWORD,
        &vault_id,
    )
    .expect("joined the synced vault");

    assert!(!kit.is_empty());
    assert_eq!(vault.state.session_epoch(), epoch + 1);
    let key = {
        let session = vault.state.session.lock().expect("session lock");
        session
            .as_ref()
            .expect("unlocked")
            .expose_vault_key(|key| Ok(*key))
            .expect("key")
    };
    assert_eq!(key, [5u8; 32]);
    assert_eq!(
        effects.calls(),
        vec![
            Effect::ReportKeyPageFallback,
            Effect::ClearPinThrottle,
            Effect::CancelPendingApprovals,
        ]
    );
    let copies: Vec<PathBuf> = std::fs::read_dir(store.backup_dir())
        .expect("backup directory")
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert_eq!(copies.len(), 1);
    assert_eq!(
        copies[0].extension().and_then(|value| value.to_str()),
        Some("sesame")
    );
}

#[test]
fn joining_a_synced_vault_while_locked_writes_no_copy_and_touches_nothing() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let vault_id = vault_id_of_test_vault(&vault);
    *vault.state.session.lock().expect("session lock") = None;
    let scratch = Scratch::new();
    let store = scratch.store();
    let effects = FakeEffects::new(PathBuf::new());
    let payload = {
        let (opened, _) =
            sesame_core::api::create_vault(WRONG_PASSWORD, "Fictional other vault").expect("vault");
        opened.payload.clone()
    };
    let before = std::fs::read(vault.path()).expect("vault bytes");

    assert_eq!(
        finish_adoption_in_state(
            &vault.state,
            &store,
            &effects,
            [5u8; 32],
            payload,
            PASSWORD,
            &vault_id,
        )
        .expect_err("a locked vault cannot join"),
        "Unlock Sesame before joining a synced vault."
    );
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert!(!store.backup_dir().exists());
    assert!(effects.calls().is_empty());
}

#[cfg(test)]
mod survivor_tests {
    use super::*;

    const VAULT: &str = "vaultAAAAAAAAAAAA01";

    fn identity(hybrid: bool) -> DeviceIdentity {
        let generated = DeviceIdentity::generate().expect("identity");
        if hybrid {
            generated
        } else {
            generated.without_hybrid_key()
        }
    }

    fn mixed_vault(
        creator: &DeviceIdentity,
        joiners: &[&DeviceIdentity],
    ) -> (DeviceList, DeviceListEntry) {
        let label = |device: &DeviceIdentity| {
            seal_label(&[9u8; 32], VAULT, &device.device_id, "Device").expect("label")
        };
        let mut entries = vec![create_entry(creator, VAULT, &label(creator))];
        let mut list = DeviceList::verify(&entries).expect("list");
        for joiner in joiners {
            let entry = add_entry(
                creator,
                &list,
                &NewDevice {
                    device_id: &joiner.device_id,
                    signing_key: &URL_SAFE_NO_PAD.encode(joiner.signing_public_key()),
                    package_key: &URL_SAFE_NO_PAD.encode(joiner.package_public_key()),
                },
                &label(joiner),
                0,
            )
            .expect("add");
            list.extend(&entry).expect("extend");
            entries.push(entry);
        }
        let removal =
            remove_entry(creator, &list, &joiners[joiners.len() - 1].device_id).expect("removal");
        (list, removal)
    }

    fn package_for<'a>(
        packages: &'a [KeyPackageV3],
        device: &DeviceIdentity,
    ) -> Option<&'a KeyPackageV3> {
        packages
            .iter()
            .find(|package| package.recipient_device_id == device.device_id)
    }

    #[test]
    fn a_rekey_seals_the_suite_each_survivor_advertises_and_nothing_to_the_removed_device() {
        let creator = identity(true);
        let older = identity(false);
        let newer = identity(true);
        let removed = identity(true);
        let (list, removal) = mixed_vault(&creator, &[&older, &newer, &removed]);
        let new_key = [4u8; 32];
        let excluded = [removed.device_id.as_str(), creator.device_id.as_str()];

        let packages = survivor_packages(
            &creator,
            &list,
            VAULT,
            &new_key,
            &excluded,
            removal.epoch_after,
            &removal.digest(),
        )
        .expect("packages");

        assert_eq!(packages.len(), 2);
        assert!(package_for(&packages, &removed).is_none());
        assert!(package_for(&packages, &creator).is_none());
        let sealed = |device: &DeviceIdentity| {
            let package = package_for(&packages, device).expect("package");
            assert_eq!(package.sender_device_id, creator.device_id);
            assert_eq!(package.vault_epoch, removal.epoch_after);
            assert_eq!(package.entry_digest, removal.digest());
            assert!(package
                .verify(&URL_SAFE_NO_PAD.encode(creator.signing_public_key()))
                .is_ok());
            URL_SAFE_NO_PAD.decode(&package.ciphertext).expect("bytes")
        };

        let for_older = sealed(&older);
        let for_newer = sealed(&newer);
        assert_eq!(
            for_older.len(),
            crate::sync::keys::X25519_KEY_BYTES
                + crate::sync::keys::KEY_PACKAGE_NONCE_BYTES
                + new_key.len()
                + 16
        );
        assert_eq!(for_newer[0], crate::sync::keys::HYBRID_PACKAGE_VERSION);
        assert!(for_newer.len() > for_older.len());

        assert_eq!(
            older
                .open_key_package(&for_older, VAULT, removal.epoch_after)
                .expect("older opens"),
            new_key
        );
        assert_eq!(
            newer
                .open_key_package(&for_newer, VAULT, removal.epoch_after)
                .expect("newer opens"),
            new_key
        );
        assert!(older
            .open_key_package(&for_newer, VAULT, removal.epoch_after)
            .is_err());
        assert!(newer
            .open_key_package(&for_older, VAULT, removal.epoch_after)
            .is_err());
        assert!(newer
            .open_key_package(&for_newer, VAULT, removal.epoch_after + 1)
            .is_err());
        assert!(newer
            .open_key_package(&for_newer, "vaultBBBBBBBBBBBB02", removal.epoch_after)
            .is_err());
        assert!(removed
            .open_key_package(&for_newer, VAULT, removal.epoch_after)
            .is_err());
    }

    #[test]
    fn a_rekey_to_a_vault_of_older_devices_seals_only_the_older_suite() {
        let creator = identity(false);
        let first = identity(false);
        let removed = identity(false);
        let (list, removal) = mixed_vault(&creator, &[&first, &removed]);
        let packages = survivor_packages(
            &creator,
            &list,
            VAULT,
            &[4u8; 32],
            &[removed.device_id.as_str(), creator.device_id.as_str()],
            removal.epoch_after,
            &removal.digest(),
        )
        .expect("packages");
        assert_eq!(packages.len(), 1);
        let bytes = URL_SAFE_NO_PAD
            .decode(&packages[0].ciphertext)
            .expect("bytes");
        assert!(bytes.len() < 512);
        assert_eq!(
            first
                .open_key_package(&bytes, VAULT, removal.epoch_after)
                .expect("opens"),
            [4u8; 32]
        );
    }
}

#[cfg(test)]
mod key_change_tests {
    use super::*;

    const VAULT: &str = "vaultAAAAAAAAAAAA01";

    fn lists() -> (DeviceListEntry, DeviceList, DeviceList) {
        let creator = DeviceIdentity::generate().expect("identity");
        let other = DeviceIdentity::generate().expect("identity");
        let label = |device: &DeviceIdentity| {
            seal_label(&[9u8; 32], VAULT, &device.device_id, "Device").expect("label")
        };
        let mut base =
            DeviceList::verify(&[create_entry(&creator, VAULT, &label(&creator))]).expect("list");
        let add = add_entry(
            &creator,
            &base,
            &NewDevice {
                device_id: &other.device_id,
                signing_key: &URL_SAFE_NO_PAD.encode(other.signing_public_key()),
                package_key: &URL_SAFE_NO_PAD.encode(other.package_public_key()),
            },
            &label(&other),
            0,
        )
        .expect("add");
        base.extend(&add).expect("extend");
        let removal = remove_entry(&creator, &base, &other.device_id).expect("removal");
        let mut committed = base.clone();
        committed.extend(&removal).expect("extend");
        (removal, base, committed)
    }

    fn path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sesame-keychange-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        rekey_journal::journal_path(&dir)
    }

    #[test]
    fn without_a_journal_nothing_changes() {
        let (_, base, _) = lists();
        let path = path("none");
        assert!(matches!(
            reconcile_key_change(&path, &base, 1),
            Ok(KeyChange::Proceed)
        ));
    }

    #[test]
    fn a_removal_in_the_list_hands_back_the_saved_key_and_keeps_the_journal_until_adoption() {
        let (removal, base, committed) = lists();
        let path = path("adopt");
        Journal::new(
            &removal,
            base.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1,
        )
        .save(&path)
        .expect("saved");
        match reconcile_key_change(&path, &committed, 2) {
            Ok(KeyChange::Adopt(journal)) => assert_eq!(journal.key(), [4u8; 32]),
            _ => panic!("expected the saved key"),
        }
        assert!(rekey_journal::is_pending(&path));
    }

    #[test]
    fn a_removal_that_did_not_commit_drops_the_journal_and_says_nothing_changed() {
        let (removal, base, _) = lists();
        let path = path("not-done");
        Journal::new(
            &removal,
            base.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1,
        )
        .save(&path)
        .expect("saved");
        assert!(matches!(
            reconcile_key_change(&path, &base, 1),
            Ok(KeyChange::NotDone)
        ));
        assert!(!rekey_journal::is_pending(&path));
    }

    #[test]
    fn a_journal_that_matches_nothing_drops_and_leaves_the_normal_path_to_a_device_that_is_behind()
    {
        let (removal, base, _) = lists();
        let path = path("stale");
        Journal::new(
            &removal,
            base.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1,
        )
        .save(&path)
        .expect("saved");
        assert!(matches!(
            reconcile_key_change(&path, &base, 0),
            Ok(KeyChange::Proceed)
        ));
        assert!(!rekey_journal::is_pending(&path));
    }

    #[test]
    fn an_unreadable_journal_is_kept_and_reported() {
        let (_, base, _) = lists();
        let path = path("unreadable");
        std::fs::write(&path, b"damaged").unwrap();
        let error = match reconcile_key_change(&path, &base, 1) {
            Err(error) => error,
            Ok(_) => panic!("a damaged journal was accepted"),
        };
        assert!(error.contains("pair it again"));
        assert!(rekey_journal::is_pending(&path));
    }

    #[test]
    fn only_an_answer_the_service_could_not_have_committed_drops_the_journal() {
        for refused in [
            SyncError::Conflict,
            SyncError::NotApproved,
            SyncError::NotActivated,
            SyncError::NotEntitled,
            SyncError::NotFound,
            SyncError::StorageFull,
        ] {
            assert!(refused_before_commit(&refused), "{refused:?}");
        }
        for unknown in [
            SyncError::Unavailable("offline".into()),
            SyncError::Failed("timed out".into()),
        ] {
            assert!(!refused_before_commit(&unknown), "{unknown:?}");
        }
    }

    #[test]
    fn a_vault_key_change_needs_every_current_device_to_have_the_newer_key() {
        let creator = DeviceIdentity::generate().expect("identity");
        let older = DeviceIdentity::generate()
            .expect("identity")
            .without_hybrid_key();
        let label = |device: &DeviceIdentity| {
            seal_label(&[9u8; 32], VAULT, &device.device_id, "Device").expect("label")
        };
        let mut list =
            DeviceList::verify(&[create_entry(&creator, VAULT, &label(&creator))]).expect("list");
        assert!(every_member_has_the_newer_key(&list));
        let add = add_entry(
            &creator,
            &list,
            &NewDevice {
                device_id: &older.device_id,
                signing_key: &URL_SAFE_NO_PAD.encode(older.signing_public_key()),
                package_key: &URL_SAFE_NO_PAD.encode(older.package_public_key()),
            },
            &label(&older),
            0,
        )
        .expect("add");
        list.extend(&add).expect("extend");
        assert!(!every_member_has_the_newer_key(&list));

        let upgraded = older.with_hybrid_key().expect("hybrid");
        let replacement = key_entry(
            &upgraded,
            &list,
            &URL_SAFE_NO_PAD.encode(upgraded.package_public_key()),
        )
        .expect("replacement");
        list.extend(&replacement).expect("extend");
        assert!(every_member_has_the_newer_key(&list));
    }

    #[test]
    fn a_journal_for_a_rotation_is_adopted_once_the_rotation_is_in_the_list() {
        let creator = DeviceIdentity::generate().expect("identity");
        let label = seal_label(&[9u8; 32], VAULT, &creator.device_id, "Device").expect("label");
        let mut list = DeviceList::verify(&[create_entry(&creator, VAULT, &label)]).expect("list");
        let rotation = rotate_entry(&creator, &list).expect("rotation");
        let path = path("rotation");
        Journal::new(
            &rotation,
            list.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1,
        )
        .save(&path)
        .expect("saved");
        assert!(matches!(
            reconcile_key_change(&path, &list, 1),
            Ok(KeyChange::NotDone)
        ));
        Journal::new(
            &rotation,
            list.head_digest(),
            &[4u8; 32],
            fictional_recovery(),
            1,
        )
        .save(&path)
        .expect("saved");
        list.extend(&rotation).expect("extend");
        assert!(matches!(
            reconcile_key_change(&path, &list, 2),
            Ok(KeyChange::Adopt(_))
        ));
    }
}

#[cfg(test)]
mod applied_digest_tests {
    use super::*;

    const PASSWORD: &str = "fictional master password";

    fn session() -> UnlockedVault {
        let (opened, _) = create_vault(PASSWORD, "Fictional vault").expect("created vault");
        let directory =
            std::env::temp_dir().join(format!("sesame-applied-{}", crate::vault::random_id()));
        std::fs::create_dir_all(&directory).expect("directory");
        UnlockedVault::from_opened(directory.join("vault.sesame"), &opened).expect("unlocked vault")
    }

    fn remote_payload(vault: &UnlockedVault) -> crate::vault::types::VaultPayload {
        let mut payload = vault.open_payload().expect("payload").clone();
        payload.vault_name = "Fictional vault from another device".into();
        payload.revision = 40;
        payload
    }

    fn has_changes(state: &SyncState, vault: &UnlockedVault) -> bool {
        let (plaintext, _) = local_payload_bytes(vault).expect("bytes");
        state.has_local_changes(&plaintext)
    }

    #[test]
    fn a_device_that_just_applied_a_remote_vault_has_no_changes_of_its_own() {
        let mut vault = session();
        let mut state = SyncState::new("fictionalVault00000001", "fictionalDevice001");
        let remote = remote_payload(&vault);

        let (digest, _) = apply_remote_payload(&mut vault, remote).expect("applied");
        state.payload_digest = digest;

        assert!(
            !has_changes(&state, &vault),
            "the stored digest must describe the vault as it is on disk after the commit"
        );
    }

    #[test]
    fn a_local_edit_after_applying_a_remote_vault_is_still_seen() {
        let mut vault = session();
        let mut state = SyncState::new("fictionalVault00000001", "fictionalDevice001");
        let remote = remote_payload(&vault);
        let (digest, _) = apply_remote_payload(&mut vault, remote).expect("applied");
        state.payload_digest = digest;

        let mut edited = vault.open_payload().expect("payload").clone();
        edited.vault_name = "Fictional vault renamed here".into();
        crate::vault::storage::commit_payload_change(&mut vault, edited).expect("edit");

        assert!(has_changes(&state, &vault));
    }

    #[test]
    fn a_prepared_kit_stays_valid_after_adoption_and_no_second_kit_is_made() {
        let mut vault = session();
        let payload = vault.open_payload().expect("payload").clone();
        let key = [7u8; 32];
        let (kit, recovery) = prepare_recovery(&key).expect("prepared");

        let shown = adopt_with(
            &mut vault,
            key,
            payload.clone(),
            PASSWORD,
            Some(recovery.clone()),
        )
        .expect("adopted");
        assert!(shown.is_none());
        assert!(recovery_opens(&vault, &kit, &key));
        assert!(!recovery_opens(
            &vault,
            "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA",
            &key
        ));

        let again =
            adopt_with(&mut vault, key, payload, PASSWORD, Some(recovery)).expect("adopted again");
        assert!(again.is_none());
        assert!(
            recovery_opens(&vault, &kit, &key),
            "adopting twice from the journal keeps the saved kit working"
        );
    }

    fn recovery_opens(vault: &UnlockedVault, kit: &str, key: &[u8; 32]) -> bool {
        let (Some(kdf), Some(wrap)) = (&vault.recovery_kdf, &vault.recovery_wrap) else {
            return false;
        };
        let wrapping = crate::vault::crypto::derive_key(kit, kdf).expect("derived");
        decrypt_bytes(&wrapping, wrap, RECOVERY_WRAP_AAD)
            .is_ok_and(|opened| opened.as_slice() == key.as_slice())
    }

    #[test]
    fn without_a_prepared_kit_adoption_makes_one_that_opens_the_new_key() {
        let mut vault = session();
        let payload = vault.open_payload().expect("payload").clone();
        let key = [9u8; 32];
        let kit = adopt_with(&mut vault, key, payload, PASSWORD, None)
            .expect("adopted")
            .expect("a kit");
        assert!(recovery_opens(&vault, &kit, &key));
    }

    fn bytes_of(vault: &UnlockedVault) -> Vec<u8> {
        serde_json::to_vec(&*vault.open_payload().expect("payload")).expect("bytes")
    }

    fn state_matching(vault: &UnlockedVault) -> SyncState {
        let mut state = SyncState::new("fictionalVault00000001", "device");
        state.payload_digest = payload_digest(&bytes_of(vault));
        state
    }

    #[test]
    fn taking_a_new_key_does_not_make_a_synced_vault_look_edited() {
        let mut vault = session();
        let mut state = state_matching(&vault);
        let kept = crate::application::sync_adopt::digest_kept_through_adoption(
            &state,
            &vault,
            [None, None],
        )
        .expect("digest");
        let payload = vault.open_payload().expect("payload").clone();
        adopt_with(&mut vault, [5u8; 32], payload, PASSWORD, None).expect("adopted");
        state.payload_digest = kept.expect("a clean vault keeps its digest");
        assert!(!state.has_local_changes(&bytes_of(&vault)));
    }

    #[test]
    fn taking_a_new_key_never_hides_an_edit_that_was_not_synced() {
        let mut vault = session();
        let state = state_matching(&vault);
        let mut edited = vault.open_payload().expect("payload").clone();
        edited.vault_name = "Fictional vault edited offline".into();
        crate::vault::storage::commit_payload_change(&mut vault, edited).expect("edit");
        assert!(state.has_local_changes(&bytes_of(&vault)));

        assert_eq!(
            crate::application::sync_adopt::digest_kept_through_adoption(
                &state,
                &vault,
                [None, None],
            )
            .expect("digest"),
            None
        );
        let payload = vault.open_payload().expect("payload").clone();
        adopt_with(&mut vault, [5u8; 32], payload, PASSWORD, None).expect("adopted");
        assert!(state.has_local_changes(&bytes_of(&vault)));
    }

    #[test]
    fn the_digest_a_join_stores_before_adopting_matches_the_vault_after_it() {
        let mut vault = session();
        let mut remote = vault.open_payload().expect("payload").clone();
        remote.vault_name = "Fictional vault from the first device".into();
        remote.revision = 12;
        let expected = digest_after_commit(&remote).expect("digest");
        adopt_with(&mut vault, [6u8; 32], remote, PASSWORD, None).expect("adopted");
        assert_eq!(payload_digest(&bytes_of(&vault)), expected);
    }

    #[test]
    fn names_read_before_a_key_is_taken_are_still_shown_after_it() {
        let mut vault = session();
        let old_key = vault.expose_vault_key(|key| Ok(*key)).expect("key");
        let creator = DeviceIdentity::generate().expect("identity");
        let sealed = seal_label(
            &old_key,
            "fictionalVault00000001",
            &creator.device_id,
            "Fictional laptop",
        )
        .expect("label");
        let create = create_entry(&creator, "fictionalVault00000001", &sealed);
        let list = DeviceList::verify(std::slice::from_ref(&create)).expect("list");
        let mut state = state_matching(&vault);

        let kept = crate::application::sync_adopt::KeptThroughAdoption::capture(
            &state,
            &list,
            &vault,
            [None, None],
        )
        .expect("kept");
        let payload = vault.open_payload().expect("payload").clone();
        adopt_with(&mut vault, [5u8; 32], payload, PASSWORD, None).expect("adopted");
        kept.apply(&mut state);

        let new_key = vault.expose_vault_key(|key| Ok(*key)).expect("key");
        assert_ne!(new_key, old_key);
        let shown = crate::application::sync::names_for(
            &list,
            &state.remembered_names(),
            "fictionalVault00000001",
            Some(&new_key),
        );
        assert_eq!(
            shown.get(&creator.device_id).map(String::as_str),
            Some("Fictional laptop")
        );
        assert!(!state.has_local_changes(&bytes_of(&vault)));
    }

    #[test]
    fn a_kit_prepared_for_one_key_does_not_open_another() {
        let (kit, recovery) = prepare_recovery(&[1u8; 32]).expect("prepared");
        let wrapping = crate::vault::crypto::derive_key(&kit, &recovery.kdf).expect("derived");
        let opened = decrypt_bytes(&wrapping, &recovery.wrap, RECOVERY_WRAP_AAD).expect("opens");
        assert_eq!(opened.as_slice(), [1u8; 32].as_slice());
        assert!(decrypt_bytes(&wrapping, &recovery.wrap, crate::vault::WRAP_AAD).is_err());
    }
}

#[cfg(test)]
mod save_after_disable_tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::application::sync::Refreshed;
    use crate::application::sync_transfer::record_checkpoint_if_due_in_state;
    use crate::sync::client::StateView;
    use crate::sync::engine::VerifiedUpdate;

    #[test]
    fn a_checkpoint_that_finishes_after_sync_was_turned_off_does_not_recreate_the_state() {
        let vault = TestVault::with_login("fictional-login", "https://northwind.example");
        let vault_id = vault_id_of_test_vault(&vault);
        let scratch = Scratch::new();
        let store = scratch.store();
        let identity = DeviceIdentity::generate().expect("identity");
        identity
            .save(&store.identity_path())
            .expect("saved identity");
        let entries = labels(&vault_id, &[&identity]);
        let list = DeviceList::verify(&entries).expect("list");
        let mut local = SyncState::new(&vault_id, &identity.device_id);
        local.entries = entries.clone();
        local.activated_epoch = 1;
        let (plaintext, _) = {
            let session = vault.state.session.lock().expect("session lock");
            local_payload_bytes(session.as_ref().expect("unlocked")).expect("payload")
        };
        local.payload_digest = payload_digest(&plaintext);
        store.save_state(&local).expect("saved state");
        let refreshed = Refreshed {
            server: StateView {
                vault_id: vault_id.clone(),
                vault_epoch: 1,
                current_revision: 0,
                device_state: "approved".into(),
                activated_epoch: 1,
            },
            update: VerifiedUpdate {
                entries,
                list,
                head: None,
                receipt: None,
            },
            confirmed_at: None,
            peer_checks_skipped: false,
        };
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let server = TestServer::start({
            let started = started.clone();
            let release = release.clone();
            move |request: &Recorded| match (request.method.as_str(), request.path.as_str()) {
                ("POST", "/v1/sync/checkpoints") => {
                    started.wait();
                    release.wait();
                    Reply::json(200, &json!({}))
                }
                other => panic!("unexpected route {other:?}"),
            }
        });
        let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
        let checkpoint_store = SyncStore::new(scratch.path.clone());
        let checkpoint_vault_id = vault_id.clone();
        let checkpoint_device = identity.device_id.clone();
        let run = thread::spawn(move || {
            let local = SyncState {
                vault_id: checkpoint_vault_id,
                device_id: checkpoint_device,
                ..local
            };
            block_on(record_checkpoint_if_due_in_state(
                &checkpoint_store,
                &client,
                &local,
                &refreshed,
            ));
        });

        started.wait();
        store.forget_everything().expect("sync turned off");
        release.wait();
        run.join().expect("checkpoint thread");

        assert!(
            store.load_state().expect("state").is_none(),
            "a checkpoint that finishes after Sync is off must not bring the state file back"
        );
        assert!(!store.identity_present());
    }
}

#[cfg(test)]
mod adoption_and_publish_tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::sync::request::Receipt;

    const ACTING_TOKEN: &str = "fictional-acting-token";
    const RECIPIENT_TOKEN: &str = "fictional-recipient-token";

    struct FakeSyncWorld {
        vault_id: String,
        epoch: u64,
        revision: u64,
        device_state: String,
        entries: Vec<DeviceListEntry>,
        headers: Vec<Value>,
        snapshot: Option<(Value, String)>,
        packages: HashMap<String, KeyPackageV3>,
        tokens: HashMap<String, String>,
        activated: HashMap<String, u64>,
        drop_activation_answer: bool,
        fail_next_upload: bool,
        instance: SigningKey,
    }

    impl FakeSyncWorld {
        fn new(vault_id: &str, entries: Vec<DeviceListEntry>, epoch: u64) -> Self {
            Self {
                vault_id: vault_id.to_string(),
                epoch,
                revision: 0,
                device_state: "approved".to_string(),
                entries,
                headers: Vec::new(),
                snapshot: None,
                packages: HashMap::new(),
                tokens: HashMap::new(),
                activated: HashMap::new(),
                drop_activation_answer: false,
                fail_next_upload: false,
                instance: SigningKey::from_bytes(&[7u8; 32]),
            }
        }

        fn instance_key(&self) -> String {
            URL_SAFE_NO_PAD.encode(self.instance.verifying_key().as_bytes())
        }
    }

    fn after_of(path: &str) -> u64 {
        path.split("after=")
            .nth(1)
            .and_then(|value| value.split('&').next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    }

    fn served_header(header: &Header, instance: &SigningKey) -> (Value, String) {
        let receipt = Receipt {
            vault_id: &header.vault_id,
            revision: header.revision,
            header_digest: &header.digest(),
            vault_epoch: header.vault_epoch,
            accepted_at: ACCEPTED_UNIX,
        };
        let signature = instance.sign(&receipt.signing_payload());
        let receipt = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let mut document = serde_json::to_value(header).expect("header json");
        document["digest"] = json!(header.digest());
        document["receipt"] = json!(receipt);
        document["acceptedAt"] = json!(ACCEPTED_AT);
        (document, receipt)
    }

    fn handler(
        world: Arc<Mutex<FakeSyncWorld>>,
    ) -> impl Fn(&Recorded) -> Reply + Send + Sync + 'static {
        move |request: &Recorded| {
            let token = request
                .headers
                .get("authorization")
                .and_then(|value| value.strip_prefix("Sesame "))
                .unwrap_or_default()
                .to_string();
            let mut world = world.lock().expect("world");
            let device = world.tokens.get(&token).cloned().unwrap_or_default();
            let activated = world.activated.get(&device).copied().unwrap_or(0);
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/v1/sync/checkpoints") => checkpoint_not_found(),
                ("POST", "/v1/sync/checkpoints") => Reply::json(200, &json!({})),
                ("GET", "/v1/sync/state") => Reply::json(
                    200,
                    &json!({
                        "vaultId": world.vault_id,
                        "vaultEpoch": world.epoch,
                        "currentRevision": world.revision,
                        "deviceState": world.device_state,
                        "activatedEpoch": activated,
                    }),
                ),
                ("GET", path) if path.starts_with("/v1/sync/device-list") => {
                    let after = after_of(path);
                    let entries: Vec<DeviceListEntry> = world
                        .entries
                        .iter()
                        .filter(|entry| entry.index > after)
                        .cloned()
                        .collect();
                    Reply::json(200, &json!({ "entries": entries }))
                }
                ("GET", path) if path.starts_with("/v1/sync/headers") => {
                    let after = after_of(path);
                    let headers: Vec<Value> = world
                        .headers
                        .iter()
                        .filter(|header| header["revision"].as_u64().unwrap_or(0) > after)
                        .cloned()
                        .collect();
                    Reply::json(200, &json!({ "headers": headers }))
                }
                ("GET", "/v1/sync/key-package") => {
                    let package = world
                        .packages
                        .get(&device)
                        .cloned()
                        .expect("key package for this device");
                    Reply::json(200, &json!({ "package": package }))
                }
                ("POST", "/v1/sync/activate") => {
                    let epoch = world.epoch;
                    world.activated.insert(device, epoch);
                    if world.drop_activation_answer {
                        Reply::disconnect()
                    } else {
                        Reply::json(200, &json!({}))
                    }
                }
                ("POST", "/v1/sync/devices/rotate") => {
                    let body: Value = serde_json::from_slice(&request.body).expect("rotate body");
                    let entry: DeviceListEntry =
                        serde_json::from_value(body["entry"].clone()).expect("rotation");
                    let packages: Vec<KeyPackageV3> =
                        serde_json::from_value(body["packages"].clone()).expect("packages");
                    world.entries.push(entry.clone());
                    world.epoch = entry.epoch_after;
                    if let Some(sender) = world.tokens.get(&token).cloned() {
                        let epoch = world.epoch;
                        world.activated.insert(sender, epoch);
                    }
                    for package in packages {
                        world
                            .packages
                            .insert(package.recipient_device_id.clone(), package);
                    }
                    Reply::json(200, &json!({}))
                }
                ("POST", "/v1/sync/snapshots") => {
                    if world.fail_next_upload {
                        world.fail_next_upload = false;
                        return Reply::json(500, &json!({"error":{"code":"sync_failed"}}));
                    }
                    let body: Value = serde_json::from_slice(&request.body).expect("upload body");
                    let header: Header =
                        serde_json::from_value(body["header"].clone()).expect("header");
                    let ciphertext = body["ciphertext"].as_str().expect("ciphertext").to_string();
                    let (document, receipt) = served_header(&header, &world.instance);
                    let accepted = json!({
                        "revision": header.revision,
                        "digest": header.digest(),
                        "receipt": receipt,
                        "acceptedAt": ACCEPTED_AT,
                    });
                    world.revision = header.revision;
                    world.headers.push(document.clone());
                    world.snapshot = Some((document, ciphertext));
                    Reply::json(200, &accepted)
                }
                ("GET", "/v1/sync/snapshot") => {
                    let (header, ciphertext) = world.snapshot.clone().expect("stored snapshot");
                    Reply::json(
                        200,
                        &json!({
                            "header": header,
                            "acceptedAt": ACCEPTED_AT,
                            "ciphertext": ciphertext,
                        }),
                    )
                }
                other => panic!("unexpected route {other:?}"),
            }
        }
    }

    fn recovery_opens(vault: &UnlockedVault, kit: &str, key: &[u8; 32]) -> bool {
        let (Some(kdf), Some(wrap)) = (&vault.recovery_kdf, &vault.recovery_wrap) else {
            return false;
        };
        let wrapping = crate::vault::crypto::derive_key(kit, kdf).expect("derived");
        decrypt_bytes(&wrapping, wrap, RECOVERY_WRAP_AAD)
            .is_ok_and(|opened| opened.as_slice() == key.as_slice())
    }

    fn vault_key(vault: &TestVault) -> [u8; 32] {
        let session = vault.state.session.lock().expect("session lock");
        session
            .as_ref()
            .expect("unlocked")
            .expose_vault_key(|key| Ok(*key))
            .expect("key")
    }

    fn state_digest(vault: &TestVault, state: &mut SyncState) {
        let (plaintext, _) = {
            let session = vault.state.session.lock().expect("session lock");
            local_payload_bytes(session.as_ref().expect("unlocked")).expect("payload")
        };
        state.payload_digest = payload_digest(&plaintext);
    }

    #[test]
    fn a_lost_activation_answer_can_be_finished_after_a_restart_and_still_shows_the_kit() {
        let vault = TestVault::with_login("fictional-login", "https://northwind.example");
        let vault_id = vault_id_of_test_vault(&vault);
        let scratch = Scratch::new();
        let store = scratch.store();
        let acting = DeviceIdentity::generate().expect("acting identity");
        let recipient = DeviceIdentity::generate().expect("recipient identity");
        recipient
            .save(&store.identity_path())
            .expect("saved identity");
        let entries = labels(&vault_id, &[&acting, &recipient]);
        let list = DeviceList::verify(&entries).expect("list");
        let rotation = rotate_entry(&acting, &list).expect("rotation");
        let new_key = [5u8; 32];
        let packages = survivor_packages(
            &acting,
            &list,
            &vault_id,
            &new_key,
            &[acting.device_id.as_str()],
            rotation.epoch_after,
            &rotation.digest(),
        )
        .expect("packages");
        let package = packages
            .iter()
            .find(|package| package.recipient_device_id == recipient.device_id)
            .expect("recipient package")
            .clone();
        let mut local = SyncState::new(&vault_id, &recipient.device_id);
        local.entries = entries.clone();
        local.activated_epoch = 1;
        state_digest(&vault, &mut local);
        store.save_state(&local).expect("saved state");
        let mut committed = entries.clone();
        committed.push(rotation.clone());
        let world = Arc::new(Mutex::new(FakeSyncWorld::new(&vault_id, committed, 2)));
        {
            let mut world = world.lock().expect("world");
            world
                .tokens
                .insert(RECIPIENT_TOKEN.into(), recipient.device_id.clone());
            world.activated.insert(recipient.device_id.clone(), 1);
            world.packages.insert(recipient.device_id.clone(), package);
            world.drop_activation_answer = true;
        }
        let server = TestServer::start(handler(world.clone()));
        let instance = world.lock().expect("world").instance_key();
        let client = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);
        let effects = FakeEffects::new(PathBuf::new());
        let old_key = vault_key(&vault);

        let first = block_on(take_new_key_in_state(
            &vault.state,
            &store,
            &effects,
            &client,
            PASSWORD.into(),
        ));
        assert!(first.is_err(), "the lost answer is reported as a failure");
        assert!(
            rekey_journal::is_pending(&store.journal_path()),
            "the new key and its kit are saved before the vault changes"
        );
        assert_eq!(
            vault_key(&vault),
            new_key,
            "the vault already holds the new key"
        );
        assert_ne!(vault_key(&vault), old_key);
        assert_eq!(
            store
                .load_state()
                .expect("state")
                .expect("state")
                .activated_epoch,
            1,
            "activation was not recorded locally"
        );

        world.lock().expect("world").drop_activation_answer = false;
        let restarted = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);
        let result = block_on(take_new_key_in_state(
            &vault.state,
            &store,
            &effects,
            &restarted,
            PASSWORD.into(),
        ))
        .expect("the retry finishes the saved adoption");

        assert!(
            !result.recovery_kit.is_empty(),
            "the saved kit is shown again"
        );
        assert!(recovery_opens(
            vault
                .state
                .session
                .lock()
                .expect("session lock")
                .as_ref()
                .expect("unlocked"),
            &result.recovery_kit,
            &new_key
        ));
        assert!(!rekey_journal::is_pending(&store.journal_path()));
        assert_eq!(
            store
                .load_state()
                .expect("state")
                .expect("state")
                .activated_epoch,
            rotation.epoch_after
        );
        assert_eq!(
            server
                .paths()
                .iter()
                .filter(|path| path.as_str() == "/v1/sync/activate")
                .count(),
            1,
            "the retry reads the service state instead of activating again"
        );
    }

    struct LostActivation {
        vault: TestVault,
        scratch: Scratch,
        store: SyncStore,
        world: Arc<Mutex<FakeSyncWorld>>,
        new_key: [u8; 32],
        acting_device_id: String,
    }

    impl LostActivation {
        fn block_vault_writes(&self) -> PathBuf {
            let blocked = self.scratch.path.join("blocked");
            std::fs::write(&blocked, b"not a directory").expect("blocking file");
            let mut session = self.vault.state.session.lock().expect("session lock");
            let unlocked = session.as_mut().expect("unlocked");
            std::mem::replace(&mut unlocked.path, blocked.join("vault.sesame"))
        }

        fn allow_vault_writes(&self, original: PathBuf) {
            let mut session = self.vault.state.session.lock().expect("session lock");
            session.as_mut().expect("unlocked").path = original;
        }
    }

    fn lost_activation() -> LostActivation {
        let vault = TestVault::with_login("fictional-login", "https://northwind.example");
        let vault_id = vault_id_of_test_vault(&vault);
        let scratch = Scratch::new();
        let store = scratch.store();
        let acting = DeviceIdentity::generate().expect("acting identity");
        let recipient = DeviceIdentity::generate().expect("recipient identity");
        recipient
            .save(&store.identity_path())
            .expect("saved identity");
        let entries = labels_sealed_with(&vault_key(&vault), &vault_id, &[&acting, &recipient]);
        let list = DeviceList::verify(&entries).expect("list");
        let rotation = rotate_entry(&acting, &list).expect("rotation");
        let new_key = [5u8; 32];
        let packages = survivor_packages(
            &acting,
            &list,
            &vault_id,
            &new_key,
            &[acting.device_id.as_str()],
            rotation.epoch_after,
            &rotation.digest(),
        )
        .expect("packages");
        let package = packages
            .iter()
            .find(|package| package.recipient_device_id == recipient.device_id)
            .expect("recipient package")
            .clone();
        let mut local = SyncState::new(&vault_id, &recipient.device_id);
        local.entries = entries.clone();
        local.activated_epoch = 1;
        state_digest(&vault, &mut local);
        store.save_state(&local).expect("saved state");
        let mut committed = entries;
        committed.push(rotation);
        let mut world = FakeSyncWorld::new(&vault_id, committed, 2);
        world
            .tokens
            .insert(RECIPIENT_TOKEN.into(), recipient.device_id.clone());
        world.activated.insert(recipient.device_id.clone(), 1);
        world.packages.insert(recipient.device_id.clone(), package);
        world.drop_activation_answer = true;
        LostActivation {
            vault,
            scratch,
            store,
            world: Arc::new(Mutex::new(world)),
            new_key,
            acting_device_id: acting.device_id,
        }
    }

    fn take_key(fixture: &LostActivation, client: &SyncClient) -> Result<(), String> {
        block_on(take_new_key_in_state(
            &fixture.vault.state,
            &fixture.store,
            &FakeEffects::new(PathBuf::new()),
            client,
            PASSWORD.into(),
        ))
        .map(|_| ())
    }

    fn stored_plaintext(vault: &TestVault) -> Vec<u8> {
        let session = vault.state.session.lock().expect("session lock");
        local_payload_bytes(session.as_ref().expect("unlocked"))
            .expect("payload")
            .0
    }

    #[test]
    fn a_retry_after_a_lost_activation_leaves_the_vault_without_local_changes() {
        let fixture = lost_activation();
        let server = TestServer::start(handler(fixture.world.clone()));
        let instance = fixture.world.lock().expect("world").instance_key();
        let client = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);

        take_key(&fixture, &client).expect_err("the lost answer is reported as a failure");
        fixture.world.lock().expect("world").drop_activation_answer = false;
        let retry = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);
        take_key(&fixture, &retry).expect("the retry finishes the saved adoption");

        assert_eq!(vault_key(&fixture.vault), fixture.new_key);
        let saved = fixture
            .store
            .load_state()
            .expect("state")
            .expect("saved state");
        assert!(
            !saved.has_local_changes(&stored_plaintext(&fixture.vault)),
            "an adoption-only revision bump is not a local edit"
        );
    }

    #[test]
    fn a_retry_after_a_lost_activation_still_reports_an_edit_made_in_between() {
        let fixture = lost_activation();
        let server = TestServer::start(handler(fixture.world.clone()));
        let instance = fixture.world.lock().expect("world").instance_key();
        let client = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);

        take_key(&fixture, &client).expect_err("the lost answer is reported as a failure");
        fixture
            .vault
            .seed(|payload| payload.vault_name = "Fictional vault edited between attempts".into());
        fixture.world.lock().expect("world").drop_activation_answer = false;
        let retry = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);
        take_key(&fixture, &retry).expect("the retry finishes the saved adoption");

        let saved = fixture
            .store
            .load_state()
            .expect("state")
            .expect("saved state");
        assert!(
            saved.has_local_changes(&stored_plaintext(&fixture.vault)),
            "the edit made between attempts is still local"
        );
    }

    #[test]
    fn a_retry_after_a_lost_activation_keeps_names_read_with_the_old_key() {
        let fixture = lost_activation();
        let server = TestServer::start(handler(fixture.world.clone()));
        let instance = fixture.world.lock().expect("world").instance_key();
        let client = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);

        take_key(&fixture, &client).expect_err("the lost answer is reported as a failure");
        fixture.world.lock().expect("world").drop_activation_answer = false;
        let retry = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);
        take_key(&fixture, &retry).expect("the retry finishes the saved adoption");

        let saved = fixture
            .store
            .load_state()
            .expect("state")
            .expect("saved state");
        let list = saved.list().expect("list");
        let shown = crate::application::sync::names_for(
            &list,
            &saved.remembered_names(),
            &saved.vault_id,
            Some(&vault_key(&fixture.vault)),
        );
        assert_eq!(
            shown.get(&fixture.acting_device_id).map(String::as_str),
            Some("Fictional laptop"),
            "the name read under the old key survives the retry"
        );
    }

    #[test]
    fn a_replay_whose_vault_commit_fails_is_retried_without_a_local_change() {
        let fixture = lost_activation();
        let server = TestServer::start(handler(fixture.world.clone()));
        let instance = fixture.world.lock().expect("world").instance_key();
        let client = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);

        take_key(&fixture, &client).expect_err("the lost answer is reported as a failure");
        fixture.world.lock().expect("world").drop_activation_answer = false;
        let original = fixture.block_vault_writes();
        let replay = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);
        take_key(&fixture, &replay).expect_err("the replay cannot save the vault");
        fixture.allow_vault_writes(original);

        let retry = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);
        take_key(&fixture, &retry).expect("the next retry finishes the saved adoption");

        let saved = fixture
            .store
            .load_state()
            .expect("state")
            .expect("saved state");
        assert!(
            !saved.has_local_changes(&stored_plaintext(&fixture.vault)),
            "the adoption's revision bump is not a local edit"
        );
    }

    #[test]
    fn an_edit_between_a_failed_replay_and_its_retry_is_still_local() {
        let fixture = lost_activation();
        let server = TestServer::start(handler(fixture.world.clone()));
        let instance = fixture.world.lock().expect("world").instance_key();
        let client = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);

        take_key(&fixture, &client).expect_err("the lost answer is reported as a failure");
        fixture.world.lock().expect("world").drop_activation_answer = false;
        let original = fixture.block_vault_writes();
        let replay = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);
        take_key(&fixture, &replay).expect_err("the replay cannot save the vault");
        fixture.allow_vault_writes(original);
        fixture.vault.seed(|payload| {
            payload.vault_name = "Fictional vault edited after the failed replay".into()
        });

        let retry = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);
        take_key(&fixture, &retry).expect("the next retry finishes the saved adoption");

        let saved = fixture
            .store
            .load_state()
            .expect("state")
            .expect("saved state");
        assert!(
            saved.has_local_changes(&stored_plaintext(&fixture.vault)),
            "the edit made after the failed replay is still local"
        );
    }

    #[test]
    fn a_clean_rekey_publishes_a_snapshot_a_second_device_can_read() {
        let acting_vault = TestVault::with_login("fictional-login", "https://northwind.example");
        acting_vault.seed(|payload| {
            payload.vault_name = "Fictional vault from the acting device".into();
        });
        let vault_id = vault_id_of_test_vault(&acting_vault);
        let recipient_vault = TestVault::with_login("fictional-login", "https://northwind.example");
        recipient_vault.seed(|payload| payload.vault_id = Some(vault_id.clone()));
        let scratch = Scratch::new();
        let acting_store = scratch.store();
        let acting = DeviceIdentity::generate().expect("acting identity");
        let recipient = DeviceIdentity::generate().expect("recipient identity");
        acting
            .save(&acting_store.identity_path())
            .expect("saved identity");
        let entries = labels(&vault_id, &[&acting, &recipient]);
        let mut acting_state = SyncState::new(&vault_id, &acting.device_id);
        acting_state.entries = entries.clone();
        acting_state.activated_epoch = 1;
        state_digest(&acting_vault, &mut acting_state);
        acting_store
            .save_state(&acting_state)
            .expect("saved acting state");
        let world = Arc::new(Mutex::new(FakeSyncWorld::new(
            &vault_id,
            entries.clone(),
            1,
        )));
        {
            let mut world = world.lock().expect("world");
            world
                .tokens
                .insert(ACTING_TOKEN.into(), acting.device_id.clone());
            world.activated.insert(acting.device_id.clone(), 1);
        }
        let server = TestServer::start(handler(world.clone()));
        let instance = world.lock().expect("world").instance_key();
        let acting_client = SyncClient::for_tests(&server.base(), ACTING_TOKEN, &instance);
        let effects = FakeEffects::new(PathBuf::new());
        let new_key = [6u8; 32];
        let prepared = crate::sync::key_change::PreparedKeyChange::default();
        let (kit, recovery) = prepare_recovery(&new_key).expect("prepared");
        prepared.stage(&new_key, recovery, std::time::Instant::now());
        assert!(!kit.is_empty());

        block_on(crate::application::sync_transfer::rekey_without_in_state(
            &acting_vault.state,
            &acting_store,
            &effects,
            &acting_client,
            crate::application::sync_transfer::RekeyRequest {
                prepared: &prepared,
                subject: None,
                master_password: PASSWORD,
                adopt_locally: true,
            },
        ))
        .expect("the clean vault is rekeyed");

        assert_eq!(vault_key(&acting_vault), new_key);
        assert!(
            server
                .paths()
                .iter()
                .any(|path| path == "/v1/sync/snapshots"),
            "a clean rekey must publish under the new key"
        );
        let (published, ciphertext) = world
            .lock()
            .expect("world")
            .snapshot
            .clone()
            .expect("published snapshot");
        let published_header: Header =
            serde_json::from_value(published.clone()).expect("published header");
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&ciphertext)
            .expect("ciphertext bytes");
        let opened = crate::application::sync_transfer::decrypt_remote(
            &new_key,
            &published_header,
            &URL_SAFE_NO_PAD.encode(&ciphertext),
        )
        .expect("the published snapshot opens with the new key");
        assert_eq!(opened.payload().entries.len(), 1);

        let recipient_scratch = Scratch::new();
        let recipient_store = recipient_scratch.store();
        recipient
            .save(&recipient_store.identity_path())
            .expect("saved identity");
        let mut recipient_state = SyncState::new(&vault_id, &recipient.device_id);
        recipient_state.entries = entries;
        recipient_state.activated_epoch = 1;
        state_digest(&recipient_vault, &mut recipient_state);
        recipient_store
            .save_state(&recipient_state)
            .expect("saved recipient state");
        world
            .lock()
            .expect("world")
            .tokens
            .insert(RECIPIENT_TOKEN.into(), recipient.device_id.clone());
        world
            .lock()
            .expect("world")
            .activated
            .insert(recipient.device_id.clone(), 1);
        let recipient_client = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);

        let taken = block_on(take_new_key_in_state(
            &recipient_vault.state,
            &recipient_store,
            &effects,
            &recipient_client,
            PASSWORD.into(),
        ))
        .expect("the second device takes the new key");
        assert!(!taken.recovery_kit.is_empty());
        assert_eq!(vault_key(&recipient_vault), new_key);

        block_on(download_vault_in_state(
            &recipient_vault.state,
            &recipient_store,
            &recipient_client,
            &effects,
        ))
        .expect("the second device reads the snapshot under the new key");
        let name = {
            let session = recipient_vault.state.session.lock().expect("session lock");
            session
                .as_ref()
                .expect("unlocked")
                .open_payload()
                .expect("payload")
                .vault_name
                .clone()
        };
        assert_eq!(name, "Fictional vault from the acting device");
    }

    #[test]
    fn a_clean_rekey_retries_a_failed_first_snapshot_on_the_next_run() {
        let acting_vault = TestVault::with_login("fictional-login", "https://northwind.example");
        acting_vault.seed(|payload| {
            payload.vault_name = "Fictional vault from the acting device".into();
        });
        let vault_id = vault_id_of_test_vault(&acting_vault);
        let recipient_vault = TestVault::with_login("fictional-login", "https://northwind.example");
        recipient_vault.seed(|payload| payload.vault_id = Some(vault_id.clone()));
        let scratch = Scratch::new();
        let acting_store = scratch.store();
        let acting = DeviceIdentity::generate().expect("acting identity");
        let recipient = DeviceIdentity::generate().expect("recipient identity");
        acting
            .save(&acting_store.identity_path())
            .expect("saved identity");
        let entries = labels(&vault_id, &[&acting, &recipient]);
        let mut acting_state = SyncState::new(&vault_id, &acting.device_id);
        acting_state.entries = entries.clone();
        acting_state.activated_epoch = 1;
        state_digest(&acting_vault, &mut acting_state);
        acting_store
            .save_state(&acting_state)
            .expect("saved acting state");
        let mut world = FakeSyncWorld::new(&vault_id, entries.clone(), 1);
        world
            .tokens
            .insert(ACTING_TOKEN.into(), acting.device_id.clone());
        world.activated.insert(acting.device_id.clone(), 1);
        world.fail_next_upload = true;
        let world = Arc::new(Mutex::new(world));
        let server = TestServer::start(handler(world.clone()));
        let instance = world.lock().expect("world").instance_key();
        let acting_client = SyncClient::for_tests(&server.base(), ACTING_TOKEN, &instance);
        let effects = FakeEffects::new(PathBuf::new());
        let new_key = [6u8; 32];
        let prepared = crate::sync::key_change::PreparedKeyChange::default();
        let (kit, recovery) = prepare_recovery(&new_key).expect("prepared");
        prepared.stage(&new_key, recovery, std::time::Instant::now());
        assert!(!kit.is_empty());

        block_on(crate::application::sync_transfer::rekey_without_in_state(
            &acting_vault.state,
            &acting_store,
            &effects,
            &acting_client,
            crate::application::sync_transfer::RekeyRequest {
                prepared: &prepared,
                subject: None,
                master_password: PASSWORD,
                adopt_locally: true,
            },
        ))
        .expect("the clean vault is rekeyed");

        assert_eq!(vault_key(&acting_vault), new_key);
        assert_eq!(
            server
                .paths()
                .iter()
                .filter(|path| path.as_str() == "/v1/sync/snapshots")
                .count(),
            1,
            "the rekey attempts its first upload"
        );
        assert!(
            world.lock().expect("world").snapshot.is_none(),
            "the first upload did not reach the service"
        );

        let local = acting_store
            .load_state()
            .expect("state")
            .expect("saved state");
        let reconnect_base = server.base();
        let reconnect_instance = instance.clone();
        let outcome = block_on(
            crate::application::sync_transfer::run_one_transfer_in_state(
                &acting_vault.state,
                &acting_store,
                &acting_client,
                &effects,
                local,
                move || {
                    let base = reconnect_base.clone();
                    let instance = reconnect_instance.clone();
                    async move { Ok(SyncClient::for_tests(&base, ACTING_TOKEN, &instance)) }
                },
            ),
        )
        .expect("the ordinary run publishes the snapshot");
        assert!(
            matches!(
                outcome,
                crate::sync::coordinator::Outcome::Uploaded { revision: 1 }
            ),
            "the ordinary run retries the upload instead of reporting that everything is current"
        );
        assert_eq!(
            server
                .paths()
                .iter()
                .filter(|path| path.as_str() == "/v1/sync/snapshots")
                .count(),
            2,
            "the second upload succeeded"
        );

        let recipient_scratch = Scratch::new();
        let recipient_store = recipient_scratch.store();
        recipient
            .save(&recipient_store.identity_path())
            .expect("saved identity");
        let mut recipient_state = SyncState::new(&vault_id, &recipient.device_id);
        recipient_state.entries = entries;
        recipient_state.activated_epoch = 1;
        state_digest(&recipient_vault, &mut recipient_state);
        recipient_store
            .save_state(&recipient_state)
            .expect("saved recipient state");
        world
            .lock()
            .expect("world")
            .tokens
            .insert(RECIPIENT_TOKEN.into(), recipient.device_id.clone());
        world
            .lock()
            .expect("world")
            .activated
            .insert(recipient.device_id.clone(), 1);
        let recipient_client = SyncClient::for_tests(&server.base(), RECIPIENT_TOKEN, &instance);

        let taken = block_on(take_new_key_in_state(
            &recipient_vault.state,
            &recipient_store,
            &effects,
            &recipient_client,
            PASSWORD.into(),
        ))
        .expect("the second device takes the new key");
        assert!(!taken.recovery_kit.is_empty());
        assert_eq!(vault_key(&recipient_vault), new_key);

        block_on(download_vault_in_state(
            &recipient_vault.state,
            &recipient_store,
            &recipient_client,
            &effects,
        ))
        .expect("the second device reads the snapshot under the new key");
        let name = {
            let session = recipient_vault.state.session.lock().expect("session lock");
            session
                .as_ref()
                .expect("unlocked")
                .open_payload()
                .expect("payload")
                .vault_name
                .clone()
        };
        assert_eq!(name, "Fictional vault from the acting device");
    }
}

#[cfg(test)]
mod coordinator_classification_tests {
    use super::*;
    use crate::sync::coordinator::{Halt, Outcome};

    #[test]
    fn an_entitlement_code_halts_the_coordinator() {
        let message = present(SyncError::NotEntitled);
        assert_eq!(
            classify_transfer_failure(&message),
            Outcome::Halt(Halt::NotEntitled)
        );
    }

    #[test]
    fn the_word_subscription_in_a_message_no_longer_halts_anything() {
        for message in [
            "Your subscription has lapsed.",
            "This account's Sesame subscription is not active.",
            "subscription",
        ] {
            assert_eq!(
                classify_transfer_failure(message),
                Outcome::Transient,
                "{message}"
            );
        }
    }

    #[test]
    fn a_message_that_only_resembles_the_entitlement_code_does_not_halt() {
        for message in [
            "sync_not_entitled",
            "x sync_not_entitled:",
            "Sync_Not_Entitled:",
        ] {
            assert_eq!(
                classify_transfer_failure(message),
                Outcome::Transient,
                "{message}"
            );
        }
    }

    #[test]
    fn the_kill_switch_refusal_halts_as_incompatible_and_never_as_a_removed_device() {
        assert_eq!(
            classify_transfer_failure(crate::sync::floor::REFUSAL),
            Outcome::Halt(Halt::Incompatible)
        );
    }

    #[test]
    fn a_damaged_floor_file_halts_with_its_own_reason_and_not_as_an_old_version() {
        assert_eq!(
            classify_transfer_failure(crate::sync::floor::DAMAGED_REFUSAL),
            Outcome::Halt(Halt::FloorDamaged)
        );
    }

    #[test]
    fn a_device_that_has_not_taken_the_new_key_halts_with_its_own_reason_and_never_looks_offline() {
        let message = "This device has not taken the new vault key yet. Open Sync and take it.";
        assert_eq!(
            classify_transfer_failure(message),
            Outcome::Halt(Halt::NeedsNewKey)
        );
        assert_eq!(
            classify_transfer_failure(crate::application::sync::NOT_ACTIVATED),
            Outcome::Halt(Halt::NeedsNewKey)
        );
    }

    #[test]
    fn other_terminal_answers_still_halt() {
        assert_eq!(
            classify_transfer_failure("sync_conflict:7"),
            Outcome::Halt(Halt::Conflict { server_revision: 7 })
        );
        assert_eq!(
            classify_transfer_failure("sync_locked"),
            Outcome::Halt(Halt::Locked)
        );
        assert_eq!(
            classify_transfer_failure("This device is not approved to sync."),
            Outcome::Halt(Halt::Revoked)
        );
    }
}
