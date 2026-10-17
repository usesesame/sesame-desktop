use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use tauri::AppHandle;
use zeroize::Zeroize;

use super::sync::{
    forget_everything, identity_file, load_join_state, load_state, present, present_proof, refresh,
    save_state, this_identity, vault_id_of,
};
use super::sync_adopt::{finish_adoption, verify_master_password, SyncAdoptResult};
use crate::sync::client::{SyncClient, SyncError};
use crate::sync::engine::{
    add_entry, floor_for, seal_label, verify_join, verify_server_view, JoinCheck, NewDevice,
    ServerView,
};
use crate::sync::identity::DeviceIdentity;
use crate::sync::pairing::{ApproverIdentity, NewDeviceIdentity};
use crate::sync::pake::{self, Offer};
use crate::sync::request::KeyPackageV3;
use crate::sync::state::SyncState;
use crate::vault::VaultState;

const PAIRING_WINDOW: Duration = Duration::from_secs(10 * 60);
const APPROVAL_WAIT: Duration = Duration::from_secs(2 * 60);
const POLL: Duration = Duration::from_secs(2);

struct ShownCode {
    code: String,
    shown_at: Instant,
}

static SHOWN: Mutex<Option<ShownCode>> = Mutex::new(None);
static CANCELLED: AtomicBool = AtomicBool::new(false);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingCodeView {
    pub code: String,
    pub expires_in_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedDeviceView {
    pub label: String,
}

fn take_shown_code() -> Result<String, String> {
    let guard = SHOWN
        .lock()
        .map_err(|_| "Sesame could not read the pairing code.".to_string())?;
    let shown = guard
        .as_ref()
        .ok_or("Show a pairing code on this device first.")?;
    if shown.shown_at.elapsed() >= PAIRING_WINDOW {
        return Err("That pairing code expired. Show a new one.".into());
    }
    Ok(shown.code.clone())
}

fn clear_shown_code() {
    if let Ok(mut guard) = SHOWN.lock() {
        if let Some(mut shown) = guard.take() {
            shown.code.zeroize();
        }
    }
}

async fn pause() {
    let _ = tauri::async_runtime::spawn_blocking(|| std::thread::sleep(POLL)).await;
}

fn cancelled() -> Result<(), String> {
    if CANCELLED.load(Ordering::SeqCst) {
        return Err("Pairing was cancelled.".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn sync_pairing_code() -> Result<PairingCodeView, String> {
    let code = pake::generate_code()?;
    CANCELLED.store(false, Ordering::SeqCst);
    let mut guard = SHOWN
        .lock()
        .map_err(|_| "Sesame could not prepare a pairing code.".to_string())?;
    *guard = Some(ShownCode {
        code: code.clone(),
        shown_at: Instant::now(),
    });
    Ok(PairingCodeView {
        code,
        expires_in_seconds: PAIRING_WINDOW.as_secs(),
    })
}

#[tauri::command]
pub async fn sync_cancel_pairing() -> Result<(), String> {
    CANCELLED.store(true, Ordering::SeqCst);
    clear_shown_code();
    Ok(())
}

#[tauri::command]
pub async fn sync_approve_with_code(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
) -> Result<ApprovedDeviceView, String> {
    let outcome = approve(&app, &vault).await;
    clear_shown_code();
    outcome
}

async fn approve(
    app: &AppHandle,
    vault: &tauri::State<'_, VaultState>,
) -> Result<ApprovedDeviceView, String> {
    let code = take_shown_code()?;
    let started = Instant::now();
    let client = SyncClient::connect(app).await?;
    let identity = this_identity(app)?;
    let local = load_state(app)?.ok_or("Set up Sesame Sync on this device first.")?;

    let refreshed = refresh(&client, &local).await?;
    if refreshed.server.device_state != "approved"
        || refreshed.server.activated_epoch != refreshed.server.vault_epoch
    {
        return Err(
            "This device must take the current vault key before it can add another device.".into(),
        );
    }
    let mut state = local.clone();
    state.entries = refreshed.update.entries.clone();
    save_state(app, &state)?;
    let list = refreshed.update.list;
    if refreshed.server.current_revision == 0 {
        return Err("Sync this vault once before adding a device.".into());
    }

    let offered = loop {
        cancelled()?;
        if started.elapsed() >= PAIRING_WINDOW {
            return Err("No device entered the code in time.".into());
        }
        let view = client.devices().await.map_err(present)?;
        if let Some(found) = view
            .pairings
            .into_iter()
            .find(|pairing| pairing.state == "offered")
        {
            break found;
        }
        pause().await;
    };
    let offer = URL_SAFE_NO_PAD
        .decode(&offered.offer)
        .map_err(|_| "The pairing message could not be read.".to_string())?;

    let ad = ApproverIdentity {
        device_id: identity.device_id.clone(),
        signing_key: URL_SAFE_NO_PAD.encode(identity.signing_public_key()),
        vault_id: state.vault_id.clone(),
        head_digest: list.head_digest().to_string(),
    }
    .encode()
    .ok_or("Sesame could not prepare the pairing message.")?;
    let (answered, new_ad) = pake::answer(&code, &offer, &ad)?;
    let newcomer =
        NewDeviceIdentity::decode(&new_ad).ok_or("The pairing message could not be read.")?;
    if newcomer.device_id != offered.device_id
        || newcomer.signing_key != offered.signing_key
        || newcomer.package_key != offered.package_key
    {
        let _ = client.cancel_pairing(&identity, &offered.device_id).await;
        return Err(
            "The device and the service disagree about the new device's keys. Pairing stopped."
                .into(),
        );
    }
    client
        .answer_pairing(&identity, &offered.device_id, &answered.message)
        .await
        .map_err(present)?;

    let confirmation = loop {
        cancelled()?;
        if started.elapsed() >= PAIRING_WINDOW {
            return Err("The new device did not finish in time.".into());
        }
        let view = client.devices().await.map_err(present)?;
        if let Some(found) = view
            .pairings
            .into_iter()
            .find(|pairing| pairing.device_id == offered.device_id)
        {
            if let Some(message) = found.confirm {
                break message;
            }
        } else {
            return Err("The new device left before finishing.".into());
        }
        pause().await;
    };
    let confirmation = URL_SAFE_NO_PAD
        .decode(confirmation)
        .map_err(|_| "The pairing message could not be read.".to_string())?;
    if answered.verify_confirmation(&confirmation).is_err() {
        let _ = client.cancel_pairing(&identity, &offered.device_id).await;
        return Err(
            "The code on the new device did not match. Show a new code and try again.".into(),
        );
    }

    let recipient: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&newcomer.package_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("The new device offered a key Sesame cannot use.")?;
    let (sealed_label, package_bytes) = {
        let session = vault
            .session
            .lock()
            .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
        let unlocked = session
            .as_ref()
            .ok_or("Unlock Sesame before adding a device.")?;
        if vault_id_of(unlocked)? != state.vault_id {
            return Err("The unlocked vault is not the Sync vault.".into());
        }
        unlocked.expose_vault_key(|key| {
            let label = seal_label(key, &state.vault_id, &newcomer.device_id, &newcomer.label)
                .map_err(present_proof)?;
            let package = crate::sync::keys::seal_vault_key(key, &recipient, &state.vault_id)?;
            Ok((label, package))
        })?
    };
    let entry = add_entry(
        &identity,
        &list,
        &NewDevice {
            device_id: &newcomer.device_id,
            signing_key: &newcomer.signing_key,
            package_key: &newcomer.package_key,
        },
        &sealed_label,
        refreshed.server.current_revision,
    )
    .map_err(present_proof)?;
    let package = identity.sign_key_package(KeyPackageV3 {
        vault_id: state.vault_id.clone(),
        sender_device_id: identity.device_id.clone(),
        recipient_device_id: newcomer.device_id.clone(),
        vault_epoch: list.epoch(),
        entry_digest: entry.digest(),
        ciphertext: URL_SAFE_NO_PAD.encode(&package_bytes),
        signature: String::new(),
    });
    client
        .approve(&identity, &entry, &package)
        .await
        .map_err(|error| match error {
            SyncError::Conflict => {
                "Another device changed the device list. Show a new code and try again.".to_string()
            }
            other => present(other),
        })?;
    let mut next = state;
    next.entries.push(entry);
    save_state(app, &next)?;
    Ok(ApprovedDeviceView {
        label: newcomer.label,
    })
}

#[tauri::command]
pub async fn sync_join_with_code(
    app: AppHandle,
    vault: tauri::State<'_, VaultState>,
    code: String,
    label: String,
    master_password: String,
) -> Result<SyncAdoptResult, String> {
    let code = zeroize::Zeroizing::new(code);
    let master_password = zeroize::Zeroizing::new(master_password);
    CANCELLED.store(false, Ordering::SeqCst);
    let label = label.trim().to_string();
    if label.is_empty() || label.len() > crate::sync::pairing::MAX_FIELD_BYTES {
        return Err("Give this device a short name.".into());
    }
    let pending = load_join_state(&app)?;
    if pending
        .as_ref()
        .is_some_and(|state| state.pending_join.is_none())
    {
        return Err("Sesame Sync is already set up on this device.".into());
    }
    verify_master_password_now(&vault, &master_password)?;
    let client = SyncClient::connect(&app).await?;
    check_join_available(&client).await?;
    let path = identity_file(&app)?;
    if let Some(pending) = pending {
        let identity = this_identity(&app)?;
        if pending.device_id != identity.device_id {
            return Err("The stored joining device does not match this device's keys.".into());
        }
        let (pending, package) =
            prepare_join(&client, &identity, pending, |state| save_state(&app, state)).await?;
        return complete_join(
            &app,
            &vault,
            &client,
            &identity,
            pending,
            &package,
            &master_password,
        )
        .await;
    }
    let identity = if path.exists() {
        DeviceIdentity::load(&path)?
    } else {
        let identity = DeviceIdentity::generate()?;
        identity.save(&path)?;
        identity
    };
    let outcome = join(
        &app,
        &vault,
        &client,
        &identity,
        &code,
        &label,
        &master_password,
    )
    .await;
    if outcome.is_err() && load_join_state(&app)?.is_none() {
        if client
            .state()
            .await
            .is_ok_and(|server| server.device_state != "approved")
        {
            let _ = client.cancel_pairing(&identity, &identity.device_id).await;
            let _ = forget_everything(&app);
        }
    }
    outcome
}

async fn check_join_available(client: &SyncClient) -> Result<(), String> {
    match client.state().await {
        Ok(_) | Err(SyncError::NotApproved) => Ok(()),
        Err(SyncError::NotFound) => Err(
            "This account has no synced vault yet. Set it up on your other device first.".into(),
        ),
        Err(other) => Err(present(other)),
    }
}

fn verify_master_password_now(
    vault: &tauri::State<'_, VaultState>,
    master_password: &str,
) -> Result<(), String> {
    let session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the unlocked vault.".to_string())?;
    let unlocked = session
        .as_ref()
        .ok_or("Unlock Sesame before joining a synced vault.")?;
    verify_master_password(unlocked, master_password)
}

async fn join(
    app: &AppHandle,
    vault: &tauri::State<'_, VaultState>,
    client: &SyncClient,
    identity: &DeviceIdentity,
    code: &str,
    label: &str,
    master_password: &str,
) -> Result<SyncAdoptResult, String> {
    let started = Instant::now();
    let signing_key = URL_SAFE_NO_PAD.encode(identity.signing_public_key());
    let package_key = URL_SAFE_NO_PAD.encode(identity.encryption_public_key());
    let ad = NewDeviceIdentity {
        device_id: identity.device_id.clone(),
        signing_key: signing_key.clone(),
        package_key: package_key.clone(),
        label: label.to_string(),
    }
    .encode()
    .ok_or("Sesame could not prepare the pairing message.")?;
    let offer = Offer::begin(code, &ad)?;
    client
        .begin_pairing(
            identity,
            &identity.device_id,
            &signing_key,
            &package_key,
            &offer.message,
        )
        .await
        .map_err(present)?;

    let answer = loop {
        cancelled()?;
        if started.elapsed() >= PAIRING_WINDOW {
            return Err("The other device did not answer in time.".into());
        }
        let status = client.pairing_status().await.map_err(present)?;
        if status.state == "answered" {
            if let Some(answer) = status.answer {
                break answer;
            }
        }
        pause().await;
    };
    let answer = URL_SAFE_NO_PAD
        .decode(answer)
        .map_err(|_| "The pairing message could not be read.".to_string())?;
    let completed = offer.finish(&answer)?;
    let approver = ApproverIdentity::decode(&completed.approver_ad)
        .ok_or("The pairing message could not be read.")?;
    let mut pending = SyncState::new(&approver.vault_id, &identity.device_id);
    pending.pending_join = Some(approver);
    pending.pending_confirmation = Some(URL_SAFE_NO_PAD.encode(&completed.confirmation));
    let (pending, package) =
        prepare_join(client, identity, pending, |state| save_state(app, state)).await?;
    complete_join(
        app,
        vault,
        client,
        identity,
        pending,
        &package,
        master_password,
    )
    .await
}

async fn prepare_join(
    client: &SyncClient,
    identity: &DeviceIdentity,
    mut pending: SyncState,
    mut persist: impl FnMut(&SyncState) -> Result<(), String>,
) -> Result<(SyncState, KeyPackageV3), String> {
    persist(&pending)?;
    let package = match client.key_package().await {
        Ok(package) => package,
        Err(SyncError::NotFound | SyncError::NotApproved) => {
            let status = client.pairing_status().await.map_err(present)?;
            if status.state == "answered" {
                let confirmation = pending
                    .pending_confirmation
                    .as_deref()
                    .ok_or("The saved pairing confirmation is missing. Start joining again.")?;
                let confirmation = URL_SAFE_NO_PAD
                    .decode(confirmation)
                    .map_err(|_| "The saved pairing confirmation could not be read.".to_string())?;
                client
                    .confirm_pairing(identity, &confirmation)
                    .await
                    .map_err(present)?;
            } else if status.state != "confirmed" {
                return Err(
                    "The other device has not answered this pairing. Start joining again.".into(),
                );
            }
            wait_for_package(client).await?
        }
        Err(other) => return Err(present(other)),
    };
    let approver = pending
        .pending_join
        .as_ref()
        .ok_or("This device has no unfinished join.")?;
    let entries = client.device_list(0).await.map_err(present)?;
    if !entries.starts_with(&pending.entries) {
        return Err("sync_fork:The device list changed while this device was joining.".into());
    }
    verify_join(
        &JoinCheck {
            device_id: &identity.device_id,
            signing_key: &URL_SAFE_NO_PAD.encode(identity.signing_public_key()),
            package_key: &URL_SAFE_NO_PAD.encode(identity.encryption_public_key()),
            approver,
        },
        &entries,
        &package,
    )
    .map_err(present_proof)?;
    pending.floor = floor_for(&entries, &identity.device_id);
    pending.entries = entries;
    pending.pending_confirmation = None;
    persist(&pending)?;
    Ok((pending, package))
}

async fn wait_for_package(client: &SyncClient) -> Result<KeyPackageV3, String> {
    let waited = Instant::now();
    loop {
        cancelled()?;
        match client.key_package().await {
            Ok(package) => return Ok(package),
            Err(SyncError::NotFound | SyncError::NotApproved) => {}
            Err(other) => return Err(present(other)),
        }
        if waited.elapsed() >= APPROVAL_WAIT {
            return Err("The other device did not approve this one in time.".into());
        }
        pause().await;
    }
}

async fn complete_join(
    app: &AppHandle,
    vault: &tauri::State<'_, VaultState>,
    client: &SyncClient,
    identity: &DeviceIdentity,
    mut pending: SyncState,
    package: &KeyPackageV3,
    master_password: &str,
) -> Result<SyncAdoptResult, String> {
    let approver = pending
        .pending_join
        .as_ref()
        .ok_or("This device has no unfinished join.")?;
    let entries = client.device_list(0).await.map_err(present)?;
    if !entries.starts_with(&pending.entries) {
        return Err("sync_fork:The device list changed while this device was joining.".into());
    }
    verify_join(
        &JoinCheck {
            device_id: &identity.device_id,
            signing_key: &URL_SAFE_NO_PAD.encode(identity.signing_public_key()),
            package_key: &URL_SAFE_NO_PAD.encode(identity.encryption_public_key()),
            approver,
        },
        &entries,
        package,
    )
    .map_err(present_proof)?;
    let sealed = URL_SAFE_NO_PAD
        .decode(&package.ciphertext)
        .map_err(|_| "The key package could not be read.".to_string())?;
    let mut opened = identity.open_key_package(&sealed, &approver.vault_id)?;
    let key: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| "The synced vault key is invalid.".to_string())?;
    opened.zeroize();

    let server = client.state().await.map_err(present)?;
    if server.current_revision == 0 {
        return Err(
            "The other device has not uploaded the vault yet. Try again in a moment.".into(),
        );
    }
    let after = pending
        .head
        .as_ref()
        .map_or(server.current_revision.saturating_sub(1), |head| {
            head.revision.saturating_sub(1)
        });
    let headers = client.headers(after).await.map_err(present)?;
    let update = verify_server_view(
        &pending,
        client.instance_key(),
        &ServerView {
            entries_after: &entries[pending.entries.len()..],
            headers: &headers,
            latest_revision: server.current_revision,
        },
    )
    .map_err(present_proof)?;
    let head = update.head.clone().ok_or("The service sent no snapshot.")?;
    let snapshot = client.snapshot().await.map_err(present)?;
    if snapshot.header.digest() != head.digest() {
        return Err("The snapshot the service sent is not the one its history names.".into());
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&snapshot.ciphertext)
        .map_err(|_| "The synced vault could not be read.".to_string())?;
    head.verify_ciphertext(&ciphertext).map_err(present_proof)?;
    let blob = crate::vault::types::CipherBlob {
        nonce: head.nonce.clone(),
        ciphertext: snapshot.ciphertext.clone(),
    };
    let authenticated =
        sesame_core::loader::VaultLoader::open_snapshot(head.version, &key, &blob, &head.aad())?;
    let payload = authenticated.payload().clone();
    let entry_count = payload.entries.len();
    let digest = crate::sync::state::payload_digest(
        &serde_json::to_vec(&payload)
            .map_err(|_| "The synced vault could not be prepared.".to_string())?,
    );

    pending.entries = entries;
    pending.head = update.head;
    pending.payload_digest = digest;
    pending.receipt = update.receipt;
    let vault_id = pending.vault_id.clone();
    let recovery_kit = finish_join_transaction(
        client,
        identity,
        package,
        pending,
        |state| save_state(app, state),
        || finish_adoption(app, vault, key, payload, master_password, &vault_id),
    )
    .await?;
    Ok(SyncAdoptResult {
        entry_count,
        revision: head.revision,
        recovery_kit,
    })
}

async fn finish_join_transaction<T>(
    client: &SyncClient,
    identity: &DeviceIdentity,
    package: &KeyPackageV3,
    mut pending: SyncState,
    mut persist: impl FnMut(&SyncState) -> Result<(), String>,
    adopt: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    persist(&pending)?;
    client
        .activate(identity, &package.digest())
        .await
        .map_err(present)?;
    let result = adopt()?;
    pending.activated_epoch = package.vault_epoch;
    pending.pending_join = None;
    pending.pending_confirmation = None;
    persist(&pending)?;
    Ok(result)
}

#[cfg(test)]
mod join_transaction_tests {
    use std::cell::Cell;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use super::*;
    use crate::adapters::network::test_server::{Reply, TestServer};
    use crate::sync::devicelist::DeviceList;
    use crate::sync::engine::create_entry;
    use crate::sync::state::{read_protected, state_path, write_protected};

    #[test]
    fn a_device_can_begin_pairing_before_it_is_approved_to_read_sync_state() {
        let server = TestServer::start(|request| {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/v1/sync/state");
            Reply::json(403, &serde_json::json!({"error":{"code":"sync_forbidden"}}))
        });
        let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
        assert_eq!(
            tauri::async_runtime::block_on(check_join_available(&client)),
            Ok(())
        );
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn joining_stops_when_the_account_has_no_vault_or_the_service_refuses_access() {
        for (status, code) in [
            (404, "sync_vault_not_found"),
            (401, "desktop_token_invalid"),
            (403, "sync_unavailable"),
            (403, "sync_not_entitled"),
            (503, "sync_failed"),
        ] {
            let server = TestServer::start(move |_| {
                Reply::json(status, &serde_json::json!({"error":{"code":code}}))
            });
            let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
            let result = tauri::async_runtime::block_on(check_join_available(&client));
            assert!(result.is_err(), "{code}");
            assert_eq!(server.requests().len(), 1, "{code}");
        }
    }

    fn pending() -> (DeviceIdentity, SyncState, KeyPackageV3) {
        let approver = DeviceIdentity::generate().expect("approver");
        let identity = DeviceIdentity::generate().expect("joining device");
        let vault_id = "fictionalVault00000001";
        let first = create_entry(&approver, vault_id, &URL_SAFE_NO_PAD.encode([7; 40]));
        let list = DeviceList::verify(std::slice::from_ref(&first)).expect("list");
        let signing_key = URL_SAFE_NO_PAD.encode(identity.signing_public_key());
        let package_key = URL_SAFE_NO_PAD.encode(identity.encryption_public_key());
        let added = add_entry(
            &approver,
            &list,
            &NewDevice {
                device_id: &identity.device_id,
                signing_key: &signing_key,
                package_key: &package_key,
            },
            &URL_SAFE_NO_PAD.encode([8; 40]),
            1,
        )
        .expect("add");
        let package = approver.sign_key_package(KeyPackageV3 {
            vault_id: vault_id.into(),
            sender_device_id: approver.device_id.clone(),
            recipient_device_id: identity.device_id.clone(),
            vault_epoch: 1,
            entry_digest: added.digest(),
            ciphertext: URL_SAFE_NO_PAD.encode([9; 64]),
            signature: String::new(),
        });
        let mut pending = SyncState::new(vault_id, &identity.device_id);
        pending.entries = vec![first, added];
        pending.floor = 1;
        pending.pending_join = Some(ApproverIdentity {
            device_id: approver.device_id.clone(),
            signing_key: URL_SAFE_NO_PAD.encode(approver.signing_public_key()),
            vault_id: vault_id.into(),
            head_digest: list.head_digest().into(),
        });
        (identity, pending, package)
    }

    #[test]
    fn a_lost_activation_response_preserves_the_join_and_retry_uses_the_same_device() {
        let (identity, pending, package) = pending();
        let requests = Arc::new(AtomicUsize::new(0));
        let attempts = requests.clone();
        let server = TestServer::start(move |request| {
            assert_eq!(request.path, "/v1/sync/activate");
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Reply::disconnect()
            } else {
                Reply::bytes(204, Vec::new())
            }
        });
        let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
        let directory = std::env::temp_dir().join(format!("sesame-join-{}", identity.device_id));
        let path = state_path(&directory);
        let adopted = Cell::new(0);
        let first = tauri::async_runtime::block_on(finish_join_transaction(
            &client,
            &identity,
            &package,
            pending.clone(),
            |state| write_protected(&path, state),
            || {
                adopted.set(adopted.get() + 1);
                Ok(())
            },
        ));
        assert!(first.is_err());
        assert_eq!(adopted.get(), 0);
        let retained = read_protected(&path).expect("pending join persists");
        assert_eq!(retained, pending);
        assert!(retained.require_join_complete().is_err());
        let mut altered = serde_json::to_value(&retained).expect("stored state");
        altered["pendingJoin"] = serde_json::Value::Null;
        std::fs::write(&path, serde_json::to_vec(&altered).expect("altered state"))
            .expect("write altered state");
        assert!(read_protected(&path).is_none());
        write_protected(&path, &retained).expect("restore approved state");
        tauri::async_runtime::block_on(finish_join_transaction(
            &client,
            &identity,
            &package,
            retained,
            |state| write_protected(&path, state),
            || {
                adopted.set(adopted.get() + 1);
                Ok(())
            },
        ))
        .expect("retry completes");
        let saved = read_protected(&path).expect("completed state");
        assert_eq!(saved.device_id, identity.device_id);
        assert_eq!(saved.entries, pending.entries);
        assert_eq!(saved.activated_epoch, 1);
        assert!(saved.pending_join.is_none());
        assert!(saved.require_join_complete().is_ok());
        assert_eq!(adopted.get(), 1);
        let recorded = server.requests();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].body, recorded[1].body);
        assert_ne!(
            recorded[0].headers["sesame-request-signature"],
            recorded[1].headers["sesame-request-signature"]
        );
        std::fs::remove_dir_all(directory).expect("remove fixture");
    }

    #[test]
    fn a_pending_join_that_cannot_be_saved_does_not_activate_or_replace_the_vault() {
        let (identity, pending, package) = pending();
        let server = TestServer::start(|_| Reply::bytes(204, Vec::new()));
        let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
        let result = tauri::async_runtime::block_on(finish_join_transaction(
            &client,
            &identity,
            &package,
            pending,
            |_| Err("fictional write failure".into()),
            || -> Result<(), String> { panic!("the local vault must remain untouched") },
        ));
        assert_eq!(result, Err("fictional write failure".into()));
        assert!(server.requests().is_empty());
    }

    #[test]
    fn a_failed_vault_replacement_preserves_the_pending_join() {
        let (identity, pending, package) = pending();
        let server = TestServer::start(|_| Reply::bytes(204, Vec::new()));
        let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
        let saved = std::cell::RefCell::new(None);
        let result = tauri::async_runtime::block_on(finish_join_transaction(
            &client,
            &identity,
            &package,
            pending.clone(),
            |state| {
                *saved.borrow_mut() = Some(state.clone());
                Ok(())
            },
            || -> Result<(), String> { Err("fictional vault replacement failure".into()) },
        ));
        assert_eq!(result, Err("fictional vault replacement failure".into()));
        assert_eq!(*saved.borrow(), Some(pending));
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn lost_pairing_responses_keep_the_authenticated_context_and_resume_without_pairing_again() {
        for lost in ["confirmation", "package", "device-list"] {
            let (identity, approved, package) = pending();
            let mut unfinished = approved.clone();
            unfinished.entries.clear();
            unfinished.floor = 0;
            unfinished.pending_confirmation = Some(URL_SAFE_NO_PAD.encode([7; pake::TAG_BYTES]));
            let confirmed = Arc::new(AtomicBool::new(false));
            let remote_confirmed = confirmed.clone();
            let package_reads = Arc::new(AtomicUsize::new(0));
            let remote_reads = package_reads.clone();
            let list_reads = Arc::new(AtomicUsize::new(0));
            let remote_lists = list_reads.clone();
            let served_package = package.clone();
            let entries = approved.entries.clone();
            let server = TestServer::start(move |request| match request.path.as_str() {
                "/v1/sync/key-package" => {
                    if lost != "device-list" && !remote_confirmed.load(Ordering::SeqCst) {
                        return Reply::json(
                            403,
                            &serde_json::json!({"error":{"code":"sync_forbidden"}}),
                        );
                    }
                    if lost == "package" && remote_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                        return Reply::disconnect();
                    }
                    Reply::json(200, &serde_json::json!({"package":served_package}))
                }
                "/v1/sync/pairings/mine" => Reply::json(
                    200,
                    &serde_json::json!({
                        "state": if remote_confirmed.load(Ordering::SeqCst) { "confirmed" } else { "answered" }
                    }),
                ),
                "/v1/sync/pairings/mine/confirm" => {
                    remote_confirmed.store(true, Ordering::SeqCst);
                    if lost == "confirmation" {
                        Reply::disconnect()
                    } else {
                        Reply::bytes(204, Vec::new())
                    }
                }
                "/v1/sync/device-list?after=0" => {
                    if lost == "device-list" && remote_lists.fetch_add(1, Ordering::SeqCst) == 0 {
                        return Reply::disconnect();
                    }
                    Reply::json(200, &serde_json::json!({"entries":entries}))
                }
                other => panic!("unexpected route {other}"),
            });
            let client = SyncClient::for_tests(&server.base(), "fictional-token", "unused");
            let directory =
                std::env::temp_dir().join(format!("sesame-join-{lost}-{}", identity.device_id));
            let path = state_path(&directory);
            let first = tauri::async_runtime::block_on(prepare_join(
                &client,
                &identity,
                unfinished.clone(),
                |state| write_protected(&path, state),
            ));
            assert!(first.is_err(), "{lost}");
            let retained = read_protected(&path).expect("the authenticated context persists");
            assert_eq!(retained, unfinished, "{lost}");
            if lost != "device-list" {
                assert!(confirmed.load(Ordering::SeqCst));
            }
            let (resumed, received) = tauri::async_runtime::block_on(prepare_join(
                &client,
                &identity,
                retained,
                |state| write_protected(&path, state),
            ))
            .expect("retry resumes the same pairing");
            assert_eq!(received, package);
            assert_eq!(resumed.device_id, identity.device_id);
            assert_eq!(resumed.entries, approved.entries);
            assert_eq!(resumed.pending_join, approved.pending_join);
            assert!(resumed.pending_confirmation.is_none());
            assert!(resumed.require_join_complete().is_err());
            assert_eq!(read_protected(&path), Some(resumed));
            assert!(server
                .requests()
                .iter()
                .all(|request| request.path != "/v1/sync/pairings"));
            assert_eq!(
                server
                    .requests()
                    .iter()
                    .filter(|request| request.path == "/v1/sync/pairings/mine/confirm")
                    .count(),
                usize::from(lost != "device-list")
            );
            std::fs::remove_dir_all(directory).expect("remove fixture");
        }
    }
}
