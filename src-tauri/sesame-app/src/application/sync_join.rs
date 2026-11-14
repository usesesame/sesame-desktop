use std::future::Future;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use zeroize::Zeroize;

use crate::application::sync::{present, present_proof, SyncStore};
use crate::application::sync_adopt::{digest_after_commit, finish_adoption_in_state};
use crate::application::sync_pairing::{
    cancelled, clean_join_label, reset_cancellation, verify_master_password_now_in_state,
    PAIRING_WINDOW,
};
use crate::application::DesktopEffects;
use crate::sync::client::{SyncClient, SyncError};
use crate::sync::engine::{verify_join, verify_server_view, JoinCheck, ServerView};
use crate::sync::identity::DeviceIdentity;
use crate::sync::pairing::ApproverIdentity;
use crate::sync::pake::Offer;
use crate::sync::request::KeyPackageV3;
use crate::sync::state::SyncState;
use crate::vault::VaultState;

const APPROVAL_WAIT: Duration = Duration::from_secs(2 * 60);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncAdoptResult {
    pub entry_count: usize,
    pub revision: u64,
    pub recovery_kit: String,
}

pub struct JoinRequest<'a> {
    pub code: &'a str,
    pub label: &'a str,
    pub master_password: &'a str,
    pub pending: Option<SyncState>,
}

pub struct PreparedJoin {
    pub pending: SyncState,
    pub package: KeyPackageV3,
}

pub fn join_preflight_in_state(
    state: &VaultState,
    store: &SyncStore,
    label: &str,
    master_password: &str,
) -> Result<(String, Option<SyncState>), String> {
    reset_cancellation();
    let label = clean_join_label(label)?;
    let pending = store.load_join_state()?;
    if pending
        .as_ref()
        .is_some_and(|pending| pending.pending_join.is_none())
    {
        return Err("Sesame Sync is already set up on this device.".into());
    }
    verify_master_password_now_in_state(state, master_password)?;
    Ok((label, pending))
}

pub async fn join_with_code_in_state<P, F>(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    client: &SyncClient,
    request: JoinRequest<'_>,
    pause: P,
) -> Result<SyncAdoptResult, String>
where
    P: Fn() -> F,
    F: Future<Output = ()>,
{
    let JoinRequest {
        code,
        label,
        master_password,
        pending,
    } = request;
    check_join_available(client).await?;
    let path = store.identity_path();
    if let Some(pending) = pending {
        let identity = store.this_identity()?;
        if pending.device_id != identity.device_id {
            return Err("The stored joining device does not match this device's keys.".into());
        }
        let (pending, package) = prepare_join(
            client,
            &identity,
            pending,
            |state| store.save_state(state),
            &pause,
        )
        .await?;
        return complete_join(
            state,
            store,
            effects,
            client,
            &identity,
            PreparedJoin { pending, package },
            master_password,
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
        state,
        store,
        effects,
        client,
        &identity,
        &JoinRequest {
            code,
            label,
            master_password,
            pending: None,
        },
        &pause,
    )
    .await;
    if outcome.is_err()
        && store.load_join_state()?.is_none()
        && client
            .state()
            .await
            .is_ok_and(|server| server.device_state != "approved")
    {
        let _ = client.cancel_pairing(&identity, &identity.device_id).await;
        let _ = store.forget_everything();
    }
    outcome
}

pub async fn check_join_available(client: &SyncClient) -> Result<(), String> {
    match client.state().await {
        Ok(_) | Err(SyncError::NotApproved) => Ok(()),
        Err(SyncError::NotFound) => Err(
            "This account has no synced vault yet. Set it up on your other device first.".into(),
        ),
        Err(other) => Err(present(other)),
    }
}

async fn join<P, F>(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    client: &SyncClient,
    identity: &DeviceIdentity,
    request: &JoinRequest<'_>,
    pause: &P,
) -> Result<SyncAdoptResult, String>
where
    P: Fn() -> F,
    F: Future<Output = ()>,
{
    let code = request.code;
    let label = request.label;
    let master_password = request.master_password;
    let started = Instant::now();
    let signing_key = URL_SAFE_NO_PAD.encode(identity.signing_public_key());
    let package_key = URL_SAFE_NO_PAD.encode(identity.package_public_key());
    let ad = crate::sync::pairing::NewDeviceIdentity {
        device_id: identity.device_id.clone(),
        signing_key: signing_key.clone(),
        package_key: crate::sync::pairing::package_key_commitment(&package_key),
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
    let (pending, package) = prepare_join(
        client,
        identity,
        pending,
        |state| store.save_state(state),
        pause,
    )
    .await?;
    complete_join(
        state,
        store,
        effects,
        client,
        identity,
        PreparedJoin { pending, package },
        master_password,
    )
    .await
}

pub async fn prepare_join<P, F>(
    client: &SyncClient,
    identity: &DeviceIdentity,
    mut pending: SyncState,
    mut persist: impl FnMut(&SyncState) -> Result<(), String>,
    pause: &P,
) -> Result<(SyncState, KeyPackageV3), String>
where
    P: Fn() -> F,
    F: Future<Output = ()>,
{
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
            wait_for_package(client, pause).await?
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
            package_key: &URL_SAFE_NO_PAD.encode(identity.package_public_key()),
            approver,
        },
        &entries,
        &package,
    )
    .map_err(present_proof)?;
    pending.floor = crate::sync::engine::floor_for(&entries, &identity.device_id);
    pending.entries = entries;
    pending.pending_confirmation = None;
    persist(&pending)?;
    Ok((pending, package))
}

async fn wait_for_package<P, F>(client: &SyncClient, pause: &P) -> Result<KeyPackageV3, String>
where
    P: Fn() -> F,
    F: Future<Output = ()>,
{
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

pub async fn complete_join(
    state: &VaultState,
    store: &SyncStore,
    effects: &dyn DesktopEffects,
    client: &SyncClient,
    identity: &DeviceIdentity,
    prepared: PreparedJoin,
    master_password: &str,
) -> Result<SyncAdoptResult, String> {
    let PreparedJoin {
        mut pending,
        package,
    } = prepared;
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
            package_key: &URL_SAFE_NO_PAD.encode(identity.package_public_key()),
            approver,
        },
        &entries,
        &package,
    )
    .map_err(present_proof)?;
    let sealed = URL_SAFE_NO_PAD
        .decode(&package.ciphertext)
        .map_err(|_| "The key package could not be read.".to_string())?;
    let mut opened = identity.open_key_package(&sealed, &approver.vault_id, package.vault_epoch)?;
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
    let digest = digest_after_commit(&payload)?;

    pending.entries = entries;
    pending.head = update.head;
    pending.payload_digest = digest;
    pending.receipt = update.receipt;
    let vault_id = pending.vault_id.clone();
    let recovery_kit = finish_join_transaction(
        client,
        identity,
        &package,
        pending,
        |state| store.save_state(state),
        || {
            finish_adoption_in_state(
                state,
                store,
                effects,
                key,
                payload,
                master_password,
                &vault_id,
            )
        },
    )
    .await?;
    Ok(SyncAdoptResult {
        entry_count,
        revision: head.revision,
        recovery_kit,
    })
}

pub async fn finish_join_transaction<T>(
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
