use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::devicelist::DeviceListEntry;
use crate::engine::{verify_join, JoinCheck};
use crate::identity::DeviceIdentity;
use crate::pairing::ApproverIdentity;
use crate::request::KeyPackageV3;
use crate::state::{
    decide_upload, pending_outcome, PendingOutcome, PendingUpload, SyncState, UploadDecision,
};
use crate::wire::{PairingStatus, StateView, SyncError};

pub const NOT_ACTIVATED: &str =
    "This device has not taken the new vault key yet. Open Sync and take it.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferChoice {
    Upload,
    Download { server_revision: u64 },
    AlreadyCurrent,
}

pub fn plan_transfer(
    local: &SyncState,
    server: &StateView,
    local_payload: &[u8],
) -> TransferChoice {
    if local.has_local_changes(local_payload) {
        return TransferChoice::Upload;
    }
    if server.current_revision > local.head_revision() {
        return TransferChoice::Download {
            server_revision: server.current_revision,
        };
    }
    TransferChoice::AlreadyCurrent
}

pub fn plan_upload(local: &SyncState, server: &StateView) -> UploadDecision {
    decide_upload(local.head_revision(), server.current_revision)
}

pub fn require_activated(server: &StateView) -> Result<(), String> {
    if server.device_state != "approved" {
        return Err("This device is not approved to sync.".into());
    }
    if server.activated_epoch != server.vault_epoch {
        return Err(NOT_ACTIVATED.into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingUploadAction {
    None,
    Adopt,
    Clear,
}

pub fn pending_upload_action(
    local: &SyncState,
    pending: &PendingUpload,
    server: &StateView,
    head_digest: Option<&str>,
) -> PendingUploadAction {
    match pending_outcome(
        pending,
        local.head_revision(),
        server.current_revision,
        head_digest,
    ) {
        PendingOutcome::Landed => PendingUploadAction::Adopt,
        PendingOutcome::NotLanded | PendingOutcome::Diverged => PendingUploadAction::Clear,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinAction {
    WaitForAnswer,
    Confirm { confirmation: Vec<u8> },
    WaitForKeyPackage,
}

pub fn join_action(pending: &SyncState, status: &PairingStatus) -> Result<JoinAction, String> {
    match status.state.as_str() {
        "answered" => {
            let confirmation = pending
                .pending_confirmation
                .as_deref()
                .ok_or("The saved pairing confirmation is missing. Start joining again.")?;
            let confirmation = URL_SAFE_NO_PAD
                .decode(confirmation)
                .map_err(|_| "The saved pairing confirmation could not be read.".to_string())?;
            Ok(JoinAction::Confirm { confirmation })
        }
        "confirmed" => Ok(JoinAction::WaitForKeyPackage),
        _ => Err("The other device has not answered this pairing. Start joining again.".into()),
    }
}

pub fn join_available(state: Result<&StateView, &SyncError>) -> Result<(), String> {
    match state {
        Ok(_) | Err(SyncError::NotApproved) => Ok(()),
        Err(SyncError::NotFound) => Err(
            "This account has no synced vault yet. Set it up on your other device first.".into(),
        ),
        Err(other) => Err(other.to_string()),
    }
}

pub fn apply_join_package(
    pending: &mut SyncState,
    identity: &DeviceIdentity,
    entries: &[DeviceListEntry],
    package: &KeyPackageV3,
) -> Result<(), String> {
    let approver = pending
        .pending_join
        .as_ref()
        .ok_or("This device has no unfinished join.")?;
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
        entries,
        package,
    )
    .map_err(|error| error.to_string())?;
    pending.floor = crate::engine::floor_for(entries, &identity.device_id);
    pending.entries = entries.to_vec();
    pending.pending_confirmation = None;
    Ok(())
}

pub fn new_join_state(
    identity: &DeviceIdentity,
    approver: &ApproverIdentity,
    confirmation: &[u8],
) -> SyncState {
    let mut pending = SyncState::new(&approver.vault_id, &identity.device_id);
    pending.pending_join = Some(approver.clone());
    pending.pending_confirmation = Some(URL_SAFE_NO_PAD.encode(confirmation));
    pending
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::payload_digest;

    fn local(revision: u64, digest: &str) -> SyncState {
        let mut state = SyncState::new("vaultAAAAAAAAAAAA01", "deviceAAAAAAAAAAAAAA01");
        state.payload_digest = digest.to_string();
        state.head = Some(header(revision));
        state
    }

    fn header(revision: u64) -> crate::header::Header {
        crate::header::Header {
            version: 3,
            vault_id: "vaultAAAAAAAAAAAA01".into(),
            device_id: "deviceAAAAAAAAAAAAAA01".into(),
            revision,
            vault_epoch: 1,
            device_list_index: 1,
            device_list_digest: "listdigest".into(),
            previous_digest: String::new(),
            ciphertext_digest: "ciphertextdigest".into(),
            ciphertext_length: 10,
            nonce: "nonce".into(),
            signature: "signature".into(),
        }
    }

    fn server(revision: u64) -> StateView {
        StateView {
            vault_id: "vaultAAAAAAAAAAAA01".into(),
            vault_epoch: 1,
            current_revision: revision,
            device_state: "approved".into(),
            activated_epoch: 1,
        }
    }

    #[test]
    fn local_changes_win_over_a_newer_server_revision() {
        let state = local(3, &payload_digest(b"old"));
        assert_eq!(
            plan_transfer(&state, &server(5), b"new"),
            TransferChoice::Upload
        );
    }

    #[test]
    fn a_clean_device_downloads_only_when_the_server_is_ahead() {
        let digest = payload_digest(b"same");
        let state = local(3, &digest);
        assert_eq!(
            plan_transfer(&state, &server(4), b"same"),
            TransferChoice::Download { server_revision: 4 }
        );
        assert_eq!(
            plan_transfer(&state, &server(3), b"same"),
            TransferChoice::AlreadyCurrent
        );
    }

    #[test]
    fn an_unactivated_or_unapproved_device_is_refused() {
        assert_eq!(require_activated(&server(1)), Ok(()));
        let mut unapproved = server(1);
        unapproved.device_state = "pairing".into();
        assert!(require_activated(&unapproved).is_err());
        let mut not_activated = server(1);
        not_activated.activated_epoch = 0;
        assert_eq!(
            require_activated(&not_activated),
            Err(NOT_ACTIVATED.to_string())
        );
    }

    #[test]
    fn a_pending_upload_is_adopted_only_when_the_service_names_it() {
        let state = local(3, &payload_digest(b"same"));
        let pending = PendingUpload {
            header: header(4),
            payload_digest: payload_digest(b"new"),
        };
        let digest = pending.header.digest();
        assert_eq!(
            pending_upload_action(&state, &pending, &server(4), Some(&digest)),
            PendingUploadAction::Adopt
        );
        assert_eq!(
            pending_upload_action(&state, &pending, &server(3), None),
            PendingUploadAction::Clear
        );
    }

    #[test]
    fn an_answered_pairing_needs_the_saved_confirmation() {
        let mut state = SyncState::new("vaultAAAAAAAAAAAA01", "deviceAAAAAAAAAAAAAA01");
        let status = PairingStatus {
            state: "answered".into(),
            answer: Some("answer".into()),
        };
        assert!(join_action(&state, &status).is_err());
        state.pending_confirmation = Some(URL_SAFE_NO_PAD.encode(b"confirmation"));
        assert_eq!(
            join_action(&state, &status),
            Ok(JoinAction::Confirm {
                confirmation: b"confirmation".to_vec()
            })
        );
        let confirmed = PairingStatus {
            state: "confirmed".into(),
            answer: None,
        };
        assert_eq!(
            join_action(&state, &confirmed),
            Ok(JoinAction::WaitForKeyPackage)
        );
    }

    #[test]
    fn join_availability_separates_a_missing_vault_from_other_errors() {
        assert!(join_available(Ok(&server(1))).is_ok());
        assert!(join_available(Err(&SyncError::NotApproved)).is_ok());
        assert!(join_available(Err(&SyncError::NotFound)).is_err());
        assert!(join_available(Err(&SyncError::Conflict)).is_err());
    }
}
