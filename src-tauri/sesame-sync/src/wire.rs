use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::checkpoint::Checkpoint;
use crate::devicelist::DeviceListEntry;
use crate::engine::{ServedCheckpoint, ServedHeader};
use crate::header::Header;
use crate::identity::DeviceIdentity;
use crate::request::{KeyPackageV3, RequestSignature};
use crate::xwing::PUBLIC_KEY_BYTES;

pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const HEADER_PAGE_SIZE: usize = 500;
pub const MAX_HEADERS: usize = 20_000;
pub const SERVER_NEEDS_UPDATE: &str = "This Sync server does not accept the newer device keys yet. If you run the server yourself, update it and try again. Otherwise try again later.";

pub const PATH_STATE: &str = "/v1/sync/state";
pub const PATH_VAULT: &str = "/v1/sync/vault";
pub const PATH_DEVICE_LIST: &str = "/v1/sync/device-list";
pub const PATH_DEVICES: &str = "/v1/sync/devices";
pub const PATH_DEVICES_REMOVE: &str = "/v1/sync/devices/remove";
pub const PATH_DEVICES_KEY: &str = "/v1/sync/devices/key";
pub const PATH_DEVICES_ROTATE: &str = "/v1/sync/devices/rotate";
pub const PATH_PAIRINGS: &str = "/v1/sync/pairings";
pub const PATH_PAIRING_MINE: &str = "/v1/sync/pairings/mine";
pub const PATH_PAIRING_CONFIRM: &str = "/v1/sync/pairings/mine/confirm";
pub const PATH_KEY_PACKAGE: &str = "/v1/sync/key-package";
pub const PATH_ACTIVATE: &str = "/v1/sync/activate";
pub const PATH_SNAPSHOTS: &str = "/v1/sync/snapshots";
pub const PATH_SNAPSHOT: &str = "/v1/sync/snapshot";
pub const PATH_HEADERS: &str = "/v1/sync/headers";
pub const PATH_CHECKPOINTS: &str = "/v1/sync/checkpoints";
pub const PATH_RESET: &str = "/v1/sync/reset";

pub fn device_list_path(after: u64) -> String {
    format!("{PATH_DEVICE_LIST}?after={after}")
}

pub fn headers_path(after: u64) -> String {
    format!("{PATH_HEADERS}?after={after}&limit={HEADER_PAGE_SIZE}")
}

pub fn pairing_answer_path(device_id: &str) -> String {
    format!("{PATH_PAIRINGS}/{device_id}/answer")
}

pub fn pairing_cancel_path(device_id: &str) -> String {
    format!("{PATH_PAIRINGS}/{device_id}")
}

pub const SYNC_TURNED_OFF: &str = "Sesame Sync is turned off on this server, so this device cannot sync. Your vault on this device still works. Ask whoever runs the server to turn Sync on.";
pub const SYNC_NOT_AVAILABLE: &str = "Sesame Sync is not available.";
pub const LINK_ENDED: &str = "This desktop is no longer linked to your Sesame account. Link it again in Settings with a new one-time code. If Sync still does not resume, turn Sync off on this device and join again with a code from another device.";
pub const BUSY_DEFAULT_SECS: u64 = 5;
pub const RATE_LIMITED_DEFAULT_SECS: u64 = 30;
pub const RETRY_AFTER_MIN_SECS: u64 = 1;
pub const RETRY_AFTER_MAX_SECS: u64 = 300;

#[derive(Debug)]
pub enum SyncError {
    Unavailable(String),
    Conflict,
    NotApproved,
    NotActivated,
    NotEntitled,
    NotFound,
    StorageFull,
    TooLarge,
    Busy { retry_after_secs: u64 },
    RateLimited { retry_after_secs: u64 },
    LinkEnded,
    Unreachable,
    Rejected,
    ServerNeedsUpdate,
    Failed(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) | Self::Failed(message) => write!(formatter, "{message}"),
            Self::Conflict => write!(
                formatter,
                "Another device changed this vault. Review the difference before syncing."
            ),
            Self::NotApproved => write!(formatter, "This device is not approved to sync."),
            Self::NotActivated => write!(
                formatter,
                "This device has not taken the new vault key yet."
            ),
            Self::NotEntitled => write!(
                formatter,
                "This account's subscription does not include Sesame Sync."
            ),
            Self::NotFound => write!(formatter, "That Sync record does not exist."),
            Self::StorageFull => write!(
                formatter,
                "This vault is too large for the space the service gives it."
            ),
            Self::TooLarge => write!(formatter, "This vault is too large for Sesame Sync."),
            Self::Busy { .. } => write!(
                formatter,
                "Sesame Sync is busy right now. Try again in a few seconds."
            ),
            Self::RateLimited { .. } => write!(
                formatter,
                "This device sent Sesame Sync too many requests. Wait a minute, then try again."
            ),
            Self::LinkEnded => write!(formatter, "{LINK_ENDED}"),
            Self::Unreachable => write!(formatter, "Sesame could not reach Sesame Sync."),
            Self::Rejected => write!(formatter, "Sesame Sync could not complete that request."),
            Self::ServerNeedsUpdate => write!(formatter, "{SERVER_NEEDS_UPDATE}"),
        }
    }
}

impl From<SyncError> for String {
    fn from(error: SyncError) -> Self {
        error.to_string()
    }
}

pub type SyncResult<T> = Result<T, SyncError>;

pub fn is_hybrid_package_key(encoded: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .is_ok_and(|bytes| bytes.len() == PUBLIC_KEY_BYTES)
}

pub fn name_the_server_without_the_route(error: SyncError) -> SyncError {
    match error {
        SyncError::Rejected | SyncError::NotFound => SyncError::ServerNeedsUpdate,
        other => other,
    }
}

pub fn name_the_old_server(error: SyncError, package_key: &str) -> SyncError {
    match error {
        SyncError::Rejected if is_hybrid_package_key(package_key) => SyncError::ServerNeedsUpdate,
        other => other,
    }
}

pub fn retry_after_secs(header: Option<&str>, default: u64) -> u64 {
    header
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .map(|value| value.parse::<u64>().unwrap_or(u64::MAX))
        .unwrap_or(default)
        .clamp(RETRY_AFTER_MIN_SECS, RETRY_AFTER_MAX_SECS)
}

pub fn classify(
    status: u16,
    retry_after: Option<&str>,
    body: &[u8],
    entitlement_enforced: bool,
) -> SyncError {
    let parsed: Option<ErrorEnvelope> = serde_json::from_slice(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|envelope| envelope.error.as_ref())
        .map(|error| error.code.as_str())
        .unwrap_or_default();
    match (status, code) {
        (503, _) => {
            return SyncError::Busy {
                retry_after_secs: retry_after_secs(retry_after, BUSY_DEFAULT_SECS),
            }
        }
        (429, _) => {
            return SyncError::RateLimited {
                retry_after_secs: retry_after_secs(retry_after, RATE_LIMITED_DEFAULT_SECS),
            }
        }
        (413, "sync_storage_limit_reached") => return SyncError::StorageFull,
        (413, _) => return SyncError::TooLarge,
        (401, code) if code != "sync_signature_invalid" => return SyncError::LinkEnded,
        (403, "sync_unavailable") => return SyncError::Unavailable(SYNC_TURNED_OFF.into()),
        _ => {}
    }
    match code {
        "sync_unavailable" => SyncError::Unavailable(SYNC_NOT_AVAILABLE.into()),
        "sync_not_entitled" if entitlement_enforced => SyncError::NotEntitled,
        "sync_not_entitled" => SyncError::Unavailable(SYNC_NOT_AVAILABLE.into()),
        "sync_not_activated" => SyncError::NotActivated,
        "sync_forbidden" => SyncError::NotApproved,
        "sync_vault_not_found" | "sync_not_found" => SyncError::NotFound,
        "sync_conflict" | "sync_vault_exists" => SyncError::Conflict,
        "sync_storage_limit_reached" => SyncError::StorageFull,
        "sync_invalid" => SyncError::Rejected,
        "sync_signature_invalid" => SyncError::Failed(
            "The service did not accept this device's signature. Check that the date and time on this computer are correct."
                .into(),
        ),
        "sync_replayed" => SyncError::Failed(
            "The service saw that request twice. Try again.".into(),
        ),
        _ => match status {
            403 => SyncError::Unavailable(SYNC_NOT_AVAILABLE.into()),
            404 => SyncError::NotFound,
            _ => SyncError::Failed("Sesame Sync could not complete that request.".into()),
        },
    }
}

pub fn parse<T: DeserializeOwned>(bytes: &[u8]) -> SyncResult<T> {
    serde_json::from_slice(bytes)
        .map_err(|_| SyncError::Failed("Sesame could not read the Sync response.".into()))
}

pub fn encode<T: Serialize + ?Sized>(value: &T) -> SyncResult<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|_| SyncError::Failed("Sesame could not prepare the request.".into()))
}

pub fn request_signature_header(
    identity: &DeviceIdentity,
    method: &str,
    target: &str,
    body: &[u8],
    token: &str,
    timestamp: u64,
    nonce: &str,
) -> String {
    let signature = identity.sign_request(&RequestSignature {
        method,
        target,
        body,
        token,
        timestamp,
        nonce,
    });
    format!("{timestamp}.{nonce}.{signature}")
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StateView {
    pub vault_id: String,
    pub vault_epoch: u64,
    pub current_revision: u64,
    pub device_state: String,
    pub activated_epoch: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PairingRecord {
    pub device_id: String,
    pub signing_key: String,
    pub package_key: String,
    pub state: String,
    pub offer: String,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct DevicesView {
    pub pairings: Vec<PairingRecord>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PairingStatus {
    pub state: String,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub answer: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Accepted {
    pub revision: u64,
    pub digest: String,
    pub receipt: String,
    pub accepted_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServedSnapshot {
    pub header: Header,
    pub accepted_at: String,
    pub ciphertext: String,
}

fn empty_as_none<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.filter(|text| !text.is_empty()))
}

#[derive(Deserialize)]
pub struct Entries {
    pub entries: Vec<DeviceListEntry>,
}

#[derive(Deserialize)]
pub struct Headers {
    pub headers: Vec<ServedHeader>,
}

#[derive(Deserialize)]
pub struct Checkpoints {
    pub checkpoints: Vec<ServedCheckpoint>,
}

#[derive(Serialize)]
pub struct CheckpointBody<'a> {
    pub checkpoint: &'a Checkpoint,
}

#[derive(Deserialize)]
pub struct PackageBody {
    pub package: KeyPackageV3,
}

#[derive(Serialize)]
pub struct CreateVaultBody<'a> {
    pub entry: &'a DeviceListEntry,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BeginPairingBody<'a> {
    pub device_id: &'a str,
    pub signing_key: &'a str,
    pub package_key: &'a str,
    pub message: &'a str,
}

#[derive(Serialize)]
pub struct MessageBody<'a> {
    pub message: &'a str,
}

#[derive(Serialize)]
pub struct ApproveBody<'a> {
    pub entry: &'a DeviceListEntry,
    pub package: &'a KeyPackageV3,
}

#[derive(Serialize)]
pub struct UpgradeKeyBody<'a> {
    pub entry: &'a DeviceListEntry,
}

#[derive(Serialize)]
pub struct RemoveBody<'a> {
    pub entry: &'a DeviceListEntry,
    pub packages: &'a [KeyPackageV3],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateBody<'a> {
    pub package_digest: &'a str,
}

#[derive(Serialize)]
pub struct UploadBody<'a> {
    pub header: &'a Header,
    pub ciphertext: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetBody {
    pub vault_epoch: u64,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    #[serde(default)]
    error: Option<ErrorBody>,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    code: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        ActivateBody, BeginPairingBody, CheckpointBody, CreateVaultBody, MessageBody, RemoveBody,
        ResetBody, UploadBody,
    };
    use serde_json::json;

    #[test]
    fn the_complete_error_mapping_is_stable() {
        let cases = [
            (
                "sync_unavailable",
                403,
                SyncError::Unavailable(SYNC_TURNED_OFF.into()),
            ),
            (
                "sync_unavailable",
                400,
                SyncError::Unavailable(SYNC_NOT_AVAILABLE.into()),
            ),
            (
                "sync_unavailable",
                503,
                SyncError::Busy {
                    retry_after_secs: 5,
                },
            ),
            (
                "rate_limit_unavailable",
                503,
                SyncError::Busy {
                    retry_after_secs: 5,
                },
            ),
            (
                "too_many_attempts",
                429,
                SyncError::RateLimited {
                    retry_after_secs: 5,
                },
            ),
            ("sync_not_activated", 403, SyncError::NotActivated),
            ("sync_forbidden", 403, SyncError::NotApproved),
            ("sync_vault_not_found", 404, SyncError::NotFound),
            ("sync_not_found", 404, SyncError::NotFound),
            ("sync_conflict", 409, SyncError::Conflict),
            ("sync_vault_exists", 409, SyncError::Conflict),
            ("sync_storage_limit_reached", 413, SyncError::StorageFull),
            ("sync_too_large", 413, SyncError::TooLarge),
            ("sync_invalid", 400, SyncError::Rejected),
            ("not_authenticated", 401, SyncError::LinkEnded),
            (
                "sync_signature_invalid",
                401,
                SyncError::Failed(
                    "The service did not accept this device's signature. Check that the date and time on this computer are correct."
                        .into(),
                ),
            ),
        ];
        for (code, status, expected) in cases {
            let body = serde_json::to_vec(&json!({"error":{"code":code}})).unwrap();
            assert_eq!(
                format!("{:?}", classify(status, Some("5"), &body, true)),
                format!("{:?}", expected),
                "{code} {status}"
            );
        }
        assert!(matches!(
            classify(400, None, b"{}", true),
            SyncError::Failed(_)
        ));
    }

    #[test]
    fn entitlement_is_enforced_only_for_the_official_service() {
        let body = br#"{"error":{"code":"sync_not_entitled"}}"#;
        assert!(matches!(
            classify(402, None, body, true),
            SyncError::NotEntitled
        ));
        assert!(matches!(
            classify(402, None, body, false),
            SyncError::Unavailable(_)
        ));
    }

    #[test]
    fn unknown_codes_fall_back_to_the_http_status() {
        assert!(matches!(
            classify(401, None, b"{}", false),
            SyncError::LinkEnded
        ));
        assert!(matches!(
            classify(403, None, b"{}", false),
            SyncError::Unavailable(_)
        ));
        assert!(matches!(
            classify(404, None, b"{}", false),
            SyncError::NotFound
        ));
        assert!(matches!(
            classify(413, None, b"not json", false),
            SyncError::TooLarge
        ));
        assert!(matches!(
            classify(500, None, b"{}", false),
            SyncError::Failed(_)
        ));
    }

    #[test]
    fn a_busy_answer_waits_as_told_within_safe_bounds() {
        let busy = |header: Option<&str>| match classify(503, header, b"", false) {
            SyncError::Busy { retry_after_secs } => retry_after_secs,
            _ => 0,
        };
        assert_eq!(busy(Some("5")), 5);
        assert_eq!(busy(Some(" 42 ")), 42);
        assert_eq!(busy(None), BUSY_DEFAULT_SECS);
        assert_eq!(busy(Some("")), BUSY_DEFAULT_SECS);
        assert_eq!(busy(Some("soon")), BUSY_DEFAULT_SECS);
        assert_eq!(busy(Some("-5")), BUSY_DEFAULT_SECS);
        assert_eq!(busy(Some("2.5")), BUSY_DEFAULT_SECS);
        assert_eq!(
            busy(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
            BUSY_DEFAULT_SECS
        );
        assert_eq!(busy(Some("0")), RETRY_AFTER_MIN_SECS);
        assert_eq!(busy(Some("86400")), RETRY_AFTER_MAX_SECS);
        assert_eq!(
            busy(Some("99999999999999999999999999")),
            RETRY_AFTER_MAX_SECS
        );
    }

    #[test]
    fn a_rate_limit_without_a_usable_wait_falls_back_to_its_own_default() {
        for header in [None, Some("later"), Some("")] {
            assert!(matches!(
                classify(429, header, b"{}", false),
                SyncError::RateLimited {
                    retry_after_secs: RATE_LIMITED_DEFAULT_SECS
                }
            ));
        }
        assert!(matches!(
            classify(429, Some("12"), b"{}", false),
            SyncError::RateLimited {
                retry_after_secs: 12
            }
        ));
    }

    #[test]
    fn the_signature_header_is_the_timestamp_nonce_and_signature() {
        let identity = DeviceIdentity::generate().expect("identity");
        let header = request_signature_header(
            &identity,
            "POST",
            "/v1/sync/snapshots",
            b"{\"a\":1}",
            "fictional-token",
            1_800_000_000,
            "fictional-nonce",
        );
        let parts: Vec<&str> = header.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "1800000000");
        assert_eq!(parts[1], "fictional-nonce");
        let payload = RequestSignature {
            method: "POST",
            target: "/v1/sync/snapshots",
            body: b"{\"a\":1}",
            token: "fictional-token",
            timestamp: 1_800_000_000,
            nonce: "fictional-nonce",
        }
        .signing_payload();
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("signature");
        let signature = ed25519_dalek::Signature::from_slice(&signature).expect("signature");
        ed25519_dalek::VerifyingKey::from_bytes(&identity.signing_public_key())
            .expect("key")
            .verify_strict(&payload, &signature)
            .expect("verified");
    }

    #[test]
    fn a_hybrid_package_key_is_recognised_only_at_its_exact_length() {
        assert!(is_hybrid_package_key(
            &URL_SAFE_NO_PAD.encode([7u8; PUBLIC_KEY_BYTES])
        ));
        assert!(!is_hybrid_package_key(
            &URL_SAFE_NO_PAD.encode([7u8; PUBLIC_KEY_BYTES - 1])
        ));
        assert!(!is_hybrid_package_key(&URL_SAFE_NO_PAD.encode([7u8; 32])));
        assert!(!is_hybrid_package_key("not base64!"));
    }

    #[test]
    fn an_old_server_rejection_names_the_update_only_for_hybrid_keys() {
        let hybrid = URL_SAFE_NO_PAD.encode([5u8; PUBLIC_KEY_BYTES]);
        let classical = URL_SAFE_NO_PAD.encode([5u8; 32]);
        assert!(matches!(
            name_the_old_server(SyncError::Rejected, &hybrid),
            SyncError::ServerNeedsUpdate
        ));
        assert!(matches!(
            name_the_old_server(SyncError::Rejected, &classical),
            SyncError::Rejected
        ));
        assert!(matches!(
            name_the_server_without_the_route(SyncError::NotFound),
            SyncError::ServerNeedsUpdate
        ));
    }

    #[test]
    fn the_wire_paths_carry_their_query_and_device_id() {
        assert_eq!(device_list_path(7), "/v1/sync/device-list?after=7");
        assert_eq!(headers_path(3), "/v1/sync/headers?after=3&limit=500");
        assert_eq!(
            pairing_answer_path("deviceAAAAAAAAAAAAAA01"),
            "/v1/sync/pairings/deviceAAAAAAAAAAAAAA01/answer"
        );
        assert_eq!(
            pairing_cancel_path("deviceAAAAAAAAAAAAAA01"),
            "/v1/sync/pairings/deviceAAAAAAAAAAAAAA01"
        );
    }

    #[test]
    fn request_body_fields_match_the_wire_names() {
        let value = serde_json::to_value(BeginPairingBody {
            device_id: "deviceAAAAAAAAAAAAAA01",
            signing_key: "signing",
            package_key: "package",
            message: "message",
        })
        .unwrap();
        assert!(value.get("deviceId").is_some());
        assert!(value.get("signingKey").is_some());
        assert!(value.get("packageKey").is_some());
        let activate = serde_json::to_value(ActivateBody {
            package_digest: "digest",
        })
        .unwrap();
        assert_eq!(activate["packageDigest"], "digest");
        let reset = serde_json::to_value(ResetBody { vault_epoch: 2 }).unwrap();
        assert_eq!(reset["vaultEpoch"], 2);
        let _ = serde_json::to_value(MessageBody { message: "m" }).unwrap();
        let _ = serde_json::to_value(CheckpointBody {
            checkpoint: &fictional_checkpoint(),
        })
        .unwrap();
        let _ = serde_json::to_value(CreateVaultBody {
            entry: &fictional_entry(),
        })
        .unwrap();
        let _ = serde_json::to_value(UploadBody {
            header: &fictional_header(),
            ciphertext: "ciphertext",
        })
        .unwrap();
        let _ = serde_json::to_value(RemoveBody {
            entry: &fictional_entry(),
            packages: &[],
        })
        .unwrap();
    }

    fn fictional_checkpoint() -> Checkpoint {
        Checkpoint {
            version: 3,
            vault_id: "vaultAAAAAAAAAAAA01".into(),
            device_id: "deviceAAAAAAAAAAAAAA01".into(),
            device_list_index: 1,
            device_list_digest: "listdigest".into(),
            header_revision: 1,
            header_digest: "headerdigest".into(),
            observed_at: 1_800_000_000,
            signature: "signature".into(),
        }
    }

    fn fictional_entry() -> DeviceListEntry {
        DeviceListEntry {
            vault_id: "vaultAAAAAAAAAAAA01".into(),
            index: 1,
            previous_digest: String::new(),
            kind: crate::devicelist::ENTRY_CREATE.into(),
            signer_device_id: "deviceAAAAAAAAAAAAAA01".into(),
            subject_device_id: "deviceAAAAAAAAAAAAAA01".into(),
            subject_signing_key: "signing".into(),
            subject_package_key: "package".into(),
            sealed_label: "label".into(),
            epoch_after: 1,
            snapshot_floor: 0,
            signature: "signature".into(),
        }
    }

    fn fictional_header() -> Header {
        Header {
            version: 3,
            vault_id: "vaultAAAAAAAAAAAA01".into(),
            device_id: "deviceAAAAAAAAAAAAAA01".into(),
            revision: 1,
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

    #[test]
    fn malformed_response_bytes_are_a_readable_failure() {
        assert!(matches!(
            parse::<StateView>(b"{"),
            Err(SyncError::Failed(_))
        ));
        assert!(matches!(
            parse::<StateView>(b"null"),
            Err(SyncError::Failed(_))
        ));
    }
}
