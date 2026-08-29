//! Network client for the `/v1/sync` control plane; compiled only under `sync-preview`.
//! Only ciphertext, identifiers, and signatures leave; authentication is the desktop device token, never a cookie.
//! Conflicts are surfaced, never resolved by retrying: overwriting a lost compare-and-swap is how a password change disappears.

use std::time::Duration;

use super::ensure_crypto_provider;
use serde::{Deserialize, Serialize};

use crate::vault::service::{read_service_connection, read_service_token, service_api_base_url};
use crate::vault::VaultResult;
use tauri::AppHandle;

/// Ceiling on any response body, derived from the protocol's own constant so the limits cannot drift apart.
const MAX_RESPONSE_BYTES: usize = crate::sync::envelope::MAX_ENVELOPE_BYTES;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub enum SyncError {
    Unavailable(String),
    /// A compare-and-swap lost; carries the service's revision for the conflict screen.
    Conflict {
        current_revision: i64,
        vault_epoch: i64,
    },
    NotApproved,
    NotFound,
    Failed(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => write!(formatter, "{message}"),
            Self::Conflict { .. } => write!(
                formatter,
                "Another device changed this vault. Review the difference before syncing."
            ),
            Self::NotApproved => write!(formatter, "This device is not approved to sync."),
            Self::NotFound => write!(formatter, "That Sync record does not exist."),
            Self::Failed(message) => write!(formatter, "{message}"),
        }
    }
}

impl From<SyncError> for String {
    fn from(error: SyncError) -> Self {
        error.to_string()
    }
}

pub type SyncResult<T> = Result<T, SyncError>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentChallenge {
    pub vault_id: String,
    pub vault_epoch: i64,
    pub challenge: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncDevice {
    pub device_id: String,
    pub state: String,
    pub device_epoch: i64,
    pub label: String,
    pub signing_public_key: String,
    pub encryption_public_key: String,
    pub created_at: String,
    #[serde(default)]
    pub approved_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceList {
    pub vault_id: String,
    pub vault_epoch: i64,
    pub devices: Vec<SyncDevice>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackage {
    pub vault_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub ciphertext: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadedEnvelope {
    pub vault_id: String,
    pub vault_epoch: i64,
    pub revision: i64,
    #[serde(default)]
    pub envelope: Option<serde_json::Value>,
    /// Service-reported, not signed, so it is shown to a person and never branched on.
    #[serde(default)]
    pub uploaded_at: String,
    /// Chain predecessor; recomputed locally before it is trusted.
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub receipt: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadAccepted {
    pub vault_id: String,
    pub revision: i64,
    pub vault_epoch: i64,
    /// Checked against the locally computed digest before being recorded.
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub receipt: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollBeginBody<'a> {
    vault_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollFinishBody<'a> {
    device_id: &'a str,
    signing_public_key: &'a str,
    encryption_public_key: &'a str,
    challenge: &'a str,
    proof: &'a str,
    label: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApproveBody<'a> {
    sender_device_id: &'a str,
    expected_vault_epoch: i64,
    ciphertext: &'a str,
    signature: &'a str,
}

/// Chunked read with a hard cap: a lying length must not allocate past it.
async fn read_capped(response: reqwest::Response) -> SyncResult<Vec<u8>> {
    if let Some(declared) = response.content_length() {
        if declared > MAX_RESPONSE_BYTES as u64 {
            return Err(SyncError::Failed(
                "Sesame Sync returned more data than it accepts.".into(),
            ));
        }
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| SyncError::Failed("Sesame could not read the Sync response.".into()))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(SyncError::Failed(
                "Sesame Sync returned more data than it accepts.".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Built per operation so a revoked token is never cached across a long-lived handle.
pub struct SyncClient {
    base_url: String,
    http: reqwest::Client,
    token: String,
}

impl SyncClient {
    pub fn connect(app: &AppHandle) -> VaultResult<Self> {
        let base_url = service_api_base_url()?;
        let connection = read_service_connection(app)?;
        let token = read_service_token(&connection)?;
        let parsed = url::Url::parse(&base_url)
            .map_err(|_| "Sesame account service URL is invalid.".to_string())?;
        let loopback_http = parsed.scheme() == "http"
            && parsed
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
        if parsed.scheme() != "https" && !loopback_http {
            return Err("Sesame refuses to send vault ciphertext over an insecure URL.".into());
        }
        ensure_crypto_provider();
        let http = reqwest::Client::builder()
            .https_only(!loopback_http)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| "Sesame could not prepare its Sync connection.".to_string())?;
        Ok(Self {
            base_url,
            http,
            token,
        })
    }

    async fn send<T: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> SyncResult<T> {
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base_url, path))
            // Device token, never a cookie; the service rejects cookies on these routes.
            .header("Authorization", format!("Sesame {}", self.token));
        if let Some(payload) = body {
            request = request.json(payload);
        }
        let response = request
            .send()
            .await
            .map_err(|_| SyncError::Failed("Sesame could not reach Sesame Sync.".into()))?;
        let status = response.status();
        let bytes = read_capped(response).await?;
        if status.is_success() {
            return serde_json::from_slice(&bytes)
                .map_err(|_| SyncError::Failed("Sesame could not read the Sync response.".into()));
        }
        Err(classify(status, &bytes))
    }

    /// Creates the vault on first use and returns a one-time, vault-bound, expiring challenge.
    pub async fn enroll_begin(&self, vault_id: &str) -> SyncResult<EnrollmentChallenge> {
        self.send(
            reqwest::Method::POST,
            "/v1/sync/enroll/begin",
            Some(&EnrollBeginBody { vault_id }),
        )
        .await
    }

    /// Registers this device as pending; it holds no key package, so it can decrypt nothing until approved.
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_finish(
        &self,
        device_id: &str,
        signing_public_key: &str,
        encryption_public_key: &str,
        challenge: &str,
        proof: &str,
        label: &str,
    ) -> SyncResult<SyncDevice> {
        self.send(
            reqwest::Method::POST,
            "/v1/sync/enroll/finish",
            Some(&EnrollFinishBody {
                device_id,
                signing_public_key,
                encryption_public_key,
                challenge,
                proof,
                label,
            }),
        )
        .await
    }

    pub async fn devices(&self) -> SyncResult<DeviceList> {
        self.send::<DeviceList>(reqwest::Method::GET, "/v1/sync/devices", NO_BODY)
            .await
    }

    /// Sealed key package only; the plaintext vault key never appears in this call.
    pub async fn approve_device(
        &self,
        device_id: &str,
        sender_device_id: &str,
        expected_vault_epoch: i64,
        sealed_package: &str,
        signature: &str,
    ) -> SyncResult<SyncDevice> {
        self.send(
            reqwest::Method::POST,
            &format!("/v1/sync/devices/{device_id}/approve"),
            Some(&ApproveBody {
                sender_device_id,
                expected_vault_epoch,
                ciphertext: sealed_package,
                signature,
            }),
        )
        .await
    }

    pub async fn revoke_device(&self, device_id: &str) -> SyncResult<()> {
        let path = format!("/v1/sync/devices/{device_id}");
        let response = self
            .http
            .delete(format!("{}{}", self.base_url, path))
            .header("Authorization", format!("Sesame {}", self.token))
            .send()
            .await
            .map_err(|_| SyncError::Failed("Sesame could not reach Sesame Sync.".into()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let bytes = read_capped(response).await.unwrap_or_default();
        Err(classify(status, &bytes))
    }

    /// Naming this device in the query is safe: the package is sealed to its key regardless.
    pub async fn key_package(&self, device_id: &str) -> SyncResult<KeyPackage> {
        self.send::<KeyPackage>(
            reqwest::Method::GET,
            &format!(
                "/v1/sync/key-package?deviceId={}",
                opaque_query_value(device_id)?
            ),
            NO_BODY,
        )
        .await
    }

    pub async fn download(&self) -> SyncResult<DownloadedEnvelope> {
        self.send::<DownloadedEnvelope>(reqwest::Method::GET, "/v1/sync/envelope", NO_BODY)
            .await
    }

    /// Compare-and-swap upload; a lost race returns a conflict and must never be retried by overwriting.
    pub async fn upload(&self, envelope: &serde_json::Value) -> SyncResult<UploadAccepted> {
        self.send(reqwest::Method::POST, "/v1/sync/envelope", Some(envelope))
            .await
    }
}

const NO_BODY: Option<&()> = None;

/// The two error shapes disagree (flat string versus `code` object), so they parse as separate types.
#[derive(Deserialize)]
struct ConflictBody {
    #[serde(rename = "currentRevision")]
    current_revision: i64,
    #[serde(rename = "vaultEpoch")]
    vault_epoch: i64,
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

/// A conflict stays its own variant: collapsing it would let a caller retry and discard another device's upload.
fn classify(status: reqwest::StatusCode, body: &[u8]) -> SyncError {
    if status == reqwest::StatusCode::CONFLICT {
        return match serde_json::from_slice::<ConflictBody>(body) {
            Ok(conflict) => SyncError::Conflict {
                current_revision: conflict.current_revision,
                vault_epoch: conflict.vault_epoch,
            },
            // An unparsable conflict must not render a difference against a fake revision.
            Err(_) => SyncError::Failed(
                "Another device changed this vault. Review the difference before syncing.".into(),
            ),
        };
    }
    let parsed: Option<ErrorEnvelope> = serde_json::from_slice(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|envelope| envelope.error.as_ref())
        .map(|error| error.code.as_str())
        .unwrap_or_default();
    match code {
        "sync_unavailable" => SyncError::Unavailable("Sesame Sync is not available.".into()),
        "sync_device_not_approved" => SyncError::NotApproved,
        "sync_device_not_found" | "sync_vault_not_found" => SyncError::NotFound,
        _ => match status {
            reqwest::StatusCode::FORBIDDEN => {
                SyncError::Unavailable("Sesame Sync is not available.".into())
            }
            reqwest::StatusCode::NOT_FOUND => SyncError::NotFound,
            _ => SyncError::Failed("Sesame Sync could not complete that request.".into()),
        },
    }
}

/// Base64url alphabet checked instead of percent-encoding; anything outside it is refused.
fn opaque_query_value(value: &str) -> SyncResult<&str> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if !valid {
        return Err(SyncError::Failed(
            "This device identifier is not usable with Sesame Sync.".into(),
        ));
    }
    Ok(value)
}

impl SyncClient {
    /// Records that this device opened the key package it was given.
    pub async fn activate(&self, proof: &str) -> SyncResult<()> {
        #[derive(Serialize)]
        struct Body<'a> {
            proof: &'a str,
        }
        let response = self
            .http
            .post(format!("{}/v1/sync/activate", self.base_url))
            .header("Authorization", format!("Sesame {}", self.token))
            .json(&Body { proof })
            .send()
            .await
            .map_err(|_| SyncError::Failed("Sesame could not reach Sesame Sync.".into()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let bytes = read_capped(response).await.unwrap_or_default();
        Err(classify(status, &bytes))
    }

    /// Removes another device and rotates the vault key in one call.
    pub async fn rekey_device(
        &self,
        device_id: &str,
        body: &serde_json::Value,
    ) -> SyncResult<UploadAccepted> {
        self.send(
            reqwest::Method::POST,
            &format!("/v1/sync/devices/{device_id}/rekey"),
            Some(body),
        )
        .await
    }

    /// A pending device never held the vault key, so nothing is rotated.
    pub async fn deny_device(&self, device_id: &str) -> SyncResult<()> {
        let response = self
            .http
            .post(format!(
                "{}/v1/sync/devices/{device_id}/deny",
                self.base_url
            ))
            .header("Authorization", format!("Sesame {}", self.token))
            .send()
            .await
            .map_err(|_| SyncError::Failed("Sesame could not reach Sesame Sync.".into()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let bytes = read_capped(response).await.unwrap_or_default();
        Err(classify(status, &bytes))
    }

    /// Destructive reset; refused while any approved device still works.
    pub async fn reset_vault(&self) -> SyncResult<()> {
        let response = self
            .http
            .post(format!("{}/v1/sync/reset", self.base_url))
            .header("Authorization", format!("Sesame {}", self.token))
            .send()
            .await
            .map_err(|_| SyncError::Failed("Sesame could not reach Sesame Sync.".into()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let bytes = read_capped(response).await.unwrap_or_default();
        Err(classify(status, &bytes))
    }
}
