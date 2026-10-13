use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use zeroize::Zeroize;

use super::capabilities::{
    fetch_signed_document, official_capability_public_key, require_sync_enabled,
};
use super::ensure_crypto_provider;
use super::server_trust::verify_pinned_server;
use crate::sync::canonical::REQUEST_NONCE_BYTES;
use crate::sync::checkpoint::Checkpoint;
use crate::sync::devicelist::DeviceListEntry;
use crate::sync::engine::{ServedCheckpoint, ServedHeader};
use crate::sync::header::Header;
use crate::sync::identity::DeviceIdentity;
use crate::sync::request::{KeyPackageV3, RequestSignature};
use crate::vault::service::{
    read_service_connection, read_service_token, service_target, ServiceTarget,
};
use crate::vault::VaultResult;

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug)]
pub enum SyncError {
    Unavailable(String),
    Conflict,
    NotApproved,
    NotActivated,
    NotEntitled,
    NotFound,
    StorageFull,
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
        }
    }
}

impl From<SyncError> for String {
    fn from(error: SyncError) -> Self {
        error.to_string()
    }
}

pub type SyncResult<T> = Result<T, SyncError>;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateView {
    pub vault_id: String,
    pub vault_epoch: u64,
    pub current_revision: u64,
    pub device_state: String,
    pub activated_epoch: u64,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct DevicesView {
    pub pairings: Vec<PairingRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingStatus {
    pub state: String,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub answer: Option<String>,
}

#[derive(Debug, Deserialize)]
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
struct Entries {
    entries: Vec<DeviceListEntry>,
}

#[derive(Deserialize)]
struct Headers {
    headers: Vec<ServedHeader>,
}

#[derive(Deserialize)]
struct Checkpoints {
    checkpoints: Vec<ServedCheckpoint>,
}

#[derive(Serialize)]
struct CheckpointBody<'a> {
    checkpoint: &'a Checkpoint,
}

#[derive(Deserialize)]
struct PackageBody {
    package: KeyPackageV3,
}

#[derive(Serialize)]
struct CreateVaultBody<'a> {
    entry: &'a DeviceListEntry,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BeginPairingBody<'a> {
    device_id: &'a str,
    signing_key: &'a str,
    package_key: &'a str,
    message: &'a str,
}

#[derive(Serialize)]
struct MessageBody<'a> {
    message: &'a str,
}

#[derive(Serialize)]
struct ApproveBody<'a> {
    entry: &'a DeviceListEntry,
    package: &'a KeyPackageV3,
}

#[derive(Serialize)]
struct RemoveBody<'a> {
    entry: &'a DeviceListEntry,
    packages: &'a [KeyPackageV3],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivateBody<'a> {
    package_digest: &'a str,
}

#[derive(Serialize)]
struct UploadBody<'a> {
    header: &'a Header,
    ciphertext: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResetBody {
    vault_epoch: u64,
}

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
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(SyncError::Failed(
                "Sesame Sync returned more data than it accepts.".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub struct SyncClient {
    base_url: String,
    http: reqwest::Client,
    token: String,
    entitlement_enforced: bool,
    instance_key: String,
}

impl Drop for SyncClient {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl SyncClient {
    pub async fn connect(app: &AppHandle) -> VaultResult<Self> {
        use tauri::Manager;
        let data_dir = app
            .path()
            .app_local_data_dir()
            .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
        super::sync_floor::require_sync_allowed(&data_dir).await?;
        let connection = read_service_connection(app)?;
        let target = service_target(&connection)?;
        let token = read_service_token(&connection)?;
        Self::for_target(&target, token).await
    }

    pub(crate) async fn for_target(target: &ServiceTarget, mut token: String) -> VaultResult<Self> {
        let base_url = target.base_url().to_string();
        let parsed = url::Url::parse(&base_url)
            .map_err(|_| "Sesame account service URL is invalid.".to_string())?;
        let loopback_http = parsed.scheme() == "http"
            && match parsed.host() {
                Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
                Some(url::Host::Ipv4(address)) => address.is_loopback(),
                Some(url::Host::Ipv6(address)) => address.is_loopback(),
                None => false,
            };
        if parsed.scheme() != "https" && !loopback_http {
            token.zeroize();
            return Err("Sesame refuses to send vault ciphertext over an insecure URL.".into());
        }
        ensure_crypto_provider();
        let http = reqwest::Client::builder()
            .https_only(!loopback_http)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| "Sesame could not prepare its Sync connection.".to_string())?;
        let (key_text, key_id) = match target {
            ServiceTarget::Official { .. } => (official_capability_public_key()?, None),
            ServiceTarget::Custom { address, pin } => {
                if let Err(failure) = verify_pinned_server(&http, address, pin).await {
                    token.zeroize();
                    return Err(failure.message());
                }
                (
                    pin.capability_public_key.clone(),
                    Some(pin.capability_key_id.clone()),
                )
            }
        };
        let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&key_text)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| "The service key is invalid.".to_string())?;
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| "The service key is invalid.".to_string())?;
        let document = fetch_signed_document(&http, &base_url, &verifying, key_id.as_deref()).await;
        let document = match document {
            Ok(document) => document,
            Err(failure) => {
                token.zeroize();
                return Err(failure.into());
            }
        };
        if let Err(failure) = require_sync_enabled(&document, env!("CARGO_PKG_VERSION")) {
            token.zeroize();
            return Err(failure.into());
        }
        Ok(Self {
            base_url,
            http,
            token,
            entitlement_enforced: !target.is_custom(),
            instance_key: key_text,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests(base_url: &str, token: &str, instance_key: &str) -> Self {
        ensure_crypto_provider();
        Self {
            base_url: base_url.to_string(),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
            token: token.to_string(),
            entitlement_enforced: false,
            instance_key: instance_key.to_string(),
        }
    }

    pub fn instance_key(&self) -> &str {
        &self.instance_key
    }

    fn classify(&self, status: reqwest::StatusCode, body: &[u8]) -> SyncError {
        let parsed: Option<ErrorEnvelope> = serde_json::from_slice(body).ok();
        let code = parsed
            .as_ref()
            .and_then(|envelope| envelope.error.as_ref())
            .map(|error| error.code.as_str())
            .unwrap_or_default();
        match code {
            "sync_unavailable" => SyncError::Unavailable("Sesame Sync is not available.".into()),
            "sync_not_entitled" if self.entitlement_enforced => SyncError::NotEntitled,
            "sync_not_entitled" => SyncError::Unavailable("Sesame Sync is not available.".into()),
            "sync_not_activated" => SyncError::NotActivated,
            "sync_forbidden" => SyncError::NotApproved,
            "sync_vault_not_found" | "sync_not_found" => SyncError::NotFound,
            "sync_conflict" | "sync_vault_exists" => SyncError::Conflict,
            "sync_storage_limit_reached" => SyncError::StorageFull,
            "sync_signature_invalid" => SyncError::Failed(
                "The service did not accept this device's signature. Check that the date and time on this computer are correct."
                    .into(),
            ),
            "sync_replayed" => SyncError::Failed(
                "The service saw that request twice. Try again.".into(),
            ),
            _ => match status {
                reqwest::StatusCode::UNAUTHORIZED => SyncError::Failed(
                    "This desktop is no longer linked to the service.".into(),
                ),
                reqwest::StatusCode::FORBIDDEN => {
                    SyncError::Unavailable("Sesame Sync is not available.".into())
                }
                reqwest::StatusCode::NOT_FOUND => SyncError::NotFound,
                _ => SyncError::Failed("Sesame Sync could not complete that request.".into()),
            },
        }
    }

    async fn dispatch(
        &self,
        method: reqwest::Method,
        path: &str,
        raw: Vec<u8>,
        signature: Option<String>,
        long: bool,
    ) -> SyncResult<Vec<u8>> {
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base_url, path))
            .header("Authorization", format!("Sesame {}", self.token));
        if let Some(value) = signature {
            request = request.header("Sesame-Request-Signature", value);
        }
        if long {
            request = request.timeout(TRANSFER_TIMEOUT);
        }
        if !raw.is_empty() {
            request = request.header("Content-Type", "application/json").body(raw);
        }
        let response = request
            .send()
            .await
            .map_err(|_| SyncError::Failed("Sesame could not reach Sesame Sync.".into()))?;
        let status = response.status();
        let bytes = read_capped(response).await?;
        if status.is_success() {
            return Ok(bytes);
        }
        Err(self.classify(status, &bytes))
    }

    async fn read<T: for<'de> Deserialize<'de>>(&self, path: &str, long: bool) -> SyncResult<T> {
        let bytes = self
            .dispatch(reqwest::Method::GET, path, Vec::new(), None, long)
            .await?;
        parse(&bytes)
    }

    async fn write<T: for<'de> Deserialize<'de>>(
        &self,
        identity: &DeviceIdentity,
        method: reqwest::Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
        long: bool,
    ) -> SyncResult<T> {
        let bytes = self.write_raw(identity, method, path, body, long).await?;
        parse(&bytes)
    }

    async fn write_raw(
        &self,
        identity: &DeviceIdentity,
        method: reqwest::Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
        long: bool,
    ) -> SyncResult<Vec<u8>> {
        let raw = match body {
            Some(value) => serde_json::to_vec(value)
                .map_err(|_| SyncError::Failed("Sesame could not prepare the request.".into()))?,
            None => Vec::new(),
        };
        let mut nonce = [0u8; REQUEST_NONCE_BYTES];
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| SyncError::Failed("Sesame could not gather randomness.".into()))?;
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| SyncError::Failed("This computer's clock is not usable.".into()))?
            .as_secs();
        let signature = identity.sign_request(&RequestSignature {
            method: method.as_str(),
            target: path,
            body: &raw,
            token: &self.token,
            timestamp,
            nonce: &nonce,
        });
        self.dispatch(
            method,
            path,
            raw,
            Some(format!("{timestamp}.{nonce}.{signature}")),
            long,
        )
        .await
    }

    pub async fn state(&self) -> SyncResult<StateView> {
        self.read("/v1/sync/state", false).await
    }

    pub async fn create_vault(
        &self,
        identity: &DeviceIdentity,
        entry: &DeviceListEntry,
    ) -> SyncResult<()> {
        self.write_raw(
            identity,
            reqwest::Method::POST,
            "/v1/sync/vault",
            Some(&CreateVaultBody { entry }),
            false,
        )
        .await
        .map(|_| ())
    }

    pub async fn device_list(&self, after: u64) -> SyncResult<Vec<DeviceListEntry>> {
        let entries: Entries = self
            .read(&format!("/v1/sync/device-list?after={after}"), false)
            .await?;
        Ok(entries.entries)
    }

    pub async fn devices(&self) -> SyncResult<DevicesView> {
        self.read("/v1/sync/devices", false).await
    }

    pub async fn begin_pairing(
        &self,
        identity: &DeviceIdentity,
        device_id: &str,
        signing_key: &str,
        package_key: &str,
        message: &[u8],
    ) -> SyncResult<()> {
        let message = URL_SAFE_NO_PAD.encode(message);
        self.write_raw(
            identity,
            reqwest::Method::POST,
            "/v1/sync/pairings",
            Some(&BeginPairingBody {
                device_id,
                signing_key,
                package_key,
                message: &message,
            }),
            false,
        )
        .await
        .map(|_| ())
    }

    pub async fn pairing_status(&self) -> SyncResult<PairingStatus> {
        self.read("/v1/sync/pairings/mine", false).await
    }

    pub async fn answer_pairing(
        &self,
        identity: &DeviceIdentity,
        device_id: &str,
        message: &[u8],
    ) -> SyncResult<()> {
        let message = URL_SAFE_NO_PAD.encode(message);
        self.write_raw(
            identity,
            reqwest::Method::POST,
            &format!("/v1/sync/pairings/{device_id}/answer"),
            Some(&MessageBody { message: &message }),
            false,
        )
        .await
        .map(|_| ())
    }

    pub async fn confirm_pairing(
        &self,
        identity: &DeviceIdentity,
        message: &[u8],
    ) -> SyncResult<()> {
        let message = URL_SAFE_NO_PAD.encode(message);
        self.write_raw(
            identity,
            reqwest::Method::POST,
            "/v1/sync/pairings/mine/confirm",
            Some(&MessageBody { message: &message }),
            false,
        )
        .await
        .map(|_| ())
    }

    pub async fn cancel_pairing(
        &self,
        identity: &DeviceIdentity,
        device_id: &str,
    ) -> SyncResult<()> {
        self.write_raw(
            identity,
            reqwest::Method::DELETE,
            &format!("/v1/sync/pairings/{device_id}"),
            NO_BODY,
            false,
        )
        .await
        .map(|_| ())
    }

    pub async fn approve(
        &self,
        identity: &DeviceIdentity,
        entry: &DeviceListEntry,
        package: &KeyPackageV3,
    ) -> SyncResult<()> {
        self.write_raw(
            identity,
            reqwest::Method::POST,
            "/v1/sync/devices",
            Some(&ApproveBody { entry, package }),
            false,
        )
        .await
        .map(|_| ())
    }

    pub async fn remove(
        &self,
        identity: &DeviceIdentity,
        entry: &DeviceListEntry,
        packages: &[KeyPackageV3],
    ) -> SyncResult<()> {
        self.write_raw(
            identity,
            reqwest::Method::POST,
            "/v1/sync/devices/remove",
            Some(&RemoveBody { entry, packages }),
            false,
        )
        .await
        .map(|_| ())
    }

    pub async fn key_package(&self) -> SyncResult<KeyPackageV3> {
        let body: PackageBody = self.read("/v1/sync/key-package", false).await?;
        Ok(body.package)
    }

    pub async fn activate(
        &self,
        identity: &DeviceIdentity,
        package_digest: &str,
    ) -> SyncResult<()> {
        self.write_raw(
            identity,
            reqwest::Method::POST,
            "/v1/sync/activate",
            Some(&ActivateBody { package_digest }),
            false,
        )
        .await
        .map(|_| ())
    }

    pub async fn upload(
        &self,
        identity: &DeviceIdentity,
        header: &Header,
        ciphertext: &[u8],
    ) -> SyncResult<Accepted> {
        let ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        self.write(
            identity,
            reqwest::Method::POST,
            "/v1/sync/snapshots",
            Some(&UploadBody {
                header,
                ciphertext: &ciphertext,
            }),
            true,
        )
        .await
    }

    pub async fn headers(&self, after: u64) -> SyncResult<Vec<ServedHeader>> {
        let mut collected = Vec::new();
        let mut cursor = after;
        loop {
            let page: Headers = self
                .read(&format!("/v1/sync/headers?after={cursor}&limit=500"), false)
                .await?;
            let count = page.headers.len();
            if let Some(last) = page.headers.last() {
                cursor = last.header.revision;
            }
            collected.extend(page.headers);
            if count < 500 || collected.len() > 20_000 {
                return Ok(collected);
            }
        }
    }

    pub async fn checkpoints(&self) -> SyncResult<Vec<ServedCheckpoint>> {
        let page: Checkpoints = self.read("/v1/sync/checkpoints", false).await?;
        Ok(page.checkpoints)
    }

    pub async fn post_checkpoint(
        &self,
        identity: &DeviceIdentity,
        checkpoint: &Checkpoint,
    ) -> SyncResult<()> {
        self.write_raw(
            identity,
            reqwest::Method::POST,
            "/v1/sync/checkpoints",
            Some(&CheckpointBody { checkpoint }),
            false,
        )
        .await
        .map(|_| ())
    }

    pub async fn snapshot(&self) -> SyncResult<ServedSnapshot> {
        self.read("/v1/sync/snapshot", true).await
    }

    pub async fn reset(&self, identity: &DeviceIdentity, vault_epoch: u64) -> SyncResult<()> {
        self.write_raw(
            identity,
            reqwest::Method::POST,
            "/v1/sync/reset",
            Some(&ResetBody { vault_epoch }),
            false,
        )
        .await
        .map(|_| ())
    }
}

const NO_BODY: Option<&()> = None;

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> SyncResult<T> {
    serde_json::from_slice(bytes)
        .map_err(|_| SyncError::Failed("Sesame could not read the Sync response.".into()))
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

    fn fixture() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("contracts")
            .join("sync")
            .join("v3")
            .join("wire-fixture.json");
        serde_json::from_slice(&std::fs::read(path).expect("read")).expect("parse")
    }

    fn response<T: for<'de> Deserialize<'de>>(name: &str) -> T {
        serde_json::from_value(fixture()["responses"][name].clone())
            .unwrap_or_else(|error| panic!("response {name} does not parse: {error}"))
    }

    fn request(name: &str) -> serde_json::Value {
        fixture()["requests"][name].clone()
    }

    #[test]
    fn every_service_response_parses_into_the_client_types() {
        let state: StateView = response("state");
        assert_eq!(
            (
                state.current_revision,
                state.vault_epoch,
                state.device_state.as_str()
            ),
            (5, 1, "approved")
        );
        let entries: Entries = response("deviceList");
        assert_eq!(entries.entries.len(), 1);
        let devices: DevicesView = response("devices");
        assert_eq!(devices.pairings.len(), 1);
        assert!(devices.pairings[0].confirm.is_none());
        let status: PairingStatus = response("pairingStatus");
        assert!(status.answer.is_none());
        let package: PackageBody = response("keyPackage");
        assert_eq!(package.package.vault_epoch, 1);
        let headers: Headers = response("headers");
        assert_eq!(headers.headers[0].header.revision, 5);
        assert_eq!(headers.headers[0].digest, "digest");
        assert!(headers.headers[0].accepted_at_unix().is_some());
        let snapshot: ServedSnapshot = response("snapshot");
        assert_eq!(snapshot.header.revision, 5);
        assert_eq!(snapshot.ciphertext, "ciphertext");
        let accepted: Accepted = response("upload");
        assert_eq!(accepted.revision, 5);
        let checkpoints: Checkpoints = response("checkpoints");
        assert_eq!(checkpoints.checkpoints[0].checkpoint.header_revision, 5);
        assert_eq!(
            checkpoints.checkpoints[0].checkpoint.observed_at,
            1_800_000_000
        );
    }

    #[test]
    fn every_request_body_has_exactly_the_shape_the_service_decodes() {
        let entry: DeviceListEntry =
            serde_json::from_value(request("createVault")["entry"].clone()).expect("entry");
        let package: KeyPackageV3 =
            serde_json::from_value(request("approve")["package"].clone()).expect("package");
        let header: Header =
            serde_json::from_value(request("upload")["header"].clone()).expect("header");
        let to = |value: &dyn erased::Json| value.to_value();
        assert_eq!(
            to(&CreateVaultBody { entry: &entry }),
            request("createVault")
        );
        assert_eq!(
            to(&BeginPairingBody {
                device_id: "deviceBBBBBBBBBBBB01",
                signing_key: "signingkey",
                package_key: "packagekey",
                message: "message",
            }),
            request("beginPairing")
        );
        assert_eq!(to(&MessageBody { message: "message" }), request("message"));
        assert_eq!(
            to(&ApproveBody {
                entry: &entry,
                package: &package
            }),
            request("approve")
        );
        assert_eq!(
            to(&RemoveBody {
                entry: &entry,
                packages: std::slice::from_ref(&package)
            }),
            request("remove")
        );
        assert_eq!(
            to(&ActivateBody {
                package_digest: "packagedigest"
            }),
            request("activate")
        );
        assert_eq!(
            to(&UploadBody {
                header: &header,
                ciphertext: "ciphertext"
            }),
            request("upload")
        );
        assert_eq!(to(&ResetBody { vault_epoch: 2 }), request("reset"));
        let checkpoint: Checkpoint =
            serde_json::from_value(request("checkpoint")["checkpoint"].clone())
                .expect("checkpoint");
        assert_eq!(
            to(&CheckpointBody {
                checkpoint: &checkpoint
            }),
            request("checkpoint")
        );
    }

    mod erased {
        pub trait Json {
            fn to_value(&self) -> serde_json::Value;
        }
        impl<T: serde::Serialize> Json for T {
            fn to_value(&self) -> serde_json::Value {
                serde_json::to_value(self).expect("serialize")
            }
        }
    }
}
