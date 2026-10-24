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
const TRANSFER_BASE_TIMEOUT: Duration = Duration::from_secs(60);
const TRANSFER_SLOWEST_BYTES_PER_SECOND: usize = 32 * 1024;
const TRANSFER_MAX_TIMEOUT: Duration = Duration::from_secs(30 * 60);

fn transfer_timeout(bytes: usize) -> Duration {
    (TRANSFER_BASE_TIMEOUT
        + Duration::from_secs((bytes / TRANSFER_SLOWEST_BYTES_PER_SECOND) as u64))
    .min(TRANSFER_MAX_TIMEOUT)
}

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

const HEADER_PAGE_SIZE: usize = 500;
const MAX_HEADERS: usize = 20_000;

async fn collect_header_pages<F, Fut>(after: u64, mut fetch: F) -> SyncResult<Vec<ServedHeader>>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = SyncResult<Vec<ServedHeader>>>,
{
    let mut collected = Vec::new();
    let mut cursor = after;
    loop {
        let page = fetch(cursor).await?;
        let count = page.len();
        if let Some(last) = page.last() {
            cursor = last.header.revision;
        }
        collected.extend(page);
        if collected.len() > MAX_HEADERS {
            return Err(SyncError::Failed(
                "The service returned more history than Sesame will read. Sync stopped and nothing was changed."
                    .to_string(),
            ));
        }
        if count < HEADER_PAGE_SIZE {
            return Ok(collected);
        }
    }
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
            let size = if raw.is_empty() {
                MAX_RESPONSE_BYTES
            } else {
                raw.len()
            };
            request = request.timeout(transfer_timeout(size));
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
        collect_header_pages(after, |cursor| async move {
            let page: Headers = self
                .read(&format!("/v1/sync/headers?after={cursor}&limit=500"), false)
                .await?;
            Ok(page.headers)
        })
        .await
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
    use crate::adapters::network::server_address::ServerAddress;
    use crate::adapters::network::server_trust::parse_instance;
    use crate::adapters::network::test_server::{FakeSesame, Recorded, Reply, TestServer};

    fn custom(server: &TestServer, pinned: &FakeSesame) -> ServiceTarget {
        let pin = parse_instance(&serde_json::to_vec(&pinned.instance()).unwrap(), "0.3.0")
            .unwrap()
            .pin();
        ServiceTarget::Custom {
            address: ServerAddress::parse(&server.base()).unwrap(),
            pin,
        }
    }

    fn sync_enabled(fake: &FakeSesame) -> impl Fn(&Recorded) -> Reply + Send + Sync + 'static {
        let inner = fake.handler();
        let mut payload = fake.capability_payload();
        payload["features"]["sync"] = serde_json::json!(true);
        let capabilities = fake.signed(&payload);
        move |request| {
            if request.path == "/v1/capabilities" {
                Reply::json(200, &capabilities)
            } else {
                inner(request)
            }
        }
    }

    fn connect(target: &ServiceTarget) -> VaultResult<SyncClient> {
        tauri::async_runtime::block_on(SyncClient::for_target(
            target,
            "fictional-device-token".to_string(),
        ))
    }

    fn sent_the_token(server: &TestServer) -> bool {
        server.requests().iter().any(|request| {
            request.headers.get("authorization").map(String::as_str)
                == Some("Sesame fictional-device-token")
        })
    }

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

    fn served(revision: u64) -> ServedHeader {
        let mut header: ServedHeader =
            serde_json::from_value(fixture()["responses"]["headers"]["headers"][0].clone())
                .expect("fixture header");
        header.header.revision = revision;
        header
    }

    fn pages(
        sizes: Vec<usize>,
    ) -> impl FnMut(u64) -> std::future::Ready<SyncResult<Vec<ServedHeader>>> {
        let mut sizes = sizes.into_iter();
        let mut next = 1_u64;
        move |_cursor| {
            let count = sizes.next().unwrap_or(0);
            let page = (0..count)
                .map(|offset| served(next + offset as u64))
                .collect::<Vec<_>>();
            next += count as u64;
            std::future::ready(Ok(page))
        }
    }

    #[test]
    fn a_transfer_gets_time_for_its_size_at_a_slow_uplink() {
        assert_eq!(transfer_timeout(0), TRANSFER_BASE_TIMEOUT);
        let ten_mebibytes_encoded = 14 * 1024 * 1024;
        assert!(transfer_timeout(ten_mebibytes_encoded) > Duration::from_secs(180));
        assert!(
            transfer_timeout(ten_mebibytes_encoded)
                >= Duration::from_secs((ten_mebibytes_encoded / (32 * 1024)) as u64)
        );
    }

    #[test]
    fn a_transfer_timeout_never_exceeds_its_ceiling_and_grows_with_size() {
        assert!(transfer_timeout(1024 * 1024) < transfer_timeout(8 * 1024 * 1024));
        assert_eq!(transfer_timeout(usize::MAX / 2), TRANSFER_MAX_TIMEOUT);
        assert!(transfer_timeout(MAX_RESPONSE_BYTES) <= TRANSFER_MAX_TIMEOUT);
    }

    #[test]
    fn header_paging_collects_every_page_until_a_short_one() {
        let collected = tauri::async_runtime::block_on(collect_header_pages(
            0,
            pages(vec![HEADER_PAGE_SIZE, HEADER_PAGE_SIZE, 7]),
        ))
        .unwrap();
        assert_eq!(collected.len(), 2 * HEADER_PAGE_SIZE + 7);
        assert_eq!(
            collected.last().map(|header| header.header.revision),
            Some(1007)
        );
    }

    #[test]
    fn header_paging_passes_the_last_revision_as_the_next_cursor() {
        let mut cursors = Vec::new();
        let mut source = pages(vec![HEADER_PAGE_SIZE, 3]);
        let collected = tauri::async_runtime::block_on(collect_header_pages(5, |cursor| {
            cursors.push(cursor);
            source(cursor)
        }))
        .unwrap();
        assert_eq!(collected.len(), HEADER_PAGE_SIZE + 3);
        assert_eq!(cursors, vec![5, HEADER_PAGE_SIZE as u64]);
    }

    #[test]
    fn header_paging_refuses_a_history_past_the_cap_instead_of_reading_part_of_it() {
        let full_pages = vec![HEADER_PAGE_SIZE; MAX_HEADERS / HEADER_PAGE_SIZE + 1];
        let outcome = tauri::async_runtime::block_on(collect_header_pages(0, pages(full_pages)));
        assert!(matches!(outcome, Err(SyncError::Failed(_))));
    }

    #[test]
    fn header_paging_accepts_exactly_the_cap() {
        let mut sizes = vec![HEADER_PAGE_SIZE; MAX_HEADERS / HEADER_PAGE_SIZE];
        sizes.push(0);
        let collected =
            tauri::async_runtime::block_on(collect_header_pages(0, pages(sizes))).unwrap();
        assert_eq!(collected.len(), MAX_HEADERS);
    }

    #[test]
    fn header_paging_passes_a_failed_page_through() {
        let outcome = tauri::async_runtime::block_on(collect_header_pages(0, |_| {
            std::future::ready(Err(SyncError::Unavailable("fictional outage".into())))
        }));
        assert!(matches!(outcome, Err(SyncError::Unavailable(_))));
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

    #[test]
    fn a_pinned_server_is_checked_before_it_gets_the_token() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(sync_enabled(&fake));
        let client = connect(&custom(&server, &fake)).unwrap();
        assert_eq!(
            server.paths(),
            vec![
                "/v1/instance".to_string(),
                "/v1/capabilities".to_string(),
                "/v1/capabilities".to_string()
            ]
        );
        assert!(!sent_the_token(&server));
        let _ = tauri::async_runtime::block_on(client.devices());
        assert!(sent_the_token(&server));
    }

    #[test]
    fn a_server_with_a_rotated_key_is_refused_before_any_token_is_sent() {
        let pinned = FakeSesame::new(1);
        let rotated = FakeSesame::new(2);
        let server = TestServer::start(rotated.handler());
        let error = connect(&custom(&server, &pinned)).err().unwrap();
        assert!(error.contains("different key"), "{error}");
        assert!(!sent_the_token(&server));
        assert_eq!(server.paths(), vec!["/v1/instance".to_string()]);
    }

    #[test]
    fn a_server_that_only_repeats_the_pinned_key_is_refused() {
        let pinned = FakeSesame::new(1);
        let instance = pinned.instance();
        let mut payload = pinned.capability_payload();
        payload["features"]["sync"] = serde_json::json!(true);
        let mut forged = FakeSesame::new(2).signed(&payload);
        forged["keyId"] = serde_json::json!(pinned.key_id);
        let server = TestServer::start(move |request| match request.path.as_str() {
            "/v1/instance" => Reply::json(200, &instance),
            _ => Reply::json(200, &forged),
        });
        assert!(connect(&custom(&server, &pinned)).is_err());
        assert!(!sent_the_token(&server));
    }

    #[test]
    fn an_unreachable_pinned_server_gets_no_token() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let target = custom(&server, &fake);
        drop(server);
        assert!(connect(&target).is_err());
    }

    #[test]
    fn a_self_hosted_server_is_never_asked_for_an_entitlement() {
        let body = br#"{"error":{"code":"sync_not_entitled"}}"#;
        let fake = FakeSesame::new(1);
        let server = TestServer::start(sync_enabled(&fake));
        let own = connect(&custom(&server, &fake)).unwrap();
        assert!(matches!(
            own.classify(reqwest::StatusCode::PAYMENT_REQUIRED, body),
            SyncError::Unavailable(_)
        ));
        let mut official = SyncClient::for_tests(&server.base(), "fictional-device-token", "key");
        official.entitlement_enforced = true;
        assert!(matches!(
            official.classify(reqwest::StatusCode::PAYMENT_REQUIRED, body),
            SyncError::NotEntitled
        ));
    }
}
