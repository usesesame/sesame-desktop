use crate::vault::VaultResult;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::Poll;
use tauri::{process::restart, AppHandle, Emitter, Manager};
#[derive(Clone, serde::Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DesktopUpdateStatus {
    pub available: bool,
    pub version: Option<String>,
    pub body: Option<String>,
}

#[derive(Clone, serde::Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
struct DesktopUpdateProgress {
    downloaded_bytes: u64,
    total_bytes: Option<u64>,
}

struct VerifiedDesktopUpdate {
    update: tauri_plugin_updater::Update,
    artifact: ReceiptArtifact,
}

#[derive(Debug, PartialEq, Eq)]
struct ReceiptArtifact {
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeRefusal {
    AnnouncedLength,
    ExceededSignedSize,
    ReceivedLength,
}

#[derive(Debug)]
enum DownloadFailure {
    Refused(SizeRefusal),
    Failed(tauri_plugin_updater::Error),
}

struct SignedSizeGuard {
    signed_size: u64,
    received: AtomicU64,
    refusal: OnceLock<SizeRefusal>,
}

impl SignedSizeGuard {
    fn new(signed_size: u64) -> Self {
        Self {
            signed_size,
            received: AtomicU64::new(0),
            refusal: OnceLock::new(),
        }
    }

    fn refuse(&self, refusal: SizeRefusal) {
        let _ = self.refusal.set(refusal);
    }

    fn observe(&self, chunk_len: usize, announced_length: Option<u64>) -> u64 {
        if announced_length.is_some_and(|length| length != self.signed_size) {
            self.refuse(SizeRefusal::AnnouncedLength);
        }
        let received = self
            .received
            .fetch_add(chunk_len as u64, Ordering::Relaxed)
            .saturating_add(chunk_len as u64);
        if received > self.signed_size {
            self.refuse(SizeRefusal::ExceededSignedSize);
        }
        received
    }

    fn refusal(&self) -> Option<SizeRefusal> {
        self.refusal.get().copied()
    }
}

async fn download_within_signed_size<Fut>(
    signed_size: u64,
    start: impl FnOnce(Arc<SignedSizeGuard>) -> Fut,
) -> Result<Vec<u8>, DownloadFailure>
where
    Fut: Future<Output = Result<Vec<u8>, tauri_plugin_updater::Error>>,
{
    let guard = Arc::new(SignedSizeGuard::new(signed_size));
    let mut download = std::pin::pin!(start(Arc::clone(&guard)));
    std::future::poll_fn(|context| {
        let polled = download.as_mut().poll(context);
        if let Some(refusal) = guard.refusal() {
            return Poll::Ready(Err(DownloadFailure::Refused(refusal)));
        }
        polled.map(|outcome| match outcome {
            Ok(bytes) if bytes.len() as u64 != signed_size => {
                Err(DownloadFailure::Refused(SizeRefusal::ReceivedLength))
            }
            Ok(bytes) => Ok(bytes),
            Err(error) => Err(DownloadFailure::Failed(error)),
        })
    })
    .await
}

fn download_failure_message(failure: &DownloadFailure) -> String {
    match failure {
        DownloadFailure::Refused(SizeRefusal::AnnouncedLength) => {
            "The update server announced a download size that differs from the signed size, so Sesame stopped it."
        }
        DownloadFailure::Refused(SizeRefusal::ExceededSignedSize) => {
            "The update download was larger than its signed size, so Sesame stopped it."
        }
        DownloadFailure::Refused(SizeRefusal::ReceivedLength) => {
            "The update download was shorter than its signed size, so Sesame stopped it."
        }
        DownloadFailure::Failed(tauri_plugin_updater::Error::Reqwest(error))
            if error.is_timeout() =>
        {
            "The update download took too long and was stopped."
        }
        DownloadFailure::Failed(_) => "Sesame could not download or verify the update.",
    }
    .to_string()
}

async fn download_verified_artifact(
    verified: &VerifiedDesktopUpdate,
    mut on_progress: impl FnMut(u64, Option<u64>) + Send,
) -> VaultResult<Vec<u8>> {
    let bytes = download_within_signed_size(verified.artifact.bytes, |guard| {
        verified.update.download(
            move |chunk_bytes, announced_length| {
                on_progress(
                    guard.observe(chunk_bytes, announced_length),
                    announced_length,
                );
            },
            || {},
        )
    })
    .await
    .map_err(|failure| download_failure_message(&failure))?;
    let digest = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != verified.artifact.sha256 {
        return Err(
            "Sesame rejected an update that did not match its signed release receipt.".into(),
        );
    }
    Ok(bytes)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CandidateReceipt {
    payload: String,
    signing_key_id: String,
    signature: String,
}

async fn check(app: &AppHandle) -> VaultResult<Option<VerifiedDesktopUpdate>> {
    let platform = updater_platform()?;
    if option_env!("SESAME_UPDATER_PUBLIC_KEY").is_none_or(|key| key.trim().is_empty()) {
        return Err("This Sesame build does not include an updater public key.".into());
    }
    let candidate_public_key = option_env!("SESAME_RELEASE_CANDIDATE_PUBLIC_KEY")
        .filter(|key| !key.trim().is_empty())
        .ok_or("This Sesame build does not include a release-candidate public key.")?;
    let candidate_key_id = option_env!("SESAME_RELEASE_CANDIDATE_KEY_ID")
        .filter(|key| !key.trim().is_empty())
        .ok_or("This Sesame build does not include a release-candidate key ID.")?;
    let update = crate::adapters::network::public_updates::check(app).await?;
    update
        .map(|update| {
            let artifact = verify_candidate_receipt(
                &update.raw_json,
                &update.version,
                &update.signature,
                candidate_public_key,
                candidate_key_id,
                platform,
                updater_architecture()?,
            )?;
            Ok(VerifiedDesktopUpdate { update, artifact })
        })
        .transpose()
}

#[tauri::command]
pub async fn check_desktop_update(app: AppHandle) -> VaultResult<DesktopUpdateStatus> {
    match check(&app).await? {
        Some(update) => Ok(DesktopUpdateStatus {
            available: true,
            version: Some(update.update.version),
            body: update.update.body,
        }),
        None => Ok(DesktopUpdateStatus {
            available: false,
            version: None,
            body: None,
        }),
    }
}

#[tauri::command]
pub async fn download_and_install_desktop_update(app: AppHandle) -> VaultResult<()> {
    let verified = check(&app).await?.ok_or("Sesame is already up to date.")?;
    let progress_app = app.clone();
    let bytes = download_verified_artifact(&verified, move |downloaded_bytes, total_bytes| {
        let _ = progress_app.emit(
            "desktop-update-progress",
            DesktopUpdateProgress {
                downloaded_bytes,
                total_bytes,
            },
        );
    })
    .await?;
    // Nothing decrypted may stay alive while the updater replaces the executable.
    crate::desktop_shell::lock_vault_if_unlocked(&app);
    crate::browser_fill::cancel_pending_approvals(&app);
    verified
        .update
        .install(&bytes)
        .map_err(|_| "Sesame could not install the verified update.".to_string())?;
    restart(&app.env());
}

fn updater_architecture() -> VaultResult<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64"),
        "aarch64" => Ok("aarch64"),
        _ => Err("This architecture is not supported by the Sesame updater.".into()),
    }
}

fn updater_platform() -> VaultResult<&'static str> {
    updater_platform_for(std::env::consts::OS)
}

fn updater_platform_for(os: &str) -> VaultResult<&'static str> {
    match os {
        "windows" => Ok("windows"),
        _ => Err("This operating system is not supported by the Sesame updater.".into()),
    }
}

fn verify_candidate_receipt(
    manifest: &serde_json::Value,
    announced_version: &str,
    updater_signature: &str,
    encoded_public_key: &str,
    expected_key_id: &str,
    expected_platform: &str,
    expected_architecture: &str,
) -> VaultResult<ReceiptArtifact> {
    let receipt: CandidateReceipt = serde_json::from_value(
        manifest
            .get("candidateReceipt")
            .cloned()
            .ok_or("The update manifest did not include its signed release receipt.")?,
    )
    .map_err(|_| "The update manifest contained an invalid release receipt.".to_string())?;
    if receipt.signing_key_id != expected_key_id {
        return Err("The update manifest used an unexpected release-candidate key.".into());
    }

    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(encoded_public_key)
        .map_err(|_| "The embedded release-candidate public key is invalid.".to_string())?;
    let public_key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "The embedded release-candidate public key is invalid.".to_string())?;
    let public_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| "The embedded release-candidate public key is invalid.".to_string())?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&receipt.signature)
        .map_err(|_| "The release-candidate signature is invalid.".to_string())?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "The release-candidate signature is invalid.".to_string())?;
    public_key
        .verify_strict(receipt.payload.as_bytes(), &signature)
        .map_err(|_| "Sesame rejected an update with an invalid release receipt.".to_string())?;

    let manifest_url = manifest
        .get("url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let expected_format = match expected_platform {
        "windows" => "nsis",
        "linux" => "appimage",
        _ => "",
    };
    let claims: Vec<&str> = receipt.payload.split('\n').collect();
    match claims.first().copied() {
        // Clients before 0.2.3 verify only the v3 receipt layout and 0.2.3
        // verifies only the release-set layout, so both are accepted until the
        // installed base is past the release that understands both.
        Some("sesame-release-set-candidate-v1") => {
            verify_set_candidate_claims(
                &claims,
                announced_version,
                expected_platform,
                expected_architecture,
                expected_format,
                manifest_url,
                updater_signature,
            )?;
            receipt_artifact(claims[13], claims[14])
        }
        Some("sesame-release-candidate-v3") => {
            verify_v3_candidate_claims(
                &claims,
                announced_version,
                expected_platform,
                expected_architecture,
                manifest_url,
                updater_signature,
            )?;
            receipt_artifact(claims[9], claims[10])
        }
        _ => Err(
            "Sesame rejected an update whose manifest did not match its signed release receipt."
                .into(),
        ),
    }
}

fn receipt_artifact(sha256: &str, bytes: &str) -> VaultResult<ReceiptArtifact> {
    let bytes = bytes
        .parse::<u64>()
        .ok()
        .filter(|bytes| *bytes > 0)
        .ok_or("The update manifest contained an invalid release receipt.")?;
    Ok(ReceiptArtifact {
        sha256: sha256.to_owned(),
        bytes,
    })
}

fn verify_set_candidate_claims(
    claims: &[&str],
    announced_version: &str,
    expected_platform: &str,
    expected_architecture: &str,
    expected_format: &str,
    manifest_url: &str,
    updater_signature: &str,
) -> VaultResult<()> {
    // Claim 11 is the download URL the publisher signed. Comparing it to the URL
    // this manifest actually points at is what stops a tampered manifest from
    // redirecting an otherwise genuine receipt at a different file.
    if claims.len() != 17
        || claims[1] != announced_version
        || claims[3] != expected_platform
        || claims[4] != expected_architecture
        || !valid_sha256(claims[7])
        || claims[8] != "updater"
        || claims[9] != expected_format
        || claims[10] != expected_architecture
        || claims[11].is_empty()
        || claims[11] != manifest_url
        || claims[12].is_empty()
        || !valid_sha256(claims[13])
        || claims[14]
            .parse::<u64>()
            .ok()
            .is_none_or(|bytes| bytes == 0)
        || claims[15] != updater_signature
        || claims[16].is_empty()
    {
        return Err(
            "Sesame rejected an update whose manifest did not match its signed release receipt."
                .into(),
        );
    }
    Ok(())
}

fn verify_v3_candidate_claims(
    claims: &[&str],
    announced_version: &str,
    expected_platform: &str,
    expected_architecture: &str,
    manifest_url: &str,
    updater_signature: &str,
) -> VaultResult<()> {
    let expected_sigstore_identity = format!(
        "https://github.com/usesesame/sesame-desktop/.github/workflows/release-early-access.yml@refs/tags/v{announced_version}"
    );
    // Claim 7 is the download URL the publisher signed. Comparing it to the URL
    // this manifest actually points at is what stops a tampered manifest from
    // redirecting an otherwise genuine receipt at a different file.
    if claims.len() != 23
        || claims[1] != announced_version
        || claims[3] != expected_platform
        || claims[4] != expected_architecture
        || claims[7].is_empty()
        || claims[7] != manifest_url
        || claims[8].is_empty()
        || !valid_sha256(claims[9])
        || claims[10]
            .parse::<u64>()
            .ok()
            .is_none_or(|bytes| bytes == 0)
        || claims[11] != updater_signature
        || claims[12].is_empty()
        || (claims[13] != "early_access" && claims[13] != "production")
        || claims[14] != "true"
        || claims[15] != "https://token.actions.githubusercontent.com"
        || claims[16] != expected_sigstore_identity
        || !valid_sha256(claims[17])
        || !valid_base64url_sha256(claims[18])
        || (claims[19] != "true" && claims[19] != "false")
        || (claims[13] == "early_access" && claims[19] != "false")
        || (claims[13] == "production" && claims[19] != "true")
        || (claims[19] == "true" && (claims[20].is_empty() || claims[21].is_empty()))
        || (claims[19] == "true" && !valid_base64url_sha256(claims[22]))
        || (claims[19] == "false" && !claims[22].is_empty())
    {
        return Err(
            "Sesame rejected an update whose manifest did not match its signed release receipt."
                .into(),
        );
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_base64url_sha256(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 32)
}

#[cfg(test)]
mod tests {
    use super::{updater_platform_for, verify_candidate_receipt, ReceiptArtifact};
    use crate::vault::VaultResult;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn signed_manifest() -> (serde_json::Value, String, String) {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let artifact_sha256 = "a".repeat(64);
        let updater_signature = "s".repeat(64);
        let payload = [
            "sesame-release-set-candidate-v1".to_owned(),
            "1.2.3".to_owned(),
            "beta".to_owned(),
            "windows".to_owned(),
            "x86_64".to_owned(),
            "Windows 10,Windows 11".to_owned(),
            "https://example.invalid/releases/1.2.3".to_owned(),
            "b".repeat(64),
            "updater".to_owned(),
            "nsis".to_owned(),
            "x86_64".to_owned(),
            "https://downloads.example.invalid/Sesame.exe".to_owned(),
            "windows/1.2.3/Sesame.exe".to_owned(),
            artifact_sha256.clone(),
            "42".to_owned(),
            updater_signature.clone(),
            "fictional-updater-key".to_owned(),
        ]
        .join("\n");
        let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(payload.as_bytes()).to_bytes());
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let manifest = json!({
            "url": "https://downloads.example.invalid/Sesame.exe",
            "candidateReceipt": {
                "payload": payload,
                "signingKeyId": "fictional-candidate-key",
                "signature": signature,
            }
        });
        (manifest, public_key, updater_signature)
    }

    #[test]
    fn verifies_the_signed_updater_binding() {
        let (manifest, public_key, updater_signature) = signed_manifest();
        let artifact = verify_candidate_receipt(
            &manifest,
            "1.2.3",
            &updater_signature,
            &public_key,
            "fictional-candidate-key",
            "windows",
            "x86_64",
        )
        .expect("verify receipt");
        assert_eq!(artifact.sha256, "a".repeat(64));
        assert_eq!(artifact.bytes, 42);
    }

    #[test]
    fn rejects_a_redirected_or_relabelled_updater() {
        let (mut manifest, public_key, updater_signature) = signed_manifest();
        manifest["url"] = json!("https://downloads.example.invalid/other.exe");
        assert!(verify_candidate_receipt(
            &manifest,
            "1.2.3",
            &updater_signature,
            &public_key,
            "fictional-candidate-key",
            "windows",
            "x86_64",
        )
        .is_err());
        let (manifest, _, _) = signed_manifest();
        assert!(verify_candidate_receipt(
            &manifest,
            "9.9.9",
            &updater_signature,
            &public_key,
            "fictional-candidate-key",
            "windows",
            "x86_64",
        )
        .is_err());
    }

    #[test]
    fn updater_support_matches_the_release_pipeline() {
        assert_eq!(updater_platform_for("windows").ok(), Some("windows"));
        assert!(updater_platform_for("linux").is_err());
    }

    fn signed_v3_manifest() -> (serde_json::Value, String, String) {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let artifact_sha256 = "a".repeat(64);
        let updater_signature = "s".repeat(64);
        let sigstore_identity =
            "https://github.com/usesesame/sesame-desktop/.github/workflows/release-early-access.yml@refs/tags/v1.2.3";
        let payload = [
            "sesame-release-candidate-v3".to_owned(),
            "1.2.3".to_owned(),
            "beta".to_owned(),
            "windows".to_owned(),
            "x86_64".to_owned(),
            "Windows 10,Windows 11".to_owned(),
            "https://example.invalid/releases/1.2.3".to_owned(),
            "https://downloads.example.invalid/Sesame.exe".to_owned(),
            "windows/1.2.3/Sesame.exe".to_owned(),
            artifact_sha256.clone(),
            "42".to_owned(),
            updater_signature.clone(),
            "fictional-updater-key".to_owned(),
            "early_access".to_owned(),
            "true".to_owned(),
            "https://token.actions.githubusercontent.com".to_owned(),
            sigstore_identity.to_owned(),
            "c".repeat(64),
            "A".repeat(43),
            "false".to_owned(),
            String::new(),
            String::new(),
            String::new(),
        ]
        .join("\n");
        let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(payload.as_bytes()).to_bytes());
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let manifest = json!({
            "url": "https://downloads.example.invalid/Sesame.exe",
            "candidateReceipt": {
                "payload": payload,
                "signingKeyId": "fictional-candidate-key",
                "signature": signature,
            }
        });
        (manifest, public_key, updater_signature)
    }

    #[test]
    fn verifies_a_v3_receipt_from_clients_before_0_2_3() {
        let (manifest, public_key, updater_signature) = signed_v3_manifest();
        let artifact = verify_candidate_receipt(
            &manifest,
            "1.2.3",
            &updater_signature,
            &public_key,
            "fictional-candidate-key",
            "windows",
            "x86_64",
        )
        .expect("verify v3 receipt");
        assert_eq!(artifact.sha256, "a".repeat(64));
        assert_eq!(artifact.bytes, 42);
    }

    #[test]
    fn rejects_a_v3_receipt_bound_to_another_version_or_download() {
        let (manifest, public_key, updater_signature) = signed_v3_manifest();
        assert!(verify_candidate_receipt(
            &manifest,
            "9.9.9",
            &updater_signature,
            &public_key,
            "fictional-candidate-key",
            "windows",
            "x86_64",
        )
        .is_err());
        let (mut manifest, public_key, updater_signature) = signed_v3_manifest();
        manifest["url"] = json!("https://downloads.example.invalid/other.exe");
        assert!(verify_candidate_receipt(
            &manifest,
            "1.2.3",
            &updater_signature,
            &public_key,
            "fictional-candidate-key",
            "windows",
            "x86_64",
        )
        .is_err());
    }

    const RELEASE_SET_FIXTURE: &str =
        include_str!("../../tests/fixtures/update-manifests/release-set-early-access.latest.json");
    const V3_EARLY_ACCESS_FIXTURE: &str =
        include_str!("../../tests/fixtures/update-manifests/v3-early-access.latest.json");
    const V3_PRODUCTION_FIXTURE: &str =
        include_str!("../../tests/fixtures/update-manifests/v3-production.latest.json");
    const RECEIPT_KEY_FIXTURE: &str =
        include_str!("../../tests/fixtures/update-manifests/receipt-key.json");
    const TOOL_FIXTURES: [&str; 3] = [
        RELEASE_SET_FIXTURE,
        V3_EARLY_ACCESS_FIXTURE,
        V3_PRODUCTION_FIXTURE,
    ];

    struct ToolManifest {
        manifest: serde_json::Value,
        public_key: String,
        key_id: String,
    }

    impl ToolManifest {
        fn load(source: &str) -> Self {
            let key: serde_json::Value =
                serde_json::from_str(RECEIPT_KEY_FIXTURE).expect("receipt key fixture");
            Self {
                manifest: serde_json::from_str(source).expect("manifest fixture"),
                public_key: key["publicKey"].as_str().expect("public key").to_owned(),
                key_id: key["keyId"].as_str().expect("key id").to_owned(),
            }
        }

        fn updater_signature(&self) -> String {
            self.manifest["platforms"]["windows-x86_64-nsis"]["signature"]
                .as_str()
                .expect("updater signature")
                .to_owned()
        }

        fn verify(
            &self,
            version: &str,
            platform: &str,
            architecture: &str,
        ) -> VaultResult<ReceiptArtifact> {
            verify_candidate_receipt(
                &self.manifest,
                version,
                &self.updater_signature(),
                &self.public_key,
                &self.key_id,
                platform,
                architecture,
            )
        }
    }

    #[test]
    fn accepts_every_receipt_layout_the_release_tool_writes() {
        for source in TOOL_FIXTURES {
            let fixture = ToolManifest::load(source);
            let artifact = fixture
                .verify("1.2.3", "windows", "x86_64")
                .expect("verify tool manifest");
            assert_eq!(artifact.sha256, "a".repeat(64));
            assert_eq!(artifact.bytes, 42);
        }
    }

    #[test]
    fn rejects_a_tool_manifest_without_its_top_level_download_url() {
        for source in TOOL_FIXTURES {
            let mut fixture = ToolManifest::load(source);
            fixture
                .manifest
                .as_object_mut()
                .expect("object")
                .remove("url");
            assert!(fixture.verify("1.2.3", "windows", "x86_64").is_err());
        }
    }

    #[test]
    fn rejects_a_tool_manifest_for_another_version_platform_or_download() {
        for source in TOOL_FIXTURES {
            let fixture = ToolManifest::load(source);
            assert!(fixture.verify("1.2.4", "windows", "x86_64").is_err());
            assert!(fixture.verify("1.2.2", "windows", "x86_64").is_err());
            assert!(fixture.verify("1.2.3", "linux", "x86_64").is_err());
            assert!(fixture.verify("1.2.3", "windows", "aarch64").is_err());
            let mut redirected = ToolManifest::load(source);
            redirected.manifest["url"] = json!("https://downloads.example.test/v1.2.3/other.exe");
            assert!(redirected.verify("1.2.3", "windows", "x86_64").is_err());
            let mut relabelled = ToolManifest::load(source);
            relabelled.manifest["platforms"]["windows-x86_64-nsis"]["signature"] =
                json!("B".repeat(64));
            assert!(relabelled.verify("1.2.3", "windows", "x86_64").is_err());
        }
    }

    #[test]
    fn rejects_a_stale_receipt_attached_to_a_newer_manifest() {
        let stale = ToolManifest::load(V3_EARLY_ACCESS_FIXTURE);
        let mut newer = ToolManifest::load(V3_EARLY_ACCESS_FIXTURE);
        newer.manifest["version"] = json!("1.2.4");
        newer.manifest["candidateReceipt"] = stale.manifest["candidateReceipt"].clone();
        assert!(newer.verify("1.2.4", "windows", "x86_64").is_err());
    }

    #[test]
    fn rejects_a_truncated_or_tampered_tool_receipt() {
        for source in TOOL_FIXTURES {
            let mut truncated = ToolManifest::load(source);
            let payload = truncated.manifest["candidateReceipt"]["payload"]
                .as_str()
                .expect("payload")
                .to_owned();
            let cut = payload.rfind('\n').expect("claim separator");
            truncated.manifest["candidateReceipt"]["payload"] = json!(&payload[..cut]);
            assert!(truncated.verify("1.2.3", "windows", "x86_64").is_err());

            let mut forged_signature = ToolManifest::load(source);
            let signature = forged_signature.manifest["candidateReceipt"]["signature"]
                .as_str()
                .expect("signature")
                .to_owned();
            let flipped = if signature.starts_with('A') { 'B' } else { 'A' };
            forged_signature.manifest["candidateReceipt"]["signature"] =
                json!(format!("{flipped}{}", &signature[1..]));
            assert!(forged_signature
                .verify("1.2.3", "windows", "x86_64")
                .is_err());

            let mut other_key = ToolManifest::load(source);
            other_key.key_id = "another-key".to_owned();
            assert!(other_key.verify("1.2.3", "windows", "x86_64").is_err());

            let mut other_public_key = ToolManifest::load(source);
            other_public_key.public_key = URL_SAFE_NO_PAD.encode(
                SigningKey::from_bytes(&[9_u8; 32])
                    .verifying_key()
                    .to_bytes(),
            );
            assert!(other_public_key
                .verify("1.2.3", "windows", "x86_64")
                .is_err());

            let mut missing = ToolManifest::load(source);
            missing
                .manifest
                .as_object_mut()
                .expect("object")
                .remove("candidateReceipt");
            assert!(missing.verify("1.2.3", "windows", "x86_64").is_err());
        }
    }

    #[test]
    fn the_production_receipt_carries_the_publisher_signature_claims() {
        let production = ToolManifest::load(V3_PRODUCTION_FIXTURE);
        let payload = production.manifest["candidateReceipt"]["payload"]
            .as_str()
            .expect("payload");
        let claims: Vec<&str> = payload.split('\n').collect();
        assert_eq!(claims[13], "production");
        assert_eq!(claims[19], "true");
        assert!(!claims[20].is_empty() && !claims[21].is_empty());
    }
}

#[cfg(test)]
mod download_tests {
    use super::{
        download_verified_artifact, download_within_signed_size, DownloadFailure, ReceiptArtifact,
        SignedSizeGuard, SizeRefusal, VerifiedDesktopUpdate,
    };
    use crate::adapters::network::public_updates::{check_endpoint, TransferLimits};
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};
    use std::task::{Context, Poll};
    use std::thread;
    use std::time::{Duration, Instant};
    use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime};

    const FIXTURE_UPDATER_PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IENERDcyNDRFOEEzOUNFQzQKUldURXpqbUtUaVRYemEvVUlKalpjSzZqMzNvbVZ6cFg4amlhUFdwU1A0S0VpaytCaG1jeURESTIK";
    const FIXTURE_ARTIFACT: &[u8] =
        b"sesame fictional installer body, 64 bytes of text for signing.....";
    const FIXTURE_SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVURXpqbUtUaVRYemE3RlpuUXlXV2JNeTlPaGlDRHJqcDZVdDE0RnJpTkxuYzltaXpsZ2k5VDBpMmtJRVVPakpXU0kveGc5d3dPOUpCZkpjVEwyRGgrZWZGL3JmWkZzWmdFPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkxMjE4NTYxCWZpbGU6Ym9keS5iaW4KenpKTVNRUWlrUGJreFlaZFpUbVhMMkhKRGxldDhoRDRwK2N6VFk2aTh1NjFXNGhud21EQUsxM2QvSVdBL3FZZ2d0RnZuU1p4ZTZWTVRJUW9xUFpvQ3c9PQo=";

    fn signed_size() -> u64 {
        FIXTURE_ARTIFACT.len() as u64
    }

    fn quick_limits() -> TransferLimits {
        TransferLimits {
            connect: Duration::from_secs(2),
            read: Duration::from_millis(400),
            manifest_total: Duration::from_secs(5),
            download_total: Duration::from_secs(2),
        }
    }

    struct TestServer {
        host: &'static str,
        port: u16,
        connections: Arc<AtomicUsize>,
    }

    impl TestServer {
        fn url(&self, path: &str) -> String {
            format!("http://{}:{}{path}", self.host, self.port)
        }
    }

    fn request_path(stream: &mut TcpStream) -> Option<String> {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).ok()?;
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).ok()?;
        head.split_whitespace().nth(1).map(str::to_owned)
    }

    fn start(
        listener: TcpListener,
        host: &'static str,
        route: impl Fn(&str, &mut TcpStream) + Send + Sync + 'static,
    ) -> TestServer {
        let port = listener.local_addr().expect("address").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        let route = Arc::new(route);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                let route = Arc::clone(&route);
                thread::spawn(move || {
                    if let Some(path) = request_path(&mut stream) {
                        route(&path, &mut stream);
                    }
                });
            }
        });
        TestServer {
            host,
            port,
            connections,
        }
    }

    fn serve(
        host: &'static str,
        route: impl Fn(&str, &mut TcpStream) + Send + Sync + 'static,
    ) -> TestServer {
        start(TcpListener::bind((host, 0)).expect("bind"), host, route)
    }

    fn manifest(version: &str, artifact_url: &str) -> String {
        let target = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        serde_json::json!({
            "version": version,
            "notes": "fictional release",
            "platforms": { target: { "url": artifact_url, "signature": FIXTURE_SIGNATURE } },
        })
        .to_string()
    }

    fn respond(stream: &mut TcpStream, status: &str, headers: &[String], body: &[u8]) {
        let mut head = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
        for header in headers {
            head.push_str(header);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }

    fn respond_with_length(stream: &mut TcpStream, declared: u64, body: &[u8]) {
        respond(
            stream,
            "200 OK",
            &[format!("Content-Length: {declared}")],
            body,
        );
    }

    fn write_chunk(stream: &mut TcpStream, data: &[u8]) -> bool {
        stream
            .write_all(format!("{:x}\r\n", data.len()).as_bytes())
            .and_then(|()| stream.write_all(data))
            .and_then(|()| stream.write_all(b"\r\n"))
            .is_ok()
    }

    fn serve_release(
        version: &'static str,
        artifact: impl Fn(&mut TcpStream) + Send + Sync + 'static,
    ) -> TestServer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().expect("address").port();
        let manifest_body = manifest(version, &format!("http://127.0.0.1:{port}/Sesame.exe"));
        start(listener, "127.0.0.1", move |path, stream| {
            if path == "/latest.json" {
                respond(
                    stream,
                    "200 OK",
                    &[
                        "Content-Type: application/json".to_owned(),
                        format!("Content-Length: {}", manifest_body.len()),
                    ],
                    manifest_body.as_bytes(),
                );
            } else {
                artifact(stream);
            }
        })
    }

    fn updater_app() -> tauri::App<MockRuntime> {
        let mut context = mock_context(noop_assets());
        context.config_mut().plugins.0.insert(
            "updater".to_owned(),
            serde_json::json!({ "pubkey": FIXTURE_UPDATER_PUBLIC_KEY }),
        );
        mock_builder()
            .plugin(tauri_plugin_updater::Builder::new().build())
            .build(context)
            .expect("mock app")
    }

    fn endpoint(server: &TestServer) -> url::Url {
        url::Url::parse(&server.url("/latest.json")).expect("endpoint")
    }

    fn fetch(server: &TestServer, limits: TransferLimits) -> Result<Vec<u8>, DownloadFailure> {
        let app = updater_app();
        tauri::async_runtime::block_on(async {
            let update = check_endpoint(app.handle(), endpoint(server), limits)
                .await
                .expect("check")
                .expect("update available");
            download_within_signed_size(signed_size(), |guard| {
                update.download(
                    move |chunk_bytes, announced_length| {
                        guard.observe(chunk_bytes, announced_length);
                    },
                    || {},
                )
            })
            .await
        })
    }

    fn verified_update(
        server: &TestServer,
        sha256: &str,
        bytes: u64,
    ) -> (tauri::App<MockRuntime>, VerifiedDesktopUpdate) {
        let app = updater_app();
        let update = tauri::async_runtime::block_on(check_endpoint(
            app.handle(),
            endpoint(server),
            quick_limits(),
        ))
        .expect("check")
        .expect("update available");
        let artifact = ReceiptArtifact {
            sha256: sha256.to_owned(),
            bytes,
        };
        (app, VerifiedDesktopUpdate { update, artifact })
    }

    fn fixture_sha256() -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(FIXTURE_ARTIFACT)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn the_install_path_gets_the_artifact_only_when_size_signature_and_digest_agree() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        let (_app, verified) = verified_update(&server, &fixture_sha256(), signed_size());
        let progress = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&progress);
        let bytes = tauri::async_runtime::block_on(download_verified_artifact(
            &verified,
            move |downloaded, total| recorded.lock().expect("progress").push((downloaded, total)),
        ))
        .expect("verified artifact");
        assert_eq!(bytes, FIXTURE_ARTIFACT);
        let progress = progress.lock().expect("progress");
        assert_eq!(progress.last(), Some(&(signed_size(), Some(signed_size()))));
    }

    #[test]
    fn the_install_path_refuses_a_signed_body_whose_digest_is_not_in_the_receipt() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        let (_app, verified) = verified_update(&server, &"0".repeat(64), signed_size());
        let message =
            tauri::async_runtime::block_on(download_verified_artifact(&verified, |_, _| {}))
                .expect_err("digest mismatch");
        assert!(message.contains("did not match its signed release receipt"));
    }

    #[test]
    fn the_install_path_refuses_a_body_that_differs_from_the_receipt_size() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        for receipt_size in [signed_size() - 1, signed_size() + 1] {
            let (_app, verified) = verified_update(&server, &fixture_sha256(), receipt_size);
            let message =
                tauri::async_runtime::block_on(download_verified_artifact(&verified, |_, _| {}))
                    .expect_err("size mismatch");
            assert!(message.contains("signed size"), "{message}");
        }
    }

    fn is_timeout(failure: &DownloadFailure) -> bool {
        matches!(
            failure,
            DownloadFailure::Failed(tauri_plugin_updater::Error::Reqwest(error)) if error.is_timeout()
        )
    }

    #[test]
    fn downloads_and_verifies_a_body_of_the_signed_size() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        let bytes = fetch(&server, quick_limits()).expect("download");
        assert_eq!(bytes, FIXTURE_ARTIFACT);
    }

    #[test]
    fn the_download_carries_the_total_time_limit() {
        let server = serve_release("1.2.3", |_| {});
        let app = updater_app();
        let update = tauri::async_runtime::block_on(check_endpoint(
            app.handle(),
            endpoint(&server),
            quick_limits(),
        ))
        .expect("check")
        .expect("update available");
        assert_eq!(update.timeout, Some(quick_limits().download_total));
    }

    #[test]
    fn keeps_the_plugin_signature_check_for_a_body_of_the_signed_size() {
        let server = serve_release("1.2.3", |stream| {
            let forged = vec![b'x'; FIXTURE_ARTIFACT.len()];
            respond_with_length(stream, signed_size(), &forged);
        });
        let failure = fetch(&server, quick_limits()).expect_err("forged body");
        assert!(matches!(
            failure,
            DownloadFailure::Failed(tauri_plugin_updater::Error::Minisign(_))
        ));
    }

    #[test]
    fn stops_an_endless_body_at_the_signed_size() {
        let (finished, written) = mpsc::channel();
        let server = serve_release("1.2.3", move |stream| {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            let block = vec![0_u8; 8192];
            let mut total = 0_u64;
            while total < 256 * 1024 * 1024 && write_chunk(stream, &block) {
                total += block.len() as u64;
            }
            let _ = finished.send(total);
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("endless body");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::ExceededSignedSize)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        let total = written
            .recv_timeout(Duration::from_secs(10))
            .expect("server stopped writing");
        assert!(total < 256 * 1024 * 1024);
    }

    #[test]
    fn refuses_a_larger_body_with_an_honest_length_header() {
        let server = serve_release("1.2.3", |stream| {
            let oversized = vec![0_u8; 1024 * 1024];
            respond_with_length(stream, oversized.len() as u64, &oversized);
        });
        let failure = fetch(&server, quick_limits()).expect_err("oversized body");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::AnnouncedLength)
        ));
    }

    #[test]
    fn refuses_a_smaller_body_with_an_honest_length_header() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, 20, &FIXTURE_ARTIFACT[..20]);
        });
        let failure = fetch(&server, quick_limits()).expect_err("short body");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::AnnouncedLength)
        ));
    }

    #[test]
    fn refuses_a_length_header_that_understates_the_body() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, 10, FIXTURE_ARTIFACT);
        });
        let failure = fetch(&server, quick_limits()).expect_err("understated length");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::AnnouncedLength)
        ));
    }

    #[test]
    fn refuses_a_length_header_that_overstates_the_body() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, 5_000_000_000, FIXTURE_ARTIFACT);
            thread::sleep(Duration::from_secs(1));
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("overstated length");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::AnnouncedLength)
        ));
        assert!(started.elapsed() < Duration::from_millis(900));
    }

    #[test]
    fn refuses_a_body_that_ends_before_its_declared_length() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), &FIXTURE_ARTIFACT[..20]);
        });
        let failure = fetch(&server, quick_limits()).expect_err("cut body");
        assert!(matches!(failure, DownloadFailure::Failed(_)));
    }

    #[test]
    fn refuses_a_chunked_body_that_ends_early() {
        let server = serve_release("1.2.3", |stream| {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            write_chunk(stream, &FIXTURE_ARTIFACT[..20]);
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        let failure = fetch(&server, quick_limits()).expect_err("early end");
        assert!(matches!(
            failure,
            DownloadFailure::Failed(tauri_plugin_updater::Error::Minisign(_))
        ));
    }

    #[test]
    fn stops_a_body_that_stalls_after_the_headers() {
        let server = serve_release("1.2.3", |stream| {
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    signed_size()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(&FIXTURE_ARTIFACT[..10]);
            let _ = stream.flush();
            thread::sleep(Duration::from_secs(4));
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("stalled body");
        assert!(is_timeout(&failure), "{failure:?}");
        assert!(started.elapsed() < Duration::from_millis(1500));
    }

    #[test]
    fn stops_a_body_that_trickles_past_the_total_limit() {
        let server = serve_release("1.2.3", |stream| {
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    signed_size()
                )
                .as_bytes(),
            );
            for byte in FIXTURE_ARTIFACT {
                if stream
                    .write_all(&[*byte])
                    .and_then(|()| stream.flush())
                    .is_err()
                {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("trickling body");
        assert!(is_timeout(&failure), "{failure:?}");
        assert!(started.elapsed() < Duration::from_millis(3500));
    }

    #[test]
    fn stops_a_server_that_never_sends_a_response() {
        let server = serve_release("1.2.3", |_| {
            thread::sleep(Duration::from_secs(5));
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("silent server");
        assert!(is_timeout(&failure), "{failure:?}");
        assert!(started.elapsed() < Duration::from_millis(3500));
    }

    #[test]
    fn does_not_follow_a_download_redirect_to_another_host() {
        let other = serve("127.0.0.2", |_, stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        let target = other.url("/Sesame.exe");
        let server = serve_release("1.2.3", move |stream| {
            respond(stream, "302 Found", &[format!("Location: {target}")], b"");
        });
        let failure = fetch(&server, quick_limits()).expect_err("redirected download");
        assert!(matches!(failure, DownloadFailure::Failed(_)));
        assert_eq!(other.connections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn does_not_follow_a_download_redirect_to_the_same_host_over_http() {
        let server = serve_release("1.2.3", |stream| {
            respond(
                stream,
                "302 Found",
                &["Location: /elsewhere.exe".to_owned()],
                b"",
            );
        });
        let failure = fetch(&server, quick_limits()).expect_err("redirected download");
        assert!(matches!(failure, DownloadFailure::Failed(_)));
    }

    #[test]
    fn does_not_follow_a_manifest_redirect_to_another_host() {
        let other = serve("127.0.0.2", |_, stream| {
            let body = manifest("1.2.3", "http://127.0.0.2/Sesame.exe");
            respond(
                stream,
                "200 OK",
                &[format!("Content-Length: {}", body.len())],
                body.as_bytes(),
            );
        });
        let target = other.url("/latest.json");
        let server = serve("127.0.0.1", move |_, stream| {
            respond(stream, "302 Found", &[format!("Location: {target}")], b"");
        });
        let app = updater_app();
        let result = tauri::async_runtime::block_on(check_endpoint(
            app.handle(),
            endpoint(&server),
            quick_limits(),
        ));
        assert!(result.is_err());
        assert_eq!(other.connections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ignores_a_replayed_manifest_for_the_installed_or_an_older_version() {
        for replayed in ["0.1.0", "0.0.9"] {
            let server = serve_release(replayed, |_| {});
            let app = updater_app();
            let update = tauri::async_runtime::block_on(check_endpoint(
                app.handle(),
                endpoint(&server),
                quick_limits(),
            ))
            .expect("check");
            assert!(update.is_none(), "{replayed} must not offer an update");
        }
    }

    struct YieldOnce(bool);

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    async fn scripted_download(
        guard: Arc<SignedSizeGuard>,
        chunks: Vec<usize>,
        announced_length: Option<u64>,
        delivered: Arc<AtomicUsize>,
    ) -> Result<Vec<u8>, tauri_plugin_updater::Error> {
        let mut body = Vec::new();
        for chunk in chunks {
            YieldOnce(false).await;
            delivered.fetch_add(1, Ordering::SeqCst);
            guard.observe(chunk, announced_length);
            body.extend(std::iter::repeat_n(0_u8, chunk));
        }
        Ok(body)
    }

    fn run_scripted(
        signed: u64,
        chunks: Vec<usize>,
        announced_length: Option<u64>,
    ) -> (Result<Vec<u8>, DownloadFailure>, usize) {
        let delivered = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&delivered);
        let outcome =
            tauri::async_runtime::block_on(download_within_signed_size(signed, move |guard| {
                scripted_download(guard, chunks, announced_length, counter)
            }));
        (outcome, delivered.load(Ordering::SeqCst))
    }

    #[test]
    fn a_body_of_exactly_the_signed_size_passes() {
        let (outcome, _) = run_scripted(100, vec![40, 60], Some(100));
        assert_eq!(outcome.expect("download").len(), 100);
        let (outcome, _) = run_scripted(100, vec![40, 60], None);
        assert_eq!(outcome.expect("download").len(), 100);
    }

    #[test]
    fn a_body_past_the_signed_size_is_dropped_at_the_first_excess_chunk() {
        let (outcome, delivered) = run_scripted(100, vec![60; 1000], None);
        assert!(matches!(
            outcome,
            Err(DownloadFailure::Refused(SizeRefusal::ExceededSignedSize))
        ));
        assert_eq!(delivered, 2);
    }

    #[test]
    fn a_body_short_of_the_signed_size_is_refused() {
        let (outcome, _) = run_scripted(100, vec![40, 59], None);
        assert!(matches!(
            outcome,
            Err(DownloadFailure::Refused(SizeRefusal::ReceivedLength))
        ));
        let (outcome, _) = run_scripted(100, Vec::new(), None);
        assert!(matches!(
            outcome,
            Err(DownloadFailure::Refused(SizeRefusal::ReceivedLength))
        ));
    }

    #[test]
    fn an_announced_length_that_differs_from_the_signed_size_is_refused_at_once() {
        for announced in [99, 101, u64::MAX] {
            let (outcome, delivered) = run_scripted(100, vec![10; 1000], Some(announced));
            assert!(matches!(
                outcome,
                Err(DownloadFailure::Refused(SizeRefusal::AnnouncedLength))
            ));
            assert_eq!(delivered, 1);
        }
    }
}
