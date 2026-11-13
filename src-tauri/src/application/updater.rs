use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::vault::VaultResult;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReceiptArtifact {
    pub(crate) sha256: String,
    pub(crate) bytes: u64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CandidateReceipt {
    payload: String,
    signing_key_id: String,
    signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SizeRefusal {
    AnnouncedLength,
    ExceededSignedSize,
    ReceivedLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownloadFailureKind {
    Refused(SizeRefusal),
    TimedOut,
    Failed,
}

pub(crate) struct UpdaterTrust {
    platform: &'static str,
    candidate_public_key: &'static str,
    candidate_key_id: &'static str,
}

pub(crate) struct UpdateRelease {
    pub(crate) version: String,
    pub(crate) body: Option<String>,
}

pub(crate) struct UpdateStatus {
    pub(crate) available: bool,
    pub(crate) version: Option<String>,
    pub(crate) body: Option<String>,
}

pub(crate) fn updater_trust() -> VaultResult<UpdaterTrust> {
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
    Ok(UpdaterTrust {
        platform,
        candidate_public_key,
        candidate_key_id,
    })
}

pub(crate) fn verify_update_manifest(
    trust: &UpdaterTrust,
    manifest: &serde_json::Value,
    announced_version: &str,
    updater_signature: &str,
) -> VaultResult<ReceiptArtifact> {
    verify_candidate_receipt(
        manifest,
        announced_version,
        updater_signature,
        trust.candidate_public_key,
        trust.candidate_key_id,
        trust.platform,
        updater_architecture()?,
    )
}

pub(crate) fn update_status(checked: Option<UpdateRelease>) -> UpdateStatus {
    match checked {
        Some(release) => UpdateStatus {
            available: true,
            version: Some(release.version),
            body: release.body,
        },
        None => UpdateStatus {
            available: false,
            version: None,
            body: None,
        },
    }
}

pub(crate) fn require_available_update<T>(checked: Option<T>) -> VaultResult<T> {
    checked.ok_or_else(|| "Sesame is already up to date.".to_string())
}

pub(crate) fn verify_artifact_digest(digest: &str, artifact: &ReceiptArtifact) -> VaultResult<()> {
    if digest != artifact.sha256.as_str() {
        return Err(
            "Sesame rejected an update that did not match its signed release receipt.".into(),
        );
    }
    Ok(())
}

pub(crate) fn download_failure_message(failure: DownloadFailureKind) -> String {
    match failure {
        DownloadFailureKind::Refused(SizeRefusal::AnnouncedLength) => {
            "The update server announced a download size that differs from the signed size, so Sesame stopped it."
        }
        DownloadFailureKind::Refused(SizeRefusal::ExceededSignedSize) => {
            "The update download was larger than its signed size, so Sesame stopped it."
        }
        DownloadFailureKind::Refused(SizeRefusal::ReceivedLength) => {
            "The update download was shorter than its signed size, so Sesame stopped it."
        }
        DownloadFailureKind::TimedOut => "The update download took too long and was stopped.",
        DownloadFailureKind::Failed => "Sesame could not download or verify the update.",
    }
    .to_string()
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

pub(crate) fn updater_platform_for(os: &str) -> VaultResult<&'static str> {
    match os {
        "windows" => Ok("windows"),
        _ => Err("This operating system is not supported by the Sesame updater.".into()),
    }
}

pub(crate) fn verify_candidate_receipt(
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

pub(crate) fn valid_base64url_sha256(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 32)
}
