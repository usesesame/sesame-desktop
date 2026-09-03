use crate::vault::VaultResult;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
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
    artifact_sha256: String,
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
            let artifact_sha256 = verify_candidate_receipt(
                &update.raw_json,
                &update.version,
                &update.signature,
                candidate_public_key,
                candidate_key_id,
                platform,
                updater_architecture()?,
            )?;
            Ok(VerifiedDesktopUpdate {
                update,
                artifact_sha256,
            })
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
    // Nothing decrypted may stay alive while the updater replaces the executable.
    crate::desktop_shell::lock_vault_if_unlocked(&app);
    crate::browser_fill::cancel_pending_approvals(&app);
    let progress_app = app.clone();
    let mut downloaded_bytes = 0_u64;
    let bytes = verified
        .update
        .download(
            move |chunk_bytes, total| {
                downloaded_bytes = downloaded_bytes.saturating_add(chunk_bytes as u64);
                let _ = progress_app.emit(
                    "desktop-update-progress",
                    DesktopUpdateProgress {
                        downloaded_bytes,
                        total_bytes: total,
                    },
                );
            },
            || {},
        )
        .await
        .map_err(|_| "Sesame could not download or verify the update.".to_string())?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if digest != verified.artifact_sha256 {
        return Err(
            "Sesame rejected an update that did not match its signed release receipt.".into(),
        );
    }
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
) -> VaultResult<String> {
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

    let claims: Vec<&str> = receipt.payload.split('\n').collect();
    // Claim 11 is the download URL the publisher signed. Comparing it to the URL
    // this manifest actually points at is what stops a tampered manifest from
    // redirecting an otherwise genuine receipt at a different file.
    let manifest_url = manifest
        .get("url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let expected_format = match expected_platform {
        "windows" => "nsis",
        "linux" => "appimage",
        _ => "",
    };
    if claims.len() != 17
        || claims[0] != "sesame-release-set-candidate-v1"
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
    Ok(claims[13].to_owned())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{updater_platform_for, verify_candidate_receipt};
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
        let digest = verify_candidate_receipt(
            &manifest,
            "1.2.3",
            &updater_signature,
            &public_key,
            "fictional-candidate-key",
            "windows",
            "x86_64",
        )
        .expect("verify receipt");
        assert_eq!(digest, "a".repeat(64));
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
}
