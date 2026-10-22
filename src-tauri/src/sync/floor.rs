use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::sync::state::{read_tagged, write_tagged};
use crate::vault::VaultResult;

pub const FLOOR_FILE_NAME: &str = "sync-floor.json";
const PAYLOAD_LABEL: &str = "sesame-sync-floor-v1";
const TAG_LABEL: &[u8] = b"sesame-sync-floor-tag-v1";
const MANIFEST_RECEIPT_SET_LABEL: &str = "sesame-release-set-candidate-v1";
pub(crate) const REFUSAL: &str =
    "This version of Sesame can no longer use Sync. Update Sesame to keep syncing.";
pub(crate) const DAMAGED_REFUSAL: &str = "Sesame could not read its Sync version file. It repairs the file at the next update check. If Sync stays refused, close Sesame and delete sync-floor.json, sync-floor.json.tag and sync-floor.json.next in its local data folder.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    core: [u64; 3],
    release: bool,
}

impl Version {
    pub fn parse_floor(value: &str) -> Option<Self> {
        Self::parse(value, false)
    }

    pub fn parse_build(value: &str) -> Option<Self> {
        Self::parse(value, true)
    }

    fn parse(value: &str, allow_prerelease: bool) -> Option<Self> {
        let (core_text, prerelease) = match value.split_once('-') {
            Some((core, prerelease)) => (core, Some(prerelease)),
            None => (value, None),
        };
        if let Some(prerelease) = prerelease {
            let valid = allow_prerelease
                && !prerelease.is_empty()
                && prerelease
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
            if !valid {
                return None;
            }
        }
        let mut parts = core_text.split('.');
        let mut core = [0_u64; 3];
        for number in &mut core {
            let part = parts.next()?;
            let digits = !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
            if !digits || (part.len() > 1 && part.starts_with('0')) {
                return None;
            }
            *number = part.parse().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            core,
            release: prerelease.is_none(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FloorError {
    Malformed,
    WrongKey,
    BadSignature,
    Mismatch,
}

impl std::fmt::Display for FloorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "The Sync version notice in the release manifest is invalid.",
            Self::WrongKey => "The Sync version notice used an unexpected release key.",
            Self::BadSignature => "The Sync version notice has an invalid signature.",
            Self::Mismatch => "The Sync version notice does not match its release.",
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FloorDocument {
    payload: String,
    signing_key_id: String,
    signature: String,
}

pub fn verify_manifest_floor(
    manifest: &serde_json::Value,
    encoded_public_key: &str,
    expected_key_id: &str,
) -> Result<Option<String>, FloorError> {
    let Some(raw) = manifest.get("syncFloor") else {
        return Ok(None);
    };
    let document: FloorDocument =
        serde_json::from_value(raw.clone()).map_err(|_| FloorError::Malformed)?;
    if document.signing_key_id != expected_key_id {
        return Err(FloorError::WrongKey);
    }
    let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(encoded_public_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(FloorError::WrongKey)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| FloorError::WrongKey)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&document.signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(FloorError::BadSignature)?;
    key.verify_strict(document.payload.as_bytes(), &signature)
        .map_err(|_| FloorError::BadSignature)?;

    let lines: Vec<&str> = document.payload.split('\n').collect();
    if lines.len() != 4 || lines[0] != PAYLOAD_LABEL {
        return Err(FloorError::Malformed);
    }
    let release = Version::parse_build(lines[1]).ok_or(FloorError::Malformed)?;
    let minimum = Version::parse_floor(lines[2]).ok_or(FloorError::Malformed)?;
    let digest_valid = lines[3].len() == 64
        && lines[3]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !digest_valid {
        return Err(FloorError::Malformed);
    }
    let announced = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if lines[1] != announced || minimum > release {
        return Err(FloorError::Mismatch);
    }
    let receipt_claims: Option<Vec<&str>> = manifest
        .get("candidateReceipt")
        .and_then(|receipt| receipt.get("payload"))
        .and_then(serde_json::Value::as_str)
        .map(|payload| payload.split('\n').collect());
    if let Some(claims) = receipt_claims {
        if claims.first() == Some(&MANIFEST_RECEIPT_SET_LABEL) && claims.get(7) != Some(&lines[3]) {
            return Err(FloorError::Mismatch);
        }
    }
    Ok(Some(lines[2].to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredFloor {
    pub minimum: String,
    pub confirmed_at: u64,
}

pub fn floor_path(app_local_data_dir: &Path) -> PathBuf {
    app_local_data_dir.join(FLOOR_FILE_NAME)
}

pub fn read_floor(path: &Path) -> Option<StoredFloor> {
    let body = read_tagged(path, TAG_LABEL)?;
    let stored: StoredFloor = serde_json::from_slice(&body).ok()?;
    Version::parse_floor(&stored.minimum)?;
    Some(stored)
}

pub fn raise_floor(path: &Path, verified_minimum: &str, now: u64) -> VaultResult<StoredFloor> {
    let incoming =
        Version::parse_floor(verified_minimum).ok_or_else(|| FloorError::Malformed.to_string())?;
    let kept = match read_floor(path) {
        Some(stored) if Version::parse_floor(&stored.minimum) > Some(incoming) => stored.minimum,
        _ => verified_minimum.to_string(),
    };
    let stored = StoredFloor {
        minimum: kept,
        confirmed_at: now,
    };
    let body = serde_json::to_vec(&stored)
        .map_err(|_| "Sesame could not record the Sync version notice.".to_string())?;
    write_tagged(path, TAG_LABEL, &body)?;
    Ok(stored)
}

pub fn record_manifest_floor(
    path: &Path,
    manifest: &serde_json::Value,
    encoded_public_key: &str,
    expected_key_id: &str,
    now: u64,
) -> VaultResult<Option<StoredFloor>> {
    match verify_manifest_floor(manifest, encoded_public_key, expected_key_id)
        .map_err(|error| error.to_string())?
    {
        Some(minimum) => raise_floor(path, &minimum, now).map(Some),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorState {
    Absent,
    Present(StoredFloor),
    Damaged,
}

pub fn floor_state(path: &Path) -> FloorState {
    match read_floor(path) {
        Some(stored) => FloorState::Present(stored),
        None if crate::sync::state::tagged_files_exist(path) => FloorState::Damaged,
        None => FloorState::Absent,
    }
}

pub fn confirmed_at(path: &Path) -> Option<u64> {
    read_floor(path).map(|stored| stored.confirmed_at)
}

pub fn require_allowed(build_version: &str, path: &Path, can_fetch: bool) -> Result<(), String> {
    let stored = match floor_state(path) {
        FloorState::Absent => return Ok(()),
        FloorState::Damaged if can_fetch => return Err(DAMAGED_REFUSAL.to_string()),
        FloorState::Damaged => return Ok(()),
        FloorState::Present(stored) => stored,
    };
    let minimum = Version::parse_floor(&stored.minimum).ok_or_else(|| REFUSAL.to_string())?;
    match Version::parse_build(build_version) {
        Some(build) if build >= minimum => Ok(()),
        _ => Err(REFUSAL.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const KEY_ID: &str = "fictional-candidate-key";
    const DIGEST: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9_u8; 32])
    }

    fn public_key() -> String {
        URL_SAFE_NO_PAD.encode(key().verifying_key().to_bytes())
    }

    fn payload(release: &str, minimum: &str, digest: &str) -> String {
        [PAYLOAD_LABEL, release, minimum, digest].join("\n")
    }

    fn manifest_with(signing: &SigningKey, key_id: &str, payload: &str) -> serde_json::Value {
        let receipt_payload = [
            "sesame-release-set-candidate-v1",
            "1.2.3",
            "beta",
            "windows",
            "x86_64",
            "",
            "https://example.invalid/r",
            DIGEST,
        ]
        .join("\n");
        json!({
            "version": "1.2.3",
            "candidateReceipt": {
                "payload": receipt_payload,
                "signingKeyId": KEY_ID,
                "signature": "ignored",
            },
            "syncFloor": {
                "payload": payload,
                "signingKeyId": key_id,
                "signature": URL_SAFE_NO_PAD.encode(signing.sign(payload.as_bytes()).to_bytes()),
            }
        })
    }

    fn signed_manifest(minimum: &str) -> serde_json::Value {
        manifest_with(&key(), KEY_ID, &payload("1.2.3", minimum, DIGEST))
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sesame-sync-floor-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        floor_path(&dir)
    }

    #[test]
    fn a_signed_floor_is_accepted() {
        let minimum = verify_manifest_floor(&signed_manifest("1.2.0"), &public_key(), KEY_ID);
        assert_eq!(minimum, Ok(Some("1.2.0".to_string())));
    }

    #[test]
    fn a_manifest_without_a_floor_changes_nothing() {
        let manifest = json!({ "version": "1.2.3" });
        assert_eq!(
            verify_manifest_floor(&manifest, &public_key(), KEY_ID),
            Ok(None)
        );
    }

    #[test]
    fn a_tampered_value_fails_verification() {
        let mut manifest = signed_manifest("1.2.0");
        let edited = manifest["syncFloor"]["payload"]
            .as_str()
            .unwrap()
            .replace("1.2.0", "1.0.0");
        manifest["syncFloor"]["payload"] = json!(edited);
        assert_eq!(
            verify_manifest_floor(&manifest, &public_key(), KEY_ID),
            Err(FloorError::BadSignature)
        );
    }

    #[test]
    fn a_floor_signed_by_another_key_or_naming_another_key_id_is_refused() {
        let other = SigningKey::from_bytes(&[3_u8; 32]);
        let forged = manifest_with(&other, KEY_ID, &payload("1.2.3", "1.2.0", DIGEST));
        assert_eq!(
            verify_manifest_floor(&forged, &public_key(), KEY_ID),
            Err(FloorError::BadSignature)
        );
        let renamed = manifest_with(&key(), "other-key", &payload("1.2.3", "1.2.0", DIGEST));
        assert_eq!(
            verify_manifest_floor(&renamed, &public_key(), KEY_ID),
            Err(FloorError::WrongKey)
        );
    }

    #[test]
    fn a_floor_for_another_release_or_above_its_release_or_with_extra_lines_is_refused() {
        let other_release = manifest_with(&key(), KEY_ID, &payload("1.2.4", "1.2.0", DIGEST));
        assert_eq!(
            verify_manifest_floor(&other_release, &public_key(), KEY_ID),
            Err(FloorError::Mismatch)
        );
        assert_eq!(
            verify_manifest_floor(&signed_manifest("1.2.4"), &public_key(), KEY_ID),
            Err(FloorError::Mismatch)
        );
        let other_set = manifest_with(&key(), KEY_ID, &payload("1.2.3", "1.2.0", &"c".repeat(64)));
        assert_eq!(
            verify_manifest_floor(&other_set, &public_key(), KEY_ID),
            Err(FloorError::Mismatch)
        );
        let extra = format!("{}\nextra", payload("1.2.3", "1.2.0", DIGEST));
        assert_eq!(
            verify_manifest_floor(
                &manifest_with(&key(), KEY_ID, &extra),
                &public_key(),
                KEY_ID
            ),
            Err(FloorError::Malformed)
        );
        for minimum in ["1.2", "01.2.0", "1.2.0-beta", "1.2.x", ""] {
            assert_eq!(
                verify_manifest_floor(&signed_manifest(minimum), &public_key(), KEY_ID),
                Err(FloorError::Malformed),
                "{minimum}"
            );
        }
    }

    #[test]
    fn a_build_below_the_stored_floor_refuses_and_a_build_at_it_passes() {
        let path = scratch("below");
        raise_floor(&path, "0.4.0", 100).unwrap();
        assert!(require_allowed("0.3.9", &path, true).is_err());
        assert!(require_allowed("0.4.0-beta.1", &path, true).is_err());
        assert!(require_allowed("0.4.0", &path, true).is_ok());
        assert!(require_allowed("0.10.0", &path, true).is_ok());
        assert!(require_allowed("not-a-version", &path, true).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn nothing_stored_means_no_floor() {
        let path = scratch("none");
        assert!(require_allowed("0.0.1", &path, true).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_stored_floor_only_rises() {
        let path = scratch("rises");
        raise_floor(&path, "0.4.0", 100).unwrap();
        let after_older = raise_floor(&path, "0.3.0", 200).unwrap();
        assert_eq!(after_older.minimum, "0.4.0");
        assert_eq!(after_older.confirmed_at, 200);
        let after_newer = raise_floor(&path, "0.5.0", 300).unwrap();
        assert_eq!(after_newer.minimum, "0.5.0");
        assert!(require_allowed("0.4.9", &path, true).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_replayed_older_manifest_cannot_lower_the_stored_floor() {
        let path = scratch("replay");
        record_manifest_floor(&path, &signed_manifest("1.2.0"), &public_key(), KEY_ID, 100)
            .unwrap();
        record_manifest_floor(&path, &signed_manifest("1.0.0"), &public_key(), KEY_ID, 200)
            .unwrap();
        record_manifest_floor(
            &path,
            &json!({ "version": "1.0.0" }),
            &public_key(),
            KEY_ID,
            300,
        )
        .unwrap();
        assert_eq!(read_floor(&path).unwrap().minimum, "1.2.0");
        assert!(require_allowed("1.1.9", &path, true).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_refused_manifest_leaves_the_stored_floor_alone() {
        let path = scratch("refused");
        raise_floor(&path, "0.4.0", 100).unwrap();
        let mut manifest = signed_manifest("0.1.0");
        manifest["syncFloor"]["signature"] = json!("A".repeat(86));
        assert!(record_manifest_floor(&path, &manifest, &public_key(), KEY_ID, 200).is_err());
        assert_eq!(
            read_floor(&path),
            Some(StoredFloor {
                minimum: "0.4.0".into(),
                confirmed_at: 100
            })
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_edited_floor_file_reads_as_absent() {
        let path = scratch("edited");
        raise_floor(&path, "0.4.0", 100).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, body.replace("0.4.0", "0.1.0")).unwrap();
        assert_eq!(read_floor(&path), None);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn versions_order_numerically_and_prereleases_sort_below_releases() {
        let parse = |value: &str| Version::parse_build(value).unwrap();
        assert!(parse("0.10.0") > parse("0.9.9"));
        assert!(parse("1.0.0") > parse("1.0.0-rc.1"));
        assert!(parse("1.0.0-rc.1") > parse("0.99.99"));
        assert_eq!(Version::parse_floor("1.0.0-rc.1"), None);
        assert_eq!(Version::parse_build("1.0"), None);
        assert_eq!(Version::parse_build("1.0.0.0"), None);
        assert_eq!(Version::parse_build("99999999999999999999.0.0"), None);
    }
    #[test]
    fn the_refusal_names_all_three_files_that_a_manual_reset_removes() {
        for name in [
            "sync-floor.json",
            "sync-floor.json.tag",
            "sync-floor.json.next",
        ] {
            assert!(DAMAGED_REFUSAL.contains(name), "{name}");
        }
    }

    #[test]
    fn removing_all_three_files_resets_a_damaged_floor_and_removing_only_one_does_not() {
        let path = scratch("manual-reset");
        raise_floor(&path, "0.4.0", 100).unwrap();
        std::fs::write(&path, b"damaged").unwrap();
        std::fs::write(path.with_extension("json.next"), b"leftover").unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(floor_state(&path), FloorState::Damaged);
        std::fs::remove_file(path.with_extension("json.next")).unwrap();
        assert_eq!(floor_state(&path), FloorState::Damaged);
        std::fs::remove_file(path.with_extension("json.tag")).unwrap();
        assert_eq!(floor_state(&path), FloorState::Absent);
        assert!(require_allowed("0.1.0", &path, true).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_damaged_floor_file_refuses_sync_where_a_floor_can_be_fetched() {
        let path = scratch("damaged");
        raise_floor(&path, "0.4.0", 100).unwrap();
        std::fs::write(&path, b"damaged").unwrap();
        assert_eq!(floor_state(&path), FloorState::Damaged);
        assert_eq!(
            require_allowed("9.9.9", &path, true),
            Err(DAMAGED_REFUSAL.to_string())
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_damaged_floor_file_changes_nothing_where_no_floor_can_be_fetched() {
        let path = scratch("damaged-offline");
        raise_floor(&path, "0.4.0", 100).unwrap();
        std::fs::write(&path, b"damaged").unwrap();
        assert!(require_allowed("0.1.0", &path, false).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_lost_body_with_a_surviving_tag_counts_as_damaged_and_no_files_as_absent() {
        let path = scratch("lost-body");
        assert_eq!(floor_state(&path), FloorState::Absent);
        raise_floor(&path, "0.4.0", 100).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(floor_state(&path), FloorState::Damaged);
        assert!(require_allowed("0.1.0", &path, true).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_verified_manifest_repairs_a_damaged_floor_file() {
        let path = scratch("repair");
        raise_floor(&path, "0.4.0", 100).unwrap();
        std::fs::write(&path, b"damaged").unwrap();
        record_manifest_floor(&path, &signed_manifest("1.2.0"), &public_key(), KEY_ID, 300)
            .unwrap();
        assert_eq!(
            floor_state(&path),
            FloorState::Present(StoredFloor {
                minimum: "1.2.0".into(),
                confirmed_at: 300
            })
        );
        assert!(require_allowed("1.2.0", &path, true).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_confirmation_time_is_read_back_and_absent_before_any_confirmation() {
        let path = scratch("confirmed");
        assert_eq!(confirmed_at(&path), None);
        raise_floor(&path, "0.4.0", 123).unwrap();
        assert_eq!(confirmed_at(&path), Some(123));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
