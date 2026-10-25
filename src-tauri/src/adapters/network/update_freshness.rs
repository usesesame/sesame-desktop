use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::sync::floor::Version;
use crate::sync::state::{read_tagged, write_tagged};
use crate::vault::VaultResult;

pub const PAYLOAD_LABEL: &str = "sesame-update-freshness-v1";
pub const MAX_STATEMENT_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const MAX_FUTURE_SKEW_SECONDS: u64 = 24 * 60 * 60;
const FILE_NAME: &str = "update-freshness.json";
const TAG_LABEL: &[u8] = b"sesame-update-freshness-tag-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub latest_version: String,
    pub issued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementError {
    Malformed,
    KeyId,
    Signature,
}

pub fn verify_statement(
    value: &serde_json::Value,
    encoded_public_key: &str,
    expected_key_id: &str,
) -> Result<Statement, StatementError> {
    let payload = value
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .ok_or(StatementError::Malformed)?;
    let key_id = value
        .get("signingKeyId")
        .and_then(serde_json::Value::as_str)
        .ok_or(StatementError::Malformed)?;
    let signature = value
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or(StatementError::Malformed)?;
    if key_id != expected_key_id {
        return Err(StatementError::KeyId);
    }
    let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(encoded_public_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StatementError::Malformed)?;
    let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StatementError::Malformed)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| StatementError::Malformed)?;
    key.verify_strict(payload.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .map_err(|_| StatementError::Signature)?;
    let lines: Vec<&str> = payload.split('\n').collect();
    let [label, version, issued_at] = lines.as_slice() else {
        return Err(StatementError::Malformed);
    };
    if *label != PAYLOAD_LABEL || Version::parse_floor(version).is_none() {
        return Err(StatementError::Malformed);
    }
    let canonical = issued_at
        .parse::<u64>()
        .map_err(|_| StatementError::Malformed)?;
    if canonical.to_string() != *issued_at {
        return Err(StatementError::Malformed);
    }
    Ok(Statement {
        latest_version: (*version).to_string(),
        issued_at: canonical,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    Confirmed { at: u64 },
    NewerExists { version: String },
    Unconfirmed { last_confirmed: Option<u64> },
}

pub struct Inputs<'a> {
    pub statement: Option<&'a Statement>,
    pub last_confirmed: Option<u64>,
    pub installed: &'a str,
    pub manifest_newest: Option<&'a str>,
    pub now: u64,
}

fn within_age(issued_at: u64, now: u64) -> bool {
    issued_at <= now.saturating_add(MAX_FUTURE_SKEW_SECONDS)
        && now.saturating_sub(issued_at) <= MAX_STATEMENT_AGE_SECONDS
}

pub fn assess(inputs: &Inputs<'_>) -> Freshness {
    let installed = Version::parse_build(inputs.installed);
    if let (Some(statement), Some(installed)) = (inputs.statement, installed) {
        let announced = Version::parse_floor(&statement.latest_version);
        let shown = inputs.manifest_newest.and_then(Version::parse_build);
        let newer_than_installed = announced.is_some_and(|announced| announced > installed);
        let manifest_shows_it =
            matches!((shown, announced), (Some(shown), Some(announced)) if shown >= announced);
        let not_from_the_far_future =
            statement.issued_at <= inputs.now.saturating_add(MAX_FUTURE_SKEW_SECONDS);
        if newer_than_installed && !manifest_shows_it && not_from_the_far_future {
            return Freshness::NewerExists {
                version: statement.latest_version.clone(),
            };
        }
        if within_age(statement.issued_at, inputs.now) {
            return Freshness::Confirmed {
                at: statement.issued_at,
            };
        }
    }
    match inputs.last_confirmed {
        Some(at) if within_age(at, inputs.now) => Freshness::Confirmed { at },
        last_confirmed => Freshness::Unconfirmed { last_confirmed },
    }
}

#[derive(Clone, Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFreshness {
    pub state: String,
    pub version: Option<String>,
    pub at: Option<u64>,
}

impl From<Freshness> for UpdateFreshness {
    fn from(freshness: Freshness) -> Self {
        match freshness {
            Freshness::Confirmed { at } => Self {
                state: "confirmed".to_string(),
                version: None,
                at: Some(at),
            },
            Freshness::NewerExists { version } => Self {
                state: "newer_exists".to_string(),
                version: Some(version),
                at: None,
            },
            Freshness::Unconfirmed { last_confirmed } => Self {
                state: "unconfirmed".to_string(),
                version: None,
                at: last_confirmed,
            },
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub(crate) async fn current(
    app: &tauri::AppHandle,
    manifest_newest: Option<&str>,
) -> Option<UpdateFreshness> {
    use tauri::Manager;

    let (endpoint, key, key_id) = super::public_updates::freshness_trust()?;
    let data_dir = app.path().app_local_data_dir().ok()?;
    let now = unix_now();
    let statement = match super::sync_floor::fetch_manifest(endpoint).await {
        Some(value) => verify_statement(&value, key, key_id).ok(),
        None => None,
    };
    let mut last_confirmed = read_confirmation(&data_dir);
    if let Some(statement) = statement.as_ref() {
        if within_age(statement.issued_at, now)
            && last_confirmed.is_none_or(|stored| stored < statement.issued_at)
        {
            let _ = record_confirmation(&data_dir, statement.issued_at);
            last_confirmed = Some(statement.issued_at);
        }
    }
    Some(
        assess(&Inputs {
            statement: statement.as_ref(),
            last_confirmed,
            installed: env!("CARGO_PKG_VERSION"),
            manifest_newest,
            now,
        })
        .into(),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredConfirmation {
    confirmed_at: u64,
}

fn confirmation_path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

pub fn read_confirmation(data_dir: &Path) -> Option<u64> {
    let body = read_tagged(&confirmation_path(data_dir), TAG_LABEL)?;
    serde_json::from_slice::<StoredConfirmation>(&body)
        .ok()
        .map(|stored| stored.confirmed_at)
}

pub fn record_confirmation(data_dir: &Path, confirmed_at: u64) -> VaultResult<()> {
    let body = serde_json::to_vec(&StoredConfirmation { confirmed_at })
        .map_err(|_| "Sesame could not record the update check.".to_string())?;
    write_tagged(&confirmation_path(data_dir), TAG_LABEL, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const KEY_ID: &str = "fictional-freshness-key";
    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[4_u8; 32])
    }

    fn public_key() -> String {
        URL_SAFE_NO_PAD.encode(signing_key().verifying_key().to_bytes())
    }

    fn statement_json(payload: &str) -> serde_json::Value {
        json!({
            "payload": payload,
            "signingKeyId": KEY_ID,
            "signature": URL_SAFE_NO_PAD.encode(signing_key().sign(payload.as_bytes()).to_bytes()),
        })
    }

    fn payload(version: &str, issued_at: u64) -> String {
        format!("{PAYLOAD_LABEL}\n{version}\n{issued_at}")
    }

    fn statement(version: &str, issued_at: u64) -> Statement {
        Statement {
            latest_version: version.to_string(),
            issued_at,
        }
    }

    fn inputs<'a>(
        statement: Option<&'a Statement>,
        installed: &'a str,
        manifest_newest: Option<&'a str>,
        last_confirmed: Option<u64>,
    ) -> Inputs<'a> {
        Inputs {
            statement,
            last_confirmed,
            installed,
            manifest_newest,
            now: NOW,
        }
    }

    #[test]
    fn the_statement_the_signing_tool_made_verifies_here() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/update-freshness/statement.json"
        ))
        .expect("fixture");
        let public_key = fixture["publicKey"].as_str().expect("public key");
        let statement = &fixture["statement"];
        assert_eq!(
            verify_statement(statement, public_key, "fictional-freshness-key"),
            Ok(Statement {
                latest_version: "0.4.4".to_string(),
                issued_at: 1_800_000_000,
            })
        );
        let mut edited = statement.clone();
        edited["payload"] = serde_json::json!("sesame-update-freshness-v1\n0.4.5\n1800000000");
        assert_eq!(
            verify_statement(&edited, public_key, "fictional-freshness-key"),
            Err(StatementError::Signature)
        );
    }

    #[test]
    fn a_signed_statement_is_accepted() {
        let value = statement_json(&payload("0.4.4", NOW));
        assert_eq!(
            verify_statement(&value, &public_key(), KEY_ID),
            Ok(statement("0.4.4", NOW))
        );
    }

    #[test]
    fn a_statement_signed_by_another_key_or_naming_another_key_id_is_refused() {
        let mut value = statement_json(&payload("0.4.4", NOW));
        let other = SigningKey::from_bytes(&[5_u8; 32]);
        value["signature"] =
            json!(URL_SAFE_NO_PAD.encode(other.sign(payload("0.4.4", NOW).as_bytes()).to_bytes()));
        assert_eq!(
            verify_statement(&value, &public_key(), KEY_ID),
            Err(StatementError::Signature)
        );
        let value = statement_json(&payload("0.4.4", NOW));
        assert_eq!(
            verify_statement(&value, &public_key(), "another-key"),
            Err(StatementError::KeyId)
        );
    }

    #[test]
    fn an_edited_version_or_time_fails_the_signature() {
        let mut value = statement_json(&payload("0.4.4", NOW));
        value["payload"] = json!(payload("0.4.5", NOW));
        assert_eq!(
            verify_statement(&value, &public_key(), KEY_ID),
            Err(StatementError::Signature)
        );
        let mut value = statement_json(&payload("0.4.4", NOW));
        value["payload"] = json!(payload("0.4.4", NOW + 1));
        assert_eq!(
            verify_statement(&value, &public_key(), KEY_ID),
            Err(StatementError::Signature)
        );
    }

    #[test]
    fn a_signed_payload_in_another_shape_is_refused() {
        for text in [
            format!("{PAYLOAD_LABEL}\n0.4.4"),
            format!("{PAYLOAD_LABEL}\n0.4.4\n{NOW}\nextra"),
            format!("another-label\n0.4.4\n{NOW}"),
            format!("{PAYLOAD_LABEL}\n0.4.4-beta.1\n{NOW}"),
            format!("{PAYLOAD_LABEL}\nnot-a-version\n{NOW}"),
            format!("{PAYLOAD_LABEL}\n0.4.4\n0{NOW}"),
            format!("{PAYLOAD_LABEL}\n0.4.4\n-1"),
        ] {
            assert_eq!(
                verify_statement(&statement_json(&text), &public_key(), KEY_ID),
                Err(StatementError::Malformed),
                "{text:?}"
            );
        }
    }

    #[test]
    fn missing_or_mistyped_fields_are_refused() {
        for value in [
            json!({}),
            json!({"payload": 1}),
            json!({"payload": "x", "signingKeyId": KEY_ID}),
        ] {
            assert!(verify_statement(&value, &public_key(), KEY_ID).is_err());
        }
    }

    #[test]
    fn a_fresh_statement_for_the_installed_version_confirms_the_check() {
        let current = statement("0.4.4", NOW - DAY);
        assert_eq!(
            assess(&inputs(Some(&current), "0.4.4", None, None)),
            Freshness::Confirmed { at: NOW - DAY }
        );
    }

    #[test]
    fn a_newer_release_than_the_manifest_shows_means_the_manifest_is_frozen() {
        let announced = statement("0.4.9", NOW - DAY);
        assert_eq!(
            assess(&inputs(Some(&announced), "0.4.4", None, None)),
            Freshness::NewerExists {
                version: "0.4.9".to_string()
            }
        );
        assert_eq!(
            assess(&inputs(Some(&announced), "0.4.4", Some("0.4.5"), None)),
            Freshness::NewerExists {
                version: "0.4.9".to_string()
            }
        );
    }

    #[test]
    fn a_manifest_that_already_shows_the_announced_release_is_not_frozen() {
        let announced = statement("0.4.9", NOW - DAY);
        assert_eq!(
            assess(&inputs(Some(&announced), "0.4.4", Some("0.4.9"), None)),
            Freshness::Confirmed { at: NOW - DAY }
        );
    }

    #[test]
    fn an_old_statement_still_proves_that_a_newer_release_exists_but_never_confirms_freshness() {
        let old = statement("0.4.9", NOW - 90 * DAY);
        assert_eq!(
            assess(&inputs(Some(&old), "0.4.4", None, None)),
            Freshness::NewerExists {
                version: "0.4.9".to_string()
            }
        );
        let old_current = statement("0.4.4", NOW - 90 * DAY);
        assert_eq!(
            assess(&inputs(Some(&old_current), "0.4.4", None, None)),
            Freshness::Unconfirmed {
                last_confirmed: None
            }
        );
    }

    #[test]
    fn a_statement_from_the_far_future_confirms_nothing() {
        let future = statement("0.4.4", NOW + 10 * DAY);
        assert_eq!(
            assess(&inputs(Some(&future), "0.4.4", None, None)),
            Freshness::Unconfirmed {
                last_confirmed: None
            }
        );
        let announcing = statement("0.4.9", NOW + 10 * DAY);
        assert_eq!(
            assess(&inputs(Some(&announcing), "0.4.4", None, None)),
            Freshness::Unconfirmed {
                last_confirmed: None
            }
        );
    }

    #[test]
    fn without_a_statement_a_recent_confirmation_stands_and_an_old_one_does_not() {
        assert_eq!(
            assess(&inputs(None, "0.4.4", None, Some(NOW - 10 * DAY))),
            Freshness::Confirmed { at: NOW - 10 * DAY }
        );
        assert_eq!(
            assess(&inputs(None, "0.4.4", None, Some(NOW - 45 * DAY))),
            Freshness::Unconfirmed {
                last_confirmed: Some(NOW - 45 * DAY)
            }
        );
        assert_eq!(
            assess(&inputs(None, "0.4.4", None, None)),
            Freshness::Unconfirmed {
                last_confirmed: None
            }
        );
    }

    #[test]
    fn a_prerelease_build_is_compared_by_its_core_version() {
        let announced = statement("0.4.4", NOW);
        assert_eq!(
            assess(&inputs(Some(&announced), "0.4.4-beta.1", None, None)),
            Freshness::NewerExists {
                version: "0.4.4".to_string()
            }
        );
    }

    #[test]
    fn the_confirmation_time_is_stored_and_an_edited_file_is_not_trusted() {
        let dir = std::env::temp_dir().join(format!("sesame-freshness-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_confirmation(&dir), None);
        record_confirmation(&dir, 123).unwrap();
        assert_eq!(read_confirmation(&dir), Some(123));
        let path = confirmation_path(&dir);
        let body = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, body.replace("123", "999")).unwrap();
        assert_eq!(read_confirmation(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
