use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::platform::{minimum_for_platform, ANDROID_PLATFORM};
use crate::version;

pub const MAX_CAPABILITY_BYTES: usize = 16 * 1024;
pub const CLOCK_DIFFERENCE: &str = "This computer's clock and the server's clock differ, so Sesame cannot rely on the server's settings. Check the date and time on both, then try again.";
pub const CAPABILITY_INVALID: &str = "Sesame capability configuration is invalid.";
const ISSUED_AT_TOLERANCE_SECS: i64 = 5 * 60;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    payload: String,
    signature: String,
    #[serde(default)]
    key_id: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub schema_version: u8,
    pub minimum_desktop_version: String,
    #[serde(default)]
    pub minimum_android_version: Option<String>,
    pub features: std::collections::BTreeMap<String, bool>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: time::OffsetDateTime,
    #[serde(default)]
    pub instance_id: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub issued_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapabilityError {
    Untrusted,
    ClockDifference,
    Unavailable(String),
}

impl From<CapabilityError> for String {
    fn from(error: CapabilityError) -> Self {
        match error {
            CapabilityError::Untrusted => "Sesame capability signature is invalid.".to_string(),
            CapabilityError::ClockDifference => CLOCK_DIFFERENCE.to_string(),
            CapabilityError::Unavailable(message) => message,
        }
    }
}

fn unavailable(message: &str) -> CapabilityError {
    CapabilityError::Unavailable(message.to_string())
}

pub fn verify_capability_envelope(
    body: &[u8],
    key: &VerifyingKey,
    expected_key_id: Option<&str>,
    now: time::OffsetDateTime,
) -> Result<Document, CapabilityError> {
    let envelope: Envelope =
        serde_json::from_slice(body).map_err(|_| unavailable(CAPABILITY_INVALID))?;
    if let Some(expected) = expected_key_id {
        if envelope.key_id.as_deref() != Some(expected) {
            return Err(CapabilityError::Untrusted);
        }
    }
    let payload = URL_SAFE_NO_PAD
        .decode(envelope.payload)
        .map_err(|_| unavailable(CAPABILITY_INVALID))?;
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(envelope.signature)
            .map_err(|_| unavailable(CAPABILITY_INVALID))?,
    )
    .map_err(|_| unavailable(CAPABILITY_INVALID))?;
    key.verify(&payload, &signature)
        .map_err(|_| CapabilityError::Untrusted)?;
    let document: Document =
        serde_json::from_slice(&payload).map_err(|_| unavailable(CAPABILITY_INVALID))?;
    if document.schema_version != 1 {
        return Err(unavailable("Desktop linking is currently unavailable."));
    }
    if document.expires_at <= now
        || document
            .issued_at
            .is_some_and(|issued| issued > now + time::Duration::seconds(ISSUED_AT_TOLERANCE_SECS))
    {
        return Err(CapabilityError::ClockDifference);
    }
    Ok(document)
}

pub fn require_instance(document: &Document, expected: &str) -> Result<(), CapabilityError> {
    if document.instance_id.as_deref() != Some(expected) {
        return Err(unavailable(
            "The server's signed document names a different server than the one this desktop paired with.",
        ));
    }
    Ok(())
}

pub fn require_linking_enabled(
    document: &Document,
    client_version: &str,
    client_platform: &str,
) -> Result<(), CapabilityError> {
    if !document
        .features
        .get("desktopLinking")
        .copied()
        .unwrap_or(false)
    {
        return Err(unavailable("Desktop linking is currently unavailable."));
    }
    if let Some(minimum) = minimum_for_platform(
        client_platform,
        &document.minimum_desktop_version,
        document.minimum_android_version.as_deref(),
    ) {
        if version::below(client_version, minimum) != Some(false) {
            return Err(unavailable(if client_platform == ANDROID_PLATFORM {
                "Update Sesame before linking this device."
            } else {
                "Update Sesame before linking this desktop."
            }));
        }
    }
    Ok(())
}

pub fn require_sync_enabled(
    document: &Document,
    client_version: &str,
    client_platform: &str,
) -> Result<(), CapabilityError> {
    if !document.features.get("sync").copied().unwrap_or(false) {
        return Err(unavailable(
            "Sesame Sync is not turned on for this service.",
        ));
    }
    if let Some(minimum) = minimum_for_platform(
        client_platform,
        &document.minimum_desktop_version,
        document.minimum_android_version.as_deref(),
    ) {
        if version::below(client_version, minimum) != Some(false) {
            return Err(unavailable("Update Sesame before using Sync."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::DESKTOP_PLATFORM;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const KEY_ID: &str = "fictional-key";
    const NOW: &str = "2026-10-10T12:00:00Z";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9_u8; 32])
    }

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_791_633_600).unwrap()
    }

    fn payload() -> serde_json::Value {
        json!({
            "schemaVersion": 1,
            "minimumDesktopVersion": "0.5.1",
            "features": {"desktopLinking": true, "sync": true},
            "expiresAt": "2026-10-10T13:00:00Z",
            "issuedAt": NOW,
        })
    }

    fn envelope(value: &serde_json::Value) -> Vec<u8> {
        let payload = serde_json::to_vec(value).unwrap();
        serde_json::to_vec(&json!({
            "payload": URL_SAFE_NO_PAD.encode(&payload),
            "signature": URL_SAFE_NO_PAD.encode(key().sign(&payload).to_bytes()),
            "keyId": KEY_ID,
        }))
        .unwrap()
    }

    fn document(value: serde_json::Value) -> Document {
        verify_capability_envelope(
            &envelope(&value),
            &key().verifying_key(),
            Some(KEY_ID),
            now(),
        )
        .expect("document")
    }

    #[test]
    fn a_document_without_the_android_field_still_verifies() {
        let document = document(payload());
        assert_eq!(document.minimum_android_version, None);
        assert!(require_sync_enabled(&document, "0.5.1", DESKTOP_PLATFORM).is_ok());
        assert!(require_sync_enabled(&document, "0.1.0", ANDROID_PLATFORM).is_ok());
    }

    #[test]
    fn the_desktop_ignores_the_android_minimum() {
        let mut value = payload();
        value["minimumAndroidVersion"] = json!("99.0.0");
        let document = document(value);
        assert!(require_sync_enabled(&document, "0.5.1", DESKTOP_PLATFORM).is_ok());
        assert!(require_linking_enabled(&document, "0.5.1", DESKTOP_PLATFORM).is_ok());
        assert!(require_sync_enabled(&document, "0.4.9", DESKTOP_PLATFORM).is_err());
    }

    #[test]
    fn android_ignores_the_desktop_minimum_and_uses_its_own() {
        let mut value = payload();
        value["minimumAndroidVersion"] = json!("0.2.0");
        let document = document(value);
        assert!(require_sync_enabled(&document, "0.1.0", ANDROID_PLATFORM).is_err());
        assert!(require_sync_enabled(&document, "0.2.0", ANDROID_PLATFORM).is_ok());
        assert!(require_sync_enabled(&document, "0.1.0", DESKTOP_PLATFORM).is_err());
        assert!(require_sync_enabled(&document, "0.5.1", DESKTOP_PLATFORM).is_ok());
    }

    #[test]
    fn a_malformed_android_minimum_is_refused_only_for_android() {
        let mut value = payload();
        value["minimumAndroidVersion"] = json!("latest");
        let document = document(value);
        assert!(require_sync_enabled(&document, "0.1.0", ANDROID_PLATFORM).is_err());
        assert!(require_linking_enabled(&document, "0.1.0", ANDROID_PLATFORM).is_err());
        assert!(require_sync_enabled(&document, "0.5.1", DESKTOP_PLATFORM).is_ok());
    }

    fn desktop_minimum(minimum: &str) -> Document {
        let mut value = payload();
        value["minimumDesktopVersion"] = json!(minimum);
        document(value)
    }

    fn desktop_allowed(client: &str, minimum: &str) -> bool {
        let document = desktop_minimum(minimum);
        let sync = require_sync_enabled(&document, client, DESKTOP_PLATFORM).is_ok();
        let linking = require_linking_enabled(&document, client, DESKTOP_PLATFORM).is_ok();
        assert_eq!(sync, linking, "{client} against {minimum}");
        sync
    }

    #[test]
    fn a_desktop_at_the_minimum_is_allowed_and_one_patch_below_is_refused() {
        assert!(desktop_allowed("0.6.0", "0.6.0"));
        assert!(desktop_allowed("0.6.1", "0.6.0"));
        assert!(!desktop_allowed("0.5.9", "0.6.0"));
        assert!(!desktop_allowed("0.6.0", "0.6.1"));
        assert!(!desktop_allowed("0.1.0", "0.6.0"));
    }

    #[test]
    fn desktop_versions_compare_by_number_and_not_by_text() {
        assert!(!desktop_allowed("0.3.0", "0.10.0"));
        assert!(desktop_allowed("0.10.0", "0.3.0"));
        assert!(desktop_allowed("1.0.0", "0.99.99"));
    }

    #[test]
    fn a_desktop_prerelease_compares_as_its_release_numbers() {
        assert!(desktop_allowed("0.6.0-rc.1", "0.6.0"));
        assert!(!desktop_allowed("0.5.3-rc.1", "0.6.0"));
        assert!(desktop_allowed("0.6.0", "0.6.0-beta.1"));
        assert!(!desktop_allowed("0.5.9", "0.6.0-beta.1"));
    }

    #[test]
    fn a_malformed_desktop_minimum_refuses_sync_and_linking() {
        for minimum in [
            "latest", "", "1", "0.6", "0.6.x", "0.6.0.1", " 0.6.0", "v0.6.0",
        ] {
            assert!(!desktop_allowed("0.6.0", minimum), "{minimum:?}");
            assert!(!desktop_allowed("99.0.0", minimum), "{minimum:?}");
        }
    }

    #[test]
    fn a_malformed_desktop_client_version_is_refused() {
        assert!(!desktop_allowed("not-a-version", "0.0.0"));
        assert!(!desktop_allowed("", "0.0.0"));
    }

    #[test]
    fn a_malformed_android_client_version_is_refused() {
        let mut value = payload();
        value["minimumAndroidVersion"] = json!("0.2.0");
        let document = document(value);
        assert!(require_sync_enabled(&document, "not-a-version", ANDROID_PLATFORM).is_err());
    }

    #[test]
    fn the_signed_payload_still_binds_the_optional_field() {
        let mut value = payload();
        value["minimumAndroidVersion"] = json!("0.2.0");
        let mut envelope: serde_json::Value = serde_json::from_slice(&envelope(&value)).unwrap();
        envelope["payload"] =
            json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload()).expect("payload")));
        assert_eq!(
            verify_capability_envelope(
                &serde_json::to_vec(&envelope).unwrap(),
                &key().verifying_key(),
                Some(KEY_ID),
                now()
            )
            .unwrap_err(),
            CapabilityError::Untrusted
        );
    }
}
