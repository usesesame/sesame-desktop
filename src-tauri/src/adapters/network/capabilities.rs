use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use super::account_service::{read_limited, service_api_base_url, service_client};
use crate::vault::VaultResult;

const MAX_CAPABILITY_BYTES: usize = 16 * 1024;
const ISSUED_AT_TOLERANCE_SECS: i64 = 5 * 60;
const CLOCK_DIFFERENCE: &str = "This computer's clock and the server's clock differ, so Sesame cannot rely on the server's settings. Check the date and time on both, then try again.";
const CAPABILITY_INVALID: &str = "Sesame capability configuration is invalid.";

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
pub(crate) struct Document {
    schema_version: u8,
    minimum_desktop_version: String,
    features: std::collections::BTreeMap<String, bool>,
    expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    issued_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn official_capability_key() -> VaultResult<VerifyingKey> {
    let encoded = option_env!("SESAME_CAPABILITY_PUBLIC_KEY")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("Desktop capability verification is not configured for this build.")?;
    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "Desktop capability verification key is invalid.")?;
    Ok(VerifyingKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Desktop capability verification key is invalid.")?,
    )
    .map_err(|_| "Desktop capability verification key is invalid.")?)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CapabilityError {
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

pub async fn require_desktop_linking() -> VaultResult<()> {
    let key = official_capability_key()?;
    let client = service_client()?;
    let document = fetch_signed_document(&client, &service_api_base_url()?, &key, None).await?;
    Ok(require_linking_enabled(
        &document,
        env!("CARGO_PKG_VERSION"),
    )?)
}

pub(crate) async fn fetch_signed_document(
    client: &reqwest::Client,
    base_url: &str,
    key: &VerifyingKey,
    expected_key_id: Option<&str>,
) -> Result<Document, CapabilityError> {
    let response = client
        .get(format!("{base_url}/v1/capabilities"))
        .send()
        .await
        .map_err(|_| {
            unavailable("Sesame could not retrieve the signed capability configuration.")
        })?;
    if !response.status().is_success() {
        return Err(unavailable(
            "Sesame capability configuration is unavailable. Desktop linking stays disabled.",
        ));
    }
    let body = read_limited(response, MAX_CAPABILITY_BYTES)
        .await
        .ok_or_else(|| unavailable(CAPABILITY_INVALID))?;
    verify_capability_envelope(&body, key, expected_key_id, chrono::Utc::now())
}

pub(crate) fn verify_capability_envelope(
    body: &[u8],
    key: &VerifyingKey,
    expected_key_id: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
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
        || document.issued_at.is_some_and(|issued| {
            issued > now + chrono::Duration::seconds(ISSUED_AT_TOLERANCE_SECS)
        })
    {
        return Err(CapabilityError::ClockDifference);
    }
    Ok(document)
}

pub(crate) fn require_linking_enabled(
    document: &Document,
    client_version: &str,
) -> Result<(), CapabilityError> {
    if !document
        .features
        .get("desktopLinking")
        .copied()
        .unwrap_or(false)
    {
        return Err(unavailable("Desktop linking is currently unavailable."));
    }
    if version_lt(client_version, &document.minimum_desktop_version) {
        return Err(unavailable("Update Sesame before linking this desktop."));
    }
    Ok(())
}

fn version_lt(current: &str, minimum: &str) -> bool {
    let parse = |value: &str| {
        value
            .split('.')
            .take(3)
            .map(|part| part.parse::<u32>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let current = parse(current);
    let minimum = parse(minimum);
    for index in 0..3 {
        let a = current.get(index).copied().unwrap_or(0);
        let b = minimum.get(index).copied().unwrap_or(0);
        if a != b {
            return a < b;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::network::test_server::{FakeSesame, Reply, TestServer};
    use chrono::{TimeZone, Utc};

    const CLIENT: &str = "0.3.0";

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 10, 12, 0, 0).unwrap()
    }

    fn body(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    fn verify(fake: &FakeSesame, key_id: Option<&str>) -> Result<Document, CapabilityError> {
        verify_capability_envelope(
            &body(&fake.capabilities()),
            &fake.signing_key.verifying_key(),
            key_id,
            now(),
        )
    }

    #[test]
    fn a_document_signed_by_the_pinned_key_is_accepted() {
        let fake = FakeSesame::new(1);
        let document = verify(&fake, Some("key-1")).unwrap();
        assert_eq!(document.schema_version, 1);
        assert!(require_linking_enabled(&document, CLIENT).is_ok());
    }

    #[test]
    fn a_document_signed_by_another_key_is_untrusted() {
        let attacker = FakeSesame::new(2);
        let pinned = FakeSesame::new(1);
        assert_eq!(
            verify_capability_envelope(
                &body(&attacker.capabilities()),
                &pinned.signing_key.verifying_key(),
                None,
                now()
            )
            .unwrap_err(),
            CapabilityError::Untrusted
        );
    }

    #[test]
    fn a_document_replayed_from_another_server_with_a_matching_key_id_is_untrusted() {
        let mut other = FakeSesame::new(2);
        other.key_id = "key-1".into();
        let pinned = FakeSesame::new(1);
        assert_eq!(
            verify_capability_envelope(
                &body(&other.capabilities()),
                &pinned.signing_key.verifying_key(),
                Some("key-1"),
                now()
            )
            .unwrap_err(),
            CapabilityError::Untrusted
        );
    }

    #[test]
    fn a_tampered_payload_is_untrusted() {
        let fake = FakeSesame::new(1);
        let mut envelope = fake.capabilities();
        let mut payload = URL_SAFE_NO_PAD
            .decode(envelope["payload"].as_str().unwrap())
            .unwrap();
        let position = payload.len() / 2;
        payload[position] ^= 1;
        envelope["payload"] = serde_json::json!(URL_SAFE_NO_PAD.encode(payload));
        assert_eq!(
            verify_capability_envelope(
                &body(&envelope),
                &fake.signing_key.verifying_key(),
                None,
                now()
            )
            .unwrap_err(),
            CapabilityError::Untrusted
        );
    }

    #[test]
    fn a_key_id_that_is_not_the_pinned_one_or_is_missing_is_untrusted() {
        let fake = FakeSesame::new(1);
        assert_eq!(
            verify(&fake, Some("key-9")).unwrap_err(),
            CapabilityError::Untrusted
        );
        let mut envelope = fake.capabilities();
        envelope.as_object_mut().unwrap().remove("keyId");
        assert_eq!(
            verify_capability_envelope(
                &body(&envelope),
                &fake.signing_key.verifying_key(),
                Some("key-1"),
                now()
            )
            .unwrap_err(),
            CapabilityError::Untrusted
        );
        assert!(verify_capability_envelope(
            &body(&envelope),
            &fake.signing_key.verifying_key(),
            None,
            now()
        )
        .is_ok());
    }

    #[test]
    fn an_expired_document_is_refused_even_with_a_valid_signature() {
        let mut fake = FakeSesame::new(1);
        fake.capability_expires_at = "2026-10-10T11:59:59Z".into();
        assert_eq!(
            verify(&fake, None).unwrap_err(),
            CapabilityError::ClockDifference
        );
        fake.capability_expires_at = "2026-10-10T12:00:00Z".into();
        assert_eq!(
            verify(&fake, None).unwrap_err(),
            CapabilityError::ClockDifference
        );
        fake.capability_expires_at = "2026-10-10T12:00:01Z".into();
        assert!(verify(&fake, None).is_ok());
    }

    #[test]
    fn a_document_issued_in_the_future_is_reported_as_a_clock_difference() {
        let fake = FakeSesame::new(1);
        let check = |issued: &str| {
            let mut payload = fake.capability_payload();
            payload["issuedAt"] = serde_json::json!(issued);
            verify_capability_envelope(
                &body(&fake.signed(&payload)),
                &fake.signing_key.verifying_key(),
                None,
                now(),
            )
        };
        assert_eq!(
            check("2026-10-10T12:05:01Z").unwrap_err(),
            CapabilityError::ClockDifference
        );
        assert!(check("2026-10-10T12:05:00Z").is_ok());
        assert!(check("2026-10-10T11:00:00Z").is_ok());
    }

    #[test]
    fn the_clock_message_says_the_clocks_differ() {
        let message = String::from(CapabilityError::ClockDifference);
        assert!(message.contains("clock"));
        assert!(message.contains("differ"));
        assert!(!message.contains("unavailable"));
    }

    #[test]
    fn an_unknown_schema_version_is_refused() {
        let fake = FakeSesame::new(1);
        let mut payload = fake.capability_payload();
        payload["schemaVersion"] = serde_json::json!(2);
        let envelope = fake.signed(&payload);
        assert!(matches!(
            verify_capability_envelope(
                &body(&envelope),
                &fake.signing_key.verifying_key(),
                None,
                now()
            ),
            Err(CapabilityError::Unavailable(_))
        ));
    }

    #[test]
    fn linking_needs_the_feature_and_a_new_enough_client() {
        let mut fake = FakeSesame::new(1);
        fake.desktop_linking = false;
        let disabled = verify(&fake, None).unwrap();
        assert!(require_linking_enabled(&disabled, CLIENT).is_err());

        let fake = FakeSesame::new(1);
        let mut payload = fake.capability_payload();
        payload["minimumDesktopVersion"] = serde_json::json!("0.4.0");
        let document = verify_capability_envelope(
            &body(&fake.signed(&payload)),
            &fake.signing_key.verifying_key(),
            None,
            now(),
        )
        .unwrap();
        let error = require_linking_enabled(&document, CLIENT).unwrap_err();
        assert_eq!(
            String::from(error),
            "Update Sesame before linking this desktop."
        );
        assert!(require_linking_enabled(&document, "0.4.0").is_ok());
    }

    #[test]
    fn malformed_envelopes_are_refused() {
        let fake = FakeSesame::new(1);
        let key = fake.signing_key.verifying_key();
        for garbage in [
            b"".to_vec(),
            b"{".to_vec(),
            b"null".to_vec(),
            b"[]".to_vec(),
            body(&serde_json::json!({ "payload": "!!", "signature": "!!" })),
            body(&serde_json::json!({ "payload": "", "signature": "" })),
            body(&serde_json::json!({ "payload": 1, "signature": 2 })),
            body(&serde_json::json!({ "payload": fake.capabilities()["payload"] })),
            body(&serde_json::json!({
                "payload": fake.capabilities()["payload"],
                "signature": URL_SAFE_NO_PAD.encode([0u8; 10]),
            })),
        ] {
            assert!(
                verify_capability_envelope(&garbage, &key, None, now()).is_err(),
                "{}",
                String::from_utf8_lossy(&garbage)
            );
        }
    }

    #[test]
    fn a_validly_signed_payload_that_is_not_a_document_is_refused() {
        let fake = FakeSesame::new(1);
        let envelope = fake.signed(&serde_json::json!({ "hello": "world" }));
        assert!(matches!(
            verify_capability_envelope(
                &body(&envelope),
                &fake.signing_key.verifying_key(),
                None,
                now()
            ),
            Err(CapabilityError::Unavailable(_))
        ));
    }

    #[test]
    fn the_version_comparison_reads_numeric_parts() {
        assert!(version_lt("0.3.0", "0.10.0"));
        assert!(!version_lt("0.10.0", "0.3.0"));
        assert!(!version_lt("1.0.0", "1.0.0"));
        assert!(version_lt("0.3.0", "1"));
    }

    fn fetch(server: &TestServer, fake: &FakeSesame) -> Result<Document, CapabilityError> {
        let client =
            crate::adapters::network::account_service::client_for_base(&server.base()).unwrap();
        tauri::async_runtime::block_on(fetch_signed_document(
            &client,
            &server.base(),
            &fake.signing_key.verifying_key(),
            Some(&fake.key_id),
        ))
    }

    #[test]
    fn a_served_document_is_fetched_and_verified() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        assert!(fetch(&server, &fake).is_ok());
        assert_eq!(server.paths(), vec!["/v1/capabilities".to_string()]);
    }

    #[test]
    fn a_server_that_answers_with_an_error_or_an_oversized_body_is_refused() {
        let fake = FakeSesame::new(1);
        let failing = TestServer::start(|_| Reply::bytes(503, b"{}".to_vec()));
        assert!(matches!(
            fetch(&failing, &fake),
            Err(CapabilityError::Unavailable(_))
        ));
        let huge = TestServer::start(|_| Reply::bytes(200, vec![b' '; MAX_CAPABILITY_BYTES + 1]));
        assert!(matches!(
            fetch(&huge, &fake),
            Err(CapabilityError::Unavailable(_))
        ));
    }

    #[test]
    fn a_redirect_is_not_followed() {
        let fake = FakeSesame::new(1);
        let target = TestServer::start(fake.handler());
        let target_base = target.base();
        let redirecting = TestServer::start(move |_| {
            Reply::bytes(307, Vec::new())
                .with_header("Location", &format!("{target_base}/v1/capabilities"))
        });
        assert!(fetch(&redirecting, &fake).is_err());
        assert!(target.requests().is_empty());
    }
}
