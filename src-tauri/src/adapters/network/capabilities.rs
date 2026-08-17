use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use super::account_service::{service_api_base_url, service_client};
use crate::vault::VaultResult;

#[derive(Deserialize)]
struct Envelope {
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    schema_version: u8,
    minimum_desktop_version: String,
    features: std::collections::BTreeMap<String, bool>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub async fn require_desktop_linking() -> VaultResult<()> {
    let encoded = option_env!("SESAME_CAPABILITY_PUBLIC_KEY")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("Desktop capability verification is not configured for this build.")?;
    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "Desktop capability verification key is invalid.")?;
    let key = VerifyingKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Desktop capability verification key is invalid.")?,
    )
    .map_err(|_| "Desktop capability verification key is invalid.")?;
    let client = service_client()?;
    let response = client
        .get(format!("{}/v1/capabilities", service_api_base_url()?))
        .send()
        .await
        .map_err(|_| "Sesame could not retrieve the signed capability configuration.")?;
    if !response.status().is_success() {
        return Err(
            "Sesame capability configuration is unavailable. Desktop linking stays disabled."
                .into(),
        );
    }
    let envelope: Envelope = response
        .json()
        .await
        .map_err(|_| "Sesame capability configuration is invalid.")?;
    let payload = URL_SAFE_NO_PAD
        .decode(envelope.payload)
        .map_err(|_| "Sesame capability configuration is invalid.")?;
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(envelope.signature)
            .map_err(|_| "Sesame capability configuration is invalid.")?,
    )
    .map_err(|_| "Sesame capability configuration is invalid.")?;
    key.verify(&payload, &signature)
        .map_err(|_| "Sesame capability signature is invalid.")?;
    let document: Document = serde_json::from_slice(&payload)
        .map_err(|_| "Sesame capability configuration is invalid.")?;
    if document.schema_version != 1
        || document.expires_at <= chrono::Utc::now()
        || !document
            .features
            .get("desktopLinking")
            .copied()
            .unwrap_or(false)
    {
        return Err("Desktop linking is currently unavailable.".into());
    }
    if version_lt(env!("CARGO_PKG_VERSION"), &document.minimum_desktop_version) {
        return Err("Update Sesame before linking this desktop.".into());
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
