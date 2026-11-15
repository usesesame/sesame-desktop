use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

use crate::platform::ANDROID_PLATFORM;
use crate::server_address::{fingerprint_of_public_key, normalized_fingerprint};
use crate::version;
pub use sesame_core::types::CustomServerPin;

pub const MAX_INSTANCE_BYTES: usize = 16 * 1024;
pub const MAX_NAME_CHARS: usize = 80;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const SUPPORTED_API_VERSION: u64 = 1;
pub const NOT_A_SESAME_SERVER: &str = "That address did not answer like a Sesame server.";
pub const MAX_PIN_FIELD_BYTES: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub enum ServerFailure {
    Unreachable,
    Incompatible(String),
    Invalid(String),
    KeyChanged,
    LinkMismatch,
    ClockDifference(String),
}

impl ServerFailure {
    pub fn message(&self) -> String {
        match self {
            Self::Unreachable => {
                "Sesame could not reach that server. Check the address and your connection."
                    .to_string()
            }
            Self::Incompatible(message) | Self::Invalid(message) | Self::ClockDifference(message) => {
                message.clone()
            }
            Self::KeyChanged => "This server now uses a different key than the one this desktop pinned. Disconnect, then pair again only if you expect the change.".to_string(),
            Self::LinkMismatch => "The server's fingerprint does not match the pairing link. Do not pair with this server.".to_string(),
        }
    }
}

impl From<ServerFailure> for String {
    fn from(failure: ServerFailure) -> Self {
        failure.message()
    }
}

fn invalid() -> ServerFailure {
    ServerFailure::Invalid(NOT_A_SESAME_SERVER.to_string())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstanceDocument {
    instance_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    api_version: u64,
    minimum_client_version: String,
    #[serde(default)]
    maximum_client_version: Option<String>,
    #[serde(default)]
    minimum_android_version: Option<String>,
    capability_key_id: String,
    capability_public_key: String,
    fingerprint: String,
}

#[derive(Clone, Debug)]
pub struct InstanceInfo {
    pub instance_id: String,
    pub name: String,
    pub version: String,
    pub capability_key_id: String,
    pub capability_public_key: String,
    pub fingerprint: String,
    key: VerifyingKey,
}

impl InstanceInfo {
    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }

    pub fn pin(&self) -> CustomServerPin {
        CustomServerPin {
            instance_id: self.instance_id.clone(),
            name: self.name.clone(),
            capability_key_id: self.capability_key_id.clone(),
            capability_public_key: self.capability_public_key.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

pub use crate::version::parse as parse_version;

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES && !value.chars().any(char::is_control)
}

pub fn parse_instance(
    body: &[u8],
    client_version: &str,
    client_platform: &str,
) -> Result<InstanceInfo, ServerFailure> {
    let document: InstanceDocument = serde_json::from_slice(body).map_err(|_| invalid())?;
    if document.api_version != SUPPORTED_API_VERSION {
        return Err(ServerFailure::Incompatible(format!(
            "This server uses API version {}, and this version of Sesame supports version {SUPPORTED_API_VERSION}. Update Sesame or the server.",
            document.api_version
        )));
    }
    let client = version::parse(client_version).ok_or_else(invalid)?;
    let minimum = version::parse(&document.minimum_client_version).ok_or_else(invalid)?;
    let maximum = match &document.maximum_client_version {
        Some(value) => Some(version::parse(value).ok_or_else(invalid)?),
        None => None,
    };
    if maximum.is_some_and(|maximum| maximum < minimum) {
        return Err(invalid());
    }
    let android_minimum = match &document.minimum_android_version {
        Some(value) => Some(version::parse(value).ok_or_else(invalid)?),
        None => None,
    };
    if client_platform == ANDROID_PLATFORM {
        if let Some(minimum) = android_minimum {
            if client < minimum {
                return Err(ServerFailure::Incompatible(format!(
                    "This server needs Sesame {} or newer. Update Sesame, then try again.",
                    version::display(minimum)
                )));
            }
        }
    } else {
        if client < minimum {
            return Err(ServerFailure::Incompatible(format!(
                "This server needs Sesame {} or newer. Update Sesame, then try again.",
                version::display(minimum)
            )));
        }
        if let Some(maximum) = maximum.filter(|maximum| client > *maximum) {
            return Err(ServerFailure::Incompatible(format!(
                "This server supports Sesame up to {}. Update the server, then try again.",
                version::display(maximum)
            )));
        }
    }
    if !bounded_identifier(&document.instance_id)
        || !bounded_identifier(&document.capability_key_id)
        || document.name.chars().count() > MAX_NAME_CHARS
        || document.name.len() > MAX_IDENTIFIER_BYTES
        || document.name.chars().any(char::is_control)
        || document.version.chars().count() > MAX_NAME_CHARS
        || document.version.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let raw_key = URL_SAFE_NO_PAD
        .decode(&document.capability_public_key)
        .map_err(|_| invalid())?;
    let key = VerifyingKey::from_bytes(raw_key.as_slice().try_into().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let fingerprint = fingerprint_of_public_key(&raw_key);
    if normalized_fingerprint(&document.fingerprint).as_deref() != Some(fingerprint.as_str()) {
        return Err(invalid());
    }
    Ok(InstanceInfo {
        instance_id: document.instance_id,
        name: document.name,
        version: document.version,
        capability_key_id: document.capability_key_id,
        capability_public_key: document.capability_public_key,
        fingerprint,
        key,
    })
}

pub fn pin_key(pin: &CustomServerPin) -> Option<VerifyingKey> {
    let fields = [&pin.instance_id, &pin.name, &pin.capability_key_id];
    if fields.iter().any(|field| field.len() > MAX_PIN_FIELD_BYTES)
        || pin.instance_id.is_empty()
        || pin.capability_key_id.is_empty()
    {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(&pin.capability_public_key).ok()?;
    let key = VerifyingKey::from_bytes(raw.as_slice().try_into().ok()?).ok()?;
    let fingerprint = normalized_fingerprint(&pin.fingerprint)?;
    (fingerprint == pin.fingerprint && fingerprint == fingerprint_of_public_key(&raw))
        .then_some(key)
}

pub fn check_pinned_instance(
    info: &InstanceInfo,
    pin: &CustomServerPin,
) -> Result<(), ServerFailure> {
    if info.fingerprint != pin.fingerprint || info.capability_key_id != pin.capability_key_id {
        return Err(ServerFailure::KeyChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::DESKTOP_PLATFORM;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    const KEY_ID: &str = "fictional-key";
    const CLIENT: &str = "0.3.0";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9_u8; 32])
    }

    fn public_key() -> String {
        URL_SAFE_NO_PAD.encode(key().verifying_key().to_bytes())
    }

    fn document(value: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    fn instance() -> serde_json::Value {
        let public_key = public_key();
        let raw = URL_SAFE_NO_PAD.decode(&public_key).unwrap();
        json!({
            "instanceId": "instanceAAAAAAAAAAAA1",
            "name": "Fictional server",
            "version": "1.0.0",
            "apiVersion": 1,
            "minimumClientVersion": "0.3.0",
            "maximumClientVersion": "0.9.0",
            "capabilityKeyId": KEY_ID,
            "capabilityPublicKey": public_key,
            "fingerprint": fingerprint_of_public_key(&raw),
        })
    }

    fn unsigned() -> Vec<u8> {
        document(instance())
    }

    #[test]
    fn a_document_without_the_android_field_parses_for_both_platforms() {
        assert!(parse_instance(&unsigned(), CLIENT, DESKTOP_PLATFORM).is_ok());
        assert!(parse_instance(&unsigned(), "0.1.0", ANDROID_PLATFORM).is_ok());
    }

    #[test]
    fn the_desktop_ignores_the_android_minimum() {
        let mut value = instance();
        value["minimumAndroidVersion"] = json!("99.0.0");
        assert!(parse_instance(&document(value), CLIENT, DESKTOP_PLATFORM).is_ok());
    }

    #[test]
    fn android_uses_its_own_minimum_and_ignores_the_desktop_range() {
        let mut value = instance();
        value["minimumAndroidVersion"] = json!("0.2.0");
        let body = document(value);
        assert!(parse_instance(&body, "0.1.0", ANDROID_PLATFORM).is_err());
        assert!(parse_instance(&body, "0.2.0", ANDROID_PLATFORM).is_ok());
        assert!(parse_instance(&body, "9.0.0", ANDROID_PLATFORM).is_ok());
        assert!(parse_instance(&body, "0.8.0", DESKTOP_PLATFORM).is_ok());
        assert!(parse_instance(&body, "1.0.0", DESKTOP_PLATFORM).is_err());
    }

    #[test]
    fn a_malformed_android_minimum_is_refused() {
        let mut value = instance();
        value["minimumAndroidVersion"] = json!("latest");
        assert!(matches!(
            parse_instance(&document(value), "0.1.0", ANDROID_PLATFORM),
            Err(ServerFailure::Invalid(_))
        ));
    }

    #[test]
    fn a_stored_pin_is_validated_against_its_own_key_and_fingerprint() {
        let info = parse_instance(&unsigned(), CLIENT, DESKTOP_PLATFORM).unwrap();
        let pin = info.pin();
        assert!(pin_key(&pin).is_some());
        assert_eq!(check_pinned_instance(&info, &pin), Ok(()));
        let mut forged = pin.clone();
        forged.fingerprint = "0".repeat(64);
        assert!(pin_key(&forged).is_none());
        let mut renamed = pin;
        renamed.capability_key_id = "other".into();
        assert_eq!(
            check_pinned_instance(&info, &renamed),
            Err(ServerFailure::KeyChanged)
        );
    }
}
