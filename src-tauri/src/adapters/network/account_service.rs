use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use super::ensure_crypto_provider;
use super::server_address::{fingerprint_of_public_key, normalized_fingerprint, ServerAddress};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::redirect::Policy;
use tauri::{AppHandle, Manager};
use zeroize::Zeroize;

use crate::vault::platform::unprotect_for_device;
use crate::vault::types::{CustomServerPin, ServiceConnectionFile};
use crate::vault::{VaultResult, SERVICE_CONNECTION_FORMAT_VERSION};

const BOUND_TOKEN_PREFIX: &str = "sesame-server-token-v1\n";
const MAX_PIN_FIELD_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceTarget {
    Official {
        base_url: String,
    },
    Custom {
        address: ServerAddress,
        pin: CustomServerPin,
    },
}

impl ServiceTarget {
    pub fn base_url(&self) -> &str {
        match self {
            Self::Official { base_url } => base_url,
            Self::Custom { address, .. } => address.as_str(),
        }
    }

    #[cfg(feature = "sync-preview")]
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom { .. })
    }
}

/// Rust-only URL: the webview CSP never includes it in `connect-src`.
pub fn service_api_base_url() -> VaultResult<String> {
    let configured = option_env!("SESAME_API_BASE_URL")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Desktop account service is not configured for this build. For local development, create src-tauri/.env.local from src-tauri/.env.example. Release builds require SESAME_API_BASE_URL.".to_string())?;
    let parsed = url::Url::parse(configured)
        .map_err(|_| "Sesame account service URL is invalid.".to_string())?;
    let loopback_development = parsed.scheme() == "http"
        && parsed
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if (parsed.scheme() != "https" && !loopback_development)
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("Sesame account service URL must be an HTTPS origin (or a loopback HTTP development origin).".into());
    }
    Ok(parsed.origin().ascii_serialization())
}

fn loopback_http(parsed: &url::Url) -> bool {
    parsed.scheme() == "http"
        && match parsed.host() {
            Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        }
}

pub fn service_client() -> VaultResult<reqwest::Client> {
    client_for_base(&service_api_base_url()?)
}

pub fn client_for_base(base_url: &str) -> VaultResult<reqwest::Client> {
    let parsed = url::Url::parse(base_url)
        .map_err(|_| "Sesame account service URL is invalid.".to_string())?;
    let loopback_http = loopback_http(&parsed);
    if parsed.scheme() != "https" && !loopback_http {
        return Err("Sesame refuses to send an account token over an insecure network URL.".into());
    }
    ensure_crypto_provider();
    reqwest::Client::builder()
        .https_only(!loopback_http)
        .redirect(Policy::none())
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| "Sesame could not prepare its account connection.".to_string())
}

pub async fn read_limited(mut response: reqwest::Response, limit: usize) -> Option<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len() + chunk.len() > limit {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

pub fn bind_token_to_server(address: &ServerAddress, token: &str) -> Vec<u8> {
    format!("{BOUND_TOKEN_PREFIX}{}\n{token}", address.as_str()).into_bytes()
}

fn service_connection_path(app: &AppHandle) -> VaultResult<PathBuf> {
    let mut path = app
        .path()
        .app_local_data_dir()
        .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
    path.push("service-connection.json");
    Ok(path)
}

pub fn write_service_connection(
    app: &AppHandle,
    connection: &ServiceConnectionFile,
) -> VaultResult<()> {
    let path = service_connection_path(app)?;
    let parent = path
        .parent()
        .ok_or("Sesame could not find its local data folder.")?;
    fs::create_dir_all(parent)
        .map_err(|_| "Sesame could not prepare its local data folder.".to_string())?;
    let bytes = serde_json::to_vec(connection)
        .map_err(|_| "Sesame could not save the desktop connection.".to_string())?;
    crate::vault::storage::atomic_replace(&path, &bytes)
}

pub fn read_service_connection(app: &AppHandle) -> VaultResult<ServiceConnectionFile> {
    read_service_connection_at(
        &service_connection_path(app)?,
        service_api_base_url().ok().as_deref(),
    )
}

fn read_service_connection_at(
    path: &std::path::Path,
    official_base_url: Option<&str>,
) -> VaultResult<ServiceConnectionFile> {
    let bytes = crate::vault::util::require_file_with_limit(
        path,
        64 * 1024,
        "No desktop account connection is stored on this device.",
    )?;
    parse_service_connection(&bytes, official_base_url)
}

fn connection_invalid() -> String {
    "The desktop account connection is invalid.".to_string()
}

fn parse_service_connection(
    bytes: &[u8],
    official_base_url: Option<&str>,
) -> VaultResult<ServiceConnectionFile> {
    let connection: ServiceConnectionFile =
        serde_json::from_slice(bytes).map_err(|_| connection_invalid())?;
    if connection.format_version != SERVICE_CONNECTION_FORMAT_VERSION
        || connection.protected_token.is_empty()
        || connection.device_id.is_empty()
        || connection.device_name.is_empty()
    {
        return Err(connection_invalid());
    }
    match &connection.custom_server {
        None => {
            if official_base_url != Some(connection.api_base_url.as_str()) {
                return Err(connection_invalid());
            }
        }
        Some(pin) => {
            let address =
                ServerAddress::parse(&connection.api_base_url).map_err(|_| connection_invalid())?;
            if address.as_str() != connection.api_base_url
                || address.refuse_official_host(official_base_url).is_err()
                || pin_key(pin).is_none()
            {
                return Err(connection_invalid());
            }
        }
    }
    Ok(connection)
}

pub fn pin_key(pin: &CustomServerPin) -> Option<ed25519_dalek::VerifyingKey> {
    let fields = [&pin.instance_id, &pin.name, &pin.capability_key_id];
    if fields.iter().any(|field| field.len() > MAX_PIN_FIELD_BYTES)
        || pin.instance_id.is_empty()
        || pin.capability_key_id.is_empty()
    {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(&pin.capability_public_key).ok()?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(raw.as_slice().try_into().ok()?).ok()?;
    let fingerprint = normalized_fingerprint(&pin.fingerprint)?;
    (fingerprint == pin.fingerprint && fingerprint == fingerprint_of_public_key(&raw))
        .then_some(key)
}

pub fn service_target(connection: &ServiceConnectionFile) -> VaultResult<ServiceTarget> {
    match &connection.custom_server {
        None => Ok(ServiceTarget::Official {
            base_url: connection.api_base_url.clone(),
        }),
        Some(pin) => {
            let address =
                ServerAddress::parse(&connection.api_base_url).map_err(|_| connection_invalid())?;
            if address.as_str() != connection.api_base_url || pin_key(pin).is_none() {
                return Err(connection_invalid());
            }
            Ok(ServiceTarget::Custom {
                address,
                pin: pin.clone(),
            })
        }
    }
}

pub fn read_service_token(connection: &ServiceConnectionFile) -> VaultResult<String> {
    let protected = URL_SAFE_NO_PAD
        .decode(&connection.protected_token)
        .map_err(|_| connection_invalid())?;
    let mut bytes = unprotect_for_device(&protected)?;
    let text = std::str::from_utf8(&bytes).map(str::to_owned);
    bytes.zeroize();
    let mut text = text.map_err(|_| connection_invalid())?;
    let token = unbound_token(
        &connection.api_base_url,
        connection.custom_server.is_some(),
        &text,
    );
    text.zeroize();
    token
}

fn unbound_token(api_base_url: &str, custom: bool, stored: &str) -> VaultResult<String> {
    if !custom {
        return if stored.starts_with(BOUND_TOKEN_PREFIX) {
            Err(connection_invalid())
        } else {
            Ok(stored.to_string())
        };
    }
    let rest = stored
        .strip_prefix(BOUND_TOKEN_PREFIX)
        .ok_or_else(connection_invalid)?;
    let (origin, token) = rest.split_once('\n').ok_or_else(connection_invalid)?;
    if origin != api_base_url || token.is_empty() {
        return Err(connection_invalid());
    }
    Ok(token.to_string())
}

pub fn remove_service_connection(app: &AppHandle) -> VaultResult<()> {
    let path = service_connection_path(app)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not remove the desktop account connection.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const API_BASE_URL: &str = "https://api.example.test";
    const CUSTOM_BASE_URL: &str = "https://sesame.home.example.test/vault";

    fn pin(seed: u8) -> CustomServerPin {
        let key = SigningKey::from_bytes(&[seed; 32]).verifying_key();
        CustomServerPin {
            instance_id: "instance-1".to_string(),
            name: "Home server".to_string(),
            capability_key_id: "key-1".to_string(),
            capability_public_key: URL_SAFE_NO_PAD.encode(key.as_bytes()),
            fingerprint: fingerprint_of_public_key(key.as_bytes()),
        }
    }

    fn connection() -> ServiceConnectionFile {
        ServiceConnectionFile {
            format_version: SERVICE_CONNECTION_FORMAT_VERSION,
            api_base_url: API_BASE_URL.to_string(),
            protected_token: "cHJvdGVjdGVk".to_string(),
            device_id: "device-1".to_string(),
            device_name: "Linux desktop".to_string(),
            expires_at: None,
            custom_server: None,
        }
    }

    fn custom_connection() -> ServiceConnectionFile {
        ServiceConnectionFile {
            api_base_url: CUSTOM_BASE_URL.to_string(),
            custom_server: Some(pin(1)),
            ..connection()
        }
    }

    fn parse(value: &ServiceConnectionFile) -> VaultResult<ServiceConnectionFile> {
        parse_service_connection(&serde_json::to_vec(value).unwrap(), Some(API_BASE_URL))
    }

    #[test]
    fn a_stored_connection_round_trips() {
        let parsed = parse(&connection()).unwrap();
        assert_eq!(parsed.api_base_url, API_BASE_URL);
        assert_eq!(parsed.device_id, "device-1");
        assert_eq!(parsed.device_name, "Linux desktop");
        assert_eq!(parsed.custom_server, None);
    }

    #[test]
    fn a_record_written_before_custom_servers_existed_still_reads() {
        let legacy = br#"{"formatVersion":1,"apiBaseUrl":"https://api.example.test","protectedToken":"cHJvdGVjdGVk","deviceId":"device-1","deviceName":"Linux desktop"}"#;
        let parsed = parse_service_connection(legacy, Some(API_BASE_URL)).unwrap();
        assert_eq!(parsed.custom_server, None);
        assert!(matches!(
            service_target(&parsed).unwrap(),
            ServiceTarget::Official { .. }
        ));
    }

    #[test]
    fn an_official_record_serializes_without_a_custom_server_field() {
        let json = serde_json::to_string(&connection()).unwrap();
        assert!(!json.contains("customServer"));
    }

    #[test]
    fn a_custom_record_round_trips_with_its_pin() {
        let parsed = parse(&custom_connection()).unwrap();
        assert_eq!(parsed.custom_server, Some(pin(1)));
        match service_target(&parsed).unwrap() {
            ServiceTarget::Custom {
                address,
                pin: stored,
            } => {
                assert_eq!(address.as_str(), CUSTOM_BASE_URL);
                assert_eq!(stored, pin(1));
            }
            ServiceTarget::Official { .. } => panic!("a custom record became official"),
        }
    }

    #[test]
    fn a_custom_record_reads_when_the_build_has_no_official_service() {
        let bytes = serde_json::to_vec(&custom_connection()).unwrap();
        assert!(parse_service_connection(&bytes, None).is_ok());
        let official = serde_json::to_vec(&connection()).unwrap();
        assert!(parse_service_connection(&official, None).is_err());
    }

    #[test]
    fn a_connection_written_for_another_service_is_refused() {
        let mut value = connection();
        value.api_base_url = "https://api.other.test".to_string();
        assert!(parse(&value).is_err());
    }

    #[test]
    fn an_official_record_cannot_be_redirected_by_editing_its_address() {
        let mut value = connection();
        value.api_base_url = CUSTOM_BASE_URL.to_string();
        assert!(parse(&value).is_err());
    }

    #[test]
    fn a_pin_cannot_be_attached_to_the_official_address() {
        let mut value = connection();
        value.custom_server = Some(pin(1));
        assert!(parse(&value).is_err());
        let mut same_host = custom_connection();
        same_host.api_base_url = "https://api.example.test/other".to_string();
        assert!(parse(&same_host).is_err());
    }

    #[test]
    fn a_custom_record_with_an_unsafe_or_unnormalized_address_is_refused() {
        for address in [
            "http://sesame.home.example.test",
            "https://user@sesame.home.example.test",
            "https://sesame.home.example.test?x=1",
            "https://sesame.home.example.test/vault/",
            "https://Sesame.Home.Example.Test/vault",
            "ftp://sesame.home.example.test",
            "",
        ] {
            let mut value = custom_connection();
            value.api_base_url = address.to_string();
            assert!(parse(&value).is_err(), "{address}");
        }
    }

    #[test]
    fn a_custom_record_with_a_forged_pin_is_refused() {
        let mut mismatched = custom_connection();
        if let Some(stored) = mismatched.custom_server.as_mut() {
            stored.fingerprint = pin(2).fingerprint;
        }
        assert!(parse(&mismatched).is_err());

        let mut uppercase = custom_connection();
        if let Some(stored) = uppercase.custom_server.as_mut() {
            stored.fingerprint = stored.fingerprint.to_uppercase();
        }
        assert!(parse(&uppercase).is_err());

        for edit in [
            |stored: &mut CustomServerPin| stored.capability_public_key = "AAAA".to_string(),
            |stored: &mut CustomServerPin| stored.capability_public_key.clear(),
            |stored: &mut CustomServerPin| stored.instance_id.clear(),
            |stored: &mut CustomServerPin| stored.capability_key_id.clear(),
            |stored: &mut CustomServerPin| stored.name = "n".repeat(MAX_PIN_FIELD_BYTES + 1),
        ] {
            let mut value = custom_connection();
            if let Some(stored) = value.custom_server.as_mut() {
                edit(stored);
            }
            assert!(parse(&value).is_err());
        }
    }

    #[test]
    fn an_unsupported_connection_format_is_refused() {
        let mut value = connection();
        value.format_version = SERVICE_CONNECTION_FORMAT_VERSION + 1;
        assert!(parse(&value).is_err());
        let mut custom = custom_connection();
        custom.format_version = SERVICE_CONNECTION_FORMAT_VERSION + 1;
        assert!(parse(&custom).is_err());
    }

    #[test]
    fn blank_connection_fields_are_refused() {
        for blank in [
            |value: &mut ServiceConnectionFile| value.protected_token.clear(),
            |value: &mut ServiceConnectionFile| value.device_id.clear(),
            |value: &mut ServiceConnectionFile| value.device_name.clear(),
        ] {
            let mut value = connection();
            blank(&mut value);
            assert!(parse(&value).is_err());
        }
    }

    #[test]
    fn a_malformed_connection_is_refused() {
        assert!(parse_service_connection(b"{", Some(API_BASE_URL)).is_err());
        assert!(parse_service_connection(b"", Some(API_BASE_URL)).is_err());
        assert!(parse_service_connection(b"null", Some(API_BASE_URL)).is_err());
        let wrong_type = br#"{"formatVersion":1,"apiBaseUrl":"https://api.example.test","protectedToken":"x","deviceId":"d","deviceName":"n","customServer":"yes"}"#;
        assert!(parse_service_connection(wrong_type, Some(API_BASE_URL)).is_err());
    }

    #[test]
    fn an_oversized_connection_file_is_refused() {
        let directory = std::env::temp_dir().join(format!(
            "sesame-account-connection-{}",
            crate::vault::util::random_id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("service-connection.json");
        std::fs::write(&path, vec![b' '; 64 * 1024 + 1]).unwrap();
        assert!(read_service_connection_at(&path, Some(API_BASE_URL)).is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_custom_token_is_stored_bound_to_its_server() {
        let address = ServerAddress::parse(CUSTOM_BASE_URL).unwrap();
        let bound = String::from_utf8(bind_token_to_server(&address, "fictional-token")).unwrap();
        assert_eq!(
            unbound_token(CUSTOM_BASE_URL, true, &bound).unwrap(),
            "fictional-token"
        );
    }

    #[test]
    fn a_bound_token_is_refused_for_any_other_address() {
        let address = ServerAddress::parse(CUSTOM_BASE_URL).unwrap();
        let bound = String::from_utf8(bind_token_to_server(&address, "fictional-token")).unwrap();
        for other in [
            "https://evil.example.test",
            "https://sesame.home.example.test",
            "https://sesame.home.example.test/vault/other",
            "https://sesame.home.example.test/vaul",
            API_BASE_URL,
        ] {
            assert!(unbound_token(other, true, &bound).is_err(), "{other}");
        }
    }

    #[test]
    fn a_bound_token_is_never_sent_as_an_official_token() {
        let address = ServerAddress::parse(CUSTOM_BASE_URL).unwrap();
        let bound = String::from_utf8(bind_token_to_server(&address, "fictional-token")).unwrap();
        assert!(unbound_token(API_BASE_URL, false, &bound).is_err());
    }

    #[test]
    fn a_plain_token_is_not_accepted_for_a_custom_server() {
        assert!(unbound_token(CUSTOM_BASE_URL, true, "fictional-token").is_err());
        assert_eq!(
            unbound_token(API_BASE_URL, false, "fictional-token").unwrap(),
            "fictional-token"
        );
    }

    #[test]
    fn malformed_bound_tokens_are_refused() {
        for stored in [
            BOUND_TOKEN_PREFIX.to_string(),
            format!("{BOUND_TOKEN_PREFIX}{CUSTOM_BASE_URL}"),
            format!("{BOUND_TOKEN_PREFIX}{CUSTOM_BASE_URL}\n"),
            format!("{BOUND_TOKEN_PREFIX}\ntoken"),
        ] {
            assert!(
                unbound_token(CUSTOM_BASE_URL, true, &stored).is_err(),
                "{stored:?}"
            );
        }
    }

    #[test]
    fn the_client_refuses_plain_http_off_loopback_and_unknown_schemes() {
        assert!(client_for_base("https://sesame.home.example.test").is_ok());
        assert!(client_for_base("http://127.0.0.1:8787").is_ok());
        assert!(client_for_base("http://[::1]:8787").is_ok());
        assert!(client_for_base("http://localhost:8787").is_ok());
        for refused in [
            "http://sesame.home.example.test",
            "http://192.168.0.2",
            "ftp://localhost",
            "not a url",
        ] {
            assert!(client_for_base(refused).is_err(), "{refused}");
        }
    }
}
