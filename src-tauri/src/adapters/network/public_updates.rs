//! Account-independent discovery for signed desktop updates.

use tauri::AppHandle;
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::vault::VaultResult;

fn configured_value(name: &str) -> Option<&'static str> {
    match name {
        "manifest" => option_env!("SESAME_UPDATE_MANIFEST_URL"),
        "updater-key" => option_env!("SESAME_UPDATER_PUBLIC_KEY"),
        "candidate-key" => option_env!("SESAME_RELEASE_CANDIDATE_PUBLIC_KEY"),
        "candidate-key-id" => option_env!("SESAME_RELEASE_CANDIDATE_KEY_ID"),
        _ => None,
    }
    .map(str::trim)
    .filter(|value| !value.is_empty())
}

fn insecure_loopback_enabled() -> bool {
    option_env!("SESAME_ALLOW_INSECURE_UPDATE_LOOPBACK") == Some("1")
}

fn manifest_endpoint(value: &str, allow_insecure_loopback: bool) -> VaultResult<url::Url> {
    let parsed = url::Url::parse(value)
        .map_err(|_| "This Sesame build has an invalid update manifest URL.".to_string())?;
    let credential_free = parsed.username().is_empty() && parsed.password().is_none();
    let static_location = parsed.query().is_none() && parsed.fragment().is_none();
    let secure = parsed.scheme() == "https" && parsed.host_str().is_some();
    let lab_loopback = allow_insecure_loopback
        && parsed.scheme() == "http"
        && parsed.host().is_some_and(|host| match host {
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
            url::Host::Domain(_) => false,
        });
    if !credential_free || !static_location || (!secure && !lab_loopback) {
        return Err("This Sesame build has an unsafe update manifest URL.".into());
    }
    Ok(parsed)
}

pub(crate) fn updater_public_key_if_configured() -> Option<&'static str> {
    let required = [
        configured_value("manifest"),
        configured_value("updater-key"),
        configured_value("candidate-key"),
        configured_value("candidate-key-id"),
    ];
    if required.iter().any(Option::is_none) {
        return None;
    }
    manifest_endpoint(required[0]?, insecure_loopback_enabled()).ok()?;
    required[1]
}

fn configured_endpoint() -> VaultResult<url::Url> {
    if updater_public_key_if_configured().is_none() {
        return Err(
            "This Sesame build does not include a complete signed-update configuration.".into(),
        );
    }
    let manifest = configured_value("manifest")
        .ok_or("This Sesame build does not include an update manifest URL.")?;
    manifest_endpoint(manifest, insecure_loopback_enabled())
}

pub(crate) async fn check(app: &AppHandle) -> VaultResult<Option<Update>> {
    let endpoint = configured_endpoint()?;
    app.updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|_| "Sesame could not prepare the signed updater.".to_string())?
        .build()
        .map_err(|_| "Sesame could not prepare the signed updater.".to_string())?
        .check()
        .await
        .map_err(|_| {
            "Sesame could not check for updates. Check your connection and try again.".to_string()
        })
}
