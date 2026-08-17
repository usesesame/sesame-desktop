//! OS browser launch behind a Rust-owned URL policy.
//! The renderer has no opener permission; this rejects non-web schemes and embedded credentials.

use std::collections::BTreeSet;

use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_opener::OpenerExt;

use crate::vault::{VaultEntry, VaultResult, VaultState};

const SAVED_LOGIN_PURPOSE: &str = "savedLogin";
const SUPPORT_PURPOSE: &str = "support";

fn allowed_external_url(value: &str) -> VaultResult<url::Url> {
    let parsed =
        url::Url::parse(value).map_err(|_| "That website address is invalid.".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("Sesame opens only credential-free HTTP or HTTPS website addresses.".into());
    }
    Ok(parsed)
}

fn saved_url(value: &str) -> Option<url::Url> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let candidate = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    allowed_external_url(&candidate).ok()
}

fn entry_owns_url(entry: &VaultEntry, requested: &url::Url) -> bool {
    std::iter::once(&entry.url)
        .chain(entry.urls.iter())
        .filter_map(|candidate| saved_url(candidate))
        .any(|candidate| candidate == *requested)
}

fn safe_support_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn support_url_matches(requested: &url::Url, configured_origin: Option<&str>) -> bool {
    let Some(origin) = configured_origin.and_then(|value| allowed_external_url(value).ok()) else {
        return false;
    };
    if requested.origin() != origin.origin()
        || requested.path() != "/support"
        || requested.fragment().is_some()
    {
        return false;
    }
    let mut names = BTreeSet::new();
    requested.query_pairs().all(|(name, value)| {
        matches!(
            name.as_ref(),
            "appVersion" | "diagnosticCode" | "browserIntegration" | "requestId"
        ) && names.insert(name.into_owned())
            && safe_support_value(&value)
    })
}

#[tauri::command]
pub fn open_external_url(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, VaultState>,
    url: String,
    purpose: String,
) -> VaultResult<()> {
    if window.label() != "main" {
        return Err("This window cannot open external websites.".into());
    }
    let parsed = allowed_external_url(url.trim())?;
    match purpose.as_str() {
        SAVED_LOGIN_PURPOSE => {
            let session = state
                .session
                .lock()
                .map_err(|_| "Sesame could not read the vault session.".to_string())?;
            let session = session.as_ref().ok_or("Unlock your vault first.")?;
            if !session
                .payload
                .entries
                .iter()
                .any(|entry| entry_owns_url(entry, &parsed))
            {
                return Err("That website is not attached to a saved login.".into());
            }
        }
        SUPPORT_PURPOSE => {
            if !support_url_matches(&parsed, option_env!("VITE_SESAME_SITE_ORIGIN")) {
                return Err("The Sesame support website is not configured for this build.".into());
            }
        }
        _ => return Err("That external website request is not supported.".into()),
    }
    app.opener()
        .open_url(parsed.as_str(), None::<&str>)
        .map_err(|_| "Sesame could not open that website.".to_string())
}
