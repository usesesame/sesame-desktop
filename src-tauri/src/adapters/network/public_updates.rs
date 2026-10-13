//! Account-independent discovery for signed desktop updates.

use std::time::Duration;

use reqwest::{redirect, ClientBuilder};
use tauri::{AppHandle, Runtime};
use tauri_plugin_updater::{Update, UpdaterBuilder, UpdaterExt};

use crate::vault::VaultResult;

#[derive(Clone, Copy)]
pub(crate) struct TransferLimits {
    pub connect: Duration,
    pub read: Duration,
    pub manifest_total: Duration,
    pub download_total: Duration,
}

pub(crate) const TRANSFER_LIMITS: TransferLimits = TransferLimits {
    connect: Duration::from_secs(15),
    read: Duration::from_secs(30),
    manifest_total: Duration::from_secs(30),
    download_total: Duration::from_secs(30 * 60),
};

const MAX_REDIRECTS: usize = 5;
const RELEASE_HOST: &str = "github.com";
const RELEASE_ASSET_HOSTS: [&str; 2] = [
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];

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

pub(crate) fn redirect_allowed(origin: &url::Url, target: &url::Url) -> bool {
    let credential_free = target.username().is_empty() && target.password().is_none();
    let same_origin = target.scheme() == origin.scheme()
        && target.host_str() == origin.host_str()
        && target.port_or_known_default() == origin.port_or_known_default();
    let release_asset = origin.host_str() == Some(RELEASE_HOST)
        && target
            .host_str()
            .is_some_and(|host| RELEASE_ASSET_HOSTS.contains(&host));
    credential_free && target.scheme() == "https" && (same_origin || release_asset)
}

fn redirect_policy() -> redirect::Policy {
    redirect::Policy::custom(|attempt| {
        let origin_allows = attempt
            .previous()
            .first()
            .is_some_and(|origin| redirect_allowed(origin, attempt.url()));
        if attempt.previous().len() > MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else if origin_allows {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

pub(crate) fn bounded_client(builder: ClientBuilder, limits: TransferLimits) -> ClientBuilder {
    builder
        .connect_timeout(limits.connect)
        .read_timeout(limits.read)
        .redirect(redirect_policy())
}

pub(crate) fn updater_builder<R: Runtime>(
    app: &AppHandle<R>,
    endpoint: url::Url,
    limits: TransferLimits,
) -> VaultResult<UpdaterBuilder> {
    Ok(app
        .updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|_| "Sesame could not prepare the signed updater.".to_string())?
        .timeout(limits.manifest_total)
        .configure_client(move |client| bounded_client(client, limits)))
}

pub(crate) async fn check(app: &AppHandle) -> VaultResult<Option<Update>> {
    check_endpoint(app, configured_endpoint()?, TRANSFER_LIMITS).await
}

pub(crate) async fn check_endpoint<R: Runtime>(
    app: &AppHandle<R>,
    endpoint: url::Url,
    limits: TransferLimits,
) -> VaultResult<Option<Update>> {
    let update = updater_builder(app, endpoint, limits)?
        .build()
        .map_err(|_| "Sesame could not prepare the signed updater.".to_string())?
        .check()
        .await
        .map_err(|_| {
            "Sesame could not check for updates. Check your connection and try again.".to_string()
        })?;
    Ok(update.map(|mut update| {
        update.timeout = Some(limits.download_total);
        update
    }))
}

#[cfg(test)]
mod tests {
    use super::redirect_allowed;

    fn parse(value: &str) -> url::Url {
        url::Url::parse(value).expect("url")
    }

    #[test]
    fn follows_a_redirect_inside_one_origin() {
        let origin = parse("https://releases.example.test/a/latest.json");
        assert!(redirect_allowed(
            &origin,
            &parse("https://releases.example.test/b/latest.json")
        ));
    }

    #[test]
    fn refuses_a_redirect_to_another_host_port_or_scheme() {
        let origin = parse("https://releases.example.test/latest.json");
        for target in [
            "https://other.example.test/latest.json",
            "https://releases.example.test.other.example/latest.json",
            "https://releases.example.test:8443/latest.json",
            "http://releases.example.test/latest.json",
            "https://user:secret@releases.example.test/latest.json",
            "https://127.0.0.1/latest.json",
        ] {
            assert!(!redirect_allowed(&origin, &parse(target)), "{target}");
        }
    }

    #[test]
    fn follows_the_release_host_to_its_asset_hosts_only() {
        let origin = parse("https://github.com/fictional/app/releases/download/v1.2.3/Setup.exe");
        for target in [
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/2",
            "https://objects.githubusercontent.com/github-production-release-asset/1/2",
        ] {
            assert!(redirect_allowed(&origin, &parse(target)), "{target}");
        }
        for target in [
            "https://githubusercontent.com/x",
            "https://evil.githubusercontent.com/x",
            "https://release-assets.githubusercontent.com.evil.example/x",
            "http://release-assets.githubusercontent.com/x",
            "https://gist.github.com/x",
        ] {
            assert!(!redirect_allowed(&origin, &parse(target)), "{target}");
        }
    }

    #[test]
    fn grants_no_asset_host_exception_to_other_origins() {
        let origin = parse("https://releases.example.test/Setup.exe");
        assert!(!redirect_allowed(
            &origin,
            &parse("https://release-assets.githubusercontent.com/x")
        ));
    }
}
