use super::ensure_crypto_provider;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};

use crate::vault::VaultResult;

const SUCCESS_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const FAILURE_RETRY_SECS: u64 = 6 * 60 * 60;
const MAX_ICON_BYTES: usize = 128 * 1024;
const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 500;

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CacheMetadata {
    fetched_at: Option<u64>,
    failed_at: Option<u64>,
    media_type: Option<String>,
}

struct CachePaths {
    metadata: PathBuf,
    image: PathBuf,
}

struct ValidatedHost {
    host: String,
    addresses: Vec<SocketAddr>,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct WebsiteIconCacheStatus {
    entry_count: usize,
    icon_count: usize,
    size_bytes: u64,
}

#[tauri::command]
pub async fn get_website_icon(app: AppHandle, site: String) -> VaultResult<Option<String>> {
    let host = normalized_host(&site)?;
    let cache_dir = cache_dir(&app)?;
    fs::create_dir_all(&cache_dir)
        .map_err(|_| "Sesame could not create the website icon cache.".to_string())?;
    let paths = cache_paths(&cache_dir, &host);
    let mut metadata = read_metadata(&paths.metadata);
    let now = unix_time();

    if cache_is_fresh(&metadata, now) {
        if let Some(icon) = read_cached_icon(&paths.image, metadata.media_type.as_deref()) {
            return Ok(Some(icon));
        }
    }

    if failure_is_recent(&metadata, now) {
        return Ok(read_cached_icon(
            &paths.image,
            metadata.media_type.as_deref(),
        ));
    }

    let fetched = match resolve_public_host(host).await {
        Ok(validated) => fetch_icon(&validated).await,
        Err(error) => Err(error),
    };
    match fetched {
        Ok((bytes, media_type)) => {
            write_atomic(&paths.image, &bytes)?;
            metadata.fetched_at = Some(now);
            metadata.failed_at = None;
            metadata.media_type = Some(media_type.clone());
            write_metadata(&paths.metadata, &metadata)?;
            prune_cache(&cache_dir, &paths.metadata, &paths.image);
            Ok(Some(data_url(&media_type, &bytes)))
        }
        Err(_) => {
            metadata.failed_at = Some(now);
            write_metadata(&paths.metadata, &metadata)?;
            prune_cache(&cache_dir, &paths.metadata, &paths.image);
            Ok(read_cached_icon(
                &paths.image,
                metadata.media_type.as_deref(),
            ))
        }
    }
}

#[tauri::command]
pub fn clear_website_icon_cache(app: AppHandle) -> VaultResult<()> {
    let path = cache_dir(&app)?;
    if path.exists() {
        fs::remove_dir_all(path)
            .map_err(|_| "Sesame could not clear the website icon cache.".to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn get_website_icon_cache_status(app: AppHandle) -> VaultResult<WebsiteIconCacheStatus> {
    let path = cache_dir(&app)?;
    cleanup_stale_temporary_files(&path);
    Ok(cache_status_at(&path))
}

fn cache_dir(app: &AppHandle) -> VaultResult<PathBuf> {
    app.path()
        .app_cache_dir()
        .map(|path| path.join("website-icons-v1"))
        .map_err(|_| "Sesame could not locate its website icon cache.".to_string())
}

fn cache_paths(cache_dir: &Path, host: &str) -> CachePaths {
    let key = format!("{:x}", Sha256::digest(host.as_bytes()));
    CachePaths {
        metadata: cache_dir.join(format!("{key}.json")),
        image: cache_dir.join(format!("{key}.img")),
    }
}

fn normalized_host(site: &str) -> VaultResult<String> {
    let candidate = site.trim().trim_end_matches('.').to_ascii_lowercase();
    if candidate.is_empty()
        || candidate == "no website saved"
        || candidate == "localhost"
        || candidate.ends_with(".local")
        || !candidate.contains('.')
        || candidate.len() > 253
        || candidate.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|value| value.is_ascii_alphanumeric() || value == '-')
        })
    {
        return Err("This website cannot be used for icon fetching.".to_string());
    }
    let parsed = url::Url::parse(&format!("https://{candidate}/favicon.ico"))
        .map_err(|_| "This website cannot be used for icon fetching.".to_string())?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "This website cannot be used for icon fetching.".to_string())?
        .to_string();
    if host.parse::<IpAddr>().is_ok() {
        return Err("Website icons are only fetched for public domain names.".to_string());
    }
    Ok(host)
}

async fn resolve_public_host(host: String) -> VaultResult<ValidatedHost> {
    let lookup_host = host.clone();
    let addresses = tauri::async_runtime::spawn_blocking(move || {
        (lookup_host.as_str(), 443)
            .to_socket_addrs()
            .map(|items| items.collect::<Vec<_>>())
    })
    .await
    .map_err(|_| "Sesame could not check the website address.".to_string())?
    .map_err(|_| "Sesame could not find that website.".to_string())?;

    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err("Website icons are only fetched from public addresses.".to_string());
    }
    Ok(ValidatedHost { host, addresses })
}

/// One redirect only: HTTPS, same registrable domain, re-checked through the public-address pin.
async fn fetch_icon(validated: &ValidatedHost) -> VaultResult<(Vec<u8>, String)> {
    let mut response = request_icon(validated).await?;

    if response.status().is_redirection() {
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| "That website did not provide an icon.".to_string())?;
        let target = redirect_target(&validated.host, location)?;
        let hop = resolve_public_host(target).await?;
        response = request_icon(&hop).await?;
    }

    if !response.status().is_success() {
        return Err("That website did not provide an icon.".to_string());
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ICON_BYTES as u64)
    {
        return Err("That website icon is too large.".to_string());
    }

    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Sesame could not read that website icon.".to_string())?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_ICON_BYTES {
            return Err("That website icon is too large.".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    let media_type = detect_image_type(&bytes)
        .ok_or_else(|| "That website returned an unsupported icon format.".to_string())?;
    Ok((bytes, media_type.to_string()))
}

async fn request_icon(validated: &ValidatedHost) -> VaultResult<reqwest::Response> {
    icon_client(&validated.host, &validated.addresses)?
        .get(format!("https://{}/favicon.ico", validated.host))
        .send()
        .await
        .map_err(|_| "Sesame could not fetch that website icon.".to_string())
}

/// Only the bare/www equivalence is followed; anything else would let a site pick an arbitrary URL.
fn redirect_target(original: &str, location: &str) -> VaultResult<String> {
    let refused = || "That website did not provide an icon.".to_string();
    let base =
        url::Url::parse(&format!("https://{original}/favicon.ico")).map_err(|_| refused())?;
    let target = base.join(location).map_err(|_| refused())?;

    if target.scheme() != "https" || target.port().is_some_and(|port| port != 443) {
        return Err(refused());
    }
    let host = target.host_str().ok_or_else(refused)?.to_ascii_lowercase();
    let original = original.to_ascii_lowercase();
    let same_site =
        host == original || host == format!("www.{original}") || original == format!("www.{host}");
    if !same_site {
        return Err(refused());
    }
    Ok(host)
}

fn icon_client(host: &str, pinned: &[SocketAddr]) -> VaultResult<Client> {
    ensure_crypto_provider();
    Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .user_agent("Sesame website icon cache/1")
        .resolve_to_addrs(host, pinned)
        .build()
        .map_err(|_| "Sesame could not prepare the website icon request.".to_string())
}

fn detect_image_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x00\x00\x01\x00") {
        Some("image/x-icon")
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

fn read_metadata(path: &Path) -> CacheMetadata {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_metadata(path: &Path, metadata: &CacheMetadata) -> VaultResult<()> {
    let bytes = serde_json::to_vec(metadata)
        .map_err(|_| "Sesame could not update the website icon cache.".to_string())?;
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .map_err(|_| "Sesame could not update the website icon cache.".to_string())?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|_| "Sesame could not update the website icon cache.".to_string())?;
    }
    fs::rename(temporary, path)
        .map_err(|_| "Sesame could not update the website icon cache.".to_string())
}

fn read_cached_icon(path: &Path, media_type: Option<&str>) -> Option<String> {
    let media_type = media_type?;
    if fs::metadata(path).ok()?.len() > MAX_ICON_BYTES as u64 {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    if bytes.len() > MAX_ICON_BYTES || detect_image_type(&bytes) != Some(media_type) {
        return None;
    }
    Some(data_url(media_type, &bytes))
}

fn data_url(media_type: &str, bytes: &[u8]) -> String {
    format!("data:{media_type};base64,{}", STANDARD.encode(bytes))
}

fn cache_is_fresh(metadata: &CacheMetadata, now: u64) -> bool {
    metadata
        .fetched_at
        .is_some_and(|fetched| now.saturating_sub(fetched) < SUCCESS_TTL_SECS)
}

fn failure_is_recent(metadata: &CacheMetadata, now: u64) -> bool {
    metadata
        .failed_at
        .is_some_and(|failed| now.saturating_sub(failed) < FAILURE_RETRY_SECS)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn prune_cache(cache_dir: &Path, current_metadata: &Path, current_image: &Path) {
    prune_cache_to_limits(
        cache_dir,
        current_metadata,
        current_image,
        MAX_CACHE_ENTRIES,
        MAX_CACHE_BYTES,
    );
}

fn prune_cache_to_limits(
    cache_dir: &Path,
    current_metadata: &Path,
    current_image: &Path,
    max_entries: usize,
    max_bytes: u64,
) {
    cleanup_stale_temporary_files(cache_dir);
    let Ok(items) = fs::read_dir(cache_dir) else {
        return;
    };
    let mut entries = items
        .flatten()
        .filter_map(|item| {
            let metadata_path = item.path();
            if metadata_path.extension().and_then(|value| value.to_str()) != Some("json") {
                return None;
            }
            let metadata = item.metadata().ok()?;
            let modified = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_secs())
                .unwrap_or_default();
            let image = metadata_path.with_extension("img");
            let image_size = fs::metadata(&image)
                .map(|value| value.len())
                .unwrap_or_default();
            Some((metadata_path, image, image_size, modified))
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|item| item.3);
    let mut total = entries.iter().map(|item| item.2).sum::<u64>();
    let mut count = entries.len();
    for (metadata, image, size, _) in entries {
        if count <= max_entries && total <= max_bytes {
            break;
        }
        if image == current_image || metadata == current_metadata {
            continue;
        }
        let _ = fs::remove_file(&image);
        let _ = fs::remove_file(metadata);
        total = total.saturating_sub(size);
        count = count.saturating_sub(1);
    }
}

fn cache_status_at(cache_dir: &Path) -> WebsiteIconCacheStatus {
    let Ok(items) = fs::read_dir(cache_dir) else {
        return WebsiteIconCacheStatus::default();
    };
    let mut status = WebsiteIconCacheStatus::default();
    for item in items.flatten() {
        let path = item.path();
        let extension = path.extension().and_then(|value| value.to_str());
        let size = item.metadata().map(|value| value.len()).unwrap_or_default();
        if extension == Some("json") {
            status.entry_count += 1;
            status.size_bytes = status.size_bytes.saturating_add(size);
        } else if extension == Some("img") {
            status.icon_count += 1;
            status.size_bytes = status.size_bytes.saturating_add(size);
        }
    }
    status
}

fn cleanup_stale_temporary_files(cache_dir: &Path) {
    const STALE_TEMP_SECS: u64 = 60 * 60;
    let Ok(items) = fs::read_dir(cache_dir) else {
        return;
    };
    let now = SystemTime::now();
    for item in items.flatten() {
        let path = item.path();
        if path.extension().and_then(|value| value.to_str()) != Some("tmp") {
            continue;
        }
        let stale = item
            .metadata()
            .ok()
            .and_then(|value| value.modified().ok())
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age.as_secs() >= STALE_TEMP_SECS);
        if stale {
            let _ = fs::remove_file(path);
        }
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}
