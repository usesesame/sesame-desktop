use super::ensure_crypto_provider;
use crate::desktop_settings;
use crate::vault::VaultResult;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::Rng;
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

const SUCCESS_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const FAILURE_RETRY_SECS: u64 = 6 * 60 * 60;
const MAX_ICON_BYTES: usize = 128 * 1024;
const MAX_PAGE_BYTES: usize = 256 * 1024;
const MAX_ICON_CANDIDATES: usize = 3;
const MAX_LINK_TAGS: usize = 64;
const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 500;
const CACHE_SALT_FILE: &str = "icon-cache-salt.bin";
const CACHE_SALT_BYTES: usize = 32;
const ALLOWED_ICON_MEDIA_TYPES: [&str; 7] = [
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/gif",
    "image/webp",
];

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CacheMetadata {
    fetched_at: Option<u64>,
    failed_at: Option<u64>,
    media_type: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
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

async fn run_cache_work<T: Send + 'static>(
    work: impl FnOnce() -> VaultResult<T> + Send + 'static,
) -> VaultResult<T> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|_| "Sesame could not complete the website icon request.".to_string())?
}

#[tauri::command]
pub async fn get_website_icon(app: AppHandle, site: String) -> VaultResult<Option<String>> {
    desktop_settings::require_website_icons_enabled(&desktop_settings::settings_path(&app)?)?;
    let host = normalized_host(&site)?;
    let cache_dir = cache_dir(&app)?;
    let (paths, mut metadata, now, cached) = {
        let cache_dir = cache_dir.clone();
        let host = host.clone();
        run_cache_work(move || {
            fs::create_dir_all(&cache_dir)
                .map_err(|_| "Sesame could not create the website icon cache.".to_string())?;
            let salt = cache_salt(&cache_dir)?;
            let paths = cache_paths(&cache_dir, &salt, &host);
            let metadata = read_metadata(&paths.metadata);
            let now = unix_time();
            let cached = read_cached_icon(&paths.image, metadata.media_type.as_deref());
            Ok((paths, metadata, now, cached))
        })
        .await?
    };

    if cache_is_fresh(&metadata, now) {
        if let Some(icon) = cached.clone() {
            return Ok(Some(icon));
        }
    }

    if failure_is_recent(&metadata, now) {
        return Ok(cached);
    }

    let fetched = match resolve_public_host(host).await {
        Ok(validated) => fetch_icon(&validated).await,
        Err(error) => Err(error),
    };
    match fetched {
        Ok((bytes, media_type)) => {
            run_cache_work(move || {
                write_atomic(&paths.image, &bytes)?;
                metadata.fetched_at = Some(now);
                metadata.failed_at = None;
                metadata.media_type = Some(media_type.clone());
                write_metadata(&paths.metadata, &metadata)?;
                prune_cache(&cache_dir, &paths.metadata, &paths.image);
                Ok(Some(data_url(&media_type, &bytes)))
            })
            .await
        }
        Err(_) => {
            run_cache_work(move || {
                metadata.failed_at = Some(now);
                write_metadata(&paths.metadata, &metadata)?;
                prune_cache(&cache_dir, &paths.metadata, &paths.image);
                Ok(read_cached_icon(
                    &paths.image,
                    metadata.media_type.as_deref(),
                ))
            })
            .await
        }
    }
}

#[tauri::command]
pub async fn clear_website_icon_cache(app: AppHandle) -> VaultResult<()> {
    let path = cache_dir(&app)?;
    run_cache_work(move || {
        if path.exists() {
            fs::remove_dir_all(path)
                .map_err(|_| "Sesame could not clear the website icon cache.".to_string())?;
        }
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn get_website_icon_cache_status(app: AppHandle) -> VaultResult<WebsiteIconCacheStatus> {
    let path = cache_dir(&app)?;
    run_cache_work(move || {
        cleanup_stale_temporary_files(&path);
        Ok(cache_status_at(&path))
    })
    .await
}

fn cache_dir(app: &AppHandle) -> VaultResult<PathBuf> {
    app.path()
        .app_cache_dir()
        .map(|path| path.join("website-icons-v1"))
        .map_err(|_| "Sesame could not locate its website icon cache.".to_string())
}

fn cache_paths(cache_dir: &Path, salt: &[u8; CACHE_SALT_BYTES], host: &str) -> CachePaths {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update([0_u8]);
    hasher.update(host.as_bytes());
    let key = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    CachePaths {
        metadata: cache_dir.join(format!("{key}.json")),
        image: cache_dir.join(format!("{key}.img")),
    }
}

fn cache_salt(cache_dir: &Path) -> VaultResult<[u8; CACHE_SALT_BYTES]> {
    let path = cache_dir.join(CACHE_SALT_FILE);
    if let Some(salt) = read_cache_salt(&path) {
        return Ok(salt);
    }
    let mut salt = [0_u8; CACHE_SALT_BYTES];
    rand::rng().fill_bytes(&mut salt);
    match crate::vault::storage::atomic_replace(&path, &salt) {
        Ok(()) => {
            clear_unsalted_cache_entries(cache_dir);
            Ok(salt)
        }
        Err(_) => read_cache_salt(&path)
            .ok_or_else(|| "Sesame could not prepare the website icon cache.".to_string()),
    }
}

fn read_cache_salt(path: &Path) -> Option<[u8; CACHE_SALT_BYTES]> {
    let bytes = fs::read(path).ok()?;
    bytes.as_slice().try_into().ok()
}

fn clear_unsalted_cache_entries(cache_dir: &Path) {
    let Ok(items) = fs::read_dir(cache_dir) else {
        return;
    };
    for item in items.flatten() {
        let path = item.path();
        if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("json" | "img")
        ) {
            let _ = fs::remove_file(path);
        }
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
    match fetch_site_path(validated, "/favicon.ico").await {
        Ok(response) => match read_icon(response).await {
            Ok(icon) => Ok(icon),
            Err(_) => fetch_declared_icon(validated).await,
        },
        Err(_) => fetch_declared_icon(validated).await,
    }
}

async fn fetch_site_path(validated: &ValidatedHost, path: &str) -> VaultResult<reqwest::Response> {
    let mut response = request_url(validated, &format!("https://{}{path}", validated.host)).await?;
    if response.status().is_redirection() {
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| "That website did not provide an icon.".to_string())?;
        let target = redirect_target(&validated.host, location)?;
        let hop = resolve_public_host(target).await?;
        response = request_url(&hop, &format!("https://{}{path}", hop.host)).await?;
    }
    if !response.status().is_success() {
        return Err("That website did not provide an icon.".to_string());
    }
    Ok(response)
}

async fn fetch_declared_icon(validated: &ValidatedHost) -> VaultResult<(Vec<u8>, String)> {
    let page = fetch_site_path(validated, "/").await?;
    let page_url = page.url().clone();
    let html = read_limited(page, MAX_PAGE_BYTES).await?;
    let candidates =
        declared_icon_urls(&String::from_utf8_lossy(&html), &page_url, &validated.host);
    for candidate in candidates.into_iter().take(MAX_ICON_CANDIDATES) {
        let Some(host) = candidate.host_str().map(str::to_string) else {
            continue;
        };
        let Ok(target) = resolve_public_host(host).await else {
            continue;
        };
        let Ok(response) = request_url(&target, candidate.as_str()).await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        if let Ok(icon) = read_icon(response).await {
            return Ok(icon);
        }
    }
    Err("That website did not provide an icon.".to_string())
}

async fn read_icon(mut response: reqwest::Response) -> VaultResult<(Vec<u8>, String)> {
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    accepted_icon_media_type(content_type.as_deref())?;
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
    let media_type = accepted_icon_body(content_type.as_deref(), &bytes)?;
    Ok((bytes, media_type.to_string()))
}

fn accepted_icon_media_type(content_type: Option<&str>) -> VaultResult<()> {
    let Some(value) = content_type else {
        return Ok(());
    };
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if ALLOWED_ICON_MEDIA_TYPES.contains(&media_type.as_str()) {
        Ok(())
    } else {
        Err("That website returned an unsupported icon format.".to_string())
    }
}

fn accepted_icon_body(content_type: Option<&str>, bytes: &[u8]) -> VaultResult<&'static str> {
    accepted_icon_media_type(content_type)?;
    if bytes.len() > MAX_ICON_BYTES {
        return Err("That website icon is too large.".to_string());
    }
    detect_image_type(bytes)
        .ok_or_else(|| "That website returned an unsupported icon format.".to_string())
}

async fn read_limited(mut response: reqwest::Response, limit: usize) -> VaultResult<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Sesame could not read that website.".to_string())?
    {
        let room = limit.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if bytes.len() >= limit {
            break;
        }
    }
    Ok(bytes)
}

async fn request_url(validated: &ValidatedHost, url: &str) -> VaultResult<reqwest::Response> {
    icon_client(&validated.host, &validated.addresses)?
        .get(url)
        .send()
        .await
        .map_err(|_| "Sesame could not fetch that website icon.".to_string())
}

fn declared_icon_urls(html: &str, page_url: &url::Url, site_host: &str) -> Vec<url::Url> {
    let head = match find_ascii_case_insensitive(html, "</head") {
        Some(end) => &html[..end],
        None => html,
    };
    let mut ranked: Vec<(u8, usize, url::Url)> = Vec::new();
    let mut cursor = 0;
    let mut seen = 0;
    while let Some(offset) = find_ascii_case_insensitive(&head[cursor..], "<link") {
        let start = cursor + offset;
        let Some(length) = head[start..].find('>') else {
            break;
        };
        let tag = &head[start + 5..start + length];
        cursor = start + length + 1;
        seen += 1;
        if seen > MAX_LINK_TAGS {
            break;
        }
        let attributes = tag_attributes(tag);
        let rel = attribute(&attributes, "rel")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let Some(rank) = rel
            .split_ascii_whitespace()
            .filter_map(|token| match token {
                "icon" => Some(0u8),
                "apple-touch-icon" | "apple-touch-icon-precomposed" => Some(1u8),
                _ => None,
            })
            .min()
        else {
            continue;
        };
        let media_type = attribute(&attributes, "type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let Some(href) = attribute(&attributes, "href") else {
            continue;
        };
        let href = href.trim().replace("&amp;", "&");
        if href.is_empty() || media_type.contains("svg") {
            continue;
        }
        let Ok(candidate) = page_url.join(&href) else {
            continue;
        };
        if candidate.path().to_ascii_lowercase().ends_with(".svg")
            || !allowed_icon_url(&candidate, site_host)
        {
            continue;
        }
        let size = attribute(&attributes, "sizes")
            .and_then(|sizes| {
                sizes
                    .split(['x', 'X'])
                    .next()
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let distance = if size == 0 { 1_000 } else { size.abs_diff(64) };
        if !ranked.iter().any(|(_, _, existing)| existing == &candidate) {
            ranked.push((rank, distance, candidate));
        }
    }
    ranked.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    ranked
        .into_iter()
        .map(|(_, _, candidate)| candidate)
        .collect()
}

fn allowed_icon_url(candidate: &url::Url, site_host: &str) -> bool {
    if candidate.scheme() != "https"
        || candidate.port().is_some_and(|port| port != 443)
        || !candidate.username().is_empty()
        || candidate.password().is_some()
    {
        return false;
    }
    let Some(host) = candidate.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
        return false;
    }
    let site = site_host.to_ascii_lowercase();
    let base = site.strip_prefix("www.").unwrap_or(&site);
    host == base || host.ends_with(&format!(".{base}"))
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn tag_attributes(tag: &str) -> Vec<(String, String)> {
    let bytes = tag.as_bytes();
    let mut attributes = Vec::new();
    let mut index = 0;
    while index < bytes.len() && attributes.len() < 32 {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b'/') {
            index += 1;
        }
        let name_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && bytes[index] != b'='
            && bytes[index] != b'/'
        {
            index += 1;
        }
        if name_start == index {
            index += 1;
            continue;
        }
        let name = tag[name_start..index].to_ascii_lowercase();
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let mut value = String::new();
        if index < bytes.len() && bytes[index] == b'=' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index < bytes.len() && (bytes[index] == b'"' || bytes[index] == b'\'') {
                let quote = bytes[index];
                index += 1;
                let value_start = index;
                while index < bytes.len() && bytes[index] != quote {
                    index += 1;
                }
                value = tag[value_start..index].to_string();
                index += 1;
            } else {
                let value_start = index;
                while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                    index += 1;
                }
                value = tag[value_start..index].to_string();
            }
        }
        attributes.push((name, value));
    }
    attributes
}

fn attribute(attributes: &[(String, String)], name: &str) -> Option<String> {
    attributes
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
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
        .https_only(true)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn page(url: &str) -> url::Url {
        url::Url::parse(url).unwrap()
    }

    fn declared(html: &str) -> Vec<String> {
        declared_icon_urls(html, &page("https://www.example.test/"), "example.test")
            .into_iter()
            .map(|candidate| candidate.to_string())
            .collect()
    }

    #[test]
    fn a_relative_icon_resolves_against_the_page() {
        assert_eq!(
            declared(
                r#"<head><link rel="icon" type="image/x-icon" href="/res/favicon.ico?v1" /></head>"#
            ),
            ["https://www.example.test/res/favicon.ico?v1"]
        );
    }

    #[test]
    fn a_subdomain_of_the_saved_site_is_allowed() {
        assert_eq!(
            declared(
                r#"<link rel="shortcut icon" href="https://cdn-resources.example.test/static/favicon.ico">"#
            ),
            ["https://cdn-resources.example.test/static/favicon.ico"]
        );
        assert_eq!(
            declared(r#"<link rel="icon" href="//static.example.test/icon.png">"#),
            ["https://static.example.test/icon.png"]
        );
    }

    #[test]
    fn a_foreign_or_lookalike_host_is_refused() {
        assert!(declared(r#"<link rel="icon" href="https://evil.test/favicon.ico">"#).is_empty());
        assert!(
            declared(r#"<link rel="icon" href="https://evilexample.test/favicon.ico">"#).is_empty()
        );
        assert!(
            declared(r#"<link rel="icon" href="https://example.test.evil.test/favicon.ico">"#)
                .is_empty()
        );
        assert!(
            declared(r#"<link rel="icon" href="https://93.184.216.34/favicon.ico">"#).is_empty()
        );
    }

    #[test]
    fn insecure_schemes_ports_and_credentials_are_refused() {
        for href in [
            "http://www.example.test/favicon.ico",
            "javascript:alert(1)",
            "data:image/png;base64,AAAA",
            "file:///etc/passwd",
            "https://www.example.test:8443/favicon.ico",
            "https://user:secret@www.example.test/favicon.ico",
        ] {
            assert!(
                declared(&format!(r#"<link rel="icon" href="{href}">"#)).is_empty(),
                "{href}"
            );
        }
    }

    #[test]
    fn vector_icons_and_unrelated_links_are_skipped() {
        assert!(declared(r#"<link rel="icon" type="image/svg+xml" href="/icon.svg">"#).is_empty());
        assert!(declared(r#"<link rel="icon" href="/logo.SVG">"#).is_empty());
        assert!(declared(
            r#"<link rel="mask-icon" href="/mask.png"><link rel="stylesheet" href="/site.css">"#
        )
        .is_empty());
    }

    #[test]
    fn icons_are_ranked_by_kind_then_size() {
        let html = r#"
            <LINK REL="apple-touch-icon" HREF="/apple.png">
            <link rel='icon' sizes='16x16' href='/16.png'>
            <link rel=icon sizes=64x64 href=/64.png>
            <link rel="icon" sizes="32x32" href="/32.png">
        "#;
        assert_eq!(
            declared(html),
            [
                "https://www.example.test/64.png",
                "https://www.example.test/32.png",
                "https://www.example.test/16.png",
                "https://www.example.test/apple.png",
            ]
        );
    }

    #[test]
    fn links_after_the_head_and_duplicates_are_ignored() {
        let html = r#"<link rel="icon" href="/a.ico"><link rel="icon" href="/a.ico"></head><link rel="icon" href="/body.ico">"#;
        assert_eq!(declared(html), ["https://www.example.test/a.ico"]);
    }

    #[test]
    fn entities_in_the_address_are_decoded() {
        assert_eq!(
            declared(r#"<link rel="icon" href="/favicon.ico?a=1&amp;b=2">"#),
            ["https://www.example.test/favicon.ico?a=1&b=2"]
        );
    }

    #[test]
    fn malformed_markup_never_panics() {
        for html in [
            "<link",
            "<link rel=\"icon\" href=\"/unterminated",
            "<link rel=\"icon\" href=\"/a.ico\"",
            "<link ==== rel icon href>",
            "<link rel=\"icon\" href=\"\u{00e9}\u{1f600}/icon.png\">",
            "\u{1f600}<LiNk rel=icon href=/x.ico>",
            "",
        ] {
            let _ = declared(html);
        }
    }

    #[test]
    fn the_number_of_link_tags_read_is_bounded() {
        let mut html = String::new();
        for index in 0..(MAX_LINK_TAGS + 10) {
            html.push_str(&format!("<link rel=\"stylesheet\" href=\"/{index}.css\">"));
        }
        html.push_str(r#"<link rel="icon" href="/late.ico">"#);
        assert!(declared(&html).is_empty());
    }

    #[test]
    fn a_www_saved_site_accepts_the_bare_domain_and_its_subdomains() {
        let page_url = page("https://www.example.test/");
        let found = declared_icon_urls(
            r#"<link rel="icon" href="https://example.test/i.ico">"#,
            &page_url,
            "www.example.test",
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn redirects_follow_only_the_bare_and_www_forms() {
        assert_eq!(
            redirect_target("example.test", "https://www.example.test/favicon.ico").unwrap(),
            "www.example.test"
        );
        assert!(redirect_target("example.test", "https://cdn.evil.test/favicon.ico").is_err());
        assert!(redirect_target("example.test", "http://www.example.test/favicon.ico").is_err());
    }

    #[test]
    fn private_and_reserved_addresses_are_not_public() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        assert!(is_public_ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn saved_sites_that_cannot_be_fetched_are_refused() {
        for site in [
            "",
            "localhost",
            "printer.local",
            "192.168.1.1",
            "intranet",
            "-bad.example.test",
        ] {
            assert!(normalized_host(site).is_err(), "{site}");
        }
        assert_eq!(normalized_host(" Example.TEST. ").unwrap(), "example.test");
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sesame-website-icons-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("test directory");
        dir
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    const _: () = assert!(MAX_ICON_BYTES <= 512 * 1024);

    #[test]
    fn icon_fetch_is_refused_when_the_opt_in_is_off() {
        let settings = test_dir("opt-in").join("desktop-settings.json");
        assert!(desktop_settings::require_website_icons_enabled(&settings).is_err());
        desktop_settings::write_settings_at(
            &settings,
            &desktop_settings::DesktopSettings {
                website_icons_enabled: true,
            },
        )
        .expect("enable setting");
        assert!(desktop_settings::require_website_icons_enabled(&settings).is_ok());
        desktop_settings::write_settings_at(
            &settings,
            &desktop_settings::DesktopSettings {
                website_icons_enabled: false,
            },
        )
        .expect("disable setting");
        assert!(desktop_settings::require_website_icons_enabled(&settings).is_err());
        let _ = fs::remove_dir_all(settings.parent().expect("settings parent"));
    }

    #[test]
    fn a_non_image_body_is_refused() {
        assert!(accepted_icon_body(Some("text/html"), b"<!doctype html>").is_err());
        assert!(accepted_icon_body(Some("application/json"), b"{}").is_err());
        assert!(accepted_icon_body(Some("application/octet-stream"), b"\x00\x00\x01\x00").is_err());
        assert!(accepted_icon_body(None, b"fictional not an icon").is_err());
        assert_eq!(
            accepted_icon_body(Some("image/png; charset=binary"), b"\x89PNG\r\n\x1a\n")
                .expect("png accepted"),
            "image/png"
        );
        assert_eq!(
            accepted_icon_body(Some("image/x-icon"), b"\x00\x00\x01\x00").expect("icon accepted"),
            "image/x-icon"
        );
    }

    #[test]
    fn an_oversized_body_is_refused() {
        let mut png = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        png.resize(MAX_ICON_BYTES + 1, 0);
        assert!(accepted_icon_body(Some("image/png"), &png).is_err());
        assert_eq!(
            accepted_icon_body(Some("image/png"), &png[..MAX_ICON_BYTES])
                .expect("boundary accepted"),
            "image/png"
        );
    }

    #[test]
    fn the_cache_name_is_salted_and_stable_for_this_device() {
        let dir = test_dir("salt");
        let salt = cache_salt(&dir).expect("cache salt");
        assert_eq!(salt, cache_salt(&dir).expect("persisted salt"));
        let paths = cache_paths(&dir, &salt, "example.test");
        assert_eq!(paths, cache_paths(&dir, &salt, "example.test"));

        let plain = hex(&Sha256::digest(b"example.test"));
        assert_ne!(
            paths.metadata.file_stem().and_then(|value| value.to_str()),
            Some(plain.as_str())
        );
        assert_ne!(
            paths.image.file_stem().and_then(|value| value.to_str()),
            Some(plain.as_str())
        );

        let mut other = salt;
        other[0] ^= 0xff;
        assert_ne!(cache_paths(&dir, &other, "example.test"), paths);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(CACHE_SALT_FILE))
                .expect("salt metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn creating_the_salt_removes_unsalted_entries() {
        let dir = test_dir("legacy");
        let legacy = hex(&Sha256::digest(b"legacy.test"));
        let legacy_metadata = dir.join(format!("{legacy}.json"));
        let legacy_image = dir.join(format!("{legacy}.img"));
        fs::write(&legacy_metadata, b"{}").expect("legacy metadata");
        fs::write(&legacy_image, b"png").expect("legacy image");
        let _ = cache_salt(&dir).expect("cache salt");
        assert!(!legacy_metadata.exists());
        assert!(!legacy_image.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_eviction_ignores_the_salt_file() {
        let dir = test_dir("eviction");
        let salt = cache_salt(&dir).expect("cache salt");
        let first = cache_paths(&dir, &salt, "first.example.test");
        fs::write(&first.metadata, b"{}").expect("first metadata");
        fs::write(&first.image, b"png").expect("first image");
        std::thread::sleep(Duration::from_millis(20));
        let second = cache_paths(&dir, &salt, "second.example.test");
        fs::write(&second.metadata, b"{}").expect("second metadata");
        fs::write(&second.image, b"png").expect("second image");

        prune_cache_to_limits(&dir, &second.metadata, &second.image, 1, u64::MAX);

        assert!(dir.join(CACHE_SALT_FILE).exists());
        let remaining = fs::read_dir(&dir)
            .expect("cache directory")
            .flatten()
            .filter(|item| item.path().extension().and_then(|value| value.to_str()) == Some("json"))
            .count();
        assert_eq!(remaining, 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
