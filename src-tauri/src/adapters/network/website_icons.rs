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
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};

const SUCCESS_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const FAILURE_RETRY_SECS: u64 = 6 * 60 * 60;
const MAX_ICON_BYTES: usize = 128 * 1024;
const MAX_CACHED_ICON_BYTES: usize = 512 * 1024;
const MAX_ICON_DIMENSION: u32 = 256;
const PNG_DECODE_MEMORY_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAGE_BYTES: usize = 256 * 1024;
const MAX_ICON_CANDIDATES: usize = 3;
const MAX_LINK_TAGS: usize = 64;
const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 500;
const CACHE_SALT_FILE: &str = "icon-cache-salt.bin";
const CACHE_SALT_BYTES: usize = 32;
const PNG_MEDIA_TYPE: &str = "image/png";
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
const ICO_SIGNATURE: [u8; 4] = [0x00, 0x00, 0x01, 0x00];
const ICO_DIRECTORY_BYTES: usize = 6;
const ICO_ENTRY_BYTES: usize = 16;
const BMP_HEADER_BYTES: usize = 40;
const ALLOWED_ICON_MEDIA_TYPES: [&str; 3] =
    ["image/x-icon", "image/vnd.microsoft.icon", "image/png"];

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
            let cached = read_cached_icon(&paths.image);
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
        Ok(bytes) => {
            run_cache_work(move || {
                write_atomic(&paths.image, &bytes)?;
                metadata.fetched_at = Some(now);
                metadata.failed_at = None;
                metadata.media_type = Some(PNG_MEDIA_TYPE.to_string());
                write_metadata(&paths.metadata, &metadata)?;
                prune_cache(&cache_dir, &paths.metadata, &paths.image);
                Ok(Some(png_data_url(&bytes)))
            })
            .await
        }
        Err(_) => {
            run_cache_work(move || {
                metadata.failed_at = Some(now);
                write_metadata(&paths.metadata, &metadata)?;
                prune_cache(&cache_dir, &paths.metadata, &paths.image);
                Ok(read_cached_icon(&paths.image))
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
async fn fetch_icon(validated: &ValidatedHost) -> VaultResult<Vec<u8>> {
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

async fn fetch_declared_icon(validated: &ValidatedHost) -> VaultResult<Vec<u8>> {
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

async fn read_icon(mut response: reqwest::Response) -> VaultResult<Vec<u8>> {
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
    accepted_icon_body(content_type.as_deref(), &bytes)?;
    reencode_icon(&bytes)
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
        .no_proxy()
        .build()
        .map_err(|_| "Sesame could not prepare the website icon request.".to_string())
}

fn detect_image_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&ICO_SIGNATURE) {
        Some("image/x-icon")
    } else if bytes.starts_with(&PNG_SIGNATURE) {
        Some("image/png")
    } else {
        None
    }
}

struct DecodedIcon {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

struct IcoCandidate {
    width: u32,
    height: u32,
    offset: usize,
    size: usize,
}

fn icon_format_error() -> String {
    "That website returned an unsupported icon format.".to_string()
}

fn icon_size_error() -> String {
    "That website icon is too large.".to_string()
}

fn read_be_u32(bytes: &[u8]) -> Option<u32> {
    bytes
        .first_chunk::<4>()
        .map(|value| u32::from_be_bytes(*value))
}

fn read_le_u16(bytes: &[u8]) -> Option<u16> {
    bytes
        .first_chunk::<2>()
        .map(|value| u16::from_le_bytes(*value))
}

fn read_le_u32(bytes: &[u8]) -> Option<u32> {
    bytes
        .first_chunk::<4>()
        .map(|value| u32::from_le_bytes(*value))
}

fn read_le_i32(bytes: &[u8]) -> Option<i32> {
    bytes
        .first_chunk::<4>()
        .map(|value| i32::from_le_bytes(*value))
}

fn reencode_icon(bytes: &[u8]) -> VaultResult<Vec<u8>> {
    if bytes.len() > MAX_ICON_BYTES {
        return Err(icon_size_error());
    }
    if bytes.starts_with(&PNG_SIGNATURE) {
        encode_icon_png(decode_png(bytes)?)
    } else if bytes.starts_with(&ICO_SIGNATURE) {
        encode_icon_png(decode_ico(bytes)?)
    } else {
        Err(icon_format_error())
    }
}

fn png_dimensions(bytes: &[u8]) -> VaultResult<(u32, u32)> {
    if bytes.len() < 24 || !bytes.starts_with(&PNG_SIGNATURE) || &bytes[12..16] != b"IHDR" {
        return Err(icon_format_error());
    }
    if read_be_u32(&bytes[8..]).ok_or_else(icon_format_error)? != 13 {
        return Err(icon_format_error());
    }
    let width = read_be_u32(&bytes[16..]).ok_or_else(icon_format_error)?;
    let height = read_be_u32(&bytes[20..]).ok_or_else(icon_format_error)?;
    if width == 0 || height == 0 {
        return Err(icon_format_error());
    }
    if width > MAX_ICON_DIMENSION || height > MAX_ICON_DIMENSION {
        return Err(icon_size_error());
    }
    Ok((width, height))
}

fn decode_png(bytes: &[u8]) -> VaultResult<DecodedIcon> {
    let (width, height) = png_dimensions(bytes)?;
    let mut decoder = png::Decoder::new_with_limits(
        Cursor::new(bytes),
        png::Limits {
            bytes: PNG_DECODE_MEMORY_BYTES,
        },
    );
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(|_| icon_format_error())?;
    let mut buffer = vec![0; reader.output_buffer_size().ok_or_else(icon_size_error)?];
    let frame = reader
        .next_frame(&mut buffer)
        .map_err(|_| icon_format_error())?;
    if frame.width != width || frame.height != height || frame.bit_depth != png::BitDepth::Eight {
        return Err(icon_format_error());
    }
    buffer.truncate(frame.buffer_size());
    Ok(DecodedIcon {
        width,
        height,
        rgba: rgba_pixels(&buffer, frame.color_type)?,
    })
}

fn rgba_pixels(pixels: &[u8], color_type: png::ColorType) -> VaultResult<Vec<u8>> {
    let mut rgba = Vec::new();
    match color_type {
        png::ColorType::Grayscale => {
            for value in pixels {
                rgba.extend_from_slice(&[*value, *value, *value, 0xff]);
            }
        }
        png::ColorType::GrayscaleAlpha => {
            if !pixels.len().is_multiple_of(2) {
                return Err(icon_format_error());
            }
            for pixel in pixels.as_chunks::<2>().0 {
                rgba.extend_from_slice(&[pixel[0], pixel[0], pixel[0], pixel[1]]);
            }
        }
        png::ColorType::Rgb => {
            if !pixels.len().is_multiple_of(3) {
                return Err(icon_format_error());
            }
            for pixel in pixels.as_chunks::<3>().0 {
                rgba.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 0xff]);
            }
        }
        png::ColorType::Rgba => rgba.extend_from_slice(pixels),
        png::ColorType::Indexed => return Err(icon_format_error()),
    }
    Ok(rgba)
}

fn encode_icon_png(icon: DecodedIcon) -> VaultResult<Vec<u8>> {
    if icon.width == 0
        || icon.height == 0
        || icon.width > MAX_ICON_DIMENSION
        || icon.height > MAX_ICON_DIMENSION
    {
        return Err(icon_size_error());
    }
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, icon.width, icon.height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|_| icon_format_error())?;
        writer
            .write_image_data(&icon.rgba)
            .map_err(|_| icon_format_error())?;
        writer.finish().map_err(|_| icon_format_error())?;
    }
    Ok(bytes)
}

fn ico_image_size(data: &[u8]) -> Option<(u32, u32)> {
    if data.starts_with(&PNG_SIGNATURE) {
        return png_dimensions(data).ok();
    }
    if data.len() < 12 || read_le_u32(data)? != BMP_HEADER_BYTES as u32 {
        return None;
    }
    let width = read_le_i32(&data[4..])?;
    let height = read_le_i32(&data[8..])?;
    if width <= 0 || height <= 0 || height % 2 != 0 {
        return None;
    }
    Some((u32::try_from(width).ok()?, u32::try_from(height / 2).ok()?))
}

fn largest_ico_entry(bytes: &[u8]) -> VaultResult<IcoCandidate> {
    if bytes.len() < ICO_DIRECTORY_BYTES || !bytes.starts_with(&ICO_SIGNATURE) {
        return Err(icon_format_error());
    }
    let count = read_le_u16(&bytes[4..]).ok_or_else(icon_format_error)? as usize;
    let directory_end = ICO_DIRECTORY_BYTES
        + count
            .checked_mul(ICO_ENTRY_BYTES)
            .ok_or_else(icon_format_error)?;
    if count == 0 || directory_end > bytes.len() {
        return Err(icon_format_error());
    }
    let mut best: Option<IcoCandidate> = None;
    for index in 0..count {
        let start = ICO_DIRECTORY_BYTES + index * ICO_ENTRY_BYTES;
        let entry = &bytes[start..start + ICO_ENTRY_BYTES];
        if entry[3] != 0 {
            continue;
        }
        let size = read_le_u32(&entry[8..]).ok_or_else(icon_format_error)? as usize;
        let offset = read_le_u32(&entry[12..]).ok_or_else(icon_format_error)? as usize;
        let Some(end) = offset.checked_add(size) else {
            continue;
        };
        if size == 0 || end > bytes.len() {
            continue;
        }
        let Some((width, height)) = ico_image_size(&bytes[offset..end]) else {
            continue;
        };
        if width > MAX_ICON_DIMENSION || height > MAX_ICON_DIMENSION {
            continue;
        }
        let area = u64::from(width) * u64::from(height);
        let replaces = best
            .as_ref()
            .is_none_or(|current| area > u64::from(current.width) * u64::from(current.height));
        if replaces {
            best = Some(IcoCandidate {
                width,
                height,
                offset,
                size,
            });
        }
    }
    best.ok_or_else(icon_format_error)
}

fn decode_ico(bytes: &[u8]) -> VaultResult<DecodedIcon> {
    let entry = largest_ico_entry(bytes)?;
    let data = bytes
        .get(entry.offset..entry.offset + entry.size)
        .ok_or_else(icon_format_error)?;
    if data.starts_with(&PNG_SIGNATURE) {
        decode_png(data)
    } else {
        decode_ico_bmp(entry.width, entry.height, data)
    }
}

fn decode_ico_bmp(width: u32, height: u32, data: &[u8]) -> VaultResult<DecodedIcon> {
    let mut bytes = Vec::with_capacity(ICO_DIRECTORY_BYTES + ICO_ENTRY_BYTES + data.len());
    bytes.extend_from_slice(&ICO_SIGNATURE);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.push(if width == MAX_ICON_DIMENSION {
        0
    } else {
        width as u8
    });
    bytes.push(if height == MAX_ICON_DIMENSION {
        0
    } else {
        height as u8
    });
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&32_u16.to_le_bytes());
    bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&((ICO_DIRECTORY_BYTES + ICO_ENTRY_BYTES) as u32).to_le_bytes());
    bytes.extend_from_slice(data);
    let directory = ico::IconDir::read(Cursor::new(bytes)).map_err(|_| icon_format_error())?;
    let image = directory
        .entries()
        .first()
        .ok_or_else(icon_format_error)?
        .decode()
        .map_err(|_| icon_format_error())?;
    Ok(DecodedIcon {
        width: image.width(),
        height: image.height(),
        rgba: image.rgba_data().to_vec(),
    })
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

fn read_cached_icon(path: &Path) -> Option<String> {
    if fs::metadata(path).ok()?.len() > MAX_CACHED_ICON_BYTES as u64 {
        let _ = fs::remove_file(path);
        return None;
    }
    let bytes = fs::read(path).ok()?;
    if bytes.len() > MAX_CACHED_ICON_BYTES {
        let _ = fs::remove_file(path);
        return None;
    }
    let Ok(icon) = decode_png(&bytes) else {
        let _ = fs::remove_file(path);
        return None;
    };
    let Ok(png) = encode_icon_png(icon) else {
        let _ = fs::remove_file(path);
        return None;
    };
    if png != bytes && write_atomic(path, &png).is_err() {
        let _ = fs::remove_file(path);
    }
    Some(png_data_url(&png))
}

fn png_data_url(bytes: &[u8]) -> String {
    format!("data:{PNG_MEDIA_TYPE};base64,{}", STANDARD.encode(bytes))
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
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || (a == 192 && b == 0 && c == 0)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240)
}

fn ipv4_from_segments(high: u16, low: u16) -> Ipv4Addr {
    Ipv4Addr::from((u32::from(high) << 16) | u32::from(low))
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    if segments[0] == 0x0064 && segments[1] == 0xff9b {
        if segments[2] == 0 && segments[3..6].iter().all(|segment| *segment == 0) {
            return is_public_ipv4(ipv4_from_segments(segments[6], segments[7]));
        }
        if segments[2] == 0x0001 && segments[5..8].iter().all(|segment| *segment == 0) {
            return is_public_ipv4(ipv4_from_segments(segments[3], segments[4]));
        }
        return false;
    }
    if segments[0] == 0x2002 {
        return is_public_ipv4(ipv4_from_segments(segments[1], segments[2]));
    }
    if segments[0] == 0x2001 && segments[1] == 0 {
        return false;
    }
    if segments[..6].iter().all(|segment| *segment == 0) {
        return is_public_ipv4(ipv4_from_segments(segments[6], segments[7]));
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0))
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::ReleasePresence;
    use crate::vault::VaultState;

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
            "192.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "::ffff:10.0.0.1",
            "::a00:1",
            "64:ff9b::a00:1",
            "64:ff9b::c0a8:101",
            "64:ff9b:1::c0a8:101",
            "64:ff9b:1:c0a8:101::",
            "64:ff9b:2::1",
            "2002:c0a8:101::1",
            "2001::1",
            "100::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        assert!(is_public_ip("93.184.216.34".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(is_public_ip("64:ff9b::101:101".parse().unwrap()));
        assert!(is_public_ip("64:ff9b::808:808".parse().unwrap()));
        assert!(is_public_ip("64:ff9b:1:808:808::".parse().unwrap()));
        assert!(is_public_ip("2002:5db8:d822::1".parse().unwrap()));
    }

    #[test]
    fn a_nat64_48_prefix_judges_the_embedded_ipv4_in_the_right_segments() {
        assert!(!is_public_ip("64:ff9b:1:c0a8:101::".parse().unwrap()));
        assert!(!is_public_ip("64:ff9b:1:a00:1::".parse().unwrap()));
        assert!(is_public_ip("64:ff9b:1:808:808::".parse().unwrap()));
        assert!(!is_public_ip("64:ff9b:1::c0a8:101".parse().unwrap()));
        assert!(!is_public_ip("64:ff9b:1:808:808:1::".parse().unwrap()));
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

    fn png_fixture(width: u32, height: u32, srgb: bool) -> Vec<u8> {
        let pixels = (0..(width as usize * height as usize))
            .flat_map(|index| [index as u8, 0x40, 0x80, 0xff])
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        if srgb {
            encoder.set_source_srgb(png::SrgbRenderingIntent::Perceptual);
        }
        let mut writer = encoder.write_header().expect("png header");
        writer.write_image_data(&pixels).expect("png data");
        writer.finish().expect("png finish");
        bytes
    }

    fn grayscale_png_fixture(width: u32, height: u32) -> Vec<u8> {
        let pixels = (0..(width as usize * height as usize))
            .map(|index| index as u8)
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, width, height);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().expect("png header");
        writer.write_image_data(&pixels).expect("png data");
        writer.finish().expect("png finish");
        bytes
    }

    fn bmp_fixture(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(BMP_HEADER_BYTES as u32).to_le_bytes());
        bytes.extend_from_slice(&(width as i32).to_le_bytes());
        bytes.extend_from_slice(&((height as i32) * 2).to_le_bytes());
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&32_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&(width * height * 4).to_le_bytes());
        bytes.extend_from_slice(&[0; 16]);
        for _ in 0..(width * height) {
            bytes.extend_from_slice(&[0x20, 0x60, 0xa0, 0xff]);
        }
        bytes
    }

    fn ico_fixture(entries: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ICO_SIGNATURE);
        bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        let mut offset = (ICO_DIRECTORY_BYTES + ICO_ENTRY_BYTES * entries.len()) as u32;
        for (width, height, data) in entries {
            bytes.push(if *width == MAX_ICON_DIMENSION {
                0
            } else {
                *width as u8
            });
            bytes.push(if *height == MAX_ICON_DIMENSION {
                0
            } else {
                *height as u8
            });
            bytes.extend_from_slice(&[0, 0]);
            bytes.extend_from_slice(&1_u16.to_le_bytes());
            bytes.extend_from_slice(&32_u16.to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&offset.to_le_bytes());
            offset += data.len() as u32;
        }
        for (_, _, data) in entries {
            bytes.extend_from_slice(data);
        }
        bytes
    }

    fn png_header_fixture(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&13_u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes.extend_from_slice(&[0; 4]);
        bytes
    }

    fn png_metadata(bytes: &[u8]) -> (u32, u32, png::ColorType, png::BitDepth) {
        let mut decoder = png::Decoder::new(Cursor::new(bytes));
        let info = decoder.read_header_info().expect("png header info");
        (info.width, info.height, info.color_type, info.bit_depth)
    }

    fn png_chunk_types(bytes: &[u8]) -> Vec<[u8; 4]> {
        let mut types = Vec::new();
        let mut offset = 8;
        while let Some(length) = bytes.get(offset..offset + 4) {
            let length = u32::from_be_bytes(length.try_into().expect("chunk length")) as usize;
            let kind: [u8; 4] = bytes
                .get(offset + 4..offset + 8)
                .expect("chunk kind")
                .try_into()
                .expect("chunk kind");
            types.push(kind);
            offset += 12 + length;
            if &kind == b"IEND" {
                break;
            }
        }
        types
    }

    fn assert_reencoded_png(source: &[u8], width: u32, height: u32) {
        let output = reencode_icon(source).expect("icon reencoded");
        assert!(output.starts_with(&PNG_SIGNATURE));
        let decoded = decode_png(&output).expect("output decodes");
        assert_eq!((decoded.width, decoded.height), (width, height));
        let (output_width, output_height, color_type, bit_depth) = png_metadata(&output);
        assert_eq!((output_width, output_height), (width, height));
        assert_eq!(color_type, png::ColorType::Rgba);
        assert_eq!(bit_depth, png::BitDepth::Eight);
        assert!(png_chunk_types(&output)
            .iter()
            .all(|kind| matches!(kind, b"IHDR" | b"IDAT" | b"IEND")));
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
                ..desktop_settings::DesktopSettings::default()
            },
        )
        .expect("enable setting");
        assert!(desktop_settings::require_website_icons_enabled(&settings).is_ok());
        desktop_settings::write_settings_at(
            &settings,
            &desktop_settings::DesktopSettings {
                website_icons_enabled: false,
                ..desktop_settings::DesktopSettings::default()
            },
        )
        .expect("disable setting");
        assert!(desktop_settings::require_website_icons_enabled(&settings).is_err());
        let _ = fs::remove_dir_all(settings.parent().expect("settings parent"));
    }

    #[test]
    fn the_icon_opt_in_requires_presence_only_to_enable() {
        let settings = test_dir("opt-in-presence").join("desktop-settings.json");
        let state = VaultState::default();
        let presence = ReleasePresence::default();
        assert!(
            desktop_settings::set_website_icons_enabled_at(&settings, true, &state, &presence)
                .is_err()
        );
        assert!(desktop_settings::require_website_icons_enabled(&settings).is_err());
        desktop_settings::write_settings_at(
            &settings,
            &desktop_settings::DesktopSettings {
                website_icons_enabled: true,
                ..desktop_settings::DesktopSettings::default()
            },
        )
        .expect("enable setting");
        assert!(desktop_settings::set_website_icons_enabled_at(
            &settings, false, &state, &presence
        )
        .is_ok());
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
    fn webp_and_gif_icons_are_refused_by_type_and_by_content() {
        let webp = b"RIFF\x24\x00\x00\x00WEBPVP8 ";
        let gif = b"GIF89a\x01\x00\x01\x00";
        for media_type in ["image/webp", "image/gif"] {
            assert!(
                accepted_icon_media_type(Some(media_type)).is_err(),
                "{media_type}"
            );
        }
        assert!(accepted_icon_body(Some("image/png"), webp).is_err());
        assert!(accepted_icon_body(Some("image/png"), gif).is_err());
        assert!(accepted_icon_body(None, webp).is_err());
        assert!(accepted_icon_body(None, gif).is_err());
        assert_eq!(detect_image_type(webp), None);
        assert_eq!(detect_image_type(gif), None);
    }

    #[test]
    fn ico_and_png_media_types_are_accepted() {
        for (media_type, bytes, detected) in [
            ("image/x-icon", &b"\x00\x00\x01\x00"[..], "image/x-icon"),
            (
                "image/vnd.microsoft.icon",
                &b"\x00\x00\x01\x00"[..],
                "image/x-icon",
            ),
            ("image/png", &b"\x89PNG\r\n\x1a\n"[..], "image/png"),
        ] {
            assert_eq!(
                accepted_icon_body(Some(media_type), bytes).expect(media_type),
                detected
            );
        }
    }

    #[test]
    fn jpeg_icons_are_refused_by_type_and_by_content() {
        let jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00";
        for media_type in ["image/jpeg", "image/jpg"] {
            assert!(
                accepted_icon_media_type(Some(media_type)).is_err(),
                "{media_type}"
            );
            assert!(
                accepted_icon_body(Some(media_type), jpeg).is_err(),
                "{media_type}"
            );
        }
        assert!(accepted_icon_body(None, jpeg).is_err());
        assert_eq!(detect_image_type(jpeg), None);
        assert!(reencode_icon(jpeg).is_err());
    }

    #[test]
    fn a_png_icon_is_reencoded_as_rgba_png() {
        assert_reencoded_png(&png_fixture(32, 24, false), 32, 24);
    }

    #[test]
    fn a_grayscale_png_is_reencoded_as_rgba_png() {
        assert_reencoded_png(&grayscale_png_fixture(20, 12), 20, 12);
    }

    #[test]
    fn an_ico_holding_a_bmp_is_reencoded_from_the_largest_entry() {
        let source = ico_fixture(&[
            (16, 16, bmp_fixture(16, 16)),
            (64, 64, bmp_fixture(64, 64)),
            (32, 32, bmp_fixture(32, 32)),
        ]);
        assert_reencoded_png(&source, 64, 64);
    }

    #[test]
    fn an_ico_holding_a_png_is_reencoded() {
        let source = ico_fixture(&[(48, 40, png_fixture(48, 40, false))]);
        assert_reencoded_png(&source, 48, 40);
    }

    #[test]
    fn an_ico_entry_larger_than_the_limit_is_skipped() {
        let source = ico_fixture(&[
            (16, 16, bmp_fixture(16, 16)),
            (256, 256, png_fixture(512, 512, false)),
        ]);
        assert_reencoded_png(&source, 16, 16);
    }

    #[test]
    fn an_ico_entry_at_the_size_limit_is_accepted() {
        let source = ico_fixture(&[(256, 256, png_fixture(256, 256, false))]);
        assert_reencoded_png(&source, 256, 256);
    }

    #[test]
    fn a_truncated_png_is_refused() {
        let mut source = png_fixture(16, 16, false);
        source.truncate(source.len() / 2);
        assert!(reencode_icon(&source).is_err());
    }

    #[test]
    fn a_png_header_that_declares_huge_dimensions_is_refused() {
        assert!(reencode_icon(&png_header_fixture(4096, 4096)).is_err());
        assert!(reencode_icon(&png_header_fixture(256, 257)).is_err());
    }

    #[test]
    fn png_magic_without_png_content_is_refused() {
        let mut source = PNG_SIGNATURE.to_vec();
        source.extend_from_slice(b"fictional bytes that are not a png");
        assert!(reencode_icon(&source).is_err());
    }

    #[test]
    fn an_ico_without_a_usable_entry_is_refused() {
        assert!(reencode_icon(&ico_fixture(&[])).is_err());
        assert!(reencode_icon(&ico_fixture(&[(16, 16, b"fictional bytes".to_vec())])).is_err());
        assert!(reencode_icon(&[
            0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ])
        .is_err());
    }

    #[test]
    fn an_old_raw_cache_entry_is_deleted_instead_of_served() {
        let dir = test_dir("old-cache");
        let ico_path = dir.join("ico.img");
        let jpeg_path = dir.join("jpeg.img");
        fs::write(&ico_path, ico_fixture(&[(32, 32, bmp_fixture(32, 32))])).expect("old ico");
        fs::write(&jpeg_path, b"\xff\xd8\xff\xe0\x00\x10JFIF\x00").expect("old jpeg");
        assert!(read_cached_icon(&ico_path).is_none());
        assert!(read_cached_icon(&jpeg_path).is_none());
        assert!(!ico_path.exists());
        assert!(!jpeg_path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cached_png_is_reencoded_before_it_is_served() {
        let dir = test_dir("cached-png");
        let path = dir.join("entry.img");
        fs::write(&path, png_fixture(16, 16, true)).expect("cached png");
        let url = read_cached_icon(&path).expect("cached png served");
        assert!(url.starts_with("data:image/png;base64,"));
        let stored = fs::read(&path).expect("stored png");
        let (stored_width, stored_height, _, _) = png_metadata(&stored);
        assert_eq!((stored_width, stored_height), (16, 16));
        assert!(!png_chunk_types(&stored).contains(b"sRGB"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cached_png_with_huge_dimensions_is_deleted() {
        let dir = test_dir("cached-huge");
        let path = dir.join("entry.img");
        fs::write(&path, png_header_fixture(1024, 1024)).expect("huge cache entry");
        assert!(read_cached_icon(&path).is_none());
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
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
