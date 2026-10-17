use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::account_service::read_limited;
use super::ensure_crypto_provider;
use super::public_updates::{candidate_trust, configured_endpoint};
use crate::sync::floor::{floor_path, record_manifest_floor, require_allowed};
use crate::vault::VaultResult;

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
const MAX_REDIRECTS: usize = 5;

static LAST_ATTEMPT: Mutex<Option<Instant>> = Mutex::new(None);

fn attempt_due() -> bool {
    let Ok(mut last) = LAST_ATTEMPT.lock() else {
        return false;
    };
    let due = last.is_none_or(|at| at.elapsed() >= REFRESH_INTERVAL);
    if due {
        *last = Some(Instant::now());
    }
    due
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

async fn fetch_manifest(endpoint: url::Url) -> Option<serde_json::Value> {
    ensure_crypto_provider();
    let secure = endpoint.scheme() == "https";
    let client = reqwest::Client::builder()
        .https_only(secure)
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        .timeout(FETCH_TIMEOUT)
        .build()
        .ok()?;
    let response = client.get(endpoint).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = read_limited(response, MAX_MANIFEST_BYTES).await?;
    serde_json::from_slice(&body).ok()
}

async fn refresh(data_dir: &Path) {
    let Ok(endpoint) = configured_endpoint() else {
        return;
    };
    let Ok((key, key_id)) = candidate_trust() else {
        return;
    };
    if !attempt_due() {
        return;
    }
    let Some(manifest) = fetch_manifest(endpoint).await else {
        return;
    };
    let _ = record_manifest_floor(&floor_path(data_dir), &manifest, key, key_id, unix_now());
}

pub(crate) async fn require_sync_allowed(data_dir: &Path) -> VaultResult<()> {
    refresh(data_dir).await;
    require_allowed(env!("CARGO_PKG_VERSION"), &floor_path(data_dir))
}
