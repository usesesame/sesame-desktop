use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::account_service::read_limited;
use super::ensure_crypto_provider;
use super::public_updates::{candidate_trust, configured_endpoint};
use crate::sync::floor::{confirmed_at, floor_path, record_manifest_floor, require_allowed};
use crate::vault::VaultResult;

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
const RETRY_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_REDIRECTS: usize = 5;

#[derive(Clone, Copy)]
struct Attempt {
    at: Instant,
    reached: bool,
}

static LAST_ATTEMPT: Mutex<Option<Attempt>> = Mutex::new(None);

fn due(last: Option<Attempt>, now: Instant) -> bool {
    match last {
        None => true,
        Some(attempt) => {
            let wait = if attempt.reached {
                REFRESH_INTERVAL
            } else {
                RETRY_INTERVAL
            };
            now.saturating_duration_since(attempt.at) >= wait
        }
    }
}

fn attempt_due() -> bool {
    let Ok(mut last) = LAST_ATTEMPT.lock() else {
        return false;
    };
    let now = Instant::now();
    let is_due = due(*last, now);
    if is_due {
        *last = Some(Attempt {
            at: now,
            reached: false,
        });
    }
    is_due
}

fn mark_reached() {
    if let Ok(mut last) = LAST_ATTEMPT.lock() {
        if let Some(attempt) = last.as_mut() {
            attempt.reached = true;
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub(crate) async fn fetch_manifest(endpoint: url::Url) -> Option<serde_json::Value> {
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
    mark_reached();
    let _ = record_manifest_floor(&floor_path(data_dir), &manifest, key, key_id, unix_now());
}

pub(crate) async fn require_sync_allowed(data_dir: &Path) -> VaultResult<()> {
    refresh(data_dir).await;
    let can_fetch = configured_endpoint().is_ok() && candidate_trust().is_ok();
    require_allowed(env!("CARGO_PKG_VERSION"), &floor_path(data_dir), can_fetch)
}

pub(crate) fn floor_confirmed_at(data_dir: &Path) -> Option<u64> {
    confirmed_at(&floor_path(data_dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(at: Instant, reached: bool) -> Option<Attempt> {
        Some(Attempt { at, reached })
    }

    #[test]
    fn the_first_check_is_always_due() {
        assert!(due(None, Instant::now()));
    }

    #[test]
    fn a_confirmed_floor_is_checked_again_after_an_hour_and_not_before() {
        let start = Instant::now();
        assert!(!due(
            attempt(start, true),
            start + Duration::from_secs(59 * 60)
        ));
        assert!(due(attempt(start, true), start + REFRESH_INTERVAL));
    }

    #[test]
    fn a_failed_fetch_is_retried_in_minutes_and_not_blocked_for_an_hour() {
        let start = Instant::now();
        assert!(!due(attempt(start, false), start + Duration::from_secs(60)));
        assert!(due(attempt(start, false), start + RETRY_INTERVAL));
        assert!(RETRY_INTERVAL < REFRESH_INTERVAL);
    }
}
