use std::time::Duration;

use reqwest::{header::DATE, redirect::Policy, Client};

use super::ensure_crypto_provider;
use crate::vault::VaultResult;

const TIME_SOURCES: [&str; 2] = ["https://usesesame.app/", "https://github.com/"];
const MAX_SOURCE_DISAGREEMENT_SECS: u64 = 5 * 60;
const TIME_SOURCE_TIMEOUT_SECS: u64 = 10;
const TIME_UNAVAILABLE: &str = "Sesame could not confirm the current time with usesesame.app and github.com. Connect to the internet and try again.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TrustedTime {
    pub earliest: u64,
    pub latest: u64,
}

pub(crate) fn parse_http_date(value: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc2822(value)
        .ok()
        .and_then(|moment| u64::try_from(moment.timestamp()).ok())
}

pub(crate) fn agreed_time(readings: &[u64]) -> VaultResult<TrustedTime> {
    if readings.len() != TIME_SOURCES.len() {
        return Err(TIME_UNAVAILABLE.into());
    }
    let earliest = *readings.iter().min().ok_or(TIME_UNAVAILABLE)?;
    let latest = *readings.iter().max().ok_or(TIME_UNAVAILABLE)?;
    if latest - earliest > MAX_SOURCE_DISAGREEMENT_SECS {
        return Err("The time servers disagree, so Sesame cannot confirm the current time. Try again later.".into());
    }
    Ok(TrustedTime { earliest, latest })
}

fn client() -> VaultResult<Client> {
    ensure_crypto_provider();
    Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(TIME_SOURCE_TIMEOUT_SECS))
        .timeout(Duration::from_secs(TIME_SOURCE_TIMEOUT_SECS))
        .build()
        .map_err(|_| TIME_UNAVAILABLE.to_string())
}

async fn source_time(client: &Client, url: &str) -> VaultResult<u64> {
    let response = client
        .head(url)
        .send()
        .await
        .map_err(|_| TIME_UNAVAILABLE.to_string())?;
    response
        .headers()
        .get(DATE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_http_date)
        .ok_or_else(|| TIME_UNAVAILABLE.to_string())
}

pub(crate) async fn trusted_time() -> VaultResult<TrustedTime> {
    let client = client()?;
    let mut readings = Vec::with_capacity(TIME_SOURCES.len());
    for url in TIME_SOURCES {
        readings.push(source_time(&client, url).await?);
    }
    agreed_time(&readings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_http_date_reads_as_unix_seconds() {
        assert_eq!(
            parse_http_date("Sat, 03 Oct 2026 14:00:00 GMT"),
            Some(1_791_036_000)
        );
        assert_eq!(parse_http_date("not a date"), None);
        assert_eq!(parse_http_date(""), None);
    }

    #[test]
    fn two_close_readings_give_their_earliest_and_latest() {
        assert_eq!(
            agreed_time(&[1_000_100, 1_000_000]),
            Ok(TrustedTime {
                earliest: 1_000_000,
                latest: 1_000_100
            })
        );
    }

    #[test]
    fn readings_that_disagree_or_are_missing_are_refused() {
        assert!(agreed_time(&[1_000_000, 1_000_000 + MAX_SOURCE_DISAGREEMENT_SECS + 1]).is_err());
        assert!(agreed_time(&[1_000_000]).is_err());
        assert!(agreed_time(&[]).is_err());
    }
}
