//! Explicit one-password Have I Been Pwned range request.

use std::time::Duration;

use super::ensure_crypto_provider;
use reqwest::Client;
use serde::Serialize;
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::vault::VaultResult;

const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const HIBP_TIMEOUT_SECS: u64 = 10;

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct BreachCheckResult {
    pub breached: bool,
    pub count: u32,
}

pub async fn check_password_breach(password: String) -> VaultResult<BreachCheckResult> {
    let mut password = password;
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    password.zeroize();

    let hex: String = digest.iter().map(|byte| format!("{byte:02X}")).collect();
    let (prefix, suffix) = hex.split_at(5);
    ensure_crypto_provider();
    let client = Client::builder()
        .timeout(Duration::from_secs(HIBP_TIMEOUT_SECS))
        .build()
        .map_err(|_| "Sesame could not prepare the breach check request.".to_string())?;
    let response = client
        .get(format!("{HIBP_RANGE_URL}{prefix}"))
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(|_| "Sesame could not reach the breach-check service. Try again.".to_string())?;
    if !response.status().is_success() {
        return Err("Sesame could not reach the breach-check service. Try again.".to_string());
    }
    let body = response
        .text()
        .await
        .map_err(|_| "Sesame could not read the breach-check response.".to_string())?;
    for line in body.lines() {
        if let Some((candidate, count)) = line.split_once(':') {
            if candidate.eq_ignore_ascii_case(suffix) {
                let count = count.trim().parse::<u32>().unwrap_or(0);
                return Ok(BreachCheckResult {
                    breached: count > 0,
                    count,
                });
            }
        }
    }
    Ok(BreachCheckResult {
        breached: false,
        count: 0,
    })
}
