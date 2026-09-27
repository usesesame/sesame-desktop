//! Explicit one-password and vault-wide Have I Been Pwned range requests.
//! Only the first five hex characters of a SHA-1 hash ever leave the process.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::ensure_crypto_provider;
use reqwest::Client;
use serde::Serialize;
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, Zeroizing};

use crate::vault::VaultResult;

const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const HIBP_TIMEOUT_SECS: u64 = 10;
pub const SHA1_PREFIX_CHARS: usize = 5;

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct BreachCheckResult {
    pub breached: bool,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum BreachVerdict {
    Breached,
    Safe,
    Unknown,
}

pub struct PasswordRange {
    pub prefix: String,
    pub suffix: Zeroizing<String>,
}

pub fn password_range(password: &str) -> PasswordRange {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let mut digest = hasher.finalize();
    let mut hex: String = digest.iter().map(|byte| format!("{byte:02X}")).collect();
    digest.zeroize();
    let (prefix, suffix) = hex.split_at(SHA1_PREFIX_CHARS);
    let range = PasswordRange {
        prefix: prefix.to_string(),
        suffix: Zeroizing::new(suffix.to_string()),
    };
    hex.zeroize();
    range
}

pub struct LoginRange {
    pub id: String,
    pub prefix: String,
    pub suffix: Zeroizing<String>,
}

impl std::fmt::Debug for LoginRange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoginRange")
            .field("id", &self.id)
            .field("prefix", &self.prefix)
            .field("suffix", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct LoginBreachCheck {
    pub id: String,
    pub verdict: BreachVerdict,
    pub count: u32,
}

#[derive(Debug)]
pub struct ScanOutcome {
    pub cancelled: bool,
    pub checks: Vec<LoginBreachCheck>,
}

pub trait RangeFetcher {
    fn fetch(&self, prefix: &str) -> impl Future<Output = Result<String, String>> + Send;
}

pub struct HibpRangeFetcher {
    client: Client,
}

impl HibpRangeFetcher {
    pub fn new() -> VaultResult<Self> {
        Ok(Self {
            client: range_client()?,
        })
    }
}

impl RangeFetcher for HibpRangeFetcher {
    fn fetch(&self, prefix: &str) -> impl Future<Output = Result<String, String>> + Send {
        let prefix = prefix.to_string();
        let client = self.client.clone();
        async move { fetch_range(&client, &prefix).await }
    }
}

pub fn range_client() -> VaultResult<Client> {
    ensure_crypto_provider();
    Client::builder()
        .timeout(Duration::from_secs(HIBP_TIMEOUT_SECS))
        .build()
        .map_err(|_| "Sesame could not prepare the breach check request.".to_string())
}

pub async fn fetch_range(client: &Client, prefix: &str) -> VaultResult<String> {
    let response = client
        .get(format!("{HIBP_RANGE_URL}{prefix}"))
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(|_| "Sesame could not reach the breach-check service. Try again.".to_string())?;
    if !response.status().is_success() {
        return Err("Sesame could not reach the breach-check service. Try again.".to_string());
    }
    response
        .text()
        .await
        .map_err(|_| "Sesame could not read the breach-check response.".to_string())
}

pub fn count_for_suffix(body: &str, suffix: &str) -> u32 {
    for line in body.lines() {
        if let Some((candidate, count)) = line.split_once(':') {
            if candidate.eq_ignore_ascii_case(suffix) {
                return count.trim().parse::<u32>().unwrap_or(0);
            }
        }
    }
    0
}

/// One range per distinct prefix, in prefix order; a prefix shared by several
/// logins is fetched once. Only a failing whole scan reports unknown; a failed
/// range leaves every login behind it unknown, never safe.
pub async fn scan_logins<F: RangeFetcher>(
    logins: Vec<LoginRange>,
    fetcher: &F,
    cancel: &AtomicBool,
    mut on_progress: impl FnMut(usize, usize),
) -> ScanOutcome {
    let total = logins.len();
    let mut by_prefix: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, login) in logins.iter().enumerate() {
        by_prefix
            .entry(login.prefix.as_str())
            .or_default()
            .push(index);
    }

    let mut checks: Vec<Option<LoginBreachCheck>> = (0..total).map(|_| None).collect();
    let mut checked = 0;
    for (prefix, indexes) in &by_prefix {
        if cancel.load(Ordering::Acquire) {
            return ScanOutcome {
                cancelled: true,
                checks: Vec::new(),
            };
        }
        let verdicts = match fetcher.fetch(prefix).await {
            Ok(body) => indexes
                .iter()
                .map(|index| {
                    let count = count_for_suffix(&body, &logins[*index].suffix);
                    (
                        *index,
                        if count > 0 {
                            BreachVerdict::Breached
                        } else {
                            BreachVerdict::Safe
                        },
                        count,
                    )
                })
                .collect::<Vec<_>>(),
            Err(_) => indexes
                .iter()
                .map(|index| (*index, BreachVerdict::Unknown, 0))
                .collect::<Vec<_>>(),
        };
        for (index, verdict, count) in verdicts {
            checks[index] = Some(LoginBreachCheck {
                id: logins[index].id.clone(),
                verdict,
                count,
            });
        }
        checked += indexes.len();
        on_progress(checked, total);
    }

    ScanOutcome {
        cancelled: false,
        checks: checks.into_iter().flatten().collect(),
    }
}

pub async fn check_password_breach(password: String) -> VaultResult<BreachCheckResult> {
    let mut password = password;
    let range = password_range(&password);
    password.zeroize();

    let client = range_client()?;
    let body = fetch_range(&client, &range.prefix).await?;
    let count = count_for_suffix(&body, &range.suffix);
    Ok(BreachCheckResult {
        breached: count > 0,
        count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeFetcher {
        seen: Mutex<Vec<String>>,
        bodies: Mutex<HashMap<String, String>>,
        failing: Vec<String>,
        cancel_after: Option<usize>,
        cancel: Option<Arc<AtomicBool>>,
    }

    impl FakeFetcher {
        fn with_body(mut self, prefix: &str, body: &str) -> Self {
            self.bodies
                .get_mut()
                .expect("bodies lock")
                .insert(prefix.to_string(), body.to_string());
            self
        }

        fn failing(mut self, prefix: &str) -> Self {
            self.failing.push(prefix.to_string());
            self
        }

        fn cancelling_after(mut self, call: usize, cancel: Arc<AtomicBool>) -> Self {
            self.cancel_after = Some(call);
            self.cancel = Some(cancel);
            self
        }
    }

    impl RangeFetcher for FakeFetcher {
        fn fetch(&self, prefix: &str) -> impl Future<Output = Result<String, String>> + Send {
            let call = {
                let mut seen = self.seen.lock().expect("seen lock");
                seen.push(prefix.to_string());
                seen.len() - 1
            };
            if self.cancel_after == Some(call) {
                if let Some(cancel) = &self.cancel {
                    cancel.store(true, Ordering::Release);
                }
            }
            if self.failing.iter().any(|failed| failed.as_str() == prefix) {
                return std::future::ready(Err("fake transport failed".to_string()));
            }
            let body = self
                .bodies
                .lock()
                .expect("bodies lock")
                .get(prefix)
                .cloned()
                .unwrap_or_default();
            std::future::ready(Ok(body))
        }
    }

    fn login(id: &str, password: &str) -> LoginRange {
        let range = password_range(password);
        LoginRange {
            id: id.to_string(),
            prefix: range.prefix,
            suffix: range.suffix,
        }
    }

    fn password_hash(password: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    #[test]
    fn only_the_five_character_prefix_reaches_the_fetcher() {
        let passwords = ["fictional-one", "fictional-two"];
        let fetcher = FakeFetcher::default();
        let cancel = AtomicBool::new(false);
        let logins = passwords
            .iter()
            .enumerate()
            .map(|(index, password)| login(&format!("login-{index}"), password))
            .collect::<Vec<_>>();
        let outcome =
            tauri::async_runtime::block_on(scan_logins(logins, &fetcher, &cancel, |_, _| {}));

        let seen = fetcher.seen.lock().expect("seen lock").clone();
        assert_eq!(seen.len(), 2);
        for prefix in &seen {
            assert_eq!(prefix.len(), SHA1_PREFIX_CHARS);
            assert!(prefix.chars().all(|value| value.is_ascii_hexdigit()));
        }
        let serialized = serde_json::to_string(&outcome.checks).expect("serialized checks");
        for password in passwords {
            assert!(!serialized.contains(password));
            assert!(!serialized.contains(&password_hash(password)));
        }
    }

    #[test]
    fn a_cancelled_scan_stops_before_the_next_request() {
        let cancel = Arc::new(AtomicBool::new(false));
        let fetcher = FakeFetcher::default().cancelling_after(0, cancel.clone());
        let logins = vec![
            login("login-a", "fictional-one"),
            login("login-b", "fictional-two"),
        ];
        let outcome =
            tauri::async_runtime::block_on(scan_logins(logins, &fetcher, &cancel, |_, _| {}));

        assert!(outcome.cancelled);
        assert!(outcome.checks.is_empty());
        assert_eq!(fetcher.seen.lock().expect("seen lock").len(), 1);
    }

    #[test]
    fn a_failed_range_is_unknown_and_never_safe() {
        let failing = password_range("fictional-one");
        let healthy = password_range("fictional-two");
        let fetcher = FakeFetcher::default().failing(&failing.prefix);
        let cancel = AtomicBool::new(false);
        let logins = vec![
            LoginRange {
                id: "login-a".to_string(),
                prefix: failing.prefix,
                suffix: failing.suffix,
            },
            LoginRange {
                id: "login-b".to_string(),
                prefix: healthy.prefix,
                suffix: healthy.suffix,
            },
        ];
        let outcome =
            tauri::async_runtime::block_on(scan_logins(logins, &fetcher, &cancel, |_, _| {}));

        let failed = outcome
            .checks
            .iter()
            .find(|check| check.id == "login-a")
            .expect("first check");
        assert_eq!(failed.verdict, BreachVerdict::Unknown);
        let other = outcome
            .checks
            .iter()
            .find(|check| check.id == "login-b")
            .expect("second check");
        assert_eq!(other.verdict, BreachVerdict::Safe);
    }

    #[test]
    fn a_matching_suffix_is_reported_as_breached_with_its_count() {
        let range = password_range("fictional-one");
        let body = format!(
            "00000000000000000000000000000000000A:3\r\n{}:17\r\n",
            *range.suffix
        );
        let fetcher = FakeFetcher::default().with_body(&range.prefix, &body);
        let cancel = AtomicBool::new(false);
        let outcome = tauri::async_runtime::block_on(scan_logins(
            vec![LoginRange {
                id: "login-a".to_string(),
                prefix: range.prefix,
                suffix: range.suffix,
            }],
            &fetcher,
            &cancel,
            |_, _| {},
        ));

        assert_eq!(outcome.checks.len(), 1);
        assert_eq!(outcome.checks[0].verdict, BreachVerdict::Breached);
        assert_eq!(outcome.checks[0].count, 17);
    }

    #[test]
    fn shared_prefixes_use_one_request() {
        let fetcher = FakeFetcher::default();
        let cancel = AtomicBool::new(false);
        let range = password_range("fictional-one");
        let first = LoginRange {
            id: "login-a".to_string(),
            prefix: range.prefix.clone(),
            suffix: range.suffix.clone(),
        };
        let twin = LoginRange {
            id: "login-b".to_string(),
            prefix: range.prefix,
            suffix: range.suffix,
        };
        let outcome = tauri::async_runtime::block_on(scan_logins(
            vec![first, twin],
            &fetcher,
            &cancel,
            |_, _| {},
        ));

        assert_eq!(fetcher.seen.lock().expect("seen lock").len(), 1);
        assert_eq!(outcome.checks.len(), 2);
    }
}
