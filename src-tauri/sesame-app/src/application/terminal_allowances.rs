use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Serialize;

use super::browser_fill_broker::Clock;
use crate::vault::util::unix_timestamp;

pub const ALLOWANCE_TTL: Duration = Duration::from_secs(5 * 60);
pub const MAX_ALLOWED_REQUESTS: usize = 50;
const MAX_ALLOWANCES: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(all(windows, not(test)), allow(dead_code))]
pub struct TerminalKey {
    device: u64,
    session: u32,
    leader_started: u64,
}

impl TerminalKey {
    #[cfg(any(not(windows), test))]
    pub fn controlling(device: u64, session: u32, leader_started: u64) -> Self {
        Self {
            device,
            session,
            leader_started,
        }
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct UnverifiedProgram {
    pub reported_name: String,
}

impl UnverifiedProgram {
    pub fn reported(name: String) -> Self {
        Self {
            reported_name: name,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TerminalOrigin {
    pub key: Option<TerminalKey>,
    pub device: Option<String>,
    pub program: Option<UnverifiedProgram>,
    pub remote: bool,
}

impl TerminalOrigin {
    pub fn without_terminal() -> Self {
        Self::default()
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct TerminalAllowanceView {
    pub terminal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<UnverifiedProgram>,
    pub remote: bool,
    pub expires_in_ms: u64,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct AllowedTerminalRequest {
    pub at: u64,
    pub terminal: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TerminalAllowanceList {
    pub allowances: Vec<TerminalAllowanceView>,
    pub requests: Vec<AllowedTerminalRequest>,
}

struct Allowance {
    key: TerminalKey,
    terminal: String,
    program: Option<UnverifiedProgram>,
    remote: bool,
    epoch: u64,
    expires_at: Instant,
}

struct AllowanceInner {
    allowances: Vec<Allowance>,
    requests: VecDeque<AllowedTerminalRequest>,
    epoch_checked: bool,
}

impl Default for AllowanceInner {
    fn default() -> Self {
        Self {
            allowances: Vec::new(),
            requests: VecDeque::new(),
            epoch_checked: true,
        }
    }
}

pub(super) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub struct TerminalAllowances {
    inner: Mutex<AllowanceInner>,
    clock: Arc<dyn Clock>,
}

impl Default for TerminalAllowances {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl TerminalAllowances {
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::default(),
            clock,
        }
    }

    #[cfg(test)]
    pub fn without_epoch_check(clock: Arc<dyn Clock>) -> Self {
        let allowances = Self::with_clock(clock);
        if let Ok(mut inner) = allowances.inner.lock() {
            inner.epoch_checked = false;
        }
        allowances
    }

    pub fn grant(&self, origin: &TerminalOrigin, epoch: u64) -> bool {
        let Some(key) = origin.key.clone() else {
            return false;
        };
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        let now = self.clock.now();
        inner
            .allowances
            .retain(|allowance| allowance.expires_at > now && allowance.key != key);
        if inner.allowances.len() >= MAX_ALLOWANCES {
            inner.allowances.remove(0);
        }
        inner.allowances.push(Allowance {
            key,
            terminal: terminal_label(origin),
            program: origin.program.clone(),
            remote: origin.remote,
            epoch,
            expires_at: now + ALLOWANCE_TTL,
        });
        true
    }

    pub fn covers(&self, origin: &TerminalOrigin, epoch: u64) -> bool {
        let Some(key) = origin.key.as_ref() else {
            return false;
        };
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        let now = self.clock.now();
        let epoch_checked = inner.epoch_checked;
        inner.allowances.retain(|allowance| {
            allowance.expires_at > now && (!epoch_checked || allowance.epoch == epoch)
        });
        inner
            .allowances
            .iter()
            .any(|allowance| allowance.key == *key)
    }

    pub fn note_request(&self, origin: &TerminalOrigin, request: AllowedTerminalRequest) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let mut request = request;
        request.terminal = terminal_label(origin);
        inner.requests.push_front(request);
        inner.requests.truncate(MAX_ALLOWED_REQUESTS);
    }

    pub fn forget_all(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.allowances.clear();
            inner.requests.clear();
        }
    }

    pub fn list(&self, epoch: u64) -> TerminalAllowanceList {
        let Ok(mut inner) = self.inner.lock() else {
            return TerminalAllowanceList {
                allowances: Vec::new(),
                requests: Vec::new(),
            };
        };
        let now = self.clock.now();
        let epoch_checked = inner.epoch_checked;
        inner.allowances.retain(|allowance| {
            allowance.expires_at > now && (!epoch_checked || allowance.epoch == epoch)
        });
        TerminalAllowanceList {
            allowances: inner
                .allowances
                .iter()
                .map(|allowance| TerminalAllowanceView {
                    terminal: allowance.terminal.clone(),
                    program: allowance.program.clone(),
                    remote: allowance.remote,
                    expires_in_ms: allowance
                        .expires_at
                        .saturating_duration_since(now)
                        .as_millis()
                        .min(u128::from(u64::MAX)) as u64,
                })
                .collect(),
            requests: inner.requests.iter().cloned().collect(),
        }
    }
}

pub fn terminal_label(origin: &TerminalOrigin) -> String {
    origin
        .device
        .clone()
        .unwrap_or_else(|| "No terminal".to_string())
}

pub fn allowed_request(
    command: &str,
    item: Option<(&str, &str)>,
    field: Option<&str>,
) -> AllowedTerminalRequest {
    AllowedTerminalRequest {
        at: unix_timestamp(),
        terminal: String::new(),
        command: command.to_string(),
        item_id: item.map(|(id, _)| id.to_string()),
        item_kind: item.map(|(_, kind)| kind.to_string()),
        field: field.map(str::to_string),
    }
}
