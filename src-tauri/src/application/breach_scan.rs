//! Opt-in breach scan across every saved login. The scan reads passwords only
//! inside this process, sends five-character hash prefixes, and keeps results
//! in memory for the current vault session only.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, Zeroizing};

use crate::application::DesktopEffects;
use crate::vault::{VaultResult, VaultState};

pub(crate) const BREACH_SCAN_PROGRESS_EVENT: &str = "breach-scan-progress";
pub(crate) const BREACH_SCAN_FINISHED_EVENT: &str = "breach-scan-finished";
pub(crate) const SHA1_PREFIX_CHARS: usize = 5;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum BreachScanPhase {
    #[default]
    Idle,
    Running,
    Finished,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum BreachVerdict {
    Breached,
    Safe,
    Unknown,
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

#[derive(Debug, Clone, Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct BreachScanReport {
    pub phase: BreachScanPhase,
    pub checked: usize,
    pub total: usize,
    pub results: Vec<LoginBreachCheck>,
}

impl BreachScanReport {
    fn idle() -> Self {
        Self {
            phase: BreachScanPhase::Idle,
            checked: 0,
            total: 0,
            results: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct BreachScanProgress {
    pub checked: usize,
    pub total: usize,
}

#[derive(Debug, Default)]
struct ScanData {
    epoch: u64,
    generation: u64,
    phase: BreachScanPhase,
    checked: usize,
    total: usize,
    results: Vec<LoginBreachCheck>,
    cancel: Option<Arc<AtomicBool>>,
}

impl ScanData {
    fn reset(&mut self) {
        let generation = self.generation;
        *self = Self {
            generation,
            ..Self::default()
        };
    }
}

#[derive(Default)]
struct BreachScanShared {
    data: Mutex<ScanData>,
}

impl BreachScanShared {
    /// Starts a scan at the current epoch unless one is already running.
    fn begin(&self, epoch: u64, total: usize) -> Option<(u64, Arc<AtomicBool>)> {
        let mut data = self.data.lock().ok()?;
        if data.phase == BreachScanPhase::Running && data.epoch == epoch {
            return None;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        data.generation = data.generation.wrapping_add(1);
        data.epoch = epoch;
        data.phase = BreachScanPhase::Running;
        data.checked = 0;
        data.total = total;
        data.results.clear();
        data.cancel = Some(cancel.clone());
        Some((data.generation, cancel))
    }

    fn set_progress(&self, generation: u64, checked: usize) {
        let Ok(mut data) = self.data.lock() else {
            return;
        };
        if data.generation == generation && data.phase == BreachScanPhase::Running {
            data.checked = checked;
        }
    }

    fn finish(&self, generation: u64, current_epoch: u64, outcome: ScanOutcome) {
        let Ok(mut data) = self.data.lock() else {
            return;
        };
        if data.generation != generation {
            return;
        }
        data.cancel = None;
        if data.epoch != current_epoch {
            data.reset();
            return;
        }
        if outcome.cancelled {
            data.phase = BreachScanPhase::Cancelled;
            data.checked = 0;
            data.total = 0;
            data.results.clear();
            return;
        }
        data.phase = BreachScanPhase::Finished;
        data.checked = data.total;
        data.results = outcome.checks;
    }

    /// Stops a running scan. Results already found are dropped with it.
    fn cancel(&self) {
        let Ok(mut data) = self.data.lock() else {
            return;
        };
        if data.phase != BreachScanPhase::Running {
            return;
        }
        if let Some(cancel) = data.cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        data.phase = BreachScanPhase::Cancelled;
        data.checked = 0;
        data.total = 0;
        data.results.clear();
    }

    fn report_for(&self, epoch: u64) -> BreachScanReport {
        let Ok(data) = self.data.lock() else {
            return BreachScanReport::idle();
        };
        if data.epoch != epoch {
            return BreachScanReport::idle();
        }
        BreachScanReport {
            phase: data.phase,
            checked: data.checked,
            total: data.total,
            results: data.results.clone(),
        }
    }
}

#[derive(Clone, Default)]
pub struct BreachScanState {
    shared: Arc<BreachScanShared>,
}

impl BreachScanState {
    pub(crate) fn begin(&self, epoch: u64, total: usize) -> Option<(u64, Arc<AtomicBool>)> {
        self.shared.begin(epoch, total)
    }

    fn set_progress(&self, generation: u64, checked: usize) {
        self.shared.set_progress(generation, checked);
    }

    pub(crate) fn finish(&self, generation: u64, current_epoch: u64, outcome: ScanOutcome) {
        self.shared.finish(generation, current_epoch, outcome);
    }

    /// Stops a running scan from the interface or a vault lock.
    pub(crate) fn cancel(&self) {
        self.shared.cancel();
    }

    pub(crate) fn report_for(&self, epoch: u64) -> BreachScanReport {
        self.shared.report_for(epoch)
    }
}

pub(crate) fn scan_targets(vault: &VaultState) -> VaultResult<Vec<LoginRange>> {
    let session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault before checking saved passwords for breaches.")?;
    let payload = session.open_payload()?;
    let mut logins = Vec::new();
    for entry in &payload.entries {
        if entry.password.is_empty() {
            continue;
        }
        let range = password_range(&entry.password);
        logins.push(LoginRange {
            id: entry.id.clone(),
            prefix: range.prefix,
            suffix: range.suffix,
        });
    }
    Ok(logins)
}

#[derive(Debug)]
pub(crate) struct BreachScanStart {
    pub epoch: u64,
    pub run: Option<BreachScanRun>,
}

#[derive(Debug)]
pub(crate) struct BreachScanRun {
    pub generation: u64,
    pub cancel: Arc<AtomicBool>,
    pub logins: Vec<LoginRange>,
}

pub(crate) fn start_breach_scan_in_state(
    vault: &VaultState,
    scan: &BreachScanState,
) -> VaultResult<BreachScanStart> {
    let epoch = vault.session_epoch();
    let logins = scan_targets(vault)?;
    let total = logins.len();
    let Some((generation, cancel)) = scan.begin(epoch, total) else {
        return Ok(BreachScanStart { epoch, run: None });
    };
    if total == 0 {
        scan.finish(
            generation,
            epoch,
            ScanOutcome {
                cancelled: false,
                checks: Vec::new(),
            },
        );
        return Ok(BreachScanStart { epoch, run: None });
    }
    Ok(BreachScanStart {
        epoch,
        run: Some(BreachScanRun {
            generation,
            cancel,
            logins,
        }),
    })
}

pub(crate) fn report_breach_scan_progress(
    scan: &BreachScanState,
    generation: u64,
    checked: usize,
    total: usize,
    effects: &dyn DesktopEffects,
) {
    scan.set_progress(generation, checked);
    effects.emit_breach_scan_progress(checked, total);
}

pub(crate) fn complete_breach_scan(
    scan: &BreachScanState,
    generation: u64,
    current_epoch: u64,
    outcome: ScanOutcome,
    effects: &dyn DesktopEffects,
) {
    scan.finish(generation, current_epoch, outcome);
    effects.emit_breach_scan_finished();
}

pub(crate) fn unknown_scan_outcome(logins: &[LoginRange]) -> ScanOutcome {
    ScanOutcome {
        cancelled: false,
        checks: logins
            .iter()
            .map(|login| LoginBreachCheck {
                id: login.id.clone(),
                verdict: BreachVerdict::Unknown,
                count: 0,
            })
            .collect(),
    }
}

pub(crate) fn breach_scan_status_in_state(
    vault: &VaultState,
    scan: &BreachScanState,
) -> BreachScanReport {
    scan.report_for(vault.session_epoch())
}
