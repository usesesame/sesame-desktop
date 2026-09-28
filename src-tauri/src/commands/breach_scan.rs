//! Opt-in breach scan across every saved login. The scan reads passwords only
//! inside this process, sends five-character hash prefixes, and keeps results
//! in memory for the current vault session only.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::adapters::network::breach::{
    self, BreachVerdict, HibpRangeFetcher, LoginBreachCheck, LoginRange, ScanOutcome,
};
use crate::vault::{VaultResult, VaultState};

pub const BREACH_SCAN_PROGRESS_EVENT: &str = "breach-scan-progress";
pub const BREACH_SCAN_FINISHED_EVENT: &str = "breach-scan-finished";

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
    fn shared(&self) -> Arc<BreachScanShared> {
        self.shared.clone()
    }

    fn begin(&self, epoch: u64, total: usize) -> Option<(u64, Arc<AtomicBool>)> {
        self.shared.begin(epoch, total)
    }

    fn finish(&self, generation: u64, current_epoch: u64, outcome: ScanOutcome) {
        self.shared.finish(generation, current_epoch, outcome);
    }

    /// Stops a running scan from the interface or a vault lock.
    pub fn cancel(&self) {
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
        let range = breach::password_range(&entry.password);
        logins.push(LoginRange {
            id: entry.id.clone(),
            prefix: range.prefix,
            suffix: range.suffix,
        });
    }
    Ok(logins)
}

async fn run_scan(
    app: AppHandle,
    shared: Arc<BreachScanShared>,
    generation: u64,
    cancel: Arc<AtomicBool>,
    logins: Vec<LoginRange>,
) {
    let outcome = match HibpRangeFetcher::new() {
        Ok(fetcher) => {
            breach::scan_logins(logins, &fetcher, &cancel, |checked, total| {
                shared.set_progress(generation, checked);
                let _ = app.emit(
                    BREACH_SCAN_PROGRESS_EVENT,
                    BreachScanProgress { checked, total },
                );
            })
            .await
        }
        Err(_) => ScanOutcome {
            cancelled: false,
            checks: logins
                .iter()
                .map(|login| LoginBreachCheck {
                    id: login.id.clone(),
                    verdict: BreachVerdict::Unknown,
                    count: 0,
                })
                .collect(),
        },
    };
    let current_epoch = app.state::<VaultState>().session_epoch();
    shared.finish(generation, current_epoch, outcome);
    let _ = app.emit(BREACH_SCAN_FINISHED_EVENT, ());
}

#[tauri::command]
pub fn start_login_breach_scan(
    app: AppHandle,
    vault: State<'_, VaultState>,
    scan: State<'_, BreachScanState>,
) -> VaultResult<BreachScanReport> {
    let epoch = vault.session_epoch();
    let logins = scan_targets(&vault)?;
    let total = logins.len();
    let Some((generation, cancel)) = scan.begin(epoch, total) else {
        return Ok(scan.report_for(epoch));
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
        return Ok(scan.report_for(epoch));
    }
    let shared = scan.shared();
    tauri::async_runtime::spawn(async move {
        run_scan(app, shared, generation, cancel, logins).await;
    });
    Ok(scan.report_for(epoch))
}

#[tauri::command]
pub fn get_login_breach_scan_status(
    vault: State<'_, VaultState>,
    scan: State<'_, BreachScanState>,
) -> BreachScanReport {
    scan.report_for(vault.session_epoch())
}

#[tauri::command]
pub fn cancel_login_breach_scan(scan: State<'_, BreachScanState>) {
    scan.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::TestVault;

    fn check(id: &str, verdict: BreachVerdict) -> LoginBreachCheck {
        LoginBreachCheck {
            id: id.to_string(),
            verdict,
            count: 0,
        }
    }

    #[test]
    fn a_locked_vault_has_no_scannable_logins() {
        let error = scan_targets(&VaultState::default()).expect_err("locked vault refused");
        assert!(error.contains("Unlock"));
    }

    #[test]
    fn an_unlocked_vault_yields_five_character_prefixes() {
        let vault = TestVault::with_login("login-a", "https://github.com");
        let logins = scan_targets(&vault.state).expect("scan targets");
        assert_eq!(logins.len(), 1);
        assert_eq!(logins[0].id, "login-a");
        assert_eq!(
            logins[0].prefix,
            breach::password_range("fictional-stored-secret").prefix
        );
    }

    #[test]
    fn a_report_never_carries_a_password_or_full_hash() {
        let vault = TestVault::with_login("login-a", "https://github.com");
        let scan = BreachScanState::default();
        let epoch = vault.state.session_epoch();
        let (generation, _cancel) = scan.begin(epoch, 1).expect("scan begins");
        scan.finish(
            generation,
            epoch,
            ScanOutcome {
                cancelled: false,
                checks: vec![check("login-a", BreachVerdict::Breached)],
            },
        );
        let serialized = serde_json::to_string(&scan.report_for(epoch)).expect("serialized report");
        let range = breach::password_range("fictional-stored-secret");
        assert!(!serialized.contains("fictional-stored-secret"));
        assert!(!serialized.contains(&range.suffix.to_string()));
    }

    #[test]
    fn results_do_not_survive_a_session_epoch_change() {
        let scan = BreachScanState::default();
        let (generation, _cancel) = scan.begin(1, 1).expect("scan begins");
        scan.finish(
            generation,
            1,
            ScanOutcome {
                cancelled: false,
                checks: vec![check("login-a", BreachVerdict::Safe)],
            },
        );
        assert_eq!(scan.report_for(1).phase, BreachScanPhase::Finished);
        let stale = scan.report_for(2);
        assert_eq!(stale.phase, BreachScanPhase::Idle);
        assert!(stale.results.is_empty());
    }

    #[test]
    fn a_running_scan_can_be_cancelled() {
        let scan = BreachScanState::default();
        let (_generation, cancel) = scan.begin(1, 3).expect("scan begins");
        scan.cancel();
        assert!(cancel.load(Ordering::Acquire));
        let report = scan.report_for(1);
        assert_eq!(report.phase, BreachScanPhase::Cancelled);
        assert!(report.results.is_empty());
    }

    #[test]
    fn a_second_start_while_running_is_refused() {
        let scan = BreachScanState::default();
        assert!(scan.begin(1, 3).is_some());
        assert!(scan.begin(1, 3).is_none());
    }

    #[test]
    fn a_scan_finished_after_a_lock_is_dropped() {
        let scan = BreachScanState::default();
        let (generation, _cancel) = scan.begin(1, 1).expect("scan begins");
        scan.finish(
            generation,
            2,
            ScanOutcome {
                cancelled: false,
                checks: vec![check("login-a", BreachVerdict::Safe)],
            },
        );
        assert_eq!(scan.report_for(2).phase, BreachScanPhase::Idle);
    }
}
