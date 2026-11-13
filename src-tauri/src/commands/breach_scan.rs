use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use tauri::{AppHandle, Manager, State};

use crate::adapters::desktop_effects::DesktopHostEffects;
use crate::adapters::network::breach::{self, HibpRangeFetcher};
pub use crate::application::breach_scan::BreachScanState;
use crate::application::breach_scan::{
    breach_scan_status_in_state, complete_breach_scan, report_breach_scan_progress,
    start_breach_scan_in_state, unknown_scan_outcome, BreachScanReport, LoginRange,
};
use crate::vault::{VaultResult, VaultState};

async fn run_scan(
    app: &AppHandle,
    scan: &BreachScanState,
    generation: u64,
    cancel: Arc<AtomicBool>,
    logins: Vec<LoginRange>,
) {
    let effects = DesktopHostEffects::new(app);
    let outcome = match HibpRangeFetcher::new() {
        Ok(fetcher) => {
            breach::scan_logins(logins, &fetcher, &cancel, |checked, total| {
                report_breach_scan_progress(scan, generation, checked, total, &effects);
            })
            .await
        }
        Err(_) => unknown_scan_outcome(&logins),
    };
    let current_epoch = app.state::<VaultState>().session_epoch();
    complete_breach_scan(scan, generation, current_epoch, outcome, &effects);
}

#[tauri::command]
pub fn start_login_breach_scan(
    app: AppHandle,
    vault: State<'_, VaultState>,
    scan: State<'_, BreachScanState>,
) -> VaultResult<BreachScanReport> {
    let started = start_breach_scan_in_state(&vault, &scan)?;
    if let Some(run) = started.run {
        let scan = scan.inner().clone();
        tauri::async_runtime::spawn(async move {
            run_scan(&app, &scan, run.generation, run.cancel, run.logins).await;
        });
    }
    Ok(scan.report_for(started.epoch))
}

#[tauri::command]
pub fn get_login_breach_scan_status(
    vault: State<'_, VaultState>,
    scan: State<'_, BreachScanState>,
) -> BreachScanReport {
    breach_scan_status_in_state(&vault, &scan)
}

#[tauri::command]
pub fn cancel_login_breach_scan(scan: State<'_, BreachScanState>) {
    scan.cancel();
}
