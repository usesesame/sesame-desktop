use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::application::breach_scan::{
    breach_scan_status_in_state, complete_breach_scan, password_range, report_breach_scan_progress,
    scan_targets, start_breach_scan_in_state, BreachScanPhase, BreachScanState, BreachVerdict,
    LoginBreachCheck, LoginRange, ScanOutcome,
};
use crate::application::file_choices::{FilePurpose, FileSelectionState};
use crate::application::imports::{
    cancel_import_in_state, commit_import_in_state, preview_import_in_state,
};
use crate::application::tests::{Effect, FakeEffects};
use crate::network::breach::{self, RangeFetcher};
use crate::test_support::{block_on, TestVault};
use crate::vault::imports::parse_import_entries;
use crate::vault::pending_import::PendingImport;
use crate::vault::{random_id, VaultState};

const STALE_CHOICE: &str = "That file choice expired or was already used. Choose the file again.";
const NO_PENDING_IMPORT: &str = "That import is no longer pending. Choose the export file again.";
const IMPORT_SOURCE: &str = "bitwarden-csv";
const CSV_HEADER: &str =
    "folder,type,name,notes,login_uri,login_username,login_password,login_totp\n";
const CSV_ROW: &str =
    "Fictional,login,Fictional login,,https://northwind.example,fictional-user,fictional-secret,\n";

struct Scratch {
    directory: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("sesame-imports-{label}-{}", random_id()));
        std::fs::create_dir_all(&directory).expect("temp directory");
        Self { directory }
    }

    fn file(&self, name: &str, content: &str) -> PathBuf {
        let path = self.directory.join(name);
        std::fs::write(&path, content).expect("import file");
        path
    }

    fn entries(&self) -> usize {
        std::fs::read_dir(&self.directory)
            .expect("temp directory entries")
            .count()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn import_csv(scratch: &Scratch) -> PathBuf {
    scratch.file("fictional-import.csv", &format!("{CSV_HEADER}{CSV_ROW}"))
}

fn pending_id(state: &VaultState) -> Option<String> {
    state
        .pending_import
        .lock()
        .expect("pending import lock")
        .as_ref()
        .map(|pending| pending.id.clone())
}

fn preview(
    vault: &TestVault,
    selection: &FileSelectionState,
    token: &str,
) -> crate::vault::ImportPreviewResult {
    preview_import_in_state(&vault.state, selection, Some(token), None, IMPORT_SOURCE)
        .expect("import preview")
}

fn login_range(id: &str, password: &str) -> LoginRange {
    let range = password_range(password);
    LoginRange {
        id: id.to_string(),
        prefix: range.prefix,
        suffix: range.suffix,
    }
}

fn check(id: &str, verdict: BreachVerdict) -> LoginBreachCheck {
    LoginBreachCheck {
        id: id.to_string(),
        verdict,
        count: 0,
    }
}

#[derive(Default)]
struct FakeRangeFetcher {
    seen: Mutex<Vec<String>>,
    cancel: Option<Arc<AtomicBool>>,
}

impl RangeFetcher for FakeRangeFetcher {
    fn fetch(&self, prefix: &str) -> impl Future<Output = Result<String, String>> + Send {
        self.seen
            .lock()
            .expect("seen lock")
            .push(prefix.to_string());
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Release);
        }
        std::future::ready(Ok(String::new()))
    }
}

#[test]
fn previewing_an_import_on_a_locked_vault_fails_and_keeps_the_choice() {
    let scratch = Scratch::new("preview-locked");
    let file = import_csv(&scratch);
    let state = VaultState::default();
    let selection = FileSelectionState::default();
    let token = selection
        .issue(FilePurpose::ImportSource, file.clone())
        .expect("issued token");

    let error = preview_import_in_state(&state, &selection, Some(&token), None, IMPORT_SOURCE)
        .err()
        .expect("locked vault refused");

    assert_eq!(error, "Unlock your vault before importing.");
    assert!(pending_id(&state).is_none());
    assert_eq!(selection.take(&token, FilePurpose::ImportSource), Ok(file));
}

#[test]
fn previewing_an_import_without_a_choice_fails_and_keeps_no_preview() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let selection = FileSelectionState::default();

    let error = preview_import_in_state(&vault.state, &selection, None, None, IMPORT_SOURCE)
        .err()
        .expect("missing choice refused");

    assert_eq!(error, STALE_CHOICE);
    assert!(pending_id(&vault.state).is_none());
}

#[test]
fn previewing_an_import_with_a_choice_for_another_purpose_fails_and_leaves_it_usable() {
    let scratch = Scratch::new("preview-purpose");
    let file = import_csv(&scratch);
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let selection = FileSelectionState::default();
    let token = selection
        .issue(FilePurpose::BackupRead, file.clone())
        .expect("issued token");

    let error =
        preview_import_in_state(&vault.state, &selection, Some(&token), None, IMPORT_SOURCE)
            .err()
            .expect("wrong purpose refused");

    assert_eq!(error, STALE_CHOICE);
    assert!(pending_id(&vault.state).is_none());
    assert_eq!(selection.take(&token, FilePurpose::BackupRead), Ok(file));
}

#[test]
fn previewing_an_import_twice_fails_the_second_time_and_keeps_the_first_preview() {
    let scratch = Scratch::new("preview-reused");
    let file = import_csv(&scratch);
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let selection = FileSelectionState::default();
    let token = selection
        .issue(FilePurpose::ImportSource, file)
        .expect("issued token");

    let first = preview(&vault, &selection, &token);
    let first_pending = pending_id(&vault.state).expect("pending preview");
    let error =
        preview_import_in_state(&vault.state, &selection, Some(&token), None, IMPORT_SOURCE)
            .err()
            .expect("reused token refused");

    assert_eq!(error, STALE_CHOICE);
    assert_eq!(first.preview.total_entries, 1);
    assert_eq!(first_pending, first.import_id);
    assert_eq!(pending_id(&vault.state), Some(first.import_id));
}

#[test]
fn a_failed_parse_spends_the_import_choice_and_keeps_no_preview() {
    let scratch = Scratch::new("preview-parse");
    let file = scratch.file("fictional-import.json", "not a Bitwarden export");
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let selection = FileSelectionState::default();
    let token = selection
        .issue(FilePurpose::ImportSource, file)
        .expect("issued token");

    let error = preview_import_in_state(
        &vault.state,
        &selection,
        Some(&token),
        None,
        "bitwarden-json",
    )
    .err()
    .expect("unreadable export refused");

    assert!(error.contains("Bitwarden JSON"));
    assert!(pending_id(&vault.state).is_none());
    assert_eq!(
        selection.take(&token, FilePurpose::ImportSource),
        Err(STALE_CHOICE.to_string())
    );
}

#[test]
fn cancelling_an_import_clears_the_pending_preview() {
    let scratch = Scratch::new("cancel");
    let file = import_csv(&scratch);
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let selection = FileSelectionState::default();
    let token = selection
        .issue(FilePurpose::ImportSource, file)
        .expect("issued token");
    preview(&vault, &selection, &token);
    assert!(pending_id(&vault.state).is_some());

    cancel_import_in_state(&vault.state).expect("cancelled");
    assert!(pending_id(&vault.state).is_none());

    cancel_import_in_state(&vault.state).expect("cancelled again");
    assert!(pending_id(&vault.state).is_none());
}

#[test]
fn committing_an_import_without_a_pending_preview_fails_and_writes_nothing() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let backups = vault.path().parent().expect("vault folder").join("backups");

    let error = commit_import_in_state(&vault.state, "fictional-import", false)
        .err()
        .expect("missing preview refused");

    assert_eq!(error, NO_PENDING_IMPORT);
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert!(!backups.exists());
    assert_eq!(vault.state.session_epoch(), 1);
}

#[test]
fn committing_an_import_on_a_locked_vault_fails_and_keeps_the_preview() {
    let scratch = Scratch::new("commit-locked");
    let csv = format!("{CSV_HEADER}{CSV_ROW}");
    let parsed = parse_import_entries(&csv, IMPORT_SOURCE).expect("parsed import");
    let pending = PendingImport::new(parsed);
    let import_id = pending.id.clone();
    let state = VaultState::default();
    *state.pending_import.lock().expect("pending import lock") = Some(pending);

    let error = commit_import_in_state(&state, &import_id, false)
        .err()
        .expect("locked vault refused");

    assert_eq!(error, "Unlock your vault before importing.");
    assert_eq!(pending_id(&state), Some(import_id));
    assert_eq!(scratch.entries(), 0);
}

#[test]
fn committing_a_preview_with_a_wrong_id_fails_writes_nothing_and_drops_the_preview() {
    let scratch = Scratch::new("commit-wrong-id");
    let file = import_csv(&scratch);
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let selection = FileSelectionState::default();
    let token = selection
        .issue(FilePurpose::ImportSource, file)
        .expect("issued token");
    preview(&vault, &selection, &token);

    let error = commit_import_in_state(&vault.state, "fictional-other-import", false)
        .err()
        .expect("wrong id refused");

    assert_eq!(error, NO_PENDING_IMPORT);
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert!(pending_id(&vault.state).is_none());
    assert!(!vault
        .path()
        .parent()
        .expect("vault folder")
        .join("backups")
        .exists());
}

#[test]
fn a_commit_that_fails_while_building_the_payload_keeps_the_vault_and_spends_the_preview() {
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let before = std::fs::read(vault.path()).expect("vault bytes");
    let csv = format!("{CSV_HEADER}{CSV_ROW}");
    let mut parsed = parse_import_entries(&csv, IMPORT_SOURCE).expect("parsed import");
    parsed.entries[0].id = "fictional-login".to_string();
    let pending = PendingImport::new(parsed);
    let import_id = pending.id.clone();
    *vault
        .state
        .pending_import
        .lock()
        .expect("pending import lock") = Some(pending);

    let error = commit_import_in_state(&vault.state, &import_id, false)
        .err()
        .expect("duplicate id refused");

    assert_eq!(error, "A saved item with that id already exists.");
    assert_eq!(std::fs::read(vault.path()).expect("vault bytes"), before);
    assert!(pending_id(&vault.state).is_none());
    assert_eq!(vault.state.session_epoch(), 1);
}

#[test]
fn committing_a_preview_imports_each_item_once_and_spends_the_preview() {
    let scratch = Scratch::new("commit");
    let file = import_csv(&scratch);
    let vault = TestVault::with_login("fictional-login", "https://northwind.example");
    let selection = FileSelectionState::default();
    let token = selection
        .issue(FilePurpose::ImportSource, file)
        .expect("issued token");
    let preview = preview(&vault, &selection, &token);

    let result =
        commit_import_in_state(&vault.state, &preview.import_id, false).expect("committed");

    assert_eq!(preview.preview.total_entries, 1);
    assert_eq!(result.imported_entries, 1);
    assert_eq!(result.snapshot.entries.len(), 2);
    assert!(result.revision_backup_name.is_some());
    assert!(pending_id(&vault.state).is_none());
    assert_eq!(vault.state.session_epoch(), 2);
    assert!(result
        .snapshot
        .entries
        .iter()
        .any(|entry| entry.title == "Fictional login"));
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
        password_range("fictional-stored-secret").prefix
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
    let range = password_range("fictional-stored-secret");

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
    assert_eq!(report.checked, 0);
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

#[test]
fn a_cancelled_scan_stops_reporting_progress() {
    let scan = BreachScanState::default();
    let effects = FakeEffects::new(PathBuf::new());
    let epoch = 9;
    let logins = vec![
        login_range("fictional-login-a", "fictional-password-one"),
        login_range("fictional-login-b", "fictional-password-two"),
    ];
    let (generation, cancel) = scan.begin(epoch, logins.len()).expect("scan begins");
    let fetcher = FakeRangeFetcher {
        cancel: Some(cancel.clone()),
        ..FakeRangeFetcher::default()
    };

    let outcome = block_on(breach::scan_logins(
        logins,
        &fetcher,
        &cancel,
        |checked, total| {
            report_breach_scan_progress(&scan, generation, checked, total, &effects);
        },
    ));
    complete_breach_scan(&scan, generation, epoch, outcome, &effects);

    let report = scan.report_for(epoch);
    assert_eq!(report.phase, BreachScanPhase::Cancelled);
    assert_eq!(report.checked, 0);
    assert_eq!(report.total, 0);
    assert!(report.results.is_empty());
    assert_eq!(fetcher.seen.lock().expect("seen lock").len(), 1);
    assert_eq!(
        effects.calls(),
        vec![
            Effect::EmitBreachScanProgress {
                checked: 1,
                total: 2
            },
            Effect::EmitBreachScanFinished,
        ]
    );
}

#[test]
fn an_empty_scan_finishes_without_starting_a_background_run() {
    let vault = TestVault::with_login("fictional-login", "https://github.com");
    vault.seed(|payload| payload.entries.clear());
    let scan = BreachScanState::default();

    let started = start_breach_scan_in_state(&vault.state, &scan).expect("start refused");

    assert!(started.run.is_none());
    let report = breach_scan_status_in_state(&vault.state, &scan);
    assert_eq!(report.phase, BreachScanPhase::Finished);
    assert_eq!(report.checked, 0);
    assert_eq!(report.total, 0);
}

#[test]
fn a_scan_over_saved_logins_starts_at_the_current_epoch_and_runs_once() {
    let vault = TestVault::with_login("fictional-login", "https://github.com");
    let scan = BreachScanState::default();

    let started = start_breach_scan_in_state(&vault.state, &scan).expect("started");

    assert_eq!(started.epoch, vault.state.session_epoch());
    let run = started.run.expect("background run");
    assert_eq!(run.logins.len(), 1);
    assert_eq!(
        scan.report_for(started.epoch).phase,
        BreachScanPhase::Running
    );
    assert!(start_breach_scan_in_state(&vault.state, &scan)
        .expect("second start")
        .run
        .is_none());
    scan.cancel();
}

#[test]
fn a_locked_vault_cannot_start_a_scan() {
    let vault = VaultState::default();
    let scan = BreachScanState::default();

    let error = start_breach_scan_in_state(&vault, &scan).expect_err("locked vault refused");

    assert!(error.contains("Unlock"));
    assert_eq!(
        breach_scan_status_in_state(&vault, &scan).phase,
        BreachScanPhase::Idle
    );
}

#[test]
fn status_on_a_locked_vault_reports_the_last_scan_for_its_epoch() {
    let vault = VaultState::default();
    let scan = BreachScanState::default();
    let idle = breach_scan_status_in_state(&vault, &scan);
    assert_eq!(idle.phase, BreachScanPhase::Idle);
    assert_eq!(idle.checked, 0);

    let epoch = vault.session_epoch();
    let (generation, _cancel) = scan.begin(epoch, 1).expect("scan begins");
    scan.finish(
        generation,
        epoch,
        ScanOutcome {
            cancelled: false,
            checks: vec![check("fictional-login", BreachVerdict::Safe)],
        },
    );
    let finished = breach_scan_status_in_state(&vault, &scan);
    assert_eq!(finished.phase, BreachScanPhase::Finished);
    assert_eq!(finished.checked, 1);
    assert_eq!(finished.results.len(), 1);

    vault.advance_session_epoch();
    let stale = breach_scan_status_in_state(&vault, &scan);
    assert_eq!(stale.phase, BreachScanPhase::Idle);
    assert!(stale.results.is_empty());
}
