use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    fs::{self, OpenOptions},
    hash::{Hash, Hasher},
    io::Write,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::app_identity::APP_IDENTIFIER;

const DIAGNOSTIC_FILE: &str = "sesame-diagnostics.jsonl";
const MAX_DIAGNOSTIC_BYTES: u64 = 1024 * 1024;
// Routine events expire; error events stay until exported or cleared.
const DIAGNOSTIC_RETENTION_SECS: u64 = 24 * 60 * 60;

type DiagnosticResult<T> = Result<T, String>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticInput {
    operation: String,
    code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticStatus {
    exists: bool,
    event_count: usize,
    error_count: usize,
    size_bytes: u64,
    local_only: bool,
    by_operation: Vec<OperationCount>,
    by_code: Vec<CodeCount>,
    recent: Vec<RecentEvent>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationCount {
    operation: String,
    count: usize,
    error_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeCount {
    code: String,
    count: usize,
    level: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentEvent {
    timestamp: u64,
    operation: String,
    code: String,
    level: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticEvent<'a> {
    timestamp: u64,
    version: &'a str,
    platform: &'a str,
    session: &'a str,
    operation: &'a str,
    code: &'a str,
    level: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    crash_site: Option<u64>,
}

/// Parsed loosely so current and older log lines classify the same way.
#[derive(Deserialize)]
struct StoredEvent {
    #[serde(default)]
    timestamp: u64,
    #[serde(default)]
    operation: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    level: Option<String>,
}

impl StoredEvent {
    fn is_error(&self) -> bool {
        self.level
            .as_deref()
            .map(|level| level == "error")
            .unwrap_or_else(|| severity(&self.code) == "error")
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Per-process correlation tag, never an identifier of machine, user, or vault.
fn session_id() -> &'static str {
    static SESSION_ID: OnceLock<String> = OnceLock::new();
    SESSION_ID.get_or_init(crate::vault::util::random_id)
}

fn severity(code: &str) -> &'static str {
    match code {
        "panic"
        | "unhandled_exception"
        | "unhandled_rejection"
        | "handled_error"
        | "failed"
        | "invalid_file"
        | "io_error"
        | "registration_host_missing"
        | "registration_manifest_failed"
        | "registration_registry_failed"
        | "registration_status_failed"
        | "host_protocol_error"
        | "host_io_error"
        | "host_origin_rejected"
        | "pipe_server_failed"
        | "fill_listener_failed"
        | "save_listener_failed"
        | "identity_fill_listener_failed"
        | "vault_lock_listener_failed"
        | "idle_warning_listener_failed" => "error",
        "fill_locked"
        | "fill_no_match"
        | "fill_denied"
        | "fill_timeout"
        | "fill_connection_closed"
        | "fill_vault_changed"
        | "save_locked"
        | "save_update_no_match"
        | "save_denied"
        | "save_timeout"
        | "save_connection_closed"
        | "save_vault_changed"
        | "identity_locked"
        | "identity_no_match"
        | "identity_denied"
        | "identity_timeout"
        | "identity_connection_closed"
        | "identity_vault_changed"
        | "registration_unsupported"
        | "host_no_request" => "warn",
        "started"
        | "registration_ok"
        | "host_started"
        | "host_response_sent"
        | "pipe_server_started"
        | "fill_requested"
        | "fill_approved"
        | "save_requested"
        | "save_approved"
        | "identity_requested"
        | "identity_approved" => "info",
        // Unknown or retired codes are routine, never misclassified failures.
        _ => "info",
    }
}

pub fn install_panic_hook(app: AppHandle) {
    let Ok(path) = diagnostic_path(&app) else {
        return;
    };
    let panic_path = path.clone();
    std::panic::set_hook(Box::new(move |info| {
        let crash_site = info.location().map(|location| {
            let mut hasher = DefaultHasher::new();
            location.file().hash(&mut hasher);
            location.line().hash(&mut hasher);
            location.column().hash(&mut hasher);
            hasher.finish()
        });
        let _ = append_event_with_site(&panic_path, "runtime", "panic", crash_site);
    }));
    // Each launch prunes routine events; failures are retained for support.
    let _ = prune_stale_at(&path, unix_now());
    let _ = append_event(&path, "app", "started");
}

pub fn record_browser_host_registration(app: &AppHandle, code: &'static str) {
    if !allowed_browser_host_code(code) {
        return;
    }
    if let Ok(path) = diagnostic_path(app) {
        let _ = append_event(&path, "browser_host", code);
    }
}

pub fn record_browser_host_process(code: &'static str) {
    if !allowed_browser_host_code(code) {
        return;
    }
    let Some(local_data) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let directory = PathBuf::from(local_data).join(APP_IDENTIFIER).join("logs");
    if fs::create_dir_all(&directory).is_ok() {
        let _ = append_event(&directory.join(DIAGNOSTIC_FILE), "browser_host", code);
    }
}

pub fn record(app: &AppHandle, input: DiagnosticInput) -> DiagnosticResult<()> {
    if !allowed_operation(&input.operation) || !allowed_code(&input.code) {
        return Err("Sesame rejected an unsupported diagnostic event.".into());
    }
    append_event(&diagnostic_path(app)?, &input.operation, &input.code)
}

pub fn status(app: &AppHandle) -> DiagnosticResult<DiagnosticStatus> {
    let path = diagnostic_path(app)?;
    let metadata = fs::metadata(&path).ok();
    let content = fs::read_to_string(&path).unwrap_or_default();
    let (event_count, error_count, by_operation, by_code, recent) = summarise(&content);
    Ok(DiagnosticStatus {
        exists: metadata.is_some(),
        event_count,
        error_count,
        size_bytes: metadata.map(|value| value.len()).unwrap_or(0),
        local_only: true,
        by_operation,
        by_code,
        recent,
    })
}

fn summarise(
    content: &str,
) -> (
    usize,
    usize,
    Vec<OperationCount>,
    Vec<CodeCount>,
    Vec<RecentEvent>,
) {
    let mut event_count = 0;
    let mut error_count = 0;
    let mut by_operation: HashMap<String, (usize, usize)> = HashMap::new();
    let mut by_code: HashMap<String, (usize, String)> = HashMap::new();
    let mut all: Vec<RecentEvent> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(event) = serde_json::from_str::<StoredEvent>(trimmed) else {
            continue;
        };
        event_count += 1;
        let level = event
            .level
            .clone()
            .unwrap_or_else(|| severity(&event.code).to_string());
        let is_error = level == "error";
        if is_error {
            error_count += 1;
        }
        let operation = if event.operation.is_empty() {
            "unknown"
        } else {
            event.operation.as_str()
        };
        let operation_entry = by_operation.entry(operation.to_string()).or_insert((0, 0));
        operation_entry.0 += 1;
        if is_error {
            operation_entry.1 += 1;
        }
        let code_entry = by_code
            .entry(event.code.clone())
            .or_insert((0, level.clone()));
        code_entry.0 += 1;
        all.push(RecentEvent {
            timestamp: event.timestamp,
            operation: event.operation,
            code: event.code,
            level,
        });
    }
    let mut operations: Vec<OperationCount> = by_operation
        .into_iter()
        .map(|(operation, (count, errors))| OperationCount {
            operation,
            count,
            error_count: errors,
        })
        .collect();
    operations.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.operation.cmp(&b.operation))
    });
    let mut codes: Vec<CodeCount> = by_code
        .into_iter()
        .map(|(code, (count, level))| CodeCount { code, count, level })
        .collect();
    codes.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.code.cmp(&b.code)));
    all.reverse();
    all.truncate(10);
    (event_count, error_count, operations, codes, all)
}

fn prune_stale_at(path: &Path, now: u64) -> DiagnosticResult<()> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Sesame could not read its local diagnostic log.".into()),
    };
    let cutoff = now.saturating_sub(DIAGNOSTIC_RETENTION_SECS);
    let mut kept = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let keep = match serde_json::from_str::<StoredEvent>(trimmed) {
            Ok(event) => event.is_error() || event.timestamp >= cutoff,
            // Keep anything that cannot be parsed rather than lose a record.
            Err(_) => true,
        };
        if keep {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    if kept.is_empty() {
        return match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("Sesame could not clear the local diagnostic log.".into()),
        };
    }
    fs::write(path, kept).map_err(|_| "Sesame could not tidy its local diagnostic log.".to_string())
}

pub fn export(app: &AppHandle, destination: &str) -> DiagnosticResult<String> {
    let source = diagnostic_path(app)?;
    if !source.is_file() {
        return Err("There is no local diagnostic log to export yet.".into());
    }
    let destination = PathBuf::from(destination);
    if destination.extension().and_then(|value| value.to_str()) != Some("jsonl") {
        return Err("Save the diagnostic log with a .jsonl extension.".into());
    }
    fs::copy(&source, &destination)
        .map_err(|_| "Sesame could not export the local diagnostic log.".to_string())?;
    destination
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_string)
        .ok_or_else(|| "Sesame exported the log, but could not read its file name.".to_string())
}

pub fn clear(app: &AppHandle) -> DiagnosticResult<()> {
    let path = diagnostic_path(app)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Sesame could not clear the local diagnostic log.".into()),
    }
}

fn diagnostic_path(app: &AppHandle) -> DiagnosticResult<PathBuf> {
    let directory = app
        .path()
        .app_log_dir()
        .map_err(|_| "Sesame could not open its local diagnostic folder.".to_string())?;
    fs::create_dir_all(&directory)
        .map_err(|_| "Sesame could not create its local diagnostic folder.".to_string())?;
    Ok(directory.join(DIAGNOSTIC_FILE))
}

fn append_event(path: &Path, operation: &str, code: &str) -> DiagnosticResult<()> {
    append_event_with_site(path, operation, code, None)
}

fn append_event_with_site(
    path: &Path,
    operation: &str,
    code: &str,
    crash_site: Option<u64>,
) -> DiagnosticResult<()> {
    if fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
        >= MAX_DIAGNOSTIC_BYTES
    {
        // Keep the most recent half rather than discarding all history at the cap.
        if let Ok(content) = fs::read_to_string(path) {
            let lines: Vec<&str> = content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect();
            let tail: String = lines[lines.len() / 2..]
                .iter()
                .map(|line| format!("{line}\n"))
                .collect();
            fs::write(path, tail)
                .map_err(|_| "Sesame could not rotate its local diagnostic log.".to_string())?;
        }
    }
    let event = DiagnosticEvent {
        timestamp: unix_now(),
        version: env!("CARGO_PKG_VERSION"),
        platform: std::env::consts::OS,
        session: session_id(),
        operation,
        code,
        level: severity(code),
        crash_site,
    };
    let line = serde_json::to_string(&event)
        .map_err(|_| "Sesame could not prepare a diagnostic event.".to_string())?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| "Sesame could not write its local diagnostic log.".to_string())?;
    writeln!(file, "{line}")
        .map_err(|_| "Sesame could not write its local diagnostic log.".to_string())
}

fn allowed_operation(value: &str) -> bool {
    matches!(
        value,
        "app"
            | "runtime"
            | "renderer"
            | "ui"
            | "import_preview"
            | "import_commit"
            | "totp_refresh"
            | "vault_open"
            | "vault_save"
            | "backup"
            | "restore"
            | "export"
            | "clipboard"
            | "browser_host"
    )
}

fn allowed_code(value: &str) -> bool {
    matches!(
        value,
        "started"
            | "panic"
            | "unhandled_exception"
            | "unhandled_rejection"
            | "handled_error"
            | "failed"
            | "invalid_file"
            | "io_error"
            | "registration_ok"
            | "registration_host_missing"
            | "registration_manifest_failed"
            | "registration_registry_failed"
            | "registration_status_failed"
            | "registration_unsupported"
            | "host_started"
            | "host_response_sent"
            | "host_no_request"
            | "host_protocol_error"
            | "host_io_error"
            | "host_origin_rejected"
            | "pipe_server_started"
            | "pipe_server_failed"
            | "fill_requested"
            | "fill_locked"
            | "fill_no_match"
            | "fill_approved"
            | "fill_denied"
            | "fill_timeout"
            | "fill_connection_closed"
            | "fill_vault_changed"
            | "fill_listener_failed"
            | "save_listener_failed"
            | "identity_fill_listener_failed"
            | "vault_lock_listener_failed"
            | "idle_warning_listener_failed"
    )
}

fn allowed_browser_host_code(value: &str) -> bool {
    matches!(
        value,
        "registration_ok"
            | "registration_host_missing"
            | "registration_manifest_failed"
            | "registration_registry_failed"
            | "registration_status_failed"
            | "registration_unsupported"
            | "host_started"
            | "host_response_sent"
            | "host_no_request"
            | "host_protocol_error"
            | "host_io_error"
            | "host_origin_rejected"
            | "pipe_server_started"
            | "pipe_server_failed"
            | "fill_requested"
            | "fill_locked"
            | "fill_no_match"
            | "fill_approved"
            | "fill_denied"
            | "fill_timeout"
            | "fill_connection_closed"
            | "fill_vault_changed"
            | "fill_listener_failed"
            | "save_requested"
            | "save_approved"
            | "save_denied"
            | "save_locked"
            | "save_update_no_match"
            | "save_timeout"
            | "save_connection_closed"
            | "save_vault_changed"
            | "identity_requested"
            | "identity_approved"
            | "identity_denied"
            | "identity_locked"
            | "identity_no_match"
            | "identity_timeout"
            | "identity_connection_closed"
            | "identity_vault_changed"
    )
}
