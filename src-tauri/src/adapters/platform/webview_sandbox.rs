use std::{
    io::Read,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

const BWRAP: &str = "/usr/bin/bwrap";
const DBUS_PROXY: &str = "/usr/bin/xdg-dbus-proxy";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const REASON_LIMIT: usize = 200;

const REMOVED_VARIABLES: [&str; 1] = ["WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"];
const FORCED_VARIABLES: [(&str, &str); 2] = [("WEBKIT_FORCE_SANDBOX", "1"), ("JSC_useJIT", "0")];

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SandboxUnavailable {
    MissingTool(&'static str),
    Refused(String),
    TimedOut,
}

impl SandboxUnavailable {
    fn detail(&self) -> String {
        match self {
            Self::MissingTool(name) => format!("{name} is not installed."),
            Self::Refused(reason) if reason.is_empty() => {
                "bubblewrap exited without starting a sandbox.".to_string()
            }
            Self::Refused(reason) => format!("bubblewrap reported: {reason}"),
            Self::TimedOut => "bubblewrap did not start a sandbox in time.".to_string(),
        }
    }

    pub(crate) fn message(&self) -> String {
        format!(
            "Sesame did not start because the sandbox for its web view is not available. {} \
             Install bubblewrap and xdg-dbus-proxy and allow unprivileged user namespaces. \
             On Ubuntu 24.04 and later, set kernel.apparmor_restrict_unprivileged_userns to 0 \
             or give /usr/bin/bwrap an AppArmor profile that allows user namespaces.",
            self.detail()
        )
    }
}

fn configure_environment(mut remove: impl FnMut(&str), mut set: impl FnMut(&str, &str)) {
    for name in REMOVED_VARIABLES {
        remove(name);
    }
    for (name, value) in FORCED_VARIABLES {
        set(name, value);
    }
}

fn probe(bwrap: &Path, dbus_proxy: &Path, timeout: Duration) -> Result<(), SandboxUnavailable> {
    if !bwrap.is_file() {
        return Err(SandboxUnavailable::MissingTool("bubblewrap"));
    }
    if !dbus_proxy.is_file() {
        return Err(SandboxUnavailable::MissingTool("xdg-dbus-proxy"));
    }
    let mut child = Command::new(bwrap)
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "/usr/bin/true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| SandboxUnavailable::Refused(error.to_string()))?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(SandboxUnavailable::Refused(first_line(&mut child))),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxUnavailable::TimedOut);
            }
            Err(error) => return Err(SandboxUnavailable::Refused(error.to_string())),
        }
    }
}

fn first_line(child: &mut std::process::Child) -> String {
    let mut text = String::new();
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(1024).read_to_string(&mut text);
    }
    text.lines()
        .next()
        .unwrap_or_default()
        .trim()
        .chars()
        .take(REASON_LIMIT)
        .collect()
}

fn configure_process_environment() {
    configure_environment(
        |name| std::env::remove_var(name),
        |name, value| std::env::set_var(name, value),
    );
}

pub(crate) fn prepare() -> Result<(), SandboxUnavailable> {
    configure_process_environment();
    probe(Path::new(BWRAP), Path::new(DBUS_PROXY), PROBE_TIMEOUT)
}

pub(crate) fn refuse(mut context: tauri::Context<tauri::Wry>, unavailable: SandboxUnavailable) {
    let message = unavailable.message();
    eprintln!("{message}");
    context.config_mut().app.windows.clear();
    let shown = message.clone();
    let built = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            let handle = app.handle().clone();
            app.dialog()
                .message(shown)
                .title("Sesame")
                .kind(MessageDialogKind::Error)
                .show(move |_| handle.exit(1));
            Ok(())
        })
        .build(context);
    match built {
        Ok(app) => app.run(|_, _| {}),
        Err(_) => std::process::exit(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, path::PathBuf};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sesame-webview-sandbox-{}",
                crate::vault::random_id()
            ));
            std::fs::create_dir_all(&path).expect("scratch directory");
            Self(path)
        }

        fn executable(&self, name: &str, body: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("mode");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn configured(mut environment: BTreeMap<String, String>) -> BTreeMap<String, String> {
        let removals = std::cell::RefCell::new(Vec::new());
        let additions = std::cell::RefCell::new(Vec::new());
        configure_environment(
            |name| removals.borrow_mut().push(name.to_string()),
            |name, value| {
                additions
                    .borrow_mut()
                    .push((name.to_string(), value.to_string()))
            },
        );
        for name in removals.into_inner() {
            environment.remove(&name);
        }
        environment.extend(additions.into_inner());
        environment
    }

    fn hostile_environment() -> BTreeMap<String, String> {
        [
            ("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "1"),
            ("WEBKIT_FORCE_SANDBOX", "0"),
            ("JSC_useJIT", "1"),
            ("JSC_dumpOptions", "2"),
            ("HOME", "/home/fictional"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
    }

    #[test]
    fn the_sandbox_is_forced_and_the_disable_variable_is_removed() {
        let environment = configured(hostile_environment());
        assert_eq!(
            environment.get("WEBKIT_FORCE_SANDBOX").map(String::as_str),
            Some("1")
        );
        assert!(!environment.contains_key("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"));
    }

    #[test]
    fn the_jit_is_switched_off_over_any_inherited_value() {
        let environment = configured(hostile_environment());
        assert_eq!(environment.get("JSC_useJIT").map(String::as_str), Some("0"));
    }

    #[test]
    fn other_variables_are_left_alone() {
        let environment = configured(hostile_environment());
        assert_eq!(
            environment.get("HOME").map(String::as_str),
            Some("/home/fictional")
        );
        assert_eq!(
            environment.get("JSC_dumpOptions").map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn the_process_environment_is_forced() {
        std::env::set_var("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "1");
        std::env::set_var("WEBKIT_FORCE_SANDBOX", "0");
        std::env::set_var("JSC_useJIT", "1");
        configure_process_environment();
        assert!(std::env::var_os("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS").is_none());
        assert_eq!(std::env::var("WEBKIT_FORCE_SANDBOX").as_deref(), Ok("1"));
        assert_eq!(std::env::var("JSC_useJIT").as_deref(), Ok("0"));
    }

    #[test]
    fn a_missing_bubblewrap_is_refused() {
        let scratch = Scratch::new();
        let proxy = scratch.executable("proxy", "exit 0");
        assert_eq!(
            probe(&scratch.0.join("absent"), &proxy, Duration::from_secs(5)),
            Err(SandboxUnavailable::MissingTool("bubblewrap"))
        );
    }

    #[test]
    fn a_missing_dbus_proxy_is_refused() {
        let scratch = Scratch::new();
        let bwrap = scratch.executable("bwrap", "exit 0");
        assert_eq!(
            probe(&bwrap, &scratch.0.join("absent"), Duration::from_secs(5)),
            Err(SandboxUnavailable::MissingTool("xdg-dbus-proxy"))
        );
    }

    #[test]
    fn a_bubblewrap_that_starts_the_sandbox_is_accepted() {
        let scratch = Scratch::new();
        let bwrap = scratch.executable("bwrap", "exit 0");
        let proxy = scratch.executable("proxy", "exit 0");
        assert_eq!(probe(&bwrap, &proxy, Duration::from_secs(5)), Ok(()));
    }

    #[test]
    fn a_blocked_user_namespace_is_refused_with_the_reason() {
        let scratch = Scratch::new();
        let bwrap = scratch.executable(
            "bwrap",
            "echo 'bwrap: setting up uid map: Permission denied' >&2\necho second line >&2\nexit 1",
        );
        let proxy = scratch.executable("proxy", "exit 0");
        assert_eq!(
            probe(&bwrap, &proxy, Duration::from_secs(5)),
            Err(SandboxUnavailable::Refused(
                "bwrap: setting up uid map: Permission denied".to_string()
            ))
        );
    }

    #[test]
    fn a_bubblewrap_that_never_returns_is_stopped_and_refused() {
        let scratch = Scratch::new();
        let bwrap = scratch.executable("bwrap", "sleep 30");
        let proxy = scratch.executable("proxy", "exit 0");
        let started = Instant::now();
        assert_eq!(
            probe(&bwrap, &proxy, Duration::from_millis(200)),
            Err(SandboxUnavailable::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_reason_is_cut_to_the_limit() {
        let scratch = Scratch::new();
        let bwrap = scratch.executable("bwrap", "printf '%0400d' 0 >&2\nexit 1");
        let proxy = scratch.executable("proxy", "exit 0");
        let Err(SandboxUnavailable::Refused(reason)) =
            probe(&bwrap, &proxy, Duration::from_secs(5))
        else {
            panic!("expected a refusal");
        };
        assert_eq!(reason.chars().count(), REASON_LIMIT);
    }

    #[test]
    fn the_refusal_message_names_the_cause_and_the_ubuntu_rule() {
        let message =
            SandboxUnavailable::Refused("setting up uid map: Permission denied".into()).message();
        assert!(message.contains("setting up uid map: Permission denied"));
        assert!(message.contains("kernel.apparmor_restrict_unprivileged_userns"));
        assert!(SandboxUnavailable::MissingTool("bubblewrap")
            .message()
            .contains("bubblewrap is not installed."));
    }
}
