use std::ffi::{OsStr, OsString};

const BLOCKED_VARIABLES: [&str; 6] = [
    "TAURI_WEBVIEW_AUTOMATION",
    "WEBKIT_INSPECTOR_SERVER",
    "WEBKIT_INSPECTOR_HTTP_SERVER",
    "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS",
    "WEBKIT_ENABLE_DEBUG_PERMISSIONS_IN_SANDBOX",
    "WEBKIT_INJECTED_BUNDLE_PATH",
];

const BLOCKED_PREFIXES: [&str; 1] = ["JSC_"];

fn is_blocked(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    BLOCKED_VARIABLES.contains(&name)
        || BLOCKED_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

fn scrub(names: impl IntoIterator<Item = OsString>, mut remove: impl FnMut(&OsStr)) {
    for name in names {
        if is_blocked(&name) {
            remove(&name);
        }
    }
}

pub(crate) fn remove_inspection_variables() {
    let names: Vec<OsString> = std::env::vars_os().map(|(name, _)| name).collect();
    scrub(names, |name| std::env::remove_var(name));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fictional_environment() -> BTreeMap<OsString, OsString> {
        [
            ("TAURI_WEBVIEW_AUTOMATION", "true"),
            ("WEBKIT_INSPECTOR_SERVER", "127.0.0.1:9222"),
            ("WEBKIT_INSPECTOR_HTTP_SERVER", "127.0.0.1:9223"),
            ("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "1"),
            ("WEBKIT_ENABLE_DEBUG_PERMISSIONS_IN_SANDBOX", "1"),
            ("WEBKIT_INJECTED_BUNDLE_PATH", "/tmp/fictional-bundle"),
            ("JSC_useDollarVM", "true"),
            ("JSC_dumpOptions", "2"),
            ("WEBKIT_DISABLE_DMABUF_RENDERER", "1"),
            ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
            ("WEBKIT_FORCE_SANDBOX", "1"),
            ("HOME", "/home/fictional"),
            ("PATH", "/usr/bin"),
            ("SESAME_DESKTOP_E2E_PORT", "4444"),
            ("TAURI_WEBVIEW_AUTOMATION_NOTES", "kept"),
            ("jsc_lowercase", "kept"),
        ]
        .into_iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect()
    }

    fn scrubbed(mut environment: BTreeMap<OsString, OsString>) -> BTreeMap<OsString, OsString> {
        let names: Vec<OsString> = environment.keys().cloned().collect();
        scrub(names, |name| {
            environment.remove(name);
        });
        environment
    }

    #[test]
    fn inspection_and_automation_variables_are_absent_after_the_scrub() {
        let environment = scrubbed(fictional_environment());
        for name in [
            "TAURI_WEBVIEW_AUTOMATION",
            "WEBKIT_INSPECTOR_SERVER",
            "WEBKIT_INSPECTOR_HTTP_SERVER",
            "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS",
            "WEBKIT_ENABLE_DEBUG_PERMISSIONS_IN_SANDBOX",
            "WEBKIT_INJECTED_BUNDLE_PATH",
        ] {
            assert!(!environment.contains_key(OsStr::new(name)), "{name}");
        }
        assert!(!environment.contains_key(OsStr::new("JSC_useDollarVM")));
        assert!(!environment.contains_key(OsStr::new("JSC_dumpOptions")));
    }

    #[test]
    fn unrelated_variables_and_rendering_workarounds_stay() {
        let environment = scrubbed(fictional_environment());
        let kept: Vec<&str> = environment
            .keys()
            .filter_map(|name| name.to_str())
            .collect();
        assert_eq!(
            kept,
            [
                "HOME",
                "PATH",
                "SESAME_DESKTOP_E2E_PORT",
                "TAURI_WEBVIEW_AUTOMATION_NOTES",
                "WEBKIT_DISABLE_COMPOSITING_MODE",
                "WEBKIT_DISABLE_DMABUF_RENDERER",
                "WEBKIT_FORCE_SANDBOX",
                "jsc_lowercase",
            ]
        );
    }

    #[test]
    fn only_the_exact_automation_name_is_matched() {
        assert!(is_blocked(OsStr::new("TAURI_WEBVIEW_AUTOMATION")));
        assert!(!is_blocked(OsStr::new("tauri_webview_automation")));
        assert!(!is_blocked(OsStr::new("TAURI_WEBVIEW_AUTOMATION_X")));
    }

    #[cfg(unix)]
    #[test]
    fn names_that_are_not_utf8_are_left_alone() {
        use std::os::unix::ffi::OsStringExt;
        assert!(!is_blocked(&OsString::from_vec(b"JSC_\xff".to_vec())));
    }

    #[test]
    fn the_process_environment_loses_the_blocked_variables() {
        std::env::set_var("TAURI_WEBVIEW_AUTOMATION", "true");
        std::env::set_var("WEBKIT_INSPECTOR_SERVER", "127.0.0.1:9222");
        std::env::set_var("JSC_useDollarVM", "true");
        std::env::set_var("SESAME_WEBVIEW_ENVIRONMENT_TEST_KEEP", "kept");

        remove_inspection_variables();

        assert!(std::env::var_os("TAURI_WEBVIEW_AUTOMATION").is_none());
        assert!(std::env::var_os("WEBKIT_INSPECTOR_SERVER").is_none());
        assert!(std::env::var_os("JSC_useDollarVM").is_none());
        assert_eq!(
            std::env::var("SESAME_WEBVIEW_ENVIRONMENT_TEST_KEEP").as_deref(),
            Ok("kept")
        );
        std::env::remove_var("SESAME_WEBVIEW_ENVIRONMENT_TEST_KEEP");
    }
}
