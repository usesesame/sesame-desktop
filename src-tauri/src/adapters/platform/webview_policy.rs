pub const WEBVIEW2_BROWSER_ARGUMENTS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --autoplay-policy=no-user-gesture-required --js-flags=--jitless";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayAffinity {
    ExcludeFromCapture,
    Unrestricted,
}

pub fn display_affinity(capture_allowed: bool) -> DisplayAffinity {
    if capture_allowed {
        DisplayAffinity::Unrestricted
    } else {
        DisplayAffinity::ExcludeFromCapture
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRY_DEFAULT_ARGUMENTS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --autoplay-policy=no-user-gesture-required";

    #[test]
    fn the_arguments_keep_the_wry_defaults_and_add_jitless_once() {
        assert!(WEBVIEW2_BROWSER_ARGUMENTS.starts_with(WRY_DEFAULT_ARGUMENTS));
        assert_eq!(
            WEBVIEW2_BROWSER_ARGUMENTS,
            format!("{WRY_DEFAULT_ARGUMENTS} --js-flags=--jitless")
        );
        assert_eq!(WEBVIEW2_BROWSER_ARGUMENTS.matches("--js-flags").count(), 1);
    }

    #[test]
    fn the_arguments_have_no_stray_whitespace() {
        assert_eq!(
            WEBVIEW2_BROWSER_ARGUMENTS,
            WEBVIEW2_BROWSER_ARGUMENTS.trim()
        );
        assert!(!WEBVIEW2_BROWSER_ARGUMENTS.contains("  "));
    }

    #[test]
    fn capture_is_excluded_unless_the_user_allows_it() {
        assert_eq!(display_affinity(false), DisplayAffinity::ExcludeFromCapture);
        assert_eq!(display_affinity(true), DisplayAffinity::Unrestricted);
    }
}
