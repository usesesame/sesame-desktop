pub const DESKTOP_PLATFORM: &str = "desktop";
pub const ANDROID_PLATFORM: &str = "android";

pub fn minimum_for_platform<'a>(
    client_platform: &str,
    desktop_minimum: &'a str,
    android_minimum: Option<&'a str>,
) -> Option<&'a str> {
    if client_platform == ANDROID_PLATFORM {
        android_minimum
    } else {
        Some(desktop_minimum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_desktop_uses_the_desktop_minimum_and_ignores_the_android_one() {
        assert_eq!(
            minimum_for_platform(DESKTOP_PLATFORM, "0.5.1", Some("0.1.0")),
            Some("0.5.1")
        );
        assert_eq!(
            minimum_for_platform("windows", "0.5.1", Some("0.1.0")),
            Some("0.5.1")
        );
    }

    #[test]
    fn android_uses_only_its_own_optional_minimum() {
        assert_eq!(
            minimum_for_platform(ANDROID_PLATFORM, "0.5.1", Some("0.1.0")),
            Some("0.1.0")
        );
        assert_eq!(minimum_for_platform(ANDROID_PLATFORM, "0.5.1", None), None);
    }
}
