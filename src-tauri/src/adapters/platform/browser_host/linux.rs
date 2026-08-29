use std::ffi::OsStr;
use std::path::PathBuf;

use super::{plan_registration, RegistrationError, RegistrationPlan, RegistrationState, HOST_NAME};

pub const HOST_FILE_NAME: &str = "sesame-browser-host";

pub fn is_supported() -> bool {
    linux_install_supported(std::env::var_os("APPIMAGE").as_deref())
}

fn linux_install_supported(appimage: Option<&OsStr>) -> bool {
    appimage.is_none()
}

pub fn unsupported_error() -> RegistrationError {
    RegistrationError::new(
        "registration_unsupported",
        "Browser connection requires an installed Linux package.",
    )
}

pub fn plan() -> Result<RegistrationPlan, RegistrationError> {
    let host = std::env::current_exe()
        .map(|executable| executable.with_file_name(HOST_FILE_NAME))
        .map_err(|_| {
            RegistrationError::new(
                "registration_host_missing",
                "Sesame could not locate its browser helper.",
            )
        })?;
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        RegistrationError::new(
            "registration_manifest_failed",
            "Sesame could not locate your home directory.",
        )
    })?;
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let file = format!("{HOST_NAME}.json");
    let chromium = |vendor: &str| config.join(vendor).join("NativeMessagingHosts").join(&file);
    Ok(RegistrationPlan {
        host,
        chrome: vec![chromium("google-chrome"), chromium("chromium")],
        edge: vec![chromium("microsoft-edge")],
        firefox: vec![home
            .join(".mozilla")
            .join("native-messaging-hosts")
            .join(&file)],
    })
}

pub fn commit(_plan: &RegistrationPlan) -> Result<(), RegistrationError> {
    Ok(())
}

pub fn registry_keys() -> &'static [&'static str] {
    &[]
}

pub fn erase(_keys: &[&str]) -> Result<(), RegistrationError> {
    Ok(())
}

pub fn matches(plan: &RegistrationPlan) -> RegistrationState {
    let (chrome, edge, firefox) = plan_registration(plan);
    RegistrationState {
        manifest_ready: plan.host.is_file(),
        chrome_registered: chrome,
        edge_registered: edge,
        firefox_registered: firefox,
    }
}

pub fn verification_failed_code() -> &'static str {
    "registration_manifest_failed"
}

pub fn launch_desktop_app() -> bool {
    let Ok(host_executable) = std::env::current_exe() else {
        return false;
    };
    let app_executable = host_executable.with_file_name("sesame");
    app_executable.is_file() && std::process::Command::new(app_executable).spawn().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use super::super::{manifest_matches, write_plan_manifests};

    #[test]
    fn an_appimage_mount_is_not_registered_as_a_persistent_browser_host() {
        assert!(linux_install_supported(None));
        assert!(!linux_install_supported(Some(OsStr::new(
            "/tmp/Sesame.AppImage"
        ))));
    }

    fn scratch_plan(name: &str, host_file: &str) -> RegistrationPlan {
        let root =
            std::env::temp_dir().join(format!("sesame-host-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("a scratch directory");
        let manifest = format!("{HOST_NAME}.json");
        let chromium = |vendor: &str| {
            root.join(vendor)
                .join("NativeMessagingHosts")
                .join(&manifest)
        };
        RegistrationPlan {
            host: root.join(host_file),
            chrome: vec![chromium("google-chrome")],
            edge: vec![chromium("microsoft-edge")],
            firefox: vec![root
                .join(".mozilla")
                .join("native-messaging-hosts")
                .join(&manifest)],
        }
    }

    #[test]
    fn an_unwritten_plan_matches_no_browser() {
        let state = matches(&scratch_plan("unwritten", "sesame-browser-host"));
        assert!(!state.manifest_ready);
        assert!(!state.chrome_registered);
        assert!(!state.edge_registered);
        assert!(!state.firefox_registered);
    }

    #[test]
    fn a_committed_plan_matches_every_browser_it_named() {
        let plan = scratch_plan("committed", "sesame-browser-host");
        fs::write(&plan.host, b"host").expect("a placeholder host");
        write_plan_manifests(&plan).expect("manifests written");

        let state = matches(&plan);
        assert!(state.manifest_ready);
        assert!(state.chrome_registered);
        assert!(state.edge_registered);
        assert!(state.firefox_registered);
    }

    #[test]
    fn a_manifest_written_for_one_host_does_not_match_another() {
        let plan = scratch_plan("other-host", "sesame-browser-host");
        write_plan_manifests(&plan).expect("manifests written");

        assert!(manifest_matches(&plan.chrome[0], &plan.host));
        assert!(!manifest_matches(
            &plan.chrome[0],
            &plan.host.with_file_name("sesame-browser-host-impostor")
        ));
    }

    #[test]
    fn a_tampered_manifest_stops_matching() {
        let plan = scratch_plan("tampered", "sesame-browser-host");
        write_plan_manifests(&plan).expect("manifests written");
        assert!(matches(&plan).firefox_registered);

        fs::write(&plan.firefox[0], b"not json").expect("a tampered manifest");
        assert!(!matches(&plan).firefox_registered);
    }

    #[test]
    fn cleanup_targets_every_location_a_commit_wrote_and_spares_the_host() {
        use super::super::{erase_registration, manifest_paths, RegistrationLocations};

        let plan = scratch_plan("cleanup", "sesame-browser-host");
        fs::write(&plan.host, b"host").expect("a placeholder host");
        write_plan_manifests(&plan).expect("manifests written");
        assert!(matches(&plan).chrome_registered);

        let locations = RegistrationLocations {
            manifests: manifest_paths(&plan),
            registry_keys: registry_keys().to_vec(),
        };
        assert_eq!(
            locations.manifests.len(),
            plan.chrome.len() + plan.edge.len() + plan.firefox.len()
        );

        erase_registration(&locations).expect("cleanup succeeds");

        let state = matches(&plan);
        assert!(!state.chrome_registered);
        assert!(!state.edge_registered);
        assert!(!state.firefox_registered);
        assert!(plan.host.is_file());
    }
}
