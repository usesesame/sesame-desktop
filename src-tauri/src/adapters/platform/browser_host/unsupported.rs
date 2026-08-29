use super::{RegistrationError, RegistrationPlan, RegistrationState};

pub const HOST_FILE_NAME: &str = "sesame-browser-host";

pub fn is_supported() -> bool {
    false
}

pub fn unsupported_error() -> RegistrationError {
    RegistrationError::new(
        "registration_unsupported",
        "Sesame browser integration is not available on this operating system.",
    )
}

pub fn plan() -> Result<RegistrationPlan, RegistrationError> {
    Err(unsupported_error())
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

pub fn matches(_plan: &RegistrationPlan) -> RegistrationState {
    RegistrationState {
        manifest_ready: false,
        chrome_registered: false,
        edge_registered: false,
        firefox_registered: false,
    }
}

pub fn verification_failed_code() -> &'static str {
    "registration_unsupported"
}

pub fn launch_desktop_app() -> bool {
    false
}
