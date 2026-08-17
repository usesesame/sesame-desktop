use serde::Serialize;

const PORT_ENV: &str = "SESAME_DESKTOP_E2E_PORT";
const TOKEN_ENV: &str = "SESAME_DESKTOP_E2E_TOKEN";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopE2eConfig {
    port: u16,
    token: String,
}

/// Test bridge compiled only under `wdio`; release binaries contain no loopback control surface.
#[tauri::command]
pub fn desktop_e2e_config() -> Result<DesktopE2eConfig, String> {
    let port = std::env::var(PORT_ENV)
        .map_err(|_| "The desktop E2E port is not configured.".to_string())?
        .parse::<u16>()
        .map_err(|_| "The desktop E2E port is not valid.".to_string())?;
    if port == 0 {
        return Err("The desktop E2E port is not valid.".to_string());
    }

    let token = std::env::var(TOKEN_ENV)
        .map_err(|_| "The desktop E2E token is not configured.".to_string())?;
    if !(32..=128).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("The desktop E2E token is not valid.".to_string());
    }

    Ok(DesktopE2eConfig { port, token })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_names_are_specific_to_the_test_bridge() {
        assert_eq!(PORT_ENV, "SESAME_DESKTOP_E2E_PORT");
        assert_eq!(TOKEN_ENV, "SESAME_DESKTOP_E2E_TOKEN");
    }
}
