use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use tauri::AppHandle;
use zeroize::Zeroize;

use crate::vault::capabilities::require_desktop_linking;
use crate::vault::platform::protect_for_device;
use crate::vault::service::{
    read_service_connection, read_service_token, remove_service_connection, service_api_base_url,
    service_client, write_service_connection,
};
use crate::vault::{
    DesktopLinkResponse, DesktopServiceStatusResponse, ServiceConnectionFile,
    ServiceConnectionStatus, VaultResult, SERVICE_CONNECTION_FORMAT_VERSION,
};

const LINK_CODE_MIN_LENGTH: usize = 32;
const LINK_CODE_MAX_LENGTH: usize = 128;

fn validated_link_code(raw: &str) -> VaultResult<String> {
    let code = raw.trim();
    if code.len() < LINK_CODE_MIN_LENGTH || code.len() > LINK_CODE_MAX_LENGTH {
        return Err("Enter the one-time desktop code from your Sesame account.".into());
    }
    Ok(code.to_string())
}

fn platform_label(os: &str) -> &str {
    match os {
        "windows" => "Windows",
        "linux" => "Linux",
        "macos" => "macOS",
        other => other,
    }
}

fn default_device_name_for(os: &str) -> String {
    format!("{} desktop", platform_label(os))
}

fn default_device_name() -> String {
    default_device_name_for(std::env::consts::OS)
}

#[tauri::command]
pub async fn link_desktop_service(
    app: AppHandle,
    code: String,
) -> VaultResult<ServiceConnectionStatus> {
    let code = validated_link_code(&code)?;
    // A valid code is not sufficient when the signed capability document disables linking.
    require_desktop_linking().await?;
    let api_base_url = service_api_base_url()?;
    let client = service_client()?;
    let response = client
        .post(format!("{api_base_url}/v1/desktop/link"))
        .json(&serde_json::json!({ "code": code, "deviceName": default_device_name() }))
        .send()
        .await
        .map_err(|_| {
            "Sesame could not reach the account service. Check your connection and try again."
                .to_string()
        })?;
    if !response.status().is_success() {
        return Err("That desktop code is invalid, expired, or has already been used.".into());
    }
    let mut linked: DesktopLinkResponse = response
        .json()
        .await
        .map_err(|_| "Sesame could not read the account service response.".to_string())?;
    if linked.access_token.is_empty()
        || linked.device.device_id.is_empty()
        || linked.device.device_name.is_empty()
    {
        linked.access_token.zeroize();
        return Err("The account service returned an incomplete desktop connection.".into());
    }
    let token_bytes = linked.access_token.as_bytes().to_vec();
    let protected_token = protect_for_device(&token_bytes)?;
    let mut token_bytes = token_bytes;
    token_bytes.zeroize();
    linked.access_token.zeroize();
    write_service_connection(
        &app,
        &ServiceConnectionFile {
            format_version: SERVICE_CONNECTION_FORMAT_VERSION,
            api_base_url,
            protected_token: URL_SAFE_NO_PAD.encode(protected_token),
            device_id: linked.device.device_id,
            device_name: linked.device.device_name.clone(),
        },
    )?;
    Ok(ServiceConnectionStatus {
        state: "connected".into(),
        connected: true,
        online: true,
        device_name: Some(linked.device.device_name),
        sync_available: linked.sync_available,
        browser_helper_available: false,
    })
}

#[tauri::command]
pub async fn get_service_connection_status(app: AppHandle) -> VaultResult<ServiceConnectionStatus> {
    let connection = match read_service_connection(&app) {
        Ok(connection) => connection,
        Err(_) => {
            return Ok(ServiceConnectionStatus {
                state: "disconnected".into(),
                connected: false,
                online: false,
                device_name: None,
                sync_available: false,
                browser_helper_available: false,
            })
        }
    };
    let mut token = read_service_token(&connection)?;
    let client = service_client()?;
    // Heartbeat reports desktop capability, not extension installation.
    let heartbeat = client
        .post(format!("{}/v1/desktop/heartbeat", connection.api_base_url))
        .header("Authorization", format!("Sesame {token}"))
        .json(&serde_json::json!({
            "appVersion": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
            "updateChannel": "beta",
            "protocolVersion": 1,
            "browserHelperCapable": true,
            "browserHelperObserved": false,
        }))
        .send()
        .await;
    if matches!(heartbeat, Ok(ref response) if response.status().as_u16() == 401) {
        token.zeroize();
        let _ = remove_service_connection(&app);
        return Ok(ServiceConnectionStatus {
            state: "revoked".into(),
            connected: false,
            online: true,
            device_name: None,
            sync_available: false,
            browser_helper_available: false,
        });
    }
    let result = client
        .get(format!("{}/v1/desktop/status", connection.api_base_url))
        .header("Authorization", format!("Sesame {token}"))
        .send()
        .await;
    token.zeroize();
    match result {
        Ok(response) if response.status().is_success() => {
            let status: DesktopServiceStatusResponse = response
                .json()
                .await
                .map_err(|_| "Sesame could not read the account service response.".to_string())?;
            Ok(ServiceConnectionStatus {
                state: if status.connected {
                    "connected"
                } else {
                    "revoked"
                }
                .into(),
                connected: status.connected,
                online: true,
                device_name: Some(status.device.device_name),
                sync_available: status.sync_available,
                browser_helper_available: status.browser_helper_available,
            })
        }
        Ok(response) if response.status().as_u16() == 401 => {
            let _ = remove_service_connection(&app);
            Ok(ServiceConnectionStatus {
                state: "revoked".into(),
                connected: false,
                online: true,
                device_name: None,
                sync_available: false,
                browser_helper_available: false,
            })
        }
        Ok(response) if response.status().as_u16() == 423 => Ok(ServiceConnectionStatus {
            state: "suspended".into(),
            connected: true,
            online: true,
            device_name: Some(connection.device_name),
            sync_available: false,
            browser_helper_available: false,
        }),
        Ok(response) if response.status().as_u16() == 429 => Ok(ServiceConnectionStatus {
            state: "rateLimited".into(),
            connected: true,
            online: true,
            device_name: Some(connection.device_name),
            sync_available: false,
            browser_helper_available: false,
        }),
        Ok(response) if response.status().is_server_error() => Ok(ServiceConnectionStatus {
            state: "serviceUnavailable".into(),
            connected: true,
            online: true,
            device_name: Some(connection.device_name),
            sync_available: false,
            browser_helper_available: false,
        }),
        Ok(_) => Ok(ServiceConnectionStatus {
            state: "needsAttention".into(),
            connected: true,
            online: true,
            device_name: Some(connection.device_name),
            sync_available: false,
            browser_helper_available: false,
        }),
        Err(_) => Ok(ServiceConnectionStatus {
            state: "offline".into(),
            connected: true,
            online: false,
            device_name: Some(connection.device_name),
            sync_available: false,
            browser_helper_available: false,
        }),
    }
}

#[tauri::command]
pub async fn disconnect_service(app: AppHandle) -> VaultResult<()> {
    let connection = match read_service_connection(&app) {
        Ok(connection) => connection,
        Err(_) => return Ok(()),
    };
    if let Ok(mut token) = read_service_token(&connection) {
        if let Ok(client) = service_client() {
            let _ = client
                .delete(format!("{}/v1/desktop/connection", connection.api_base_url))
                .header("Authorization", format!("Sesame {token}"))
                .send()
                .await;
        }
        token.zeroize();
    }
    remove_service_connection(&app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_codes_outside_the_length_bounds_are_refused() {
        assert!(validated_link_code("").is_err());
        assert!(validated_link_code(&"a".repeat(LINK_CODE_MIN_LENGTH - 1)).is_err());
        assert!(validated_link_code(&"a".repeat(LINK_CODE_MAX_LENGTH + 1)).is_err());
    }

    #[test]
    fn a_link_code_is_trimmed_before_its_length_is_checked() {
        let code = format!("  {}  ", "a".repeat(LINK_CODE_MIN_LENGTH));
        assert_eq!(
            validated_link_code(&code).unwrap(),
            "a".repeat(LINK_CODE_MIN_LENGTH)
        );
        let padded_short = format!("  {}  ", "a".repeat(LINK_CODE_MIN_LENGTH - 1));
        assert!(validated_link_code(&padded_short).is_err());
    }

    #[test]
    fn the_default_device_name_names_the_platform() {
        assert_eq!(default_device_name_for("windows"), "Windows desktop");
        assert_eq!(default_device_name_for("linux"), "Linux desktop");
        assert_eq!(default_device_name_for("macos"), "macOS desktop");
        assert_eq!(default_device_name_for("freebsd"), "freebsd desktop");
        assert_eq!(
            default_device_name(),
            default_device_name_for(std::env::consts::OS)
        );
    }
}
