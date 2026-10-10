use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use tauri::AppHandle;
use zeroize::Zeroize;

use super::server_address::{
    normalized_fingerprint, parse_pairing_input, validate_pairing_code, PairingInput,
};
use super::server_trust::{inspect_server, verify_pinned_server, InstanceInfo, ServerFailure};
use crate::vault::capabilities::require_desktop_linking;
use crate::vault::platform::protect_for_device;
use crate::vault::service::{
    bind_token_to_server, client_for_base, read_limited, read_service_connection,
    read_service_token, remove_service_connection, service_api_base_url, service_client,
    service_target, write_service_connection, ServiceTarget,
};
use crate::vault::{
    DesktopLinkResponse, DesktopServiceStatusResponse, ServiceConnectionFile,
    ServiceConnectionStatus, VaultResult, SERVICE_CONNECTION_FORMAT_VERSION,
};

const LINK_CODE_MIN_LENGTH: usize = 32;
const LINK_CODE_MAX_LENGTH: usize = 128;
const MAX_SERVICE_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_RETRY_AFTER_SECONDS: u64 = 24 * 60 * 60;

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct ServerInspection {
    pub address: String,
    pub name: String,
    pub version: String,
    pub fingerprint: String,
    pub fingerprint_in_link: bool,
    pub code_in_link: bool,
    pub plain_http: bool,
}

#[derive(Serialize, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct DisconnectOutcome {
    pub revoked_on_server: bool,
}

fn expiry_seconds(value: Option<&str>) -> Option<u64> {
    value
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
        .and_then(|moment| u64::try_from(moment.timestamp()).ok())
}

fn ended_state(connection: &ServiceConnectionFile, now: i64) -> &'static str {
    match connection.expires_at {
        Some(expires_at) if i64::try_from(expires_at).is_ok_and(|expires_at| expires_at <= now) => {
            "expired"
        }
        _ => "revoked",
    }
}

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

fn error_code(body: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct Envelope {
        #[serde(default)]
        error: Option<Detail>,
    }
    #[derive(serde::Deserialize)]
    struct Detail {
        #[serde(default)]
        code: String,
    }
    serde_json::from_slice::<Envelope>(body)
        .ok()
        .and_then(|envelope| envelope.error)
        .map(|detail| detail.code)
        .unwrap_or_default()
}

fn link_refusal(status: u16, code: &str, retry_after: Option<&str>) -> String {
    if status == 421 || code == "host_mismatch" {
        return "The address you entered is not the public address this server is set up with. Use the address your server's console shows.".into();
    }
    if status == 429 {
        return match retry_after
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|seconds| (1..=MAX_RETRY_AFTER_SECONDS).contains(seconds))
        {
            Some(1) => {
                "The server is limiting pairing attempts. Wait 1 second, then try again.".into()
            }
            Some(seconds) => format!(
                "The server is limiting pairing attempts. Wait {seconds} seconds, then try again."
            ),
            None => {
                "The server is limiting pairing attempts. Wait a moment, then try again.".into()
            }
        };
    }
    if code == "desktop_linking_disabled" {
        return "Pairing is switched off on this server. Turn it on in the server console, then try again.".into();
    }
    if status >= 500 {
        return "The server could not complete pairing right now. Try again later.".into();
    }
    if matches!(status, 400 | 401) {
        return "That desktop code is invalid, expired, or has already been used.".into();
    }
    "The server refused the pairing request.".into()
}

async fn request_link(
    client: &reqwest::Client,
    base_url: &str,
    code: &str,
) -> VaultResult<DesktopLinkResponse> {
    let response = client
        .post(format!("{base_url}/v1/desktop/link"))
        .json(&serde_json::json!({ "code": code, "deviceName": default_device_name() }))
        .send()
        .await
        .map_err(|_| {
            "Sesame could not reach the account service. Check your connection and try again."
                .to_string()
        })?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let code = match read_limited(response, MAX_SERVICE_RESPONSE_BYTES).await {
            Some(body) => error_code(&body),
            None => String::new(),
        };
        return Err(link_refusal(status, &code, retry_after.as_deref()));
    }
    let body = read_limited(response, MAX_SERVICE_RESPONSE_BYTES)
        .await
        .ok_or_else(|| "Sesame could not read the account service response.".to_string())?;
    let mut linked: DesktopLinkResponse = serde_json::from_slice(&body)
        .map_err(|_| "Sesame could not read the account service response.".to_string())?;
    if linked.access_token.is_empty()
        || linked.device.device_id.is_empty()
        || linked.device.device_name.is_empty()
    {
        linked.access_token.zeroize();
        return Err("The account service returned an incomplete desktop connection.".into());
    }
    Ok(linked)
}

fn store_connection(
    app: &AppHandle,
    mut linked: DesktopLinkResponse,
    api_base_url: String,
    token_bytes: Vec<u8>,
    custom_server: Option<crate::vault::types::CustomServerPin>,
) -> VaultResult<ServiceConnectionStatus> {
    let mut token_bytes = token_bytes;
    let expires_at = expiry_seconds(linked.expires_at.as_deref());
    let outcome = (|| {
        crate::vault::platform::ensure_device_protection()?;
        let protected_token = protect_for_device(&token_bytes)?;
        write_service_connection(
            app,
            &ServiceConnectionFile {
                format_version: SERVICE_CONNECTION_FORMAT_VERSION,
                api_base_url,
                protected_token: URL_SAFE_NO_PAD.encode(protected_token),
                device_id: linked.device.device_id.clone(),
                device_name: linked.device.device_name.clone(),
                expires_at,
                custom_server,
            },
        )
    })();
    token_bytes.zeroize();
    linked.access_token.zeroize();
    outcome?;
    Ok(ServiceConnectionStatus {
        state: "connected".into(),
        connected: true,
        online: true,
        device_name: Some(linked.device.device_name),
        sync_available: linked.sync_available,
        browser_helper_available: false,
        server_address: None,
        server_fingerprint: None,
        server_name: None,
    })
}

pub(crate) async fn redeem_official_link(
    client: &reqwest::Client,
    base_url: &str,
    code: &str,
    device_ready: impl FnOnce() -> VaultResult<()>,
) -> VaultResult<DesktopLinkResponse> {
    device_ready()?;
    request_link(client, base_url, code).await
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
    let linked = redeem_official_link(
        &client,
        &api_base_url,
        &code,
        crate::vault::platform::ensure_device_protection,
    )
    .await?;
    let token_bytes = linked.access_token.as_bytes().to_vec();
    store_connection(&app, linked, api_base_url, token_bytes, None)
}

fn inspection_for(parsed: &PairingInput, info: &InstanceInfo) -> ServerInspection {
    ServerInspection {
        address: parsed.address.as_str().to_string(),
        name: info.name.clone(),
        version: info.version.clone(),
        fingerprint: info.fingerprint.clone(),
        fingerprint_in_link: parsed.fingerprint.is_some(),
        code_in_link: parsed.code.is_some(),
        plain_http: parsed.address.is_plain_http(),
    }
}

fn parse_custom_input(input: &str) -> VaultResult<PairingInput> {
    let parsed = parse_pairing_input(input)?;
    parsed
        .address
        .refuse_official_host(service_api_base_url().ok().as_deref())?;
    Ok(parsed)
}

#[tauri::command]
pub async fn inspect_custom_server(input: String) -> VaultResult<ServerInspection> {
    let parsed = parse_custom_input(&input)?;
    let client = client_for_base(parsed.address.as_str())?;
    let info = inspect_server(&client, &parsed.address, parsed.fingerprint.as_deref()).await?;
    Ok(inspection_for(&parsed, &info))
}

pub(crate) async fn pair_with_server(
    client: &reqwest::Client,
    parsed: &PairingInput,
    typed_code: &str,
    confirmed_fingerprint: &str,
    device_ready: impl FnOnce() -> VaultResult<()>,
) -> VaultResult<(InstanceInfo, DesktopLinkResponse)> {
    let confirmed = normalized_fingerprint(confirmed_fingerprint)
        .ok_or("Confirm the server fingerprint before pairing.")?;
    let code = match (&parsed.code, typed_code.trim()) {
        (Some(from_link), "") => from_link.clone(),
        (None, typed) => validate_pairing_code(typed)?,
        (Some(from_link), typed) if validate_pairing_code(typed)? == *from_link => {
            from_link.clone()
        }
        (Some(_), _) => {
            return Err(
                "The pairing link and the code you typed are different. Use one of them.".into(),
            )
        }
    };
    device_ready()?;
    let info = inspect_server(client, &parsed.address, parsed.fingerprint.as_deref()).await?;
    if info.fingerprint != confirmed {
        return Err(ServerFailure::LinkMismatch.message());
    }
    let linked = request_link(client, parsed.address.as_str(), &code).await?;
    Ok((info, linked))
}

#[tauri::command]
pub async fn link_custom_server(
    app: AppHandle,
    input: String,
    code: String,
    confirmed_fingerprint: String,
) -> VaultResult<ServiceConnectionStatus> {
    let parsed = parse_custom_input(&input)?;
    if read_service_connection(&app).is_ok() {
        return Err(
            "This desktop is already connected. Disconnect it before pairing with another server."
                .into(),
        );
    }
    let client = client_for_base(parsed.address.as_str())?;
    let (info, linked) = pair_with_server(
        &client,
        &parsed,
        &code,
        &confirmed_fingerprint,
        crate::vault::platform::ensure_device_protection,
    )
    .await?;
    let token_bytes = bind_token_to_server(&parsed.address, &linked.access_token);
    let mut status = store_connection(
        &app,
        linked,
        parsed.address.as_str().to_string(),
        token_bytes,
        Some(info.pin()),
    )?;
    status.server_address = Some(parsed.address.as_str().to_string());
    status.server_fingerprint = Some(info.fingerprint);
    status.server_name = Some(info.name).filter(|name| !name.is_empty());
    Ok(status)
}

fn status_for(
    connection: Option<&ServiceConnectionFile>,
    state: &str,
    connected: bool,
    online: bool,
    device_name: Option<String>,
    sync_available: bool,
    browser_helper_available: bool,
) -> ServiceConnectionStatus {
    let pin = connection.and_then(|connection| connection.custom_server.as_ref());
    ServiceConnectionStatus {
        state: state.into(),
        connected,
        online,
        device_name,
        sync_available,
        browser_helper_available,
        server_address: pin
            .and(connection)
            .map(|connection| connection.api_base_url.clone()),
        server_fingerprint: pin.map(|pin| pin.fingerprint.clone()),
        server_name: pin
            .map(|pin| pin.name.clone())
            .filter(|name| !name.is_empty()),
    }
}

#[tauri::command]
pub async fn get_service_connection_status(app: AppHandle) -> VaultResult<ServiceConnectionStatus> {
    let connection = match read_service_connection(&app) {
        Ok(connection) => connection,
        Err(_) => {
            return Ok(status_for(
                None,
                "disconnected",
                false,
                false,
                None,
                false,
                false,
            ))
        }
    };
    let target = service_target(&connection)?;
    let client = client_for_base(target.base_url())?;
    let held = |state: &str, online: bool| {
        status_for(
            Some(&connection),
            state,
            true,
            online,
            Some(connection.device_name.clone()),
            false,
            false,
        )
    };
    if let ServiceTarget::Custom { address, pin } = &target {
        if let Err(failure) = verify_pinned_server(&client, address, pin).await {
            return Ok(match failure {
                ServerFailure::Unreachable => held("offline", false),
                ServerFailure::KeyChanged => held("serverKeyChanged", true),
                ServerFailure::Incompatible(_) => held("serverIncompatible", true),
                ServerFailure::ClockDifference(_) => held("serverClockDiffers", true),
                _ => held("needsAttention", true),
            });
        }
    }
    let mut token = read_service_token(&connection)?;
    let base_url = target.base_url();
    // Heartbeat reports desktop capability, not extension installation.
    let heartbeat = client
        .post(format!("{base_url}/v1/desktop/heartbeat"))
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
    let ended = ended_state(&connection, chrono::Utc::now().timestamp());
    if matches!(heartbeat, Ok(ref response) if response.status().as_u16() == 401) {
        token.zeroize();
        let _ = remove_service_connection(&app);
        return Ok(status_for(None, ended, false, true, None, false, false));
    }
    let result = client
        .get(format!("{base_url}/v1/desktop/status"))
        .header("Authorization", format!("Sesame {token}"))
        .send()
        .await;
    token.zeroize();
    match result {
        Ok(response) if response.status().is_success() => {
            let body = read_limited(response, MAX_SERVICE_RESPONSE_BYTES)
                .await
                .ok_or_else(|| "Sesame could not read the account service response.".to_string())?;
            let status: DesktopServiceStatusResponse = serde_json::from_slice(&body)
                .map_err(|_| "Sesame could not read the account service response.".to_string())?;
            Ok(status_for(
                Some(&connection),
                if status.connected { "connected" } else { ended },
                status.connected,
                true,
                Some(status.device.device_name),
                status.sync_available,
                status.browser_helper_available,
            ))
        }
        Ok(response) if response.status().as_u16() == 401 => {
            let _ = remove_service_connection(&app);
            Ok(status_for(None, ended, false, true, None, false, false))
        }
        Ok(response) if response.status().as_u16() == 423 => Ok(held("suspended", true)),
        Ok(response) if response.status().as_u16() == 429 => Ok(held("rateLimited", true)),
        Ok(response) if response.status().is_server_error() => Ok(held("serviceUnavailable", true)),
        Ok(_) => Ok(held("needsAttention", true)),
        Err(_) => Ok(held("offline", false)),
    }
}

pub(crate) async fn revoke_on_server(target: &ServiceTarget, token: &str) -> bool {
    let Ok(client) = client_for_base(target.base_url()) else {
        return false;
    };
    if let ServiceTarget::Custom { address, pin } = target {
        if verify_pinned_server(&client, address, pin).await.is_err() {
            return false;
        }
    }
    match client
        .delete(format!("{}/v1/desktop/connection", target.base_url()))
        .header("Authorization", format!("Sesame {token}"))
        .send()
        .await
    {
        Ok(response) => response.status().is_success() || response.status().as_u16() == 401,
        Err(_) => false,
    }
}

#[tauri::command]
pub async fn disconnect_service(app: AppHandle) -> VaultResult<DisconnectOutcome> {
    let connection = match read_service_connection(&app) {
        Ok(connection) => connection,
        Err(_) => {
            return Ok(DisconnectOutcome {
                revoked_on_server: true,
            })
        }
    };
    let revoked_on_server = match (service_target(&connection), read_service_token(&connection)) {
        (Ok(target), Ok(mut token)) => {
            let revoked = revoke_on_server(&target, &token).await;
            token.zeroize();
            revoked
        }
        _ => false,
    };
    remove_service_connection(&app)?;
    Ok(DisconnectOutcome { revoked_on_server })
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

    use crate::adapters::network::test_server::{FakeSesame, Reply, TestServer};

    const CODE: &str = "abcdefghijklmnopqrstuvwxyzABCDEF-_0123456789";

    fn input(server: &TestServer, fragment: &str) -> PairingInput {
        let text = if fragment.is_empty() {
            server.base()
        } else {
            format!("{}/pair#{fragment}", server.base())
        };
        parse_pairing_input(&text).unwrap()
    }

    fn pair(
        server: &TestServer,
        parsed: &PairingInput,
        typed: &str,
        confirmed: &str,
    ) -> VaultResult<(InstanceInfo, DesktopLinkResponse)> {
        let client = client_for_base(&server.base()).unwrap();
        tauri::async_runtime::block_on(pair_with_server(&client, parsed, typed, confirmed, || {
            Ok(())
        }))
    }

    fn link_posts(server: &TestServer) -> Vec<Vec<u8>> {
        server
            .requests()
            .into_iter()
            .filter(|request| request.method == "POST")
            .map(|request| request.body)
            .collect()
    }

    #[test]
    fn pairing_sends_the_code_once_after_the_fingerprint_matches() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let parsed = input(&server, &format!("code={CODE}&fp={}", fake.fingerprint()));
        let (info, linked) = pair(&server, &parsed, "", &fake.fingerprint()).unwrap();
        assert_eq!(info.fingerprint, fake.fingerprint());
        assert_eq!(linked.access_token, "fictional-device-token");
        let posts = link_posts(&server);
        assert_eq!(posts.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&posts[0]).unwrap();
        assert_eq!(body["code"], CODE);
        assert!(body["deviceName"].as_str().is_some());
    }

    #[test]
    fn a_typed_code_with_a_bare_origin_is_sent() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let parsed = input(&server, "");
        assert!(pair(&server, &parsed, &format!("  {CODE} "), &fake.fingerprint()).is_ok());
        assert_eq!(link_posts(&server).len(), 1);
    }

    #[test]
    fn a_wrong_confirmed_fingerprint_sends_no_code() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let parsed = input(&server, &format!("code={CODE}"));
        for confirmed in [
            FakeSesame::new(2).fingerprint(),
            String::new(),
            "abc".to_string(),
        ] {
            assert!(pair(&server, &parsed, "", &confirmed).is_err());
        }
        assert!(link_posts(&server).is_empty());
    }

    #[test]
    fn a_server_whose_key_changed_after_confirmation_gets_no_code() {
        let confirmed = FakeSesame::new(1).fingerprint();
        let rotated = FakeSesame::new(2);
        let server = TestServer::start(rotated.handler());
        let parsed = input(&server, &format!("code={CODE}"));
        assert!(pair(&server, &parsed, "", &confirmed).is_err());
        assert!(link_posts(&server).is_empty());
    }

    #[test]
    fn a_link_fingerprint_from_another_server_sends_no_code() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let foreign = FakeSesame::new(2).fingerprint();
        let parsed = input(&server, &format!("code={CODE}&fp={foreign}"));
        let error = pair(&server, &parsed, "", &fake.fingerprint())
            .err()
            .unwrap();
        assert_eq!(error, ServerFailure::LinkMismatch.message());
        assert!(link_posts(&server).is_empty());
    }

    #[test]
    fn a_missing_conflicting_or_malformed_code_sends_nothing() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let bare = input(&server, "");
        assert!(pair(&server, &bare, "", &fake.fingerprint()).is_err());
        assert!(pair(&server, &bare, "short", &fake.fingerprint()).is_err());
        let linked = input(&server, &format!("code={CODE}"));
        let other = CODE.replace('a', "b");
        assert!(pair(&server, &linked, &other, &fake.fingerprint()).is_err());
        assert!(pair(&server, &linked, CODE, &fake.fingerprint()).is_ok());
        assert_eq!(link_posts(&server).len(), 1);
    }

    #[test]
    fn a_rejected_or_replayed_code_is_reported_without_a_token() {
        let fake = FakeSesame::new(1);
        let inner = fake.handler();
        let used = std::sync::atomic::AtomicBool::new(false);
        let server = TestServer::start(move |request| {
            if request.method == "POST" && used.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return Reply::json(
                    400,
                    &serde_json::json!({ "error": { "code": "invalid_code" } }),
                );
            }
            inner(request)
        });
        let parsed = input(&server, &format!("code={CODE}"));
        assert!(pair(&server, &parsed, "", &fake.fingerprint()).is_ok());
        let error = pair(&server, &parsed, "", &fake.fingerprint())
            .err()
            .unwrap();
        assert_eq!(
            error,
            "That desktop code is invalid, expired, or has already been used."
        );
    }

    #[test]
    fn an_incomplete_or_oversized_link_response_is_refused() {
        let fake = FakeSesame::new(1);
        let responses = [
            serde_json::json!({ "accessToken": "", "device": { "deviceId": "d", "deviceName": "n" }, "syncAvailable": false }),
            serde_json::json!({ "accessToken": "t", "device": { "deviceId": "", "deviceName": "n" }, "syncAvailable": false }),
            serde_json::json!({ "accessToken": "t", "syncAvailable": false }),
            serde_json::json!("token"),
        ];
        for response in responses {
            let inner = fake.handler();
            let server = TestServer::start(move |request| {
                if request.method == "POST" {
                    return Reply::json(201, &response);
                }
                inner(request)
            });
            let parsed = input(&server, &format!("code={CODE}"));
            assert!(pair(&server, &parsed, "", &fake.fingerprint()).is_err());
        }
        let inner = fake.handler();
        let server = TestServer::start(move |request| {
            if request.method == "POST" {
                return Reply::bytes(201, vec![b' '; MAX_SERVICE_RESPONSE_BYTES + 1]);
            }
            inner(request)
        });
        let parsed = input(&server, &format!("code={CODE}"));
        assert!(pair(&server, &parsed, "", &fake.fingerprint()).is_err());
    }

    #[test]
    fn a_redirect_on_the_link_route_does_not_forward_the_code() {
        let fake = FakeSesame::new(1);
        let target = TestServer::start(fake.handler());
        let location = format!("{}/v1/desktop/link", target.base());
        let inner = fake.handler();
        let server = TestServer::start(move |request| {
            if request.method == "POST" {
                return Reply::bytes(307, Vec::new()).with_header("Location", &location);
            }
            inner(request)
        });
        let parsed = input(&server, &format!("code={CODE}"));
        assert!(pair(&server, &parsed, "", &fake.fingerprint()).is_err());
        assert!(target.requests().is_empty());
    }

    #[test]
    fn the_official_host_is_refused_as_a_custom_server() {
        let official = service_api_base_url().ok();
        if let Some(official) = official {
            assert!(parse_custom_input(&format!("{official}/pair#code={CODE}")).is_err());
        }
        assert!(parse_custom_input("https://home.example.test").is_ok());
    }

    #[test]
    fn a_connection_status_carries_the_pinned_server_only_for_custom_records() {
        let custom = ServiceConnectionFile {
            format_version: SERVICE_CONNECTION_FORMAT_VERSION,
            api_base_url: "https://home.example.test".into(),
            protected_token: "x".into(),
            device_id: "d".into(),
            device_name: "n".into(),
            expires_at: None,
            custom_server: Some(crate::vault::types::CustomServerPin {
                instance_id: "i".into(),
                name: "Home".into(),
                capability_key_id: "k".into(),
                capability_public_key: "p".into(),
                fingerprint: "f".repeat(64),
            }),
        };
        let status = status_for(Some(&custom), "connected", true, true, None, false, false);
        assert_eq!(
            status.server_address.as_deref(),
            Some("https://home.example.test")
        );
        assert_eq!(status.server_name.as_deref(), Some("Home"));
        let official = ServiceConnectionFile {
            custom_server: None,
            ..custom
        };
        let status = status_for(Some(&official), "connected", true, true, None, false, false);
        assert_eq!(status.server_address, None);
        assert_eq!(status.server_fingerprint, None);
    }

    fn link_error(status: u16, code: &str, retry_after: Option<&str>) -> String {
        let fake = FakeSesame::new(1);
        let inner = fake.handler();
        let code = code.to_string();
        let retry_after = retry_after.map(str::to_string);
        let server = TestServer::start(move |request| {
            if request.method == "POST" {
                let reply = Reply::json(
                    status,
                    &serde_json::json!({ "error": { "code": code, "message": "x" } }),
                );
                return match &retry_after {
                    Some(value) => reply.with_header("Retry-After", value),
                    None => reply,
                };
            }
            inner(request)
        });
        let parsed = input(&server, &format!("code={CODE}"));
        pair(&server, &parsed, "", &fake.fingerprint())
            .err()
            .unwrap()
    }

    #[test]
    fn a_host_mismatch_names_the_address_problem() {
        let message = link_error(421, "host_mismatch", None);
        assert!(message.contains("public address"), "{message}");
        assert!(!message.contains("expired"), "{message}");
    }

    #[test]
    fn a_rate_limit_asks_the_person_to_wait_for_the_stated_time() {
        let message = link_error(429, "rate_limited", Some("42"));
        assert!(message.contains("42 seconds"), "{message}");
        assert!(!message.contains("expired"), "{message}");
        let one = link_error(429, "rate_limited", Some("1"));
        assert!(one.contains("1 second"), "{one}");
        assert!(!one.contains("1 seconds"), "{one}");
    }

    #[test]
    fn a_rate_limit_without_a_usable_wait_still_says_to_wait() {
        for header in [None, Some("soon"), Some("-5"), Some("0"), Some("")] {
            let message = link_error(429, "rate_limited", header);
            assert!(message.contains("Wait a moment"), "{message}");
            assert!(!message.contains("seconds"), "{message}");
        }
        let long = link_error(429, "rate_limited", Some("99999999"));
        assert!(long.contains("Wait a moment"), "{long}");
    }

    #[test]
    fn switched_off_pairing_is_reported_as_such() {
        let message = link_error(503, "desktop_linking_disabled", None);
        assert!(message.contains("switched off"), "{message}");
        assert!(!message.contains("expired"), "{message}");
    }

    #[test]
    fn another_server_error_is_not_reported_as_a_bad_code() {
        let message = link_error(503, "unavailable", None);
        assert!(message.contains("Try again later"), "{message}");
        assert!(!message.contains("expired"), "{message}");
        let message = link_error(500, "", None);
        assert!(!message.contains("expired"), "{message}");
    }

    #[test]
    fn a_rejected_code_keeps_the_code_message() {
        for status in [400, 401] {
            let message = link_error(status, "invalid_desktop_link", None);
            assert_eq!(
                message,
                "That desktop code is invalid, expired, or has already been used."
            );
        }
    }

    #[test]
    fn a_host_mismatch_is_recognised_by_its_code_as_well_as_its_status() {
        let message = link_error(400, "host_mismatch", None);
        assert!(message.contains("public address"), "{message}");
    }

    fn target_for(server: &TestServer, fake: &FakeSesame) -> ServiceTarget {
        let pin = crate::adapters::network::server_trust::parse_instance(
            &serde_json::to_vec(&fake.instance()).unwrap(),
            "0.3.0",
        )
        .unwrap()
        .pin();
        ServiceTarget::Custom {
            address: crate::adapters::network::server_address::ServerAddress::parse(&server.base())
                .unwrap(),
            pin,
        }
    }

    fn revoke(target: &ServiceTarget) -> bool {
        tauri::async_runtime::block_on(revoke_on_server(target, "fictional-device-token"))
    }

    fn deletes(server: &TestServer) -> Vec<crate::adapters::network::test_server::Recorded> {
        server
            .requests()
            .into_iter()
            .filter(|request| request.method == "DELETE")
            .collect()
    }

    #[test]
    fn a_revocation_reaches_the_pinned_server_with_the_device_token() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        assert!(revoke(&target_for(&server, &fake)));
        let sent = deletes(&server);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].path, "/v1/desktop/connection");
        assert_eq!(
            sent[0].headers.get("authorization").map(String::as_str),
            Some("Sesame fictional-device-token")
        );
    }

    #[test]
    fn a_server_that_rotated_its_key_is_not_sent_the_token_and_the_revocation_is_reported_as_unsent(
    ) {
        let pinned = FakeSesame::new(1);
        let rotated = FakeSesame::new(2);
        let server = TestServer::start(rotated.handler());
        assert!(!revoke(&target_for(&server, &pinned)));
        assert!(deletes(&server).is_empty());
    }

    #[test]
    fn an_unreachable_or_failing_server_is_reported_as_unrevoked() {
        let fake = FakeSesame::new(1);
        let down = TestServer::start(fake.handler());
        let target = target_for(&down, &fake);
        drop(down);
        assert!(!revoke(&target));

        let inner = fake.handler();
        let failing = TestServer::start(move |request| {
            if request.method == "DELETE" {
                return Reply::json(500, &serde_json::json!({ "error": { "code": "boom" } }));
            }
            inner(request)
        });
        assert!(!revoke(&target_for(&failing, &fake)));
        assert_eq!(deletes(&failing).len(), 1);
    }

    #[test]
    fn a_token_the_server_no_longer_knows_counts_as_revoked() {
        let fake = FakeSesame::new(1);
        let inner = fake.handler();
        let server = TestServer::start(move |request| {
            if request.method == "DELETE" {
                return Reply::json(
                    401,
                    &serde_json::json!({ "error": { "code": "not_authenticated" } }),
                );
            }
            inner(request)
        });
        assert!(revoke(&target_for(&server, &fake)));
    }

    #[test]
    fn a_revocation_does_not_follow_a_redirect() {
        let fake = FakeSesame::new(1);
        let elsewhere = TestServer::start(fake.handler());
        let location = format!("{}/v1/desktop/connection", elsewhere.base());
        let inner = fake.handler();
        let server = TestServer::start(move |request| {
            if request.method == "DELETE" {
                return Reply::bytes(307, Vec::new()).with_header("Location", &location);
            }
            inner(request)
        });
        assert!(!revoke(&target_for(&server, &fake)));
        assert!(elsewhere.requests().is_empty());
    }

    fn stored(expires_at: Option<u64>) -> ServiceConnectionFile {
        ServiceConnectionFile {
            format_version: SERVICE_CONNECTION_FORMAT_VERSION,
            api_base_url: "https://api.example.test".into(),
            protected_token: "x".into(),
            device_id: "d".into(),
            device_name: "n".into(),
            expires_at,
            custom_server: None,
        }
    }

    #[test]
    fn a_link_whose_stored_expiry_has_passed_is_reported_as_expired() {
        assert_eq!(ended_state(&stored(Some(1_000)), 1_000), "expired");
        assert_eq!(ended_state(&stored(Some(1_000)), 2_000), "expired");
        assert_eq!(ended_state(&stored(Some(1_000)), 999), "revoked");
        assert_eq!(ended_state(&stored(None), 5_000_000_000), "revoked");
        assert_eq!(ended_state(&stored(Some(u64::MAX)), 1_000), "revoked");
    }

    #[test]
    fn the_link_expiry_is_read_from_the_response_and_bad_values_are_ignored() {
        assert_eq!(
            expiry_seconds(Some("2026-10-10T12:00:00Z")),
            Some(1_791_633_600)
        );
        assert_eq!(expiry_seconds(Some("tomorrow")), None);
        assert_eq!(expiry_seconds(Some("1969-12-31T00:00:00Z")), None);
        assert_eq!(expiry_seconds(None), None);
    }

    #[test]
    fn the_expiry_the_server_returns_is_kept_in_the_stored_record() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let parsed = input(&server, &format!("code={CODE}"));
        let (_, linked) = pair(&server, &parsed, "", &fake.fingerprint()).unwrap();
        assert_eq!(
            expiry_seconds(linked.expires_at.as_deref()),
            Some(4_070_908_800)
        );
    }

    #[test]
    fn a_record_without_an_expiry_still_reads_and_never_expires() {
        let legacy = br#"{"formatVersion":1,"apiBaseUrl":"https://api.example.test","protectedToken":"x","deviceId":"d","deviceName":"n"}"#;
        let parsed: ServiceConnectionFile = serde_json::from_slice(legacy).unwrap();
        assert_eq!(parsed.expires_at, None);
        assert_eq!(ended_state(&parsed, i64::MAX), "revoked");
    }

    #[test]
    fn a_failing_key_store_stops_pairing_before_any_request_reaches_the_server() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let parsed = input(&server, &format!("code={CODE}&fp={}", fake.fingerprint()));
        let client = client_for_base(&server.base()).unwrap();
        let error = tauri::async_runtime::block_on(pair_with_server(
            &client,
            &parsed,
            "",
            &fake.fingerprint(),
            || Err("The system key store is not available.".to_string()),
        ))
        .err()
        .unwrap();
        assert_eq!(error, "The system key store is not available.");
        assert!(server.requests().is_empty());
    }

    #[test]
    fn a_failing_key_store_stops_an_account_link_before_the_code_is_redeemed() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let client = client_for_base(&server.base()).unwrap();
        let error = tauri::async_runtime::block_on(redeem_official_link(
            &client,
            &server.base(),
            CODE,
            || Err("The system key store is not available.".to_string()),
        ))
        .err()
        .unwrap();
        assert_eq!(error, "The system key store is not available.");
        assert!(server.requests().is_empty());
    }

    #[test]
    fn a_working_key_store_lets_an_account_link_redeem_its_code_once() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let client = client_for_base(&server.base()).unwrap();
        let linked = tauri::async_runtime::block_on(redeem_official_link(
            &client,
            &server.base(),
            CODE,
            || Ok(()),
        ))
        .unwrap();
        assert_eq!(linked.access_token, "fictional-device-token");
        assert_eq!(link_posts(&server).len(), 1);
    }
}
