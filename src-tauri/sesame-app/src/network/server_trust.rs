use reqwest::{header::DATE, Client};

use super::account_service::read_limited;
use super::capabilities::{
    fetch_signed_document, require_instance, require_linking_enabled, CapabilityError,
};
use super::server_address::ServerAddress;
use crate::vault::types::CustomServerPin;

pub use sesame_sync::server_trust::{
    check_pinned_instance, pin_key, InstanceInfo, ServerFailure, MAX_INSTANCE_BYTES,
    NOT_A_SESAME_SERVER,
};

#[cfg(test)]
pub(crate) use sesame_sync::server_trust::{parse_version, MAX_IDENTIFIER_BYTES, MAX_NAME_CHARS};

pub fn parse_instance(body: &[u8], client_version: &str) -> Result<InstanceInfo, ServerFailure> {
    sesame_sync::server_trust::parse_instance(body, client_version, sesame_sync::DESKTOP_PLATFORM)
}

fn invalid() -> ServerFailure {
    ServerFailure::Invalid(NOT_A_SESAME_SERVER.to_string())
}

pub async fn fetch_instance(
    client: &Client,
    address: &ServerAddress,
) -> Result<(InstanceInfo, Option<u64>), ServerFailure> {
    let response = client
        .get(address.url("/v1/instance"))
        .send()
        .await
        .map_err(|_| ServerFailure::Unreachable)?;
    let status = response.status();
    if status.is_server_error() || status.as_u16() == 429 {
        return Err(ServerFailure::Unreachable);
    }
    if !status.is_success() {
        return Err(invalid());
    }
    let date = response
        .headers()
        .get(DATE)
        .and_then(|value| value.to_str().ok())
        .and_then(super::time::parse_http_date);
    let body = read_limited(response, MAX_INSTANCE_BYTES)
        .await
        .ok_or_else(invalid)?;
    Ok((parse_instance(&body, env!("CARGO_PKG_VERSION"))?, date))
}

pub async fn inspect_server(
    client: &Client,
    address: &ServerAddress,
    link_fingerprint: Option<&str>,
) -> Result<InstanceInfo, ServerFailure> {
    let (info, _) = fetch_instance(client, address).await?;
    if link_fingerprint.is_some_and(|expected| expected != info.fingerprint) {
        return Err(ServerFailure::LinkMismatch);
    }
    let document = fetch_signed_document(
        client,
        address.as_str(),
        info.key(),
        Some(&info.capability_key_id),
    )
    .await
    .map_err(|error| match error {
        CapabilityError::Untrusted => ServerFailure::Invalid(
            "The server's capability document is not signed by the key it announced, so Sesame will not pair with it.".to_string(),
        ),
        CapabilityError::ClockDifference => {
            ServerFailure::ClockDifference(String::from(CapabilityError::ClockDifference))
        }
        CapabilityError::Unavailable(message) => ServerFailure::Invalid(message),
    })?;
    require_instance(&document, &info.instance_id)
        .map_err(|error| ServerFailure::Invalid(String::from(error)))?;
    require_linking_enabled(
        &document,
        env!("CARGO_PKG_VERSION"),
        sesame_sync::DESKTOP_PLATFORM,
    )
    .map_err(|error| ServerFailure::Invalid(String::from(error)))?;
    Ok(info)
}

pub async fn verify_pinned_server(
    client: &Client,
    address: &ServerAddress,
    pin: &CustomServerPin,
) -> Result<Option<u64>, ServerFailure> {
    let key = pin_key(pin).ok_or_else(invalid)?;
    let (info, date) = fetch_instance(client, address).await?;
    check_pinned_instance(&info, pin)?;
    let document =
        fetch_signed_document(client, address.as_str(), &key, Some(&pin.capability_key_id))
            .await
            .map_err(|error| match error {
                CapabilityError::Untrusted => ServerFailure::KeyChanged,
                CapabilityError::ClockDifference => {
                    ServerFailure::ClockDifference(String::from(CapabilityError::ClockDifference))
                }
                CapabilityError::Unavailable(message) => ServerFailure::Invalid(message),
            })?;
    require_instance(&document, &pin.instance_id)
        .map_err(|error| ServerFailure::Invalid(String::from(error)))?;
    Ok(date)
}

pub async fn pinned_server_time(
    client: &Client,
    address: &ServerAddress,
    pin: &CustomServerPin,
) -> Option<u64> {
    verify_pinned_server(client, address, pin)
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::account_service::client_for_base;
    use crate::network::test_server::{closed_port_base, FakeSesame, Reply, TestServer};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    const CLIENT: &str = "0.3.0";

    fn body(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    fn parse(fake: &FakeSesame) -> Result<InstanceInfo, ServerFailure> {
        parse_instance(&body(&fake.instance()), CLIENT)
    }

    fn edited(edit: impl Fn(&mut serde_json::Value)) -> Result<InstanceInfo, ServerFailure> {
        let mut document = FakeSesame::new(1).instance();
        edit(&mut document);
        parse_instance(&body(&document), CLIENT)
    }

    fn incompatible(result: Result<InstanceInfo, ServerFailure>) -> String {
        match result {
            Err(ServerFailure::Incompatible(message)) => message,
            other => panic!("expected an incompatible server, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_instance_document_gives_its_key_and_fingerprint() {
        let fake = FakeSesame::new(1);
        let info = parse(&fake).unwrap();
        assert_eq!(info.fingerprint, fake.fingerprint());
        assert_eq!(info.capability_key_id, "key-1");
        assert_eq!(info.name, "Home server");
        assert_eq!(
            info.key().as_bytes(),
            fake.signing_key.verifying_key().as_bytes()
        );
        let pin = info.pin();
        assert!(pin_key(&pin).is_some());
        assert_eq!(pin.fingerprint, fake.fingerprint());
    }

    #[test]
    fn an_uppercase_fingerprint_for_the_right_key_is_accepted_and_stored_in_lowercase() {
        let info = edited(|document| {
            let fingerprint = document["fingerprint"].as_str().unwrap().to_uppercase();
            document["fingerprint"] = serde_json::json!(fingerprint);
        })
        .unwrap();
        assert_eq!(info.fingerprint, FakeSesame::new(1).fingerprint());
    }

    #[test]
    fn another_api_version_is_refused_with_a_clear_message() {
        for version in [0u64, 2, 99] {
            let message = incompatible(edited(|document| {
                document["apiVersion"] = serde_json::json!(version);
            }));
            assert!(message.contains(&format!("version {version}")), "{message}");
        }
        assert!(matches!(
            edited(|document| document["apiVersion"] = serde_json::json!("1")),
            Err(ServerFailure::Invalid(_))
        ));
        assert!(matches!(
            edited(|document| document["apiVersion"] = serde_json::json!(1.5)),
            Err(ServerFailure::Invalid(_))
        ));
    }

    #[test]
    fn a_server_that_needs_a_newer_client_is_refused() {
        let message = incompatible(edited(|document| {
            document["minimumClientVersion"] = serde_json::json!("0.9.1");
        }));
        assert_eq!(
            message,
            "This server needs Sesame 0.9.1 or newer. Update Sesame, then try again."
        );
        assert!(
            edited(|document| document["minimumClientVersion"] = serde_json::json!("0.3.0"))
                .is_ok()
        );
        assert!(
            edited(|document| document["minimumClientVersion"] = serde_json::json!("0.2.9"))
                .is_ok()
        );
    }

    #[test]
    fn a_server_that_supports_only_older_clients_is_refused() {
        let message = incompatible(edited(|document| {
            document["maximumClientVersion"] = serde_json::json!("0.2.9");
        }));
        assert_eq!(
            message,
            "This server supports Sesame up to 0.2.9. Update the server, then try again."
        );
        assert!(
            edited(|document| document["maximumClientVersion"] = serde_json::json!("0.3.0"))
                .is_ok()
        );
    }

    #[test]
    fn contradictory_or_malformed_versions_are_refused() {
        for (minimum, maximum) in [
            ("0.5.0", Some("0.4.0")),
            ("", None),
            ("latest", None),
            ("1.2", None),
            ("1.2.3.4", None),
            ("1.2.x", None),
            ("-1.0.0", None),
            ("99999999999.0.0", None),
            ("0.1.0", Some("")),
            ("0.1.0", Some("newest")),
        ] {
            let result = edited(|document| {
                document["minimumClientVersion"] = serde_json::json!(minimum);
                if let Some(maximum) = maximum {
                    document["maximumClientVersion"] = serde_json::json!(maximum);
                }
            });
            assert!(
                matches!(result, Err(ServerFailure::Invalid(_))),
                "{minimum} {maximum:?}"
            );
        }
    }

    #[test]
    fn a_missing_minimum_version_is_refused() {
        let result = edited(|document| {
            document
                .as_object_mut()
                .unwrap()
                .remove("minimumClientVersion");
        });
        assert!(matches!(result, Err(ServerFailure::Invalid(_))));
    }

    #[test]
    fn versions_with_a_suffix_compare_by_their_numbers() {
        assert_eq!(parse_version("1.2.3-beta.1"), Some([1, 2, 3]));
        assert_eq!(parse_version("1.2.3+build"), Some([1, 2, 3]));
        assert_eq!(parse_version("0.3.0"), Some([0, 3, 0]));
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn a_key_that_is_not_thirty_two_bytes_or_not_base64url_is_refused() {
        for key in [
            "".to_string(),
            "AAAA".to_string(),
            "!!!!".to_string(),
            URL_SAFE_NO_PAD.encode([1u8; 31]),
            URL_SAFE_NO_PAD.encode([1u8; 33]),
            format!("{}=", URL_SAFE_NO_PAD.encode([1u8; 32])),
            base64::engine::general_purpose::STANDARD.encode([0xfbu8; 32]),
        ] {
            let result =
                edited(|document| document["capabilityPublicKey"] = serde_json::json!(key));
            assert!(matches!(result, Err(ServerFailure::Invalid(_))), "{key}");
        }
    }

    #[test]
    fn a_fingerprint_that_does_not_belong_to_the_key_is_refused() {
        let other = FakeSesame::new(2).fingerprint();
        for fingerprint in [other.as_str(), "", "abc", &"0".repeat(64), &"g".repeat(64)] {
            let result =
                edited(|document| document["fingerprint"] = serde_json::json!(fingerprint));
            assert!(
                matches!(result, Err(ServerFailure::Invalid(_))),
                "{fingerprint}"
            );
        }
    }

    #[test]
    fn names_and_identifiers_that_could_mislead_a_reader_are_refused() {
        for edit in [
            (|d: &mut serde_json::Value| d["name"] = serde_json::json!("Home\nserver"))
                as fn(&mut serde_json::Value),
            |d| d["name"] = serde_json::json!("x".repeat(MAX_NAME_CHARS + 1)),
            |d| d["name"] = serde_json::json!("\u{1F512}".repeat(MAX_NAME_CHARS)),
            |d| d["name"] = serde_json::json!("bell\u{7}"),
            |d| d["version"] = serde_json::json!("1\u{0}"),
            |d| d["instanceId"] = serde_json::json!(""),
            |d| d["instanceId"] = serde_json::json!("x".repeat(MAX_IDENTIFIER_BYTES + 1)),
            |d| d["capabilityKeyId"] = serde_json::json!(""),
            |d| d["capabilityKeyId"] = serde_json::json!("a\tb"),
        ] {
            assert!(matches!(edited(edit), Err(ServerFailure::Invalid(_))));
        }
        assert!(
            edited(|document| document["name"] = serde_json::json!("x".repeat(MAX_NAME_CHARS)))
                .is_ok()
        );
    }

    #[test]
    fn missing_fields_and_garbage_are_refused() {
        for field in [
            "instanceId",
            "apiVersion",
            "capabilityKeyId",
            "capabilityPublicKey",
            "fingerprint",
        ] {
            let result = edited(|document| {
                document.as_object_mut().unwrap().remove(field);
            });
            assert!(matches!(result, Err(ServerFailure::Invalid(_))), "{field}");
        }
        for garbage in [
            &b""[..],
            b"{",
            b"null",
            b"[]",
            b"\"text\"",
            b"<html></html>",
        ] {
            assert!(matches!(
                parse_instance(garbage, CLIENT),
                Err(ServerFailure::Invalid(_))
            ));
        }
    }

    fn client(server: &TestServer) -> (Client, ServerAddress) {
        (
            client_for_base(&server.base()).unwrap(),
            ServerAddress::parse(&server.base()).unwrap(),
        )
    }

    fn inspect(
        server: &TestServer,
        link_fingerprint: Option<&str>,
    ) -> Result<InstanceInfo, ServerFailure> {
        let (client, address) = client(server);
        crate::test_support::block_on(inspect_server(&client, &address, link_fingerprint))
    }

    fn verify_pin(server: &TestServer, pin: &CustomServerPin) -> Result<(), ServerFailure> {
        let (client, address) = client(server);
        crate::test_support::block_on(verify_pinned_server(&client, &address, pin)).map(|_| ())
    }

    #[test]
    fn inspection_reads_only_the_two_public_documents() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let info = inspect(&server, Some(&fake.fingerprint())).unwrap();
        assert_eq!(info.fingerprint, fake.fingerprint());
        let requests = server.requests();
        assert_eq!(
            requests
                .iter()
                .map(|r| (r.method.as_str(), r.path.as_str()))
                .collect::<Vec<_>>(),
            vec![("GET", "/v1/instance"), ("GET", "/v1/capabilities")]
        );
        assert!(requests
            .iter()
            .all(|request| !request.headers.contains_key("authorization")));
        assert!(requests.iter().all(|request| request.body.is_empty()));
    }

    #[test]
    fn a_link_fingerprint_that_differs_stops_before_the_capability_document() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let other = FakeSesame::new(2).fingerprint();
        assert_eq!(
            inspect(&server, Some(&other)).unwrap_err(),
            ServerFailure::LinkMismatch
        );
        assert_eq!(server.paths(), vec!["/v1/instance".to_string()]);
    }

    #[test]
    fn a_server_that_announces_a_key_it_cannot_sign_with_is_refused() {
        let announced = FakeSesame::new(1);
        let signer = FakeSesame::new(2);
        let instance = announced.instance();
        let capabilities = signer.capabilities();
        let server = TestServer::start(move |request| match request.path.as_str() {
            "/v1/instance" => Reply::json(200, &instance),
            _ => Reply::json(200, &capabilities),
        });
        assert!(matches!(
            inspect(&server, None),
            Err(ServerFailure::Invalid(_))
        ));
    }

    #[test]
    fn a_server_that_replays_another_servers_documents_is_refused() {
        let victim = FakeSesame::new(1);
        let instance = victim.instance();
        let capabilities = victim.capabilities();
        let mut impostor = FakeSesame::new(2);
        impostor.key_id = victim.key_id.clone();
        let impostor_capabilities = impostor.capabilities();
        let honest = TestServer::start(move |request| match request.path.as_str() {
            "/v1/instance" => Reply::json(200, &instance),
            _ => Reply::json(200, &capabilities),
        });
        assert!(inspect(&honest, None).is_ok());
        let instance = victim.instance();
        let replaying = TestServer::start(move |request| match request.path.as_str() {
            "/v1/instance" => Reply::json(200, &instance),
            _ => Reply::json(200, &impostor_capabilities),
        });
        assert!(matches!(
            inspect(&replaying, None),
            Err(ServerFailure::Invalid(_))
        ));
    }

    #[test]
    fn a_server_with_linking_off_or_a_stale_capability_document_is_refused() {
        let mut off = FakeSesame::new(1);
        off.desktop_linking = false;
        assert!(matches!(
            inspect(&TestServer::start(off.handler()), None),
            Err(ServerFailure::Invalid(_))
        ));
        let mut stale = FakeSesame::new(1);
        stale.capability_expires_at = "2000-01-01T00:00:00Z".into();
        let failure = inspect(&TestServer::start(stale.handler()), None).unwrap_err();
        assert!(matches!(failure, ServerFailure::ClockDifference(_)));
        assert!(failure.message().contains("clock"));
    }

    #[test]
    fn an_incompatible_server_is_reported_before_anything_else_is_fetched() {
        let mut fake = FakeSesame::new(1);
        fake.api_version = 2;
        let server = TestServer::start(fake.handler());
        assert!(matches!(
            inspect(&server, None),
            Err(ServerFailure::Incompatible(_))
        ));
        assert_eq!(server.paths(), vec!["/v1/instance".to_string()]);
    }

    #[test]
    fn unreachable_missing_and_broken_servers_get_distinct_failures() {
        let (client, _) = client(&TestServer::start(|_| Reply::bytes(200, Vec::new())));
        let closed = ServerAddress::parse(&closed_port_base()).unwrap();
        assert_eq!(
            crate::test_support::block_on(inspect_server(&client, &closed, None)).unwrap_err(),
            ServerFailure::Unreachable
        );
        let missing = TestServer::start(|_| Reply::bytes(404, b"not found".to_vec()));
        assert!(matches!(
            inspect(&missing, None),
            Err(ServerFailure::Invalid(_))
        ));
        let down = TestServer::start(|_| Reply::bytes(503, Vec::new()));
        assert_eq!(
            inspect(&down, None).unwrap_err(),
            ServerFailure::Unreachable
        );
        let html = TestServer::start(|_| Reply::bytes(200, b"<html>login</html>".to_vec()));
        assert!(matches!(
            inspect(&html, None),
            Err(ServerFailure::Invalid(_))
        ));
        let huge = TestServer::start(|_| Reply::bytes(200, vec![b' '; MAX_INSTANCE_BYTES + 1]));
        assert!(matches!(
            inspect(&huge, None),
            Err(ServerFailure::Invalid(_))
        ));
    }

    #[test]
    fn a_redirect_from_the_instance_route_is_not_followed() {
        let fake = FakeSesame::new(1);
        let target = TestServer::start(fake.handler());
        let location = format!("{}/v1/instance", target.base());
        let redirecting = TestServer::start(move |_| {
            Reply::bytes(302, Vec::new()).with_header("Location", &location)
        });
        assert!(inspect(&redirecting, None).is_err());
        assert!(target.requests().is_empty());
    }

    #[test]
    fn an_address_with_a_path_prefix_keeps_the_prefix_on_every_request() {
        let fake = FakeSesame::new(1);
        let inner = fake.handler();
        let server = TestServer::start(move |request| {
            let mut stripped = request.clone();
            match request.path.strip_prefix("/sesame") {
                Some(rest) => {
                    stripped.path = rest.to_string();
                    inner(&stripped)
                }
                None => Reply::bytes(404, Vec::new()),
            }
        });
        let base = server.with_prefix("/sesame");
        let client = client_for_base(&base).unwrap();
        let address = ServerAddress::parse(&base).unwrap();
        assert!(crate::test_support::block_on(inspect_server(&client, &address, None)).is_ok());
        assert_eq!(
            server.paths(),
            vec![
                "/sesame/v1/instance".to_string(),
                "/sesame/v1/capabilities".to_string()
            ]
        );
    }

    #[test]
    fn a_pinned_server_that_still_holds_its_key_verifies() {
        let fake = FakeSesame::new(1);
        let server = TestServer::start(fake.handler());
        let pin = parse(&fake).unwrap().pin();
        assert_eq!(verify_pin(&server, &pin), Ok(()));
    }

    #[test]
    fn a_pinned_server_that_changed_its_key_is_refused_without_a_silent_update() {
        let pinned = FakeSesame::new(1);
        let pin = parse(&pinned).unwrap().pin();
        let rotated = FakeSesame::new(2);
        let server = TestServer::start(rotated.handler());
        assert_eq!(verify_pin(&server, &pin), Err(ServerFailure::KeyChanged));
        assert_eq!(server.paths(), vec!["/v1/instance".to_string()]);
    }

    #[test]
    fn a_pinned_server_that_changed_only_its_key_id_is_refused() {
        let pinned = FakeSesame::new(1);
        let pin = parse(&pinned).unwrap().pin();
        let mut renamed = FakeSesame::new(1);
        renamed.key_id = "key-rotated".into();
        let server = TestServer::start(renamed.handler());
        assert_eq!(verify_pin(&server, &pin), Err(ServerFailure::KeyChanged));
    }

    #[test]
    fn an_impostor_that_repeats_the_pinned_public_key_without_the_private_key_is_refused() {
        let pinned = FakeSesame::new(1);
        let pin = parse(&pinned).unwrap().pin();
        let instance = pinned.instance();
        let impostor_capabilities = FakeSesame::new(2).signed(&pinned.capability_payload());
        let server = TestServer::start(move |request| match request.path.as_str() {
            "/v1/instance" => Reply::json(200, &instance),
            _ => Reply::json(200, &impostor_capabilities),
        });
        assert_eq!(verify_pin(&server, &pin), Err(ServerFailure::KeyChanged));
    }

    #[test]
    fn a_pinned_server_that_serves_a_stale_capability_document_is_not_trusted_further() {
        let mut fake = FakeSesame::new(1);
        let pin = parse(&fake).unwrap().pin();
        fake.capability_expires_at = "2000-01-01T00:00:00Z".into();
        let server = TestServer::start(fake.handler());
        assert!(matches!(
            verify_pin(&server, &pin),
            Err(ServerFailure::ClockDifference(_))
        ));
    }

    #[test]
    fn a_pinned_server_that_is_down_is_unreachable_not_changed() {
        let fake = FakeSesame::new(1);
        let pin = parse(&fake).unwrap().pin();
        let down = TestServer::start(|_| Reply::bytes(502, Vec::new()));
        assert_eq!(verify_pin(&down, &pin), Err(ServerFailure::Unreachable));
        let closed = ServerAddress::parse(&closed_port_base()).unwrap();
        let (client, _) = client(&down);
        assert_eq!(
            crate::test_support::block_on(verify_pinned_server(&client, &closed, &pin)),
            Err(ServerFailure::Unreachable)
        );
    }

    #[test]
    fn a_pinned_server_with_a_forged_stored_pin_is_refused() {
        let fake = FakeSesame::new(1);
        let mut pin = parse(&fake).unwrap().pin();
        pin.fingerprint = FakeSesame::new(2).fingerprint();
        let server = TestServer::start(fake.handler());
        assert!(verify_pin(&server, &pin).is_err());
        assert!(server.requests().is_empty());
    }

    fn pinned_time(server: &TestServer, pin: &CustomServerPin) -> Option<u64> {
        let (client, address) = client(server);
        crate::test_support::block_on(pinned_server_time(&client, &address, pin))
    }

    #[test]
    fn a_pinned_server_gives_the_time_from_its_date_header() {
        let mut fake = FakeSesame::new(1);
        let pin = parse(&fake).unwrap().pin();
        fake.date = Some(1_800_000_000);
        let server = TestServer::start(fake.handler());
        assert_eq!(pinned_time(&server, &pin), Some(1_800_000_000));
        assert_eq!(
            server.paths(),
            vec!["/v1/instance".to_string(), "/v1/capabilities".to_string()]
        );
    }

    #[test]
    fn a_server_that_repeats_the_pinned_public_key_without_signing_gives_no_time() {
        let pinned = FakeSesame::new(1);
        let pin = parse(&pinned).unwrap().pin();
        let instance = pinned.instance();
        let forged = FakeSesame::new(2).signed(&pinned.capability_payload());
        let server = TestServer::start(move |request| {
            let reply = match request.path.as_str() {
                "/v1/instance" => Reply::json(200, &instance),
                _ => Reply::json(200, &forged),
            };
            reply.with_date(1_800_000_000)
        });
        assert_eq!(pinned_time(&server, &pin), None);
    }

    #[test]
    fn a_server_that_serves_no_capability_document_gives_no_time() {
        let pinned = FakeSesame::new(1);
        let pin = parse(&pinned).unwrap().pin();
        let instance = pinned.instance();
        let server = TestServer::start(move |request| match request.path.as_str() {
            "/v1/instance" => Reply::json(200, &instance).with_date(1_800_000_000),
            _ => Reply::bytes(404, Vec::new()),
        });
        assert_eq!(pinned_time(&server, &pin), None);
    }

    #[test]
    fn a_server_with_another_key_or_no_date_gives_no_time() {
        let fake = FakeSesame::new(1);
        let pin = parse(&fake).unwrap().pin();
        let mut rotated = FakeSesame::new(2);
        rotated.date = Some(1_800_000_000);
        let foreign = TestServer::start(rotated.handler());
        assert_eq!(pinned_time(&foreign, &pin), None);
        let undated = TestServer::start(fake.handler());
        assert_eq!(pinned_time(&undated, &pin), None);
        let instance = fake.instance();
        let capabilities = fake.capabilities();
        let garbled = TestServer::start(move |request| {
            let reply = match request.path.as_str() {
                "/v1/instance" => Reply::json(200, &instance),
                _ => Reply::json(200, &capabilities),
            };
            reply.with_header("Date", "yesterday-ish")
        });
        assert_eq!(pinned_time(&garbled, &pin), None);
    }
}
