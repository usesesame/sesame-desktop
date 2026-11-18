use std::time::Duration;

use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION};
use reqwest::{redirect::Policy, Client, StatusCode};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::account_service::read_limited;
use super::ensure_crypto_provider;
use crate::vault::{is_plausible_alias, EmailAliasService};

pub const ADDY_API_ORIGIN: &str = "https://app.addy.io";
pub const SIMPLELOGIN_API_ORIGIN: &str = "https://app.simplelogin.io";
const ADDY_ALIAS_PATH: &str = "/api/v1/aliases";
const SIMPLELOGIN_ALIAS_PATH: &str = "/api/alias/random/new";
const ALIAS_TIMEOUT_SECS: u64 = 10;
const ALIAS_CONNECT_TIMEOUT_SECS: u64 = 4;
pub const ALIAS_MAX_BODY_BYTES: usize = 64 * 1024;
const ADDY_MAX_DESCRIPTION_CHARS: usize = 200;

pub struct AliasRequest {
    pub service: EmailAliasService,
    pub token: Zeroizing<String>,
    pub domain: String,
    pub description: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasFailure {
    NotSent,
    NotConnected,
    Unreachable,
    TokenRefused,
    DomainRefused,
    LimitReached,
    RateLimited,
    ServiceDown,
    Refused,
    UnusableAnswer,
}

impl AliasFailure {
    pub fn message(self) -> &'static str {
        match self {
            Self::NotSent => "Sesame could not prepare the request, so your API token was not sent.",
            Self::NotConnected => {
                "Sesame could not reach the alias service. Check your connection and try again."
            }
            Self::Unreachable => {
                "The connection to the alias service ended before it answered, so an alias may have been made. Check your alias service before you try again."
            }
            Self::TokenRefused => {
                "The alias service did not accept your API token. Paste a new one in Settings."
            }
            Self::DomainRefused => {
                "addy.io did not accept the alias domain. Check the domain in Settings."
            }
            Self::LimitReached => {
                "The alias service would not make another alias. Your plan may have reached its limit."
            }
            Self::RateLimited => {
                "The alias service is not taking new aliases right now. Wait a while, or check your plan's limit."
            }
            Self::ServiceDown => "The alias service is having trouble. Try again later.",
            Self::Refused => "The alias service turned down the request, so no alias was made.",
            Self::UnusableAnswer => {
                "The alias service sent an answer Sesame could not use, so no alias was added."
            }
        }
    }
}

impl AliasFailure {
    pub fn token_may_have_left(self) -> bool {
        !matches!(self, Self::NotSent | Self::NotConnected)
    }
}

impl From<AliasFailure> for String {
    fn from(failure: AliasFailure) -> Self {
        failure.message().to_string()
    }
}

pub fn api_origin(service: EmailAliasService) -> &'static str {
    match service {
        EmailAliasService::Addy => ADDY_API_ORIGIN,
        EmailAliasService::SimpleLogin => SIMPLELOGIN_API_ORIGIN,
    }
}

pub fn api_host(service: EmailAliasService) -> &'static str {
    api_origin(service).trim_start_matches("https://")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AliasClientPolicy {
    https_only: bool,
    follow_redirects: bool,
    connect_timeout: Duration,
    timeout: Duration,
}

fn alias_client_policy() -> AliasClientPolicy {
    AliasClientPolicy {
        https_only: true,
        follow_redirects: false,
        connect_timeout: Duration::from_secs(ALIAS_CONNECT_TIMEOUT_SECS),
        timeout: Duration::from_secs(ALIAS_TIMEOUT_SECS),
    }
}

fn client_with(policy: AliasClientPolicy) -> Result<Client, AliasFailure> {
    ensure_crypto_provider();
    Client::builder()
        .https_only(policy.https_only)
        .redirect(if policy.follow_redirects {
            Policy::limited(1)
        } else {
            Policy::none()
        })
        .connect_timeout(policy.connect_timeout)
        .timeout(policy.timeout)
        .build()
        .map_err(|_| AliasFailure::NotSent)
}

pub async fn create_alias(request: &AliasRequest) -> Result<String, AliasFailure> {
    let client = client_with(alias_client_policy())?;
    create_alias_at(&client, api_origin(request.service), request).await
}

fn secret_header(value: &str) -> Result<HeaderValue, AliasFailure> {
    let mut header = HeaderValue::from_str(value).map_err(|_| AliasFailure::NotSent)?;
    header.set_sensitive(true);
    Ok(header)
}

async fn create_alias_at(
    client: &Client,
    origin: &str,
    request: &AliasRequest,
) -> Result<String, AliasFailure> {
    let builder = match request.service {
        EmailAliasService::Addy => {
            let mut body = serde_json::Map::new();
            body.insert("domain".into(), request.domain.clone().into());
            if let Some(description) = request
                .description
                .as_ref()
                .filter(|description| description.chars().count() <= ADDY_MAX_DESCRIPTION_CHARS)
            {
                body.insert("description".into(), description.clone().into());
            }
            let bearer = Zeroizing::new(format!("Bearer {}", request.token.as_str()));
            client
                .post(format!("{origin}{ADDY_ALIAS_PATH}"))
                .header(AUTHORIZATION, secret_header(&bearer)?)
                .header(ACCEPT, "application/json")
                .header("X-Requested-With", "XMLHttpRequest")
                .json(&body)
        }
        EmailAliasService::SimpleLogin => {
            let mut body = serde_json::Map::new();
            if let Some(description) = &request.description {
                body.insert("note".into(), description.clone().into());
            }
            client
                .post(format!("{origin}{SIMPLELOGIN_ALIAS_PATH}"))
                .header("Authentication", secret_header(&request.token)?)
                .header(ACCEPT, "application/json")
                .json(&body)
        }
    };
    let response = builder.send().await.map_err(|error| send_failure(&error))?;
    let status = response.status();
    if !status.is_success() {
        return Err(failure_for_status(request.service, status));
    }
    if status != StatusCode::OK && status != StatusCode::CREATED {
        return Err(AliasFailure::UnusableAnswer);
    }
    let body = read_limited(response, ALIAS_MAX_BODY_BYTES)
        .await
        .ok_or(AliasFailure::UnusableAnswer)?;
    alias_from_body(request.service, &body)
}

fn send_failure(error: &reqwest::Error) -> AliasFailure {
    if error.is_builder() {
        AliasFailure::NotSent
    } else if error.is_connect() {
        AliasFailure::NotConnected
    } else {
        AliasFailure::Unreachable
    }
}

fn failure_for_status(service: EmailAliasService, status: StatusCode) -> AliasFailure {
    match (service, status.as_u16()) {
        (_, 401) => AliasFailure::TokenRefused,
        (_, 429) => AliasFailure::RateLimited,
        (EmailAliasService::Addy, 422) => AliasFailure::DomainRefused,
        (EmailAliasService::SimpleLogin, 400) => AliasFailure::LimitReached,
        (_, 500..=599) => AliasFailure::ServiceDown,
        (_, 300..=399) => AliasFailure::UnusableAnswer,
        _ => AliasFailure::Refused,
    }
}

#[derive(Deserialize)]
struct AddyAnswer {
    data: AddyAlias,
}

#[derive(Deserialize)]
struct AddyAlias {
    email: String,
}

#[derive(Deserialize)]
struct SimpleLoginAnswer {
    alias: Option<String>,
    email: Option<String>,
}

fn alias_from_body(service: EmailAliasService, body: &[u8]) -> Result<String, AliasFailure> {
    let alias = match service {
        EmailAliasService::Addy => {
            serde_json::from_slice::<AddyAnswer>(body)
                .map_err(|_| AliasFailure::UnusableAnswer)?
                .data
                .email
        }
        EmailAliasService::SimpleLogin => {
            let answer = serde_json::from_slice::<SimpleLoginAnswer>(body)
                .map_err(|_| AliasFailure::UnusableAnswer)?;
            answer
                .alias
                .or(answer.email)
                .ok_or(AliasFailure::UnusableAnswer)?
        }
    };
    if !is_plausible_alias(&alias) {
        return Err(AliasFailure::UnusableAnswer);
    }
    Ok(alias)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::test_server::{Recorded, Reply, TestServer};

    const TOKEN: &str = "fictional-alias-token";

    fn request(service: EmailAliasService, description: Option<&str>) -> AliasRequest {
        AliasRequest {
            service,
            token: Zeroizing::new(TOKEN.to_string()),
            domain: match service {
                EmailAliasService::Addy => "anonaddy.me".to_string(),
                EmailAliasService::SimpleLogin => String::new(),
            },
            description: description.map(str::to_string),
        }
    }

    fn local_client(timeout: Duration) -> Client {
        client_with(AliasClientPolicy {
            https_only: false,
            timeout,
            ..alias_client_policy()
        })
        .expect("local client")
    }

    fn create_against(server: &TestServer, request: &AliasRequest) -> Result<String, AliasFailure> {
        crate::test_support::block_on(create_alias_at(
            &local_client(Duration::from_secs(5)),
            &server.base(),
            request,
        ))
    }

    fn addy_answer(email: &str) -> Reply {
        Reply::json(
            201,
            &serde_json::json!({
                "data": {
                    "id": "50c9e585-e7f5-41c4-9016-9014c15454bc",
                    "local_part": "fictional.alias",
                    "domain": "anonaddy.me",
                    "email": email,
                    "active": true,
                    "description": null,
                }
            }),
        )
    }

    fn simplelogin_answer(alias: &str) -> Reply {
        Reply::json(
            201,
            &serde_json::json!({
                "alias": alias,
                "email": alias,
                "id": 3,
                "enabled": true,
                "note": null,
                "mailboxes": [{ "id": 1, "email": "owner@fictional.example" }],
            }),
        )
    }

    fn body_of(recorded: &Recorded) -> serde_json::Value {
        serde_json::from_slice(&recorded.body).expect("json body")
    }

    #[test]
    fn an_addy_alias_is_requested_with_the_documented_shape() {
        let server = TestServer::start(|_| addy_answer("fictional.alias@anonaddy.me"));
        let alias = create_against(
            &server,
            &request(EmailAliasService::Addy, Some("example.com")),
        )
        .expect("alias");
        assert_eq!(alias, "fictional.alias@anonaddy.me");

        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        let sent = &requests[0];
        assert_eq!(sent.method, "POST");
        assert_eq!(sent.path, "/api/v1/aliases");
        assert_eq!(
            sent.headers.get("authorization").map(String::as_str),
            Some("Bearer fictional-alias-token")
        );
        assert_eq!(
            sent.headers.get("x-requested-with").map(String::as_str),
            Some("XMLHttpRequest")
        );
        assert_eq!(
            sent.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert!(!sent.headers.contains_key("authentication"));
        assert!(!sent.headers.contains_key("cookie"));
        assert_eq!(
            body_of(sent),
            serde_json::json!({ "domain": "anonaddy.me", "description": "example.com" })
        );
    }

    #[test]
    fn an_addy_description_over_its_limit_is_left_out() {
        let fits = format!("{}.example.com", "a".repeat(188));
        let over = format!("{}.example.com", "a".repeat(189));
        for (description, expected) in [
            (
                fits.as_str(),
                serde_json::json!({ "domain": "anonaddy.me", "description": fits }),
            ),
            (
                over.as_str(),
                serde_json::json!({ "domain": "anonaddy.me" }),
            ),
        ] {
            let server = TestServer::start(|_| addy_answer("fictional.alias@anonaddy.me"));
            create_against(
                &server,
                &request(EmailAliasService::Addy, Some(description)),
            )
            .expect("alias");
            assert_eq!(body_of(&server.requests()[0]), expected);
        }
    }

    #[test]
    fn a_simplelogin_alias_is_requested_with_the_documented_shape() {
        let server = TestServer::start(|_| simplelogin_answer("fictional_alias@slmail.example"));
        let alias = create_against(
            &server,
            &request(EmailAliasService::SimpleLogin, Some("example.com")),
        )
        .expect("alias");
        assert_eq!(alias, "fictional_alias@slmail.example");

        let sent = &server.requests()[0];
        assert_eq!(sent.method, "POST");
        assert_eq!(sent.path, "/api/alias/random/new");
        assert_eq!(
            sent.headers.get("authentication").map(String::as_str),
            Some(TOKEN)
        );
        assert!(!sent.headers.contains_key("authorization"));
        assert_eq!(body_of(sent), serde_json::json!({ "note": "example.com" }));
    }

    #[test]
    fn without_a_description_neither_service_hears_about_the_site() {
        let addy = TestServer::start(|_| addy_answer("fictional.alias@anonaddy.me"));
        create_against(&addy, &request(EmailAliasService::Addy, None)).expect("addy alias");
        let sent = &addy.requests()[0];
        assert_eq!(
            body_of(sent),
            serde_json::json!({ "domain": "anonaddy.me" })
        );

        let simplelogin =
            TestServer::start(|_| simplelogin_answer("fictional_alias@slmail.example"));
        create_against(&simplelogin, &request(EmailAliasService::SimpleLogin, None))
            .expect("simplelogin alias");
        let sent = &simplelogin.requests()[0];
        assert_eq!(sent.path, "/api/alias/random/new");
        assert!(!sent.path.contains('?'));
        assert_eq!(body_of(sent), serde_json::json!({}));
    }

    #[test]
    fn a_rejected_token_is_reported_in_sesames_words() {
        for service in [EmailAliasService::Addy, EmailAliasService::SimpleLogin] {
            let server = TestServer::start(|_| {
                Reply::json(
                    401,
                    &serde_json::json!({ "error": "fictional raw service text" }),
                )
            });
            let failure = create_against(&server, &request(service, None)).unwrap_err();
            assert_eq!(failure, AliasFailure::TokenRefused);
            assert!(!String::from(failure).contains("fictional raw service text"));
        }
    }

    #[test]
    fn error_statuses_map_to_sesames_own_messages() {
        let cases = [
            (EmailAliasService::Addy, 422, AliasFailure::DomainRefused),
            (EmailAliasService::Addy, 403, AliasFailure::Refused),
            (EmailAliasService::Addy, 429, AliasFailure::RateLimited),
            (EmailAliasService::Addy, 503, AliasFailure::ServiceDown),
            (EmailAliasService::Addy, 404, AliasFailure::Refused),
            (
                EmailAliasService::SimpleLogin,
                400,
                AliasFailure::LimitReached,
            ),
            (
                EmailAliasService::SimpleLogin,
                429,
                AliasFailure::RateLimited,
            ),
            (
                EmailAliasService::SimpleLogin,
                500,
                AliasFailure::ServiceDown,
            ),
            (EmailAliasService::SimpleLogin, 409, AliasFailure::Refused),
        ];
        for (service, status, expected) in cases {
            let server = TestServer::start(move |_| {
                Reply::json(
                    status,
                    &serde_json::json!({ "error": "fictional raw service text" }),
                )
            });
            let failure = create_against(&server, &request(service, None)).unwrap_err();
            assert_eq!(failure, expected, "{service:?} {status}");
            assert!(!failure.message().contains("fictional raw service text"));
        }
    }

    #[test]
    fn a_success_status_other_than_ok_or_created_is_not_trusted() {
        let server = TestServer::start(|_| Reply::bytes(204, Vec::new()));
        assert_eq!(
            create_against(&server, &request(EmailAliasService::Addy, None)),
            Err(AliasFailure::UnusableAnswer)
        );
    }

    #[test]
    fn a_slow_service_times_out() {
        let server = TestServer::start(|_| {
            std::thread::sleep(Duration::from_millis(2_500));
            addy_answer("fictional.alias@anonaddy.me")
        });
        let started = std::time::Instant::now();
        let result = crate::test_support::block_on(create_alias_at(
            &local_client(Duration::from_millis(600)),
            &server.base(),
            &request(EmailAliasService::Addy, None),
        ));
        assert_eq!(result, Err(AliasFailure::Unreachable));
        assert!(AliasFailure::Unreachable.token_may_have_left());
        assert_eq!(server.requests().len(), 1);
        assert!(started.elapsed() < Duration::from_millis(2_000));
    }

    #[test]
    fn an_oversized_answer_is_refused() {
        let padding = "x".repeat(ALIAS_MAX_BODY_BYTES);
        let server = TestServer::start(move |_| {
            Reply::json(
                201,
                &serde_json::json!({
                    "data": { "email": "fictional.alias@anonaddy.me", "padding": padding }
                }),
            )
        });
        assert_eq!(
            create_against(&server, &request(EmailAliasService::Addy, None)),
            Err(AliasFailure::UnusableAnswer)
        );
    }

    #[test]
    fn a_redirect_is_not_followed_by_the_production_policy_and_the_token_goes_nowhere_else() {
        let target = TestServer::start(|_| addy_answer("fictional.alias@anonaddy.me"));
        let target_base = target.base();
        let redirecting = TestServer::start(move |_| {
            Reply::bytes(307, Vec::new())
                .with_header("Location", &format!("{target_base}/api/v1/aliases"))
        });
        for service in [EmailAliasService::Addy, EmailAliasService::SimpleLogin] {
            assert_eq!(
                create_against(&redirecting, &request(service, None)),
                Err(AliasFailure::UnusableAnswer)
            );
        }
        assert!(target.requests().is_empty());
    }

    #[test]
    fn malformed_answers_are_refused() {
        let bodies: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"{".to_vec(),
            b"null".to_vec(),
            b"[]".to_vec(),
            b"<html>fictional</html>".to_vec(),
            br#"{"data":{}}"#.to_vec(),
            br#"{"data":{"email":42}}"#.to_vec(),
            br#"{"alias":null,"email":null}"#.to_vec(),
            br#"{"alias":["fictional@anonaddy.me"]}"#.to_vec(),
            vec![0xff, 0xfe, 0x00],
        ];
        for body in bodies {
            for service in [EmailAliasService::Addy, EmailAliasService::SimpleLogin] {
                let reply = body.clone();
                let server = TestServer::start(move |_| Reply::bytes(201, reply.clone()));
                assert_eq!(
                    create_against(&server, &request(service, None)),
                    Err(AliasFailure::UnusableAnswer),
                    "{service:?} {}",
                    String::from_utf8_lossy(&body)
                );
            }
        }
    }

    #[test]
    fn an_alias_that_is_not_a_plain_address_is_refused() {
        for alias in [
            "not-an-address",
            "fictional@anonaddy.me\r\nBcc: someone@fictional.example",
            "<script>@anonaddy.me",
            "fictional@localhost",
            " fictional@anonaddy.me",
            "fictional@anonaddy.me ",
        ] {
            let addy_alias = alias.to_string();
            let addy = TestServer::start(move |_| addy_answer(&addy_alias));
            assert_eq!(
                create_against(&addy, &request(EmailAliasService::Addy, None)),
                Err(AliasFailure::UnusableAnswer),
                "{alias:?}"
            );
            let simplelogin_alias = alias.to_string();
            let simplelogin = TestServer::start(move |_| simplelogin_answer(&simplelogin_alias));
            assert_eq!(
                create_against(&simplelogin, &request(EmailAliasService::SimpleLogin, None)),
                Err(AliasFailure::UnusableAnswer),
                "{alias:?}"
            );
        }
    }

    const FIXTURE_WAIT: Duration = Duration::from_secs(3);

    fn serve_one_answer(declared_extra: usize) -> (String, std::sync::mpsc::Receiver<()>) {
        use std::io::{ErrorKind, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let body = serde_json::to_vec(&serde_json::json!({
            "data": { "email": "fictional.alias@anonaddy.me" }
        }))
        .expect("body");
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + FIXTURE_WAIT;
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {
                        let _ = done.send(());
                        return;
                    }
                }
            };
            let ready = stream.set_nonblocking(false).is_ok()
                && stream.set_read_timeout(Some(FIXTURE_WAIT)).is_ok();
            let mut seen = Vec::new();
            let mut chunk = [0u8; 4096];
            while ready && !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => {
                        let _ = done.send(());
                        return;
                    }
                    Ok(read) => seen.extend_from_slice(&chunk[..read]),
                }
            }
            if ready {
                let head = format!(
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len() + declared_extra
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
            let _ = done.send(());
        });
        (base, finished)
    }

    fn answer_declaring(declared_extra: usize) -> Result<String, AliasFailure> {
        let (base, finished) = serve_one_answer(declared_extra);
        ensure_crypto_provider();
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(FIXTURE_WAIT)
            .build()
            .expect("fixture client");
        let result = crate::test_support::block_on(create_alias_at(
            &client,
            &base,
            &request(EmailAliasService::Addy, None),
        ));
        assert!(finished.recv_timeout(FIXTURE_WAIT * 2).is_ok());
        result
    }

    #[test]
    fn the_answer_fixture_stops_when_no_request_arrives() {
        let (_, finished) = serve_one_answer(0);
        assert!(finished.recv_timeout(FIXTURE_WAIT * 2).is_ok());

        let (base, finished) = serve_one_answer(0);
        let address = base.trim_start_matches("http://").to_string();
        drop(std::net::TcpStream::connect(address).expect("connection"));
        assert!(finished.recv_timeout(FIXTURE_WAIT * 2).is_ok());
    }

    #[test]
    fn an_answer_cut_off_before_its_end_is_not_used() {
        assert_eq!(
            answer_declaring(0),
            Ok("fictional.alias@anonaddy.me".to_string())
        );
        assert_eq!(answer_declaring(40), Err(AliasFailure::UnusableAnswer));
    }

    #[test]
    fn a_dropped_connection_is_reported_as_unreachable() {
        let server = TestServer::start(|_| Reply::disconnect());
        let failure =
            create_against(&server, &request(EmailAliasService::SimpleLogin, None)).unwrap_err();
        assert_eq!(failure, AliasFailure::Unreachable);
        assert!(failure.token_may_have_left());
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn a_refused_connection_is_known_to_have_sent_nothing() {
        let failure = crate::test_support::block_on(create_alias_at(
            &local_client(Duration::from_secs(5)),
            &crate::network::test_server::closed_port_base(),
            &request(EmailAliasService::Addy, None),
        ))
        .unwrap_err();
        assert_eq!(failure, AliasFailure::NotConnected);
        assert!(!failure.token_may_have_left());
    }

    #[test]
    fn only_a_request_that_never_left_is_worth_simply_trying_again() {
        assert!(AliasFailure::NotConnected.message().contains("try again"));
        let unsure = AliasFailure::Unreachable.message();
        assert!(unsure.contains("may have been made"));
        assert!(unsure.contains("Check your alias service before you try again"));
    }

    #[test]
    fn the_production_client_uses_the_hardened_settings() {
        let policy = alias_client_policy();
        assert!(policy.https_only);
        assert!(!policy.follow_redirects);
        assert!(policy.connect_timeout <= policy.timeout);
        assert_eq!(policy.timeout, Duration::from_secs(10));
        assert_eq!(ALIAS_MAX_BODY_BYTES, 64 * 1024);
    }

    #[test]
    fn the_production_client_refuses_a_plain_http_endpoint() {
        let server = TestServer::start(|_| addy_answer("fictional.alias@anonaddy.me"));
        assert!(server.base().starts_with("http://"));
        let client = client_with(alias_client_policy()).expect("client");
        for service in [EmailAliasService::Addy, EmailAliasService::SimpleLogin] {
            let failure = crate::test_support::block_on(create_alias_at(
                &client,
                &server.base(),
                &request(service, None),
            ))
            .unwrap_err();
            assert_eq!(failure, AliasFailure::NotSent, "{service:?}");
            assert!(!failure.token_may_have_left());
        }
        assert!(server.requests().is_empty());
    }

    #[test]
    fn only_the_two_documented_api_hosts_are_used() {
        assert_eq!(api_origin(EmailAliasService::Addy), "https://app.addy.io");
        assert_eq!(
            api_origin(EmailAliasService::SimpleLogin),
            "https://app.simplelogin.io"
        );
        assert_eq!(api_host(EmailAliasService::Addy), "app.addy.io");
        assert_eq!(
            api_host(EmailAliasService::SimpleLogin),
            "app.simplelogin.io"
        );
    }

    #[test]
    fn a_token_that_cannot_be_a_header_is_never_sent() {
        let server = TestServer::start(|_| addy_answer("fictional.alias@anonaddy.me"));
        let mut bad = request(EmailAliasService::SimpleLogin, None);
        bad.token = Zeroizing::new("fictional\ntoken".to_string());
        let failure = create_against(&server, &bad).unwrap_err();
        assert_eq!(failure, AliasFailure::NotSent);
        assert!(!failure.token_may_have_left());
        assert!(server.requests().is_empty());
    }
}
