use std::time::Duration;

use reqwest::{header::DATE, redirect::Policy, Client};

use super::account_service::{client_for_base, pin_key, service_target, ServiceTarget};
use super::ensure_crypto_provider;
use super::server_address::ServerAddress;
use super::server_trust::pinned_server_time;
use crate::vault::types::{CustomServerPin, ServiceConnectionFile};
use crate::vault::VaultResult;

const COMPANY_SOURCES: [&str; 2] = ["https://usesesame.app/", "https://github.com/"];
const MAX_SOURCE_DISAGREEMENT_SECS: u64 = 5 * 60;
const TIME_SOURCE_TIMEOUT_SECS: u64 = 10;
const TIME_UNAVAILABLE: &str = "Sesame could not confirm the current time with usesesame.app and github.com. Connect to the internet and try again.";
const TIME_DISAGREES: &str =
    "The time servers disagree, so Sesame cannot confirm the current time. Try again later.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TrustedTime {
    pub earliest: u64,
    pub latest: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reading {
    At(u64),
    Unreachable,
    Unusable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinkedTimeSource {
    address: ServerAddress,
    pin: CustomServerPin,
}

impl LinkedTimeSource {
    #[cfg(test)]
    pub(crate) fn new(address: ServerAddress, pin: CustomServerPin) -> Self {
        Self { address, pin }
    }
}

pub(crate) fn linked_time_source(connection: &ServiceConnectionFile) -> Option<LinkedTimeSource> {
    let ServiceTarget::Custom { address, pin } = service_target(connection).ok()? else {
        return None;
    };
    pin_key(&pin)?;
    (!address.is_loopback()).then_some(LinkedTimeSource { address, pin })
}

pub(crate) fn parse_http_date(value: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc2822(value)
        .ok()
        .and_then(|moment| u64::try_from(moment.timestamp()).ok())
}

fn within_tolerance(first: u64, second: u64) -> VaultResult<TrustedTime> {
    let (earliest, latest) = (first.min(second), first.max(second));
    if latest - earliest > MAX_SOURCE_DISAGREEMENT_SECS {
        return Err(TIME_DISAGREES.into());
    }
    Ok(TrustedTime { earliest, latest })
}

pub(crate) fn agreed_time(
    first: Reading,
    second: Reading,
    linked: Option<u64>,
) -> VaultResult<TrustedTime> {
    match (first, second) {
        (Reading::At(first), Reading::At(second)) => within_tolerance(first, second),
        (Reading::At(answered), Reading::Unreachable)
        | (Reading::Unreachable, Reading::At(answered)) => match linked {
            Some(linked) => within_tolerance(answered, linked),
            None => Err(TIME_UNAVAILABLE.into()),
        },
        _ => Err(TIME_UNAVAILABLE.into()),
    }
}

fn company_client(https_only: bool) -> VaultResult<Client> {
    ensure_crypto_provider();
    Client::builder()
        .https_only(https_only)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(TIME_SOURCE_TIMEOUT_SECS))
        .timeout(Duration::from_secs(TIME_SOURCE_TIMEOUT_SECS))
        .build()
        .map_err(|_| TIME_UNAVAILABLE.to_string())
}

async fn company_reading(url: String, https_only: bool) -> Reading {
    let Ok(client) = company_client(https_only) else {
        return Reading::Unreachable;
    };
    match client.head(url).send().await {
        Err(_) => Reading::Unreachable,
        Ok(response) => response
            .headers()
            .get(DATE)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_http_date)
            .map_or(Reading::Unusable, Reading::At),
    }
}

async fn linked_reading(linked: LinkedTimeSource) -> Option<u64> {
    let client = client_for_base(linked.address.as_str()).ok()?;
    pinned_server_time(&client, &linked.address, &linked.pin).await
}

async fn collect_time(
    company: [String; 2],
    https_only: bool,
    linked: Option<LinkedTimeSource>,
) -> VaultResult<TrustedTime> {
    let [first, second] = company;
    let first = tauri::async_runtime::spawn(company_reading(first, https_only));
    let second = tauri::async_runtime::spawn(company_reading(second, https_only));
    let linked = linked.map(|linked| tauri::async_runtime::spawn(linked_reading(linked)));
    let first = first.await.unwrap_or(Reading::Unreachable);
    let second = second.await.unwrap_or(Reading::Unreachable);
    let linked = match linked {
        Some(handle) => handle.await.ok().flatten(),
        None => None,
    };
    agreed_time(first, second, linked)
}

pub(crate) async fn trusted_time(linked: Option<LinkedTimeSource>) -> VaultResult<TrustedTime> {
    collect_time(COMPANY_SOURCES.map(str::to_string), true, linked).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::network::server_trust::parse_instance;
    use crate::adapters::network::test_server::{closed_port_base, FakeSesame, Reply, TestServer};

    const START: u64 = 1_800_000_000;
    const TOLERANCE: u64 = MAX_SOURCE_DISAGREEMENT_SECS;
    const YEAR: u64 = 365 * 24 * 60 * 60;

    #[test]
    fn an_http_date_reads_as_unix_seconds() {
        assert_eq!(
            parse_http_date("Sat, 03 Oct 2026 14:00:00 GMT"),
            Some(1_791_036_000)
        );
        assert_eq!(parse_http_date("not a date"), None);
        assert_eq!(parse_http_date(""), None);
    }

    #[test]
    fn two_company_readings_that_agree_give_their_earliest_and_latest() {
        assert_eq!(
            agreed_time(Reading::At(1_000_100), Reading::At(1_000_000), None),
            Ok(TrustedTime {
                earliest: 1_000_000,
                latest: 1_000_100
            })
        );
    }

    #[test]
    fn two_company_readings_that_disagree_are_refused_whatever_the_linked_server_says() {
        let apart = START + TOLERANCE + 1;
        for linked in [None, Some(START), Some(apart), Some(START + 10)] {
            assert_eq!(
                agreed_time(Reading::At(START), Reading::At(apart), linked),
                Err(TIME_DISAGREES.to_string()),
                "{linked:?}"
            );
        }
        assert!(agreed_time(Reading::At(START), Reading::At(START + TOLERANCE), None).is_ok());
    }

    #[test]
    fn a_far_future_company_source_is_never_outvoted_by_the_linked_server() {
        let future = START + 10 * YEAR;
        assert!(agreed_time(Reading::At(START), Reading::At(future), Some(START)).is_err());
        assert!(agreed_time(Reading::At(START), Reading::At(future), Some(future)).is_err());
    }

    #[test]
    fn one_unreachable_company_source_with_no_linked_server_is_refused() {
        for answering in [Reading::At(START), Reading::Unreachable, Reading::Unusable] {
            assert_eq!(
                agreed_time(answering, Reading::Unreachable, None),
                Err(TIME_UNAVAILABLE.to_string())
            );
            assert_eq!(
                agreed_time(Reading::Unreachable, answering, None),
                Err(TIME_UNAVAILABLE.to_string())
            );
        }
    }

    #[test]
    fn a_linked_server_stands_in_for_an_unreachable_company_source_when_it_agrees() {
        for pair in [
            (Reading::At(START), Reading::Unreachable),
            (Reading::Unreachable, Reading::At(START)),
        ] {
            assert_eq!(
                agreed_time(pair.0, pair.1, Some(START + 30)),
                Ok(TrustedTime {
                    earliest: START,
                    latest: START + 30
                })
            );
        }
    }

    #[test]
    fn a_linked_server_that_disagrees_with_the_answering_source_is_refused() {
        assert_eq!(
            agreed_time(
                Reading::At(START),
                Reading::Unreachable,
                Some(START + TOLERANCE + 1)
            ),
            Err(TIME_DISAGREES.to_string())
        );
        assert_eq!(
            agreed_time(
                Reading::At(START),
                Reading::Unreachable,
                Some(START + 10 * YEAR)
            ),
            Err(TIME_DISAGREES.to_string())
        );
    }

    #[test]
    fn a_linked_server_alone_or_an_answer_without_a_date_never_stands_in() {
        assert!(agreed_time(Reading::Unreachable, Reading::Unreachable, Some(START)).is_err());
        assert!(agreed_time(Reading::Unusable, Reading::Unreachable, Some(START)).is_err());
        assert!(agreed_time(Reading::Unusable, Reading::At(START), Some(START)).is_err());
        assert!(agreed_time(Reading::Unusable, Reading::Unusable, Some(START)).is_err());
    }

    fn pin_for(fake: &FakeSesame) -> CustomServerPin {
        parse_instance(&serde_json::to_vec(&fake.instance()).unwrap(), "0.3.0")
            .unwrap()
            .pin()
    }

    fn linked(server: &TestServer, pinned: &FakeSesame) -> Option<LinkedTimeSource> {
        Some(LinkedTimeSource::new(
            ServerAddress::parse(&server.base()).unwrap(),
            pin_for(pinned),
        ))
    }

    fn company(time: Option<u64>) -> (TestServer, String) {
        let server = TestServer::start(move |_| match time {
            Some(time) => Reply::bytes(200, Vec::new()).with_date(time),
            None => Reply::bytes(200, Vec::new()),
        });
        let url = server.base();
        (server, url)
    }

    fn run(
        first: &str,
        second: &str,
        linked: Option<LinkedTimeSource>,
    ) -> VaultResult<TrustedTime> {
        tauri::async_runtime::block_on(collect_time(
            [first.to_string(), second.to_string()],
            false,
            linked,
        ))
    }

    fn dated_fake(seed: u8, time: u64) -> (FakeSesame, TestServer) {
        let mut fake = FakeSesame::new(seed);
        fake.date = Some(time);
        let server = TestServer::start(fake.handler());
        (fake, server)
    }

    #[test]
    fn both_company_sources_answering_and_agreeing_give_the_time() {
        let (_a, first) = company(Some(START));
        let (_b, second) = company(Some(START + 20));
        assert_eq!(
            run(&first, &second, None),
            Ok(TrustedTime {
                earliest: START,
                latest: START + 20
            })
        );
    }

    #[test]
    fn one_blocked_source_with_no_linked_server_is_refused() {
        let (_a, first) = company(Some(START));
        assert!(run(&first, &closed_port_base(), None).is_err());
        assert!(run(&closed_port_base(), &first, None).is_err());
    }

    #[test]
    fn one_blocked_source_and_an_agreeing_linked_server_are_accepted() {
        let (_a, first) = company(Some(START));
        let (fake, server) = dated_fake(1, START + 15);
        assert_eq!(
            run(&first, &closed_port_base(), linked(&server, &fake)),
            Ok(TrustedTime {
                earliest: START,
                latest: START + 15
            })
        );
        assert!(run(&closed_port_base(), &first, linked(&server, &fake)).is_ok());
    }

    #[test]
    fn a_linked_server_that_disagrees_with_the_one_answering_source_is_refused() {
        let (_a, first) = company(Some(START));
        let (fake, server) = dated_fake(1, START + TOLERANCE + 60);
        assert_eq!(
            run(&first, &closed_port_base(), linked(&server, &fake)),
            Err(TIME_DISAGREES.to_string())
        );
    }

    #[test]
    fn two_answering_company_sources_that_disagree_are_refused_even_if_the_linked_server_sides_with_one(
    ) {
        let (_a, first) = company(Some(START));
        let (_b, second) = company(Some(START + 10 * YEAR));
        let (fake, server) = dated_fake(1, START);
        assert_eq!(
            run(&first, &second, linked(&server, &fake)),
            Err(TIME_DISAGREES.to_string())
        );
    }

    #[test]
    fn both_company_sources_blocked_are_refused_even_with_a_linked_server() {
        let (fake, server) = dated_fake(1, START);
        assert!(run(
            &closed_port_base(),
            &closed_port_base(),
            linked(&server, &fake)
        )
        .is_err());
    }

    #[test]
    fn a_company_answer_without_a_date_is_not_replaced_by_the_linked_server() {
        let (_a, first) = company(Some(START));
        let (_b, undated) = company(None);
        let (fake, server) = dated_fake(1, START);
        assert!(run(&first, &undated, linked(&server, &fake)).is_err());
    }

    #[test]
    fn a_linked_server_with_a_rotated_key_does_not_stand_in() {
        let (_a, first) = company(Some(START));
        let pinned = FakeSesame::new(1);
        let (_rotated, server) = dated_fake(2, START);
        assert!(run(&first, &closed_port_base(), linked(&server, &pinned)).is_err());
    }

    #[test]
    fn a_linked_server_that_only_repeats_the_pinned_key_does_not_stand_in() {
        let (_a, first) = company(Some(START));
        let pinned = FakeSesame::new(1);
        let instance = pinned.instance();
        let forged = FakeSesame::new(2).signed(&pinned.capability_payload());
        let server = TestServer::start(move |request| {
            let reply = match request.path.as_str() {
                "/v1/instance" => Reply::json(200, &instance),
                _ => Reply::json(200, &forged),
            };
            reply.with_date(START)
        });
        assert!(run(&first, &closed_port_base(), linked(&server, &pinned)).is_err());
    }

    #[test]
    fn a_linked_server_that_is_down_does_not_stand_in() {
        let (_a, first) = company(Some(START));
        let pinned = FakeSesame::new(1);
        let down = LinkedTimeSource::new(
            ServerAddress::parse(&closed_port_base()).unwrap(),
            pin_for(&pinned),
        );
        assert!(run(&first, &closed_port_base(), Some(down)).is_err());
    }

    fn connection(base: &str, custom: Option<&FakeSesame>) -> ServiceConnectionFile {
        ServiceConnectionFile {
            format_version: 1,
            api_base_url: base.to_string(),
            protected_token: "x".into(),
            device_id: "d".into(),
            device_name: "n".into(),
            expires_at: None,
            custom_server: custom.map(pin_for),
        }
    }

    #[test]
    fn an_unlinked_or_official_connection_adds_no_source() {
        assert_eq!(
            linked_time_source(&connection("https://api.example.test", None)),
            None
        );
    }

    #[test]
    fn a_remote_custom_server_is_a_source_and_a_loopback_one_is_not() {
        let fake = FakeSesame::new(1);
        assert!(
            linked_time_source(&connection("https://home.example.test/vault", Some(&fake)))
                .is_some()
        );
        for local in [
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://[::1]:8787",
        ] {
            assert_eq!(
                linked_time_source(&connection(local, Some(&fake))),
                None,
                "{local}"
            );
        }
    }

    #[test]
    fn a_custom_connection_with_a_forged_pin_or_a_malformed_address_is_not_a_source() {
        let fake = FakeSesame::new(1);
        let mut value = connection("https://home.example.test", Some(&fake));
        if let Some(pin) = value.custom_server.as_mut() {
            pin.fingerprint = FakeSesame::new(2).fingerprint();
        }
        assert_eq!(linked_time_source(&value), None);
        for address in [
            "https://home.example.test/",
            "http://home.example.test",
            "https://user@home.example.test",
            "https://home.example.test:0",
        ] {
            assert_eq!(
                linked_time_source(&connection(address, Some(&fake))),
                None,
                "{address}"
            );
        }
    }
}
