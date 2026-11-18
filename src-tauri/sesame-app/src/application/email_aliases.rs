use std::future::Future;

use serde::{Deserialize, Serialize};
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

use super::release_record::record;
use crate::network::email_alias::{api_host, AliasFailure, AliasRequest};
use crate::vault::release_record::{EntryKind, Outcome, ReleaseDraft};
use crate::vault::storage::commit_payload_change;
use crate::vault::{
    is_domain_name, EmailAliasService, EmailAliasSettings, VaultResult, VaultState,
};

const NOT_SET_UP: &str = "Turn on email aliases in Settings first.";
const PRIVATE_NAME_ENDINGS: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "intranet",
    "private",
    "lan",
    "home",
    "corp",
    "arpa",
    "onion",
    "invalid",
];

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct EmailAliasStatus {
    pub service: Option<EmailAliasService>,
    pub domain: Option<String>,
    pub name_site: bool,
}

impl EmailAliasStatus {
    fn of(settings: Option<&EmailAliasSettings>) -> Self {
        match settings.filter(|settings| settings.is_valid()) {
            Some(settings) => Self {
                service: Some(settings.service),
                domain: (!settings.domain.is_empty()).then(|| settings.domain.clone()),
                name_site: settings.name_site,
            },
            None => Self {
                service: None,
                domain: None,
                name_site: false,
            },
        }
    }
}

#[derive(Deserialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailAliasSettingsInput {
    pub service: EmailAliasService,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub name_site: bool,
}

impl Drop for EmailAliasSettingsInput {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

pub fn email_alias_status_in_state(vault: &VaultState) -> VaultResult<EmailAliasStatus> {
    let session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    Ok(EmailAliasStatus::of(
        session.open_payload()?.email_aliases.as_ref(),
    ))
}

pub fn save_email_alias_settings_in_state(
    vault: &VaultState,
    input: EmailAliasSettingsInput,
) -> VaultResult<EmailAliasStatus> {
    change_email_aliases(vault, |current| {
        let typed = input.token.as_deref().map(str::trim).unwrap_or("");
        let token = if typed.is_empty() {
            match current {
                Some(saved) if saved.service == input.service => {
                    Zeroizing::new(saved.token.as_str().to_string())
                }
                _ => return Err("Paste the API token from your alias service.".into()),
            }
        } else {
            Zeroizing::new(typed.to_string())
        };
        EmailAliasSettings::validated(
            input.service,
            &token,
            input.domain.as_deref().unwrap_or(""),
            input.name_site,
        )
        .map(Some)
    })
}

pub fn remove_email_alias_settings_in_state(vault: &VaultState) -> VaultResult<EmailAliasStatus> {
    change_email_aliases(vault, |_| Ok(None))
}

fn change_email_aliases(
    vault: &VaultState,
    change: impl FnOnce(Option<&EmailAliasSettings>) -> VaultResult<Option<EmailAliasSettings>>,
) -> VaultResult<EmailAliasStatus> {
    let mut session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_mut()
        .ok_or("Unlock your vault before changing email aliases.")?;
    let current = session.open_payload()?;
    let next = change(current.email_aliases.as_ref())?;
    let status = EmailAliasStatus::of(next.as_ref());
    if next == current.email_aliases {
        return Ok(status);
    }
    let mut next_payload = current.clone();
    next_payload.email_aliases = next;
    drop(current);
    commit_payload_change(session, next_payload)?;
    vault.advance_session_epoch();
    Ok(status)
}

pub fn site_description(site: &str) -> Option<String> {
    let site = site.trim();
    if site.is_empty() || site.len() > 2048 {
        return None;
    }
    let parsed = Url::parse(site)
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .or_else(|| Url::parse(&format!("https://{site}")).ok())?;
    let Host::Domain(domain) = parsed.host()? else {
        return None;
    };
    let domain = domain
        .strip_suffix('.')
        .unwrap_or(domain)
        .to_ascii_lowercase();
    let ending = domain.rsplit('.').next().unwrap_or_default();
    (is_domain_name(&domain) && !PRIVATE_NAME_ENDINGS.contains(&ending)).then_some(domain)
}

fn prepare_alias_request(vault: &VaultState, site: Option<&str>) -> VaultResult<AliasRequest> {
    let session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let payload = session.open_payload()?;
    let settings = payload
        .email_aliases
        .as_ref()
        .filter(|settings| settings.is_valid())
        .ok_or(NOT_SET_UP)?;
    Ok(AliasRequest {
        service: settings.service,
        token: Zeroizing::new(settings.token.as_str().to_string()),
        domain: settings.domain.clone(),
        description: if settings.name_site {
            site.and_then(site_description)
        } else {
            None
        },
    })
}

struct AliasAttempt<'a> {
    vault: &'a VaultState,
    host: &'static str,
    outcome: Outcome,
}

impl AliasAttempt<'_> {
    fn finish(&mut self, result: &Result<String, AliasFailure>) {
        if let Err(failure) = result {
            if !failure.token_may_have_left() {
                self.outcome = Outcome::Withdrawn;
            }
        }
    }
}

impl Drop for AliasAttempt<'_> {
    fn drop(&mut self) {
        record(
            self.vault,
            ReleaseDraft::new(EntryKind::EmailAlias, self.outcome).host(self.host),
        );
    }
}

pub async fn create_email_alias_in_state<F, Fut>(
    vault: &VaultState,
    site: Option<String>,
    send: F,
) -> VaultResult<String>
where
    F: FnOnce(AliasRequest) -> Fut,
    Fut: Future<Output = Result<String, AliasFailure>>,
{
    let request = prepare_alias_request(vault, site.as_deref())?;
    let mut attempt = AliasAttempt {
        vault,
        host: api_host(request.service),
        outcome: Outcome::Released,
    };
    let result = send(request).await;
    attempt.finish(&result);
    drop(attempt);
    result.map_err(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::release_record::release_record_page_in_state;
    use crate::application::release_record::ReleaseRecordQuery;
    use crate::test_support::{block_on, TestVault};
    use crate::vault::AliasToken;
    use std::sync::{Arc, Mutex};

    const TOKEN: &str = "fictional-alias-token";

    type Seen = (EmailAliasService, String, String, Option<String>);

    fn input(
        service: EmailAliasService,
        token: Option<&str>,
        domain: Option<&str>,
        name_site: bool,
    ) -> EmailAliasSettingsInput {
        EmailAliasSettingsInput {
            service,
            token: token.map(str::to_string),
            domain: domain.map(str::to_string),
            name_site,
        }
    }

    fn vault_with_addy(name_site: bool) -> TestVault {
        let vault = TestVault::with_login("login-a", "https://example.com");
        save_email_alias_settings_in_state(
            &vault.state,
            input(
                EmailAliasService::Addy,
                Some(TOKEN),
                Some("anonaddy.me"),
                name_site,
            ),
        )
        .expect("saved settings");
        vault
    }

    fn sent_requests(
        vault: &TestVault,
        site: Option<&str>,
        answer: Result<String, AliasFailure>,
    ) -> (VaultResult<String>, Vec<Seen>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let result = block_on(create_email_alias_in_state(
            &vault.state,
            site.map(str::to_string),
            move |request: AliasRequest| {
                recorder.lock().unwrap().push((
                    request.service,
                    request.token.to_string(),
                    request.domain.clone(),
                    request.description.clone(),
                ));
                async move { answer }
            },
        ));
        let seen = seen.lock().unwrap().clone();
        (result, seen)
    }

    #[test]
    fn aliases_are_off_until_a_token_is_saved() {
        let vault = TestVault::with_login("login-a", "https://example.com");
        let status = email_alias_status_in_state(&vault.state).expect("status");
        assert_eq!(status.service, None);
        assert!(!status.name_site);
        let (result, seen) = sent_requests(&vault, Some("https://example.com"), Ok(String::new()));
        assert_eq!(result.unwrap_err(), NOT_SET_UP);
        assert!(seen.is_empty());
    }

    #[test]
    fn the_saved_token_never_appears_in_the_status_the_window_reads() {
        let vault = vault_with_addy(true);
        let status = email_alias_status_in_state(&vault.state).expect("status");
        assert_eq!(status.service, Some(EmailAliasService::Addy));
        assert_eq!(status.domain.as_deref(), Some("anonaddy.me"));
        assert!(status.name_site);
        let serialized = serde_json::to_string(&status).expect("status json");
        assert!(!serialized.contains(TOKEN));
        let snapshot = serde_json::to_string(
            &vault
                .state
                .session
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .snapshot(),
        )
        .expect("snapshot json");
        assert!(!snapshot.contains(TOKEN));
    }

    #[test]
    fn the_token_is_stored_in_the_vault_file_and_survives_a_reopen() {
        let vault = vault_with_addy(false);
        let bytes = std::fs::read(vault.path()).expect("vault bytes");
        assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN));
        vault.reopen();
        let (result, seen) =
            sent_requests(&vault, None, Ok("fictional.alias@anonaddy.me".to_string()));
        assert_eq!(result.unwrap(), "fictional.alias@anonaddy.me");
        assert_eq!(seen[0].1, TOKEN);
    }

    #[test]
    fn changing_options_keeps_the_saved_token_but_switching_service_needs_a_new_one() {
        let vault = vault_with_addy(false);
        let status = save_email_alias_settings_in_state(
            &vault.state,
            input(
                EmailAliasService::Addy,
                None,
                Some("fictional.example"),
                true,
            ),
        )
        .expect("kept token");
        assert!(status.name_site);
        assert_eq!(status.domain.as_deref(), Some("fictional.example"));
        let (_, seen) = sent_requests(&vault, None, Ok("a@anonaddy.me".to_string()));
        assert_eq!(seen[0].1, TOKEN);

        assert!(save_email_alias_settings_in_state(
            &vault.state,
            input(EmailAliasService::SimpleLogin, Some("  "), None, false),
        )
        .is_err());
        let status = email_alias_status_in_state(&vault.state).expect("status");
        assert_eq!(status.service, Some(EmailAliasService::Addy));
    }

    #[test]
    fn an_invalid_token_or_domain_changes_nothing() {
        let vault = vault_with_addy(false);
        for bad in [
            input(
                EmailAliasService::Addy,
                Some("has space"),
                Some("anonaddy.me"),
                false,
            ),
            input(
                EmailAliasService::Addy,
                Some(TOKEN),
                Some("not a domain"),
                false,
            ),
            input(EmailAliasService::Addy, Some(TOKEN), None, false),
        ] {
            assert!(save_email_alias_settings_in_state(&vault.state, bad).is_err());
        }
        let (_, seen) = sent_requests(&vault, None, Ok("a@anonaddy.me".to_string()));
        assert_eq!(seen[0].2, "anonaddy.me");
    }

    #[test]
    fn turning_aliases_off_removes_the_token_from_the_current_vault() {
        let vault = vault_with_addy(false);
        let status = remove_email_alias_settings_in_state(&vault.state).expect("removed");
        assert_eq!(status.service, None);
        vault.reopen();
        let (result, seen) = sent_requests(&vault, None, Ok(String::new()));
        assert!(result.is_err());
        assert!(seen.is_empty());
    }

    #[test]
    fn the_site_is_named_only_when_the_person_turned_it_on() {
        let off = vault_with_addy(false);
        let (_, seen) = sent_requests(
            &off,
            Some("https://login.example.com/path?secret=1"),
            Ok("a@anonaddy.me".to_string()),
        );
        assert_eq!(seen[0].3, None);

        let on = vault_with_addy(true);
        let (_, seen) = sent_requests(
            &on,
            Some("https://login.example.com/path?secret=1"),
            Ok("a@anonaddy.me".to_string()),
        );
        assert_eq!(seen[0].3.as_deref(), Some("login.example.com"));
    }

    #[test]
    fn only_a_host_name_can_become_a_description() {
        for (site, description) in [
            ("Example.COM", "example.com"),
            ("https://user:pass@example.com:8443/a?b#c", "example.com"),
            ("user:pass@login.example.com:8443/path", "login.example.com"),
            ("http://example.com./", "example.com"),
            ("example.com.", "example.com"),
            ("https://bücher.example/", "xn--bcher-kva.example"),
            ("https://EXAMPLE.com/%2e%2e/", "example.com"),
        ] {
            assert_eq!(
                site_description(site).as_deref(),
                Some(description),
                "{site:?}"
            );
        }
        for nothing in [
            "",
            "   ",
            ".",
            "..",
            "example.com..",
            ".example.com",
            "https://127.0.0.1/",
            "127.0.0.1",
            "https://2130706433/",
            "https://0x7f.1/",
            "https://[::1]/",
            "[fe80::1]:8080",
            "localhost",
            "https://localhost:8443/",
            "intranet",
            "nas.local",
            "https://router.lan/",
            "printer.home.arpa",
            "files.internal",
            "fictionalhiddenservice.onion",
            "https://example.123/",
            "javascript:alert(1)",
            "javascript:alert(document.domain)//example.com",
            "javascript://example.com/%0aalert(1)",
            "data:text/html,<script>alert(1)</script>",
            "data:,example.com",
            "file:///etc/passwd",
            "ftp://files.example.com",
            "https://ex$ample.com/",
            "https://exa_mple.com/",
            "https://-example.com/",
            &format!("https://{}.example/", "a".repeat(64)),
            &format!("https://{}example.com/", "a.".repeat(1100)),
        ] {
            assert_eq!(site_description(nothing), None, "{nothing:?}");
        }
    }

    #[test]
    fn each_request_is_listed_in_the_activity_record_without_the_token() {
        let vault = vault_with_addy(true);
        let (result, _) = sent_requests(
            &vault,
            Some("https://example.com"),
            Err(AliasFailure::TokenRefused),
        );
        assert_eq!(result.unwrap_err(), AliasFailure::TokenRefused.message());
        let page = release_record_page_in_state(&vault.state, ReleaseRecordQuery::default())
            .expect("record page");
        assert_eq!(page.entries.len(), 1);
        let entry = &page.entries[0];
        assert_eq!(entry.kind, EntryKind::EmailAlias);
        assert_eq!(entry.outcome, Outcome::Released);
        assert_eq!(entry.host.as_deref(), Some("app.addy.io"));
        assert_eq!(entry.item_id, None);
        let serialized = serde_json::to_string(&page).expect("page json");
        assert!(!serialized.contains(TOKEN));
    }

    #[test]
    fn an_alias_made_for_a_login_records_no_item() {
        let vault = vault_with_addy(true);
        let (result, _) = sent_requests(
            &vault,
            Some("https://example.com"),
            Ok("fictional.alias@anonaddy.me".to_string()),
        );
        assert!(result.is_ok());
        let for_item = release_record_page_in_state(
            &vault.state,
            ReleaseRecordQuery {
                item_id: Some("login-a".to_string()),
                ..ReleaseRecordQuery::default()
            },
        )
        .expect("item page");
        assert_eq!(for_item.total, 0);
    }

    fn recorded(vault: &TestVault) -> Vec<(EntryKind, Outcome, Option<String>)> {
        release_record_page_in_state(&vault.state, ReleaseRecordQuery::default())
            .expect("record page")
            .entries
            .into_iter()
            .map(|entry| (entry.kind, entry.outcome, entry.host))
            .collect()
    }

    #[test]
    fn a_request_that_never_left_is_recorded_as_not_sent() {
        for failure in [AliasFailure::NotSent, AliasFailure::NotConnected] {
            let vault = vault_with_addy(false);
            let (result, seen) = sent_requests(&vault, None, Err(failure));
            assert_eq!(result.unwrap_err(), failure.message());
            assert_eq!(seen.len(), 1);
            assert_eq!(
                recorded(&vault),
                vec![(
                    EntryKind::EmailAlias,
                    Outcome::Withdrawn,
                    Some("app.addy.io".to_string())
                )],
                "{failure:?}"
            );
        }
    }

    #[test]
    fn a_request_that_may_have_left_is_recorded_as_sent() {
        for answer in [
            Ok("fictional.alias@anonaddy.me".to_string()),
            Err(AliasFailure::Unreachable),
            Err(AliasFailure::TokenRefused),
            Err(AliasFailure::UnusableAnswer),
            Err(AliasFailure::ServiceDown),
        ] {
            let vault = vault_with_addy(false);
            let (result, seen) = sent_requests(&vault, None, answer.clone());
            assert_eq!(result.is_ok(), answer.is_ok());
            assert_eq!(seen.len(), 1);
            assert_eq!(
                recorded(&vault),
                vec![(
                    EntryKind::EmailAlias,
                    Outcome::Released,
                    Some("app.addy.io".to_string())
                )],
                "{answer:?}"
            );
        }
    }

    #[test]
    fn a_request_cut_short_after_it_started_is_still_recorded_as_sent() {
        let vault = vault_with_addy(false);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(create_email_alias_in_state(
                &vault.state,
                None,
                |_request: AliasRequest| async move {
                    panic!("fictional interruption");
                    #[allow(unreachable_code)]
                    Ok::<String, AliasFailure>(String::new())
                },
            ))
        }));
        assert!(outcome.is_err());
        assert_eq!(
            recorded(&vault),
            vec![(
                EntryKind::EmailAlias,
                Outcome::Released,
                Some("app.addy.io".to_string())
            )]
        );
    }

    #[test]
    fn nothing_is_recorded_when_no_request_was_made() {
        let vault = TestVault::with_login("login-a", "https://example.com");
        let (result, seen) = sent_requests(&vault, None, Ok(String::new()));
        assert!(result.is_err());
        assert!(seen.is_empty());
        assert!(recorded(&vault).is_empty());
    }

    #[test]
    fn an_unusable_stored_setting_counts_as_not_set_up() {
        for settings in [
            EmailAliasSettings {
                service: EmailAliasService::Addy,
                token: AliasToken::from("has space"),
                domain: "anonaddy.me".to_string(),
                name_site: true,
            },
            EmailAliasSettings {
                service: EmailAliasService::Addy,
                token: AliasToken::from(TOKEN),
                domain: String::new(),
                name_site: false,
            },
            EmailAliasSettings {
                service: EmailAliasService::SimpleLogin,
                token: AliasToken::from(TOKEN),
                domain: "anonaddy.me".to_string(),
                name_site: false,
            },
        ] {
            let vault = TestVault::with_login("login-a", "https://example.com");
            vault.seed(|payload| payload.email_aliases = Some(settings));
            vault.reopen();
            let status = email_alias_status_in_state(&vault.state).expect("status");
            assert_eq!(status, EmailAliasStatus::of(None));
            let (result, seen) =
                sent_requests(&vault, Some("https://example.com"), Ok(String::new()));
            assert_eq!(result.unwrap_err(), NOT_SET_UP);
            assert!(seen.is_empty());
            assert!(recorded(&vault).is_empty());

            save_email_alias_settings_in_state(
                &vault.state,
                input(EmailAliasService::SimpleLogin, Some(TOKEN), None, false),
            )
            .expect("a new token replaces the unusable one");
            assert_eq!(
                email_alias_status_in_state(&vault.state)
                    .expect("status")
                    .service,
                Some(EmailAliasService::SimpleLogin)
            );
        }
    }

    #[test]
    fn changing_the_setting_advances_the_session_like_any_vault_change() {
        let vault = vault_with_addy(false);
        let before = vault.state.session_epoch();
        save_email_alias_settings_in_state(
            &vault.state,
            input(EmailAliasService::Addy, None, Some("anonaddy.me"), true),
        )
        .expect("saved");
        assert!(vault.state.session_epoch() > before);
        let unchanged = vault.state.session_epoch();
        save_email_alias_settings_in_state(
            &vault.state,
            input(EmailAliasService::Addy, None, Some("anonaddy.me"), true),
        )
        .expect("saved again");
        assert_eq!(vault.state.session_epoch(), unchanged);
    }

    #[test]
    fn a_locked_vault_sends_nothing() {
        let vault = vault_with_addy(false);
        *vault.state.session.lock().unwrap() = None;
        let (result, seen) = sent_requests(&vault, None, Ok(String::new()));
        assert!(result.is_err());
        assert!(seen.is_empty());
        assert!(email_alias_status_in_state(&vault.state).is_err());
    }
}
