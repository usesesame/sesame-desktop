use std::future::Future;

use serde::{Deserialize, Serialize};
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

use super::release_record::record_in;
use crate::network::email_alias::{api_host, AliasFailure, AliasRequest};
use crate::vault::release_record::{EntryKind, Outcome, ReleaseDraft};
use crate::vault::storage::commit_payload_change;
use crate::vault::{
    EmailAliasService, EmailAliasSettings, VaultResult, VaultState, MAX_ALIAS_DOMAIN_CHARS,
};

const NOT_SET_UP: &str = "Turn on email aliases in Settings first.";

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
        match settings {
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
                    Zeroizing::new(saved.token.clone())
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
    match parsed.host()? {
        Host::Domain(domain) if domain.contains('.') && domain.len() <= MAX_ALIAS_DOMAIN_CHARS => {
            Some(domain.trim_end_matches('.').to_ascii_lowercase())
        }
        _ => None,
    }
}

fn prepare_alias_request(vault: &VaultState, site: Option<&str>) -> VaultResult<AliasRequest> {
    let session = vault
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session.as_ref().ok_or("Unlock your vault first.")?;
    let payload = session.open_payload()?;
    let settings = payload.email_aliases.as_ref().ok_or(NOT_SET_UP)?;
    if !settings.is_valid() {
        return Err(NOT_SET_UP.into());
    }
    let request = AliasRequest {
        service: settings.service,
        token: Zeroizing::new(settings.token.clone()),
        domain: settings.domain.clone(),
        description: if settings.name_site {
            site.and_then(site_description)
        } else {
            None
        },
    };
    drop(payload);
    record_in(
        vault,
        Some(session),
        ReleaseDraft::new(EntryKind::EmailAlias, Outcome::Released).host(api_host(request.service)),
    );
    Ok(request)
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
    send(request).await.map_err(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::release_record::release_record_page_in_state;
    use crate::application::release_record::ReleaseRecordQuery;
    use crate::test_support::{block_on, TestVault};
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
    fn removing_aliases_forgets_the_token() {
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
        assert_eq!(site_description("Example.COM"), Some("example.com".into()));
        assert_eq!(
            site_description("https://user:pass@example.com:8443/a?b#c"),
            Some("example.com".into())
        );
        for nothing in [
            "",
            "   ",
            "https://127.0.0.1/",
            "https://[::1]/",
            "localhost",
            "javascript:alert(1)",
            "file:///etc/passwd",
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
    fn a_locked_vault_sends_nothing() {
        let vault = vault_with_addy(false);
        *vault.state.session.lock().unwrap() = None;
        let (result, seen) = sent_requests(&vault, None, Ok(String::new()));
        assert!(result.is_err());
        assert!(seen.is_empty());
        assert!(email_alias_status_in_state(&vault.state).is_err());
    }
}
