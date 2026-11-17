use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_ALIAS_TOKEN_CHARS: usize = 512;
pub const MAX_ALIAS_DOMAIN_CHARS: usize = 253;
pub const DEFAULT_ADDY_DOMAIN: &str = "anonaddy.me";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum EmailAliasService {
    Addy,
    SimpleLogin,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailAliasSettings {
    pub service: EmailAliasService,
    pub token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub name_site: bool,
}

impl Zeroize for EmailAliasSettings {
    fn zeroize(&mut self) {
        self.token.zeroize();
        self.domain.zeroize();
        self.name_site = false;
    }
}

impl Drop for EmailAliasSettings {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for EmailAliasSettings {}

impl EmailAliasSettings {
    pub fn validated(
        service: EmailAliasService,
        token: &str,
        domain: &str,
        name_site: bool,
    ) -> Result<Self, String> {
        let token = alias_token(token)?;
        let domain = match service {
            EmailAliasService::Addy => alias_domain(domain)?,
            EmailAliasService::SimpleLogin => String::new(),
        };
        Ok(Self {
            service,
            token,
            domain,
            name_site,
        })
    }

    pub fn is_valid(&self) -> bool {
        alias_token(&self.token).is_ok_and(|token| token == self.token)
            && match self.service {
                EmailAliasService::Addy => {
                    alias_domain(&self.domain).is_ok_and(|domain| domain == self.domain)
                }
                EmailAliasService::SimpleLogin => self.domain.is_empty(),
            }
    }
}

fn alias_token(token: &str) -> Result<String, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("Paste the API token from your alias service.".into());
    }
    if token.chars().count() > MAX_ALIAS_TOKEN_CHARS
        || !token.chars().all(|character| character.is_ascii_graphic())
    {
        return Err(
            "That does not look like an API token. Copy it again from your alias service.".into(),
        );
    }
    Ok(token.to_string())
}

pub fn alias_domain(domain: &str) -> Result<String, String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let message = || "Enter the domain your aliases use, such as anonaddy.me.".to_string();
    if domain.is_empty() || domain.len() > MAX_ALIAS_DOMAIN_CHARS {
        return Err(message());
    }
    if !is_domain_name(&domain) {
        return Err(message());
    }
    Ok(domain)
}

pub fn is_domain_name(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    domain.len() <= MAX_ALIAS_DOMAIN_CHARS
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        && labels.last().is_some_and(|label| {
            label
                .chars()
                .any(|character| character.is_ascii_alphabetic())
        })
}

pub fn is_plausible_alias(address: &str) -> bool {
    if address.len() > 254 {
        return false;
    }
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '-')
        })
        && is_domain_name(&domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Outcome = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_token_is_trimmed_and_must_be_plain_visible_ascii() -> Outcome {
        let settings = EmailAliasSettings::validated(
            EmailAliasService::SimpleLogin,
            "  fictional-token\n",
            "",
            true,
        )?;
        assert_eq!(settings.token, "fictional-token");
        assert!(settings.domain.is_empty());
        for bad in [
            "",
            "   ",
            "two words",
            "line\nbreak",
            "naïve",
            &"x".repeat(513),
        ] {
            assert!(
                EmailAliasSettings::validated(EmailAliasService::SimpleLogin, bad, "", false)
                    .is_err(),
                "{bad:?}"
            );
        }
        assert!(EmailAliasSettings::validated(
            EmailAliasService::SimpleLogin,
            &"x".repeat(512),
            "",
            false
        )
        .is_ok());
        Ok(())
    }

    #[test]
    fn an_addy_domain_is_normalized_and_checked() -> Outcome {
        let settings = EmailAliasSettings::validated(
            EmailAliasService::Addy,
            "fictional-token",
            " Fictional.Example. ",
            false,
        )?;
        assert_eq!(settings.domain, "fictional.example");
        assert!(settings.is_valid());
        for bad in [
            "",
            "localhost",
            "fictional example",
            "-fictional.example",
            "fictional.example/path",
            "fictional.example:443",
            "user@fictional.example",
            "fictional..example",
            "1.2.3.4",
        ] {
            assert!(
                EmailAliasSettings::validated(
                    EmailAliasService::Addy,
                    "fictional-token",
                    bad,
                    false
                )
                .is_err(),
                "{bad:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_simplelogin_setting_carries_no_domain() -> Outcome {
        let settings = EmailAliasSettings::validated(
            EmailAliasService::SimpleLogin,
            "fictional-token",
            "fictional.example",
            false,
        )?;
        assert!(settings.domain.is_empty());
        Ok(())
    }

    #[test]
    fn stored_settings_that_skipped_validation_are_not_valid() -> Outcome {
        let mut settings = EmailAliasSettings::validated(
            EmailAliasService::Addy,
            "fictional-token",
            "anonaddy.me",
            false,
        )?;
        settings.token = "has space".into();
        assert!(!settings.is_valid());
        settings.token = "fictional-token".into();
        settings.domain = String::new();
        assert!(!settings.is_valid());
        Ok(())
    }

    fn payload_json(extra: &str) -> String {
        format!(r#"{{"vaultName":"Fictional","items":[],"revision":3{extra}}}"#)
    }

    #[test]
    fn a_payload_without_alias_settings_opens_and_writes_no_alias_key() -> Outcome {
        let payload: crate::VaultPayload = serde_json::from_str(&payload_json(""))?;
        assert!(payload.email_aliases.is_none());
        let written = serde_json::to_string(&payload)?;
        assert!(!written.contains("emailAliases"));
        Ok(())
    }

    #[test]
    fn alias_settings_round_trip_through_the_payload() -> Outcome {
        let mut payload: crate::VaultPayload = serde_json::from_str(&payload_json(""))?;
        payload.email_aliases = Some(EmailAliasSettings::validated(
            EmailAliasService::Addy,
            "fictional-token",
            "anonaddy.me",
            true,
        )?);
        let written = serde_json::to_string(&payload)?;
        let read: crate::VaultPayload = serde_json::from_str(&written)?;
        let settings = read.email_aliases.as_ref().ok_or("missing settings")?;
        assert_eq!(settings.service, EmailAliasService::Addy);
        assert_eq!(settings.token, "fictional-token");
        assert_eq!(settings.domain, "anonaddy.me");
        assert!(settings.name_site);
        Ok(())
    }

    #[test]
    fn alias_settings_with_unknown_or_missing_fields_are_refused() -> Outcome {
        for extra in [
            r#","emailAliases":{"service":"addy","token":"t","domain":"anonaddy.me","extra":1}"#,
            r#","emailAliases":{"service":"other","token":"t"}"#,
            r#","emailAliases":{"service":"simpleLogin"}"#,
            r#","emailAliases":"fictional-token""#,
        ] {
            assert!(
                serde_json::from_str::<crate::VaultPayload>(&payload_json(extra)).is_err(),
                "{extra}"
            );
        }
        let read: crate::VaultPayload = serde_json::from_str(&payload_json(
            r#","emailAliases":{"service":"simpleLogin","token":"fictional-token"}"#,
        ))?;
        assert!(
            !read
                .email_aliases
                .as_ref()
                .ok_or("missing settings")?
                .name_site
        );
        Ok(())
    }

    #[test]
    fn only_plain_addresses_count_as_aliases() {
        for good in [
            "fictional.alias@anonaddy.me",
            "a1b2c3+tag@sl.example",
            "x_y-z@mail.fictional.example",
        ] {
            assert!(is_plausible_alias(good), "{good}");
        }
        for bad in [
            "",
            "no-at-sign",
            "@anonaddy.me",
            "two@@anonaddy.me",
            "a@b@anonaddy.me",
            "space here@anonaddy.me",
            "fictional@localhost",
            "fictional@anonaddy.me\r\nBcc: someone@fictional.example",
            "\"quoted\"@anonaddy.me",
            "<fictional@anonaddy.me>",
            ".dot@anonaddy.me",
            "dot.@anonaddy.me",
            "do..t@anonaddy.me",
            "fictional@1.2.3.4",
            "fictional@[127.0.0.1]",
            "javascript:alert(1)@anonaddy.me",
            "ünicode@anonaddy.me",
        ] {
            assert!(!is_plausible_alias(bad), "{bad:?}");
        }
        assert!(!is_plausible_alias(&format!(
            "{}@anonaddy.me",
            "a".repeat(65)
        )));
        assert!(!is_plausible_alias(&format!(
            "a@{}.example",
            "b".repeat(250)
        )));
    }
}
