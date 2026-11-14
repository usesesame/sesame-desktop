use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::vault::VaultResult;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_PATH_BYTES: usize = 256;
const PAIRING_PAGE_SEGMENT: &str = "/pair";
pub const PAIRING_CODE_MIN_LENGTH: usize = 32;
pub const PAIRING_CODE_MAX_LENGTH: usize = 128;
pub const FINGERPRINT_LENGTH: usize = 64;

const ADDRESS_INVALID: &str = "Enter the server address as https://host, with an optional path. Plain http is accepted only for localhost.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerAddress {
    base: String,
    host: String,
    loopback: bool,
    plain_http: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PairingInput {
    pub address: ServerAddress,
    pub code: Option<String>,
    pub fingerprint: Option<String>,
}

impl ServerAddress {
    pub fn parse(input: &str) -> VaultResult<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty()
            || trimmed.len() > MAX_INPUT_BYTES
            || trimmed.chars().any(|character| {
                character.is_control() || character.is_whitespace() || character == '\\'
            })
        {
            return Err(ADDRESS_INVALID.into());
        }
        let url = Url::parse(trimmed).map_err(|_| ADDRESS_INVALID.to_string())?;
        if url.username() != "" || url.password().is_some() {
            return Err("The server address cannot contain a user name or password.".into());
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err("The server address cannot contain a query or a fragment.".into());
        }
        if url.port() == Some(0) {
            return Err(ADDRESS_INVALID.into());
        }
        let host = match url.host() {
            Some(Host::Domain(domain)) => {
                let stripped = domain.trim_end_matches('.').to_ascii_lowercase();
                if stripped.is_empty() {
                    return Err(ADDRESS_INVALID.into());
                }
                stripped
            }
            Some(_) => url
                .host_str()
                .map(str::to_ascii_lowercase)
                .ok_or_else(|| ADDRESS_INVALID.to_string())?,
            None => return Err(ADDRESS_INVALID.into()),
        };
        let loopback = match url.host() {
            Some(Host::Domain(_)) => host == "localhost",
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            None => return Err(ADDRESS_INVALID.into()),
        };
        let plain_http = match url.scheme() {
            "https" => false,
            "http" if loopback => true,
            "http" => {
                return Err(
                    "Sesame sends pairing codes and tokens only over https. Plain http is accepted only for localhost."
                        .into(),
                )
            }
            _ => return Err(ADDRESS_INVALID.into()),
        };
        if raw_path_is_ambiguous(trimmed) {
            return Err(ADDRESS_INVALID.into());
        }
        let segments: Vec<&str> = url
            .path_segments()
            .map(|segments| segments.collect())
            .unwrap_or_default();
        let (last, leading) = match segments.split_last() {
            Some((last, leading)) => (*last, leading),
            None => ("", &[][..]),
        };
        let checked: Vec<&str> = leading
            .iter()
            .copied()
            .chain((!last.is_empty()).then_some(last))
            .collect();
        if checked.iter().any(|segment| !valid_path_segment(segment)) {
            return Err(ADDRESS_INVALID.into());
        }
        let path = if checked.is_empty() {
            String::new()
        } else {
            format!("/{}", checked.join("/"))
        };
        if path.len() > MAX_PATH_BYTES {
            return Err(ADDRESS_INVALID.into());
        }
        let port = url
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        Ok(Self {
            base: format!("{}://{host}{port}{path}", url.scheme()),
            host,
            loopback,
            plain_http,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.base
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub fn is_loopback(&self) -> bool {
        self.loopback
    }

    pub fn is_plain_http(&self) -> bool {
        self.plain_http
    }

    pub fn refuse_official_host(&self, official_base_url: Option<&str>) -> VaultResult<()> {
        let official_host = official_base_url
            .and_then(|base| Url::parse(base).ok())
            .and_then(|url| {
                url.host_str()
                    .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
            });
        if official_host.as_deref() == Some(self.host.as_str()) {
            return Err("That is the Sesame service address. Use the Sesame account setting to link this desktop to it.".into());
        }
        Ok(())
    }
}

fn raw_path_is_ambiguous(input: &str) -> bool {
    let Some((_, rest)) = input.split_once("://") else {
        return false;
    };
    let Some((_, path)) = rest.split_once('/') else {
        return false;
    };
    path.contains('%')
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

fn valid_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

pub fn validate_pairing_code(raw: &str) -> VaultResult<String> {
    let code = raw.trim();
    let well_formed = (PAIRING_CODE_MIN_LENGTH..=PAIRING_CODE_MAX_LENGTH).contains(&code.len())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'));
    if !well_formed {
        return Err("Enter the one-time pairing code from your server.".into());
    }
    Ok(code.to_string())
}

pub fn normalized_fingerprint(value: &str) -> Option<String> {
    let lowered = value.trim().to_ascii_lowercase();
    (lowered.len() == FINGERPRINT_LENGTH && lowered.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(lowered)
}

pub fn fingerprint_of_public_key(raw_key: &[u8]) -> String {
    Sha256::digest(raw_key)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn parse_pairing_input(input: &str) -> VaultResult<PairingInput> {
    let trimmed = input.trim();
    let Some((head, fragment)) = trimmed.split_once('#') else {
        if trimmed
            .trim_end_matches('/')
            .ends_with(PAIRING_PAGE_SEGMENT)
        {
            return Err("That pairing link has no code. Copy the whole link again.".into());
        }
        return Ok(PairingInput {
            address: ServerAddress::parse(trimmed)?,
            code: None,
            fingerprint: None,
        });
    };
    let address_text = head
        .strip_suffix(PAIRING_PAGE_SEGMENT)
        .ok_or_else(|| "A pairing link must look like https://host/pair#code=...".to_string())?;
    let address = ServerAddress::parse(address_text)?;
    let mut code = None;
    let mut fingerprint = None;
    for pair in fragment.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key {
            "code" => {
                if code.replace(validate_pairing_code(value)?).is_some() {
                    return Err("That pairing link contains two codes.".into());
                }
            }
            "fp" => {
                let normalized = normalized_fingerprint(value).ok_or_else(|| {
                    "The fingerprint in that pairing link is not valid.".to_string()
                })?;
                if fingerprint.replace(normalized).is_some() {
                    return Err("That pairing link contains two fingerprints.".into());
                }
            }
            _ => {}
        }
    }
    Ok(PairingInput {
        address,
        code,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "abcdefghijklmnopqrstuvwxyzABCDEF-_0123456789";
    const FP: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn address(value: &str) -> String {
        ServerAddress::parse(value).unwrap().as_str().to_string()
    }

    #[test]
    fn an_https_origin_is_accepted_and_normalized() {
        assert_eq!(
            address("https://Vault.Example.test"),
            "https://vault.example.test"
        );
        assert_eq!(
            address("https://vault.example.test/"),
            "https://vault.example.test"
        );
        assert_eq!(
            address("  https://vault.example.test:443/ "),
            "https://vault.example.test"
        );
        assert_eq!(
            address("https://vault.example.test:8443"),
            "https://vault.example.test:8443"
        );
    }

    #[test]
    fn a_path_prefix_is_kept_without_a_trailing_slash() {
        assert_eq!(
            address("https://example.test/sesame/"),
            "https://example.test/sesame"
        );
        assert_eq!(
            address("https://example.test/a/b-c_d.e~f"),
            "https://example.test/a/b-c_d.e~f"
        );
    }

    #[test]
    fn plain_http_is_accepted_only_for_loopback_hosts() {
        for accepted in [
            "http://localhost:8787",
            "http://127.0.0.1:8787",
            "http://[::1]:8787",
            "http://LOCALHOST",
        ] {
            assert!(
                ServerAddress::parse(accepted).unwrap().is_plain_http(),
                "{accepted}"
            );
        }
        for refused in [
            "http://example.test",
            "http://192.168.1.20:8787",
            "http://10.0.0.5",
            "http://localhost.example.test",
            "http://127.0.0.1.example.test",
            "http://[2001:db8::1]",
        ] {
            assert!(ServerAddress::parse(refused).is_err(), "{refused}");
        }
        assert!(!ServerAddress::parse("https://localhost")
            .unwrap()
            .is_plain_http());
    }

    #[test]
    fn other_schemes_are_refused() {
        for refused in [
            "ftp://example.test",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ws://localhost",
            "wss://example.test",
            "sesame://example.test",
            "data:text/plain,hello",
            "example.test",
            "//example.test",
            "",
            "   ",
        ] {
            assert!(ServerAddress::parse(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn userinfo_query_and_fragment_are_refused() {
        for refused in [
            "https://user@example.test",
            "https://user:secret@example.test",
            "https://:secret@example.test",
            "https://example.test?x=1",
            "https://example.test/?",
            "https://example.test/prefix?x=1",
            "https://example.test#frag",
            "https://example.test/#",
            "https://example.test@evil.test",
        ] {
            assert!(ServerAddress::parse(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn dot_segments_encoded_characters_and_odd_paths_are_refused() {
        for refused in [
            "https://example.test/a/../b",
            "https://example.test/./a",
            "https://example.test/..",
            "https://example.test/%2e%2e/a",
            "https://example.test/a%2Fb",
            "https://example.test/a%20b",
            "https://example.test//a",
            "https://example.test/a//b",
            "https://example.test/a b",
            "https://example.test/a\\b",
            "https://example.test/\u{e9}",
            "https://example.test/a\nb",
        ] {
            assert!(ServerAddress::parse(refused).is_err(), "{refused:?}");
        }
        let long = format!("https://example.test/{}", "a".repeat(MAX_PATH_BYTES));
        assert!(ServerAddress::parse(&long).is_err());
        assert!(ServerAddress::parse(&format!(
            "https://example.test/{}",
            "a".repeat(MAX_INPUT_BYTES)
        ))
        .is_err());
    }

    #[test]
    fn an_international_host_is_shown_in_its_ascii_form() {
        let parsed = ServerAddress::parse("https://b\u{fc}cher.example.test").unwrap();
        assert_eq!(parsed.as_str(), "https://xn--bcher-kva.example.test");
    }

    #[test]
    fn the_official_host_is_refused_as_a_custom_server() {
        let official = Some("https://api.sesame.example.test");
        for refused in [
            "https://api.sesame.example.test",
            "https://API.sesame.example.test/prefix",
            "https://api.sesame.example.test:8443",
        ] {
            assert!(
                ServerAddress::parse(refused)
                    .unwrap()
                    .refuse_official_host(official)
                    .is_err(),
                "{refused}"
            );
        }
        assert!(
            ServerAddress::parse("https://api.sesame.example.test.evil.test")
                .unwrap()
                .refuse_official_host(official)
                .is_ok()
        );
        assert!(ServerAddress::parse("https://other.example.test")
            .unwrap()
            .refuse_official_host(official)
            .is_ok());
        assert!(ServerAddress::parse("https://other.example.test")
            .unwrap()
            .refuse_official_host(None)
            .is_ok());
    }

    #[test]
    fn a_fingerprint_is_the_lowercase_hex_sha256_of_the_raw_key() {
        let fingerprint = fingerprint_of_public_key(&[7u8; 32]);
        assert_eq!(fingerprint.len(), FINGERPRINT_LENGTH);
        assert!(fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            fingerprint_of_public_key(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_ne!(fingerprint, fingerprint_of_public_key(&[8u8; 32]));
    }

    #[test]
    fn a_fingerprint_must_be_sixty_four_hex_characters() {
        assert_eq!(normalized_fingerprint(FP).as_deref(), Some(FP));
        assert_eq!(
            normalized_fingerprint(&FP.to_uppercase()).as_deref(),
            Some(FP)
        );
        for refused in [
            String::new(),
            FP[..63].to_string(),
            format!("{FP}0"),
            FP.replace('0', "g"),
            format!(" {FP} x"),
        ] {
            assert_eq!(normalized_fingerprint(&refused), None, "{refused}");
        }
    }

    #[test]
    fn a_pairing_link_gives_the_address_code_and_fingerprint() {
        let link = format!("https://vault.example.test/pair#code={CODE}&fp={FP}");
        let parsed = parse_pairing_input(&link).unwrap();
        assert_eq!(parsed.address.as_str(), "https://vault.example.test");
        assert_eq!(parsed.code.as_deref(), Some(CODE));
        assert_eq!(parsed.fingerprint.as_deref(), Some(FP));
    }

    #[test]
    fn a_pairing_link_keeps_a_path_prefix() {
        let link = format!("https://example.test/sesame/pair#fp={FP}&code={CODE}");
        let parsed = parse_pairing_input(&link).unwrap();
        assert_eq!(parsed.address.as_str(), "https://example.test/sesame");
        assert_eq!(parsed.code.as_deref(), Some(CODE));
    }

    #[test]
    fn a_bare_origin_gives_only_an_address() {
        let parsed = parse_pairing_input("https://vault.example.test").unwrap();
        assert_eq!(parsed.code, None);
        assert_eq!(parsed.fingerprint, None);
        let local =
            parse_pairing_input(&format!("http://127.0.0.1:8787/pair#code={CODE}")).unwrap();
        assert_eq!(local.address.as_str(), "http://127.0.0.1:8787");
    }

    #[test]
    fn a_link_without_the_pair_page_or_its_fragment_is_refused() {
        for refused in [
            format!("https://vault.example.test#code={CODE}"),
            format!("https://vault.example.test/other#code={CODE}"),
            format!("https://vault.example.test/pairing#code={CODE}"),
            "https://vault.example.test/pair".to_string(),
            "https://vault.example.test/pair/".to_string(),
        ] {
            assert!(parse_pairing_input(&refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_link_with_a_bad_part_is_refused() {
        let origin = "https://vault.example.test/pair";
        for refused in [
            format!("{origin}#code={CODE}&code={CODE}"),
            format!("{origin}#code=short"),
            format!("{origin}#code={}", "a".repeat(PAIRING_CODE_MAX_LENGTH + 1)),
            format!("{origin}#code=%41{}", &CODE[3..]),
            format!("{origin}#code={CODE}&fp={FP}&fp={FP}"),
            format!("{origin}#code={CODE}&fp=abc"),
            format!("{origin}#code={CODE}&fp={}", "z".repeat(64)),
            format!("{origin}?next=1#code={CODE}"),
            format!("https://user@vault.example.test/pair#code={CODE}"),
            format!("http://vault.example.test/pair#code={CODE}"),
            format!("ftp://vault.example.test/pair#code={CODE}"),
        ] {
            assert!(parse_pairing_input(&refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn unknown_fragment_keys_are_ignored_and_a_missing_code_is_allowed() {
        let parsed =
            parse_pairing_input(&format!("https://vault.example.test/pair#fp={FP}&utm=1&x"))
                .unwrap();
        assert_eq!(parsed.code, None);
        assert_eq!(parsed.fingerprint.as_deref(), Some(FP));
    }

    #[test]
    fn a_pairing_code_is_trimmed_and_bounded() {
        assert_eq!(validate_pairing_code(&format!("  {CODE}  ")).unwrap(), CODE);
        assert!(validate_pairing_code(&"a".repeat(PAIRING_CODE_MIN_LENGTH - 1)).is_err());
        assert!(validate_pairing_code(&"a".repeat(PAIRING_CODE_MAX_LENGTH + 1)).is_err());
        assert!(validate_pairing_code(&"a".repeat(PAIRING_CODE_MIN_LENGTH)).is_ok());
        assert!(validate_pairing_code(&format!("{CODE}&x=1")).is_err());
        assert!(validate_pairing_code(&format!("{CODE} {CODE}")).is_err());
    }

    #[test]
    fn a_trailing_dot_on_the_host_is_removed_before_storage_and_the_official_check() {
        assert_eq!(
            address("https://vault.example.test./prefix"),
            "https://vault.example.test/prefix"
        );
        assert_eq!(
            address("https://vault.example.test.:8443"),
            "https://vault.example.test:8443"
        );
        let official = Some("https://api.sesame.example.test");
        for refused in [
            "https://api.sesame.example.test.",
            "https://API.sesame.example.test.:8443/x",
        ] {
            assert!(
                ServerAddress::parse(refused)
                    .unwrap()
                    .refuse_official_host(official)
                    .is_err(),
                "{refused}"
            );
        }
        assert!(ServerAddress::parse("https://api.usesesame.app.")
            .unwrap()
            .refuse_official_host(Some("https://api.usesesame.app"))
            .is_err());
        assert!(ServerAddress::parse("https://api.usesesame.app.")
            .unwrap()
            .refuse_official_host(Some("https://api.usesesame.app."))
            .is_err());
    }

    #[test]
    fn a_dotted_loopback_name_and_a_bare_dot_host_are_handled() {
        assert!(ServerAddress::parse("http://localhost.:8787")
            .unwrap()
            .is_loopback());
        assert!(ServerAddress::parse("https://.").is_err());
        assert!(ServerAddress::parse("https://./x").is_err());
    }

    #[test]
    fn port_zero_is_refused() {
        for refused in [
            "https://example.test:0",
            "https://example.test:0/prefix",
            "http://127.0.0.1:0",
            "http://[::1]:0",
        ] {
            assert!(ServerAddress::parse(refused).is_err(), "{refused}");
        }
        assert!(ServerAddress::parse("https://example.test:1").is_ok());
    }
}
