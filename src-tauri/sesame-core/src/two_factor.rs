//! Local match of a stored login host against the bundled 2FA Directory list.
//! The list carries sites with a documented 2FA or passkey method; a match is
//! availability on the site, never a claim that the account has it enabled.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::two_factor_sites::TWO_FACTOR_SITES;

pub const MAX_TWO_FACTOR_LOGINS: usize = 5;

pub fn site_offers_two_factor(host: &str) -> bool {
    let Some(host) = normalised_host(host) else {
        return false;
    };
    candidates(&host)
        .iter()
        .any(|candidate| two_factor_index().contains(candidate))
}

/// The host itself plus the parent hosts that stay specific enough to name a
/// service. A two-label parent under a two-letter country code is a registry
/// suffix, not a site, so it is never a candidate on its own.
fn candidates(host: &str) -> Vec<&str> {
    let mut candidates = vec![host];
    let mut rest = host;
    while let Some((_, parent)) = rest.split_once('.') {
        let label_count = parent.matches('.').count() + 1;
        let last_label_len = parent
            .rsplit_once('.')
            .map_or(parent.len(), |(_, last)| last.len());
        if label_count < 2 || (label_count == 2 && last_label_len < 3) {
            break;
        }
        candidates.push(parent);
        rest = parent;
    }
    candidates
}

fn two_factor_index() -> &'static HashSet<&'static str> {
    static INDEX: OnceLock<HashSet<&'static str>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index = HashSet::with_capacity(TWO_FACTOR_SITES.len());
        for site in TWO_FACTOR_SITES {
            index.extend(candidates(site));
        }
        index
    })
}

fn normalised_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.split([':', '/']).next().unwrap_or_default();
    let host = host.strip_prefix("www.").unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    Some(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_hosts_and_their_subdomains_match() {
        assert!(site_offers_two_factor("github.com"));
        assert!(site_offers_two_factor("GitHub.com"));
        assert!(site_offers_two_factor("gist.github.com"));
        assert!(site_offers_two_factor("www.github.com"));
        assert!(site_offers_two_factor("dropbox.com"));
    }

    #[test]
    fn a_product_host_matches_a_login_saved_at_the_parent_host() {
        assert!(site_offers_two_factor("google.com"));
        assert!(site_offers_two_factor("accounts.google.com"));
        assert!(site_offers_two_factor("mail.google.com"));
    }

    #[test]
    fn lookalike_hosts_and_registry_suffixes_do_not_match() {
        assert!(!site_offers_two_factor("notgithub.com"));
        assert!(!site_offers_two_factor("github.com.example.test"));
        assert!(!site_offers_two_factor("co.uk"));
        assert!(!site_offers_two_factor("example.co.uk"));
        assert!(!site_offers_two_factor(""));
        assert!(!site_offers_two_factor("No website saved"));
    }

    #[test]
    fn the_list_stays_sorted_and_free_of_duplicates() {
        assert!(TWO_FACTOR_SITES.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn every_match_comes_from_the_bundled_list() {
        for site in TWO_FACTOR_SITES {
            assert!(site_offers_two_factor(site));
        }
    }
}
