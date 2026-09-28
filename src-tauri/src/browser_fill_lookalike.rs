use unicode_security::mixed_script::AugmentedScriptSet;

fn lookalike_host(entries: &[VaultEntry], requested: &NormalizedOrigin) -> Option<String> {
    let requested_registrable = registrable_domain(&requested.hostname)?;
    let requested_unicode = decode_domain(requested_registrable)?;
    let requested_skeleton = confusable_skeleton(&requested_unicode);
    let requested_mixed_script = has_confusable_mixed_script_label(&requested_unicode);
    for entry in entries {
        let Some(saved_origin) = NormalizedOrigin::from_saved_url(&entry.url) else {
            continue;
        };
        if saved_origin.hostname == requested.hostname {
            continue;
        }
        let Some(saved_registrable) = registrable_domain(&saved_origin.hostname) else {
            continue;
        };
        if saved_registrable == requested_registrable {
            continue;
        }
        let Some(saved_unicode) = decode_domain(saved_registrable) else {
            continue;
        };
        if saved_unicode == requested_unicode {
            continue;
        }
        let saved_skeleton = confusable_skeleton(&saved_unicode);
        if requested_skeleton == saved_skeleton {
            return Some(bounded_lookalike_host(&saved_origin.hostname));
        }
        let budget = edit_budget(
            requested_skeleton
                .chars()
                .count()
                .max(saved_skeleton.chars().count()),
        );
        if budget == 0 {
            continue;
        }
        let within_budget = within_edit_distance(&requested_skeleton, &saved_skeleton, budget);
        if within_budget
            && (requested_mixed_script
                || first_and_last_match(&requested_skeleton, &saved_skeleton))
        {
            return Some(bounded_lookalike_host(&saved_origin.hostname));
        }
    }
    None
}

fn registrable_domain(hostname: &str) -> Option<&str> {
    if !hostname.contains('.') || hostname.contains(':') {
        return None;
    }
    match Host::parse(hostname) {
        Ok(Host::Domain(domain)) if domain == hostname => psl::domain_str(hostname),
        _ => None,
    }
}

fn decode_domain(domain: &str) -> Option<String> {
    let (decoded, result) = idna::domain_to_unicode(domain);
    result.ok()?;
    (!decoded.is_empty()).then_some(decoded)
}

fn confusable_skeleton(domain: &str) -> String {
    unicode_security::skeleton(domain).collect()
}

fn has_confusable_mixed_script_label(domain: &str) -> bool {
    const CONFUSABLE_PROBES: [char; 4] = ['\u{0430}', '\u{03b1}', '\u{0561}', '\u{13a0}'];
    domain.split('.').any(|label| {
        let mut has_latin = false;
        let mut has_confusable_pair = false;
        for value in label.chars() {
            let script_set = AugmentedScriptSet::for_char(value);
            if script_set.is_all() {
                continue;
            }
            if shares_script(script_set, 'a') {
                has_latin = true;
            }
            if CONFUSABLE_PROBES
                .iter()
                .any(|probe| shares_script(script_set, *probe))
            {
                has_confusable_pair = true;
            }
        }
        has_latin && has_confusable_pair
    })
}

fn shares_script(script_set: AugmentedScriptSet, probe: char) -> bool {
    let mut combined = script_set;
    combined.intersect_with(AugmentedScriptSet::for_char(probe));
    !combined.is_empty()
}

fn bounded_lookalike_host(hostname: &str) -> String {
    bounded_display(hostname, crate::browser_protocol::MAX_LOOKALIKE_HOST_CHARS)
        .trim_end_matches('.')
        .to_string()
}

fn edit_budget(length: usize) -> usize {
    if length >= 16 {
        2
    } else if length >= 8 {
        1
    } else {
        0
    }
}

fn first_and_last_match(left: &str, right: &str) -> bool {
    left.chars().next().is_some()
        && left.chars().next() == right.chars().next()
        && left.chars().last() == right.chars().last()
}

fn within_edit_distance(left: &str, right: &str, max: usize) -> bool {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    let (rows, columns) = (left.len(), right.len());
    if rows.abs_diff(columns) > max {
        return false;
    }
    let unreachable = max + 1;
    let mut previous = vec![unreachable; columns + 1];
    for (column, value) in previous.iter_mut().enumerate() {
        if column <= max {
            *value = column;
        }
    }
    let mut current = vec![unreachable; columns + 1];
    for row in 1..=rows {
        current.fill(unreachable);
        let low = row.saturating_sub(max);
        let high = (row + max).min(columns);
        let mut row_min = unreachable;
        for column in low..=high {
            let distance = if column == 0 {
                previous[0].saturating_add(1)
            } else {
                let substitution = previous[column - 1]
                    + usize::from(left[row - 1] != right[column - 1]);
                let deletion = previous[column].saturating_add(1);
                let insertion = current[column - 1].saturating_add(1);
                substitution.min(deletion).min(insertion)
            }
            .min(unreachable);
            current[column] = distance;
            row_min = row_min.min(distance);
        }
        if row_min > max {
            return false;
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[columns] <= max
}

#[cfg(test)]
mod lookalike_tests {
    use super::*;
    use crate::browser_protocol::{
        fill_carries_match_kind, BrowserRequest, BrowserResponse, LOOKALIKE_PROTOCOL_VERSION,
        MAX_NATIVE_MESSAGE_BYTES,
    };

    const CANARY_PASSWORD: &str = "fictional-canary-password";

    fn origin(value: &str) -> NormalizedOrigin {
        NormalizedOrigin::from_request(value).expect("request origin")
    }

    fn entry(id: &str, url: &str, password: &str) -> VaultEntry {
        VaultEntry {
            id: id.to_string(),
            title: format!("Entry {id}"),
            username: "casey".to_string(),
            email: "casey@example.test".to_string(),
            password: password.to_string(),
            url: url.to_string(),
            ..VaultEntry::default()
        }
    }

    fn fill_request(origin: &str) -> BrowserRequest {
        BrowserRequest {
            version: LOOKALIKE_PROTOCOL_VERSION,
            message_type: "fill".to_string(),
            request_id: "fill-lookalike-1".to_string(),
            origin: Some(origin.to_string()),
            fields: None,
            username: None,
            password: None,
            title: None,
            kind: None,
        }
    }

    fn wire(response: &BrowserResponse) -> String {
        String::from_utf8(response.to_zeroizing_bytes().expect("encodes").to_vec()).expect("utf8")
    }

    #[test]
    fn a_cyrillic_homoglyph_host_warns_with_the_stored_host_and_no_credential() {
        let entries = vec![entry(
            "login-apple",
            "https://apple.com",
            CANARY_PASSWORD,
        )];
        let requested = origin("https://\u{0430}pple.com");
        assert_eq!(requested.hostname, "xn--pple-43d.com");

        let found = lookalike_host(&entries, &requested).expect("a lookalike");
        assert_eq!(found, "apple.com");

        let request = fill_request("https://\u{0430}pple.com");
        let response = BrowserResponse::lookalike_unavailable(&request, found);
        assert_eq!(response.message_type, "fill-unavailable");
        assert_eq!(response.reason.as_deref(), Some("lookalike"));
        assert!(response.username.is_none());
        assert!(response.password.is_none());
        assert!(response.match_kind.is_none());
        assert!(response.validate_for(&request));
        assert!(!wire(&response).contains(CANARY_PASSWORD));
    }

    #[test]
    fn the_punycode_form_of_the_same_host_warns() {
        let entries = vec![entry("login-apple", "https://apple.com", CANARY_PASSWORD)];
        let found = lookalike_host(&entries, &origin("https://xn--pple-43d.com"));
        assert_eq!(found.as_deref(), Some("apple.com"));
    }

    #[test]
    fn a_mixed_script_label_outside_the_confusables_table_still_warns() {
        let entries = vec![entry("login-example", "https://example.test", CANARY_PASSWORD)];
        let requested = origin("https://\u{044d}xample.test");
        assert_eq!(requested.hostname, "xn--xample-vtf.test");
        assert_eq!(confusable_skeleton("\u{044d}"), "\u{044d}");
        assert_ne!(
            confusable_skeleton("\u{044d}xample.test"),
            confusable_skeleton("example.test")
        );

        assert_eq!(
            lookalike_host(&entries, &requested).as_deref(),
            Some("example.test")
        );
        assert_eq!(lookalike_host(&entries, &origin("https://zxample.test")), None);
    }

    #[test]
    fn a_one_edit_typo_on_a_long_domain_warns_and_a_two_edit_short_one_does_not() {
        let long = vec![entry("login-northwind", "https://northwind.co.uk", CANARY_PASSWORD)];
        assert_eq!(
            lookalike_host(&long, &origin("https://northwine.co.uk")).as_deref(),
            Some("northwind.co.uk")
        );

        let short = vec![entry("login-seldom", "https://seldom.com", CANARY_PASSWORD)];
        assert_eq!(lookalike_host(&short, &origin("https://selfim.com")), None);
    }

    #[test]
    fn a_trailing_dot_origin_fails_before_any_lookalike_check() {
        assert!(NormalizedOrigin::from_request("https://example.test./").is_none());

        let request = fill_request("https://example.test./");
        let response = BrowserResponse::unavailable(&request, "staleRequest");
        assert!(response.validate_for(&request));
        assert!(response.lookalike.is_none());
    }

    #[test]
    fn an_unrelated_domain_is_no_match_not_a_lookalike() {
        let entries = vec![entry("login-example", "https://example.test", CANARY_PASSWORD)];
        assert_eq!(lookalike_host(&entries, &origin("https://unrelated.test")), None);

        let request = fill_request("https://unrelated.test");
        let response = BrowserResponse::unavailable(&request, "noMatch");
        assert!(response.validate_for(&request));
    }

    #[test]
    fn a_different_subdomain_of_the_stored_host_is_not_a_lookalike() {
        let entries = vec![entry("login-example", "https://example.test", CANARY_PASSWORD)];
        assert_eq!(lookalike_host(&entries, &origin("https://app.example.test")), None);
        assert_eq!(lookalike_host(&entries, &origin("https://www.example.test")), None);
    }

    #[test]
    fn a_stored_login_without_a_usable_password_still_warns_without_a_credential() {
        let entries = vec![entry("login-apple", "https://apple.com", "")];
        let request = fill_request("https://\u{0430}pple.com");
        let found = lookalike_host(&entries, &origin("https://\u{0430}pple.com")).expect("a lookalike");

        let response = BrowserResponse::lookalike_unavailable(&request, found);
        assert!(response.validate_for(&request));
        assert!(!wire(&response).contains("password"));
        assert!(!wire(&response).contains(CANARY_PASSWORD));
    }

    #[test]
    fn a_long_stored_host_truncates_to_the_display_bound() {
        let label = "a".repeat(62);
        let stored_host = format!("{label}.{label}.{}.test", "c".repeat(62));
        let requested_host = format!("{label}.{label}.{}d.test", "c".repeat(61));
        let entries = vec![entry(
            "login-long",
            &format!("https://{stored_host}"),
            CANARY_PASSWORD,
        )];

        let found = lookalike_host(&entries, &origin(&format!("https://{requested_host}")))
            .expect("a lookalike");
        assert_eq!(found, stored_host[..128]);
        assert_eq!(found.chars().count(), 128);

        let request = fill_request(&format!("https://{requested_host}"));
        let response = BrowserResponse::lookalike_unavailable(&request, found);
        assert!(response.validate_for(&request));
        assert!(wire(&response).len() <= MAX_NATIVE_MESSAGE_BYTES);
    }

    #[test]
    fn a_lookalike_answer_is_never_a_fill() {
        let request = fill_request("https://\u{0430}pple.com");
        let response = BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        assert_ne!(response.message_type, "fill");
        assert!(response.validate_for(&request));

        let mut smuggled = BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        smuggled.message_type = "fill".to_string();
        assert!(!smuggled.validate_for(&request));

        let mut replay = BrowserResponse::lookalike_unavailable(&request, "apple.com".to_string());
        replay.username = Some("person@example.test".to_string());
        replay.password = Some(CANARY_PASSWORD.to_string());
        assert!(!replay.validate_for(&request));
        assert!(fill_carries_match_kind(LOOKALIKE_PROTOCOL_VERSION));
    }

    #[test]
    fn local_hosts_and_loopback_addresses_never_warn() {
        let entries = vec![entry("login-example", "https://example.test", CANARY_PASSWORD)];
        for requested in [
            "https://localhost/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "http://localhost:3000/",
        ] {
            assert_eq!(
                lookalike_host(&entries, &origin(requested)),
                None,
                "{requested} warned"
            );
        }
    }

    #[test]
    fn the_lookalike_scan_of_five_thousand_logins_stays_bounded() {
        let entries: Vec<VaultEntry> = (0..5_000)
            .map(|index| {
                entry(
                    &format!("login-{index}"),
                    &format!("https://site-{index}.example.test"),
                    CANARY_PASSWORD,
                )
            })
            .collect();
        let requested = origin("https://\u{0430}pple.com");

        let started = std::time::Instant::now();
        let found = lookalike_host(&entries, &requested);
        let elapsed = started.elapsed();
        eprintln!("lookalike scan of 5000 stored logins: {elapsed:?}");

        assert_eq!(found, None);
        assert!(elapsed < std::time::Duration::from_secs(5));
    }
}
