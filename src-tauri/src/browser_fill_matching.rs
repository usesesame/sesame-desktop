fn matching_entries(
    entries: &[VaultEntry],
    origin: &NormalizedOrigin,
) -> Vec<BrowserFillCandidate> {
    let mut candidates = Vec::new();
    for requested_kind in [OriginMatchKind::Exact, OriginMatchKind::WwwAlias] {
        for entry in entries {
            if !credential_fields_valid(entry) {
                continue;
            }
            let Some(saved_origin) = NormalizedOrigin::from_saved_url(&entry.url) else {
                continue;
            };
            if origin_match_kind(&saved_origin, origin) != Some(requested_kind) {
                continue;
            }
            candidates.push(BrowserFillCandidate {
                id: entry.id.clone(),
                title: bounded_display(&entry.title, 128),
                username: bounded_display(&entry.username, 256),
                email: bounded_display(&entry.email, 256),
                saved_origin: saved_origin.canonical(),
                match_kind: requested_kind.as_str(),
            });
            if candidates.len() >= MAX_MATCHING_CANDIDATES {
                return candidates;
            }
        }
    }
    candidates
}

fn credential_fields_valid(entry: &VaultEntry) -> bool {
    entry.username.len() <= MAX_CREDENTIAL_FIELD_BYTES
        && !entry.password.is_empty()
        && entry.password.len() <= MAX_CREDENTIAL_FIELD_BYTES
}

fn bounded_display(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}
