use sesame_core::types::VaultEntry;

pub fn login(url: &str, username: &str, password: &str) -> VaultEntry {
    let mut entry = VaultEntry::default();
    entry.title = "Example".into();
    entry.url = url.into();
    entry.username = username.into();
    entry.password = password.into();
    entry
}
