//! Quick access searches every saved item and hands back one field at a time.
//! Search results carry titles and non-secret detail only; a stored value
//! crosses back solely for the field the person just chose.

use serde::Serialize;
use sesame_core::secret_fields::secret_keys;
use tauri::{AppHandle, Emitter, State, WebviewWindow};
use zeroize::Zeroizing;

use crate::adapters::platform::clipboard::{copy_secret_value, ClipboardGuard};
use crate::adapters::platform::desktop_shell::show_main_window;
use crate::commands::require_release_presence;
use crate::release::ReleasePresence;
use crate::vault::snapshot::current_totp;
use crate::vault::storage::vault_path;
use crate::vault::util::initials_for;
use crate::vault::{Identity, TaggedItem, VaultResult, VaultState};

const QUICK_ACCESS_WINDOW: &str = "quick-access";
const QUICK_ACCESS_RESULT_LIMIT: usize = 8;

#[derive(Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessStatus {
    exists: bool,
    unlocked: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessAction {
    field: &'static str,
    label: &'static str,
    guarded: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessItem {
    id: String,
    #[ts(
        type = "'login' | 'identity' | 'secure_note' | 'card' | 'wifi_network' | 'ssh_key' | 'software_license' | 'document' | 'custom_record'"
    )]
    kind: &'static str,
    title: String,
    /// Never a stored secret: a domain, an SSID, a card brand, a product name.
    subtitle: String,
    initials: String,
    actions: Vec<QuickAccessAction>,
}

fn require_quick_access(window: &WebviewWindow) -> VaultResult<()> {
    if window.label() == QUICK_ACCESS_WINDOW {
        Ok(())
    } else {
        Err("That command is available only from quick access.".into())
    }
}

#[tauri::command]
pub fn get_quick_access_status(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, VaultState>,
) -> VaultResult<QuickAccessStatus> {
    require_quick_access(&window)?;
    let unlocked = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault state.".to_string())?
        .is_some();
    Ok(QuickAccessStatus {
        exists: vault_path(&app)?.exists(),
        unlocked,
    })
}

#[tauri::command]
pub fn search_quick_access_items(
    window: WebviewWindow,
    state: State<'_, VaultState>,
    query: String,
) -> VaultResult<Vec<QuickAccessItem>> {
    require_quick_access(&window)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault in Sesame first.")?;
    let index = session.snapshot();
    let needle = query.trim().to_lowercase();
    let mut items = Vec::new();
    for id in index
        .entries
        .iter()
        .map(|item| item.id.as_str())
        .chain(index.items.iter().map(|item| item.id.as_str()))
    {
        let item = session.open_item(id)?;
        if quick_access_matches(&item, &needle) {
            items.push(quick_access_item(&item));
        }
    }
    items.sort_by_key(|item| item.title.to_lowercase());
    items.truncate(QUICK_ACCESS_RESULT_LIMIT);
    Ok(items)
}

#[tauri::command]
pub fn copy_quick_access_field(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, VaultState>,
    presence: State<'_, ReleasePresence>,
    clipboard: State<'_, ClipboardGuard>,
    id: String,
    field: String,
    clear_after_ms: Option<u64>,
) -> VaultResult<()> {
    require_quick_access(&window)?;
    let value = quick_access_field_in_state(&state, &presence, &id, &field)?;
    copy_secret_value(app, &clipboard, value.to_string(), clear_after_ms).map(|_| ())
}

fn quick_access_field_in_state(
    state: &VaultState,
    presence: &ReleasePresence,
    id: &str,
    field: &str,
) -> VaultResult<Zeroizing<String>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault in Sesame first.")?;
    let item = session.open_item(id.trim())?;
    let action = quick_access_actions(&item)
        .into_iter()
        .find(|action| action.field == field.trim())
        .ok_or("Quick access cannot copy that field for this item.")?;
    if action.guarded {
        require_release_presence(state, presence)?;
    }
    quick_access_value(&item, action.field)
        .map(Zeroizing::new)
        .ok_or_else(|| "Nothing is saved in that field for this item.".to_string())
}

/// A note, document, or custom record opens in Sesame rather than exposing its
/// contents in a search window.
#[tauri::command]
pub fn open_quick_access_item(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, VaultState>,
    id: String,
) -> VaultResult<()> {
    require_quick_access(&window)?;
    let id = id.trim().to_string();
    {
        let session = state
            .session
            .lock()
            .map_err(|_| "Sesame could not read the vault session.".to_string())?;
        let session = session
            .as_ref()
            .ok_or("Unlock your vault in Sesame first.")?;
        session.open_item(&id)?;
    }
    let _ = window.hide();
    show_main_window(&app);
    app.emit("quick-access-open-item", id)
        .map_err(|_| "Sesame could not open that item in the main window.".to_string())
}

fn quick_access_item(item: &TaggedItem) -> QuickAccessItem {
    let actions = quick_access_actions(item);
    let preview = item.preview();
    QuickAccessItem {
        id: item.id().to_string(),
        kind: item.kind(),
        initials: initials_for(&preview.title),
        title: preview.title,
        subtitle: preview.detail.unwrap_or_default(),
        actions,
    }
}

fn quick_access_matches(item: &TaggedItem, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let metadata = item.metadata();
    if metadata.item_title().to_lowercase().contains(needle)
        || metadata
            .item_tags()
            .iter()
            .any(|tag| tag.to_lowercase().contains(needle))
    {
        return true;
    }
    // Only fields already safe to print in a result row take part in matching.
    let searchable: Vec<&str> = match item {
        TaggedItem::Login(entry) => vec![
            entry.username.as_str(),
            entry.email.as_str(),
            entry.url.as_str(),
        ],
        TaggedItem::Identity(identity) => {
            vec![identity.full_name.as_str(), identity.email.as_str()]
        }
        TaggedItem::Card(card) => vec![card.brand.as_str(), card.cardholder_name.as_str()],
        TaggedItem::WifiNetwork(network) => vec![network.ssid.as_str()],
        TaggedItem::SshKey(key) => vec![key.key_type.as_str()],
        TaggedItem::SoftwareLicense(license) => vec![license.product_name.as_str()],
        TaggedItem::Document(document) => vec![document.document_type.as_str()],
        TaggedItem::SecureNote(_) | TaggedItem::CustomRecord(_) => Vec::new(),
    };
    searchable
        .iter()
        .any(|field| field.to_lowercase().contains(needle))
}

fn action(item: &TaggedItem, field: &'static str, label: &'static str) -> QuickAccessAction {
    QuickAccessAction {
        field,
        label,
        guarded: secret_keys(item).iter().any(|key| key == field),
    }
}

/// A field absent here cannot be copied, whatever the caller asks for.
fn quick_access_actions(item: &TaggedItem) -> Vec<QuickAccessAction> {
    let mut actions = Vec::new();
    match item {
        TaggedItem::Login(entry) => {
            if !entry.password.is_empty() {
                actions.push(action(item, "password", "Copy password"));
            }
            if !entry.username.is_empty() {
                actions.push(action(item, "username", "Copy username"));
            }
            if entry.totp.as_deref().is_some_and(|totp| !totp.is_empty()) {
                actions.push(action(item, "totp", "Copy 2FA code"));
            }
        }
        TaggedItem::Card(card) => {
            if !card.number.is_empty() {
                actions.push(action(item, "number", "Copy card number"));
            }
            if !card.expiry_month.is_empty() || !card.expiry_year.is_empty() {
                actions.push(action(item, "expiry", "Copy expiry"));
            }
            if !card.security_code.is_empty() {
                actions.push(action(item, "securityCode", "Copy security code"));
            }
        }
        TaggedItem::WifiNetwork(network) => {
            if !network.password.is_empty() {
                actions.push(action(item, "password", "Copy Wi-Fi password"));
            }
        }
        TaggedItem::SoftwareLicense(license) => {
            if !license.license_key.is_empty() {
                actions.push(action(item, "licenseKey", "Copy licence key"));
            }
        }
        TaggedItem::Identity(identity) => {
            for (field, label) in [
                ("fullName", "Copy full name"),
                ("email", "Copy email"),
                ("phone", "Copy phone"),
                ("address", "Copy address"),
            ] {
                if identity_field(identity, field).is_some() {
                    actions.push(action(item, field, label));
                }
            }
        }
        TaggedItem::SshKey(key) => {
            if !key.public_key.is_empty() {
                actions.push(action(item, "publicKey", "Copy public key"));
            }
            if !key.private_key.is_empty() {
                actions.push(action(item, "privateKey", "Copy private key"));
            }
        }
        // Contents stay in Sesame; a search window is the wrong place to read them.
        TaggedItem::SecureNote(_) | TaggedItem::Document(_) | TaggedItem::CustomRecord(_) => {
            actions.push(action(item, "open", "Open in Sesame"));
        }
    }
    actions
}

fn identity_field(identity: &Identity, field: &str) -> Option<String> {
    let value = match field {
        "fullName" => identity.full_name.clone(),
        "email" => identity.email.clone(),
        "phone" => identity.phone.clone(),
        "address" => [
            identity.address_line1.as_str(),
            identity.address_line2.as_str(),
            identity.city.as_str(),
            identity.region.as_str(),
            identity.postal_code.as_str(),
            identity.country.as_str(),
        ]
        .iter()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", "),
        _ => String::new(),
    };
    (!value.trim().is_empty()).then_some(value)
}

fn quick_access_value(item: &TaggedItem, field: &str) -> Option<String> {
    let value = match (item, field) {
        (TaggedItem::Login(entry), "password") => entry.password.clone(),
        (TaggedItem::Login(entry), "username") => entry.username.clone(),
        (TaggedItem::Login(entry), "totp") => entry
            .totp
            .as_deref()
            .and_then(current_totp)
            .map(|(code, _, _)| code)?,
        (TaggedItem::Card(card), "number") => card.number.clone(),
        (TaggedItem::Card(card), "expiry") => {
            format!("{}/{}", card.expiry_month.trim(), card.expiry_year.trim())
        }
        (TaggedItem::Card(card), "securityCode") => card.security_code.clone(),
        (TaggedItem::WifiNetwork(network), "password") => network.password.clone(),
        (TaggedItem::SoftwareLicense(license), "licenseKey") => license.license_key.clone(),
        (TaggedItem::Identity(identity), field) => identity_field(identity, field)?,
        (TaggedItem::SshKey(key), "publicKey") => key.public_key.clone(),
        (TaggedItem::SshKey(key), "privateKey") => key.private_key.clone(),
        _ => String::new(),
    };
    (!value.trim().is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::TestVault;
    use crate::release::PRESENCE_REQUIRED;
    use crate::vault::{Card, SoftwareLicense, SshKey, VaultEntry, WifiNetwork};
    use std::time::{Duration, Instant};

    fn login() -> TaggedItem {
        let mut entry = VaultEntry::default();
        entry.id = "fictional-login".to_string();
        entry.title = "Northwind".to_string();
        entry.username = "casey".to_string();
        entry.password = "fictional-secret-canary".to_string();
        TaggedItem::Login(entry)
    }

    #[test]
    fn quick_access_result_is_redacted_after_one_record_is_opened() {
        let result = quick_access_item(&login());
        let serialized = serde_json::to_string(&result).expect("serialized quick access item");

        assert!(serialized.contains("Northwind"));
        assert!(serialized.contains("Copy password"));
        assert!(!serialized.contains("fictional-secret-canary"));
    }

    #[test]
    fn quick_access_search_does_not_match_secret_values() {
        assert!(quick_access_matches(&login(), "casey"));
        assert!(!quick_access_matches(&login(), "secret-canary"));
    }

    fn seeded_vault() -> TestVault {
        let vault = TestVault::with_login("fictional-login", "https://northwind.example");
        vault.seed(|payload| {
            let mut card = Card::default();
            card.id = "fictional-card".to_string();
            card.title = "Fictional card".to_string();
            card.number = "4000000000000002".to_string();
            card.security_code = "123".to_string();
            card.expiry_month = "04".to_string();
            card.expiry_year = "2031".to_string();
            payload.cards.push(card);
            let mut network = WifiNetwork::default();
            network.id = "fictional-wifi".to_string();
            network.ssid = "Fictional network".to_string();
            network.password = "fictional-wifi-secret".to_string();
            payload.wifi_networks.push(network);
            let mut license = SoftwareLicense::default();
            license.id = "fictional-license".to_string();
            license.title = "Fictional licence".to_string();
            license.license_key = "fictional-license-key".to_string();
            payload.software_licenses.push(license);
            let mut key = SshKey::default();
            key.id = "fictional-ssh".to_string();
            key.title = "Fictional key".to_string();
            key.public_key = "ssh-ed25519 FICTIONAL".to_string();
            key.private_key = "fictional-private-key".to_string();
            payload.ssh_keys.push(key);
            payload.entries[0].totp = Some("JBSWY3DPEHPK3PXP".to_string());
        });
        vault
    }

    fn grant(vault: &TestVault, presence: &ReleasePresence) {
        let session = vault.state.session.lock().expect("session lock");
        presence
            .grant_with_password(
                session.as_ref().expect("session"),
                vault.state.session_epoch(),
                "fictional master password",
            )
            .expect("granted presence");
    }

    const GUARDED_FIELDS: [(&str, &str); 6] = [
        ("fictional-login", "password"),
        ("fictional-card", "number"),
        ("fictional-card", "securityCode"),
        ("fictional-wifi", "password"),
        ("fictional-ssh", "privateKey"),
        ("fictional-license", "licenseKey"),
    ];

    #[test]
    fn guarded_fields_need_a_master_password_grant() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();

        for (id, field) in GUARDED_FIELDS {
            let error = quick_access_field_in_state(&vault.state, &presence, id, field)
                .expect_err("no grant");
            assert_eq!(error, PRESENCE_REQUIRED, "{id} {field}");
        }
    }

    #[test]
    fn guarded_fields_are_released_with_a_current_grant() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();
        grant(&vault, &presence);

        for (id, field) in GUARDED_FIELDS {
            let released = quick_access_field_in_state(&vault.state, &presence, id, field)
                .unwrap_or_else(|error| panic!("{id} {field}: {error}"));
            assert!(!released.is_empty(), "{id} {field}");
        }
    }

    #[test]
    fn an_expired_grant_releases_nothing() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();
        presence.grant_until(
            vault.state.session_epoch(),
            Instant::now() - Duration::from_secs(1),
        );

        for (id, field) in GUARDED_FIELDS {
            let error = quick_access_field_in_state(&vault.state, &presence, id, field)
                .expect_err("expired grant");
            assert_eq!(error, PRESENCE_REQUIRED, "{id} {field}");
        }
    }

    #[test]
    fn a_grant_from_an_earlier_session_epoch_releases_nothing() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();
        grant(&vault, &presence);
        vault.state.advance_session_epoch();

        for (id, field) in GUARDED_FIELDS {
            let error = quick_access_field_in_state(&vault.state, &presence, id, field)
                .expect_err("stale epoch");
            assert_eq!(error, PRESENCE_REQUIRED, "{id} {field}");
        }
    }

    #[test]
    fn a_revoked_grant_releases_nothing() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();
        grant(&vault, &presence);
        presence.revoke();

        for (id, field) in GUARDED_FIELDS {
            let error = quick_access_field_in_state(&vault.state, &presence, id, field)
                .expect_err("revoked grant");
            assert_eq!(error, PRESENCE_REQUIRED, "{id} {field}");
        }
    }

    #[test]
    fn a_locked_vault_releases_nothing() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();
        grant(&vault, &presence);
        *vault.state.session.lock().expect("session lock") = None;

        assert!(quick_access_field_in_state(
            &vault.state,
            &presence,
            "fictional-login",
            "password"
        )
        .is_err());
    }

    #[test]
    fn a_field_the_item_does_not_offer_is_refused_even_with_a_grant() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();
        grant(&vault, &presence);

        assert!(
            quick_access_field_in_state(&vault.state, &presence, "fictional-login", "notes")
                .is_err()
        );
        assert!(
            quick_access_field_in_state(&vault.state, &presence, "fictional-card", "password")
                .is_err()
        );
    }

    #[test]
    fn fields_without_a_guard_stay_available_with_no_grant() {
        let vault = seeded_vault();
        let presence = ReleasePresence::default();

        for (id, field) in [
            ("fictional-login", "username"),
            ("fictional-login", "totp"),
            ("fictional-card", "expiry"),
            ("fictional-ssh", "publicKey"),
        ] {
            let released = quick_access_field_in_state(&vault.state, &presence, id, field)
                .unwrap_or_else(|error| panic!("{id} {field}: {error}"));
            assert!(!released.is_empty(), "{id} {field}");
        }
    }

    #[test]
    fn every_secret_the_popup_offers_is_guarded_unless_listed_here() {
        let vault = seeded_vault();
        let session = vault.state.session.lock().expect("session lock");
        let session = session.as_ref().expect("session");
        let open_fields = [
            "username",
            "totp",
            "expiry",
            "publicKey",
            "fullName",
            "email",
            "phone",
            "address",
            "open",
        ];
        for id in [
            "fictional-login",
            "fictional-card",
            "fictional-wifi",
            "fictional-ssh",
            "fictional-license",
        ] {
            let item = session.open_item(id).expect("seeded item");
            for action in quick_access_actions(&item) {
                assert_eq!(
                    action.guarded,
                    !open_fields.contains(&action.field),
                    "{id} {}",
                    action.field
                );
            }
        }
    }
}
