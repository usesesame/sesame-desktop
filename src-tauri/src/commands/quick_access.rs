//! Quick access searches every saved item and hands back one field at a time.
//! Search results carry titles and non-secret detail only; a stored value
//! crosses back solely for the field the person just chose.

use serde::Serialize;
use tauri::{AppHandle, Emitter, State, WebviewWindow};

use crate::adapters::platform::desktop_shell::show_main_window;
use crate::vault::snapshot::current_totp;
use crate::vault::storage::vault_path;
use crate::vault::util::initials_for;
use crate::vault::{Identity, TaggedItem, VaultPayload, VaultResult, VaultState};

const QUICK_ACCESS_WINDOW: &str = "quick-access";
const QUICK_ACCESS_RESULT_LIMIT: usize = 8;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessStatus {
    exists: bool,
    unlocked: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessAction {
    field: &'static str,
    label: &'static str,
    /// Needs a second, deliberate confirmation before the value is produced.
    guarded: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessItem {
    id: String,
    kind: &'static str,
    title: String,
    /// Never a stored secret: a domain, an SSID, a card brand, a product name.
    subtitle: String,
    initials: String,
    actions: Vec<QuickAccessAction>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QuickAccessValue {
    value: String,
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
    Ok(quick_access_items(&session.payload, &query))
}

#[tauri::command]
pub fn get_quick_access_field(
    window: WebviewWindow,
    state: State<'_, VaultState>,
    id: String,
    field: String,
    confirmed: bool,
) -> VaultResult<QuickAccessValue> {
    require_quick_access(&window)?;
    let session = state
        .session
        .lock()
        .map_err(|_| "Sesame could not read the vault session.".to_string())?;
    let session = session
        .as_ref()
        .ok_or("Unlock your vault in Sesame first.")?;
    let item = session
        .payload
        .active_item(id.trim())
        .ok_or("That saved item no longer exists.")?;
    let action = quick_access_actions(&item)
        .into_iter()
        .find(|action| action.field == field.trim())
        .ok_or("Quick access cannot copy that field for this item.")?;
    if action.guarded && !confirmed {
        return Err("Confirm this copy in quick access first.".into());
    }
    let value = quick_access_value(&item, action.field)
        .ok_or("Nothing is saved in that field for this item.")?;
    Ok(QuickAccessValue { value })
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
        if session.payload.active_item(&id).is_none() {
            return Err("That saved item no longer exists.".into());
        }
    }
    let _ = window.hide();
    show_main_window(&app);
    app.emit("quick-access-open-item", id)
        .map_err(|_| "Sesame could not open that item in the main window.".to_string())
}

fn quick_access_items(payload: &VaultPayload, query: &str) -> Vec<QuickAccessItem> {
    let needle = query.trim().to_lowercase();
    let mut items: Vec<QuickAccessItem> = payload
        .item_views()
        .into_iter()
        .filter(|item| quick_access_matches(item, &needle))
        .map(|item| {
            let actions = quick_access_actions(&item);
            let preview = item.preview();
            QuickAccessItem {
                id: item.id().to_string(),
                kind: item.kind(),
                initials: initials_for(&preview.title),
                title: preview.title,
                subtitle: preview.detail.unwrap_or_default(),
                actions,
            }
        })
        .collect();
    items.sort_by(|left, right| left.title.to_lowercase().cmp(&right.title.to_lowercase()));
    items.truncate(QUICK_ACCESS_RESULT_LIMIT);
    items
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

fn action(field: &'static str, label: &'static str) -> QuickAccessAction {
    QuickAccessAction {
        field,
        label,
        guarded: false,
    }
}

fn guarded_action(field: &'static str, label: &'static str) -> QuickAccessAction {
    QuickAccessAction {
        field,
        label,
        guarded: true,
    }
}

/// A field absent here cannot be copied, whatever the caller asks for.
fn quick_access_actions(item: &TaggedItem) -> Vec<QuickAccessAction> {
    let mut actions = Vec::new();
    match item {
        TaggedItem::Login(entry) => {
            if !entry.password.is_empty() {
                actions.push(action("password", "Copy password"));
            }
            if !entry.username.is_empty() {
                actions.push(action("username", "Copy username"));
            }
            if entry.totp.as_deref().is_some_and(|totp| !totp.is_empty()) {
                actions.push(action("totp", "Copy 2FA code"));
            }
        }
        TaggedItem::Card(card) => {
            if !card.number.is_empty() {
                actions.push(action("number", "Copy card number"));
            }
            if !card.expiry_month.is_empty() || !card.expiry_year.is_empty() {
                actions.push(action("expiry", "Copy expiry"));
            }
            if !card.security_code.is_empty() {
                actions.push(action("securityCode", "Copy security code"));
            }
        }
        TaggedItem::WifiNetwork(network) => {
            if !network.password.is_empty() {
                actions.push(action("password", "Copy Wi-Fi password"));
            }
        }
        TaggedItem::SoftwareLicense(license) => {
            if !license.license_key.is_empty() {
                actions.push(action("licenseKey", "Copy licence key"));
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
                    actions.push(action(field, label));
                }
            }
        }
        TaggedItem::SshKey(key) => {
            if !key.public_key.is_empty() {
                actions.push(action("publicKey", "Copy public key"));
            }
            if !key.private_key.is_empty() {
                actions.push(guarded_action("privateKey", "Copy private key"));
            }
        }
        // Contents stay in Sesame; a search window is the wrong place to read them.
        TaggedItem::SecureNote(_) | TaggedItem::Document(_) | TaggedItem::CustomRecord(_) => {
            actions.push(action("open", "Open in Sesame"));
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
